//! The Helios init process — first userspace task and, since ADR-023, the
//! first **launcher** (spawns the process server from an embedded image).
//!
//! Built for `x86_64-unknown-none` with `--features user`:
//! ```text
//! cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release
//! ```
//! Entry: `_start` with `rdi` = pointer to the kernel-written BootInfo block.
//!
//! Flow: parse BootInfo → debug-EP markers → Factory endpoint round-trip →
//! heap over the boot Region (ADR-023 `self_as`) → spawn the process server
//! (ELF load into a fresh AS, ANON stack, ADR-009 package with Factory in the
//! optional tail) → reap the child via its death notification → exit(0).
//! Without `PS_IMAGE` (build.rs), the spawn step is skipped with a marker.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::bootinfo::{BootInfo, MAX_LEN};
use sdk::bootstrap;
use sdk::elf::ElfImage;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{
    CHILD_STACK_PAGES, HEAP_CHUNK, HEAP_CHUNKS, INIT_HEAP_VA_BASE, INIT_SCRATCH_VA_BASE,
    USER_STACK_TOP,
};
use sdk::loader;
use sdk::methods;
use sdk::syscall::{Handle, Syscalls, X86_64Syscalls};

include!(concat!(env!("OUT_DIR"), "/ps_image.rs"));

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

/// Log marker: "INIT" in the high bytes, step number in the low byte.
const MARK: u64 = 0x494E_4954_0000_0000;
const STEP_ALIVE: u64 = 1;
const STEP_BOOTINFO: u64 = 2;
const STEP_ENDPOINT: u64 = 3;
const STEP_IPC: u64 = 4;
const STEP_REVOKE: u64 = 5;
const STEP_HEAP: u64 = 6;
const STEP_SPAWNED: u64 = 7;
const STEP_CHILD_READY: u64 = 8;
const STEP_CONNECT: u64 = 9;
const STEP_CHILD_EXIT: u64 = 10;
const STEP_DONE: u64 = 0x0F;
/// Failure marker family for exits: `0xDEAD_0000_00SS_EEEE` (step, errno).
const FAIL: u64 = 0xDEAD_0000_0000_0000;

const DEBUG_LABEL: u16 = 0x0001;
const PING_LABEL: u16 = 0x4900;
const PING_WORD: u64 = 0x1234_5678_9ABC_DEF0;
/// `STEP_SPAWNED.w1` when the build has no embedded image.
const SPAWN_SKIPPED: u64 = u64::MAX;

const STACK_FLAGS: u32 = 0b011; // R | W

type Result<T> = core::result::Result<T, u64>;

#[no_mangle]
pub extern "C" fn _start(bootinfo_ptr: *const u8) -> ! {
    let info = match unsafe { read_bootinfo(bootinfo_ptr) } {
        Ok(info) => info,
        Err(errno) => exit_with(fail_code(STEP_BOOTINFO, errno)),
    };

    let mut raw = X86_64Syscalls;
    mark(&mut raw, info.debug_ep, STEP_ALIVE, 0);
    mark(
        &mut raw,
        info.debug_ep,
        STEP_BOOTINFO,
        info.region_count as u64,
    );

    match run(&mut raw, &info) {
        Ok(()) => {
            mark(&mut raw, info.debug_ep, STEP_DONE, 0);
            Syscalls::new(&mut raw).exit(0)
        }
        Err(code) => exit_with(code),
    }
}

fn run(raw: &mut X86_64Syscalls, info: &BootInfo) -> Result<()> {
    // Steps 3-5: Factory endpoint round-trip (Phase 1 acceptance).
    let endpoint = {
        let mut sys = Syscalls::new(raw);
        let reply = sys
            .invoke(info.factory, &Message::new(methods::factory::NEW_ENDPOINT))
            .map_err(|e| fail_code(STEP_ENDPOINT, e as u64))?;
        reply.words[0] as Handle
    };
    if endpoint == 0 {
        return Err(fail_code(STEP_ENDPOINT, 0xE0));
    }
    mark(raw, info.debug_ep, STEP_ENDPOINT, endpoint as u64);

    let echo = {
        let mut sys = Syscalls::new(raw);
        let mut ping = Message::new(PING_LABEL);
        ping.words[0] = PING_WORD;
        sys.send(endpoint, &ping)
            .map_err(|e| fail_code(STEP_IPC, e as u64))?;
        sys.recv(endpoint)
            .map_err(|e| fail_code(STEP_IPC, e as u64))?
    };
    if echo.tag.label() != PING_LABEL || echo.words[0] != PING_WORD {
        return Err(fail_code(STEP_IPC, 0xE1));
    }
    mark(raw, info.debug_ep, STEP_IPC, echo.words[0]);
    {
        let mut sys = Syscalls::new(raw);
        sys.cap_revoke(endpoint, 1)
            .map_err(|e| fail_code(STEP_REVOKE, e as u64))?;
    }
    mark(raw, info.debug_ep, STEP_REVOKE, 0);

    // From here failures report their code on the serial BEFORE exiting (the
    // kernel's last-thread clean halt masks the exit status otherwise).
    let stepped = heap_and_spawn(raw, info).map_err(|code| {
        mark(raw, info.debug_ep, 0xEE, code);
        code
    });
    stepped?;
    Ok(())
}

/// Steps 6-9 (heap, spawn, reap) split out so `run` can report failures.
fn heap_and_spawn(raw: &mut X86_64Syscalls, info: &BootInfo) -> Result<()> {
    // Step 6: heap over the boot Region (ADR-023 self_as).
    let self_as = info.self_as.ok_or(fail_code(STEP_HEAP, 0xE4))?;
    let region = info.region(0).ok_or(fail_code(STEP_HEAP, 0xE5))?.handle;
    let span = {
        let mut src = RegionSource::new(raw, region, self_as, INIT_HEAP_VA_BASE, HEAP_CHUNK);
        let mut chunk = 0u64;
        let err = loop {
            if chunk == HEAP_CHUNKS {
                break None;
            }
            if let Err(e) = src.grow(HEAP_CHUNK) {
                // Encode chunk number + underlying errno for diagnosis.
                break Some(fail_code(STEP_HEAP, ((e as u64 & 0xFF) << 8) | (chunk + 1)));
            }
            chunk += 1;
        };
        match err {
            Some(code) => return Err(code),
            None => (
                INIT_HEAP_VA_BASE as usize,
                (HEAP_CHUNKS * HEAP_CHUNK) as usize,
            ),
        }
    };
    HEAP.init(span.0, span.1)
        .map_err(|e| fail_code(STEP_HEAP, e as u64))?;
    mark(raw, info.debug_ep, STEP_HEAP, (span.1 >> 10) as u64);

    // Step 7: spawn the process server (embedded image, ADR-023).
    if !HAS_PS_IMAGE {
        mark(raw, info.debug_ep, STEP_SPAWNED, SPAWN_SKIPPED);
        return Ok(());
    }
    let pid = spawn_ps(raw, info, self_as, region)?;
    mark(raw, info.debug_ep, STEP_SPAWNED, pid);

    // Step 8: ready callback — PS publishes its service endpoint as a
    // capability (descriptor 0) over the package's service-endpoint slot.
    let ready = {
        let mut sys = Syscalls::new(raw);
        sys.recv(READY_EP.load(core::sync::atomic::Ordering::Relaxed))
            .map_err(|e| fail_code(STEP_CHILD_READY, e as u64))?
    };
    if ready.tag.label() != bootstrap::READY_LABEL || ready.words[0] != bootstrap::READY_MAGIC {
        return Err(fail_code(STEP_CHILD_READY, 0xE1));
    }
    let svc = ready
        .descriptor(0)
        .map(|cs| cs.handle())
        .filter(|h| *h != 0)
        .ok_or(fail_code(STEP_CHILD_READY, 0xE2))?;
    mark(raw, info.debug_ep, STEP_CHILD_READY, ready.words[1]);

    // Step 9: CONNECT round-trip (design §2.6, label 0x0101). The v0 packing
    // keeps the version in w0; the three caps (session notification, arg
    // frame, result frame) overlay w1..w3 per the v1 message format; windows
    // are 4 KiB each (design §1.3) so no size words travel.
    let session = mint(raw, info.factory, methods::factory::NEW_NOTIFICATION, 0xE6)?;
    let arg_frame = carve_frame(raw, region)?;
    let result_frame = carve_frame(raw, region)?;
    let conn = {
        let mut sys = Syscalls::new(raw);
        let mut connect = Message::new(methods::process::CONNECT);
        connect.tag = connect.tag.with_caps(3);
        connect.words[0] = 1; // protocol version
        let _ = connect.set_descriptor(0, ipc::CapSlot::pack(session, ipc::Rights::SIGNAL));
        let _ = connect.set_descriptor(1, ipc::CapSlot::pack(arg_frame, ipc::Rights::READ));
        let _ = connect.set_descriptor(2, ipc::CapSlot::pack(result_frame, ipc::Rights::WRITE));
        sys.call(svc, &connect)
            .map_err(|e| fail_code(STEP_CONNECT, e as u64))?
    };
    if conn.words[0] != 0 || conn.words[1] == 0 {
        return Err(fail_code(STEP_CONNECT, 0xE1));
    }
    // The connection endpoint rides in descriptor 0 (design §1.2); all later
    // operations go there, not to the service endpoint.
    let session_ep = conn
        .descriptor(0)
        .map(|cs| cs.handle())
        .filter(|h| *h != 0)
        .ok_or(fail_code(STEP_CONNECT, 0xE2))?;
    mark(raw, info.debug_ep, STEP_CONNECT, conn.words[1]);

    // Step 10: shut the child down (KILL acks, then PS exits) and reap — the
    // death notification fires when it exits (ADR-007 §6).
    {
        let mut sys = Syscalls::new(raw);
        let mut kill = Message::new(methods::process::KILL);
        kill.words[0] = pid;
        let ack = sys
            .call(session_ep, &kill)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
        if ack.words[0] != 0 {
            return Err(fail_code(STEP_CHILD_EXIT, 0xE2));
        }
    }
    let death = ps_death_handle(raw)?;
    let notified = {
        let mut sys = Syscalls::new(raw);
        sys.recv(death)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?
    };
    mark(raw, info.debug_ep, STEP_CHILD_EXIT, notified.tag.0);
    Ok(())
}

/// Carve one 4 KiB frame from the boot Region (CONNECT windows, design §1.3).
fn carve_frame(raw: &mut X86_64Syscalls, region: Handle) -> Result<Handle> {
    let mut sys = Syscalls::new(raw);
    let mut carve = Message::new(methods::region::CARVE);
    carve.words[0] = 4096;
    carve.words[1] = 4096;
    let reply = sys
        .invoke(region, &carve)
        .map_err(|e| fail_code(STEP_CONNECT, e as u64))?;
    let handle = reply.words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(STEP_CONNECT, 0xE3));
    }
    Ok(handle)
}

/// The launcher's service endpoint for the spawned child, set by `spawn_ps`
/// when building the package (prefix[7]).
static READY_EP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn ps_death_handle(raw: &mut X86_64Syscalls) -> Result<Handle> {
    let _ = raw;
    DEATH_HANDLE.get().ok_or(fail_code(STEP_CHILD_EXIT, 0xE6))
}

/// Spawn the process server: load `PS_IMAGE` into a fresh AS, mint its
/// endpoints/notifications, create the thread, deliver the ADR-009 package,
/// and bind its death notification. Returns the child pid.
fn spawn_ps(
    raw: &mut X86_64Syscalls,
    info: &BootInfo,
    self_as: Handle,
    region: Handle,
) -> Result<u64> {
    let image = ElfImage::parse(PS_IMAGE).map_err(|e| fail_code(STEP_SPAWNED, e as u64))?;
    let ops = loader::plan(&image, INIT_SCRATCH_VA_BASE)
        .map_err(|e| fail_code(STEP_SPAWNED, 0xE0_00 | (e as u64 & 0xFF)))?;

    let child_as = {
        let mut sys = Syscalls::new(raw);
        sys.invoke(
            info.factory,
            &Message::new(methods::factory::NEW_ADDRESS_SPACE),
        )
        .map_err(|e| fail_code(STEP_SPAWNED, 0xE0_01 | (e as u64 & 0xFF)))?
        .words[0] as Handle
    };
    if child_as == 0 {
        return Err(fail_code(STEP_SPAWNED, 0xE0_02));
    }

    {
        let mut sys = Syscalls::new(raw);
        loader::execute(
            &mut sys,
            &mut loader::MemoryWriter,
            &ops,
            child_as,
            region,
            self_as,
            PS_IMAGE,
        )
        .map_err(|e| fail_code(STEP_SPAWNED, 0xE1_00 | (e as u64 & 0xFF)))?;
        loader::map_anon(
            &mut sys,
            child_as,
            USER_STACK_TOP - CHILD_STACK_PAGES * 4096,
            CHILD_STACK_PAGES,
            STACK_FLAGS,
        )
        .map_err(|e| fail_code(STEP_SPAWNED, 0xE1_01 | (e as u64 & 0xFF)))?;
    }

    // Endpoints + notifications for the package.
    let bootstrap_ep = mint(raw, info.factory, methods::factory::NEW_ENDPOINT, 0xE2)?;
    let init_ep = mint(raw, info.factory, methods::factory::NEW_ENDPOINT, 0xE3)?;
    let death = mint(raw, info.factory, methods::factory::NEW_NOTIFICATION, 0xE4)?;
    let mut sessions = [0 as Handle; 4];
    for slot in sessions.iter_mut() {
        *slot = mint(raw, info.factory, methods::factory::NEW_NOTIFICATION, 0xE5)?;
    }

    // Child thread (ADR-017 packing): w0 = entry; caps[0] = AS (input),
    // caps[1] = fault EP (none v0), caps[2] = bootstrap EP.
    let (thread_cap, pid) = {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::factory::NEW_THREAD);
        m.tag = m.tag.with_caps(3);
        m.words[0] = image.entry;
        let _ = m.set_descriptor(0, CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
        let _ = m.set_descriptor(1, CapSlot::NULL);
        let _ = m.set_descriptor(2, CapSlot::pack(bootstrap_ep, Rights::RECV));
        let reply = sys
            .invoke(info.factory, &m)
            .map_err(|e| fail_code(STEP_SPAWNED, 0xE6_00 | (e as u64 & 0xFF)))?;
        (reply.words[0] as Handle, reply.words[2])
    };
    if thread_cap == 0 {
        return Err(fail_code(STEP_SPAWNED, 0xE6_01));
    }

    // Bind the child's death notification to its thread (ADR-007 §6).
    {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::thread::BIND_DEATH_NOTIFICATION);
        m.tag = m.tag.with_caps(1);
        let _ = m.set_descriptor(0, CapSlot::pack(death, Rights::SIGNAL));
        sys.invoke(thread_cap, &m)
            .map_err(|e| fail_code(STEP_SPAWNED, 0xE7_00 | (e as u64 & 0xFF)))?;
    }

    // ADR-009 package: §2.3 prefix + ADR-023 tail[0] = Factory.
    let mut caps: Vec<CapSlot> = Vec::with_capacity(9);
    caps.push(CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
    caps.push(CapSlot::pack(thread_cap, Rights::CONTROL));
    caps.push(CapSlot::pack(region, Rights::GRANT));
    for s in sessions {
        caps.push(CapSlot::pack(
            s,
            Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT),
        ));
    }
    caps.push(CapSlot::pack(init_ep, Rights::SEND.union(Rights::GRANT)));
    caps.push(CapSlot::pack(info.factory, Rights::ALL));
    READY_EP.store(init_ep, core::sync::atomic::Ordering::Relaxed);
    {
        let mut sys = Syscalls::new(raw);
        bootstrap::deliver(&mut sys, bootstrap_ep, &caps)
            .map_err(|e| fail_code(STEP_SPAWNED, 0xE8_00 | (e as u64 & 0xFF)))?;
    }

    DEATH_HANDLE.set(death);
    Ok(pid)
}

fn mint(raw: &mut X86_64Syscalls, factory: Handle, method: u16, errno: u64) -> Result<Handle> {
    let mut sys = Syscalls::new(raw);
    let handle = sys
        .invoke(factory, &Message::new(method))
        .map_err(|e| fail_code(STEP_SPAWNED, errno | (e as u64 & 0xFF)))?
        .words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(STEP_SPAWNED, errno | 0xFF));
    }
    Ok(handle)
}

/// Tiny module-local state: the death notification handle for the reaper
/// step (single-threaded init; no allocator needed). 0 = unset.
struct DeathHandle(core::sync::atomic::AtomicU32);

impl DeathHandle {
    const fn new() -> Self {
        Self(core::sync::atomic::AtomicU32::new(0))
    }

    fn set(&self, death: Handle) {
        self.0.store(death, core::sync::atomic::Ordering::Relaxed);
    }

    fn get(&self) -> Option<Handle> {
        match self.0.load(core::sync::atomic::Ordering::Relaxed) {
            0 => None,
            h => Some(h),
        }
    }
}

static DEATH_HANDLE: DeathHandle = DeathHandle::new();

fn exit_with(code: u64) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(code as i32)
}

const fn fail_code(step: u64, errno: u64) -> u64 {
    FAIL | ((step & 0xFF) << 16) | (errno & 0xFFFF)
}

/// Log one marker through the debug endpoint (SEND-only capability).
fn mark(raw: &mut X86_64Syscalls, debug_ep: u32, step: u64, value: u64) {
    let mut sys = Syscalls::new(raw);
    let mut m = Message::new(DEBUG_LABEL);
    m.words[0] = MARK | step;
    m.words[1] = value;
    let _ = sys.send(debug_ep, &m);
}

/// SAFETY: the kernel passes a pointer to the BootInfo block it wrote into
/// init's first stack page; the writer (ADR-018) bounds the block to
/// `24 + region_count * 24 <= MAX_LEN` bytes inside that page, so reading
/// `MAX_LEN` bytes stays within init's own stack mapping.
unsafe fn read_bootinfo(ptr: *const u8) -> core::result::Result<BootInfo, u64> {
    if ptr.is_null() {
        return Err(0xE2);
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr, MAX_LEN) };
    BootInfo::parse(bytes).map_err(|e| e as u64)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit_with(FAIL | 0x0BAD_0000)
}
