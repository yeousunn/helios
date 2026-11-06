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

use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::bootinfo::{BootInfo, MAX_LEN};
use sdk::bootstrap;
use sdk::elf::ElfImage;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{
    CHILD_STACK_PAGES, HEAP_CHUNK, HEAP_CHUNKS, INIT_HEAP_VA_BASE, INIT_SCRATCH_VA_BASE,
    INIT_WINDOW_VA_BASE, USER_STACK_TOP,
};
use sdk::loader;
use sdk::methods;
use sdk::syscall::{Handle, Syscalls, X86_64Syscalls};

include!(concat!(env!("OUT_DIR"), "/ps_image.rs")); // PS + VFS + CONSOLE images

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
const STEP_SPAWNED: u64 = 9;
const STEP_CHILD_READY: u64 = 10;
const STEP_CONNECT: u64 = 11;
const STEP_SPAWN_CHILD: u64 = 12;
const STEP_WAIT: u64 = 13;
const STEP_VFS_SPAWNED: u64 = 7;
const STEP_VFS_READY: u64 = 8;
const STEP_VFS_READ: u64 = 14;
const STEP_CHILD_EXIT: u64 = 15;
const STEP_POSIX_SPAWN: u64 = 16;
const STEP_POSIX_WAIT: u64 = 17;
const STEP_CONSOLE_SPAWN: u64 = 18;
const STEP_CONSOLE_READY: u64 = 19;
const STEP_SH_SPAWN: u64 = 20;
const STEP_SH_WAIT: u64 = 21;
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

    // Steps 18–19: the console server. Spawned before everything else that
    // might want to print: it receives the kernel debug endpoint as its
    // package tail (`optional[1]`) — the launcher is the only process that
    // holds it — and forwards console writes to the serial line. Later
    // spawns hand its service endpoint to children as stdio (design §2.3).
    let (console_svc, console_death) = {
        if !HAS_CONSOLE_IMAGE {
            return Err(fail_code(STEP_CONSOLE_SPAWN, 0xE1));
        }
        let pid = spawn_server(
            raw,
            info,
            self_as,
            region,
            CONSOLE_IMAGE,
            STEP_CONSOLE_SPAWN,
            Some(CapSlot::pack(info.debug_ep, Rights::SEND)),
        )?;
        let ready_ep = SP_INIT_EP.load(SpOrdering::Relaxed);
        let death = SP_DEATH.load(SpOrdering::Relaxed);
        mark(raw, info.debug_ep, STEP_CONSOLE_SPAWN, pid);
        let ready = {
            let mut sys = Syscalls::new(raw);
            sys.recv(ready_ep)
                .map_err(|e| fail_code(STEP_CONSOLE_READY, e as u64))?
        };
        if ready.tag.label() != bootstrap::READY_LABEL || ready.words[0] != bootstrap::READY_MAGIC {
            return Err(fail_code(STEP_CONSOLE_READY, 0xE1));
        }
        let svc = ready
            .descriptor(0)
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(fail_code(STEP_CONSOLE_READY, 0xE2))?;
        mark(raw, info.debug_ep, STEP_CONSOLE_READY, svc as u64);
        (svc, death)
    };

    // Steps 7–8: the first system server — spawn the VFS from its embedded
    // image and accept its ready callback. The VFS comes first because PS
    // loads program images through it (design §2.6: SPAWN carries the VFS
    // service endpoint as input cap 0).
    if !HAS_VFS_IMAGE {
        return Err(fail_code(STEP_VFS_SPAWNED, 0xE1));
    }
    let vfs_pid = spawn_server(
        raw,
        info,
        self_as,
        region,
        VFS_IMAGE,
        STEP_VFS_SPAWNED,
        None,
    )?;
    let vfs_ready_ep = SP_INIT_EP.load(SpOrdering::Relaxed);
    let vfs_death = SP_DEATH.load(SpOrdering::Relaxed);
    mark(raw, info.debug_ep, STEP_VFS_SPAWNED, vfs_pid);
    let vfs_svc = {
        let ready = {
            let mut sys = Syscalls::new(raw);
            sys.recv(vfs_ready_ep)
                .map_err(|e| fail_code(STEP_VFS_READY, e as u64))?
        };
        if ready.tag.label() != bootstrap::READY_LABEL || ready.words[0] != bootstrap::READY_MAGIC {
            return Err(fail_code(STEP_VFS_READY, 0xE1));
        }
        let svc = ready
            .descriptor(0)
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(fail_code(STEP_VFS_READY, 0xE2))?;
        mark(raw, info.debug_ep, STEP_VFS_READY, ready.words[1]);
        svc
    };

    // Steps 9–10: spawn the process server (embedded image, ADR-023) and
    // accept its ready callback.
    if !HAS_PS_IMAGE {
        mark(raw, info.debug_ep, STEP_SPAWNED, SPAWN_SKIPPED);
        return Ok(());
    }
    let ps_pid = spawn_server(raw, info, self_as, region, PS_IMAGE, STEP_SPAWNED, None)?;
    let ps_ready_ep = SP_INIT_EP.load(SpOrdering::Relaxed);
    let ps_death = SP_DEATH.load(SpOrdering::Relaxed);
    mark(raw, info.debug_ep, STEP_SPAWNED, ps_pid);
    let svc = {
        let ready = {
            let mut sys = Syscalls::new(raw);
            sys.recv(ps_ready_ep)
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
        svc
    };

    // Step 11: CONNECT round-trip (design §2.6, label 0x0101). The v0 packing
    // keeps the version in w0; the three caps (session notification, arg
    // frame, result frame) overlay w1..w3 per the v1 message format; windows
    // are 4 KiB each (design §1.3) so no size words travel.
    let session = mint(
        raw,
        info.factory,
        methods::factory::NEW_NOTIFICATION,
        STEP_CONNECT,
        0xE6,
    )
    .map_err(|c| c | 0x0100 | (((info.factory as u64) & 0xFF) << 24))?;
    let arg_frame = carve_frame(raw, region).map_err(|c| c | 0x0200)?;
    let result_frame = carve_frame(raw, region).map_err(|c| c | 0x0300)?;
    let conn = {
        let mut sys = Syscalls::new(raw);
        let mut connect = Message::new(methods::process::CONNECT);
        connect.tag = connect.tag.with_caps(3);
        connect.words[0] = 1; // protocol version
        let _ = connect.set_descriptor(0, ipc::CapSlot::pack(session, ipc::Rights::SIGNAL));
        let _ = connect.set_descriptor(1, ipc::CapSlot::pack(arg_frame, ipc::Rights::READ));
        let _ = connect.set_descriptor(2, ipc::CapSlot::pack(result_frame, ipc::Rights::WRITE));
        sys.call(svc, &connect)
            .map_err(|e| fail_code(STEP_CONNECT, e as u64) | 0x0400)?
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

    // Step 12: SPAWN a child through PS (design §2.6). The arg window carries
    // the program path ("child") at offset 0 and the argv blob ("42") at
    // offset 6; cap 0 is the VFS service endpoint, so PS resolves the program
    // image through the VFS instead of an embedded copy.
    {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::aspace::MAP);
        m.tag = m.tag.with_caps(1);
        m.words[0] = INIT_WINDOW_VA_BASE;
        m.words[1] = 0b011; // R | W
        let _ = m.set_descriptor(
            0,
            ipc::CapSlot::pack(arg_frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
        );
        sys.invoke(self_as, &m)
            .map_err(|e| fail_code(STEP_SPAWN_CHILD, e as u64))?;
    }
    write_spawn_blob(b"child", &[b"42"]);
    let spawned = {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::process::SPAWN);
        m.tag = m.tag.with_caps(1);
        let _ = m.set_descriptor(
            0,
            ipc::CapSlot::pack(vfs_svc, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
        );
        sys.call(session_ep, &m)
            .map_err(|e| fail_code(STEP_SPAWN_CHILD, e as u64))?
    };
    if spawned.words[0] != 0 || spawned.words[1] == 0 {
        // Encode the server status (and a nonzero pid check) for diagnosis.
        return Err(fail_code(
            STEP_SPAWN_CHILD,
            0xE1 | ((spawned.words[0] as u64 & 0xFFFF) << 8),
        ));
    }
    let child_pid = spawned.words[1];
    mark(raw, info.debug_ep, STEP_SPAWN_CHILD, child_pid);

    // Step 13: WAIT — blocking wait for the child's exit status (design §2.6).
    // WAIT is a non-blocking poll on PS's side (deferred replies need a
    // kernel reply-handle primitive); the caller polls cooperatively.
    let waited = loop {
        let reply = {
            let mut sys = Syscalls::new(raw);
            let mut m = Message::new(methods::process::WAIT);
            m.words[0] = child_pid;
            sys.call(session_ep, &m)
                .map_err(|e| fail_code(STEP_WAIT, e as u64))?
        };
        if reply.words[0] == 0 {
            break reply;
        }
        if reply.words[0] == ipc::status::EWOULDBLOCK as i64 as u64 {
            let _ = Syscalls::new(raw).yield_now();
            continue;
        }
        return Err(fail_code(
            STEP_WAIT,
            0xE1 | ((reply.words[0] as u64 & 0xFF) << 8),
        ));
    };
    if waited.words[1] != 42 {
        return Err(fail_code(STEP_WAIT, 0xE2 | (waited.words[1] << 8)));
    }
    mark(raw, info.debug_ep, STEP_WAIT, waited.words[1]);

    // Step 14: read `/hello` through the VFS over IPC (design §3.3):
    // CONNECT (fresh windows) → OPEN(dir=root, name="hello", READ) →
    // READ into the result window → verify the bytes. The protocol is
    // hand-packed (init is an sdk bin; the vfs crate is not a dependency).
    // Yields the connection endpoint (all later VFS ops go there).
    let vfs_conn = {
        let arg_va = INIT_WINDOW_VA_BASE + 0x1000;
        let result_va = INIT_WINDOW_VA_BASE + 0x2000;
        let session = mint(
            raw,
            info.factory,
            methods::factory::NEW_NOTIFICATION,
            STEP_VFS_READ,
            0xE7,
        )?;
        let arg_frame = carve_frame(raw, region)?;
        let result_frame = carve_frame(raw, region)?;
        for (frame, va) in [(arg_frame, arg_va), (result_frame, result_va)] {
            let mut sys = Syscalls::new(raw);
            let mut m = Message::new(methods::aspace::MAP);
            m.tag = m.tag.with_caps(1);
            m.words[0] = va;
            m.words[1] = 0b011; // R | W
            let _ = m.set_descriptor(
                0,
                ipc::CapSlot::pack(frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
            );
            sys.invoke(self_as, &m)
                .map_err(|e| fail_code(STEP_VFS_READ, e as u64))?;
        }
        let conn_ep = {
            let mut sys = Syscalls::new(raw);
            let mut connect = Message::new(methods::vfs::CONNECT);
            connect.tag = connect.tag.with_caps(3);
            connect.words[0] = 1; // protocol version
            let _ = connect.set_descriptor(0, ipc::CapSlot::pack(session, ipc::Rights::SIGNAL));
            let _ = connect.set_descriptor(
                1,
                ipc::CapSlot::pack(arg_frame, ipc::Rights::READ.union(ipc::Rights::WRITE)),
            );
            let _ = connect.set_descriptor(
                2,
                ipc::CapSlot::pack(
                    result_frame,
                    ipc::Rights::READ
                        .union(ipc::Rights::WRITE)
                        .union(ipc::Rights::MAP),
                ),
            );
            let reply = sys
                .call(vfs_svc, &connect)
                .map_err(|e| fail_code(STEP_VFS_READ, 0xE1 | (e as u64 & 0xFF)))?;
            if reply.words[0] != 0 {
                // Encode the server status for diagnosis.
                return Err(fail_code(
                    STEP_VFS_READ,
                    0xE2 | ((reply.words[0] as u64 & 0xFFFF) << 8),
                ));
            }
            reply
                .descriptor(0)
                .map(|cs| cs.handle())
                .filter(|h| *h != 0)
                .ok_or(fail_code(STEP_VFS_READ, 0xE3))?
        };
        let root_handle = 1u64; // VfsServer opens the root as handle 1 (design §3.2)
        unsafe {
            core::ptr::copy_nonoverlapping(b"hello".as_ptr(), arg_va as *mut u8, 5);
        }
        let file_handle = {
            let mut sys = Syscalls::new(raw);
            let mut open = Message::new(methods::vfs::OPEN);
            open.words[0] = root_handle;
            open.words[1] = (0u64 << 32) | 5; // name: Span { off 0, len 5 } in the arg window
            open.words[2] = methods::vfs_open::READ as u64;
            let reply = sys
                .call(conn_ep, &open)
                .map_err(|e| fail_code(STEP_VFS_READ, 0xE4 | (e as u64 & 0xFF)))?;
            if reply.words[0] != 0 || reply.words[1] == 0 {
                return Err(fail_code(STEP_VFS_READ, 0xE5));
            }
            reply.words[1]
        };
        let count = {
            let mut sys = Syscalls::new(raw);
            let mut read = Message::new(methods::vfs::READ);
            read.words[0] = file_handle;
            read.words[1] = 0;
            read.words[2] = 64;
            read.words[3] = 0; // result-window offset
            let reply = sys
                .call(conn_ep, &read)
                .map_err(|e| fail_code(STEP_VFS_READ, 0xE6 | (e as u64 & 0xFF)))?;
            if reply.words[0] != 0 {
                return Err(fail_code(STEP_VFS_READ, 0xE7));
            }
            reply.words[1]
        };
        let expect = b"helios-vfs-ok";
        let got = unsafe { core::slice::from_raw_parts(result_va as *const u8, expect.len()) };
        if count != expect.len() as u64 || got != expect {
            return Err(fail_code(STEP_VFS_READ, 0xE8));
        }
        mark(raw, info.debug_ep, STEP_VFS_READ, count);
        conn_ep
    };

    // Steps 16–17: run the POSIX personality demo (`/posix`, embedded into
    // the VFS ramfs): a regular process whose whole I/O goes through the
    // personality runtime (bootstrap → heap → VFS client → open/read/write).
    // The SPAWN carries the VFS service endpoint so PS installs it as the
    // child package's `optional[0]` (design §2.3). The demo exits 77.
    {
        unsafe {
            core::ptr::copy_nonoverlapping(b"posix".as_ptr(), INIT_WINDOW_VA_BASE as *mut u8, 5);
        }
        let spawned = {
            write_spawn_blob(b"posix", &[]);
            let mut sys = Syscalls::new(raw);
            let mut m = Message::new(methods::process::SPAWN);
            m.tag = m.tag.with_caps(3);
            let _ = m.set_descriptor(
                0,
                ipc::CapSlot::pack(vfs_svc, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
            );
            // SPAWN descriptor order is (vfs, stdin, stdout, stderr); the
            // console endpoint rides as stdout so the demo can print.
            let _ = m.set_descriptor(1, ipc::CapSlot::NULL);
            let _ = m.set_descriptor(
                2,
                ipc::CapSlot::pack(console_svc, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
            );
            sys.call(session_ep, &m)
                .map_err(|e| fail_code(STEP_POSIX_SPAWN, e as u64))?
        };
        if spawned.words[0] != 0 || spawned.words[1] == 0 {
            return Err(fail_code(
                STEP_POSIX_SPAWN,
                0xE1 | ((spawned.words[0] as u64 & 0xFFFF) << 8),
            ));
        }
        let posix_pid = spawned.words[1];
        mark(raw, info.debug_ep, STEP_POSIX_SPAWN, posix_pid);

        let waited = loop {
            let reply = {
                let mut sys = Syscalls::new(raw);
                let mut m = Message::new(methods::process::WAIT);
                m.words[0] = posix_pid;
                sys.call(session_ep, &m)
                    .map_err(|e| fail_code(STEP_POSIX_WAIT, e as u64))?
            };
            if reply.words[0] == 0 {
                break reply;
            }
            if reply.words[0] == ipc::status::EWOULDBLOCK as i64 as u64 {
                let _ = Syscalls::new(raw).yield_now();
                continue;
            }
            return Err(fail_code(
                STEP_POSIX_WAIT,
                0xE1 | ((reply.words[0] as u64 & 0xFF) << 8),
            ));
        };
        if waited.words[1] != 77 {
            return Err(fail_code(STEP_POSIX_WAIT, 0xE2 | (waited.words[1] << 8)));
        }
        mark(raw, info.debug_ep, STEP_POSIX_WAIT, waited.words[1]);
    }

    // Steps 20–21: the shell — the userland driver (scripted in v0; input
    // awaits UART RX/IRQ work). It spawns commands through PS, reaps them and
    // exits 0 on success.
    {
        write_spawn_blob(b"sh", &[]);
        let spawned = {
            let mut sys = Syscalls::new(raw);
            let mut m = Message::new(methods::process::SPAWN);
            m.tag = m.tag.with_caps(3);
            let _ = m.set_descriptor(
                0,
                ipc::CapSlot::pack(vfs_svc, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
            );
            let _ = m.set_descriptor(1, ipc::CapSlot::NULL);
            let _ = m.set_descriptor(
                2,
                ipc::CapSlot::pack(console_svc, ipc::Rights::SEND.union(ipc::Rights::GRANT)),
            );
            sys.call(session_ep, &m)
                .map_err(|e| fail_code(STEP_SH_SPAWN, e as u64))?
        };
        if spawned.words[0] != 0 || spawned.words[1] == 0 {
            return Err(fail_code(
                STEP_SH_SPAWN,
                0xE1 | ((spawned.words[0] as u64 & 0xFFFF) << 8),
            ));
        }
        let sh_pid = spawned.words[1];
        mark(raw, info.debug_ep, STEP_SH_SPAWN, sh_pid);

        let waited = loop {
            let reply = {
                let mut sys = Syscalls::new(raw);
                let mut m = Message::new(methods::process::WAIT);
                m.words[0] = sh_pid;
                sys.call(session_ep, &m)
                    .map_err(|e| fail_code(STEP_SH_WAIT, e as u64))?
            };
            if reply.words[0] == 0 {
                break reply;
            }
            if reply.words[0] == ipc::status::EWOULDBLOCK as i64 as u64 {
                let _ = Syscalls::new(raw).yield_now();
                continue;
            }
            return Err(fail_code(
                STEP_SH_WAIT,
                0xE1 | ((reply.words[0] as u64 & 0xFF) << 8),
            ));
        };
        // The shell ends its script with `exec child 9`: the process BECOMES
        // the child image, and — because SET_ENTRY keeps the thread's
        // identity — the parent now observes the exec'd program's real exit
        // status (9). (Before ADR-039 composition this raced at 0.)
        if waited.words[1] != 9 {
            return Err(fail_code(STEP_SH_WAIT, 0xE2 | (waited.words[1] << 8)));
        }
        mark(raw, info.debug_ep, STEP_SH_WAIT, waited.words[1]);
    }

    // Shutdown: console down (KILL acks, then it exits) and reap.
    {
        let mut sys = Syscalls::new(raw);
        let kill = Message::new(methods::process::KILL);
        let ack = sys
            .call(console_svc, &kill)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
        if ack.words[0] != 0 {
            return Err(fail_code(STEP_CHILD_EXIT, 0xE4));
        }
    }
    {
        let mut sys = Syscalls::new(raw);
        sys.recv(console_death)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
    }
    {
        let mut sys = Syscalls::new(raw);
        let kill = Message::new(methods::process::KILL);
        let ack = sys
            .call(vfs_conn, &kill)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
        if ack.words[0] != 0 {
            return Err(fail_code(STEP_CHILD_EXIT, 0xE3));
        }
    }
    {
        let mut sys = Syscalls::new(raw);
        sys.recv(vfs_death)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
    }

    // Shutdown: PS down (KILL acks, then PS exits) and reap — the death
    // notification fires when it exits (ADR-007 §6).
    {
        let mut sys = Syscalls::new(raw);
        let mut kill = Message::new(methods::process::KILL);
        kill.words[0] = ps_pid;
        let ack = sys
            .call(session_ep, &kill)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
        if ack.words[0] != 0 {
            return Err(fail_code(STEP_CHILD_EXIT, 0xE2));
        }
    }
    {
        let mut sys = Syscalls::new(raw);
        sys.recv(ps_death)
            .map_err(|e| fail_code(STEP_CHILD_EXIT, e as u64))?;
    }
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

/// What a spawned server hands back to the launcher: everything lives in the
/// pinned `.data` atomics (SP_INIT_EP/SP_DEATH) and the function returns only
/// the pid — a scalar return goes in registers, avoiding the compiler's
/// struct-return (sret) slot entirely (it was observed corrupted across the
/// spawn's syscalls; harness pins alone could not protect a compiler temp).
// Pinned spawn handles, in .data (live locals across this inlined spawn path
// were observed clobbered — a stale value silently mis-delivers caps and
// misbinds death notifications; atomics are immune. Same fix as PS).
use core::sync::atomic::Ordering as SpOrdering;
static SP_BOOT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_INIT_EP: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_DEATH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_S0: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_S1: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_S2: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_S3: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_THREAD: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SP_REGION: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Spawn a system server from an embedded image: fresh AS + ELF load,
/// endpoints/notifications, thread, ADR-009 package (with Factory tail),
/// death binding. `step` tags every failure for the serial marker stream.
fn spawn_server(
    raw: &mut X86_64Syscalls,
    info: &BootInfo,
    self_as: Handle,
    region: Handle,
    image: &[u8],
    step: u64,
    extra: Option<CapSlot>,
) -> Result<u64> {
    SP_REGION.store(region, SpOrdering::Relaxed);
    let elf = ElfImage::parse(image).map_err(|e| fail_code(step, e as u64))?;
    let ops = loader::plan(&elf, INIT_SCRATCH_VA_BASE)
        .map_err(|e| fail_code(step, 0xE0_00 | (e as u64 & 0xFF)))?;

    let child_as = {
        let mut sys = Syscalls::new(raw);
        sys.invoke(
            info.factory,
            &Message::new(methods::factory::NEW_ADDRESS_SPACE),
        )
        .map_err(|e| fail_code(step, 0xE0_01 | (e as u64 & 0xFF)))?
        .words[0] as Handle
    };
    if child_as == 0 {
        return Err(fail_code(step, 0xE0_02));
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
            image,
        )
        .map_err(|e| fail_code(step, 0xE1_00 | (e as u64 & 0xFF)))?;
        loader::map_anon(
            &mut sys,
            child_as,
            USER_STACK_TOP - CHILD_STACK_PAGES * 4096,
            CHILD_STACK_PAGES,
            STACK_FLAGS,
        )
        .map_err(|e| fail_code(step, 0xE1_01 | (e as u64 & 0xFF)))?;
    }

    // Endpoints + notifications for the package. Every handle travels through
    // a .data atomic: live locals across this inlined spawn path were observed
    // clobbered (a stale value silently misbinds/mis-delivers; same fix as PS).
    let bootstrap_ep = mint(
        raw,
        info.factory,
        methods::factory::NEW_ENDPOINT,
        step,
        0xE2,
    )?;
    SP_BOOT.store(bootstrap_ep, SpOrdering::Relaxed);
    let init_ep = mint(
        raw,
        info.factory,
        methods::factory::NEW_ENDPOINT,
        step,
        0xE3,
    )?;
    SP_INIT_EP.store(init_ep, SpOrdering::Relaxed);
    let death = mint(
        raw,
        info.factory,
        methods::factory::NEW_NOTIFICATION,
        step,
        0xE4,
    )?;
    SP_DEATH.store(death, SpOrdering::Relaxed);
    for slot in 0..bootstrap::SESSION_POOL {
        let s = mint(
            raw,
            info.factory,
            methods::factory::NEW_NOTIFICATION,
            step,
            0xE5,
        )?;
        match slot {
            0 => SP_S0.store(s, SpOrdering::Relaxed),
            1 => SP_S1.store(s, SpOrdering::Relaxed),
            2 => SP_S2.store(s, SpOrdering::Relaxed),
            _ => SP_S3.store(s, SpOrdering::Relaxed),
        }
    }

    // Child thread (ADR-017 packing): w0 = entry; caps[0] = AS (input),
    // caps[1] = fault EP (none v0), caps[2] = bootstrap EP.
    let (thread_cap, pid) = {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::factory::NEW_THREAD);
        m.tag = m.tag.with_caps(3);
        m.words[0] = elf.entry;
        let _ = m.set_descriptor(0, CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
        let _ = m.set_descriptor(1, CapSlot::NULL);
        let _ = m.set_descriptor(
            2,
            CapSlot::pack(SP_BOOT.load(SpOrdering::Relaxed), Rights::RECV),
        );
        let reply = sys
            .invoke(info.factory, &m)
            .map_err(|e| fail_code(step, 0xE6_00 | (e as u64 & 0xFF)))?;
        (reply.words[0] as Handle, reply.words[2])
    };
    if thread_cap == 0 {
        return Err(fail_code(step, 0xE6_01));
    }
    SP_THREAD.store(thread_cap, SpOrdering::Relaxed);

    // Bind the child's death notification to its thread (ADR-007 §6).
    {
        let mut sys = Syscalls::new(raw);
        let mut m = Message::new(methods::thread::BIND_DEATH_NOTIFICATION);
        m.tag = m.tag.with_caps(1);
        let _ = m.set_descriptor(
            0,
            CapSlot::pack(SP_DEATH.load(SpOrdering::Relaxed), Rights::SIGNAL),
        );
        sys.invoke(SP_THREAD.load(SpOrdering::Relaxed), &m)
            .map_err(|e| fail_code(step, 0xE7_00 | (e as u64 & 0xFF)))?;
    }

    // ADR-009 package: §2.3 prefix + ADR-023 tail[0] = Factory.
    // Manual chunked delivery: values are loaded from `.data` atomics and
    // packed into the outgoing Message immediately before each send, so no
    // stack structure spans a syscall (a live-local clobbering kernel bug —
    // see TASKS.md — corrupts anything that does; proven by the four
    // spawn-handle pins).
    let sr = Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT);
    let boot = SP_BOOT.load(SpOrdering::Relaxed);
    {
        let mut sys = Syscalls::new(raw);
        let mut hdr = Message::new(bootstrap::PACKAGE_LABEL);
        hdr.words[0] = bootstrap::FIXED_CAPS as u64 + if extra.is_some() { 2 } else { 1 };
        hdr.words[1] = pid;
        sys.send(boot, &hdr)
            .map_err(|e| fail_code(step, 0xE8_00 | (e as u64 & 0xFF)))?;

        let mut c1 = Message::new(bootstrap::PACKAGE_LABEL);
        c1.tag = c1.tag.with_caps(4);
        let _ = c1.set_descriptor(0, CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
        let _ = c1.set_descriptor(
            1,
            CapSlot::pack(SP_THREAD.load(SpOrdering::Relaxed), Rights::CONTROL),
        );
        let _ = c1.set_descriptor(
            2,
            CapSlot::pack(SP_REGION.load(SpOrdering::Relaxed), Rights::GRANT),
        );
        let _ = c1.set_descriptor(3, CapSlot::pack(SP_S0.load(SpOrdering::Relaxed), sr));
        sys.send(boot, &c1)
            .map_err(|e| fail_code(step, 0xE8_01 | (e as u64 & 0xFF)))?;

        let mut c2 = Message::new(bootstrap::PACKAGE_LABEL);
        c2.tag = c2.tag.with_caps(4);
        let _ = c2.set_descriptor(0, CapSlot::pack(SP_S1.load(SpOrdering::Relaxed), sr));
        let _ = c2.set_descriptor(1, CapSlot::pack(SP_S2.load(SpOrdering::Relaxed), sr));
        let _ = c2.set_descriptor(2, CapSlot::pack(SP_S3.load(SpOrdering::Relaxed), sr));
        let _ = c2.set_descriptor(
            3,
            CapSlot::pack(
                SP_INIT_EP.load(SpOrdering::Relaxed),
                Rights::SEND.union(Rights::GRANT),
            ),
        );
        sys.send(boot, &c2)
            .map_err(|e| fail_code(step, 0xE8_02 | (e as u64 & 0xFF)))?;

        let extra_count = if extra.is_some() { 2 } else { 1 };
        let mut c3 = Message::new(bootstrap::PACKAGE_LABEL);
        c3.tag = c3.tag.with_caps(extra_count);
        let _ = c3.set_descriptor(0, CapSlot::pack(info.factory, Rights::ALL));
        if let Some(x) = extra {
            let _ = c3.set_descriptor(1, x);
        }
        sys.send(boot, &c3)
            .map_err(|e| fail_code(step, 0xE8_03 | (e as u64 & 0xFF)))?;
    }

    Ok(pid)
}

/// v0.2 SPAWN payload (see `sdk::spawn`): the path and argv/env areas live
/// in the **connect arg window** — words are not usable for spans when the
/// SPAWN carries 3+ capability descriptors (descriptors overlay the trailing
/// words in `ipc::Message`), so the window is the only safe data channel.
fn write_spawn_blob(path: &[u8], argv: &[&[u8]]) {
    let ok = sdk::spawn::write_spawn_blob(INIT_WINDOW_VA_BASE, path, argv, &[]);
    debug_assert_eq!(ok, Some(()));
}

fn mint(
    raw: &mut X86_64Syscalls,
    factory: Handle,
    method: u16,
    step: u64,
    errno: u64,
) -> Result<Handle> {
    let mut sys = Syscalls::new(raw);
    let handle = sys
        .invoke(factory, &Message::new(method))
        .map_err(|e| fail_code(step, errno | (e as u64 & 0xFF)))?
        .words[0] as Handle;
    if handle == 0 {
        return Err(fail_code(step, errno | 0xFF));
    }
    Ok(handle)
}

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
