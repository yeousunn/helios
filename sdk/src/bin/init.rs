//! The Helios init process — the first userspace task (ADR-018, syscall-abi §8).
//!
//! Built for `x86_64-unknown-none` with `--features user`:
//! ```text
//! cargo build -p sdk --bin init --features user --target x86_64-unknown-none
//! ```
//! Entry: `_start` with `rdi` = pointer to the kernel-written BootInfo block
//! (inside init's first stack page).
//!
//! What it does (the Phase-1 acceptance test): parse BootInfo, report liveness
//! through the debug endpoint, mint an endpoint through the Factory, round-trip
//! a message over IPC v1 to itself, revoke the endpoint, exit cleanly.
//! Every step logs `MARK | step` in `w0` and a payload in `w1` via the debug
//! endpoint, so the QEMU harness can assert on the serial log deterministically.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

use ipc::Message;
use sdk::bootinfo::{BootInfo, MAX_LEN};
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls};

/// Log marker: "INIT" in the high bytes, step number in the low byte.
const MARK: u64 = 0x494E_4954_0000_0000;
const STEP_ALIVE: u64 = 1;
const STEP_BOOTINFO: u64 = 2;
const STEP_ENDPOINT: u64 = 3;
const STEP_IPC: u64 = 4;
const STEP_REVOKE: u64 = 5;
const STEP_DONE: u64 = 0x0F;
/// Failure marker family for exits: `0xDEAD_0000_00SS_EEEE` (step, errno).
const FAIL: u64 = 0xDEAD_0000_0000_0000;

const DEBUG_LABEL: u16 = 0x0001;
const PING_LABEL: u16 = 0x4900;
const PING_WORD: u64 = 0x1234_5678_9ABC_DEF0;

type Result<T> = core::result::Result<T, u64>;

#[no_mangle]
#[allow(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "entry point: the ABI passes a kernel-owned BootInfo pointer; validity is checked by parse"
)]
pub extern "C" fn _start(bootinfo_ptr: *const u8) -> ! {
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);

    let info = match unsafe { read_bootinfo(bootinfo_ptr) } {
        Ok(info) => info,
        Err(errno) => sys.exit(fail_code(STEP_BOOTINFO, errno) as i32),
    };

    mark(&mut sys, info.debug_ep, STEP_ALIVE, 0);
    mark(
        &mut sys,
        info.debug_ep,
        STEP_BOOTINFO,
        info.region_count as u64,
    );

    match run(&mut sys, &info) {
        Ok(()) => {
            mark(&mut sys, info.debug_ep, STEP_DONE, 0);
            sys.exit(0);
        }
        Err(code) => sys.exit(code as i32),
    }
}

fn run(sys: &mut Syscalls<'_, X86_64Syscalls>, info: &BootInfo) -> Result<()> {
    // Mint an endpoint through the Factory.
    let mut invoke = Message::new(methods::factory::NEW_ENDPOINT);
    invoke.words = [0; 4];
    let reply = map_err(sys.invoke(info.factory, &invoke), STEP_ENDPOINT)?;
    let endpoint = reply.words[0] as u32;
    if endpoint == 0 {
        return Err(fail_code(STEP_ENDPOINT, 0xE0));
    }
    mark(sys, info.debug_ep, STEP_ENDPOINT, endpoint as u64);

    // IPC v1 self round-trip: one-message mailbox takes the send immediately.
    let mut ping = Message::new(PING_LABEL);
    ping.words[0] = PING_WORD;
    map_err(sys.send(endpoint, &ping), STEP_IPC)?;
    let echo = map_err(sys.recv(endpoint), STEP_IPC)?;
    if echo.tag.label() != PING_LABEL || echo.words[0] != PING_WORD {
        return Err(fail_code(STEP_IPC, 0xE1));
    }
    mark(sys, info.debug_ep, STEP_IPC, echo.words[0]);

    // Give the endpoint back (DELETE mode).
    map_err(sys.cap_revoke(endpoint, 1), STEP_REVOKE)?;
    mark(sys, info.debug_ep, STEP_REVOKE, 0);
    Ok(())
}

fn map_err<T>(r: core::result::Result<T, i32>, step: u64) -> Result<T> {
    r.map_err(|e| fail_code(step, e as u64))
}

const fn fail_code(step: u64, errno: u64) -> u64 {
    FAIL | ((step & 0xFF) << 16) | (errno & 0xFFFF)
}

/// Log one marker through the debug endpoint (SEND-only capability).
fn mark(sys: &mut Syscalls<'_, X86_64Syscalls>, debug_ep: u32, step: u64, value: u64) {
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
    let mut raw = X86_64Syscalls;
    let mut sys = Syscalls::new(&mut raw);
    sys.exit((FAIL | 0x0BAD_0000) as i32)
}

/// init is allocation-free, but the SDK lib references `alloc` (window/byte
/// helpers), so the linker requires a global allocator. Any allocation here
/// would be a bug — fail the allocation, which routes into the panic path.
struct FailAlloc;

// SAFETY: `alloc` returns null (allocation always fails, never UB) and
// `dealloc` ignores its pointer (nothing was ever allocated).
unsafe impl core::alloc::GlobalAlloc for FailAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static FAIL_ALLOC: FailAlloc = FailAlloc;
