//! v0 spawn payload: the app that a PS-spawned child runs (embedded into the
//! process server via `CHILD_IMAGE`; design §2.4/§2.6 SPAWN).
//!
//! Protocol hygiene: every child receives its ADR-009 bootstrap package
//! first (PS's `deliver` parks per chunk until consumed — skipping this
//! deadlocks the spawner), then reads its initial stack, which PS crafts
//! (v0 convention, `servers/process/src/bin/ps.rs`):
//!
//! ```text
//! entry rsp = sdk::layout::USER_STACK_TOP
//! [rsp - 8]  = argc (u64)
//! [rsp - 16] = argv[0] pointer (u64, VA)
//! [rsp - 32 ..] = NUL-terminated argv strings (written downward)
//! ```
//!
//! The smoke behavior: exit with argv[0] parsed as a decimal number — proof
//! that arg-window → PS → child-stack data flow and exit-status propagation
//! (PS `WAIT`) work end to end.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::global_asm;
use core::panic::PanicInfo;

use sdk::heap::GlobalHeap;
use sdk::syscall::{Syscalls, X86_64Syscalls};

/// The sdk rlib links `alloc`; a handler satisfies the link even though this
/// child allocates nothing (initializing the heap is optional).
#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

// Capture the crafted header in registers BEFORE any Rust code runs: the
// first prologue push would overwrite [sp-8]/[sp-16]. Then move sp safely
// below the header so the rest of the program cannot clobber it either.
global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, [rsp - 8]",  // argc
    "mov rsi, [rsp - 16]", // argv[0]
    "sub rsp, 32",
    "and rsp, -16",
    "jmp {main}",
    main = sym child_main,
);

/// `argc`/`argv[0]` were read by the entry stub (v0: single argv).
extern "C" fn child_main(argc: u64, raw_argv0: *const u8) -> ! {
    let mut raw = X86_64Syscalls;
    // Consume the bootstrap package so the spawner's `deliver` completes.
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match sdk::bootstrap::receive(&mut sys) {
            Ok(p) => Some(p),
            Err(_) => None,
        }
    };
    // Diagnostic: echo the crafted argv through a caller-supplied console
    // endpoint (package `optional[2]`) before exiting — makes stack-crafting
    // bugs visible on the serial line.
    if let Some(p) = package {
        if let Some(console) = p.optional.get(2).copied().flatten() {
            if argc != 0 {
                let mut sys = Syscalls::new(&mut raw);
                let mut m = ipc::Message::new(sdk::methods::console::WRITE);
                let mut n = 0usize;
                let prefix = b"argv=";
                for b in prefix {
                    m.words[n / 8] |= (*b as u64) << ((n % 8) * 8);
                    n += 1;
                }
                // Up to 16 argv bytes, NUL/Space-safe: replace non-printables.
                let mut i = 0isize;
                while n < 32 && i < 16 {
                    let c = unsafe { *raw_argv0.offset(i) };
                    if c == 0 || !c.is_ascii_graphic() {
                        break;
                    }
                    m.words[n / 8] |= (c as u64) << ((n % 8) * 8);
                    n += 1;
                    i += 1;
                }
                let _ = sys.send(console.handle(), &m);
            }
        }
    }
    let status = if argc == 0 {
        -1 // no argv: PS did not craft the stack (diagnostic)
    } else {
        let first = unsafe { *raw_argv0 };
        if !first.is_ascii_digit() {
            -2 // argv[0] does not start with a digit (diagnostic)
        } else {
            parse_dec(raw_argv0)
        }
    };
    Syscalls::new(&mut raw).exit(status)
}

/// Parse a leading decimal integer (0 on empty/garbage), saturating.
fn parse_dec(p: *const u8) -> i32 {
    let mut value: i32 = 0;
    let mut i = 0isize;
    loop {
        let c = unsafe { *p.offset(i) };
        if !c.is_ascii_digit() {
            return value;
        }
        value = value.saturating_mul(10).saturating_add((c - b'0') as i32);
        i += 1;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0001)
}
