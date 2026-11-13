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
// first prologue push would overwrite [sp-8..sp-24]. Then move sp safely
// below the header so the rest of the program cannot clobber it either
// (v0.2 entry contract, `sdk::args`).
global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, [rsp - 8]",  // argc
    "mov rsi, [rsp - 16]", // argv*
    "mov rdx, [rsp - 24]", // envp*
    "sub rsp, 64",
    "and rsp, -16",
    "jmp {main}",
    main = sym child_main,
);

/// The crafted argv/envp (v0.2 entry contract) were captured by the stub.
extern "C" fn child_main(argc: u64, argv: *const *const u8, envp: *const *const u8) -> ! {
    let args = unsafe { sdk::args::Args::new(argc, argv, envp) };
    let mut raw = X86_64Syscalls;
    // S11 attack mode: `argv[0] == "attack"` runs the kernel-hardening attack
    // cases (sdk::attack) instead of the numeric-argv smoke. init spawns this
    // as a new marker step; exit 0 = every bad call was rejected.
    if matches!(args.arg(0), Some(b"attack")) {
        let status = {
            let mut sys = Syscalls::new(&mut raw);
            match sdk::bootstrap::receive(&mut sys) {
                Ok(package) => sdk::attack::run(&mut sys, &package),
                Err(_) => sdk::attack::FAIL_NO_PACKAGE,
            }
        };
        Syscalls::new(&mut raw).exit(status)
    }
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
    // bugs visible on the serial line. All args, space-joined.
    if let Some(p) = package {
        if let Some(console) = p.optional.get(2).copied().flatten() {
            if args.argc() != 0 {
                let mut sys = Syscalls::new(&mut raw);
                let mut m = ipc::Message::new(sdk::methods::console::WRITE);
                let mut n = 0usize;
                let mut put = |bytes: &[u8]| {
                    for &b in bytes {
                        if n < 32 {
                            m.words[n / 8] |= (b as u64) << ((n % 8) * 8);
                            n += 1;
                        }
                    }
                };
                put(b"argv=");
                for i in 0..args.argc() {
                    if i != 0 {
                        put(b" ");
                    }
                    if let Some(a) = args.arg(i) {
                        put(a);
                    }
                }
                if args.envc() != 0 {
                    put(b"|env=");
                    for i in 0..args.envc() {
                        if i != 0 {
                            put(b" ");
                        }
                        if let Some(e) = args.env(i) {
                            put(e);
                        }
                    }
                }
                let _ = sys.send(console.handle(), &m);
            }
        }
    }
    Syscalls::new(&mut raw).exit(args.arg0_as_status())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0001)
}
