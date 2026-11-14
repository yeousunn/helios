//! `/echo` — write argv[1..] to stdout, space-separated, newline-terminated.
//! The smallest possible argv-to-stdout contract test as a real utility.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::arch::global_asm;
use core::panic::PanicInfo;

use personality::layout::HEAP_VA_BASE;
use personality::runtime::{exit, Runtime};
use sdk::args::Args;
use sdk::bootstrap::receive;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

global_asm!(
    ".global _start",
    "_start:",
    "mov rdi, [rsp - 8]",
    "mov rsi, [rsp - 16]",
    "mov rdx, [rsp - 24]",
    "sub rsp, 64",
    "and rsp, -16",
    "jmp {main}",
    main = sym echo_main,
);

extern "C" fn echo_main(argc: u64, argv_va: u64, envp_va: u64) -> ! {
    let mut raw = X86_64Syscalls;

    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match receive(&mut sys) {
            Ok(p) => p,
            Err(e) => exit(&mut sys, e),
        }
    };

    let span = {
        let mut src = RegionSource::new(
            &mut raw,
            package.region,
            package.aspace,
            HEAP_VA_BASE,
            HEAP_CHUNK,
        );
        src.map_startup(HEAP_CHUNKS)
    };
    let (start, len) = match span {
        Ok(v) => v,
        Err(e) => exit(&mut Syscalls::new(&mut raw), e),
    };
    if HEAP.init(start, len).is_err() {
        exit(&mut Syscalls::new(&mut raw), 0xE2);
    }
    // The heap must be up before the argv parse: `sdk::args::Args::new`
    // copies every argument into an owned Vec, so running it against the
    // uninitialized allocator is an allocation failure (a panic, not an
    // error code). The crafted strings sit in the lower half of the top
    // stack page, well below this shallow call chain (ADR-055's clobbering
    // only bites linrun's deep chain).
    let args = Args::new(argc as usize, argv_va, envp_va);

    let mut sys = Syscalls::new(&mut raw);
    let mut rt = match Runtime::new(&mut sys, package) {
        Ok(r) => r,
        Err(e) => exit(&mut sys, e),
    };

    let mut first = true;
    for i in 1..args.argc() {
        let Some(a) = args.arg(i) else { break };
        if !first {
            let _ = rt.write_stdout(&mut sys, b" ");
        }
        first = false;
        let _ = rt.write_stdout(&mut sys, a);
    }
    let _ = rt.write_stdout(&mut sys, b"\n");
    exit(&mut sys, 0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0008)
}
