//! Helios shell (v0, scripted — input waits on UART RX/IRQ work): drives the
//! system through the personality runtime. The compiled-in script spawns
//! commands through PS, reaps them, checks their exit statuses and reports on
//! the console. Exits 0 on success; small codes identify the failing step.

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
    main = sym sh_main,
);

extern "C" fn sh_main(argc: u64, argv: *const *const u8, envp: *const *const u8) -> ! {
    let _args = unsafe { Args::new(argc, argv, envp) };
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

    let mut sys = Syscalls::new(&mut raw);
    let mut rt = match Runtime::new(&mut sys, package) {
        Ok(r) => r,
        Err(e) => exit(&mut sys, e),
    };

    let _ = rt.write_stdout(&mut sys, b"helios sh v0\n");

    // Script: run each command, verify its exit status.
    let vfs_ep = rt.package.optional[0].map(|cs| cs.handle());
    let stdout = rt.stdout_handle();
    let script: [(&[u8], &[&[u8]], i32); 2] = [(b"child", &[b"7"], 7), (b"child", &[b"9"], 9)];
    let mut fail = 0x10;
    for (path, args, expect) in script {
        let pid = match rt.ps.spawn(&mut sys, path, args, vfs_ep, stdout) {
            Ok(pid) => pid,
            Err(e) => exit(&mut sys, fail | (e & 0xFF)),
        };
        let status = match rt.ps.wait(&mut sys, pid) {
            Ok(s) => s,
            Err(e) => exit(&mut sys, (fail + 1) | (e & 0xFF)),
        };
        if status != expect {
            exit(&mut sys, fail + 2);
        }
        fail += 4;
    }

    let _ = rt.write_stdout(&mut sys, b"sh ok\n");
    exit(&mut sys, 0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0005)
}
