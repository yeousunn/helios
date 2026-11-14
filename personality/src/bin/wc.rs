//! `/wc` — count bytes and newlines read from stdin (a stream endpoint,
//! package `optional[1]`), stopping at the writer's `console::EOF` marker.
//! The consumer half of the first pipeline: `cat file | wc`.

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
    main = sym wc_main,
);

extern "C" fn wc_main(argc: u64, argv_va: u64, envp_va: u64) -> ! {
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
    let _args = Args::new(argc as usize, argv_va, envp_va);

    let mut sys = Syscalls::new(&mut raw);
    let mut rt = match Runtime::new(&mut sys, package) {
        Ok(r) => r,
        Err(e) => exit(&mut sys, e),
    };

    let mut bytes = 0u64;
    let mut lines = 0u64;
    if let Some(stdin) = rt.stdin_handle() {
        // `Err` = endpoint gone: treat as EOF.
        while let Ok(msg) = sys.recv(stdin) {
            if msg.tag.label() == sdk::methods::console::EOF {
                break;
            }
            for w in msg.words {
                for b in w.to_le_bytes() {
                    if b == 0 {
                        continue;
                    }
                    bytes += 1;
                    if b == b'\n' {
                        lines += 1;
                    }
                }
            }
        }
    }

    let mut out = [0u8; 32];
    let mut n = 0usize;
    let put = |bytes_text: &[u8], out: &mut [u8; 32], n: &mut usize| {
        for &b in bytes_text {
            if *n < 32 {
                out[*n] = b;
                *n += 1;
            }
        }
    };
    put(b"bytes=", &mut out, &mut n);
    let mut digits = [0u8; 12];
    put(write_u64(bytes, &mut digits), &mut out, &mut n);
    put(b" lines=", &mut out, &mut n);
    put(write_u64(lines, &mut digits), &mut out, &mut n);
    put(b"\n", &mut out, &mut n);
    let _ = rt.write_stdout(&mut sys, &out[..n]);
    rt.exit(&mut sys, 0)
}

/// Write `v` as decimal into `buf`, returning the used slice.
fn write_u64(mut v: u64, buf: &mut [u8; 12]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &buf[i..]
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
