//! `/cat` — the first real utility program: concatenates each argv path's
//! contents to stdout (multiple arguments exercise the multi-arg argv
//! contract end-to-end: blob → crafted stack → `sdk::args` → VFS reads).
//! Exits 0 on success; small codes identify the failing file.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;

use personality::layout::HEAP_VA_BASE;
use personality::runtime::{exit, Runtime};
use sdk::args::Args;
use sdk::bootstrap::receive;
use sdk::heap::RegionSource;
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::sys::SysHeap;
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

sdk::sys::entry_point!(cat_main);

extern "C" fn cat_main(argc: u64, argv_va: u64, envp_va: u64) -> ! {
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

    // With no file arguments, `cat` is a stdin->stdout relay (POSIX): read
    // console::WRITE chunks until the writer's EOF, stripping the chunk NUL
    // padding. This makes `cmd | cat | ...` and `cat < file` work.
    if args.argc() <= 1 {
        if let Some(stdin) = rt.stdin_handle() {
            while let Ok(m) = sys.recv(stdin) {
                if m.tag.label() == sdk::methods::console::EOF {
                    break;
                }
                for w in m.words {
                    let bytes = w.to_le_bytes();
                    let mut end = 8;
                    while end > 0 && bytes[end - 1] == 0 {
                        end -= 1;
                    }
                    if end > 0 {
                        let _ = rt.write_stdout(&mut sys, &bytes[..end]);
                    }
                }
            }
        }
        rt.exit(&mut sys, 0)
    }

    // Otherwise argv[0] is the program name; every other argument is a file.
    let mut fail = 0x10i32;
    for i in 1..args.argc() {
        let Some(path) = args.arg(i) else { break };
        let mut buf = [0u8; 256];
        let n = match rt.vfs.read_file(&mut sys, path, &mut buf) {
            Ok(n) => n,
            Err(e) => exit(&mut sys, fail | (e & 0xFF)),
        };
        let _ = rt.write_stdout(&mut sys, &buf[..n]);
        fail += 2;
    }
    rt.exit(&mut sys, 0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0006)
}
