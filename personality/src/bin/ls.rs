//! `/ls` — list directories (each argv path; default: the cwd). Entries print
//! one per line, directories marked with a trailing `/`. Exits 0.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;

use personality::layout::HEAP_VA_BASE;
use personality::runtime::{exit, Runtime};
use personality::vfs::KIND_DIR;
use sdk::args::Args;
use sdk::bootstrap::receive;
use sdk::heap::RegionSource;
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::sys::SysHeap;
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

sdk::sys::entry_point!(ls_main);

extern "C" fn ls_main(argc: u64, argv_va: u64, envp_va: u64) -> ! {
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

    // No arguments: list the cwd. Otherwise: resolve + list each path.
    let paths = args.argc().saturating_sub(1);
    let mut fail = 0x10i32;
    for i in 0..=paths {
        // i == 0 with no args uses the cwd handle; otherwise resolve arg i.
        let dir = if paths == 0 {
            rt.vfs.cwd()
        } else if i == 0 {
            continue;
        } else {
            let Some(path) = args.arg(i) else { break };
            match rt.vfs.walk_path(&mut sys, path) {
                Ok(h) => h,
                Err(e) => exit(&mut sys, fail | (e & 0xFF)),
            }
        };
        let mut cursor = 0u64;
        let mut name = [0u8; 64];
        loop {
            match rt.vfs.readdir(&mut sys, dir, cursor, &mut name) {
                Ok(Some((next, kind, n))) => {
                    let _ = rt.write_stdout(&mut sys, &name[..n]);
                    if kind == KIND_DIR {
                        let _ = rt.write_stdout(&mut sys, b"/");
                    }
                    let _ = rt.write_stdout(&mut sys, b"\n");
                    if next == 0 {
                        break;
                    }
                    cursor = next;
                }
                Ok(None) => break,
                Err(e) => exit(&mut sys, fail | (e & 0xFF)),
            }
        }
        fail += 2;
    }
    exit(&mut sys, 0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0007)
}
