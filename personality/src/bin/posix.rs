//! POSIX personality demo program (`/posix` in the VFS ramfs): a spawned
//! process whose whole I/O goes through the personality runtime — bootstrap
//! package → heap → VFS client → open/read/write over IPC. Proves the native
//! runtime-wrapper path (PLAN.md Phase 3 slice 1).
//!
//! Behavior (smoke; init asserts the exit status):
//!   1. read `hello` through the VFS (v0: root-relative names) and
//!      byte-verify `"helios-vfs-ok"`;
//!   2. create + write `posix-log` = `"helios-posix-ok"`, read it back,
//!      byte-verify;
//!   3. exit(77) on success. Small codes identify the failing step.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

use core::panic::PanicInfo;

use personality::layout::HEAP_VA_BASE;
use personality::posix::O_RDONLY;
use personality::runtime::{exit, Runtime};
use sdk::bootstrap::receive;
use sdk::heap::RegionSource;
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::sys::SysHeap;
use sdk::syscall::{Syscalls, X86_64Syscalls};

#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

sdk::sys::entry_point!(posix_main);

/// Success status asserted by init's `WAIT` (marker 17).
const OK: i32 = 77;

/// The crafted header (argc/argv/envp) is captured by the shared entry stub;
/// this demo takes no arguments, so they are ignored here.
extern "C" fn posix_main(_argc: u64, _argv_va: u64, _envp_va: u64) -> ! {
    let mut raw = X86_64Syscalls;

    // Bootstrap package (handle 1): [as, thread, region, sessions x4, ps_ep]
    // + optional[0] = the VFS service endpoint the SPAWN caller supplied.
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match receive(&mut sys) {
            Ok(p) => p,
            Err(e) => exit(&mut sys, e),
        }
    };

    // Heap over the package region (1 MiB, the PS/init convention).
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

    // 1. Read /hello and verify. (`0xEnnn`: open/read failed with errno nnn;
    // 2: content mismatch — diagnostic codes the smoke can decode.)
    let mut buf = [0u8; 32];
    let fd = match rt.vfs.open(&mut sys, b"hello", O_RDONLY) {
        Ok(fd) => fd,
        Err(e) => exit(&mut sys, 0xE000 | (e & 0xFF)),
    };
    let n = match rt.vfs.read(&mut sys, fd, &mut buf) {
        Ok(n) => n,
        Err(e) => exit(&mut sys, 0xE100 | (e & 0xFF)),
    };
    let _ = rt.vfs.close(&mut sys, fd);
    if n != 13 || &buf[..13] != b"helios-vfs-ok" {
        exit(&mut sys, 2);
    }

    // 2. Create + write /posix-log, read back, verify.
    if rt
        .vfs
        .write_file(&mut sys, b"posix-log", b"helios-posix-ok")
        .is_err()
    {
        exit(&mut sys, 3);
    }
    let mut back = [0u8; 32];
    let n = match rt.vfs.read_file(&mut sys, b"posix-log", &mut back) {
        Ok(n) => n,
        Err(_) => exit(&mut sys, 4),
    };
    if n != 15 || &back[..15] != b"helios-posix-ok" {
        exit(&mut sys, 5);
    }

    // 3. Spawn a grandchild through PS (the shell's engine): `child` exits
    //    with its argv[0], so WAIT must observe 42. This exercises a full
    //    process tree (init -> posix -> child) over one process server.
    let vfs_ep = rt.package.optional[0].map(|cs| cs.handle());
    let child = match rt.ps.spawn(
        &mut sys,
        b"child",
        &[b"42"],
        &[],
        vfs_ep,
        None,
        rt.stdout_handle(),
    ) {
        Ok(pid) => pid,
        Err(e) => exit(&mut sys, 0x200 | (e & 0xFF)),
    };
    let status = match rt.ps.wait(&mut sys, child) {
        Ok(s) => s,
        Err(e) => exit(&mut sys, 0x300 | (e & 0xFF)),
    };
    if status != 42 {
        exit(&mut sys, 0x400 | (status & 0xFF));
    }

    // 4. Report on stdout (the console endpoint the launcher supplied) and
    //    exit; the smoke verifies the serial line and the status.
    let _ = rt.write_stdout(&mut sys, b"helios-posix-ok\n");
    debug_assert_eq!(O_RDONLY, 0);
    exit(&mut sys, OK)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0003)
}
