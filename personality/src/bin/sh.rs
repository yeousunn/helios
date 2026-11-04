//! Helios shell (v0, scripted — input waits on UART RX/IRQ work): drives the
//! system through the personality runtime. A compiled-in command table mixes
//! builtins (`echo`, `cat` — over the VFS) with external programs spawned
//! through PS; exit statuses are checked and reported. Exits 0 on success;
//! small codes identify the failing step.

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

/// One script entry.
enum Command {
    /// Write the text plus a newline to stdout.
    Echo(&'static [u8]),
    /// Read a VFS file and write it to stdout.
    Cat(&'static [u8]),
    /// List the VFS root directory.
    Ls,
    /// Create a directory under the root.
    Mkdir(&'static [u8]),
    /// Print the stat of a root entry.
    Stat(&'static [u8]),
    /// Spawn `path` with argv/env through PS; report `<path> -> <status>`;
    /// fail the script when the status differs from `expect`.
    Run {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
        env: &'static [&'static [u8]],
        expect: i32,
    },
}

const SCRIPT: &[Command] = &[
    Command::Echo(b"helios sh v0"),
    Command::Ls,
    Command::Mkdir(b"work"),
    Command::Ls,
    Command::Stat(b"hello"),
    Command::Cat(b"hello"),
    Command::Run {
        path: b"child",
        argv: &[b"7"],
        env: &[],
        expect: 7,
    },
    // envp plumbing: the child echoes its environment alongside argv.
    Command::Run {
        path: b"child",
        argv: &[b"5"],
        env: &[b"X=42"],
        expect: 5,
    },
    Command::Echo(b"sh ok"),
];

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

    let vfs_ep = rt.package.optional[0].map(|cs| cs.handle());
    let stdout = rt.stdout_handle();
    let mut fail = 0x10i32;
    for cmd in SCRIPT {
        match cmd {
            Command::Echo(text) => {
                let _ = rt.write_stdout(&mut sys, text);
                let _ = rt.write_stdout(&mut sys, b"\n");
            }
            Command::Cat(path) => {
                let mut buf = [0u8; 64];
                let n = match rt.vfs.read_file(&mut sys, path, &mut buf) {
                    Ok(n) => n,
                    Err(e) => exit(&mut sys, fail | (e & 0xFF)),
                };
                let _ = rt.write_stdout(&mut sys, &buf[..n]);
            }
            Command::Ls => {
                let root = rt.vfs.root();
                let mut cursor = 0u64;
                let mut name = [0u8; 64];
                loop {
                    match rt.vfs.readdir(&mut sys, root, cursor, &mut name) {
                        Ok(Some((next, kind, len))) => {
                            let _ = rt.write_stdout(&mut sys, &name[..len]);
                            if kind == personality::vfs::KIND_DIR {
                                let _ = rt.write_stdout(&mut sys, b"/");
                            }
                            let _ = rt.write_stdout(&mut sys, b"\n");
                            // `next == 0` marks the final entry: emit it, stop.
                            if next == 0 {
                                break;
                            }
                            cursor = next;
                        }
                        Ok(None) => break,
                        Err(e) => exit(&mut sys, fail | (e & 0xFF)),
                    }
                }
            }
            Command::Mkdir(name) => {
                if let Err(e) = rt.vfs.mkdir(&mut sys, name) {
                    exit(&mut sys, fail | (e & 0xFF));
                }
            }
            Command::Stat(name) => {
                let st = match rt.vfs.stat(&mut sys, name) {
                    Ok(st) => st,
                    Err(e) => exit(&mut sys, fail | (e & 0xFF)),
                };
                let _ = rt.write_stdout(&mut sys, name);
                if st.kind == personality::vfs::KIND_DIR {
                    let _ = rt.write_stdout(&mut sys, b" kind=dir");
                } else {
                    let _ = rt.write_stdout(&mut sys, b" kind=file");
                }
                let _ = rt.write_stdout(&mut sys, b" size=");
                let mut digits = [0u8; 12];
                let text = write_i32(st.size as i32, &mut digits);
                let _ = rt.write_stdout(&mut sys, text);
                let _ = rt.write_stdout(&mut sys, b"\n");
            }
            Command::Run {
                path,
                argv,
                env,
                expect,
            } => {
                let pid = match rt.ps.spawn(&mut sys, path, argv, env, vfs_ep, stdout) {
                    Ok(pid) => pid,
                    Err(e) => exit(&mut sys, fail | (e & 0xFF)),
                };
                let status = match rt.ps.wait(&mut sys, pid) {
                    Ok(s) => s,
                    Err(e) => exit(&mut sys, (fail + 1) | (e & 0xFF)),
                };
                // Report "<path> -> <status>" on stdout (tiny decimal writer:
                // no format! in a no_std bin's hot path here).
                let _ = rt.write_stdout(&mut sys, path);
                let _ = rt.write_stdout(&mut sys, b" -> ");
                let mut digits = [0u8; 12];
                let text = write_i32(status, &mut digits);
                let _ = rt.write_stdout(&mut sys, text);
                let _ = rt.write_stdout(&mut sys, b"\n");
                if status != *expect {
                    exit(&mut sys, fail + 2);
                }
                fail += 4;
            }
        }
    }
    exit(&mut sys, 0)
}

/// Write `v` as decimal into `buf`, returning the used slice.
fn write_i32(v: i32, buf: &mut [u8; 12]) -> &[u8] {
    let neg = v < 0;
    let mut n = (v as i64).unsigned_abs();
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    &buf[i..]
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0005)
}
