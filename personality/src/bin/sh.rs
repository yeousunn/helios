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
    /// List the current working directory.
    Ls,
    /// Create a directory in the cwd.
    Mkdir(&'static [u8]),
    /// Print the stat of a cwd entry.
    Stat(&'static [u8]),
    /// Change the working directory (`..` pops).
    Cd(&'static [u8]),
    /// Print the working directory path.
    Pwd,
    /// Create an empty file (open with O_CREAT, close).
    Touch(&'static [u8]),
    /// Remove a file or an empty directory (UNLINK).
    Rm(&'static [u8]),
    /// Replace the shell's own image with `path` (must be the last command).
    Exec {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
    },
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
    Command::Cd(b"work"),
    Command::Mkdir(b"inner"),
    Command::Touch(b"note"),
    Command::Ls,
    Command::Rm(b"note"),
    Command::Ls,
    Command::Pwd,
    Command::Cd(b".."),
    // Multi-component paths: stat walks `work` then stats `inner`; touch and
    // rm create + remove a file through the same resolution. (v0 has no
    // rmdir: the ramfs rejects directory unlink with EISDIR by design.)
    Command::Stat(b"work/inner"),
    Command::Touch(b"work/gone"),
    Command::Rm(b"work/gone"),
    Command::Ls,
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
    // The `/cat` utility: a real program taking MULTIPLE argv paths (the
    // second run concatenates two files — multi-arg argv end to end).
    Command::Run {
        path: b"cat",
        argv: &[b"cat", b"hello"],
        env: &[],
        expect: 0,
    },
    Command::Run {
        path: b"cat",
        argv: &[b"cat", b"hello", b"posix-log"],
        env: &[],
        expect: 0,
    },
    Command::Echo(b"sh ok"),
    // exec: replaces this shell with the child image, which echoes its argv
    // and exits 9. The shell's process keeps its capabilities (and its pid).
    Command::Exec {
        path: b"child",
        argv: &[b"9"],
    },
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
    let mut path = [0u8; 64];
    let mut path_len = 0usize;
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
            Command::Cd(name) => {
                let res = if name == b".." {
                    rt.vfs.chdir_up()
                } else {
                    rt.vfs.chdir(&mut sys, name)
                };
                if let Err(e) = res {
                    exit(&mut sys, fail | (e & 0xFF));
                }
                // Mirror the move in the display path.
                if name == b".." {
                    while path_len > 0 && path[path_len - 1] != b'/' {
                        path_len -= 1;
                    }
                    if path_len > 0 {
                        path_len -= 1; // drop the '/'
                    }
                    if path_len == 0 {
                        path[0] = b'/';
                        path_len = 1;
                    }
                } else if name.len() + path_len + 2 <= path.len() {
                    if path_len == 0 {
                        path[0] = b'/';
                        path_len = 1;
                    } else {
                        path[path_len] = b'/';
                        path_len += 1;
                    }
                    path[path_len..path_len + name.len()].copy_from_slice(name);
                    path_len += name.len();
                }
            }
            Command::Touch(path) => {
                // Create + close: the client's write_file with no data.
                if let Err(e) = rt.vfs.write_file(&mut sys, path, &[]) {
                    exit(&mut sys, fail | (e & 0xFF));
                }
            }
            Command::Rm(path) => {
                if let Err(e) = rt.vfs.unlink(&mut sys, path) {
                    exit(&mut sys, fail | (e & 0xFF));
                }
            }
            Command::Pwd => {
                if path_len == 0 {
                    path[0] = b'/';
                    path_len = 1;
                }
                let _ = rt.write_stdout(&mut sys, &path[..path_len]);
                let _ = rt.write_stdout(&mut sys, b"\n");
            }
            Command::Ls => {
                let root = rt.vfs.cwd();
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
            Command::Exec { path, argv } => {
                match rt.ps.exec(&mut sys, path, argv, &[]) {
                    Ok(()) => {
                        // The replacement thread runs the new image; retire
                        // this thread (v0 exec convention).
                        exit(&mut sys, 0);
                    }
                    Err(e) => exit(&mut sys, 0x70 | (e & 0xFF)),
                }
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
