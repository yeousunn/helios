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

use alloc::vec::Vec;
use ipc::Message;
use personality::layout::HEAP_VA_BASE;
use personality::runtime::{exit, Runtime};
use sdk::args::Args;
use sdk::bootstrap::receive;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS};
use sdk::syscall::{RawSyscalls, Syscalls, X86_64Syscalls};

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
    /// Rename/move a path (RENAME).
    Mv(&'static [u8], &'static [u8]),
    /// Replace the shell's own image with `path` (must be the last command).
    Exec {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
    },
    /// `s0 | s1 | ... | sN`: each stage's stdout becomes the next stage's
    /// stdin. Each stage = `(path, argv, expected status)`.
    Pipeline {
        stages: &'static [(&'static [u8], &'static [&'static [u8]], i32)],
    },
    /// Spawn `path` with argv/env through PS; report `<path> -> <status>`;
    /// fail the script when the status differs from `expect`.
    Run {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
        env: &'static [&'static [u8]],
        expect: i32,
    },
    /// `cmd args > file`: run through PS with stdout captured into a VFS
    /// file (create/truncate). The shell drains the pipe while the child
    /// runs, then writes the result.
    RunTo {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
        expect: i32,
        file: &'static [u8],
    },
    /// `cmd args < file`: run through PS with stdin fed from a VFS file.
    /// The shell writes the file into the pipe then closes it (`EOF`).
    RunFrom {
        path: &'static [u8],
        argv: &'static [&'static [u8]],
        expect: i32,
        file: &'static [u8],
    },
    /// Shell builtin `echo` with `> file` redirection (no child).
    EchoTo {
        text: &'static [u8],
        file: &'static [u8],
    },
    /// Remove an empty directory (RMDIR).
    Rmdir(&'static [u8]),
    /// Copy a file (`cp src dst`) through the VFS.
    Cp {
        src: &'static [u8],
        dst: &'static [u8],
    },
    /// `export KEY=VAL`: add an entry to the shell environment inherited by
    /// every subsequently spawned program.
    Export(&'static [u8]),
    /// `unset KEY`: drop an environment entry by name.
    Unset(&'static [u8]),
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
    // mv (RENAME): plain, then through multi-component paths.
    Command::Touch(b"moved"),
    Command::Mv(b"moved", b"moved2"),
    Command::Stat(b"moved2"),
    Command::Rm(b"moved2"),
    Command::Touch(b"work/a"),
    Command::Mv(b"work/a", b"work/b"),
    Command::Stat(b"work/b"),
    Command::Rm(b"work/b"),
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
    // The utility set: ls (argv path listing; default cwd) and echo
    // (argv -> stdout).
    Command::Run {
        path: b"ls",
        argv: &[b"ls", b"work"],
        env: &[],
        expect: 0,
    },
    Command::Run {
        path: b"echo",
        argv: &[b"echo", b"helios", b"utils"],
        env: &[],
        expect: 0,
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
    // THE FIRST PIPELINE: `cat hello posix-log | wc` (28 bytes over a pipe),
    // then a three-stage line where the middle `cat` relays stdin
    // (POSIX no-arg cat): `cat hello posix-log | cat | wc` (still 28 bytes).
    Command::Pipeline {
        stages: &[
            (b"cat", &[b"cat", b"hello", b"posix-log"], 0),
            (b"wc", &[b"wc"], 0),
        ],
    },
    Command::Pipeline {
        stages: &[
            (b"cat", &[b"cat", b"hello", b"posix-log"], 0),
            (b"cat", &[b"cat"], 0),
            (b"wc", &[b"wc"], 0),
        ],
    },
    // OUTPUT REDIRECTION (`>`): the echo builtin writes a file directly, and
    // an external command's stdout is drained through a pipe into a file.
    Command::EchoTo {
        text: b"redirection works",
        file: b"note.txt",
    },
    Command::Cat(b"note.txt"),
    Command::RunTo {
        path: b"cat",
        argv: &[b"cat", b"hello"],
        expect: 0,
        file: b"copy",
    },
    Command::Cat(b"copy"),
    // INPUT REDIRECTION (`<`): the shell feeds a VFS file into the child's
    // stdin pipe (`wc < hello` counts the file's bytes).
    Command::RunFrom {
        path: b"wc",
        argv: &[b"wc"],
        expect: 0,
        file: b"hello",
    },
    Command::Rm(b"note.txt"),
    Command::Rm(b"copy"),
    // rmdir: create a directory, remove it (empty); cp: copy a file and read
    // the copy back.
    Command::Mkdir(b"trash"),
    Command::Ls,
    Command::Rmdir(b"trash"),
    Command::Cp {
        src: b"hello",
        dst: b"hello2",
    },
    Command::Cat(b"hello2"),
    Command::Stat(b"hello2"),
    Command::Rm(b"hello2"),
    // '..' inside a path: `work/../hello` resolves to the root's `hello`
    // (the server's walk clamps at the root).
    Command::Cat(b"work/../hello"),
    // Environment: `export` adds an entry inherited by every later spawn; the
    // `child` echo utility reports the env it received (`argv=..|env=..`).
    Command::Export(b"HELIOS=1"),
    Command::Export(b"TARGET=helios"),
    Command::Run {
        path: b"child",
        argv: &[b"5"],
        env: &[],
        expect: 5,
    },
    Command::Unset(b"TARGET"),
    // Variable expansion ($NAME) against the environment table.
    Command::Echo(b"helios=$HELIOS target=$TARGET done"),
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

    // Interactive mode (ADR-043): init passes the console-input endpoint as
    // optional[1]. If a line is already pending the harness/user wants a
    // REPL; with no input the shell runs its compiled script (the automated
    // smoke). The nonblocking peek returns EWOULDBLOCK on an empty buffer.
    if let Some(console_in) = rt.stdin_handle() {
        if let Ok(first) = sys.recv_nonblock(console_in) {
            repl(&mut sys, &mut rt, console_in, first, vfs_ep, stdout);
        }
    }

    let mut path = [0u8; 64];
    let mut path_len = 0usize;
    // Shell environment (export/unset); every spawn inherits this table.
    let mut senv: [&[u8]; 16] = [b""; 16];
    let mut senv_len = 0usize;
    let mut fail = 0x10i32;
    for cmd in SCRIPT {
        match cmd {
            Command::Echo(text) => {
                let mut ebuf = [0u8; 128];
                let n = expand(text, &senv[..senv_len], &mut ebuf);
                let _ = rt.write_stdout(&mut sys, &ebuf[..n]);
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
            Command::Mv(src, dst) => {
                if let Err(e) = rt.vfs.rename(&mut sys, src, dst) {
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
            Command::Pipeline { stages } => {
                let n = stages.len();
                if n < 2 {
                    exit(&mut sys, 0x0E);
                }
                // N-1 pipes connecting consecutive stages.
                let mut pipes: Vec<(u32, u32)> = Vec::with_capacity(n - 1);
                for _ in 0..(n - 1) {
                    match rt.ps.pipe(&mut sys) {
                        Ok(p) => pipes.push(p),
                        Err(e) => exit(&mut sys, (fail << 8) | (e & 0xFF)),
                    }
                }
                let mut pids: Vec<u64> = Vec::with_capacity(n);
                for (i, (path, argv, _)) in stages.iter().enumerate() {
                    let stdin_h = if i == 0 { None } else { Some(pipes[i - 1].0) };
                    let stdout_h = if i == n - 1 { stdout } else { Some(pipes[i].1) };
                    match rt.ps.spawn(
                        &mut sys,
                        path,
                        argv,
                        &senv[..senv_len],
                        vfs_ep,
                        stdin_h,
                        stdout_h,
                    ) {
                        Ok(pid) => pids.push(pid),
                        Err(e) => exit(&mut sys, ((fail + 1) << 8) | (e & 0xFF)),
                    }
                }
                let _ = rt.write_stdout(&mut sys, b"[pipe");
                for _ in 0..(n - 1) {
                    let _ = rt.write_stdout(&mut sys, b"|");
                }
                let _ = rt.write_stdout(&mut sys, b"] ");
                for (i, (_, _, expect)) in stages.iter().enumerate() {
                    let s = match rt.ps.wait(&mut sys, pids[i]) {
                        Ok(s) => s,
                        Err(e) => exit(&mut sys, ((fail + 3) << 8) | (e & 0xFF)),
                    };
                    if s != *expect {
                        exit(&mut sys, ((fail + 4) << 8) | (s & 0xFF));
                    }
                }
                fail += 6;
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
                // The command's explicit env plus the shell environment.
                let mut cmd_env: Vec<&[u8]> = Vec::new();
                cmd_env.extend_from_slice(env);
                cmd_env.extend_from_slice(&senv[..senv_len]);
                let pid = match rt
                    .ps
                    .spawn(&mut sys, path, argv, &cmd_env, vfs_ep, None, stdout)
                {
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
            Command::EchoTo { text, file } => {
                // Builtin `echo text > file`: shell-side capture.
                let mut buf = [0u8; 96];
                let n = text.len().min(95);
                buf[..n].copy_from_slice(&text[..n]);
                buf[n] = b'\n';
                if let Err(e) = rt.vfs.write_file(&mut sys, file, &buf[..n + 1]) {
                    exit(&mut sys, fail | (e & 0xFF));
                }
                let _ = rt.write_stdout(&mut sys, b"echo > ");
                let _ = rt.write_stdout(&mut sys, file);
                let _ = rt.write_stdout(&mut sys, b"\n");
                fail += 2;
            }
            Command::RunTo {
                path,
                argv,
                expect,
                file,
            } => {
                let (read_end, write_end) = match rt.ps.pipe(&mut sys) {
                    Ok(p) => p,
                    Err(e) => exit(&mut sys, (fail << 8) | (e & 0xFF)),
                };
                let pid = match rt.ps.spawn(
                    &mut sys,
                    path,
                    argv,
                    &senv[..senv_len],
                    vfs_ep,
                    None,
                    Some(write_end),
                ) {
                    Ok(pid) => pid,
                    Err(e) => exit(&mut sys, ((fail + 1) << 8) | (e & 0xFF)),
                };
                // Drain the child's stdout (console::WRITE chunks) until EOF.
                let mut buf: Vec<u8> = Vec::new();
                loop {
                    match sys.recv(read_end) {
                        Ok(m) => {
                            if m.tag.label() == sdk::methods::console::EOF {
                                break;
                            }
                            for w in m.words {
                                for b in w.to_le_bytes() {
                                    if b != 0 {
                                        buf.push(b);
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
                let status = match rt.ps.wait(&mut sys, pid) {
                    Ok(s) => s,
                    Err(e) => exit(&mut sys, ((fail + 2) << 8) | (e & 0xFF)),
                };
                if let Err(e) = rt.vfs.write_file(&mut sys, file, &buf) {
                    exit(&mut sys, ((fail + 3) << 8) | (e & 0xFF));
                }
                let _ = rt.write_stdout(&mut sys, path);
                let _ = rt.write_stdout(&mut sys, b" > ");
                let _ = rt.write_stdout(&mut sys, file);
                let _ = rt.write_stdout(&mut sys, b" -> ");
                let mut digits = [0u8; 12];
                let _ = rt.write_stdout(&mut sys, write_i32(status, &mut digits));
                let _ = rt.write_stdout(&mut sys, b"\n");
                if status != *expect {
                    exit(&mut sys, fail + 4);
                }
                fail += 6;
            }
            Command::RunFrom {
                path,
                argv,
                expect,
                file,
            } => {
                let mut data = [0u8; 256];
                let n = match rt.vfs.read_file(&mut sys, file, &mut data) {
                    Ok(n) => n,
                    Err(e) => exit(&mut sys, (fail << 8) | (e & 0xFF)),
                };
                let (read_end, write_end) = match rt.ps.pipe(&mut sys) {
                    Ok(p) => p,
                    Err(e) => exit(&mut sys, ((fail + 1) << 8) | (e & 0xFF)),
                };
                let pid = match rt.ps.spawn(
                    &mut sys,
                    path,
                    argv,
                    &senv[..senv_len],
                    vfs_ep,
                    Some(read_end),
                    stdout,
                ) {
                    Ok(pid) => pid,
                    Err(e) => exit(&mut sys, ((fail + 2) << 8) | (e & 0xFF)),
                };
                // Feed the file, then close the write end with `EOF`.
                for chunk in data[..n].chunks(sdk::methods::console::TEXT_BYTES) {
                    let mut m = Message::new(sdk::methods::console::WRITE);
                    m.words = sdk::methods::pack_console_text(chunk);
                    if sys.send(write_end, &m).is_err() {
                        exit(&mut sys, ((fail + 3) << 8) | 0x01);
                    }
                }
                let _ = sys.send(write_end, &Message::new(sdk::methods::console::EOF));
                let status = match rt.ps.wait(&mut sys, pid) {
                    Ok(s) => s,
                    Err(e) => exit(&mut sys, ((fail + 4) << 8) | (e & 0xFF)),
                };
                let _ = rt.write_stdout(&mut sys, path);
                let _ = rt.write_stdout(&mut sys, b" < ");
                let _ = rt.write_stdout(&mut sys, file);
                let _ = rt.write_stdout(&mut sys, b" -> ");
                let mut digits = [0u8; 12];
                let _ = rt.write_stdout(&mut sys, write_i32(status, &mut digits));
                let _ = rt.write_stdout(&mut sys, b"\n");
                if status != *expect {
                    exit(&mut sys, fail + 5);
                }
                fail += 6;
            }
            Command::Rmdir(path) => {
                if let Err(e) = rt.vfs.rmdir(&mut sys, path) {
                    exit(&mut sys, fail | (e & 0xFF));
                }
                let _ = rt.write_stdout(&mut sys, b"rmdir ");
                let _ = rt.write_stdout(&mut sys, path);
                let _ = rt.write_stdout(&mut sys, b"\n");
                fail += 2;
            }
            Command::Cp { src: s, dst } => {
                let mut buf = [0u8; 512];
                let n = match rt.vfs.read_file(&mut sys, s, &mut buf) {
                    Ok(n) => n,
                    Err(e) => exit(&mut sys, fail | (e & 0xFF)),
                };
                if let Err(e) = rt.vfs.write_file(&mut sys, dst, &buf[..n]) {
                    exit(&mut sys, ((fail + 1) << 8) | (e & 0xFF));
                }
                let _ = rt.write_stdout(&mut sys, b"cp ");
                let _ = rt.write_stdout(&mut sys, s);
                let _ = rt.write_stdout(&mut sys, b" ");
                let _ = rt.write_stdout(&mut sys, dst);
                let _ = rt.write_stdout(&mut sys, b"\n");
                fail += 4;
            }
            Command::Export(entry) => {
                if senv_len < senv.len() {
                    senv[senv_len] = entry;
                    senv_len += 1;
                }
                let _ = rt.write_stdout(&mut sys, b"export ");
                let _ = rt.write_stdout(&mut sys, entry);
                let _ = rt.write_stdout(&mut sys, b"\n");
                fail += 2;
            }
            Command::Unset(key) => {
                let mut w = 0usize;
                for r in 0..senv_len {
                    let e = senv[r];
                    let klen = e.iter().position(|&b| b == b'=').unwrap_or(e.len());
                    if &e[..klen] == *key {
                        continue; // drop
                    }
                    senv[w] = e;
                    w += 1;
                }
                senv_len = w;
                let _ = rt.write_stdout(&mut sys, b"unset ");
                let _ = rt.write_stdout(&mut sys, key);
                let _ = rt.write_stdout(&mut sys, b"\n");
                fail += 2;
            }
        }
    }
    exit(&mut sys, 0)
}

// ---------------------------------------------------------------------------
// Interactive REPL (used only when console input is pending at startup).
// ---------------------------------------------------------------------------

/// Unpack a console-input line message (`words[0]` = len, bytes from
/// `words[1]`) into `buf`.
fn console_line<'a>(m: &Message, buf: &'a mut [u8; 128]) -> &'a [u8] {
    let len = (m.words[0] as usize).min(120).min(buf.len());
    for (i, slot) in buf.iter_mut().enumerate().take(len) {
        let w = m.words[1 + i / 8];
        *slot = ((w >> ((i % 8) * 8)) & 0xFF) as u8;
    }
    &buf[..len]
}

fn repl<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    console_in: u32,
    first: Message,
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
) -> ! {
    let _ = rt.write_stdout(
        sys,
        b"helios sh - interactive (type 'help'; Ctrl-D / 'exit' quits)\n",
    );
    let mut path = [0u8; 64];
    path[0] = b'/';
    let mut path_len = 1usize;
    let mut pending = Some(first);
    // REPL environment (owned: `export` copies the typed line).
    let mut renv: Vec<Vec<u8>> = Vec::new();
    loop {
        let _ = rt.write_stdout(sys, &path[..path_len]);
        let _ = rt.write_stdout(sys, b"> ");
        let line = match pending.take() {
            Some(m) => m,
            None => match sys.recv(console_in) {
                Ok(m) => m,
                Err(_) => break, // endpoint gone / EOF
            },
        };
        let mut buf = [0u8; 128];
        let text = console_line(&line, &mut buf);
        repl_line(
            sys,
            rt,
            text,
            &mut path,
            &mut path_len,
            vfs_ep,
            stdout,
            &mut renv,
        );
    }
    rt.exit(sys, 0)
}

#[allow(clippy::too_many_arguments)]
fn repl_line<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    text: &[u8],
    path: &mut [u8; 64],
    path_len: &mut usize,
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
    renv: &mut Vec<Vec<u8>>,
) {
    // `a | b | ...`: interactive pipelines reuse the pipe machinery.
    if repl_pipeline(sys, rt, text, vfs_ep, stdout, renv) {
        return;
    }
    // `cmd > file` / `cmd < file`: redirection (one per line).
    if repl_redirect(sys, rt, text, vfs_ep, stdout, renv) {
        return;
    }
    let mut toks: [&[u8]; 16] = [b""; 16];
    let mut n = 0usize;
    for t in text.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
        if n < toks.len() {
            toks[n] = t;
            n += 1;
        }
    }
    if n == 0 {
        return;
    }
    let args = &toks[1..n];
    let mut line = [0u8; 64];
    match toks[0] {
        b"exit" | b"quit" => rt.exit(sys, 0),
        b"help" => {
            let _ = rt.write_stdout(
                sys,
                b"builtins: echo pwd ls cd mkdir rmdir rm touch cat cp run <prog> [args]; 'exit'\n",
            );
        }
        b"echo" => {
            let ev: Vec<&[u8]> = renv.iter().map(|v| v.as_slice()).collect();
            let mut ebuf = [0u8; 256];
            let mut en = 0usize;
            for (i, a) in args.iter().enumerate() {
                if i > 0 && en < ebuf.len() {
                    ebuf[en] = b' ';
                    en += 1;
                }
                let mut one = [0u8; 128];
                let k = expand(a, &ev, &mut one);
                let room = (ebuf.len() - en).min(k);
                ebuf[en..en + room].copy_from_slice(&one[..room]);
                en += room;
            }
            let _ = rt.write_stdout(sys, &ebuf[..en]);
            let _ = rt.write_stdout(sys, b"\n");
        }
        b"pwd" => {
            let _ = rt.write_stdout(sys, &path[..*path_len]);
            let _ = rt.write_stdout(sys, b"\n");
        }
        b"ls" => repl_ls(sys, rt),
        b"cd" => {
            let Some(name) = args.first() else { return };
            let res = if *name == b".." {
                rt.vfs.chdir_up()
            } else {
                rt.vfs.chdir(sys, name)
            };
            if res.is_err() {
                let _ = rt.write_stdout(sys, b"cd: no such directory\n");
                return;
            }
            // Mirror the move in the display path.
            if *name == b".." {
                while *path_len > 0 && path[*path_len - 1] != b'/' {
                    *path_len -= 1;
                }
                if *path_len > 0 {
                    *path_len -= 1;
                }
                if *path_len == 0 {
                    path[0] = b'/';
                    *path_len = 1;
                }
            } else {
                if path[*path_len - 1] != b'/' {
                    path[*path_len] = b'/';
                    *path_len += 1;
                }
                let room = 63usize.saturating_sub(*path_len).min(name.len());
                path[*path_len..*path_len + room].copy_from_slice(&name[..room]);
                *path_len += room;
            }
        }
        b"mkdir" => {
            if let Some(p) = args.first() {
                let _ = rt.vfs.mkdir(sys, p);
            }
        }
        b"rmdir" => {
            if let Some(p) = args.first() {
                let _ = rt.vfs.rmdir(sys, p);
            }
        }
        b"rm" => {
            if let Some(p) = args.first() {
                let _ = rt.vfs.unlink(sys, p);
            }
        }
        b"touch" => {
            if let Some(p) = args.first() {
                let _ = rt.vfs.write_file(sys, p, b"");
            }
        }
        b"cat" => {
            if let Some(p) = args.first() {
                let mut cb = [0u8; 512];
                if let Ok(k) = rt.vfs.read_file(sys, p, &mut cb) {
                    let _ = rt.write_stdout(sys, &cb[..k]);
                } else {
                    let _ = rt.write_stdout(sys, b"cat: cannot read\n");
                }
            }
        }
        b"cp" => {
            if args.len() >= 2 {
                let mut cb = [0u8; 512];
                match rt.vfs.read_file(sys, args[0], &mut cb) {
                    Ok(k) => {
                        let _ = rt.vfs.write_file(sys, args[1], &cb[..k]);
                    }
                    Err(_) => {
                        let _ = rt.write_stdout(sys, b"cp: cannot read\n");
                    }
                }
            }
        }
        b"export" => {
            if let Some(e) = args.first() {
                if let Some(k) = renv.iter().position(|v| {
                    v.iter().position(|&b| b == b'=').map(|i| &v[..i])
                        == Some(&e[..e.iter().position(|&b| b == b'=').unwrap_or(e.len())])
                }) {
                    renv[k] = e.to_vec();
                } else {
                    renv.push(e.to_vec());
                }
            }
        }
        b"unset" => {
            if let Some(key) = args.first() {
                renv.retain(|v| {
                    let klen = v.iter().position(|&b| b == b'=').unwrap_or(v.len());
                    &v[..klen] != *key
                });
            }
        }
        b"run" => {
            // `run <prog> [args...]`: spawn through PS.
            if args.is_empty() {
                let _ = rt.write_stdout(sys, b"run: usage: run <prog> [args]\n");
                return;
            }
            repl_spawn(sys, rt, args, vfs_ep, stdout, renv, &mut line);
        }
        _ => {
            // Bare command = external program (`cat`, `ls`, `wc`, `child`, ...).
            repl_spawn(sys, rt, &toks[..n], vfs_ep, stdout, renv, &mut line);
        }
    }
}

/// Expand `$NAME` references in `text` against `env` (`KEY=VAL` entries)
/// into `out`, returning the length. An unset name expands to empty; `$$` is
/// not special. Names are `[A-Za-z_][A-Za-z0-9_]*`.
fn expand(text: &[u8], env: &[&[u8]], out: &mut [u8]) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < text.len() && n < out.len() {
        if text[i] != b'$' {
            out[n] = text[i];
            n += 1;
            i += 1;
            continue;
        }
        // Read the name.
        let start = i + 1;
        let mut j = start;
        while j < text.len() && (text[j].is_ascii_alphanumeric() || text[j] == b'_') {
            j += 1;
        }
        if j == start {
            // A lone '$' — emit it verbatim.
            out[n] = b'$';
            n += 1;
            i = start;
            continue;
        }
        let name = &text[start..j];
        let mut val: &[u8] = b"";
        for e in env {
            let eq = e.iter().position(|&b| b == b'=').unwrap_or(e.len());
            if &e[..eq] == name {
                val = &e[eq + 1..];
                break;
            }
        }
        for &b in val {
            if n < out.len() {
                out[n] = b;
                n += 1;
            }
        }
        i = j;
    }
    n
}

/// Trim ASCII spaces from both ends.
fn trim(mut s: &[u8]) -> &[u8] {
    while s.first() == Some(&b' ') {
        s = &s[1..];
    }
    while s.last() == Some(&b' ') {
        s = &s[..s.len() - 1];
    }
    s
}

/// Tokenize a command line into up to 16 words.
fn tokenize(text: &[u8]) -> ([&[u8]; 16], usize) {
    let mut toks: [&[u8]; 16] = [b""; 16];
    let mut n = 0usize;
    for t in text.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
        if n < toks.len() {
            toks[n] = t;
            n += 1;
        }
    }
    (toks, n)
}

/// `cmd > file` / `cmd < file` in the REPL. Returns true if handled.
fn repl_redirect<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    text: &[u8],
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
    renv: &[Vec<u8>],
) -> bool {
    if let Some(pos) = text.iter().position(|&b| b == b'>') {
        repl_run_to(
            sys,
            rt,
            trim(&text[..pos]),
            trim(&text[pos + 1..]),
            vfs_ep,
            renv,
        );
        return true;
    }
    if let Some(pos) = text.iter().position(|&b| b == b'<') {
        repl_run_from(
            sys,
            rt,
            trim(&text[..pos]),
            trim(&text[pos + 1..]),
            vfs_ep,
            stdout,
            renv,
        );
        return true;
    }
    false
}

/// `cmd > file`: spawn `cmd` with stdout captured into a VFS file.
fn repl_run_to<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    left: &[u8],
    file: &[u8],
    vfs_ep: Option<u32>,
    renv: &[Vec<u8>],
) {
    let (toks, n) = tokenize(left);
    if n == 0 || file.is_empty() {
        return;
    }
    let argv = &toks[..n];
    let ev: Vec<&[u8]> = renv.iter().map(|v| v.as_slice()).collect();
    let (read_end, write_end) = match rt.ps.pipe(sys) {
        Ok(p) => p,
        Err(_) => return,
    };
    let pid = match rt
        .ps
        .spawn(sys, argv[0], argv, &ev, vfs_ep, None, Some(write_end))
    {
        Ok(p) => p,
        Err(_) => {
            let _ = rt.write_stdout(sys, b"run: spawn failed\n");
            return;
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    while let Ok(m) = sys.recv(read_end) {
        if m.tag.label() == sdk::methods::console::EOF {
            break;
        }
        for w in m.words {
            for b in w.to_le_bytes() {
                if b != 0 {
                    buf.push(b);
                }
            }
        }
    }
    let _ = rt.ps.wait(sys, pid);
    let _ = rt.vfs.write_file(sys, file, &buf);
}

/// `cmd < file`: feed a VFS file into the child's stdin.
fn repl_run_from<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    left: &[u8],
    file: &[u8],
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
    renv: &[Vec<u8>],
) {
    let (toks, n) = tokenize(left);
    if n == 0 || file.is_empty() {
        return;
    }
    let argv = &toks[..n];
    let ev: Vec<&[u8]> = renv.iter().map(|v| v.as_slice()).collect();
    let mut data = [0u8; 256];
    let k = match rt.vfs.read_file(sys, file, &mut data) {
        Ok(k) => k,
        Err(_) => {
            let _ = rt.write_stdout(sys, b"cannot read file\n");
            return;
        }
    };
    let (read_end, write_end) = match rt.ps.pipe(sys) {
        Ok(p) => p,
        Err(_) => return,
    };
    let pid = match rt
        .ps
        .spawn(sys, argv[0], argv, &ev, vfs_ep, Some(read_end), stdout)
    {
        Ok(p) => p,
        Err(_) => {
            let _ = rt.write_stdout(sys, b"run: spawn failed\n");
            return;
        }
    };
    for chunk in data[..k].chunks(sdk::methods::console::TEXT_BYTES) {
        let mut m = Message::new(sdk::methods::console::WRITE);
        m.words = sdk::methods::pack_console_text(chunk);
        if sys.send(write_end, &m).is_err() {
            break;
        }
    }
    let _ = sys.send(write_end, &Message::new(sdk::methods::console::EOF));
    let _ = rt.ps.wait(sys, pid);
}

/// If `text` contains `|`, run it as a pipeline (up to 4 stages) and return
/// true; otherwise return false so the caller handles a single command.
fn repl_pipeline<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    text: &[u8],
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
    renv: &[Vec<u8>],
) -> bool {
    let stages: Vec<&[u8]> = text.split(|&b| b == b'|').collect();
    if stages.len() < 2 {
        return false;
    }
    let n = stages.len().min(4);
    let mut toks: [[&[u8]; 16]; 4] = [[b""; 16]; 4];
    let mut nt = [0usize; 4];
    for (s, st) in stages.iter().enumerate().take(n) {
        for t in st.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
            if nt[s] < 16 {
                toks[s][nt[s]] = t;
                nt[s] += 1;
            }
        }
        if nt[s] == 0 {
            let _ = rt.write_stdout(sys, b"pipeline: empty stage\n");
            return true;
        }
    }
    let ev: Vec<&[u8]> = renv.iter().map(|v| v.as_slice()).collect();
    let mut pipes: Vec<(u32, u32)> = Vec::new();
    for _ in 0..(n - 1) {
        match rt.ps.pipe(sys) {
            Ok(p) => pipes.push(p),
            Err(_) => {
                let _ = rt.write_stdout(sys, b"pipeline: pipe failed\n");
                return true;
            }
        }
    }
    let mut pids: Vec<u64> = Vec::new();
    for s in 0..n {
        let argv = &toks[s][..nt[s]];
        let stdin_h = if s == 0 { None } else { Some(pipes[s - 1].0) };
        let stdout_h = if s == n - 1 { stdout } else { Some(pipes[s].1) };
        match rt
            .ps
            .spawn(sys, argv[0], argv, &ev, vfs_ep, stdin_h, stdout_h)
        {
            Ok(pid) => pids.push(pid),
            Err(_) => {
                let _ = rt.write_stdout(sys, b"pipeline: spawn failed\n");
                return true;
            }
        }
    }
    for p in pids {
        let _ = rt.ps.wait(sys, p);
    }
    true
}

/// Spawn `argv[0]` with the given argv/env through PS and print its status.
fn repl_spawn<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    rt: &mut Runtime,
    argv: &[&[u8]],
    vfs_ep: Option<u32>,
    stdout: Option<u32>,
    renv: &[Vec<u8>],
    _scratch: &mut [u8; 64],
) {
    let path = argv[0];
    let ev: Vec<&[u8]> = renv.iter().map(|v| v.as_slice()).collect();
    let pid = match rt.ps.spawn(sys, path, argv, &ev, vfs_ep, None, stdout) {
        Ok(pid) => pid,
        Err(e) => {
            let _ = rt.write_stdout(sys, b"cannot run ");
            let _ = rt.write_stdout(sys, path);
            let _ = rt.write_stdout(sys, b"\n");
            let _ = e;
            return;
        }
    };
    match rt.ps.wait(sys, pid) {
        Ok(s) => {
            let _ = rt.write_stdout(sys, b"[");
            let _ = rt.write_stdout(sys, path);
            let _ = rt.write_stdout(sys, b"] exit ");
            let mut d = [0u8; 12];
            let _ = rt.write_stdout(sys, write_i32(s, &mut d));
            let _ = rt.write_stdout(sys, b"\n");
        }
        Err(e) => {
            let _ = e;
        }
    }
}

/// `ls`: list the cwd through the VFS client.
fn repl_ls<R: RawSyscalls>(sys: &mut Syscalls<R>, rt: &mut Runtime) {
    let dir = rt.vfs.cwd();
    let mut cursor = 0u64;
    let mut name = [0u8; 64];
    loop {
        match rt.vfs.readdir(sys, dir, cursor, &mut name) {
            Ok(Some((next, kind, len))) => {
                let _ = rt.write_stdout(sys, &name[..len]);
                if kind == personality::vfs::KIND_DIR {
                    let _ = rt.write_stdout(sys, b"/");
                }
                let _ = rt.write_stdout(sys, b"\n");
                if next == 0 {
                    break;
                }
                cursor = next;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
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
