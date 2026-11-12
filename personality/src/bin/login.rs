//! `/login` — ADR-048 slice 2: authenticate against `servers/auth` and report
//! the session. v0 is non-interactive (argv `login <user> <password>`) so the
//! flow is verifiable in the smoke; the console-prompt REPL is the next slice.
//! The auth service cap arrives in package `optional[3]` (the stderr slot).

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
use sdk::methods;
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
    main = sym login_main,
);

fn push_num(b: &mut alloc::vec::Vec<u8>, mut v: u64) {
    if v == 0 {
        b.push(b'0');
        return;
    }
    let mut t = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        t[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        b.push(t[n]);
    }
}

extern "C" fn login_main(argc: u64, argv: *const *const u8, envp: *const *const u8) -> ! {
    let args = unsafe { Args::new(argc, argv, envp) };
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

    // Auth service cap = package `optional[3]` (the stderr slot; ADR-048).
    let auth = rt
        .package
        .optional
        .get(3)
        .copied()
        .flatten()
        .map(|cs| cs.handle())
        .filter(|h| *h != 0);
    let Some(auth) = auth else {
        let _ = rt.write_stdout(&mut sys, b"login: no auth service\n");
        rt.exit(&mut sys, 0x10);
    };

    let user = args.arg(1).unwrap_or(b"");
    let pass = args.arg(2).unwrap_or(b"");
    let n = methods::auth::pack16(user);
    let p = methods::auth::pack16(pass);
    let mut m = ipc::Message::new(methods::auth::CHECK);
    m.words[0] = n[0];
    m.words[1] = n[1];
    m.words[2] = p[0];
    m.words[3] = p[1];

    match sys.call(auth, &m) {
        Ok(rep) if rep.words[0] == 0 => {
            let mut b = alloc::vec::Vec::new();
            b.extend_from_slice(b"login: ");
            b.extend_from_slice(user);
            b.extend_from_slice(b" uid=");
            push_num(&mut b, rep.words[1]);
            b.extend_from_slice(b" gid=");
            push_num(&mut b, rep.words[2]);
            b.push(b'\n');
            let _ = rt.write_stdout(&mut sys, &b);
            rt.exit(&mut sys, 0);
        }
        _ => {
            let _ = rt.write_stdout(&mut sys, b"login: denied\n");
            rt.exit(&mut sys, 1);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(&mut Syscalls::new(&mut X86_64Syscalls), 0x0BAD_0009)
}
