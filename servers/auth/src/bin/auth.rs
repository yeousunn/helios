//! Helios auth server (v0, ADR-048).
//!
//! Bootstrap: the standard server package — `optional[0]` = the Factory
//! (ADR-023). Mints its service endpoint, publishes it in the ready
//! callback, then answers `auth::CHECK` calls (short credentials packed in
//! four message words). `KILL` acks and exits (the v0 shutdown convention).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::bootstrap::{self, receive};
use sdk::heap::GlobalHeap;
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

/// v0 built-in user table: `(name, password, uid, gid)`. Plaintext v0
/// (ADR-048); `/etc/passwd` + hashing are the follow-up slice.
const USERS: &[(&[u8], &[u8], u32, u32)] =
    &[(b"root", b"root", 0, 0), (b"user", b"user", 1000, 1000)];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut raw = X86_64Syscalls;

    let package = {
        let mut sys = Syscalls::new(&mut raw);
        match receive(&mut sys) {
            Ok(p) => p,
            Err(e) => exit(e),
        }
    };
    let factory = match package.optional[0] {
        Some(cap) => cap.handle(),
        None => exit(0xE1),
    };

    let service_ep = {
        let mut sys = Syscalls::new(&mut raw);
        match sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT)) {
            Ok(reply) if reply.words[0] != 0 => reply.words[0] as u32,
            _ => exit(0xE3),
        }
    };

    // Ready callback: publish the service endpoint (descriptor 0).
    {
        let mut sys = Syscalls::new(&mut raw);
        let mut ready = Message::new(bootstrap::READY_LABEL);
        ready.tag = ready.tag.with_caps(1);
        ready.words[0] = bootstrap::READY_MAGIC;
        if ready
            .set_descriptor(
                0,
                CapSlot::pack(service_ep, Rights::SEND.union(Rights::GRANT)),
            )
            .is_none()
            || sys.send(package.process_server_ep, &ready).is_err()
        {
            exit(0xE4);
        }
    }

    // Serve `auth::CHECK` calls.
    let mut sys = Syscalls::new(&mut raw);
    loop {
        let msg = match sys.recv(service_ep) {
            Ok(m) => m,
            Err(_) => exit(0xE5),
        };
        if msg.tag.label() == methods::process::KILL {
            let ack = Message::new(methods::process::KILL);
            let _ = sys.send(REPLY_CAP, &ack);
            exit(msg.words[1] as i32);
        }
        if msg.tag.label() != methods::auth::CHECK {
            continue;
        }
        let (nb, nl) = methods::auth::unpack16([msg.words[0], msg.words[1]]);
        let (pb, pl) = methods::auth::unpack16([msg.words[2], msg.words[3]]);
        // 0 = ok, -EPERM = bad password, -ENOENT = no such user.
        let mut status: i64 = -15;
        let mut uid = 0u64;
        let mut gid = 0u64;
        for &(n, p, u, g) in USERS {
            if n == &nb[..nl] {
                if p == &pb[..pl] {
                    status = 0;
                    uid = u as u64;
                    gid = g as u64;
                } else {
                    status = -1;
                }
                break;
            }
        }
        let mut rep = Message::new(methods::auth::CHECK);
        rep.words[0] = status as u64;
        rep.words[1] = uid;
        rep.words[2] = gid;
        let _ = sys.send(REPLY_CAP, &rep);
    }
}

fn exit(code: i32) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(code)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(0x0BAD_0008)
}
