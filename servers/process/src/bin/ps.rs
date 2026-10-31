//! The Helios process server — first real server binary (ADR-023 bootstrap).
//!
//! Startup: receive the ADR-009 capability package (handle 1), build its heap
//! from the package Region (mapped into its own AS), exercise the allocator
//! once, mint its service endpoint through the package Factory, then publish
//! it to the launcher in the ready callback and **serve** (design §1.7):
//! `recv(svc)` once, then `reply_recv` per request.
//!
//! v0 protocol subset (design §2.6): `CONNECT` maps the client's arg/result
//! window frames into this AS at `PS_WINDOW_VA_BASE` and replies with a
//! connection id; `KILL` acks and exits this single-process server (the
//! launcher's smoke shutdown path). Everything else → `ENOSYS`.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::bootstrap::receive;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS, PS_HEAP_VA_BASE, PS_WINDOW_VA_BASE};
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut raw = X86_64Syscalls;

    // 1. Bootstrap package (handle 1, ADR-009): [aspace, thread, region, 4
    //    sessions, ps_ep] + tail[0] = Factory (ADR-023 §3).
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        receive(&mut sys)
    };
    let package = match package {
        Ok(p) => p,
        Err(e) => Syscalls::new(&mut raw).exit(e),
    };

    // 2. Heap: carve + map 1 MiB from the package Region into our own AS.
    let span = {
        let mut src = RegionSource::new(
            &mut raw,
            package.region,
            package.aspace,
            PS_HEAP_VA_BASE,
            HEAP_CHUNK,
        );
        src.map_startup(HEAP_CHUNKS)
    };
    let (heap_start, heap_len) = match span {
        Ok(v) => v,
        Err(e) => Syscalls::new(&mut raw).exit(e),
    };
    if let Err(e) = HEAP.init(heap_start, heap_len) {
        Syscalls::new(&mut raw).exit(e);
    }

    // 3. Allocator smoke: the global heap must actually work end to end.
    {
        let mut v: Vec<u8> = Vec::with_capacity(256);
        v.extend_from_slice(b"helios ps alive");
        if v.first() != Some(&b'h') || v.len() != 15 {
            Syscalls::new(&mut raw).exit(0xE3);
        }
        core::hint::black_box(&v);
    }

    // 4. Mint our service endpoint through the Factory (tail[0]).
    let factory = match package.optional[0] {
        Some(cap) => cap.handle(),
        None => Syscalls::new(&mut raw).exit(0xE1),
    };
    let minted = {
        let mut sys = Syscalls::new(&mut raw);
        sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))
    };
    let service_ep = match minted {
        Ok(reply) if reply.words[0] != 0 => reply.words[0] as u32,
        _ => Syscalls::new(&mut raw).exit(0xE2),
    };

    // 5. Ready callback to the launcher: proof that this process ran its own
    //    code, plus our service endpoint as a capability (descriptor 0) so the
    //    launcher can reach us. w1 = heap KiB payload.
    {
        let mut sys = Syscalls::new(&mut raw);
        let mut ready = Message::new(sdk::bootstrap::READY_LABEL);
        ready.tag = ready.tag.with_caps(1);
        ready.words[0] = sdk::bootstrap::READY_MAGIC;
        ready.words[1] = HEAP.capacity() as u64;
        if ready
            .set_descriptor(0, CapSlot::pack(service_ep, Rights::SEND))
            .is_none()
            || sys.send(package.process_server_ep, &ready).is_err()
        {
            Syscalls::new(&mut raw).exit(0xE5);
        }
    }

    // 6. Serve loop (design §1.7): one `recv`, then `reply_recv` per request.
    let mut sys = Syscalls::new(&mut raw);
    let mut req = match sys.recv(service_ep) {
        Ok(m) => m,
        Err(_) => Syscalls::new(&mut raw).exit(0xE6),
    };
    loop {
        let reply = match req.tag.label() {
            methods::process::CONNECT => connect_reply(&mut sys, &package, &req),
            methods::process::KILL => {
                // v0: KILL applies to this single-process server — ack, then
                // exit with the caller's raw status (design §2.6).
                let mut ack = Message::new(methods::process::KILL);
                let _ = sys.send(REPLY_CAP, &ack);
                Syscalls::new(&mut raw).exit(req.words[1] as i32);
            }
            label => {
                let mut reply = Message::new(label);
                reply.words[0] = ipc::status::ENOSYS as i64 as u64;
                reply
            }
        };
        req = match sys.reply_recv(service_ep, &reply) {
            Ok(m) => m,
            Err(_) => Syscalls::new(&mut raw).exit(0xE7),
        };
    }
}

/// `CONNECT` (0x0101): v0 packs the version in `w0`; the three capability
/// descriptors (session notification, arg frame, result frame) overlay
/// `w1..w3` per the v1 message format. Windows are 4 KiB (design §1.3), so
/// no size words are needed. Maps both frames into this AS and replies
/// `w0 = OK, w1 = connection id`.
fn connect_reply(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &sdk::bootstrap::BootstrapPackage,
    req: &Message,
) -> Message {
    let mut reply = Message::new(methods::process::CONNECT);
    if req.words[0] != 1 {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return reply;
    }
    let window =
        |i: usize| -> Option<u32> { req.descriptor(i).map(|cs| cs.handle()).filter(|h| *h != 0) };
    // descriptor 0 = session notification (installed by the recv; retained
    // for the connection to bind later), 1 = arg frame, 2 = result frame.
    let (arg, result) = match (window(1), window(2)) {
        (Some(a), Some(r)) => (a, r),
        _ => {
            reply.words[0] = ipc::status::EBADARG as i64 as u64;
            return reply;
        }
    };
    for (frame, va, flags) in [
        (arg, PS_WINDOW_VA_BASE, methods::map_flags::R),
        (result, PS_WINDOW_VA_BASE + 4096, methods::map_flags::W),
    ] {
        let mut map = Message::new(methods::aspace::MAP);
        map.tag = map.tag.with_caps(1);
        map.words[0] = va;
        map.words[1] = flags as u64;
        let _ = map.set_descriptor(0, CapSlot::pack(frame, Rights::READ));
        if let Err(e) = sys.invoke(package.aspace, &map) {
            reply.words[0] = e as i64 as u64;
            return reply;
        }
    }
    reply.words[1] = 1; // connection id (v0: the single published endpoint)
    reply
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0000)
}
