//! Helios console server binary (v0).
//!
//! Bootstrap: standard server package (prefix + `optional[0]` = Factory per
//! ADR-023), plus `optional[1]` = the kernel debug endpoint (`SEND`), which
//! the launcher supplies because only it holds that capability. The server
//! mints its service endpoint, publishes it in the ready callback, then
//! forwards every received message to the debug endpoint (serial output).
//! `KILL` acks and exits (the v0 shutdown convention, same as PS/VFS).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::bootstrap::{self, receive};
use sdk::heap::GlobalHeap;
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};

/// The sdk rlib links `alloc`; a handler satisfies the link even though this
/// server allocates nothing (initializing the heap is optional).
#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut raw = X86_64Syscalls;

    let package = {
        let mut sys = Syscalls::new(&mut raw);
        receive(&mut sys)
    };
    let package = match package {
        Ok(p) => p,
        Err(e) => exit(e),
    };

    let factory = match package.optional[0] {
        Some(cap) => cap.handle(),
        None => exit(0xE1),
    };
    let debug = match package.optional[1] {
        Some(cap) => cap.handle(),
        None => exit(0xE2),
    };

    // Service endpoint (children write text to this).
    let service_ep = {
        let mut sys = Syscalls::new(&mut raw);
        match sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT)) {
            Ok(reply) if reply.words[0] != 0 => reply.words[0] as u32,
            _ => exit(0xE3),
        }
    };

    // Ready callback: publish the endpoint (descriptor 0).
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

    // Forward loop: text in, serial out (the kernel prints debug-EP messages).
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
        let _ = sys.send(debug, &msg);
    }
}

fn exit(code: i32) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(code)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    exit(0x0BAD_0004)
}
