//! The Helios process server — first real server binary (ADR-023 bootstrap).
//!
//! v0-minimal startup: receive the ADR-009 capability package (handle 1),
//! build its heap from the package Region (mapped into its own AS), exercise
//! the allocator once, mint its service endpoint through the package Factory,
//! and exit cleanly — the launcher (init) asserts on the death notification.
//! The serving loop arrives with the endpoint-publishing story.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use ipc::Message;
use sdk::bootstrap::receive;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS, PS_HEAP_VA_BASE};
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls};

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
    let _service_ep = match minted {
        Ok(reply) if reply.words[0] != 0 => reply.words[0] as u32,
        _ => Syscalls::new(&mut raw).exit(0xE2),
    };

    // 5. Clean exit; the launcher's death notification fires (ADR-007 §6).
    Syscalls::new(&mut raw).exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0000)
}
