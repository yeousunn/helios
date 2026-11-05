//! The Helios VFS server — second real server binary (design §3, ADR-023
//! bootstrap like the process server).
//!
//! Startup mirrors `servers/process/src/bin/ps.rs`: receive the ADR-009
//! capability package, build the heap from the package Region, mint the
//! service endpoint through the package Factory, publish it in the ready
//! callback, then serve.
//!
//! Serving: the bin owns the recv loop (so it can intercept the process
//! protocol's `KILL` = shutdown for the smoke) and hands every other message
//! to the tested [`vfs::server::VfsServer`] core — `CONNECT` plus the full
//! ramfs op set (WALK/OPEN/READ/WRITE/READDIR/STAT/…). After the first
//! connection, requests are received on its connection endpoint (design §1.2).
//!
//! The syscall adapters here are zero-sized: [`sdk::syscall::X86_64Syscalls`]
//! is stateless, so each method builds a transient `Syscalls` — no persistent
//! borrow of the backend is needed, which keeps the kernel/transport/windows
//! objects separate (the same split the VFS tests use: the server owns the
//! `VfsKernel`, the bin keeps the `Windows` mapper).

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use ipc::{CapSlot, Message, Rights};
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{HEAP_CHUNK, HEAP_CHUNKS, VFS_HEAP_VA_BASE, VFS_WINDOW_VA_BASE};
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};
use sdk::window::{WindowMapper, FLAG_READ, FLAG_WRITE};

use vfs::proto::{Span, Status as VfsStatus};
use vfs::runtime::{Handle as KernelHandle, Transport, VfsKernel, Windows};
use vfs::server::VfsServer;

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

const MAX_WINDOWS: usize = 128;

include!(concat!(env!("OUT_DIR"), "/child_image.rs"));
include!(concat!(env!("OUT_DIR"), "/posix_image.rs"));
include!(concat!(env!("OUT_DIR"), "/sh_image.rs"));
include!(concat!(env!("OUT_DIR"), "/cat_image.rs"));
include!(concat!(env!("OUT_DIR"), "/ls_image.rs"));
include!(concat!(env!("OUT_DIR"), "/echo_image.rs"));

/// Stateless transport: one transient `Syscalls` per call.
struct BinTransport;

impl BinTransport {
    /// Non-blocking recv for the accept loop (not part of the core
    /// `Transport` trait; the core only needs blocking recv).
    fn recv_nonblock(&mut self, on: KernelHandle) -> Result<Message, VfsStatus> {
        Syscalls::new(&mut X86_64Syscalls).recv_nonblock(on)
    }
}

impl Transport for BinTransport {
    fn recv(&mut self, on: KernelHandle) -> Result<Message, VfsStatus> {
        Syscalls::new(&mut X86_64Syscalls).recv(on)
    }

    fn reply(&mut self, msg: &Message) -> Result<(), VfsStatus> {
        Syscalls::new(&mut X86_64Syscalls).reply(msg)
    }

    fn reply_recv(&mut self, on: KernelHandle, msg: &Message) -> Result<Message, VfsStatus> {
        Syscalls::new(&mut X86_64Syscalls).reply_recv(on, msg)
    }

    fn send(&mut self, on: KernelHandle, msg: &Message) -> Result<(), VfsStatus> {
        Syscalls::new(&mut X86_64Syscalls).send(on, msg)
    }
}

/// Factory minting for the VFS core (owned by the server).
struct BinKernel {
    factory: KernelHandle,
}

impl VfsKernel for BinKernel {
    fn new_endpoint(&mut self) -> Result<KernelHandle, VfsStatus> {
        let reply = Syscalls::new(&mut X86_64Syscalls)
            .invoke(self.factory, &Message::new(methods::factory::NEW_ENDPOINT))?;
        let handle = reply.words[0] as KernelHandle;
        if handle == 0 {
            return Err(ipc::status::ENOMEM);
        }
        Ok(handle)
    }

    fn now_ns(&mut self) -> u64 {
        // v0 stub: no timer service yet (design §3; mtimes stay 0).
        0
    }
}

/// Lazy window mapping (owned by the bin, passed into the server per request).
struct BinWindows {
    windows: WindowMapper,
}

impl Windows for BinWindows {
    fn read(&mut self, window: KernelHandle, span: Span) -> Result<Vec<u8>, VfsStatus> {
        let w =
            self.windows
                .window_of(&mut Syscalls::new(&mut X86_64Syscalls), window, FLAG_READ)?;
        w.read(span.offset, span.len)
    }

    fn write(&mut self, window: KernelHandle, span: Span, data: &[u8]) -> Result<(), VfsStatus> {
        if span.len as usize != data.len() {
            return Err(ipc::status::EBADARG);
        }
        let w =
            self.windows
                .window_of(&mut Syscalls::new(&mut X86_64Syscalls), window, FLAG_WRITE)?;
        w.write(span.offset, data)
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut raw = X86_64Syscalls;

    // 1. Bootstrap package (handle 1, ADR-009): [aspace, thread, region, 4
    //    sessions, ps_ep] + tail[0] = Factory (same shape as PS).
    let package = {
        let mut sys = Syscalls::new(&mut raw);
        sdk::bootstrap::receive(&mut sys)
    };
    let package = match package {
        Ok(p) => p,
        Err(e) => Syscalls::new(&mut raw).exit(0xE1_00 | (e & 0xFF)),
    };

    // 2. Heap: 1 MiB from the package Region into our own AS.
    let span = {
        let mut src = RegionSource::new(
            &mut raw,
            package.region,
            package.aspace,
            VFS_HEAP_VA_BASE,
            HEAP_CHUNK,
        );
        src.map_startup(HEAP_CHUNKS)
    };
    let (heap_start, heap_len) = match span {
        Ok(v) => v,
        Err(e) => Syscalls::new(&mut raw).exit(0xE2_00 | (e & 0xFF)),
    };
    if let Err(e) = HEAP.init(heap_start, heap_len) {
        Syscalls::new(&mut raw).exit(0xE3_00 | (e & 0xFF));
    }

    // 3. Service endpoint through the package Factory (tail[0]).
    let factory = match package.optional[0] {
        Some(cap) => cap.handle(),
        None => Syscalls::new(&mut raw).exit(0xE1),
    };
    let service_ep = {
        let mut sys = Syscalls::new(&mut raw);
        match sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT)) {
            Ok(reply) if reply.words[0] != 0 => reply.words[0] as u32,
            _ => Syscalls::new(&mut raw).exit(0xE2),
        }
    };

    // 4. Ready callback (same contract as PS): service endpoint as
    //    capability descriptor 0, heap KiB in w1.
    {
        let mut sys = Syscalls::new(&mut raw);
        let mut ready = Message::new(sdk::bootstrap::READY_LABEL);
        ready.tag = ready.tag.with_caps(1);
        ready.words[0] = sdk::bootstrap::READY_MAGIC;
        ready.words[1] = HEAP.capacity() as u64;
        if ready
            .set_descriptor(
                0,
                CapSlot::pack(service_ep, Rights::SEND.union(Rights::GRANT)),
            )
            .is_none()
            || sys.send(package.process_server_ep, &ready).is_err()
        {
            Syscalls::new(&mut raw).exit(0xE5);
        }
    }

    // 5. Seed the v0 ramfs: `/hello` = "helios-vfs-ok" and `/child` = the
    // spawn payload PS loads through us (root-level single-component paths are
    // the v0 convention; a real /init + /bin population arrives with the
    // storage slice).
    let mut server = VfsServer::new(BinKernel { factory }, BinTransport, service_ep);
    let mut windows = BinWindows {
        windows: WindowMapper::new(package.aspace, VFS_WINDOW_VA_BASE, MAX_WINDOWS),
    };
    {
        let root = server.fs().root();
        if let Ok(file) = server.fs().create_file(root, "hello", 0o644, 0) {
            let _ = server.fs().write(file, 0, b"helios-vfs-ok", 0);
        }
        if HAS_CHILD_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "child", 0o755, 0) {
                let _ = server.fs().write(file, 0, CHILD_IMAGE, 0);
            }
        }
        if HAS_POSIX_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "posix", 0o755, 0) {
                let _ = server.fs().write(file, 0, POSIX_IMAGE, 0);
            }
        }
        if HAS_SH_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "sh", 0o755, 0) {
                let _ = server.fs().write(file, 0, SH_IMAGE, 0);
            }
        }
        if HAS_CAT_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "cat", 0o755, 0) {
                let _ = server.fs().write(file, 0, CAT_IMAGE, 0);
            }
        }
        if HAS_LS_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "ls", 0o755, 0) {
                let _ = server.fs().write(file, 0, LS_IMAGE, 0);
            }
        }
        if HAS_ECHO_IMAGE {
            if let Ok(file) = server.fs().create_file(root, "echo", 0o755, 0) {
                let _ = server.fs().write(file, 0, ECHO_IMAGE, 0);
            }
        }
    }
    // v0 accept loop: the service endpoint first (new CONNECTs), then the
    // established connections round-robin; when everything is idle, yield and
    // poll again (cooperative spin). A proper multi-endpoint wait is the
    // Phase-3 item; this shape serves serialized clients correctly.
    let mut shell = BinTransport;
    loop {
        let mut handled = match shell.recv_nonblock(service_ep) {
            Ok(msg) => serve(&mut server, &mut windows, &mut shell, service_ep, &msg),
            Err(_) => false,
        };
        let mut i = 0u64;
        while !handled {
            let Some(ep) = server.connection(i).map(|c| c.endpoint) else {
                break;
            };
            if let Ok(msg) = shell.recv_nonblock(ep) {
                handled = serve(&mut server, &mut windows, &mut shell, ep, &msg);
            }
            i += 1;
        }
        if !handled {
            // Nothing pending anywhere: yield so a blocked peer can run (it
            // may be about to send its next request or a new CONNECT), then
            // poll again. v0 polling accept loop — a proper wait primitive
            // (multi-endpoint select) is the Phase-3 item.
            let mut sys = Syscalls::new(&mut raw);
            let _ = sys.yield_now();
        }
    }
}

/// Serve one message: KILL acks and exits (v0 shutdown convention, same as
/// PS); otherwise the VfsServer core handles it on the endpoint it arrived
/// on (its `handle` resolves the connection by endpoint).
fn serve(
    server: &mut VfsServer<BinKernel, BinTransport>,
    windows: &mut BinWindows,
    shell: &mut BinTransport,
    on: u32,
    msg: &Message,
) -> bool {
    if msg.tag.label() == methods::process::KILL {
        let ack = Message::new(methods::process::KILL);
        let _ = shell.send(REPLY_CAP, &ack);
        Syscalls::new(&mut X86_64Syscalls).exit(msg.words[1] as i32);
    }
    if server.handle(on, msg, windows).is_err() {
        Syscalls::new(&mut X86_64Syscalls).exit(0xE7);
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0002)
}
