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
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use ipc::{CapSlot, Message, Rights};
use sdk::bootstrap::{self, receive, BootstrapPackage};
use sdk::elf::ElfImage;
use sdk::heap::{GlobalHeap, RegionSource};
use sdk::layout::{
    CHILD_STACK_PAGES, HEAP_CHUNK, HEAP_CHUNKS, PS_HEAP_VA_BASE, PS_SCRATCH_VA_BASE,
    PS_WINDOW_VA_BASE, USER_STACK_TOP,
};
use sdk::loader;
use sdk::methods;
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};

include!(concat!(env!("OUT_DIR"), "/child_image.rs"));

#[global_allocator]
static HEAP: GlobalHeap = GlobalHeap::new();

/// Connection endpoints currently served (each `CONNECT` mints one and the
/// serve loop polls them round-robin). Round-robin slots (v0 capacity 8).
const MAX_CONNS: usize = 8;
static CONNS: [AtomicU32; MAX_CONNS] = [const { AtomicU32::new(0) }; MAX_CONNS];
static NEXT_CONN: AtomicUsize = AtomicUsize::new(0);

/// Spawned-child table: pid -> (thread-control cap, exit notification), so
/// `WAIT`/`KILL` work for every client (the old single-child statics broke as
/// soon as a process tree existed: a child spawning its own child). Slots are
/// assigned round-robin; capacity 4 (the full process table arrives with
/// fork/exec).
const MAX_CHILDREN: usize = 4;
static CH_PIDS: [AtomicU64; MAX_CHILDREN] = [const { AtomicU64::new(0) }; MAX_CHILDREN];
static CH_CAPS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
static CH_NOTIFS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
static NEXT_CHILD: AtomicUsize = AtomicUsize::new(0);

fn child_slot(pid: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    (0..MAX_CHILDREN).find(|&i| CH_PIDS[i].load(Ordering::Relaxed) == pid)
}

fn register_child(pid: u64, cap: u32, notif: u32) {
    // Reuse a slot already carrying this pid: pids are recycled once a child
    // is reaped, and a stale earlier registration would make `child_slot`
    // find the dead child's already-consumed notification (found via the
    // demo inheriting the child's pid and WAIT polling the wrong notif).
    let mut i = NEXT_CHILD.fetch_add(1, Ordering::Relaxed) % MAX_CHILDREN;
    for k in 0..MAX_CHILDREN {
        if CH_PIDS[k].load(Ordering::Relaxed) == pid {
            i = k;
            break;
        }
    }
    CH_PIDS[i].store(pid, Ordering::Relaxed);
    CH_CAPS[i].store(cap, Ordering::Relaxed);
    CH_NOTIFS[i].store(notif, Ordering::Relaxed);
}

fn register_conn(ep: u32) {
    let i = NEXT_CONN.fetch_add(1, Ordering::Relaxed) % MAX_CONNS;
    CONNS[i].store(ep, Ordering::Relaxed);
}

/// Pin the child's package handles immediately at mint time: register/spill
/// reuse in the inlined spawn path has proven unreliable, so every value
/// travels through a volatile atomic instead of a plain local.
static CH_BOOT: AtomicU32 = AtomicU32::new(0);
static CH_S0: AtomicU32 = AtomicU32::new(0);
static CH_S1: AtomicU32 = AtomicU32::new(0);
static CH_S2: AtomicU32 = AtomicU32::new(0);
static CH_S3: AtomicU32 = AtomicU32::new(0);
/// The last pinned spawn handle: the child's thread-control cap. Lived on the
/// stack across the same heavy inlined path; a stale (still thread-typed)
/// value made BIND_DEATH_NOTIFICATION silently bind the wrong thread.
static CH_THREAD: AtomicU32 = AtomicU32::new(0);
/// And the death notification that the BIND descriptor carries: a stale
/// value silently turns BIND into a clear (non-notification descriptor ->
/// bound=None -> Ok), so the child's death never fires.
static CH_EXIT_NOTIF: AtomicU32 = AtomicU32::new(0);

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

    // 6. Serve loop (design §1.7), multiplexed: the service endpoint accepts
    //    new connections; every established connection is served round-robin;
    //    idle iterations yield. A single-connection loop deadlocks as soon as
    //    two clients exist (a child spawning its own child), so the loop polls
    //    like the VFS's. `WAIT` is non-blocking (the caller polls): deferring
    //    a reply needs a kernel reply-handle primitive the v0 ABI lacks
    //    (board: ADR candidate).
    let mut sys = Syscalls::new(&mut raw);
    loop {
        let mut served = false;

        // New connections (accept endpoint).
        if let Ok(req) = sys.recv_nonblock(service_ep) {
            served = true;
            let reply = match req.tag.label() {
                methods::process::CONNECT => {
                    let slot = NEXT_CONN.load(Ordering::Relaxed) % MAX_CONNS;
                    let (reply, conn_ep) = connect_reply(&mut sys, &package, &req, factory, slot);
                    if let Some(ep) = conn_ep {
                        register_conn(ep);
                    }
                    reply
                }
                label => {
                    let mut reply = Message::new(label);
                    reply.words[0] = ipc::status::ENOSYS as i64 as u64;
                    reply
                }
            };
            let _ = sys.reply(&reply);
        }

        // Established connections, round-robin.
        let mut i = 0;
        while !served && i < MAX_CONNS {
            let c = CONNS[i].load(Ordering::Relaxed);
            i += 1;
            if c == 0 {
                continue;
            }
            let Ok(req) = sys.recv_nonblock(c) else {
                continue;
            };
            served = true;
            let reply = match req.tag.label() {
                methods::process::SPAWN => {
                    // The caller's spawn blob sits in ITS window pair (slot i).
                    let win_base = PS_WINDOW_VA_BASE + ((i - 1) as u64) * 0x2000;
                    spawn_reply(&mut sys, &package, &req, factory, service_ep, win_base)
                }
                methods::process::WAIT => wait_reply(&mut sys, &req),
                methods::process::KILL => {
                    let target = req.words[0];
                    if let Some(slot) = child_slot(target) {
                        // Kill the spawned child via its thread-control cap.
                        let cap = CH_CAPS[slot].load(Ordering::Relaxed);
                        let mut r = Message::new(methods::process::KILL);
                        let mut m = Message::new(methods::thread::KILL);
                        m.words[0] = req.words[1];
                        if cap == 0 || sys.invoke(cap, &m).is_err() {
                            r.words[0] = ipc::status::EBADCAP as i64 as u64;
                        }
                        r
                    } else {
                        // v0 launcher shutdown: ack, then exit with the
                        // caller's raw status (design §2.6).
                        let ack = Message::new(methods::process::KILL);
                        let _ = sys.send(REPLY_CAP, &ack);
                        Syscalls::new(&mut raw).exit(req.words[1] as i32);
                    }
                }
                label => {
                    let mut reply = Message::new(label);
                    reply.words[0] = ipc::status::ENOSYS as i64 as u64;
                    reply
                }
            };
            let _ = sys.reply(&reply);
        }

        if !served {
            let _ = sys.yield_now();
        }
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
    factory: u32,
    slot: usize,
) -> (Message, Option<u32>) {
    // Each connection gets its own window pair in this AS (a single client
    // was assumed before; a process tree broke that): slot N maps to
    // `PS_WINDOW_VA_BASE + N * 0x2000` (+0x1000 for the result window).
    let win_base = PS_WINDOW_VA_BASE + (slot as u64) * 0x2000;
    let mut reply = Message::new(methods::process::CONNECT);
    if req.words[0] != 1 {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return (reply, None);
    }
    let window =
        |i: usize| -> Option<u32> { req.descriptor(i).map(|cs| cs.handle()).filter(|h| *h != 0) };
    // descriptor 0 = session notification (installed by the recv; retained
    // for the connection to bind later), 1 = arg frame, 2 = result frame.
    let (arg, result) = match (window(1), window(2)) {
        (Some(a), Some(r)) => (a, r),
        _ => {
            reply.words[0] = ipc::status::EBADARG as i64 as u64;
            return (reply, None);
        }
    };
    for (frame, va, flags) in [
        (arg, win_base, methods::map_flags::R),
        (result, win_base + 4096, methods::map_flags::W),
    ] {
        let mut map = Message::new(methods::aspace::MAP);
        map.tag = map.tag.with_caps(1);
        map.words[0] = va;
        map.words[1] = flags as u64;
        let _ = map.set_descriptor(0, CapSlot::pack(frame, Rights::READ));
        if let Err(e) = sys.invoke(package.aspace, &map) {
            reply.words[0] = e as i64 as u64;
            return (reply, None);
        }
    }
    // Mint the connection endpoint and hand it to the client (design §1.2).
    let conn_ep = match sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT)) {
        Ok(minted) if minted.words[0] != 0 => minted.words[0] as u32,
        Ok(_) => {
            reply.words[0] = ipc::status::ENOMEM as i64 as u64;
            return (reply, None);
        }
        Err(e) => {
            reply.words[0] = e as i64 as u64;
            return (reply, None);
        }
    };
    reply.tag = reply.tag.with_caps(1);
    if reply
        .set_descriptor(0, CapSlot::pack(conn_ep, Rights::SEND.union(Rights::RECV)))
        .is_none()
    {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return (reply, None);
    }
    reply.words[1] = 1; // connection id (v0: the single published endpoint)
    (reply, Some(conn_ep))
}

/// `SPAWN` (0x0110): v0 loads the embedded child image (no VFS yet; the
/// program word `w1` is ignored). `w2` packs the argv blob as
/// `(off << 32) | len` into the CONNECT **arg window** (PS reads it at
/// `PS_WINDOW_VA_BASE + off`). Replies `w0 = status, w1 = pid`; out caps:
/// descriptor 0 = thread control (`CONTROL`), 1 = exit notification
/// (`SIGNAL|RECV`) for the parent's own waiting.
fn spawn_reply(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    req: &Message,
    factory: u32,
    service_ep: u32,
    win_base: u64,
) -> Message {
    let mut reply = Message::new(methods::process::SPAWN);

    // Program image (design §2.6): with the VFS service endpoint in cap 0
    // and a path span in w1, the image is loaded through the VFS; v0 has no
    // filesystem-less fallback except the embedded image (dev builds).
    // SPAWN input caps, positionally (design §2.6): (vfs, stdin, stdout,
    // stderr). They ride into the child's package tail as `optional[0..4]`;
    // absent slots stay absent (holes preserved).
    let mut extras: [Option<u32>; 4] = [None; 4];
    for (i, slot) in extras.iter_mut().enumerate() {
        *slot = req.descriptor(i).map(|cs| cs.handle()).filter(|h| *h != 0);
    }
    let vfs_svc = extras[0];
    // v0 SPAWN payload blob in the caller's CONNECT arg window (design §2.6
    // "argv/env in the arg window"): `[u64 path_span][u64 argv_span]` then
    // the string bytes. Words cannot carry spans alongside 3+ descriptors
    // (descriptors overlay the trailing words).
    let (path_off, path_len, arg_off, arg_len) = {
        let f = win_base as *const u8;
        // SAFETY: our CONNECT arg window is mapped R in this AS.
        unsafe {
            let rd = |o: usize| core::ptr::read_unaligned(f.add(o) as *const u64);
            let ps = rd(0);
            let ar = rd(8);
            (
                (ps >> 32) as usize,
                (ps & 0xFFFF_FFFF) as usize,
                (ar >> 32) as usize,
                (ar & 0xFFFF_FFFF) as usize,
            )
        }
    };
    if path_len == 0
        || path_off.checked_add(path_len).map_or(true, |e| e > 4096)
        || arg_off.checked_add(arg_len).map_or(true, |e| e > 4096)
    {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return reply;
    }
    let loaded: Option<Vec<u8>> = match vfs_svc {
        Some(svc) if path_len != 0 => {
            match load_via_vfs(sys, package, factory, svc, path_off, path_len, win_base) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    reply.words[0] = e as i64 as u64;
                    return reply;
                }
            }
        }
        _ => {
            if !HAS_CHILD_IMAGE {
                reply.words[0] = ipc::status::ENOSYS as i64 as u64;
                return reply;
            }
            None
        }
    };
    let image: &[u8] = loaded.as_deref().unwrap_or(CHILD_IMAGE);
    match spawn_child(
        sys, package, factory, service_ep, arg_off, arg_len, image, extras, win_base,
    ) {
        Ok((pid, thread_cap, exit_notif)) => {
            reply.words[1] = pid;
            reply.tag = reply.tag.with_caps(2);
            let _ = reply.set_descriptor(0, CapSlot::pack(thread_cap, Rights::CONTROL));
            let _ = reply.set_descriptor(
                1,
                CapSlot::pack(exit_notif, Rights::SIGNAL.union(Rights::RECV)),
            );
        }
        Err(e) => reply.words[0] = e as i64 as u64,
    }
    reply
}

/// Build the child: fresh AS, embedded ELF, crafted stack, thread with a
/// bootstrap package, and PS's death binding (`N_dead`, design §1.5).
/// Returns `(pid, thread_control, exit_notif)`.
#[allow(clippy::too_many_arguments)]
fn spawn_child(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    factory: u32,
    service_ep: u32,
    arg_off: usize,
    arg_len: usize,
    image_bytes: &[u8],
    extras: [Option<u32>; 4],
    win_base: u64,
) -> Result<(u64, u32, u32), i32> {
    // 1. Child address space.
    let child_as = invoke_w0(sys, factory, methods::factory::NEW_ADDRESS_SPACE, [0; 4])? as u32;
    if child_as == 0 {
        return Err(ipc::status::ENOMEM);
    }
    // 2. ELF (embedded or VFS-loaded) → segments into the child AS.
    let image = ElfImage::parse(image_bytes)?;
    let ops = loader::plan(&image, PS_SCRATCH_VA_BASE)?;
    loader::execute(
        sys,
        &mut loader::MemoryWriter,
        &ops,
        child_as,
        package.region,
        package.aspace,
        image_bytes,
    )?;
    // 3. Stack: ANON pages below the crafted top page (v0 convention: the
    //    child reads [sp-8] = argc, [sp-16] = argv[0] at sp = USER_STACK_TOP).
    loader::map_anon(
        sys,
        child_as,
        USER_STACK_TOP - CHILD_STACK_PAGES * 4096,
        CHILD_STACK_PAGES - 1,
        0b011,
    )?;
    craft_stack(sys, package, child_as, arg_off, arg_len, win_base)?;
    // 4. Endpoints + notifications for the child's package (straight-line
    // mints; no arrays — spill-slot reuse made the old form unreliable).
    let bootstrap_ep = invoke_w0(sys, factory, methods::factory::NEW_ENDPOINT, [0; 4])? as u32;
    CH_BOOT.store(bootstrap_ep, Ordering::Relaxed);
    let s0 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    CH_S0.store(s0, Ordering::Relaxed);
    let s1 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    CH_S1.store(s1, Ordering::Relaxed);
    let s2 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    CH_S2.store(s2, Ordering::Relaxed);
    let s3 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    CH_S3.store(s3, Ordering::Relaxed);
    let exit_notif = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    CH_EXIT_NOTIF.store(exit_notif, Ordering::Relaxed);
    // 5. Child thread (ADR-017 packing; ADR-009 bootstrap at child handle 1).
    let mut m = Message::new(methods::factory::NEW_THREAD);
    m.tag = m.tag.with_caps(3);
    m.words[0] = image.entry;
    let _ = m.set_descriptor(0, CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
    let _ = m.set_descriptor(1, CapSlot::NULL);
    let _ = m.set_descriptor(2, CapSlot::pack(bootstrap_ep, Rights::RECV));
    let thread_reply = sys.invoke(factory, &m)?;
    let thread_cap = thread_reply.words[0] as u32;
    let pid = thread_reply.words[2];
    if thread_cap == 0 {
        return Err(ipc::status::ENOMEM);
    }
    CH_THREAD.store(thread_cap, Ordering::Relaxed);
    // 7. ADR-009 package: fixed prefix + the optional tail (design §2.3
    //    order: vfs, stdin, stdout, stderr), holes preserved positionally.
    //    Regular processes get no Factory. Stack array: the Vec form was
    //    silently corrupted (heap aliasing).
    let session_rights = Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT);
    let mut caps = [CapSlot::NULL; bootstrap::FIXED_CAPS + 4];
    caps[0] = CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT));
    caps[1] = CapSlot::pack(CH_THREAD.load(Ordering::Relaxed), Rights::CONTROL);
    caps[2] = CapSlot::pack(package.region, Rights::GRANT);
    caps[3] = CapSlot::pack(CH_S0.load(Ordering::Relaxed), session_rights);
    caps[4] = CapSlot::pack(CH_S1.load(Ordering::Relaxed), session_rights);
    caps[5] = CapSlot::pack(CH_S2.load(Ordering::Relaxed), session_rights);
    caps[6] = CapSlot::pack(CH_S3.load(Ordering::Relaxed), session_rights);
    caps[7] = CapSlot::pack(service_ep, Rights::SEND.union(Rights::GRANT));
    let mut total = bootstrap::FIXED_CAPS;
    for (i, extra) in extras.iter().enumerate() {
        if let Some(handle) = extra {
            caps[bootstrap::FIXED_CAPS + i] =
                CapSlot::pack(*handle, Rights::SEND.union(Rights::GRANT));
            total = bootstrap::FIXED_CAPS + 1 + i;
        }
    }
    // 6. PS's death binding on the child thread.
    let mut bind = Message::new(methods::thread::BIND_DEATH_NOTIFICATION);
    bind.tag = bind.tag.with_caps(1);
    let _ = bind.set_descriptor(
        0,
        CapSlot::pack(CH_EXIT_NOTIF.load(Ordering::Relaxed), Rights::SIGNAL),
    );
    sys.invoke(CH_THREAD.load(Ordering::Relaxed), &bind)?;

    bootstrap::deliver(sys, CH_BOOT.load(Ordering::Relaxed), &caps[..total])?;
    // 8. Publish for WAIT/KILL (per-client table slot; round-robin).
    register_child(pid, thread_cap, exit_notif);
    Ok((pid, thread_cap, exit_notif))
}

/// Load a program image through the VFS (design §2.6/§3.3): CONNECT (fresh
/// session + arg/result windows at PS_WINDOW_VA_BASE + 0x2000/+0x3000), OPEN
/// the path (read from the CONNECT arg window at `path_off`), then READ 4 KiB
/// chunks into the result window until EOF, accumulating on the heap.
fn load_via_vfs(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    factory: u32,
    vfs_svc: u32,
    path_off: usize,
    path_len: usize,
    win_base: u64,
) -> Result<Vec<u8>, i32> {
    if path_len == 0 || path_off.checked_add(path_len).map_or(true, |e| e > 4096) {
        return Err(ipc::status::EBADARG);
    }
    // Dedicated load-window area, clear of the per-connection window pairs
    // (`PS_WINDOW_VA_BASE + slot * 0x2000`) and unmapped after every load, so
    // sequential spawns reuse it.
    let arg_va = PS_WINDOW_VA_BASE + 0x10_0000;
    let result_va = PS_WINDOW_VA_BASE + 0x10_1000;
    let session = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    let arg_frame = invoke_w0(
        sys,
        package.region,
        methods::region::CARVE,
        [4096, 4096, 0, 0],
    )? as u32;
    let result_frame = invoke_w0(
        sys,
        package.region,
        methods::region::CARVE,
        [4096, 4096, 0, 0],
    )? as u32;
    if session == 0 || arg_frame == 0 || result_frame == 0 {
        return Err(ipc::status::ENOMEM);
    }
    for (frame, va) in [(arg_frame, arg_va), (result_frame, result_va)] {
        invoke_map(sys, package.aspace, va, 0b011, frame as u64)?;
    }
    let mut connect = Message::new(methods::vfs::CONNECT);
    connect.tag = connect.tag.with_caps(3);
    connect.words[0] = 1;
    let _ = connect.set_descriptor(0, CapSlot::pack(session, Rights::SIGNAL));
    let _ = connect.set_descriptor(
        1,
        CapSlot::pack(arg_frame, Rights::READ.union(Rights::WRITE)),
    );
    let _ = connect.set_descriptor(
        2,
        CapSlot::pack(
            result_frame,
            Rights::READ.union(Rights::WRITE).union(Rights::MAP),
        ),
    );
    let conn = sys.call(vfs_svc, &connect)?;
    if conn.words[0] != 0 {
        return Err(conn.words[0] as i64 as i32);
    }
    let conn_ep = conn
        .descriptor(0)
        .map(|cs| cs.handle())
        .filter(|h| *h != 0)
        .ok_or(ipc::status::EBADCAP)?;
    let root = conn.words[2];
    if root == 0 {
        return Err(ipc::status::EBADCAP);
    }
    // Copy the path into the VFS arg window (its first bytes) and OPEN it.
    let path =
        unsafe { core::slice::from_raw_parts((win_base + path_off as u64) as *const u8, path_len) };
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), arg_va as *mut u8, path_len);
    }
    let mut open = Message::new(methods::vfs::OPEN);
    open.words[0] = root;
    open.words[1] = path_len as u64; // Span { off 0, len path_len }
    open.words[2] = methods::vfs_open::READ as u64;
    let opened = sys.call(conn_ep, &open)?;
    if opened.words[0] != 0 {
        return Err(opened.words[0] as i64 as i32);
    }
    let file = opened.words[1];
    if file == 0 {
        return Err(ipc::status::EBADCAP);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut offset = 0u64;
    loop {
        if out.len() > 1 << 20 {
            return Err(ipc::status::ENOMEM); // v0 bound: 1 MiB images
        }
        let mut read = Message::new(methods::vfs::READ);
        read.words[0] = file;
        read.words[1] = offset;
        read.words[2] = 4096;
        read.words[3] = 0; // result-window offset
        let reply = sys.call(conn_ep, &read)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let count = (reply.words[1] as usize).min(4096);
        if count == 0 {
            break;
        }
        let chunk = unsafe { core::slice::from_raw_parts(result_va as *const u8, count) };
        out.extend_from_slice(chunk);
        offset += count as u64;
        if count < 4096 {
            break;
        }
    }
    // Release the window VAs for the next SPAWN (the frames stay alive via
    // our caps; the VFS's own mappings of them are unaffected). Re-mapping
    // over an existing mapping is an overlap error — the second VFS-backed
    // spawn hit exactly that.
    for va in [arg_va, result_va] {
        let mut unmap = Message::new(methods::aspace::UNMAP);
        unmap.words[0] = va;
        let _ = sys.invoke(package.aspace, &unmap);
    }
    if out.is_empty() {
        return Err(ipc::status::EBADARG);
    }
    Ok(out)
}

/// Carve one frame, write the crafted initial stack page (argc + argv blob +
/// string table), map it as the child's top stack page, drop the scratch.
fn craft_stack(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    child_as: u32,
    arg_off: usize,
    arg_len: usize,
    win_base: u64,
) -> Result<(), i32> {
    let frame = invoke_w0(
        sys,
        package.region,
        methods::region::CARVE,
        [4096, 4096, 0, 0],
    )?;
    if frame == 0 {
        return Err(ipc::status::ENOMEM);
    }
    invoke_map(sys, package.aspace, PS_SCRATCH_VA_BASE, 0b011, frame)?;
    let mut page = [0u8; 4096];
    // Header at the very top ([TOP-8] = argc, [TOP-16] = argv[0]), captured
    // by the child's entry stub before any push. The STRING TABLE lives low
    // in the page (offset 0x800), well below the child's early stack frames —
    // parking it near the header got it clobbered by child_main's own frame.
    // argv[0] is NUL-terminated by the zeroed page. (v0: single argv.)
    let str_off = 0x800;
    if str_off + arg_len > 4096 - 24 {
        return Err(-103); // argv blob too large for the crafted page
    }
    for (i, b) in page[str_off..str_off + arg_len].iter_mut().enumerate() {
        *b = unsafe { *((win_base as *const u8).add(arg_off + i)) };
    }
    let argv0_va = (USER_STACK_TOP - 4096) + str_off as u64;
    page[4096 - 8..4096].copy_from_slice(&1u64.to_le_bytes()); // argc = 1
    page[4096 - 16..4096 - 8].copy_from_slice(&argv0_va.to_le_bytes());
    unsafe {
        core::ptr::copy_nonoverlapping(page.as_ptr(), PS_SCRATCH_VA_BASE as *mut u8, 4096);
    }
    invoke_map(sys, child_as, USER_STACK_TOP - 4096, 0b011, frame)?;
    let mut m = Message::new(methods::aspace::UNMAP);
    m.words[0] = PS_SCRATCH_VA_BASE;
    sys.invoke(package.aspace, &m)?;
    Ok(())
}

/// `WAIT` (0x0111): v0 blocking wait on the single child's death
/// notification (design §2.6); replies `w0 = status, w1 = child's raw exit
/// status` (kernel payload convention: bit 0 = event, bits 32.. = status).
/// `WAIT`: non-blocking poll of the child's death notification. A dead child
/// yields its exit status; a live child yields `EWOULDBLOCK` and the caller
/// polls (yielding). Deferring the reply until death would need a kernel
/// reply-handle primitive (the implicit reply slot rebinds on the next call),
/// so v0 keeps the wait on the caller's side (cooperative polling).
fn wait_reply(sys: &mut Syscalls<'_, X86_64Syscalls>, req: &Message) -> Message {
    let mut reply = Message::new(methods::process::WAIT);
    let Some(slot) = child_slot(req.words[0]) else {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return reply;
    };
    let notif = CH_NOTIFS[slot].load(Ordering::Relaxed);
    loop {
        match sys.recv_nonblock(notif) {
            Ok(notified) => {
                let mask = notified.words[0];
                if mask & 1 != 0 {
                    reply.words[1] = (mask >> 32) as u32 as i32 as i64 as u64;
                    return reply;
                }
                // Spurious signal bits: drained, keep polling.
            }
            Err(_) => {
                reply.words[0] = ipc::status::EWOULDBLOCK as i64 as u64;
                return reply;
            }
        }
    }
}

/// `invoke` returning the reply's `w0`.
fn invoke_w0(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    cap: u32,
    method: u16,
    words: [u64; 4],
) -> Result<u64, i32> {
    let mut m = Message::new(method);
    m.words = words;
    sys.invoke(cap, &m).map(|r| r.words[0])
}

/// `AddressSpace::MAP` of a frame cap (window/stack mapping helper).
fn invoke_map(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    as_cap: u32,
    vaddr: u64,
    flags: u64,
    frame: u64,
) -> Result<(), i32> {
    let mut m = Message::new(methods::aspace::MAP);
    m.tag = m.tag.with_caps(1);
    m.words[0] = vaddr;
    m.words[1] = flags;
    let _ = m.set_descriptor(
        0,
        CapSlot::pack(frame as u32, Rights::READ.union(Rights::WRITE)),
    );
    sys.invoke(as_cap, &m).map(|_| ())
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    Syscalls::new(&mut X86_64Syscalls).exit(0x0BAD_0000)
}
