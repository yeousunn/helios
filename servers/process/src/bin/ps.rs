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
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use ipc::{CapSlot, Message, Rights};
use sdk::bootstrap::{self, receive, BootstrapPackage};
use sdk::elf::ElfImage;
use sdk::heap::RegionSource;
use sdk::layout::{
    CHILD_STACK_PAGES, HEAP_CHUNK, HEAP_CHUNKS, PS_HEAP_VA_BASE, PS_SCRATCH_VA_BASE,
    PS_WINDOW_VA_BASE, USER_STACK_TOP,
};
use sdk::loader;
use sdk::methods;
use sdk::sys::SysHeap;
use sdk::sys::{raw_copy_from_va, raw_copy_from_va_to_u64x3, raw_copy_to_va};
use sdk::syscall::{Syscalls, X86_64Syscalls, REPLY_CAP};
use sdk::window::{MappedWindow, WindowMapper, FLAG_READ, FLAG_WRITE};

include!(concat!(env!("OUT_DIR"), "/child_image.rs"));

#[global_allocator]
static HEAP: SysHeap = SysHeap::new();

sdk::sys::server_entry_point!(ps_main);

/// Connection endpoints currently served (each `CONNECT` mints one and the
/// serve loop polls them round-robin). Must exceed the number of LIVE
/// connections for the whole run: the ring wraps at MAX_CONNS and an early
/// connection (init's smoke session) being evicted by a newer one silently
/// orphans its mailbox (found via the pipeline: connection #16 overwrote
/// init's slot mid-smoke and its final WAIT went unconsumed).
const MAX_CONNS: usize = 32;
static CONNS: [AtomicU32; MAX_CONNS] = [const { AtomicU32::new(0) }; MAX_CONNS];
static NEXT_CONN: AtomicUsize = AtomicUsize::new(0);

/// Spawned-child table: pid -> (thread-control cap, exit notification), so
/// `WAIT`/`KILL` work for every client (the old single-child statics broke as
/// soon as a process tree existed: a child spawning its own child). Slots are
/// assigned round-robin; capacity 4 (the full process table arrives with
/// fork/exec).
/// Child registrations (WAIT/KILL/EXEC lookup). Must hold every child that
/// can be live at once: a pipeline spawns N concurrent children and the
/// launcher's smoke keeps a few alive, so 4 collided (round-robin reuse of a
/// slot still holding a live pid made `child_slot` miss → WAIT EBADARG).
const MAX_CHILDREN: usize = 16;
static CH_PIDS: [AtomicU64; MAX_CHILDREN] = [const { AtomicU64::new(0) }; MAX_CHILDREN];
static CH_CAPS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
static CH_NOTIFS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
/// The child's AS cap and the VFS service endpoint its SPAWN carried — EXEC
/// loads the replacement image through both.
static CH_AS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
static CH_VFS: [AtomicU32; MAX_CHILDREN] = [const { AtomicU32::new(0) }; MAX_CHILDREN];
static NEXT_CHILD: AtomicUsize = AtomicUsize::new(0);

/// Caller pid per connection (the CONNECT message carries `w1 = self pid`),
/// so EXEC can resolve "the calling process" without extra capabilities.
static CONN_PIDS: [AtomicU64; MAX_CONNS] = [const { AtomicU64::new(0) }; MAX_CONNS];

/// PS's one persistent VFS connection for program loads (lazily created on
/// the first load). Was one connection + two window frames + a notification
/// PER load: the VFS never reclaims a connection's windows (no disconnect),
/// so per-load connections exhausted the VFS's window mapper after ~60 loads.
static LOAD_CONN: AtomicU32 = AtomicU32::new(0);
static LOAD_ROOT: AtomicU64 = AtomicU64::new(0);
/// Cached window frames for the dedicated load path (mapped once, reused).
static LOAD_ARG_FRAME: AtomicU32 = AtomicU32::new(0);
static LOAD_RESULT_FRAME: AtomicU32 = AtomicU32::new(0);

fn child_slot(pid: u64) -> Option<usize> {
    if pid == 0 {
        return None;
    }
    (0..MAX_CHILDREN).find(|&i| CH_PIDS[i].load(Ordering::Relaxed) == pid)
}

fn register_child(pid: u64, cap: u32, notif: u32, as_cap: u32, vfs: u32) {
    // Reuse a slot already carrying this pid: pids are recycled once a child
    // is reaped, and a stale earlier registration would make `child_slot`
    // find the dead child's already-consumed notification (found via the
    // demo inheriting the child's pid and WAIT polling the wrong notif).
    let mut i = NEXT_CHILD.fetch_add(1, Ordering::Relaxed) % MAX_CHILDREN;
    for (k, slot) in CH_PIDS.iter().enumerate() {
        if slot.load(Ordering::Relaxed) == pid {
            i = k;
            break;
        }
    }
    CH_PIDS[i].store(pid, Ordering::Relaxed);
    CH_CAPS[i].store(cap, Ordering::Relaxed);
    CH_NOTIFS[i].store(notif, Ordering::Relaxed);
    CH_AS[i].store(as_cap, Ordering::Relaxed);
    CH_VFS[i].store(vfs, Ordering::Relaxed);
}

fn register_conn(ep: u32, pid: u64) {
    let i = NEXT_CONN.fetch_add(1, Ordering::Relaxed) % MAX_CONNS;
    CONNS[i].store(ep, Ordering::Relaxed);
    CONN_PIDS[i].store(pid, Ordering::Relaxed);
}

fn ps_main() -> ! {
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

    // 4. Mint our service endpoint through the Factory (optional[4]).
    let factory = match package.optional[4] {
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
    // Persistent program-load buffer, reused across every SPAWN/EXEC. PS's heap
    // is a bump allocator whose dealloc is a no-op (sdk::heap), so a fresh
    // `Vec` per load leaked the whole image every time: repeated 200 KiB
    // `linrun` loads exhausted the 1 MiB heap and panicked PS. One buffer,
    // cleared and re-reserved per load, bounds heap use to the largest image.
    let mut load_buf: Vec<u8> = Vec::new();
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
                        // Caller identity: pid in w0's upper half (the window
                        // descriptor overlay rules out extra data words).
                        register_conn(ep, req.words[0] >> 32);
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
                    Some(spawn_reply(
                        &mut sys,
                        &package,
                        &req,
                        factory,
                        service_ep,
                        win_base,
                        &mut load_buf,
                    ))
                }
                methods::process::WAIT => Some(wait_reply(&mut sys, &req)),
                methods::process::PIPE => Some(pipe_reply(&mut sys, factory)),
                // `None` = exec took effect: the caller's context was replaced
                // and must not receive the reply.
                methods::process::EXEC => exec_reply(
                    &mut sys,
                    &package,
                    factory,
                    CONN_PIDS[i - 1].load(Ordering::Relaxed),
                    PS_WINDOW_VA_BASE + ((i - 1) as u64) * 0x2000,
                    &mut load_buf,
                ),
                methods::process::KILL => Some({
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
                        // caller's raw status (design §2.6). The launcher (init)
                        // always sends raw_status = 0; clamp to u8 range to
                        // defend against bogus messages.
                        let raw_status = (req.words[1] & 0xFF) as i32;
                        let ack = Message::new(methods::process::KILL);
                        let _ = sys.send(REPLY_CAP, &ack);
                        Syscalls::new(&mut raw).exit(raw_status);
                    }
                }),
                label => Some({
                    let mut reply = Message::new(label);
                    reply.words[0] = ipc::status::ENOSYS as i64 as u64;
                    reply
                }),
            };
            if let Some(reply) = reply {
                let _ = sys.reply(&reply);
            }
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
    if req.words[0] & 0xFFFF_FFFF != 1 {
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
    // The slot's window VAs may still carry the previous (dead) connection's
    // mappings — slot reuse after MAX_CONNS wraps. Unmap before re-mapping
    // (v0: the stale frames leak; bounded by MAX_CONNS * 2 pages).
    for va in [win_base, win_base + 4096] {
        let mut un = Message::new(methods::aspace::UNMAP);
        un.words[0] = va;
        un.words[1] = 1;
        let _ = sys.invoke(package.aspace, &un);
    }
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
    load_buf: &mut Vec<u8>,
) -> Message {
    let mut reply = Message::new(methods::process::SPAWN);

    // Program image (design §2.6): with the VFS service endpoint in cap 0
    // and a path span in w1, the image is loaded through the VFS; v0 has no
    // filesystem-less fallback except the embedded image (dev builds).
    // SPAWN input caps, positionally (design §2.6): (vfs, stdin, stdout,
    // stderr). They ride into the child's package tail as `optional[0..4]`;
    // absent slots stay absent (holes preserved).
    let mut extras: [Option<(u32, Rights)>; 4] = [None; 4];
    for (i, slot) in extras.iter_mut().enumerate() {
        *slot = req
            .descriptor(i)
            .map(|cs| (cs.handle(), cs.rights()))
            .filter(|(h, _)| *h != 0);
    }
    let vfs_svc = extras[0].map(|(h, _)| h);
    // v0.2 SPAWN payload blob in the caller's CONNECT arg window (design
    // §2.6 "argv/env in the arg window"): `[u64 path_span][u64 argv_span]
    // [u64 env_span]` then path bytes, the argv area (NUL-separated strings)
    // and the env area. Words cannot carry spans alongside 3+ descriptors
    // (descriptors overlay the trailing words). See `sdk::spawn`.
    let mut header = [0u64; 3];
    raw_copy_from_va_to_u64x3(win_base, &mut header);
    let span = |w: u64| ((w >> 32) as usize, (w & 0xFFFF_FFFF) as usize);
    let (path_off, path_len) = span(header[0]);
    let (arg_off, arg_len) = span(header[1]);
    let (env_off, env_len) = span(header[2]);
    let span_ok = |off: usize, len: usize| off.checked_add(len).is_some_and(|e| e <= 4096);
    if path_len == 0
        || !span_ok(path_off, path_len)
        || !span_ok(arg_off, arg_len)
        || !span_ok(env_off, env_len)
    {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return reply;
    }
    let loaded: usize = match vfs_svc {
        Some(svc) if path_len != 0 => {
            match load_via_vfs(
                sys,
                package,
                factory,
                VfsLoadParams {
                    vfs_svc: svc,
                    path_span: (path_off, path_len),
                    win_base,
                },
                load_buf,
            ) {
                Ok(n) => n,
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
            0
        }
    };
    let image: &[u8] = if loaded == 0 {
        CHILD_IMAGE
    } else {
        &load_buf[..loaded]
    };
    match spawn_child(
        sys,
        package,
        factory,
        service_ep,
        (arg_off, arg_len),
        (env_off, env_len),
        image,
        extras,
        win_base,
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
#[allow(clippy::type_complexity)]
fn spawn_child(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    factory: u32,
    service_ep: u32,
    argv_span: (usize, usize),
    env_span: (usize, usize),
    image_bytes: &[u8],
    extras: [Option<(u32, Rights)>; 4],
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
    craft_stack(sys, package, child_as, argv_span, env_span, win_base)?;
    // 4. Endpoints + notifications for the child's package.
    let bootstrap_ep = invoke_w0(sys, factory, methods::factory::NEW_ENDPOINT, [0; 4])? as u32;
    let s0 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    let s1 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    let s2 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    let s3 = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    let exit_notif = invoke_w0(sys, factory, methods::factory::NEW_NOTIFICATION, [0; 4])? as u32;
    // 5. Child thread (ADR-088 uniform packing): w0 = entry; caps[0] = AS (input),
    // caps[1] = bootstrap EP (fault EP moved to BIND_FAULT_EP post-creation).
    let mut m = Message::new(methods::factory::NEW_THREAD);
    m.tag = m.tag.with_caps(2);
    m.words[0] = image.entry;
    let _ = m.set_descriptor(0, CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT)));
    let _ = m.set_descriptor(1, CapSlot::pack(bootstrap_ep, Rights::RECV));
    let thread_reply = sys.invoke(factory, &m)?;
    let thread_cap = thread_reply.words[0] as u32;
    let pid = thread_reply.words[2];
    if thread_cap == 0 {
        return Err(ipc::status::ENOMEM);
    }
    // 7. ADR-009 package: fixed prefix + the optional tail (design §2.3
    //    order: vfs, stdin, stdout, stderr, factory), holes preserved
    //    positionally. The factory cap (tail[4]) lets children spawn further
    //    processes (required for attack mode). Personality bins expect vfs at
    //    optional[0], so factory is placed after the four stdio caps.
    let session_rights = Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT);
    let mut caps = [CapSlot::NULL; bootstrap::FIXED_CAPS + 5];
    caps[0] = CapSlot::pack(child_as, Rights::MAP.union(Rights::GRANT));
    caps[1] = CapSlot::pack(thread_cap, Rights::CONTROL);
    caps[2] = CapSlot::pack(package.region, Rights::GRANT);
    caps[3] = CapSlot::pack(s0, session_rights);
    caps[4] = CapSlot::pack(s1, session_rights);
    caps[5] = CapSlot::pack(s2, session_rights);
    caps[6] = CapSlot::pack(s3, session_rights);
    caps[7] = CapSlot::pack(service_ep, Rights::SEND.union(Rights::GRANT));
    for (i, extra) in extras.iter().enumerate() {
        if let Some((handle, rights)) = extra {
            caps[bootstrap::FIXED_CAPS + i] = CapSlot::pack(*handle, *rights);
        }
    }
    caps[bootstrap::FIXED_CAPS + 4] = CapSlot::pack(factory, Rights::ALL);
    let mut total = bootstrap::FIXED_CAPS + 5;
    while total > bootstrap::FIXED_CAPS && caps[total - 1].handle() == ipc::NULL_HANDLE {
        total -= 1;
    }
    // 6. PS's death binding on the child thread.
    let mut bind = Message::new(methods::thread::BIND_DEATH_NOTIFICATION);
    bind.tag = bind.tag.with_caps(1);
    let _ = bind.set_descriptor(0, CapSlot::pack(exit_notif, Rights::SIGNAL));
    sys.invoke(thread_cap, &bind)?;

    bootstrap::deliver(sys, bootstrap_ep, &caps[..total], pid)?;
    // 8. Publish for WAIT/KILL/EXEC (per-client table slot; round-robin).
    register_child(
        pid,
        thread_cap,
        exit_notif,
        child_as,
        extras[0].map(|(h, _)| h).unwrap_or(0),
    );
    Ok((pid, thread_cap, exit_notif))
}

/// VFS load parameters grouped to reduce argument count.
struct VfsLoadParams {
    vfs_svc: u32,
    path_span: (usize, usize),
    win_base: u64,
}

/// Load a program image through the VFS (design §2.6/§3.3): CONNECT (fresh
/// session + arg/result windows at PS_WINDOW_VA_BASE + 0x2000/+0x3000), OPEN
/// the path (read from the CONNECT arg window at `path_off`), then READ 4 KiB
/// chunks into the result window until EOF, accumulating on the heap.
fn load_via_vfs(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    factory: u32,
    params: VfsLoadParams,
    buf: &mut Vec<u8>,
) -> Result<usize, i32> {
    let (path_off, path_len) = params.path_span;
    if path_len == 0 || path_off.checked_add(path_len).is_none_or(|e| e > 4096) {
        return Err(ipc::status::EBADARG);
    }
    // Dedicated load-window area, clear of the per-connection window pairs
    // (`PS_WINDOW_VA_BASE + slot * 0x2000`). Mapped once and kept for the
    // whole run (the connection and its windows are cached).
    const ARG_VA: u64 = PS_WINDOW_VA_BASE + 0x10_0000;
    const RESULT_VA: u64 = PS_WINDOW_VA_BASE + 0x10_1000;
    let mut conn_ep = LOAD_CONN.load(Ordering::Relaxed);
    let mut root = LOAD_ROOT.load(Ordering::Relaxed);
    if conn_ep == 0 {
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
        // Map frames using WindowMapper to get MappedWindow for bounds-checked access.
        let mut mapper = WindowMapper::new(package.aspace, ARG_VA, 2);
        let _arg_window = mapper.window_of(sys, arg_frame, FLAG_READ | FLAG_WRITE)?;
        let _result_window = mapper.window_of(sys, result_frame, FLAG_READ | FLAG_WRITE)?;
        // Cache frames for potential future use (though WindowMapper is recreated each call).
        LOAD_ARG_FRAME.store(arg_frame, Ordering::Relaxed);
        LOAD_RESULT_FRAME.store(result_frame, Ordering::Relaxed);
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
        let conn = sys.call(params.vfs_svc, &connect)?;
        if conn.words[0] != 0 {
            return Err(conn.words[0] as i64 as i32);
        }
        conn_ep = conn
            .descriptor(0)
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(ipc::status::EBADCAP)?;
        root = conn.words[2];
        if root == 0 {
            return Err(ipc::status::EBADCAP);
        }
        LOAD_CONN.store(conn_ep, Ordering::Relaxed);
        LOAD_ROOT.store(root, Ordering::Relaxed);
    }
    // Copy the path into the VFS arg window (its first bytes) and OPEN it.
    // Read path from caller's window and copy to VFS arg window.
    let mut path = vec![0u8; path_len];
    raw_copy_from_va(params.win_base + path_off as u64, &mut path);
    // ARG_VA is a valid mapped window frame (mapped during initial connect).
    let arg_window = MappedWindow::from_mapped_va(ARG_VA);
    arg_window.write(0, &path)?;
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
    // OPEN carries the file size in w3. Reuse the caller's buffer: clear it and
    // reserve up-front so the reads never grow it (a grow would reallocate and
    // leak the old buffer on PS's bump heap, `sdk::heap`). A 256 KiB floor
    // covers every v0 image in one allocation.
    let size = (opened.words[3] as usize).min(1 << 20);
    buf.clear();
    if buf.capacity() < size {
        buf.reserve(size.max(256 * 1024));
    }
    let mut offset = 0u64;
    loop {
        if buf.len() > 1 << 20 {
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
        let start = buf.len();
        buf.resize(start + count, 0);
        // RESULT_VA is a valid mapped window frame (mapped during initial connect).
        let result_window = MappedWindow::from_mapped_va(RESULT_VA);
        result_window.read_into(0, count as u32, &mut buf[start..])?;
        offset += count as u64;
        if count < 4096 {
            break;
        }
    }
    if buf.is_empty() {
        return Err(ipc::status::EBADARG);
    }
    Ok(buf.len())
}

/// Carve one frame, write the crafted initial stack page (argc + argv blob +
/// string table), map it as the child's top stack page, drop the scratch.
/// Craft the child's top stack page (v0.2 entry contract, `sdk::args`):
/// `[TOP-8] = argc`, `[TOP-16] = argv*`, `[TOP-24] = envp*`; the pointer
/// arrays live at page offset 0x400 (argv ptrs + NULL, envp ptrs + NULL) and
/// the NUL-terminated strings at 0x800+ (well below any early push traffic —
/// parking them near the header got them clobbered by the child's own
/// frames). The argv/env areas in the spawn blob are NUL-separated string
/// lists.
fn craft_stack(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    child_as: u32,
    argv_span: (usize, usize),
    env_span: (usize, usize),
    win_base: u64,
) -> Result<(), i32> {
    const MAX_ARGS: usize = 16;
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
    let page_va = USER_STACK_TOP - 4096;

    // Strings + pointer arrays, filled from the blob areas.
    let mut str_cursor = 0x800usize;
    let mut argv_ptrs = [0u64; MAX_ARGS];
    let mut envp_ptrs = [0u64; MAX_ARGS];
    let mut argc = 0usize;
    let mut envc = 0usize;

    // Read the argv and env areas from the window into local buffers for safe parsing.
    let argv_buf = {
        let len = argv_span.1;
        let mut buf = vec![0u8; len];
        raw_copy_from_va(win_base + argv_span.0 as u64, &mut buf);
        buf
    };
    let env_buf = {
        let len = env_span.1;
        let mut buf = vec![0u8; len];
        raw_copy_from_va(win_base + env_span.0 as u64, &mut buf);
        buf
    };

    let mut fill = |buf: &[u8],
                    ptrs: &mut [u64; MAX_ARGS],
                    count: &mut usize,
                    str_cursor: &mut usize|
     -> Result<(), i32> {
        let len = buf.len();
        let mut i = 0usize;
        while i < len {
            if *count == MAX_ARGS {
                break;
            }
            // One NUL-terminated string; zero-padded tail = empty, skip.
            let start = i;
            while i < len && buf[i] != 0 {
                i += 1;
            }
            let slen = i - start;
            i += 1; // skip the NUL
            if slen == 0 {
                continue;
            }
            if *str_cursor + slen + 1 > 4096 - 32 {
                return Err(-103);
            }
            page[*str_cursor..*str_cursor + slen].copy_from_slice(&buf[start..start + slen]);
            ptrs[*count] = page_va + *str_cursor as u64;
            *count += 1;
            *str_cursor += slen + 1;
        }
        Ok(())
    };
    fill(&argv_buf, &mut argv_ptrs, &mut argc, &mut str_cursor)?;
    fill(&env_buf, &mut envp_ptrs, &mut envc, &mut str_cursor)?;

    // Pointer arrays at 0x400: argv ptrs, NULL, envp ptrs, NULL.
    let argv_arr = 0x400usize;
    let mut p = argv_arr;
    for v in argv_ptrs.iter().take(argc) {
        page[p..p + 8].copy_from_slice(&v.to_le_bytes());
        p += 8;
    }
    page[p..p + 8].copy_from_slice(&0u64.to_le_bytes());
    p += 8;
    let envp_arr = p;
    for v in envp_ptrs.iter().take(envc) {
        page[p..p + 8].copy_from_slice(&v.to_le_bytes());
        p += 8;
    }
    page[p..p + 8].copy_from_slice(&0u64.to_le_bytes());

    // Header at the very top (captured by the entry stub before any push).
    page[4096 - 8..4096].copy_from_slice(&(argc as u64).to_le_bytes());
    page[4096 - 16..4096 - 8].copy_from_slice(&(page_va + argv_arr as u64).to_le_bytes());
    page[4096 - 24..4096 - 16].copy_from_slice(&(page_va + envp_arr as u64).to_le_bytes());

    // Copy the crafted stack page to the scratch VA (mapped in this AS).
    raw_copy_to_va(PS_SCRATCH_VA_BASE, &page);
    invoke_map(sys, child_as, USER_STACK_TOP - 4096, 0b011, frame)?;
    let mut m = Message::new(methods::aspace::UNMAP);
    m.words[0] = PS_SCRATCH_VA_BASE;
    sys.invoke(package.aspace, &m)?;
    Ok(())
}

/// `WAIT` (0x0111): v0 blocking wait on the single child's death
/// notification (design §2.6); replies `w0 = status, w1 = child's raw exit
/// status` (kernel payload convention: bit 0 = event, bits 32.. = status).
/// `EXEC` (design §2.6): replace the calling process's image. v0 builds on
/// `Thread::THREAD_CREATE` (ADR-033): load the new program into the caller's
/// AS (through the VFS endpoint its SPAWN carried), re-craft the stack, create
/// a fresh thread at the new entry, then reply — the caller's runtime exits
/// its old thread, leaving the process running the new image with its
/// capabilities (and fds) intact.
///
/// v0 warts (documented): the caller's exit notification (bound to the OLD
/// thread) fires at the moment of exec rather than at process death — a
/// `Thread::SET_ENTRY`-style primitive (board: ADR candidate) removes this.
/// The image's segment range is unmapped wholesale before the load.
/// Returns `None` when exec took effect (the caller's context was replaced —
/// it must NOT receive a reply); `Some(reply)` carries a failure.
fn exec_reply(
    sys: &mut Syscalls<'_, X86_64Syscalls>,
    package: &BootstrapPackage,
    factory: u32,
    caller_pid: u64,
    win_base: u64,
    load_buf: &mut Vec<u8>,
) -> Option<Message> {
    let mut reply = Message::new(methods::process::EXEC);
    let Some(slot) = child_slot(caller_pid) else {
        reply.words[0] = ipc::status::EBADARG as i64 as u64;
        return Some(reply);
    };
    let (path_off, path_len, arg_off, arg_len, env_off, env_len) = match parse_spawn_blob(win_base)
    {
        Some(v) => v,
        None => {
            reply.words[0] = ipc::status::EBADARG as i64 as u64;
            return Some(reply);
        }
    };
    let as_cap = CH_AS[slot].load(Ordering::Relaxed);
    let vfs_cap = CH_VFS[slot].load(Ordering::Relaxed);
    let thread_cap = CH_CAPS[slot].load(Ordering::Relaxed);
    if as_cap == 0 || vfs_cap == 0 || thread_cap == 0 {
        reply.words[0] = ipc::status::EBADCAP as i64 as u64;
        return Some(reply);
    }
    let len = match load_via_vfs(
        sys,
        package,
        factory,
        VfsLoadParams {
            vfs_svc: vfs_cap,
            path_span: (path_off, path_len),
            win_base,
        },
        load_buf,
    ) {
        Ok(n) => n,
        Err(e) => {
            reply.words[0] = e as i64 as u64;
            return Some(reply);
        }
    };
    let image: &[u8] = &load_buf[..len];
    let elf = match ElfImage::parse(image) {
        Ok(el) => el,
        Err(e) => {
            reply.words[0] = ipc::status::EBADARG as i64 as u64;
            let _ = e;
            return Some(reply);
        }
    };
    // Unmap the old image segments + the crafted top stack page, then load the
    // replacement into the caller's AS and re-craft the stack for the new
    // argv/env. (64 pages covers every v0 binary; the image base is fixed by
    // the linker flags.)
    const IMAGE_BASE: u64 = 0x7E00_0000;
    const IMAGE_PAGES: u64 = 64;
    {
        let mut m = Message::new(methods::aspace::UNMAP);
        m.words[0] = IMAGE_BASE;
        m.words[1] = IMAGE_PAGES;
        let _ = sys.invoke(as_cap, &m);
        let mut m = Message::new(methods::aspace::UNMAP);
        m.words[0] = USER_STACK_TOP - 4096;
        m.words[1] = 1;
        let _ = sys.invoke(as_cap, &m);
    }
    let loaded = (|| -> Result<(), i32> {
        let ops = loader::plan(&elf, PS_SCRATCH_VA_BASE)?;
        loader::execute(
            sys,
            &mut loader::MemoryWriter,
            &ops,
            as_cap,
            package.region,
            package.aspace,
            image,
        )?;
        craft_stack(
            sys,
            package,
            as_cap,
            (arg_off, arg_len),
            (env_off, env_len),
            win_base,
        )?;
        Ok(())
    })();
    if let Err(e) = loaded {
        reply.words[0] = e as i64 as u64;
        return Some(reply);
    }
    // ADR-039 recipe (amended): the caller is blocked in this very call —
    // quiescent. SET_ENTRY rewrites its entry + rebuilds the kernel context
    // (fresh trampoline at USER_STACK_TOP) and RESUME re-queues it straight
    // into the new image. The old thread never resumes its frames; its
    // identity (tid, notification bindings) survives, so the parent's death
    // notification fires at real process death with the NEW image's status.
    let mut m = Message::new(methods::thread::SET_ENTRY);
    m.words[0] = elf.entry;
    if let Err(e) = sys.invoke(thread_cap, &m) {
        reply.words[0] = e as i64 as u64;
        return Some(reply);
    }
    let m = Message::new(methods::thread::RESUME);
    let _ = sys.invoke(thread_cap, &m);
    None
}

/// Parse the v0.2 spawn/exec payload blob from `win_base`
/// (`[path_span][argv_span][env_span]` + areas). `None` = malformed.
#[allow(clippy::type_complexity)]
fn parse_spawn_blob(win_base: u64) -> Option<(usize, usize, usize, usize, usize, usize)> {
    let mut header = [0u64; 3];
    raw_copy_from_va_to_u64x3(win_base, &mut header);
    let span = |w: u64| ((w >> 32) as usize, (w & 0xFFFF_FFFF) as usize);
    let (path_off, path_len) = span(header[0]);
    let (arg_off, arg_len) = span(header[1]);
    let (env_off, env_len) = span(header[2]);
    let ok = |off: usize, len: usize| off.checked_add(len).is_some_and(|e| e <= 4096);
    if path_len == 0 || !ok(path_off, path_len) || !ok(arg_off, arg_len) || !ok(env_off, env_len) {
        return None;
    }
    Some((path_off, path_len, arg_off, arg_len, env_off, env_len))
}

/// `PIPE`: mint a fresh endpoint pair and hand both ends to the caller
/// (descriptor 0 = read end, 1 = write end). The caller decides which ends
/// children receive; stream EOF is the `console::EOF` message a writer's
/// `Runtime::exit` sends before dying.
fn pipe_reply(sys: &mut Syscalls<'_, X86_64Syscalls>, factory: u32) -> Message {
    let mut reply = Message::new(methods::process::PIPE);
    let mint = |sys: &mut Syscalls<'_, X86_64Syscalls>| -> Result<u32, i32> {
        let r = sys.invoke(factory, &Message::new(methods::factory::NEW_ENDPOINT))?;
        let h = r.words[0] as u32;
        if h == 0 {
            return Err(ipc::status::ENOMEM);
        }
        Ok(h)
    };
    // A pipe is ONE endpoint (one mailbox): a send from the writer's cap is
    // visible to the reader's cap of the SAME object. Two separate endpoints
    // (the previous form) have independent mailboxes — the write parked in
    // the writer's endpoint mailbox while the reader polled its own.
    let ep = match mint(sys) {
        Ok(h) => h,
        Err(e) => {
            reply.words[0] = e as i64 as u64;
            return reply;
        }
    };
    reply.tag = reply.tag.with_caps(2);
    let _ = reply.set_descriptor(
        0,
        CapSlot::pack(ep, Rights::SEND.union(Rights::RECV).union(Rights::GRANT)),
    );
    let _ = reply.set_descriptor(
        1,
        CapSlot::pack(ep, Rights::SEND.union(Rights::RECV).union(Rights::GRANT)),
    );
    reply
}

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
                    // Reap the child's address space now that it is dead.
                    // AS ids live in a fixed kernel table (MAX_AS); leaking
                    // one per spawn exhausted it after ~16 children and every
                    // later NEW_ADDRESS_SPACE failed with ENOMEM (hit as soon
                    // as the smoke passed 15 total spawns).
                    let as_cap = CH_AS[slot].load(Ordering::Relaxed);
                    if as_cap != 0 {
                        let _ = sys.invoke(as_cap, &Message::new(methods::aspace::DESTROY));
                        CH_AS[slot].store(0, Ordering::Relaxed);
                    }
                    // Free the registration so the slot can be reused for a
                    // different pid (pids recycle; a stale entry would shadow
                    // the new child).
                    CH_PIDS[slot].store(0, Ordering::Relaxed);
                    CH_VFS[slot].store(0, Ordering::Relaxed);
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
