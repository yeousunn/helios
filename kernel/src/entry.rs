//! Arch syscall entry contract (ADR-011 §4, syscall-abi §2).
//!
//! The arch trap handler (hal-*, NV) decodes registers into
//! [`SyscallArgs`], then calls [`dispatch`] — the kernel never touches
//! registers. Factory::NEW_THREAD follows ADR-017 (w0 = entry PC;
//! caps[0..=2] positional).
#![forbid(unsafe_code)]

use crate::proc::{self, ProcError, ProcessId};
use crate::sched::{self, ObjRef, ThreadId};
use crate::syscall;
use caps::{Capability, ObjId, ObjType, Rights};
#[allow(unused_imports)]
use ipc::CapSlot;
use ipc::{flags, status, Message, Tag};
use spin::Mutex;

/// Decoded register arguments from the arch trap entry (syscall-abi §2).
#[derive(Clone, Copy, Debug)]
pub struct SyscallArgs {
    /// rax / x8 / a7.
    pub num: u64,
    /// arg0: destination cap handle.
    pub cap: u32,
    /// arg1: message tag.
    pub tag: Tag,
    /// arg2..arg5.
    pub w: [u64; 4],
    /// FLAG_NONBLOCK extracted from tag.flags().
    pub nonblock: bool,
}

impl SyscallArgs {
    pub fn message(&self) -> Message {
        Message {
            tag: self.tag,
            words: self.w,
        }
    }
}

/// What the kernel hands back to the arch entry: registers to restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallReturn {
    /// rax / x0 / a0: 0 or negative errno for native syscalls; for
    /// foreign-routed threads (ADR-044) the emulator's reply word[0] is the
    /// FULL 64-bit Linux result (the widened field carries it verbatim —
    /// native i32 errno values sign-extend identically).
    pub status: i64,
    /// rdx / x1 / a1: returned tag.
    pub tag: Tag,
    /// returned w0..w3.
    pub w: [u64; 4],
}

/// Reserved sentinel: the thread parked inside the syscall (ADR-019 §1).
/// The arch entry must NOT return to userspace; it schedules another thread
/// and later consults [`park_result`] when the thread is scheduled again.
pub const PARKED_STATUS: i64 = i64::MIN;

impl SyscallReturn {
    pub const fn parked() -> Self {
        SyscallReturn {
            status: PARKED_STATUS,
            tag: Tag(0),
            w: [0; 4],
        }
    }

    pub const fn err(status: i32) -> Self {
        SyscallReturn {
            status: status as i64,
            tag: Tag(0),
            w: [0; 4],
        }
    }

    pub const fn ok(tag: Tag, w: [u64; 4]) -> Self {
        SyscallReturn {
            status: ipc::status::OK as i64,
            tag,
            w,
        }
    }
}

/// Syscall numbers (syscall-abi §3). Frozen set; growth requires an ADR.
pub mod num {
    pub const YIELD: u64 = 0;
    pub const SEND: u64 = 1;
    pub const CALL: u64 = 2;
    pub const RECV: u64 = 3;
    pub const REPLY_RECV: u64 = 4;
    pub const INVOKE: u64 = 5;
    pub const CAP_MINT: u64 = 6;
    pub const CAP_REVOKE: u64 = 7;
    pub const EXIT: u64 = 8;
}

/// Per-arch registration of "who is calling" (process + thread), set by the
/// arch entry from its process context. v0: one registration; per-CPU
/// context arrives with SMP (Phase 5).
pub trait CurrentContext: Sync + Send {
    fn pid(&self) -> ProcessId;
    fn tid(&self) -> ThreadId;
}

static CTX: Mutex<Option<&'static dyn CurrentContext>> = Mutex::new(None);

pub fn set_current_context(c: &'static dyn CurrentContext) {
    *CTX.lock() = Some(c);
}

fn current() -> (ProcessId, ThreadId) {
    match CTX.lock().as_ref() {
        Some(c) => (c.pid(), c.tid()),
        None => (ObjId(1), ThreadId(1)), // v0 single-process fallback
    }
}

/// Resume contract for a parked thread (ADR-019 §1): the arch entry calls
/// this when it schedules a thread that had returned `parked()`.
pub fn park_result(tid: ThreadId) -> Option<SyscallReturn> {
    // 1. Delivered envelope (endpoint hand-off from reply_only / send).
    // The implicit reply slot rebinds only for reply-requesting messages
    // (see `set_reply_if_call`), whichever completion path delivered them.
    if let Some(mut env) = crate::endpoint::take_delivered(tid) {
        let (pid, _) = current();
        syscall::install_transfers(pid, &mut env);
        syscall::set_reply_if_call(&env, tid);
        return Some(SyscallReturn::ok(env.msg.tag, env.msg.words));
    }

    // 2. The notification this thread actually blocked on (recv-on-
    //    notification): return its mask with NOTIFIED. Checking the thread's
    //    *bound* notification instead missed this completion entirely.
    let thread = sched::get(tid).ok()?;
    if let sched::State::Blocked(sched::BlockReason::Notification(obj)) = thread.state {
        if let Ok(mask) = crate::notification::pending(obj) {
            if mask != 0 {
                let _ = crate::notification::clear(obj, mask);
                return Some(SyscallReturn::ok(
                    Tag::new(0).with_flags(flags::NOTIFIED),
                    [mask, 0, 0, 0],
                ));
            }
        }
    }

    // 3. Bound notification that fired.
    if let Some(n) = thread.bound_notification {
        let mask = match crate::notification::pending(n) {
            Ok(m) => m,
            Err(_) => return None,
        };
        if mask > 0 {
            let _ = crate::notification::clear(n, mask);
            return Some(SyscallReturn::ok(
                Tag::new(0).with_flags(flags::NOTIFIED),
                [mask, 0, 0, 0],
            ));
        }
    }

    // 4. Deadline expiry (ADR-041): the parked syscall timed out. Delivery
    //    checks above win on a race (clear_park clears the stale flag).
    if thread.timed_out {
        sched::clear_timed_out(tid);
        syscall::clear_park_entry(tid);
        return Some(SyscallReturn {
            status: status::ETIMEDOUT as i64,
            tag: Tag(0),
            w: [0; 4],
        });
    }

    // 5. Still parked.
    None
}

/// The single dispatch point for every syscall (arch entry calls this).
pub fn dispatch(args: SyscallArgs) -> SyscallReturn {
    // Deferred console-input wake (ADR-038 IRQ safety): the IRQ only marks
    // lines pending; the signal (which takes scheduler locks) fires here in
    // syscall context, waking any thread parked on the console notification.
    if crate::console_in::has_pending_line() {
        let _ = crate::notification::signal(
            crate::sched::ObjRef(crate::console_in::CONSOLE_NOTIFY_ID),
            1,
        );
    }
    let (pid, tid) = current();
    // Cooperative timer tick (ADR-041): expire parked deadlines on every
    // dispatch so timeouts fire even while other threads keep the CPU busy.
    // ADR-042: drain a pending hardware tick first (the IRQ itself is
    // lock-free and only marks).
    crate::time::drain_tick();
    crate::sched::expire_timeouts(crate::time::now_ns());
    // ADR-044: foreign-syscall routing — a flagged thread's traps go raw to
    // its emulator endpoint. The num is OPAQUE (a Linux number, not ours):
    // route everything unconditionally; the emulator maps conventions like
    // exit → its own cleanup + Thread::EXIT.
    if let Some(route) = syscall::foreign_route(pid, tid, &args) {
        return route;
    }
    match args.num {
        num::YIELD => syscall::sys_yield(tid)
            .map(|_| SyscallReturn::ok(Tag(0), [0; 4]))
            .unwrap_or_else(SyscallReturn::err),
        num::SEND => match syscall::sys_send(pid, tid, args.cap, args.message(), args.nonblock) {
            Ok(status) => SyscallReturn {
                status: status as i64,
                tag: Tag(0),
                w: [0; 4],
            },
            Err(e) => SyscallReturn::err(e),
        },
        num::CALL => match syscall::sys_call(pid, tid, args.cap, args.message()) {
            Ok(status) => SyscallReturn {
                status: status as i64,
                tag: Tag(0),
                w: [0; 4],
            },
            Err(e) => SyscallReturn::err(e),
        },
        num::RECV => match syscall::sys_recv(pid, tid, args.cap, args.w[0] != 0, args.w[1]) {
            Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
            Ok(None) => SyscallReturn::parked(), // ADR-019 §1
            Err(e) => SyscallReturn::err(e),
        },
        num::REPLY_RECV => {
            match syscall::sys_reply_recv(pid, tid, args.cap, args.message(), args.w[1]) {
                Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
                Ok(None) => SyscallReturn::parked(), // ADR-019 §1
                Err(e) => SyscallReturn::err(e),
            }
        }
        num::INVOKE => invoke(pid, tid, args),
        num::CAP_MINT => {
            let rights = ipc::Rights(u32::try_from(args.w[1]).unwrap_or(0) & Rights::ALL.0);
            match proc::mint(pid, args.cap, rights, u32::try_from(args.w[0]).unwrap_or(0)) {
                Ok(handle) => SyscallReturn::ok(Tag(0), [handle as u64, 0, 0, 0]),
                Err(e) => SyscallReturn::err(map_proc(e)),
            }
        }
        num::CAP_REVOKE => match proc::revoke(pid, args.cap, args.w[0]) {
            Ok(n) => SyscallReturn::ok(Tag(0), [n as u64, 0, 0, 0]),
            Err(e) => SyscallReturn::err(map_proc(e)),
        },
        num::EXIT => match syscall::sys_exit(tid, args.w[0] as i32) {
            Ok(_) => SyscallReturn::ok(Tag(0), [0; 4]),
            Err(e) => SyscallReturn::err(e),
        },
        _ => SyscallReturn::err(ipc::status::ENOSYS),
    }
}

fn map_proc(e: ProcError) -> i32 {
    match e {
        ProcError::NoSuchProcess | ProcError::BadHandle => ipc::status::EBADCAP,
        ProcError::Cap(caps::CapError::MissingGrantRight)
        | ProcError::Cap(caps::CapError::RightsNotSubset) => ipc::status::ERIGHTS,
        ProcError::Cap(_) | ProcError::TableFull => ipc::status::EBADCAP,
    }
}

/// Invoke dispatch: Factory + object methods (syscall-abi §7).
fn invoke(pid: ProcessId, tid: ThreadId, args: SyscallArgs) -> SyscallReturn {
    let Ok(cap) = proc::get_cap(pid, args.cap) else {
        return SyscallReturn::err(ipc::status::EBADCAP);
    };
    match cap.typ {
        ObjType::Factory => factory_invoke(pid, tid, &cap, &args),
        ObjType::Thread => thread_invoke(pid, tid, &cap, &args),
        ObjType::AddressSpace => as_invoke(pid, &cap, &args),
        ObjType::Reply => {
            // ADR-047: Reply::SEND (label 1) — deliver the deferred reply to
            // the parked caller (the cap's ObjId = caller tid) and retire
            // the cap (one-shot). The parked `call` completes via the park
            // contract with this message.
            if args.tag.label() != 1 {
                return SyscallReturn::err(ipc::status::ENOSYS);
            }
            let caller = ThreadId(cap.obj.0);
            let reply = args.message();
            match syscall::deferred_reply_send(pid, caller, reply) {
                Ok(()) => {
                    let _ = proc::remove_cap(pid, args.cap);
                    SyscallReturn::ok(args.tag, [0; 4])
                }
                Err(e) => SyscallReturn::err(e),
            }
        }
        _ => match syscall::sys_invoke(pid, tid, args.cap, args.message()) {
            Ok((status, w)) => SyscallReturn {
                status: status as i64,
                tag: Tag(0),
                w,
            },
            Err(e) => SyscallReturn::err(e),
        },
    }
}

/// AddressSpace methods (syscall-abi §7). v0: kernel-wide VMM (ADR-008/
/// 021) — MAP/UNMAP/PROTECT/SET_FAULT_POOL; FORK/DESTROY are ENOSYS until
/// per-process VMM objects land (board: Phase 2 kernel task).
fn as_invoke(pid: ProcessId, cap: &Capability, args: &SyscallArgs) -> SyscallReturn {
    use crate::aspace::{self, MapFlags, Vaddr};
    let as_id = cap.obj;
    if !cap.rights.contains(Rights::MAP) {
        return SyscallReturn::err(ipc::status::ERIGHTS);
    }
    let msg = args.message();
    const MAP: u16 = 1;
    const UNMAP: u16 = 2;
    const PROTECT: u16 = 3;
    const SET_FAULT_POOL: u16 = 4;
    const FORK: u16 = 5;
    const DESTROY: u16 = 6;

    let vaddr = Vaddr(msg.words[0]);
    match msg.tag.label() {
        MAP => {
            let mut flags = MapFlags((msg.words[1] as u32) & 0b1_1111);
            if flags.0 == 0 {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            // Frame cap check (ANON ignores caps[0]). ANON maps resolve from
            // the AS fault pool when one is attached (v1 lazy path); without a
            // pool they resolve EAGERLY with a zeroed frame — non-pager
            // launchers (e.g. spawned children) get zero-filled pages now.
            let has_pool = aspace::has_pool(as_id).unwrap_or(false);
            let frame_addr = if flags.contains(MapFlags::ANON) && !has_pool {
                let Some(frame) = crate::mem::alloc_zeroed() else {
                    return SyscallReturn::err(ipc::status::ENOMEM);
                };
                // The frame now exists: map it as an ordinary frame-backed
                // region (FrameNotOwned rejects ANON together with a base).
                flags = MapFlags(flags.0 & !MapFlags::ANON.0);
                Some(frame)
            } else if flags.contains(MapFlags::ANON) {
                None // lazy: the first fault resolves from the pool
            } else {
                match msg.descriptor(0).filter(|cs| cs.handle() != 0) {
                    Some(cs) => match proc::get_cap(pid, cs.handle()) {
                        Ok(fc) if fc.typ == ObjType::Frame => {
                            // Rights bit mapping: ipc::Rights READ=bit3, WRITE=bit4,
                            // EXEC=bit5 (syscall-abi §5) → MapFlags bits 0..2.
                            let want = flags.0 & 0b111;
                            let frame_rights = fc.rights.0;
                            let have = ((frame_rights >> 3) & 0b111) & 0xFFFF; // READ|WRITE|EXEC bits
                            if (have & want) != want {
                                return SyscallReturn::err(ipc::status::ERIGHTS);
                            }
                            Some(crate::frame::PhysAddr::new(fc.obj.0))
                        }
                        _ => return SyscallReturn::err(ipc::status::EBADCAP),
                    },
                    None => return SyscallReturn::err(ipc::status::EBADARG),
                }
            };
            crate::kinfo!(
                "MAP pid={} va={:#x} frame={:?}",
                pid.0,
                vaddr.0,
                frame_addr.map(|f| f.as_u64())
            );
            match aspace::map(as_id, vaddr, 1, frame_addr, flags) {
                Ok(_) => SyscallReturn::ok(msg.tag, [0; 4]),
                Err(aspace::VmmError::Overlap) => SyscallReturn::err(ipc::status::EBADARG),
                Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
            }
        }
        UNMAP => match aspace::unmap(as_id, vaddr, msg.words[1].max(1)) {
            Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
            Err(_) => SyscallReturn::err(ipc::status::EBADARG),
        },
        PROTECT => {
            let flags = MapFlags((msg.words[2] as u32) & 0b111);
            match aspace::protect(as_id, vaddr, flags) {
                Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                Err(_) => SyscallReturn::err(ipc::status::EBADARG),
            }
        }
        SET_FAULT_POOL => {
            // caps[0] = Region: dedicate its remaining space as the pool.
            let Some(cs) = msg.descriptor(0).filter(|cs| cs.handle() != 0) else {
                return SyscallReturn::err(ipc::status::EBADARG);
            };
            let Ok(rc) = proc::get_cap(pid, cs.handle()) else {
                return SyscallReturn::err(ipc::status::EBADCAP);
            };
            if rc.typ != ObjType::Region {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            match crate::init::region_dedicate_as_pool(rc.obj) {
                Ok((base, len)) => match aspace::set_pool(as_id, base, len) {
                    Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                    Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
                },
                Err(e) => SyscallReturn::err(e),
            }
        }
        FORK => {
            // ADR-024: COW clone; returns child AS cap (MAP|GRANT) in w0.
            match crate::aspace::fork(as_id) {
                Ok(child_id) => install_ret(
                    pid,
                    child_id.0,
                    ObjType::AddressSpace,
                    Rights::MAP.union(Rights::GRANT),
                    msg.tag,
                ),
                Err(crate::aspace::VmmError::NoBackend) => SyscallReturn::err(ipc::status::ENOSYS),
                Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
            }
        }
        DESTROY => match crate::aspace::destroy(as_id) {
            Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
            Err(_) => SyscallReturn::err(ipc::status::EBADARG),
        },
        _ => SyscallReturn::err(ipc::status::ENOSYS),
    }
}

/// Thread methods (syscall-abi §7, ADR-019 §3). cap.obj = target ThreadId;
/// CONTROL right required for everything except... everything (all methods
/// control the target).
fn thread_invoke(
    pid: ProcessId,
    tid: ThreadId,
    cap: &Capability,
    args: &SyscallArgs,
) -> SyscallReturn {
    if !cap.rights.contains(Rights::CONTROL) {
        return SyscallReturn::err(ipc::status::ERIGHTS);
    }
    let target = ThreadId(cap.obj.0);
    let msg = args.message();
    const EXIT: u16 = 1;
    const KILL: u16 = 2;
    const SUSPEND: u16 = 3;
    const RESUME: u16 = 4;
    const SET_PRIORITY: u16 = 5;
    const BIND_DEATH_NOTIFICATION: u16 = 12;
    const THREAD_CREATE: u16 = 13;
    const SET_ENTRY: u16 = 14;
    const SET_FOREIGN: u16 = 15;
    const TRAP_READ: u16 = 16;
    const DEFER: u16 = 17;
    const REGS_READ: u16 = 9;
    const REGS_WRITE: u16 = 10;

    let control_ok = sched::get(target)
        .map(|t| t.process.0 == pid.0 || cap.rights.contains(Rights::CONTROL))
        .unwrap_or(false);
    if !control_ok {
        return SyscallReturn::err(ipc::status::EBADCAP);
    }

    match msg.tag.label() {
        EXIT | KILL => {
            let status = if msg.tag.label() == EXIT {
                msg.words[0] as i32
            } else {
                -1
            };
            let _ = syscall::sys_exit(target, status);
            SyscallReturn::ok(msg.tag, [0; 4])
        }
        SUSPEND => match suspend(target) {
            Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
            Err(e) => SyscallReturn::err(e),
        },
        RESUME => match resume(target) {
            Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
            Err(e) => SyscallReturn::err(e),
        },
        SET_PRIORITY => match sched::set_priority(target, msg.words[0] as u8) {
            Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
            Err(_) => SyscallReturn::err(ipc::status::EBADCAP),
        },
        BIND_DEATH_NOTIFICATION => {
            // caps[0] = Notification or NULL to clear.
            let bound = msg
                .descriptor(0)
                .filter(|cs| cs.handle() != 0)
                .and_then(|cs| proc::get_cap(pid, cs.handle()).ok())
                .filter(|c| c.typ == ObjType::Notification);
            match set_bound_notification(target, bound.map(|c| crate::sched::ObjRef(c.obj.0))) {
                Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                Err(e) => SyscallReturn::err(e),
            }
        }
        SET_ENTRY => {
            // ADR-039: rewrite a SUSPENDED thread's entry PC + rebuild its
            // initial kernel context. Racing a running thread is rejected.
            let pc = msg.words[0];
            match sched::set_entry(target, pc) {
                Ok(()) => SyscallReturn::ok(msg.tag, [0, pc, 0, 0]),
                Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
            }
        }
        DEFER => {
            // ADR-047: mint a one-shot Reply cap from the TARGET thread's
            // implicit reply slot (self only — the slot is per-thread) and
            // clear the slot: the server will reply later via Reply::SEND.
            if target != tid {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            match syscall::defer_reply(pid, tid) {
                Ok(handle) => SyscallReturn::ok(msg.tag, [handle as u64, 0, 0, 0]),
                Err(e) => SyscallReturn::err(e),
            }
        }
        SET_FOREIGN => {
            // ADR-044 (amended): flag the thread so its syscall traps route
            // raw to the emulator's endpoint. w0 = the CALLER's cap HANDLE
            // on the route endpoint (userspace cannot learn ObjIds; the
            // kernel resolves it), 0 = clear.
            let handle = msg.words[0] as u32;
            let route = if handle == 0 {
                Ok(None)
            } else {
                proc::get_cap(pid, handle).map(|c| {
                    if c.typ == ObjType::Endpoint {
                        Some(crate::sched::ObjRef(c.obj.0))
                    } else {
                        None
                    }
                })
            };
            match route {
                Ok(ep) => match sched::set_foreign(target, ep) {
                    Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                    Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
                },
                Err(_) => SyscallReturn::err(ipc::status::EBADCAP),
            }
        }
        TRAP_READ => {
            // ADR-044: the emulator fetches the routed syscall frame's
            // remaining words [tag.0, w0, w1, w2] (the routing message
            // itself carried [num, cap, w3, 0]). Only a foreign-parked
            // thread exposes its frame.
            match sched::trap_read(target) {
                Some([tag, w0, w1, w2]) => SyscallReturn::ok(msg.tag, [tag, w0, w1, w2]),
                None => SyscallReturn::err(ipc::status::EBADSTATE),
            }
        }
        REGS_READ | REGS_WRITE => {
            // syscall-abi §7 ids 9/10: caps[0] = Frame validating the access.
            // v0: the image lives in the TARGET's kernel-context frame (the
            // suspended/forked child's own stack) — the Frame cap validates
            // the caller's authority; the kernel reads/writes the target's
            // kstack image directly.
            let Some(cs) = msg.descriptor(0).filter(|cs| cs.handle() != 0) else {
                return SyscallReturn::err(ipc::status::EBADARG);
            };
            let Ok(fc) = proc::get_cap(pid, cs.handle()) else {
                return SyscallReturn::err(ipc::status::EBADCAP);
            };
            if fc.typ != ObjType::Frame {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            let mut image = [0u64; crate::sched::REG_IMAGE_QWORDS];
            if msg.tag.label() == 9 {
                match sched::regs_read(target, &mut image) {
                    Ok(()) => SyscallReturn::ok(msg.tag, [image[0], image[2], image[1], 0]),
                    Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
                }
            } else {
                for (dst, src) in image.iter_mut().zip(msg.words.iter()) {
                    *dst = *src;
                }
                match sched::regs_write(target, &image, 2) {
                    Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                    Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
                }
            }
        }
        THREAD_CREATE => {
            // ADR-033 §1: new thread in the TARGET's process (shares AS +
            // cap table). w0 = entry PC. CONTROL right already enforced.
            let proc_ref = sched::get(target).map(|t| t.process).unwrap_or(ObjRef(0));
            let child_tid = match sched::spawn_with(proc_ref, sched::DEFAULT_PRIORITY, msg.words[0])
            {
                Ok(t) => t,
                Err(_) => return SyscallReturn::err(ipc::status::ENOMEM),
            };
            crate::objreg::register(ObjId(child_tid.0), ObjType::Thread, pid);
            match proc::install_cap(
                pid,
                Capability {
                    obj: ObjId(child_tid.0),
                    typ: ObjType::Thread,
                    rights: Rights::CONTROL.union(Rights::GRANT),
                },
            ) {
                Ok(h) => SyscallReturn::ok(msg.tag, [h as u64, child_tid.0, 0, 0]),
                Err(e) => SyscallReturn::err(map_proc(e)),
            }
        }
        _ => SyscallReturn::err(ipc::status::ENOSYS),
    }
}

/// Test hook for kernel tests (thread_invoke is private); returns the full
/// syscall return.
#[cfg(test)]
pub(crate) fn thread_invoke_for_test(
    pid: ProcessId,
    cap_handle: u32,
    msg: Message,
) -> crate::entry::SyscallReturn {
    let cap = proc::get_cap(pid, cap_handle).unwrap();
    thread_invoke(
        pid,
        ThreadId(1),
        &cap,
        &SyscallArgs {
            num: crate::entry::num::INVOKE,
            cap: cap_handle,
            tag: msg.tag,
            w: msg.words,
            nonblock: false,
        },
    )
}

fn suspend(target: ThreadId) -> Result<(), i32> {
    sched::suspend(target).map_err(|_| ipc::status::EBADCAP)
}

fn resume(target: ThreadId) -> Result<(), i32> {
    sched::resume(target).map_err(|_| ipc::status::EBADCAP)
}

fn set_bound_notification(target: ThreadId, n: Option<crate::sched::ObjRef>) -> Result<(), i32> {
    sched::set_bound_notification(target, n).map_err(|_| ipc::status::EBADCAP)
}

/// Factory methods (syscall-abi §7). NEW_THREAD per ADR-017:
/// w0 = entry PC; caps[0] = AddressSpace (required), caps[1] = fault EP
/// (optional), caps[2] = bootstrap EP (optional → child handle 1).
fn factory_invoke(
    pid: ProcessId,
    _tid: ThreadId,
    cap: &Capability,
    args: &SyscallArgs,
) -> SyscallReturn {
    const NEW_ENDPOINT: u16 = 1;
    const NEW_NOTIFICATION: u16 = 2;
    const NEW_ADDRESS_SPACE: u16 = 3;
    const NEW_THREAD: u16 = 4;

    let msg = args.message();
    match msg.tag.label() {
        NEW_ENDPOINT => match crate::endpoint::create_endpoint() {
            Ok(ep) => {
                crate::objreg::register(ObjId(ep.0), ObjType::Endpoint, pid);
                install_ret(
                    pid,
                    ep.0,
                    ObjType::Endpoint,
                    Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
                    msg.tag,
                )
            }
            Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
        },
        NEW_NOTIFICATION => match crate::notification::create() {
            Ok(n) => {
                crate::objreg::register(ObjId(n.0), ObjType::Notification, pid);
                install_ret(
                    pid,
                    n.0,
                    ObjType::Notification,
                    // GRANT: session/death notifications must be transferable to
                    // children (ADR-023 §5b).
                    Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT),
                    msg.tag,
                )
            }
            Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
        },
        NEW_ADDRESS_SPACE => {
            // Per-process AS object (ADR-022 §1); owner-registered (ADR-026).
            match crate::aspace::create() {
                Ok(as_id) => {
                    crate::objreg::register(as_id, ObjType::AddressSpace, pid);
                    crate::kinfo!("ASREG: as={} owner_pid={} (caller)", as_id.0, pid.0);
                    install_ret(
                        pid,
                        as_id.0,
                        ObjType::AddressSpace,
                        Rights::MAP.union(Rights::GRANT),
                        msg.tag,
                    )
                }
                Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
            }
        }
        NEW_THREAD => new_thread(pid, cap, &msg),
        _ => SyscallReturn::err(ipc::status::ENOSYS),
    }
}

fn install_ret(pid: ProcessId, obj: u64, typ: ObjType, rights: Rights, tag: Tag) -> SyscallReturn {
    match proc::install_cap(
        pid,
        Capability {
            obj: ObjId(obj),
            typ,
            rights,
        },
    ) {
        Ok(h) => {
            crate::kinfo!("FACTORY: pid={} obj={:#x} handle={}", pid.0, obj, h);
            SyscallReturn::ok(tag, [h as u64, 0, 0, 0])
        }
        Err(e) => {
            crate::kinfo!(
                "FACTORY: install FAILED pid={} obj={:#x} err={:?}",
                pid.0,
                obj,
                e
            );
            SyscallReturn::err(map_proc(e))
        }
    }
}

/// Factory::NEW_THREAD (ADR-017 packing): creates the child process + thread,
/// applies caps[1] (fault EP) atomically, installs caps[2] (bootstrap EP) at
/// child handle 1 (slot 0) per ADR-009, and returns the child's thread cap.
fn new_thread(pid: ProcessId, cap: &Capability, msg: &Message) -> SyscallReturn {
    if !cap.rights.contains(Rights::GRANT) {
        return SyscallReturn::err(ipc::status::ERIGHTS);
    }
    let entry_pc = msg.words[0];

    let child_pid = match proc::create() {
        Ok(p) => p,
        Err(e) => return SyscallReturn::err(map_proc(e)),
    };

    // caps[0] = AddressSpace (required): record as the child's AS (ADR-022).
    if let Some(cs) = msg.descriptor(0) {
        if cs.handle() != 0 {
            match proc::get_cap(pid, cs.handle()) {
                Ok(as_cap) if as_cap.typ == ObjType::AddressSpace => {
                    let _ = proc::set_as(child_pid, as_cap.obj);
                }
                _ => return SyscallReturn::err(ipc::status::EBADARG),
            }
        }
    }

    // caps[1] = fault endpoint (optional).
    if let Some(cs) = msg.descriptor(1) {
        if cs.handle() != 0 {
            match proc::get_cap(pid, cs.handle()) {
                Ok(fep) => {
                    if proc::install_cap(
                        child_pid,
                        Capability {
                            obj: fep.obj,
                            typ: fep.typ,
                            rights: fep.rights,
                        },
                    )
                    .is_err()
                    {
                        return SyscallReturn::err(ipc::status::ENOMEM);
                    }
                }
                Err(e) => return SyscallReturn::err(map_proc(e)),
            }
        }
    }

    // caps[2] = bootstrap endpoint → child handle 1 (slot 0), ADR-009.
    if let Some(cs) = msg.descriptor(2) {
        if cs.handle() != 0 {
            match proc::get_cap(pid, cs.handle()) {
                Ok(bep) => {
                    let rights = bep.rights.intersect(cs.rights()).union(Rights::SEND);
                    if proc::install_cap_at(
                        child_pid,
                        0,
                        Capability {
                            obj: bep.obj,
                            typ: bep.typ,
                            rights,
                        },
                    )
                    .is_err()
                    {
                        return SyscallReturn::err(ipc::status::ENOMEM);
                    }
                }
                Err(e) => return SyscallReturn::err(map_proc(e)),
            }
        }
    }

    // Spawn at scheduler default priority (ADR-017 §3); SET_PRIORITY refines.
    // Entry PC from w0 (ADR-019 §4); SP is arch-owned.
    let child_tid = match sched::spawn_with(ObjRef(child_pid.0), sched::DEFAULT_PRIORITY, entry_pc)
    {
        Ok(t) => t,
        Err(_) => return SyscallReturn::err(ipc::status::ENOMEM),
    };

    // Child thread cap (CONTROL + GRANT, ADR-023 §5c) in the parent's table.
    match proc::install_cap(
        pid,
        Capability {
            obj: ObjId(child_tid.0),
            typ: ObjType::Thread,
            rights: Rights::CONTROL.union(Rights::GRANT),
        },
    ) {
        Ok(h) => SyscallReturn::ok(msg.tag, [h as u64, entry_pc, child_pid.0, child_tid.0]),
        Err(e) => SyscallReturn::err(map_proc(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aspace::{MapFlags, Vaddr};
    use crate::sched::set_context_backend;
    use std::boxed::Box;

    struct MockCtx;
    impl crate::sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    struct FixedCtx(ProcessId, ThreadId);
    impl CurrentContext for FixedCtx {
        fn pid(&self) -> ProcessId {
            self.0
        }
        fn tid(&self) -> ThreadId {
            self.1
        }
    }

    struct MockFactory;
    impl crate::aspace::BackendFactory for MockFactory {
        fn create(&self, _as_id: u64) -> Option<&'static dyn crate::aspace::PagingBackend> {
            Some(&MockBackend)
        }
    }

    struct MockBackend;
    impl crate::aspace::PagingBackend for MockBackend {
        fn map_page(&self, _v: crate::aspace::Vaddr, _p: crate::frame::PhysAddr, _f: MapFlags) {}
        fn unmap_page(&self, _v: crate::aspace::Vaddr) {}
        fn protect_page(&self, _v: crate::aspace::Vaddr, _f: MapFlags) {}
        fn copy_page(&self, _dst: crate::frame::PhysAddr, _src: crate::frame::PhysAddr) -> bool {
            true
        }
    }

    fn setup() -> (ProcessId, ThreadId, u32) {
        crate::aspace::set_backend_factory(&MockFactory);
        let _ = crate::aspace::init_default();
        // Frame allocator: entry tests run before frame tests; seed the same
        // region frame::full_lifecycle expects so both suites coexist.
        let _ = crate::frame::init(&[crate::frame::Region::new(
            crate::frame::PhysAddr::new(0x1000),
            64 * crate::frame::FRAME_SIZE as u64,
        )
        .unwrap()]);
        crate::init::reset_regions_for_test();
        crate::proc::reset_for_test();
        crate::endpoint::reset_engine_for_test();
        crate::notification::reset_for_test();
        syscall::reset_reply_for_test();
        *sched::SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = sched::init();
        let pid = proc::create().unwrap();
        let tid = sched::spawn(ObjRef(1), 100).unwrap();
        let ctx: &'static FixedCtx = Box::leak(Box::new(FixedCtx(pid, tid)));
        set_current_context(ctx);
        // Factory cap at handle 1.
        let h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(1),
                typ: ObjType::Factory,
                rights: Rights::ALL,
            },
        )
        .unwrap();
        (pid, tid, h)
    }

    fn args(num: u64, cap: u32, tag: Tag, w: [u64; 4]) -> SyscallArgs {
        SyscallArgs {
            num,
            cap,
            tag,
            w,
            nonblock: false,
        }
    }

    #[test]
    fn factory_creates_objects_and_threads() {
        let (pid, _tid, factory) = setup();

        // NEW_ENDPOINT / NEW_NOTIFICATION / NEW_ADDRESS_SPACE → handle in w0.
        for (label, typ) in [
            (1u16, ObjType::Endpoint),
            (2, ObjType::Notification),
            (3, ObjType::AddressSpace),
        ] {
            let r = dispatch(args(num::INVOKE, factory, Tag::new(label), [0; 4]));
            assert_eq!(r.status, ipc::status::OK as i64, "label {label}");
            assert_eq!(proc::get_cap(pid, r.w[0] as u32).unwrap().typ, typ);
        }
        // ADR-023 §5b: notifications transferable.
        let r = dispatch(args(num::INVOKE, factory, Tag::new(2), [0; 4]));
        assert!(proc::get_cap(pid, r.w[0] as u32)
            .unwrap()
            .rights
            .contains(Rights::GRANT));

        // NEW_THREAD (ADR-017): w0 = entry; caps = [AS, fault=null, bootstrap].
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;
        let r_ep = dispatch(args(num::INVOKE, factory, Tag::new(1), [0; 4]));
        let boot_ep_h = r_ep.w[0] as u32;

        let mut m = Message::new(4);
        m.words[0] = 0x401000; // entry PC
        m.tag = m.tag.with_caps(3);
        m.set_descriptor(0, CapSlot::pack(as_h, Rights::MAP))
            .unwrap();
        m.set_descriptor(1, CapSlot::NULL).unwrap(); // no fault EP
        m.set_descriptor(2, CapSlot::pack(boot_ep_h, Rights::SEND))
            .unwrap();

        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "NEW_THREAD must succeed");
        let thread_h = r.w[0] as u32;
        let child_pid = ObjId(r.w[2]);

        // Child thread cap with CONTROL in parent's table; entry echoed in w1.
        let tc = proc::get_cap(pid, thread_h).unwrap();
        assert_eq!(tc.typ, ObjType::Thread);
        assert!(tc.rights.contains(Rights::CONTROL));
        assert!(
            tc.rights.contains(Rights::GRANT),
            "ADR-023 §5c: thread caps transferable"
        );
        assert_eq!(r.w[1], 0x401000);

        // Bootstrap endpoint installed at child handle 1 (slot 0) — ADR-009,
        // same kernel object as the launcher's bootstrap EP.
        let boot = proc::get_cap(child_pid, 1).unwrap();
        assert_eq!(boot.typ, ObjType::Endpoint);
        assert_eq!(boot.obj, proc::get_cap(pid, boot_ep_h).unwrap().obj);
    }

    #[test]
    fn unknown_syscall_is_enosys() {
        let (_pid, _tid, factory) = setup();
        let r = dispatch(args(99, factory, Tag(0), [0; 4]));
        assert_eq!(r.status, ipc::status::ENOSYS as i64);
    }
    #[test]
    fn as_invoke_map_protect_unmap_and_fault_pool() {
        let (pid, _tid, factory) = setup();

        // AS cap + Frame cap.
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;
        let as_id = proc::get_cap(pid, as_h).unwrap().obj;
        let frame_addr: u64 = 0xE0_0000;
        let frame_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(frame_addr),
                typ: ObjType::Frame,
                rights: ipc::Rights::READ
                    .union(ipc::Rights::WRITE)
                    .union(ipc::Rights::EXEC),
            },
        )
        .unwrap();

        // MAP: vaddr 0xA00000, R|W, frame.
        let mut m = Message::new(1);
        m.words[0] = 0xA0_0000;
        m.words[1] = 0b011; // R|W
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, ipc::CapSlot::pack(frame_h, ipc::Rights::READ))
            .unwrap();
        let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "AS::MAP");
        assert_eq!(
            crate::aspace::translate(as_id, Vaddr(0xA0_0000)),
            Ok((
                crate::frame::PhysAddr::new(frame_addr),
                MapFlags::READ.union(MapFlags::WRITE)
            ))
        );

        // MAP without frame cap → EBADARG.
        let mut m2 = Message::new(1);
        m2.words[0] = 0xA1_0000;
        m2.words[1] = 0b001;
        let r = dispatch(args(num::INVOKE, as_h, m2.tag, m2.words));
        assert_eq!(r.status, ipc::status::EBADARG as i64);

        // PROTECT → R only.
        let mut m3 = Message::new(3);
        m3.words[0] = 0xA0_0000;
        m3.words[2] = 0b001;
        assert_eq!(
            dispatch(args(num::INVOKE, as_h, m3.tag, m3.words)).status,
            ipc::status::OK as i64
        );
        assert_eq!(
            crate::aspace::translate(as_id, Vaddr(0xA0_0000)).unwrap().1,
            MapFlags::READ
        );

        // UNMAP.
        let mut m4 = Message::new(2);
        m4.words[0] = 0xA0_0000;
        assert_eq!(
            dispatch(args(num::INVOKE, as_h, m4.tag, m4.words)).status,
            ipc::status::OK as i64
        );
        assert!(crate::aspace::translate(as_id, Vaddr(0xA0_0000)).is_err());

        // SET_FAULT_POOL: Region cap → pool; then ANON fault resolves.
        let region_addr: u64 = 0xC0_0000;
        let region_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(0x501), // region id must match registry (below)
                typ: ObjType::Region,
                rights: ipc::Rights::default(),
            },
        )
        .unwrap();
        // Register the region in the init registry (test hook path mirrors
        // init::start grants).
        crate::init::register_region_for_test(
            0x501,
            region_addr,
            4 * crate::aspace::PAGE_SIZE as u64,
        );
        let mut m5 = Message::new(4);
        m5.tag = m5.tag.with_caps(1);
        m5.set_descriptor(0, ipc::CapSlot::pack(region_h, ipc::Rights::default()))
            .unwrap();
        let r = dispatch(args(num::INVOKE, as_h, m5.tag, m5.words));
        assert_eq!(r.status, ipc::status::OK as i64, "SET_FAULT_POOL");

        // ANON map + fault resolves from the attached pool (lazy path).
        let mut m6 = Message::new(1);
        m6.words[0] = 0xB0_0000;
        m6.words[1] = 0b1_1000; // ANON|R  (bit4 ANON, bit0 R)
        let r = dispatch(args(num::INVOKE, as_h, m6.tag, m6.words));
        assert_eq!(r.status, ipc::status::OK as i64, "ANON MAP");
        assert_eq!(
            crate::aspace::resolve_fault(as_id, Vaddr(0xB0_0000), false),
            Ok(crate::frame::PhysAddr::new(region_addr))
        );

        // FORK clones this AS (ADR-024); DESTROY then cleans up the fork.
        let m7 = Message::new(5);
        let r = dispatch(args(num::INVOKE, as_h, m7.tag, m7.words));
        assert_eq!(r.status, ipc::status::OK as i64, "FORK (ADR-024)");
        let forked = proc::get_cap(pid, r.w[0] as u32).unwrap().obj;
        let m8 = Message::new(6);
        assert_eq!(
            dispatch(args(num::INVOKE, r.w[0] as u32, m8.tag, m8.words)).status,
            ipc::status::OK as i64,
            "AS::DESTROY of the fork"
        );
        assert!(crate::aspace::translate(forked, Vaddr(0xB0_0000)).is_err());
    }
    #[test]
    fn as_fork_cow_shares_and_copies_resolved_pages() {
        let (pid, _tid, factory) = setup();
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;
        let as_id = proc::get_cap(pid, as_h).unwrap().obj;

        // Direct-frame region (writable) + a resolved ANON page.
        let base = crate::frame::PhysAddr::new(0xF0_0000);
        crate::aspace::track_frame(base);
        crate::aspace::map(
            as_id,
            Vaddr(0xC0_0000),
            1,
            Some(base),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();

        // Attach a pool, then resolve one ANON page (per-page override).
        crate::aspace::set_pool(
            as_id,
            crate::frame::PhysAddr::new(0xC8_0000),
            2 * crate::aspace::PAGE_SIZE as u64,
        )
        .unwrap();
        crate::aspace::map(
            as_id,
            Vaddr(0xC1_0000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        let resolved = crate::aspace::resolve_fault(as_id, Vaddr(0xC1_0000), false).unwrap();

        // FORK via invoke.
        let m = Message::new(5);
        let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "FORK must succeed");
        let child_as = proc::get_cap(pid, r.w[0] as u32).unwrap();
        assert_eq!(child_as.typ, ObjType::AddressSpace);
        assert!(child_as.rights.contains(Rights::MAP));
        let child_id = child_as.obj;

        // Child sees the shared direct region, converted to COW on both sides.
        let (pa_child, fl_child) = crate::aspace::translate(child_id, Vaddr(0xC0_0000)).unwrap();
        assert_eq!(pa_child, base, "same frame shared");
        assert!(fl_child.contains(MapFlags::COW), "child side COW");
        let (_, fl_parent) = crate::aspace::translate(as_id, Vaddr(0xC0_0000)).unwrap();
        assert!(fl_parent.contains(MapFlags::COW), "parent side COW");
        assert_eq!(crate::aspace::frame_refs(base), 3, "owner + 2 mapping refs");

        // Child's resolved ANON page is a COPY (fresh frame), not shared.
        let (pa_copy, _) = crate::aspace::translate(child_id, Vaddr(0xC1_0000)).unwrap();
        assert_ne!(pa_copy, resolved, "resolved page copied, not shared");

        // COW write on the shared region: both sides still share with the
        // other's mapping ref outstanding → both copy from their own pools.
        let w1 = crate::aspace::resolve_fault(as_id, Vaddr(0xC0_0000), true).unwrap();
        crate::aspace::set_pool(
            child_id,
            crate::frame::PhysAddr::new(0xD0_0000),
            2 * crate::aspace::PAGE_SIZE as u64,
        )
        .unwrap();
        let w2 = crate::aspace::resolve_fault(child_id, Vaddr(0xC0_0000), true).unwrap();
        // Pool frame 0 went to the earlier ANON resolve; COW copy gets frame 1.
        assert_eq!(
            w1,
            crate::frame::PhysAddr::new(0xC8_1000),
            "parent copies from its pool"
        );
        assert_eq!(
            w2,
            crate::frame::PhysAddr::new(0xD0_0000),
            "child copies from its pool"
        );

        // Tear down both ASes so the shared frame allocator returns to full
        // for the frame-test module that runs after this one.
        let _ = crate::aspace::destroy(as_id);
        let _ = crate::aspace::destroy(child_id);
    }
    #[test]
    fn thread_create_spawns_into_target_process() {
        // ADR-033 §1: new thread shares the target's process (AS + table).
        let (pid, server, _factory) = setup();
        let tc = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(server.0),
                typ: ObjType::Thread,
                rights: Rights::CONTROL.union(Rights::GRANT),
            },
        )
        .unwrap();
        let m = Message::new(13);
        let mut m = m;
        m.words[0] = 0x402000; // entry PC
        let r = thread_invoke_for_test(pid, tc, m);
        assert_eq!(
            r.status,
            ipc::status::OK as i64,
            "THREAD_CREATE must succeed"
        );
        let new_h = r.w[0] as u32;
        let new_tid = ThreadId(r.w[1]);

        // Same process as the target thread; distinct thread id.
        let t = proc::get_cap(pid, new_h).unwrap();
        assert_eq!(t.typ, ObjType::Thread);
        assert!(t.rights.contains(Rights::CONTROL));
        assert_ne!(new_tid, server);
        assert_eq!(
            sched::get(new_tid).unwrap().process,
            sched::get(server).unwrap().process,
            "in-process thread shares the process"
        );
        assert_eq!(sched::get(new_tid).unwrap().initial_pc, 0x402000);

        // objreg ownership: same owner pid → process death retires it.
        assert!(crate::objreg::is_alive(ObjId(new_tid.0)));

        // Missing CONTROL → ERIGHTS.
        let weak = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(server.0),
                typ: ObjType::Thread,
                rights: Rights::GRANT,
            },
        )
        .unwrap();
        let r = thread_invoke_for_test(pid, weak, m);
        assert_eq!(r.status, ipc::status::ERIGHTS as i64);
    }
    #[test]
    fn set_entry_exec_semantics() {
        // ADR-039: SET_ENTRY rewrites a SUSPENDED thread's entry; running
        // threads are rejected; the rebuilt context enters the new PC.
        let (pid, _tid, factory) = setup();
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;

        // NEW_THREAD (creates the child suspended-entry thread).
        let mut m = Message::new(4);
        m.words[0] = 0x401000;
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(as_h, Rights::MAP))
            .unwrap();
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64);
        let thread_h = r.w[0] as u32;
        let child_tid = ThreadId(r.w[3]);

        // SET_ENTRY on the child while it is not suspended yet -> the child
        // was spawned Ready (not Suspended), so exec-on-Ready is rejected
        // (EBADSTATE). The shell composes SUSPEND first.
        let r2 = dispatch(args(
            num::INVOKE,
            thread_h,
            Tag::new(14),
            [0x500000, 0, 0, 0],
        ));
        assert_eq!(r2.status, ipc::status::EBADSTATE as i64);

        // SUSPEND then SET_ENTRY succeeds and updates initial_pc.
        assert_eq!(
            dispatch(args(num::INVOKE, thread_h, Tag::new(3), [0; 4])).status,
            ipc::status::OK as i64
        );
        let r3 = dispatch(args(
            num::INVOKE,
            thread_h,
            Tag::new(14),
            [0x500000, 0, 0, 0],
        ));
        assert_eq!(r3.status, ipc::status::OK as i64);
        assert_eq!(proc::get_cap(pid, thread_h).unwrap().typ, ObjType::Thread);
        // initial_pc is visible via sched::get.
        let t = crate::sched::get(child_tid).unwrap();
        assert_eq!(t.initial_pc, 0x500000);
        assert_eq!(t.state, crate::sched::State::Suspended);

        // RESUME makes it Ready again (the rebuilt context enters 0x500000).
        assert_eq!(
            dispatch(args(num::INVOKE, thread_h, Tag::new(4), [0; 4])).status,
            ipc::status::OK as i64
        );
        assert_eq!(
            crate::sched::get(child_tid).unwrap().state,
            crate::sched::State::Ready
        );
    }

    /// ADR-044: a foreign-flagged thread's syscall routes to the emulator
    /// endpoint as a FOREIGN_SYSCALL call; the emulator sees the message,
    /// reads the frame via TRAP_READ, and its reply completes the syscall.
    #[test]
    fn foreign_route_parks_and_reply_completes() {
        let (pid, emu, fgn, ep, ep_h) = {
            // Two threads in one process: the emulated thread + the emulator.
            crate::aspace::set_backend_factory(&MockFactory);
            let _ = crate::aspace::init_default();
            let _ = crate::frame::init(&[crate::frame::Region::new(
                crate::frame::PhysAddr::new(0x1000),
                64 * crate::frame::FRAME_SIZE as u64,
            )
            .unwrap()]);
            crate::init::reset_regions_for_test();
            crate::proc::reset_for_test();
            crate::endpoint::reset_engine_for_test();
            crate::notification::reset_for_test();
            syscall::reset_reply_for_test();
            *sched::SCHED.lock() = None;
            set_context_backend(&MockCtx);
            let _ = sched::init();
            let pid = proc::create().unwrap();
            let emu = sched::spawn(ObjRef(1), 100).unwrap();
            let fgn = sched::spawn(ObjRef(1), 100).unwrap();
            let ctx: &'static FixedCtx = Box::leak(Box::new(FixedCtx(pid, fgn)));
            set_current_context(ctx);
            // Emulator holds a SEND cap on the route endpoint.
            let ep = crate::endpoint::create_endpoint().unwrap();
            let h = proc::install_cap(
                pid,
                Capability {
                    obj: ObjId(ep.0),
                    typ: ObjType::Endpoint,
                    rights: Rights::SEND.union(Rights::RECV),
                },
            )
            .unwrap();
            // Flag the emulated thread (SET_FOREIGN via CONTROL invoke).
            sched::make_ready(fgn).ok();
            let ctl = proc::install_cap(
                pid,
                Capability {
                    obj: ObjId(fgn.0),
                    typ: ObjType::Thread,
                    rights: Rights::CONTROL,
                },
            )
            .unwrap();
            let ret = invoke(
                pid,
                emu,
                SyscallArgs {
                    num: num::INVOKE,
                    cap: ctl,
                    tag: Tag::new(15), // SET_FOREIGN (ADR-044 amended: cap HANDLE)
                    w: [h as u64, 0, 0, 0],
                    nonblock: false,
                },
            );
            assert_eq!(ret.status, 0, "SET_FOREIGN ok");
            (pid, emu, fgn, ep, h)
        };

        // The emulated thread traps a "foreign" syscall (num = a Linux
        // number, opaque to the kernel): dispatch must route, not execute.
        let args = SyscallArgs {
            num: 999, // opaque foreign number
            cap: 0,
            tag: Tag::new(0x1234),
            w: [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD],
            nonblock: false,
        };
        let ret = dispatch(args);
        assert!(
            ret.status == crate::entry::PARKED_STATUS,
            "foreign route parks the thread"
        );
        // The thread is parked Blocked(Reply) on the route call; the
        // emulator has a delivered FOREIGN_SYSCALL message.
        assert!(matches!(
            sched::get(fgn).unwrap().state,
            sched::State::Blocked(sched::BlockReason::Reply)
        ));
        // The emulator recv's the route like any request — via sys_recv, so
        // the implicit reply slot binds (set_reply_if_call) and the reply
        // completes the parked foreign syscall.
        let env = syscall::sys_recv(pid, emu, ep_h, false, 0)
            .expect("emulator recv route")
            .expect("route message delivered");
        let _ = ep;
        assert_eq!(env.tag.label(), ipc::labels::kernel::FOREIGN_SYSCALL);
        assert_eq!(env.words[0], 999, "opaque num");
        assert_eq!(env.words[2], 0xDDDD, "w3 rides the message");
        // Emulator fetches the rest of the frame via TRAP_READ.
        let ctl = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(fgn.0),
                typ: ObjType::Thread,
                rights: Rights::CONTROL,
            },
        )
        .unwrap();
        let ret = invoke(
            pid,
            emu,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl,
                tag: Tag::new(16), // TRAP_READ
                w: [0, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0);
        assert_eq!(
            ret.w[0],
            Tag::new(0x1234).0,
            "original tag (incl. default flags)"
        );
        assert_eq!(ret.w[1], 0xAAAA, "w0");
        assert_eq!(ret.w[2], 0xBBBB, "w1");
        assert_eq!(ret.w[3], 0xCCCC, "w2");
        // Emulator replies → the parked syscall completes with the reply.
        syscall::reply_only_for_test(emu, {
            let mut m = ipc::Message::new(0x77);
            m.words[0] = 0x4242;
            let mut env = crate::endpoint::Envelope::new(m, emu);
            env.sender = emu;
            env
        })
        .unwrap();
        let r = syscall::park_result(fgn).expect("reply completes the foreign syscall");
        // ADR-044 (amended): the foreign reply's word[0] IS the rax result.
        assert_eq!(r.status, 0x4242, "the emulator's value lands in rax");
        assert_eq!(r.w[0], 0x4242, "the reply words ride too");
        // TRAP_READ after completion → EBADSTATE (frame no longer exposed).
        let ret = invoke(
            pid,
            emu,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl,
                tag: Tag::new(16),
                w: [0, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, ipc::status::EBADSTATE as i64);
    }

    /// ADR-047: DEFER mints a Reply cap and clears the implicit slot;
    /// Reply::SEND completes the parked `call` and retires the cap.
    #[test]
    fn defer_and_deferred_reply_complete_the_call() {
        let (pid, server, client, ep_h) = {
            crate::aspace::set_backend_factory(&MockFactory);
            let _ = crate::aspace::init_default();
            let _ = crate::frame::init(&[crate::frame::Region::new(
                crate::frame::PhysAddr::new(0x1000),
                64 * crate::frame::FRAME_SIZE as u64,
            )
            .unwrap()]);
            crate::init::reset_regions_for_test();
            crate::proc::reset_for_test();
            crate::endpoint::reset_engine_for_test();
            crate::notification::reset_for_test();
            syscall::reset_reply_for_test();
            *sched::SCHED.lock() = None;
            set_context_backend(&MockCtx);
            let _ = sched::init();
            let pid = proc::create().unwrap();
            let server = sched::spawn(ObjRef(1), 100).unwrap();
            let client = sched::spawn(ObjRef(1), 100).unwrap();
            let ctx: &'static FixedCtx = Box::leak(Box::new(FixedCtx(pid, client)));
            set_current_context(ctx);
            let ep = crate::endpoint::create_endpoint().unwrap();
            let h = proc::install_cap(
                pid,
                caps::Capability {
                    obj: caps::ObjId(ep.0),
                    typ: caps::ObjType::Endpoint,
                    rights: caps::Rights::SEND.union(caps::Rights::RECV),
                },
            )
            .unwrap();
            (pid, server, client, h)
        };

        // Client calls; server receives the request (implicit reply slot
        // binds to the client).
        let mut m = ipc::Message::new(0x0110);
        m.words[0] = 42;
        assert_eq!(syscall::sys_call(pid, client, ep_h, m), Ok(0));
        let _req = syscall::sys_recv(pid, server, ep_h, false, 0)
            .unwrap()
            .unwrap();

        // Server defers: DEFER (CONTROL, self) mints the Reply cap and
        // clears the implicit slot.
        let ctl = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(server.0),
                typ: caps::ObjType::Thread,
                rights: caps::Rights::CONTROL,
            },
        )
        .unwrap();
        let ret = invoke(
            pid,
            server,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl,
                tag: Tag::new(17), // DEFER
                w: [0, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0, "DEFER ok");
        let reply_cap = ret.w[0] as u32;
        assert_ne!(reply_cap, 0, "Reply cap minted");
        // The implicit slot is cleared: a second DEFER fails (EBADSTATE).
        let ret = invoke(
            pid,
            server,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl,
                tag: Tag::new(17),
                w: [0, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, status::EBADSTATE as i64, "slot cleared");

        // The server answers LATER via Reply::SEND (label 1): the parked
        // client completes and the cap retires (one-shot).
        let ret = invoke(
            pid,
            server,
            SyscallArgs {
                num: num::INVOKE,
                cap: reply_cap,
                tag: Tag::new(1), // Reply::SEND
                w: [0x4242, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0, "deferred reply delivered");
        assert_eq!(
            sched::get(client).unwrap().state,
            sched::State::Ready,
            "client woke"
        );
        let r = syscall::park_result(client).expect("the parked call completes");
        assert_eq!(r.status, 0);
        assert_eq!(r.w[0], 0x4242, "the deferred reply's words ride");
        // One-shot: the cap is retired — a second SEND fails (EBADCAP).
        let ret = invoke(
            pid,
            server,
            SyscallArgs {
                num: num::INVOKE,
                cap: reply_cap,
                tag: Tag::new(1),
                w: [1, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, status::EBADCAP as i64, "cap retired");
    }
}
