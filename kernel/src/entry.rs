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
    pub cap: u64,
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
    /// ADR-044 (foreign restore): the trap-time user r10 (the entry shuffle
    /// clobbers it; SYS_RET[6] carries it back). Any value for native — r10
    /// is caller-saved there.
    pub r10: u64,
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
            r10: 0,
        }
    }

    pub const fn err(status: i32) -> Self {
        SyscallReturn {
            status: status as i64,
            tag: Tag(0),
            w: [0; 4],
            r10: 0,
        }
    }

    pub const fn ok(tag: Tag, w: [u64; 4]) -> Self {
        SyscallReturn {
            status: ipc::status::OK as i64,
            tag,
            w,
            r10: 0,
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
        syscall::clear_park_entry(tid);
        syscall::install_transfers(pid, &mut env);
        syscall::set_reply_if_call(&env, tid);
        // ADR-044 (foreign restore): the arch resume path calls THIS function
        // (not `syscall::park_result`), so the foreign completion must be
        // handled here: restore the trap-time user GPRs and land the Linux
        // result (reply word[0]) in rax. Without this a foreign thread's
        // syscall return value is lost (rax = 0) — the musl fd/getpid bug.
        if sched::get(tid)
            .map(|t| t.foreign_ep.is_some())
            .unwrap_or(false)
        {
            let f = sched::get(tid).map(|t| t.trap_frame).unwrap_or([0; 7]);
            return Some(SyscallReturn {
                status: env.msg.words[0] as i64,
                tag: Tag(f[3]),              // user rdx
                w: [f[2], f[1], f[5], f[6]], // rsi, rdi, r8, r9
                r10: f[4],                   // user r10
            });
        }
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
                    Tag::new(ipc::labels::kernel::NOTIFY).with_flags(flags::NOTIFIED),
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
                Tag::new(ipc::labels::kernel::NOTIFY).with_flags(flags::NOTIFIED),
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
            r10: 0,
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
        num::SEND => {
            match syscall::sys_send(pid, tid, args.cap as u32, args.message(), args.nonblock) {
                Ok(status) => SyscallReturn {
                    status: status as i64,
                    tag: Tag(0),
                    w: [0; 4],
                    r10: 0,
                },
                Err(e) => SyscallReturn::err(e),
            }
        }
        num::CALL => match syscall::sys_call(pid, tid, args.cap as u32, args.message()) {
            Ok(status) => SyscallReturn {
                status: status as i64,
                tag: Tag(0),
                w: [0; 4],
                r10: 0,
            },
            Err(e) => SyscallReturn::err(e),
        },
        num::RECV => {
            match syscall::sys_recv(pid, tid, args.cap as u32, args.w[0] != 0, args.w[1]) {
                Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
                Ok(None) => SyscallReturn::parked(), // ADR-019 §1
                Err(e) => SyscallReturn::err(e),
            }
        }
        num::REPLY_RECV => {
            match syscall::sys_reply_recv(pid, tid, args.cap as u32, args.message(), args.w[1]) {
                Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
                Ok(None) => SyscallReturn::parked(), // ADR-019 §1
                Err(e) => SyscallReturn::err(e),
            }
        }
        num::INVOKE => invoke(pid, tid, args),
        num::CAP_MINT => {
            let rights = ipc::Rights(u32::try_from(args.w[1]).unwrap_or(0) & Rights::ALL.0);
            match proc::mint(
                pid,
                args.cap as u32,
                rights,
                u32::try_from(args.w[0]).unwrap_or(0),
            ) {
                Ok(handle) => SyscallReturn::ok(Tag(0), [handle as u64, 0, 0, 0]),
                Err(e) => SyscallReturn::err(map_proc(e)),
            }
        }
        num::CAP_REVOKE => match proc::revoke(pid, args.cap as u32, args.w[0]) {
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
    let Ok(cap) = proc::get_cap(pid, args.cap as u32) else {
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
                    let _ = proc::remove_cap(pid, args.cap as u32);
                    SyscallReturn::ok(args.tag, [0; 4])
                }
                Err(e) => SyscallReturn::err(e),
            }
        }
        _ => match syscall::sys_invoke(pid, tid, args.cap as u32, args.message()) {
            Ok((status, w)) => SyscallReturn {
                status: status as i64,
                tag: Tag(0),
                w,
                r10: 0,
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
            // S4: reject non-user ranges (kernel window PML4[511], the
            // reserved slots, VA 0) BEFORE any frame allocation so a bad
            // range costs no memory. aspace::map re-validates.
            if aspace::validate_user_range(vaddr, 1).is_err() {
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
                // S4: a range outside user space (or VA 0 / unaligned) is a
                // bad argument, not an allocation failure.
                Err(aspace::VmmError::Overlap) | Err(aspace::VmmError::BadVaddr) => {
                    SyscallReturn::err(ipc::status::EBADARG)
                }
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
    const SET_TLS: u16 = 11;
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
            // S2: the PC must be a canonical user address — a kernel or
            // non-canonical value would execute ring 3 in the kernel window
            // (SMEP blocks it only where the CPU supports it).
            let pc = msg.words[0];
            if !sched::is_user_addr(pc) {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            match sched::set_entry(target, pc) {
                Ok(()) => SyscallReturn::ok(msg.tag, [0, pc, 0, 0]),
                Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
            }
        }
        SET_TLS => {
            // ADR-044/046 (musl TLS): w0 = the thread's FS base — musl's
            // arch_prctl(ARCH_SET_FS) lands here via the emulator. The arch
            // switch loads it when the target is scheduled. S3: the base
            // must be a canonical user address (0 keeps its documented
            // "clear" meaning) — a kernel or non-canonical value faults in
            // ring 0 at the next switch, halting the machine.
            let fs = msg.words[0];
            if fs != 0 && !sched::is_user_addr(fs) {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
            match sched::set_tls(target, fs) {
                Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
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
            // S1/ADR-050: the image is the TARGET's per-thread user register
            // image (`Thread::user_regs`) — the kernel stack is never read
            // or written with user words. Image slot 3 is RFLAGS, masked
            // (IOPL=0, IF=1); REGS_WRITE rebuilds the target's initial
            // context from the sanitized image (kernel-generated trampoline
            // slot). S2b: the entry PC (image[2]) must be a canonical user
            // address — a kernel or non-canonical value would fault in ring 0
            // at iretq.
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
                    Ok(()) => SyscallReturn::ok(msg.tag, [image[0], image[2], image[1], image[3]]),
                    Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
                }
            } else {
                for (dst, src) in image.iter_mut().zip(msg.words.iter()) {
                    *dst = *src;
                }
                // S2b: validate the entry PC (image slot 2) before any state change
                if !sched::is_user_addr(image[2]) {
                    return SyscallReturn::err(ipc::status::EBADARG);
                }
                match sched::regs_write(target, &image) {
                    Ok(()) => SyscallReturn::ok(msg.tag, [0; 4]),
                    Err(_) => SyscallReturn::err(ipc::status::EBADSTATE),
                }
            }
        }
        THREAD_CREATE => {
            // ADR-033 §1: new thread in the TARGET's process (shares AS +
            // cap table). w0 = entry PC. CONTROL right already enforced.
            // S2: the entry PC must be a canonical user address.
            if !sched::is_user_addr(msg.words[0]) {
                return SyscallReturn::err(ipc::status::EBADARG);
            }
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
            cap: cap_handle as u64,
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

/// S8: resolve one NEW_THREAD endpoint descriptor (`idx` 1 = fault EP, 2 =
/// bootstrap EP) under the transfer rules of the in-message cap path
/// (`syscall::resolve_transfers`, ADR-026): the caller's cap must be a live
/// `ObjType::Endpoint` carrying GRANT, and the child receives
/// `rights ∩ requested` — never the caller's full rights, never an added
/// right. `Ok(None)` = descriptor absent (NULL or no slot, ADR-017 §1).
/// `Err(status)` = transfer refused; the caller must fail the syscall.
fn resolve_thread_ep(pid: ProcessId, msg: &Message, idx: usize) -> Result<Option<Capability>, i32> {
    let Some(cs) = msg.descriptor(idx) else {
        return Ok(None);
    };
    if cs.handle() == 0 {
        return Ok(None);
    }
    let cap = proc::get_cap(pid, cs.handle()).map_err(map_proc)?;
    if cap.typ != ObjType::Endpoint {
        return Err(ipc::status::EBADARG);
    }
    if !cap.rights.contains(Rights::GRANT) {
        return Err(ipc::status::ERIGHTS);
    }
    if !crate::objreg::is_alive(cap.obj) {
        return Err(ipc::status::EBADARG);
    }
    Ok(Some(Capability {
        obj: cap.obj,
        typ: cap.typ,
        rights: cap.rights.intersect(cs.rights()),
    }))
}

/// Factory::NEW_THREAD (ADR-017 packing): creates the child process + thread,
/// applies caps[1] (fault EP) atomically, installs caps[2] (bootstrap EP) at
/// child handle 1 (slot 0) per ADR-009, and returns the child's thread cap.
/// S8: caps[1]/caps[2] transfer under the same rules as in-message caps
/// (`syscall::resolve_transfers`, ADR-026): live Endpoint + GRANT on the
/// caller's cap, child receives rights ∩ requested — no full-rights copy,
/// no added SEND.
fn new_thread(pid: ProcessId, cap: &Capability, msg: &Message) -> SyscallReturn {
    if !cap.rights.contains(Rights::GRANT) {
        return SyscallReturn::err(ipc::status::ERIGHTS);
    }
    let entry_pc = msg.words[0];
    // S2: reject kernel / non-canonical / null entry PCs before any child
    // state is created, so a bad call costs no process slot.
    if !sched::is_user_addr(entry_pc) {
        return SyscallReturn::err(ipc::status::EBADARG);
    }

    // S8: resolve both endpoint descriptors BEFORE the child exists, so a
    // bad call costs no process slot.
    let fault_ep = match resolve_thread_ep(pid, msg, 1) {
        Ok(c) => c,
        Err(status) => return SyscallReturn::err(status),
    };
    let boot_ep = match resolve_thread_ep(pid, msg, 2) {
        Ok(c) => c,
        Err(status) => return SyscallReturn::err(status),
    };

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

    // caps[1] = fault endpoint (optional; S8-validated above).
    if let Some(fep) = fault_ep {
        if proc::install_cap(child_pid, fep).is_err() {
            return SyscallReturn::err(ipc::status::ENOMEM);
        }
    }

    // caps[2] = bootstrap endpoint → child handle 1 (slot 0), ADR-009
    // (S8: rights ∩ requested only — the v0 forced SEND is gone; no current
    // flow sends on the bootstrap EP, the child only receives + revokes it).
    if let Some(bep) = boot_ep {
        if proc::install_cap_at(child_pid, 0, bep).is_err() {
            return SyscallReturn::err(ipc::status::ENOMEM);
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
        crate::frame::reset_for_test();
        let _ = crate::frame::init(&[crate::frame::Region::new(
            crate::frame::PhysAddr::new(0x1000),
            64 * crate::frame::FRAME_SIZE as u64,
        )
        .unwrap()]);
        crate::init::reset_regions_for_test();
        crate::proc::reset_for_test();
        crate::objreg::reset_for_test();
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
            cap: cap as u64,
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

    /// S8: NEW_THREAD's caps[1]/caps[2] endpoint transfer must follow the
    /// in-message transfer rules (ADR-026): GRANT required on the caller's
    /// cap, cap type must be Endpoint, and the child receives
    /// rights ∩ requested — never the caller's full rights, never an added
    /// SEND. Fails on the v0 code: it copied caps[1] with full rights, never
    /// checked GRANT or type, and force-unioned SEND into caps[2].
    #[test]
    fn s8_new_thread_ep_transfer_grant_checked_and_intersected() {
        let (pid, _tid, factory) = setup();

        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;
        // A live endpoint (created through the factory so objreg has it).
        let r_ep = dispatch(args(num::INVOKE, factory, Tag::new(1), [0; 4]));
        let live_ep = proc::get_cap(pid, r_ep.w[0] as u32).unwrap();
        let r_notif = dispatch(args(num::INVOKE, factory, Tag::new(2), [0; 4]));

        // A GRANT-less cap on the SAME live endpoint object: the v0 code
        // transferred it with full rights; the transfer must refuse (ERIGHTS).
        let ep_no_grant = proc::install_cap(
            pid,
            Capability {
                obj: live_ep.obj,
                typ: ObjType::Endpoint,
                rights: Rights::SEND.union(Rights::RECV),
            },
        )
        .unwrap();

        let new_thread_msg = |c1: CapSlot, c2: CapSlot| {
            let mut m = Message::new(4);
            m.words[0] = 0x401000;
            m.tag = m.tag.with_caps(3);
            m.set_descriptor(0, CapSlot::pack(as_h, Rights::MAP))
                .unwrap();
            m.set_descriptor(1, c1).unwrap();
            m.set_descriptor(2, c2).unwrap();
            m
        };

        // (a) caps[2] without GRANT on the caller's cap → ERIGHTS.
        let m = new_thread_msg(CapSlot::NULL, CapSlot::pack(ep_no_grant, Rights::SEND));
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(
            r.status,
            ipc::status::ERIGHTS as i64,
            "caps[2] without GRANT must be refused (v0: full-rights copy)"
        );

        // (b) caps[1] with a non-Endpoint cap → EBADARG (type check).
        let m = new_thread_msg(
            CapSlot::pack(r_notif.w[0] as u32, Rights::RECV),
            CapSlot::NULL,
        );
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(
            r.status,
            ipc::status::EBADARG as i64,
            "caps[1] must be an Endpoint (v0: any type accepted)"
        );

        // (c) caps[2] with GRANT, requesting only RECV → the child's
        // bootstrap cap is exactly RECV: no forced SEND (v0 bug), no full
        // copy of the caller's SEND|RECV|GRANT.
        let m = new_thread_msg(CapSlot::NULL, CapSlot::pack(r_ep.w[0] as u32, Rights::RECV));
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64);
        let child_pid = ObjId(r.w[2]);
        let boot = proc::get_cap(child_pid, 1).unwrap();
        assert_eq!(
            boot.rights,
            Rights::RECV,
            "bootstrap cap = rights ∩ requested"
        );
        assert_eq!(boot.obj, live_ep.obj);
        proc::destroy(child_pid).unwrap();

        // (d) caps[1] fault EP with full rights held, SEND requested → the
        // child's fault-EP cap is exactly SEND (v0 copied full rights).
        let m = new_thread_msg(CapSlot::pack(r_ep.w[0] as u32, Rights::SEND), CapSlot::NULL);
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64);
        let child_pid = ObjId(r.w[2]);
        let fep = proc::get_cap(child_pid, 1).unwrap();
        assert_eq!(fep.rights, Rights::SEND, "fault EP = rights ∩ requested");
        assert_eq!(fep.obj, live_ep.obj);
        assert_eq!(fep.typ, ObjType::Endpoint);
        proc::destroy(child_pid).unwrap();
        // Ensure clean registry for subsequent tests.
        crate::proc::reset_for_test();
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
        // Ensure clean process registry (test interference from regs_write test).
        crate::proc::reset_for_test();
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

    /// S2: SET_ENTRY / THREAD_CREATE / NEW_THREAD must reject kernel-window,
    /// non-canonical and null entry PCs with EBADARG — a ring-3 thread must
    /// never be pointed into the shared kernel window (or anywhere outside
    /// the canonical user half).
    #[test]
    fn s2_entry_pcs_must_be_canonical_user_addrs() {
        let (pid, _tid, factory) = setup();
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;

        // NEW_THREAD: kernel-window PC (higher half), the canonical split
        // value itself, and null are all EBADARG; no child is spawned.
        for bad in [
            0xFFFF_8000_0100_0000, // kernel window (ADR-045)
            0xFFFF_FFFF_FFFF_F000, // non-canonical
            0x0000_8000_0000_0000, // the user/kernel split
            0,                     // null
        ] {
            let mut m = Message::new(4);
            m.words[0] = bad;
            m.tag = m.tag.with_caps(1);
            m.set_descriptor(0, CapSlot::pack(as_h, Rights::MAP))
                .unwrap();
            let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
            assert_eq!(
                r.status,
                ipc::status::EBADARG as i64,
                "NEW_THREAD pc={bad:#x}"
            );
        }
        // A valid PC still works after the rejections (no state corrupted).
        let mut m = Message::new(4);
        m.words[0] = 0x401000;
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(as_h, Rights::MAP))
            .unwrap();
        let r = dispatch(args(num::INVOKE, factory, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "valid NEW_THREAD pc");
        let thread_h = r.w[0] as u32;
        let child_tid = ThreadId(r.w[3]);

        // THREAD_CREATE with a kernel-window PC → EBADARG.
        let tc = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(child_tid.0),
                typ: ObjType::Thread,
                rights: Rights::CONTROL.union(Rights::GRANT),
            },
        )
        .unwrap();
        let mut m = Message::new(13);
        m.words[0] = 0xFFFF_8000_0100_0000;
        let r = thread_invoke_for_test(pid, tc, m);
        assert_eq!(
            r.status,
            ipc::status::EBADARG as i64,
            "THREAD_CREATE kernel pc"
        );

        // SET_ENTRY with kernel-window / non-canonical / null PCs → EBADARG
        // (the child is Ready, but the address check fires before the state
        // check — either way the call must fail, and with EBADARG).
        dispatch(args(num::INVOKE, thread_h, Tag::new(3), [0; 4])); // SUSPEND
        for bad in [0xFFFF_8000_0100_0000, 0x0000_8000_0000_0000, 0] {
            let r = dispatch(args(num::INVOKE, thread_h, Tag::new(14), [bad, 0, 0, 0]));
            assert_eq!(
                r.status,
                ipc::status::EBADARG as i64,
                "SET_ENTRY pc={bad:#x}"
            );
        }
        // A valid user PC still lands (state machine intact).
        let r = dispatch(args(
            num::INVOKE,
            thread_h,
            Tag::new(14),
            [0x500000, 0, 0, 0],
        ));
        assert_eq!(r.status, ipc::status::OK as i64, "valid SET_ENTRY pc");
        assert_eq!(sched::get(child_tid).unwrap().initial_pc, 0x500000);
    }

    /// S4: AS::MAP/UNMAP/PROTECT must reject kernel-window, split and null
    /// ranges with EBADARG — a user PTE must never be installable over the
    /// shared kernel window (PML4[511]), and a rejected call must allocate
    /// nothing.
    #[test]
    fn s4_as_ranges_must_stay_in_user_space() {
        let (pid, _tid, factory) = setup();
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;
        let as_id = proc::get_cap(pid, as_h).unwrap().obj;

        // MAP (ANON|R — no frame cap needed) at bad ranges: kernel window,
        // the split itself, null. All EBADARG, and no ANON frame burned
        // (the range check fires before allocation).
        for bad in [0xFFFF_8000_0100_0000, 0x0000_8000_0000_0000, 0] {
            let mut m = Message::new(1);
            m.words[0] = bad;
            m.words[1] = 0b1_1000; // ANON|R
            let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
            assert_eq!(r.status, ipc::status::EBADARG as i64, "MAP va={bad:#x}");
            assert!(
                crate::aspace::translate(as_id, Vaddr(bad)).is_err(),
                "nothing recorded for va={bad:#x}"
            );
        }

        // UNMAP of the kernel window (munmap hole-skip semantics would
        // otherwise "succeed") → EBADARG.
        let mut m = Message::new(2);
        m.words[0] = 0xFFFF_8000_0100_0000;
        m.words[1] = 1;
        assert_eq!(
            dispatch(args(num::INVOKE, as_h, m.tag, m.words)).status,
            ipc::status::EBADARG as i64,
            "UNMAP kernel window"
        );

        // PROTECT of the kernel window → EBADARG.
        let mut m = Message::new(3);
        m.words[0] = 0xFFFF_8000_0100_0000;
        m.words[2] = 0b001;
        assert_eq!(
            dispatch(args(num::INVOKE, as_h, m.tag, m.words)).status,
            ipc::status::EBADARG as i64,
            "PROTECT kernel window"
        );

        // A legal ANON map still works after the rejections.
        let mut m = Message::new(1);
        m.words[0] = 0xA0_0000;
        m.words[1] = 0b1_1000; // ANON|R
        let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "valid ANON MAP");
        assert!(crate::aspace::translate(as_id, Vaddr(0xA0_0000)).is_ok());

        // Release the ANON frame: kernel tests share one frame::init region
        // cumulatively (setup's re-init no-ops once initialized), so every
        // entry test must end frame-neutral or later kstack allocations
        // fail (spawn leaves kstack_top=0 → SET_ENTRY EBADSTATE).
        let mut m = Message::new(2);
        m.words[0] = 0xA0_0000;
        m.words[1] = 1;
        assert_eq!(
            dispatch(args(num::INVOKE, as_h, m.tag, m.words)).status,
            ipc::status::OK as i64,
            "UNMAP of the legal ANON map"
        );
    }

    /// S9: UNMAP with a huge page count must be rejected with EBADARG —
    /// the kernel must not loop with interrupts off for an unbounded span.
    #[test]
    fn s9_unmap_huge_page_count_rejected() {
        let (_pid, _tid, factory) = setup();
        let r_as = dispatch(args(num::INVOKE, factory, Tag::new(3), [0; 4]));
        let as_h = r_as.w[0] as u32;

        // UNMAP with page count > MAX_UNMAP_PAGES (1024) → EBADARG.
        for huge in [1025, 10_000, u64::MAX] {
            let mut m = Message::new(2);
            m.words[0] = 0x100_000; // valid user VA
            m.words[1] = huge;
            let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
            assert_eq!(
                r.status,
                ipc::status::EBADARG as i64,
                "UNMAP pages={huge} must be rejected"
            );
        }

        // A legal page count still works.
        let mut m = Message::new(2);
        m.words[0] = 0xA0_0000;
        m.words[1] = 1;
        let r = dispatch(args(num::INVOKE, as_h, m.tag, m.words));
        assert_eq!(r.status, ipc::status::OK as i64, "valid UNMAP");
    }

    /// S1/ADR-050: the REGS_WRITE syscall masks RFLAGS (IOPL=0, IF=1) and
    /// never writes caller words into the target's kernel stack — slot 3 of
    /// the init-context frame (the ring-0 trampoline return address) stays
    /// kernel-owned. REGS_READ exposes the masked RFLAGS in w3.
    #[test]
    fn regs_write_masks_rflags_and_spares_kstack_slot3() {
        let (pid, _tid, _factory) = setup();
        // Target thread with a fake-backed kstack, suspended.
        let target = sched::spawn_with(ObjRef(1), 100, 0x401000).unwrap();
        static FAKE: Mutex<[u64; 512]> = Mutex::new([0; 512]);
        let base = FAKE.lock().as_ptr() as u64;
        sched::set_kstack(target, base, 1).unwrap();
        let top = base + crate::frame::FRAME_SIZE as u64;
        crate::mem::seed_reg_image(top, &[0x1111; 10]);
        let tc = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(target.0),
                typ: ObjType::Thread,
                rights: Rights::CONTROL.union(Rights::GRANT),
            },
        )
        .unwrap();
        // SUSPEND the target (Ready → Suspended) via the syscall layer.
        let r = thread_invoke_for_test(pid, tc, Message::new(3));
        assert_eq!(r.status, ipc::status::OK as i64, "SUSPEND");
        // Frame cap for caps[0] (authority token only).
        let frame_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(0xE0_0000),
                typ: ObjType::Frame,
                rights: Rights::READ.union(Rights::WRITE),
            },
        )
        .unwrap();

        // REGS_WRITE with slot 3 = 0x3002 (IOPL=3, IF=0): the takeover word.
        let mut m = Message::new(10);
        m.words = [0xAAAA, 0xBBBB, 0x405000, 0x3002];
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
            .unwrap();
        let r = thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, ipc::status::OK as i64, "REGS_WRITE");

        // The trampoline slot kept its kernel value; the image is masked.
        let mut after = [0u64; 10];
        crate::mem::read_reg_image(top, &mut after);
        assert_eq!(after[3], 0x1111, "slot 3 kernel-owned");
        assert_eq!(after[0], 0xAAAA, "arg slot applied");
        let t = sched::get(target).unwrap();
        // words[3] rides the Frame-cap descriptor (handle | rights<<32); the
        // RFLAGS mask must still normalize it: IOPL (bits 12–13) cleared,
        // IF (bit 9) set.
        assert_eq!(
            t.user_regs[3] & 0x3000,
            0,
            "IOPL cleared in the stored image"
        );
        assert_eq!(
            t.user_regs[3] & 0x200,
            0x200,
            "IF forced in the stored image"
        );
        assert_eq!(t.initial_pc, 0x405000);

        // REGS_READ: the image comes back with the masked RFLAGS in w3.
        let mut m = Message::new(9);
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
            .unwrap();
        let r = thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, ipc::status::OK as i64, "REGS_READ");
        assert_eq!(r.w[0], 0xAAAA, "arg");
        assert_eq!(r.w[1], 0x405000, "entry");
        assert_eq!(r.w[2], 0xBBBB, "user RSP");
        assert_eq!(r.w[3] & 0x3000, 0, "IOPL cleared on the wire");
        assert_eq!(r.w[3] & 0x200, 0x200, "IF set on the wire");
        // REGS_WRITE without a Frame cap → EBADARG.
        let r = thread_invoke_for_test(pid, tc, Message::new(10));
        assert_eq!(r.status, ipc::status::EBADARG as i64);
        // Clean up for subsequent tests.
        crate::proc::reset_for_test();
        *crate::sched::SCHED.lock() = None;
    }

    /// S2b: REGS_WRITE must reject kernel-window, non-canonical and null
    /// entry PCs (image slot 2) with EBADARG — the target's rebuilt init
    /// context would fault at iretq if the PC is not a canonical user address.
    #[test]
    fn s2b_regs_write_rejects_invalid_entry_pc() {
        let (pid, _tid, _factory) = setup();
        let target = sched::spawn_with(ObjRef(1), 100, 0x401000).unwrap();
        static FAKE: Mutex<[u64; 512]> = Mutex::new([0; 512]);
        let base = FAKE.lock().as_ptr() as u64;
        sched::set_kstack(target, base, 1).unwrap();
        let top = base + crate::frame::FRAME_SIZE as u64;
        crate::mem::seed_reg_image(top, &[0x1111; 10]);
        let tc = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(target.0),
                typ: ObjType::Thread,
                rights: Rights::CONTROL.union(Rights::GRANT),
            },
        )
        .unwrap();
        let r = thread_invoke_for_test(pid, tc, Message::new(3));
        assert_eq!(r.status, ipc::status::OK as i64, "SUSPEND");
        let frame_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(0xE0_0000),
                typ: ObjType::Frame,
                rights: Rights::READ.union(Rights::WRITE),
            },
        )
        .unwrap();

        // REGS_WRITE with invalid entry PCs in image[2]: kernel window,
        // non-canonical, the split value itself, and null → all EBADARG.
        for bad in [
            0xFFFF_8000_0100_0000, // kernel window (ADR-045)
            0xFFFF_FFFF_FFFF_F000, // non-canonical
            0x0000_8000_0000_0000, // user/kernel split
            0,                     // null
        ] {
            let mut m = Message::new(10);
            m.words = [0xAAAA, 0xBBBB, bad, 0x3002];
            m.tag = m.tag.with_caps(1);
            m.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
                .unwrap();
            let r = thread_invoke_for_test(pid, tc, m);
            assert_eq!(
                r.status,
                ipc::status::EBADARG as i64,
                "REGS_WRITE pc={bad:#x}"
            );
            // The target's state must not change on rejection.
            let t = sched::get(target).unwrap();
            assert_eq!(t.state, crate::sched::State::Suspended);
            assert_eq!(t.initial_pc, 0x401000, "pc unchanged after rejection");
        }

        // A valid user PC still works after the rejections.
        let mut m = Message::new(10);
        m.words = [0xAAAA, 0xBBBB, 0x405000, 0x3002];
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
            .unwrap();
        let r = thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, ipc::status::OK as i64, "valid REGS_WRITE pc");
        assert_eq!(sched::get(target).unwrap().initial_pc, 0x405000);

        crate::proc::reset_for_test();
        *crate::sched::SCHED.lock() = None;
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
                    cap: ctl as u64,
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
                cap: ctl as u64,
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
        // ADR-044 (amended): the foreign reply's word[0] IS the rax result;
        // the REST of the trap-time user GPRs are restored (Linux ABI: only
        // rax/rcx/r11 are clobbered by a syscall).
        assert_eq!(r.status, 0x4242, "the emulator's value lands in rax");
        // The trap-time user GPRs: rdx=w0, rsi=tag, rdi=cap, r10=w1,
        // r8=w2, r9=w3 (the native arg shuffle's register mapping).
        assert_eq!(r.tag.0, 0xAAAA, "user rdx restored (w0)");
        assert_eq!(r.w[0], Tag::new(0x1234).0, "user rsi restored (tag)");
        assert_eq!(r.w[1], 0, "user rdi restored (cap arg was 0)");
        assert_eq!(r.w[2], 0xCCCC, "user r8 restored (w2→arg4)");
        assert_eq!(r.w[3], 0xDDDD, "user r9 restored (w3→arg5)");
        assert_eq!(r.r10, 0xBBBB, "user r10 restored (w1→arg3)");
        // TRAP_READ after completion → EBADSTATE (frame no longer exposed).
        let ret = invoke(
            pid,
            emu,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl as u64,
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
                cap: ctl as u64,
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
                cap: ctl as u64,
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
                cap: reply_cap as u64,
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
                cap: reply_cap as u64,
                tag: Tag::new(1),
                w: [1, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, status::EBADCAP as i64, "cap retired");
    }

    /// ADR-044/046: SET_TLS (id 11) stores the FS base; the sched accessor
    /// roundtrips it (the arch switch loads it on schedule).
    #[test]
    fn set_tls_stores_fs_base() {
        let (pid, target, _ep_h) = setup();
        let ctl = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(target.0),
                typ: caps::ObjType::Thread,
                rights: caps::Rights::CONTROL,
            },
        )
        .unwrap();
        assert_eq!(sched::fs_base_of(target), 0, "default FS base");
        let ret = invoke(
            pid,
            target,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl as u64,
                tag: Tag::new(11), // SET_TLS
                w: [0x7E00_1234_5678, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0, "SET_TLS ok");
        assert_eq!(sched::fs_base_of(target), 0x7E00_1234_5678);
        // Clear: w0 = 0.
        let ret = invoke(
            pid,
            target,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl as u64,
                tag: Tag::new(11),
                w: [0, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0);
        assert_eq!(sched::fs_base_of(target), 0);
    }

    /// S3: SET_TLS must reject kernel-window / non-canonical FS bases with
    /// EBADARG — such a base faults in ring 0 at the next context switch
    /// (any process could halt the machine). 0 stays legal (clear).
    #[test]
    fn s3_set_tls_rejects_kernel_and_non_canonical_bases() {
        let (pid, target, _ep_h) = setup();
        let ctl = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(target.0),
                typ: caps::ObjType::Thread,
                rights: caps::Rights::CONTROL,
            },
        )
        .unwrap();
        for bad in [
            0xFFFF_8000_0000_0000, // kernel window base (higher half)
            0xFFFF_FFFF_FFFF_F000, // non-canonical
            0x0000_8000_0000_0000, // the user/kernel split
        ] {
            let ret = invoke(
                pid,
                target,
                SyscallArgs {
                    num: num::INVOKE,
                    cap: ctl as u64,
                    tag: Tag::new(11), // SET_TLS
                    w: [bad, 0, 0, 0],
                    nonblock: false,
                },
            );
            assert_eq!(ret.status, ipc::status::EBADARG as i64, "fs_base={bad:#x}");
        }
        // The rejected values never entered the thread's state.
        assert_eq!(
            sched::fs_base_of(target),
            0,
            "bad bases rejected, none stored"
        );
        // A valid user base still roundtrips; 0 still clears.
        let ret = invoke(
            pid,
            target,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl as u64,
                tag: Tag::new(11),
                w: [0x7E00_1234_5678, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0, "valid user FS base still ok");
        assert_eq!(sched::fs_base_of(target), 0x7E00_1234_5678);
    }

    /// ADR-044 (DS's slice-33 corruption report): the EMULATOR does a
    /// blocking send MID-SERVE (after recv, before reply) that PARKS it;
    /// a third thread drains the target; the emulator then replies. The
    /// served foreign thread must complete with the reply's value in rax —
    /// the intra-serve park must not corrupt the parked foreign thread or
    /// the resume path.
    #[test]
    fn emulator_intra_serve_park_does_not_corrupt_the_foreign_resume() {
        let (pid, emu, fgn, drain, route_h, sink_h) = {
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
            let drain = sched::spawn(ObjRef(1), 100).unwrap();
            let ctx: &'static FixedCtx = Box::leak(Box::new(FixedCtx(pid, fgn)));
            set_current_context(ctx);
            // The route endpoint (emu recv's; fgn's traps route there).
            let route = crate::endpoint::create_endpoint().unwrap();
            let route_h = proc::install_cap(
                pid,
                caps::Capability {
                    obj: caps::ObjId(route.0),
                    typ: caps::ObjType::Endpoint,
                    rights: caps::Rights::SEND.union(caps::Rights::RECV),
                },
            )
            .unwrap();
            // The "console" sink endpoint: emu sends into it; the DRAIN
            // thread recv's — its mailbox stays FULL so emu's send parks.
            let sink = crate::endpoint::create_endpoint().unwrap();
            let sink_h = proc::install_cap(
                pid,
                caps::Capability {
                    obj: caps::ObjId(sink.0),
                    typ: caps::ObjType::Endpoint,
                    rights: caps::Rights::SEND.union(caps::Rights::RECV),
                },
            )
            .unwrap();
            (pid, emu, fgn, drain, route_h, sink_h)
        };

        // Flag fgn (SET_FOREIGN with the route handle — ADR-044 amended).
        let ctl = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(fgn.0),
                typ: caps::ObjType::Thread,
                rights: caps::Rights::CONTROL,
            },
        )
        .unwrap();
        let ret = invoke(
            pid,
            emu,
            SyscallArgs {
                num: num::INVOKE,
                cap: ctl as u64,
                tag: Tag::new(15),
                w: [route_h as u64, 0, 0, 0],
                nonblock: false,
            },
        );
        assert_eq!(ret.status, 0, "SET_FOREIGN ok");

        // fgn traps a foreign syscall → routes → parked Blocked(Reply).
        let ret = dispatch(SyscallArgs {
            num: 999,
            cap: 0,
            tag: Tag::new(0x1234),
            w: [0xAAAA, 0, 0, 0],
            nonblock: false,
        });
        assert_eq!(ret.status, crate::entry::PARKED_STATUS);
        // emu recv's the route.
        let _env = syscall::sys_recv(pid, emu, route_h, false, 0)
            .unwrap()
            .expect("route delivered");

        // emu's INTRA-SERVE blocking send: fill the sink mailbox first
        // (a filler send from emu), then the flush send PARKS emu.
        let mut m = ipc::Message::new(0x77);
        m.words[0] = 1;
        assert_eq!(syscall::sys_send(pid, emu, sink_h, m, false), Ok(0));
        m.words[0] = 2;
        // Nonblocking first to confirm the mailbox is full...
        assert_eq!(
            syscall::sys_send(pid, emu, sink_h, m, true),
            Err(status::EWOULDBLOCK)
        );
        // ...then the blocking flush send: emu parks Blocked(Send).
        syscall::sys_send(pid, emu, sink_h, m, false).unwrap();
        assert!(matches!(
            sched::get(emu).unwrap().state,
            sched::State::Blocked(sched::BlockReason::Send(_))
        ));
        assert!(matches!(
            sched::get(fgn).unwrap().state,
            sched::State::Blocked(sched::BlockReason::Reply)
        ));

        // The drain thread recv's the sink → emu unqueues and resumes.
        let _drained = syscall::sys_recv(pid, drain, sink_h, false, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            sched::get(emu).unwrap().state,
            sched::State::Ready,
            "emu resumed after the drain"
        );

        // emu replies (word[0] = the rax value).
        let mut rep = ipc::Message::new(0x99);
        rep.words[0] = 0x1234_5678;
        {
            let (env, _) = syscall::resolve_transfers_for_test(pid, &rep, emu);
            crate::endpoint::DELIVERED_FOR_REPLY.lock().insert(fgn, env);
            sched::make_ready(fgn).unwrap();
        }
        let r = syscall::park_result(fgn).expect("fgn completes");
        assert_eq!(r.status, 0x1234_5678, "rax = the reply value");
        // The emu thread's own state is sane after the intra-serve park.
        assert!(matches!(
            sched::get(emu).unwrap().state,
            sched::State::Ready | sched::State::Blocked(_)
        ));
    }
}
