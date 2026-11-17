//! Syscall engine (ADR-011): pure-logic implementation of the nine native
//! syscalls (syscall-abi §3) over the scheduler, endpoint engine, process
//! registry, and notifications. The arch trap entry only marshals registers
//! into these functions; all policy lives here (host-testable).
#![forbid(unsafe_code)]

use crate::endpoint::{self, Envelope, IpcError};
use crate::notification;
use crate::proc::{self, ProcError, ProcessId};
use crate::sched::{self, BlockReason, ObjRef, ThreadId};
use caps::Capability;
use caps::{ObjType, Rights};
use ipc::{flags, CapSlot, Message, Tag};
use spin::Mutex;

pub const REPLY_CAP_SENTINEL: u32 = 0xFFFF_FFFE;

pub type SysResult<T> = Result<T, i32>;

fn err(e: i32) -> i32 {
    e
}

fn map_ipc(e: IpcError) -> i32 {
    match e {
        IpcError::NoSuchEndpoint => ipc::status::EBADCAP,
        IpcError::EndpointFull | IpcError::NoMessage => ipc::status::EWOULDBLOCK,
        IpcError::NoWaiterSlot | IpcError::Sched(_) => ipc::status::ENOMEM,
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

/// Kernel-side per-thread implicit reply state (ADR-011 §2).
struct ReplyState {
    who: [Option<(ThreadId, ThreadId)>; 64], // (callee, caller) pairs keyed by callee index
}

static REPLY: Mutex<ReplyState> = Mutex::new(ReplyState {
    who: [const { None }; 64],
});

fn reply_key(t: ThreadId) -> Option<usize> {
    let k = t.0 as usize;
    if k > 0 && k < 64 {
        Some(k)
    } else {
        None
    }
}

fn set_reply(callee: ThreadId, caller: ThreadId) {
    if let Some(k) = reply_key(callee) {
        REPLY.lock().who[k] = Some((callee, caller));
    }
}

fn take_reply(callee: ThreadId) -> Option<ThreadId> {
    let k = reply_key(callee)?;
    REPLY.lock().who[k].take().map(|(_, caller)| caller)
}

/// Test hook: clear all implicit reply state.
#[cfg(test)]
pub(crate) fn reset_reply_for_test() {
    *REPLY.lock() = ReplyState {
        who: [const { None }; 64],
    };
}

/// Resolve outgoing descriptors against the sender's table (ADR-011 §1).
/// Returns the envelope with pending installs, or the count of failed
/// descriptors (those become FLAG_CAP_PARTIAL and null words on delivery).
/// Test hook for ADR-044 emulator tests: resolve a reply's transfers.
#[cfg(test)]
pub(crate) fn resolve_transfers_for_test(
    pid: ProcessId,
    msg: &Message,
    sender: ThreadId,
) -> (Envelope, usize) {
    resolve_transfers(pid, msg, sender)
}

fn resolve_transfers(pid: ProcessId, msg: &Message, sender: ThreadId) -> (Envelope, usize) {
    let mut env = Envelope::new(*msg, sender);
    let mut failed = 0usize;
    for i in 0..msg.cap_count() {
        let Some(cs) = msg.descriptor(i) else {
            continue;
        };
        let handle = cs.handle();
        if handle == 0 || handle == REPLY_CAP_SENTINEL || handle == ipc::FIRST_FREE_SLOT {
            failed += 1;
            continue;
        }
        match proc::get_cap(pid, handle) {
            Ok(cap) => {
                // ADR-026: dead objects never transfer (NULL + CAP_PARTIAL).
                if cap.rights.contains(Rights::GRANT) && crate::objreg::is_alive(cap.obj) {
                    env.caps[i] = Some(cap);
                } else {
                    failed += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }
    (env, failed)
}

/// Install pending caps into the receiver's table and rewrite descriptor
/// words to (receiver handle, granted rights).
pub(crate) fn install_transfers(pid: ProcessId, env: &mut Envelope) {
    let mut partial = false;
    for i in 0..env.msg.cap_count() {
        // A None slot means the sender-side descriptor already failed
        // (dead handle / missing GRANT / reserved value): per schema §3.1
        // the wire word must become NULL and FLAG_CAP_PARTIAL must be set —
        // the sender's raw handle value must NEVER reach the wire
        // (confused-deputy surface; found by DS's ABI audit).
        let Some(cap) = env.caps[i] else {
            let _ = env.msg.set_descriptor(i, CapSlot::NULL);
            partial = true;
            continue;
        };
        let requested = env
            .msg
            .descriptor(i)
            .map(|cs| cs.rights())
            .unwrap_or_default();
        let granted = cap.rights.intersect(requested);
        match proc::install_cap(
            pid,
            Capability {
                obj: cap.obj,
                typ: cap.typ,
                rights: granted,
            },
        ) {
            Ok(handle) => {
                let _ = env.msg.set_descriptor(i, CapSlot::pack(handle, granted));
            }
            Err(_) => {
                let _ = env.msg.set_descriptor(i, CapSlot::NULL);
                partial = true;
            }
        }
    }
    if partial {
        env.msg.tag = env
            .msg
            .tag
            .with_flags(env.msg.tag.flags() | flags::CAP_PARTIAL);
    }
}

/// SYS 0: `yield`.
pub fn sys_yield(tid: ThreadId) -> SysResult<()> {
    sched::yield_now(tid).map_err(|_| err(ipc::status::EBADCAP))
}

/// SYS 1: `send`. `dst_handle` dispatches on cap type; the REPLY_CAP
/// sentinel sends a standalone reply (ADR-009 §2).
pub fn sys_send(
    pid: ProcessId,
    tid: ThreadId,
    dst_handle: u32,
    msg: Message,
    nonblock: bool,
) -> SysResult<i32> {
    // Reply-only send. Descriptors must still resolve against the sender's
    // table (ADR-011 §1): the parked caller installs them on resume, so an
    // unresolved envelope would null every replied capability.
    if dst_handle == REPLY_CAP_SENTINEL {
        let (env, _) = resolve_transfers(pid, &msg, tid);
        return reply_only(tid, env);
    }
    let cap = proc::get_cap(pid, dst_handle).map_err(|e| err(map_proc(e)))?;
    match cap.typ {
        ObjType::Endpoint => {
            if !cap.rights.contains(Rights::SEND) {
                return Err(err(ipc::status::ERIGHTS));
            }
            // Debug endpoint fast path (ADR-018 §4): log, no delivery.
            // (The clobber-hunt WALK/SWEEP ops were removed with their root
            // cause: the enter_user asm clobber + frame::init stack
            // temporary, ADR-037 am2 + ebd4489.)
            if cap.obj.0 == crate::init::DEBUG_EP_ID {
                crate::init::debug_ep_send(&msg);
                return Ok(ipc::status::OK);
            }
            let (env, _) = resolve_transfers(pid, &msg, tid);
            match endpoint::try_send(ObjRef(cap.obj.0), env) {
                Ok(()) => Ok(ipc::status::OK),
                Err(IpcError::EndpointFull) => {
                    if nonblock {
                        Err(err(ipc::status::EWOULDBLOCK))
                    } else {
                        endpoint::park_send(ObjRef(cap.obj.0), tid, env)
                            .map_err(|e| err(map_ipc(e)))?;
                        Ok(ipc::status::OK)
                    }
                }
                Err(e) => Err(err(map_ipc(e))),
            }
        }
        ObjType::Notification => {
            if !cap.rights.contains(Rights::SIGNAL) {
                return Err(err(ipc::status::ERIGHTS));
            }
            notification::signal(ObjRef(cap.obj.0), msg.words[0])
                .map(|_| ipc::status::OK)
                .map_err(|e| err(map_ipc(e)))
        }
        _ => Err(err(ipc::status::EBADARG)),
    }
}

/// Test hook: deliver a reply envelope as if the server answered (ADR-044
/// foreign-route tests).
#[cfg(test)]
pub(crate) fn reply_only_for_test(tid: ThreadId, env: Envelope) -> SysResult<i32> {
    reply_only(tid, env)
}

fn reply_only(tid: ThreadId, env: Envelope) -> SysResult<i32> {
    match take_reply(tid) {
        Some(caller) => {
            // Deliver the reply to the blocked caller (must be Blocked(Reply)).
            let mut d = crate::endpoint::DELIVERED_FOR_REPLY.lock();
            d.insert(caller, env);
            drop(d);
            sched::make_ready(caller).map_err(|_| err(ipc::status::EDEAD))?;
            Ok(ipc::status::OK)
        }
        None => Err(err(ipc::status::EBADSTATE)),
    }
}

/// SYS 2: `call` — send, then block the caller awaiting the reply.
pub fn sys_call(pid: ProcessId, tid: ThreadId, dst_handle: u32, msg: Message) -> SysResult<i32> {
    let cap = proc::get_cap(pid, dst_handle).map_err(|e| err(map_proc(e)))?;
    if cap.typ != ObjType::Endpoint || !cap.rights.contains(Rights::SEND) {
        return Err(err(ipc::status::EBADARG));
    }
    let (mut env, _) = resolve_transfers(pid, &msg, tid);
    env.reply_requested = true;
    // A full mailbox must NOT sender-park a call: the rotation that moves a
    // parked sender's message into the mailbox wakes it *before its request
    // is served*, and the caller then resumes without its reply (the later
    // real reply finds it awake -> EDEAD at the server). Report EWOULDBLOCK
    // instead; the SDK's `call` retries with a yield (the server's loop is
    // draining concurrently).
    match endpoint::try_send(ObjRef(cap.obj.0), env) {
        Ok(()) => {}
        Err(IpcError::EndpointFull) => return Err(err(ipc::status::EWOULDBLOCK)),
        Err(e) => return Err(err(map_ipc(e))),
    }
    // Park awaiting reply.
    sched::block(tid, BlockReason::Reply).map_err(|_| err(ipc::status::ENOMEM))?;
    Ok(ipc::status::OK)
}

/// Parked-recv records: tid → (src handle, pid), so `park_result` can
/// complete the recv into the right table on resume (ADR-019 §1).
struct Parks {
    who: [Option<(ThreadId, u32, ProcessId)>; 64],
}

static PARKS: Mutex<Parks> = Mutex::new(Parks {
    who: [const { None }; 64],
});

fn record_park(tid: ThreadId, src_handle: u32, pid: ProcessId) {
    let mut p = PARKS.lock();
    for slot in p.who.iter_mut() {
        if slot.is_none() {
            *slot = Some((tid, src_handle, pid));
            return;
        }
    }
}

/// Park-record cleanup for the arch resume path (entry::park_result ADR-041
/// expiry step); also clears a raced timeout flag.
pub(crate) fn clear_park_entry(tid: ThreadId) {
    clear_park(tid);
}

fn clear_park(tid: ThreadId) {
    // A normal completion also clears a (raced, unused) timeout flag from
    // ADR-041 expiry — and a raced ADR-076 dead-call flag — so neither can
    // leak into this thread's next park.
    sched::clear_timed_out(tid);
    sched::clear_call_dead(tid);
    let mut p = PARKS.lock();
    for slot in p.who.iter_mut() {
        if let Some((t, _, _)) = slot {
            if *t == tid {
                *slot = None;
                return;
            }
        }
    }
}

/// Resume contract for a parked thread (ADR-019 §1): called by the arch
/// entry when a parked thread is scheduled again.
/// Priority: `call` reply → bound notification (NOTIFIED + mask) → endpoint
/// delivery (completed recv).
pub fn park_result(tid: ThreadId) -> Option<crate::entry::SyscallReturn> {
    // ADR-044 dedup: the REAL resume-path implementation lives in
    // `entry::park_result` (the arch resume calls it — including the ADR-044
    // foreign restore, the ADR-038 blocked-notification check, and the
    // ADR-041 deadline step). This delegate exists for host tests that
    // exercise the resume contract without the arch entry.
    crate::entry::park_result(tid)
}

/// ADR-047: mint a one-shot Reply cap from the caller's implicit reply slot
/// (Thread::DEFER) and clear the slot. The cap's ObjId = the caller tid
/// (the deferred reply completes the parked `call` via the park contract —
/// no endpoint involved); Reply::SEND retires the cap.
pub fn defer_reply(pid: ProcessId, tid: ThreadId) -> SysResult<u32> {
    let caller = take_reply(tid).ok_or(err(ipc::status::EBADSTATE))?;
    let handle = proc::install_cap(
        pid,
        caps::Capability {
            obj: caps::ObjId(caller.0),
            typ: caps::ObjType::Reply,
            rights: caps::Rights::SEND,
        },
    )
    .map_err(|e| err(map_proc(e)))?;
    Ok(handle)
}

/// ADR-047: deliver a deferred reply to the parked caller (Reply::SEND).
/// The envelope lands in the caller's DELIVERED_FOR_REPLY slot (the park
/// contract completes the parked `call` on resume) and the caller wakes.
pub fn deferred_reply_send(_pid: ProcessId, caller: ThreadId, reply: Message) -> SysResult<()> {
    // The caller must still be parked on its deferred `call`.
    let parked = matches!(
        sched::get(caller).map(|t| t.state),
        Ok(sched::State::Blocked(sched::BlockReason::Reply))
    );
    if !parked {
        return Err(err(ipc::status::EBADSTATE));
    }
    let (env, _) = resolve_transfers(_pid, &reply, sched::current());
    crate::endpoint::DELIVERED_FOR_REPLY
        .lock()
        .insert(caller, env);
    sched::make_ready(caller).map_err(|_| err(ipc::status::EDEAD))?;
    Ok(())
}

/// ADR-047: is this thread's syscall a foreign trap? If so, save the raw
/// frame, deliver it to the emulator endpoint as a CALL (FAULT_PAGE-as-call
/// pattern), and return the parked return for the dispatcher. The num is
/// opaque (a foreign ABI number) — the emulator translates everything.
pub(crate) fn foreign_route(
    pid: ProcessId,
    tid: ThreadId,
    args: &crate::entry::SyscallArgs,
) -> Option<crate::entry::SyscallReturn> {
    let ep = sched::get(tid).ok()?.foreign_ep?;
    // Save the raw frame for the emulator's TRAP_READ while parked.
    sched::set_trap_frame(
        tid,
        [
            args.num, args.cap, args.tag.0, args.w[0], args.w[1], args.w[2], args.w[3],
        ],
    );
    // The emulator must hold a SEND cap on the route endpoint in the trapped
    // process's table (kernel-side scan — the fault-EP pattern).
    let handle = crate::fault::find_ep_cap_for(pid, ep);
    let Some(handle) = handle else {
        // No route cap: kill like an unroutable fault (ADR-007 §1).
        let _ = sys_exit(tid, -1);
        return Some(crate::entry::SyscallReturn {
            status: ipc::status::EDEAD as i64,
            tag: Tag(0),
            w: [0; 4],
            r10: 0,
        });
    };
    let mut m = Message::new(ipc::labels::kernel::FOREIGN_SYSCALL);
    m.words[0] = args.num;
    m.words[1] = args.cap;
    m.words[2] = args.w[3];
    // sys_call parks the thread Blocked(Reply); the emulator's reply becomes
    // the syscall's SyscallReturn via park_result (ADR-019 §1).
    match sys_call(pid, tid, handle, m) {
        Ok(_) => Some(crate::entry::SyscallReturn::parked()),
        Err(_) => {
            let _ = sys_exit(tid, -1);
            Some(crate::entry::SyscallReturn {
                status: ipc::status::EDEAD as i64,
                tag: Tag(0),
                w: [0; 4],
                r10: 0,
            })
        }
    }
}

/// SYS 3: `recv`. Returns (status, delivered message or none).
/// `woken_by_notification` is surfaced via FLAG_NOTIFIED + label 0.
pub fn sys_recv(
    pid: ProcessId,
    tid: ThreadId,
    src_handle: u32,
    nonblock: bool,
    deadline_ns: u64,
) -> SysResult<Option<Message>> {
    // Deadline already passed (ADR-041): report ETIMEDOUT without parking.
    if expired(deadline_ns) {
        return Err(err(ipc::status::ETIMEDOUT));
    }
    // A pending reply for a `call` takes priority (woken by reply_only).
    // See SYS 2: the implicit request reply slot survives nested call
    // replies; only a new request (endpoint delivery) rebinds it.
    {
        let mut d = crate::endpoint::DELIVERED_FOR_REPLY.lock();
        if let Some(env) = d.take(tid) {
            return Ok(Some(env.msg));
        }
    }
    let cap = proc::get_cap(pid, src_handle).map_err(|e| err(map_proc(e)))?;
    match cap.typ {
        ObjType::Endpoint => {
            if !cap.rights.contains(Rights::RECV) {
                return Err(err(ipc::status::ERIGHTS));
            }
            // Console input (v0 line discipline): pop one line from the
            // IRQ-fed buffer; empty → park on the console notification.
            if cap.obj.0 == crate::console_in::CONSOLE_IN_EP_ID {
                let mut buf = [0u8; 120];
                match crate::console_in::pop_line(&mut buf) {
                    Some(len) => {
                        let mut m = Message::new(ipc::labels::kernel::NOTIFY);
                        let len = len.min((ipc::MAX_WORDS - 1) * 8); // bytes live in words[1..]; cap to avoid OOB (was a >24-byte-line panic)
                        m.words[0] = len as u64;
                        let mut i = 0usize;
                        while i + 8 <= 120 && i < len {
                            let mut w = 0u64;
                            for k in 0..8 {
                                if i + k < len {
                                    w |= (buf[i + k] as u64) << (k * 8);
                                }
                            }
                            m.words[1 + i / 8] = w;
                            i += 8;
                        }
                        return Ok(Some(m));
                    }
                    None => {
                        // Nonblocking poll (the shell peeks for input before
                        // falling back to its compiled script): report empty
                        // rather than parking, matching the endpoint branch.
                        if nonblock {
                            return Err(err(ipc::status::EWOULDBLOCK));
                        }
                        sched::block_with_deadline(
                            tid,
                            BlockReason::Notification(ObjRef(crate::console_in::CONSOLE_NOTIFY_ID)),
                            deadline_ns,
                        )
                        .map_err(|_| err(ipc::status::ENOMEM))?;
                        // Woken (deferred signal at dispatch entry): pop the
                        // line that arrived while parked.
                        return match crate::console_in::pop_line(&mut buf) {
                            Some(len) => {
                                let mut m = Message::new(ipc::labels::kernel::NOTIFY);
                                let len = len.min((ipc::MAX_WORDS - 1) * 8); // bytes live in words[1..]; cap to avoid OOB (was a >24-byte-line panic)
                                m.words[0] = len as u64;
                                let mut i = 0usize;
                                while i + 8 <= 120 && i < len {
                                    let mut w = 0u64;
                                    for k in 0..8 {
                                        if i + k < len {
                                            w |= (buf[i + k] as u64) << (k * 8);
                                        }
                                    }
                                    m.words[1 + i / 8] = w;
                                    i += 8;
                                }
                                Ok(Some(m))
                            }
                            None => Ok(None), // spurious wake; caller re-parks
                        };
                    }
                }
            }
            match endpoint::recv(ObjRef(cap.obj.0), tid, nonblock, deadline_ns) {
                Ok(Some(mut env)) => {
                    // Set the implicit reply cap when the message came from a call.
                    set_reply_if_call(&env, tid);
                    install_transfers(pid, &mut env);
                    Ok(Some(env.msg))
                }
                Ok(None) => {
                    if nonblock {
                        // v0 polling recv (VFS accept loop): report empty.
                        return Err(err(ipc::status::EWOULDBLOCK));
                    }
                    // Parked inside endpoint::recv (with the ADR-041
                    // deadline); record for park_result (ADR-019 §1).
                    record_park(tid, src_handle, pid);
                    Ok(None)
                }
                Err(e) => Err(err(map_ipc(e))),
            }
        }
        ObjType::Notification => {
            if !cap.rights.contains(Rights::RECV) {
                return Err(err(ipc::status::ERIGHTS));
            }
            let mask = notification::take(ObjRef(cap.obj.0)).map_err(|e| err(map_ipc(e)))?;
            if mask == 0 {
                if nonblock {
                    // Polling recv on notifications (PS's nonblocking WAIT).
                    return Err(err(ipc::status::EWOULDBLOCK));
                }
                sched::block_with_deadline(
                    tid,
                    BlockReason::Notification(ObjRef(cap.obj.0)),
                    deadline_ns,
                )
                .map_err(|_| err(ipc::status::ENOMEM))?;
                // Re-check: a signal that landed between the take and the
                // block found no waiter to wake (its scan ran first) and the
                // thread would otherwise sleep through it.
                if let Ok(m2) = notification::pending(ObjRef(cap.obj.0)) {
                    if m2 != 0 {
                        let _ = sched::make_ready(tid);
                        let m3 =
                            notification::take(ObjRef(cap.obj.0)).map_err(|e| err(map_ipc(e)))?;
                        let mut m = Message::new(ipc::labels::kernel::NOTIFY);
                        m.words[0] = m3;
                        return Ok(Some(m));
                    }
                }
                return Ok(None);
            }
            let mut m = Message::new(ipc::labels::kernel::NOTIFY);
            m.words[0] = mask;
            Ok(Some(m))
        }
        _ => Err(err(ipc::status::EBADARG)),
    }
}

pub(crate) fn set_reply_if_call(env: &Envelope, server: ThreadId) {
    // Only a `call` (reply-requesting message) rebinds the receiver's
    // implicit reply slot. Plain sends — notably bootstrap-package
    // deliveries — must not: a stale slot misroutes the server's next reply
    // to the wrong process (observed: the VFS answered PS's CONNECT to the
    // launcher, which was awaiting its SPAWN reply).
    if env.reply_requested {
        set_reply(server, env.sender);
    }
}

/// SYS 4: `reply_recv` — reply through the implicit reply cap, then recv.
pub fn sys_reply_recv(
    pid: ProcessId,
    tid: ThreadId,
    src_handle: u32,
    reply: Message,
    deadline_ns: u64,
) -> SysResult<Option<Message>> {
    // Deadline already passed (ADR-041): the reply half still completes (it
    // unblocks the caller we owe an answer to); the recv half times out.
    // With no pending reply there is nothing to flush: report the recv
    // half's own outcome (ETIMEDOUT) — EBADSTATE is not a spec/abi
    // REPLY_RECV error (ADR-080).
    if expired(deadline_ns) {
        if let Some(caller) = take_reply(tid) {
            let (env, _) = resolve_transfers(pid, &reply, tid);
            crate::endpoint::DELIVERED_FOR_REPLY
                .lock()
                .insert(caller, env);
            sched::make_ready(caller).map_err(|_| err(ipc::status::EDEAD))?;
        }
        return Err(err(ipc::status::ETIMEDOUT));
    }
    // ADR-080: the reply half is conditional on a pending call. The implicit
    // reply slot holds a caller only after a `call` was delivered, so a
    // server's FIRST reply_recv has nothing to answer and must still run
    // its recv half (and park). The slot-empty EBADSTATE was not a
    // spec/abi REPLY_RECV error, and a server loop that ignored it
    // hot-spun forever — under the cooperative scheduler that starves the
    // rest of the system (observed: bench's reply_recv server wedged the
    // bench boot before its first call).
    if let Some(caller) = take_reply(tid) {
        // Same contract as `reply_only`: resolve descriptors before the
        // parked caller installs them on resume (ADR-011 §1).
        let (env, _) = resolve_transfers(pid, &reply, tid);
        crate::endpoint::DELIVERED_FOR_REPLY
            .lock()
            .insert(caller, env);
        sched::make_ready(caller).map_err(|_| err(ipc::status::EDEAD))?;
    }
    sys_recv(pid, tid, src_handle, false, deadline_ns)
}

/// ADR-041: is this deadline already in the past? (0 = no deadline.)
fn expired(deadline_ns: u64) -> bool {
    deadline_ns != 0 && crate::time::now_ns() >= deadline_ns
}

/// SYS 5: `invoke` — method dispatch on kernel object caps.
/// v0: Notification SIGNAL(1)/CLEAR(2), Region CARVE(1); else ENOSYS.
/// Returns `(status, words)` — methods that install capabilities hand the new
/// handle back in `w0` (syscall-abi §7; `Region::CARVE` does).
pub fn sys_invoke(
    pid: ProcessId,
    _tid: ThreadId,
    cap_handle: u32,
    msg: Message,
) -> SysResult<(i32, [u64; 4])> {
    let cap = proc::get_cap(pid, cap_handle).map_err(|e| {
        if pid.0 == 1 {
            crate::kinfo!(
                "invoke NOCAP pid=1 h={} label={:#x}",
                cap_handle,
                msg.tag.label()
            );
        }
        err(map_proc(e))
    })?;
    match cap.typ {
        ObjType::Notification => match msg.tag.label() {
            1 => {
                if !cap.rights.contains(Rights::SIGNAL) {
                    return Err(err(ipc::status::ERIGHTS));
                }
                notification::signal(ObjRef(cap.obj.0), msg.words[0])
                    .map(|_| (ipc::status::OK, [0; 4]))
                    .map_err(|e| err(map_ipc(e)))
            }
            2 => notification::clear(ObjRef(cap.obj.0), msg.words[0])
                .map(|_| (ipc::status::OK, [0; 4]))
                .map_err(|e| err(map_ipc(e))),
            _ => Err(err(ipc::status::ENOSYS)),
        },
        ObjType::Region => match msg.tag.label() {
            1 => crate::init::region_carve(pid, cap.obj, msg.words[0], msg.words[1])
                .map(|handle| (ipc::status::OK, [handle as u64, 0, 0, 0])),
            _ => Err(err(ipc::status::ENOSYS)),
        },
        _ => Err(err(ipc::status::ENOSYS)),
    }
}

/// SYS 6: `cap_mint`. Returns the installed handle (also as w0).
pub fn sys_cap_mint(
    pid: ProcessId,
    parent_handle: u32,
    dst_handle: u32,
    rights: ipc::Rights,
) -> SysResult<u32> {
    proc::mint(pid, parent_handle, rights, dst_handle).map_err(|e| err(map_proc(e)))
}

/// SYS 7: `cap_revoke`. mode 0 = DERIVED, 1 = DELETE.
pub fn sys_cap_revoke(pid: ProcessId, handle: u32, mode: u64) -> SysResult<usize> {
    proc::revoke(pid, handle, mode).map_err(|e| err(map_proc(e)))
}

/// SYS 8: `exit`. Fires the bound death notification (ADR-007 §6) and, when
/// the last thread of the process is gone, retires the process's kernel
/// objects and its capability table (ADR-026).
pub fn sys_exit(tid: ThreadId, status: i32) -> SysResult<bool> {
    crate::kinfo!("thread {} exited (status {})", tid.0, status);
    // A caller parked in `call` on this exiting thread can never be answered
    // (ADR-076): take the implicit reply slot and — if the caller is still
    // parked on the reply — complete its call with EDEAD instead of
    // discarding it (a dead callee must not wedge its client; observed as
    // the 9aa7935 boot hang: init parked in SPAWN forever after PS died).
    let parked_caller = take_reply(tid);
    clear_park(tid);
    let proc_ref = sched::get(tid)
        .map_err(|_| err(ipc::status::EBADCAP))?
        .process;
    let fired = sched::exit(tid, status).map_err(|_| err(ipc::status::EBADCAP))?;
    crate::kinfo!("exit: tid={} status={} fired={}", tid.0, status, fired);
    // ADR-031: the exiting thread's kernel stack goes to the graveyard
    // (cannot be freed while this exit runs on it); the idle path drains.
    sched::bury_thread_kstack_for_exit(tid);
    if let Some(caller) = parked_caller {
        // Only a caller still parked on the reply is completed with EDEAD;
        // one already resumed (reply raced in, timeout fired, it exited)
        // handles itself. The pair was consumed above, so reply_only can no
        // longer reach this caller — the two completions are exclusive.
        let parked = sched::get(caller)
            .map(|t| matches!(t.state, sched::State::Blocked(BlockReason::Reply)))
            .unwrap_or(false);
        if parked {
            crate::kinfo!(
                "DEADCALL: callee={} caller={} parked call completes EDEAD",
                tid.0,
                caller.0
            );
            sched::mark_call_dead(caller);
            let _ = sched::make_ready(caller);
        }
    }
    if fired {
        // Read the death notification from the (now Exited) record and signal.
        // Payload convention (v0, consumed by PS's `WAIT` reaper): bit 0 = the
        // death event, bits 32.. = the raw exit status. OR-ing semantics mean
        // a later signal cannot clear an earlier event; status 0 keeps bit 0.
        if let Some(n) = sched::get(tid).ok().and_then(|t| t.death_notification) {
            let payload = 1 | ((status as u32 as u64) << 32);
            let _ = notification::signal(n, payload);
        }
    }
    // ADR-026: last thread out retires the process.
    let pid = proc::from_ref(proc_ref);
    let process_dead = !sched::process_has_live_threads(proc_ref);
    if process_dead {
        for (typ, obj) in crate::objreg::retire_owner(pid) {
            if obj.0 == 0 {
                continue;
            }
            match typ {
                ObjType::Endpoint => {
                    let _ = endpoint::destroy_endpoint(ObjRef(obj.0));
                }
                ObjType::AddressSpace => {
                    crate::kinfo!("ASDESTROY: as={} retired for pid={}", obj.0, pid.0);
                    let _ = crate::aspace::destroy(obj);
                }
                _ => {}
            }
        }
        let _ = proc::destroy(pid);
    }
    // ADR-028: the last live user thread is gone → deterministic clean halt
    // (QEMU exit code 0) so harnesses observe a fixed success state.
    if sched::thread_count() == 0 && crate::panic::has_exit_hook() {
        crate::panic::clean_exit();
    }
    // ADR-078: the launcher process (pid 1, the boot orchestrator) dying
    // while other user threads are still live ends the boot — no component
    // can manage the system any more. Without this the kernel idles with the
    // parked servers until the harness timeout (observed at a9b9f63: init
    // exits a step fail_code after a server/attack failure while the
    // console/VFS/auth servers stay parked; QEMU hit its 90 s timeout and a
    // fast, diagnosable boot failure was classified "boot hung").
    if process_dead && pid.0 == 1 && sched::thread_count() > 0 && crate::panic::has_exit_hook() {
        crate::panic::launcher_shutdown(status, sched::thread_count());
    }
    Ok(fired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::{set_context_backend, State, SCHED};
    use crate::time;
    use caps::ObjId;

    struct MockCtx;
    impl crate::sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    fn setup() -> (ProcessId, ThreadId, ThreadId, u32) {
        *SCHED.lock() = None;
        *REPLY.lock() = ReplyState {
            who: [const { None }; 64],
        };
        *PARKS.lock() = Parks {
            who: [const { None }; 64],
        };
        proc::reset_for_test();
        crate::notification::reset_for_test();
        crate::endpoint::reset_engine_for_test();
        set_context_backend(&MockCtx);
        let _ = sched::init();
        let pid = proc::create().unwrap();
        let server = sched::spawn(ObjRef(1), 100).unwrap();
        let client = sched::spawn(ObjRef(1), 100).unwrap();
        // Server endpoint cap at first-free handle.
        let ep = endpoint::create_endpoint().unwrap();
        let h = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(ep.0),
                typ: ObjType::Endpoint,
                rights: Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
            },
        )
        .unwrap();
        (pid, server, client, h)
    }

    fn msg(label: u16, w0: u64) -> Message {
        let mut m = Message::new(label);
        m.words[0] = w0;
        m
    }

    #[test]
    fn call_reply_recv_roundtrip() {
        let (pid, server, client, ep_h) = setup();

        // Client calls.
        assert_eq!(sys_call(pid, client, ep_h, msg(0x0110, 42)), Ok(0));
        assert!(matches!(
            sched::get(client).unwrap().state,
            crate::sched::State::Blocked(BlockReason::Reply)
        ));

        // Server receives: gets the request + implicit reply cap.
        let req = sys_recv(pid, server, ep_h, false, 0).unwrap().unwrap();
        assert_eq!(req.words[0], 42);

        // Server replies + recvs again (fast path).
        let rep = sys_reply_recv(pid, server, ep_h, msg(0x0110, 77), 0);
        assert!(rep.is_ok());

        // Client was woken and reads its reply.
        assert_eq!(
            sched::get(client).unwrap().state,
            crate::sched::State::Ready
        );
        let reply = crate::endpoint::DELIVERED_FOR_REPLY
            .lock()
            .take(client)
            .unwrap();
        assert_eq!(reply.msg.words[0], 77);
        assert_eq!(take_reply(client), None, "client never had a reply cap");
    }

    #[test]
    fn reply_caps_resolve_and_install() {
        let (pid, server, client, ep_h) = setup();
        // Server owns a frame cap to hand back with the reply.
        let frame_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: ObjId(0xBEEF),
                typ: ObjType::Frame,
                rights: Rights::READ.union(Rights::GRANT),
            },
        )
        .unwrap();

        // Client calls; server replies carrying the frame cap.
        assert_eq!(sys_call(pid, client, ep_h, msg(0x0101, 1)), Ok(0));
        let _req = sys_recv(pid, server, ep_h, false, 0).unwrap().unwrap();
        let mut rep = msg(0x0101, 2);
        rep.tag = rep.tag.with_caps(1);
        rep.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
            .unwrap();
        assert!(sys_reply_recv(pid, server, ep_h, rep, 0).is_ok());

        // The parked caller's envelope must carry the resolved cap and
        // install it into the receiver's table on resume (regression: the
        // reply paths used to skip resolve_transfers, nulling every cap).
        let mut env = crate::endpoint::DELIVERED_FOR_REPLY
            .lock()
            .take(client)
            .unwrap();
        install_transfers(pid, &mut env);
        let cs = env.msg.descriptor(0).unwrap();
        assert_ne!(cs.handle(), frame_h, "receiver-local handle");
        let got = proc::get_cap(pid, cs.handle()).unwrap();
        assert_eq!(got.typ, ObjType::Frame);
        assert_eq!(got.obj, ObjId(0xBEEF));
    }

    #[test]
    fn reply_sentinel_and_ebadstate() {
        let (pid, server, _client, ep_h) = setup();
        // No implicit reply cap pending → EBADSTATE.
        assert_eq!(
            sys_send(pid, server, REPLY_CAP_SENTINEL, msg(1, 1), false),
            Err(ipc::status::EBADSTATE)
        );

        // Establish one via recv of a call, then reply via sentinel.
        assert_eq!(sys_call(pid, server, ep_h, msg(5, 5)), Ok(0));
        let _req = sys_recv(pid, server, ep_h, false, 0).unwrap().unwrap();
        assert_eq!(
            sys_send(pid, server, REPLY_CAP_SENTINEL, msg(5, 6), false),
            Ok(0)
        );
        // Consumed: second reply fails again.
        assert_eq!(
            sys_send(pid, server, REPLY_CAP_SENTINEL, msg(5, 7), false),
            Err(ipc::status::EBADSTATE)
        );
    }

    #[test]
    fn cap_transfer_on_delivery() {
        let (pid, server, client, ep_h) = setup();
        // Client also owns a frame cap to give away.
        let frame_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: ObjId(0xCAFE),
                typ: ObjType::Frame,
                rights: Rights::READ.union(Rights::WRITE).union(Rights::GRANT),
            },
        )
        .unwrap();

        // Client sends the frame cap (requesting READ only) to the server.
        let mut m = msg(0x0111, 1);
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ))
            .unwrap();
        assert_eq!(sys_send(pid, client, ep_h, m, false), Ok(0));

        // Server receives; descriptor rewritten to its own handle.
        let got = sys_recv(pid, server, ep_h, false, 0).unwrap().unwrap();
        let cs = got.descriptor(0).unwrap();
        assert_ne!(cs.handle(), frame_h, "receiver handle differs");
        assert_eq!(cs.rights(), Rights::READ, "granted = sender ∩ requested");
        // Server's table now holds the frame cap.
        assert_eq!(proc::get_cap(pid, cs.handle()).unwrap().obj, ObjId(0xCAFE));
    }

    #[test]
    fn notification_send_recv_and_invoke() {
        let (pid, server, _client, _ep) = setup();
        let n = notification::create().unwrap();
        let n_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(n.0),
                typ: ObjType::Notification,
                rights: Rights::SIGNAL.union(Rights::RECV),
            },
        )
        .unwrap();

        // invoke SIGNAL.
        let mut m = msg(1, 0b1010);
        assert_eq!(sys_invoke(pid, server, n_h, m), Ok((0, [0; 4])));

        // recv-on-notification returns and clears the mask.
        let got = sys_recv(pid, server, n_h, false, 0).unwrap().unwrap();
        assert_eq!(got.tag.label(), ipc::labels::kernel::NOTIFY);
        assert_eq!(got.words[0], 0b1010);

        // Empty → parks the thread.
        assert_eq!(sys_recv(pid, server, n_h, false, 0), Ok(None));
        assert!(matches!(
            sched::get(server).unwrap().state,
            crate::sched::State::Blocked(BlockReason::Notification(_))
        ));

        // Send on the notification cap wakes it.
        assert_eq!(sys_send(pid, server, n_h, msg(1, 1), false), Ok(0));
        assert_eq!(
            sched::get(server).unwrap().state,
            crate::sched::State::Ready
        );

        // invoke with unknown method id → ENOSYS.
        m = msg(9, 0);
        assert_eq!(sys_invoke(pid, server, n_h, m), Err(ipc::status::ENOSYS));
    }

    #[test]
    fn mint_and_revoke_syscalls() {
        let (pid, _s, _c, ep_h) = setup();
        // Mint narrower child.
        let child = sys_cap_mint(pid, ep_h, ipc::FIRST_FREE_SLOT, Rights::SEND).unwrap();
        assert_eq!(proc::get_cap(pid, child).unwrap().rights, Rights::SEND);
        // Revoke derived keeps parent; child gone.
        assert_eq!(sys_cap_revoke(pid, ep_h, 0).unwrap(), 1);
        assert!(proc::get_cap(pid, ep_h).is_ok());
        assert!(proc::get_cap(pid, child).is_err());
        // Over-broad mint fails with ERIGHTS.
        assert_eq!(
            sys_cap_mint(pid, ep_h, ipc::FIRST_FREE_SLOT, Rights::ALL),
            Err(ipc::status::ERIGHTS)
        );
    }

    #[test]
    fn exit_fires_death_and_clears_reply() {
        let (pid, server, client, ep_h) = setup();
        // Grant server a notification cap bound for death notification.
        let n = notification::create().unwrap();
        {
            let mut guard = SCHED.lock();
            let s = guard.as_mut().unwrap();
            s.slots.threads[server.0 as usize]
                .as_mut()
                .unwrap()
                .death_notification = Some(n);
        }
        // Client calls so the server holds a reply target.
        assert_eq!(sys_call(pid, client, ep_h, msg(1, 1)), Ok(0));
        let _ = sys_recv(pid, server, ep_h, false, 0).unwrap();
        // Server exits: notification pending, reply state cleared.
        assert_eq!(sys_exit(server, 0), Ok(true));
        assert_eq!(notification::pending(n), Ok(1));
        assert_eq!(take_reply(server), None);
    }

    #[test]
    fn dead_callee_completes_parked_call_with_edead() {
        // ADR-076 regression (the 9aa7935 boot hang): the callee of a parked
        // `call` exits mid-call — the parked caller must wake with EDEAD,
        // not stay Blocked(Reply) forever.
        let (pid, server, client, ep_h) = setup();
        // Client calls: the message queues and the caller parks in Reply.
        assert_eq!(sys_call(pid, client, ep_h, msg(1, 1)), Ok(0));
        // Server receives: the implicit reply slot records (server, client).
        let _ = sys_recv(pid, server, ep_h, false, 0).unwrap();
        assert!(matches!(
            sched::get(client).unwrap().state,
            State::Blocked(BlockReason::Reply)
        ));
        // The callee dies mid-call (PS's OOM abort, init parked in SPAWN).
        assert_eq!(sys_exit(server, 0), Ok(false));
        assert!(matches!(sched::get(client).unwrap().state, State::Ready));
        let r = crate::entry::park_result(client).expect("dead callee completes the call");
        assert_eq!(r.status, ipc::status::EDEAD as i64);
        // Consumed: the flag must not leak into the caller's next park.
        assert!(!sched::get(client).unwrap().call_dead);
    }

    #[test]
    fn reply_recv_without_pending_call_still_receives() {
        // ADR-080 regression: a server's FIRST reply_recv has no pending
        // call, so its reply half has nothing to answer — the recv half
        // must still run (and park on an empty mailbox). The old
        // slot-empty EBADSTATE was not a spec/abi REPLY_RECV error and
        // left ignore-the-result server loops hot-spinning forever.
        let (pid, server, _client, ep_h) = setup();
        // Empty mailbox: the recv half parks instead of failing.
        let reply = msg(0x0999, 0);
        assert_eq!(
            sys_reply_recv(pid, server, ep_h, reply, 0),
            Ok(None),
            "no pending reply: recv half runs and parks"
        );
        assert!(matches!(
            sched::get(server).unwrap().state,
            State::Blocked(BlockReason::Recv(_))
        ));
        assert_eq!(take_reply(server), None, "no reply slot was consumed");
        // Queued message: the recv half returns it immediately.
        let (pid2, server2, client2, ep_h2) = setup();
        assert_eq!(sys_send(pid2, client2, ep_h2, msg(0x0110, 7), false), Ok(0));
        let got = sys_reply_recv(pid2, server2, ep_h2, msg(0x0999, 0), 0)
            .expect("no pending reply: recv half completes")
            .expect("queued message delivered");
        assert_eq!(got.words[0], 7);
    }

    #[test]
    fn reply_recv_expired_without_pending_reply_times_out() {
        // ADR-080: an expired deadline with nothing to reply still reports
        // the recv half's own outcome (ETIMEDOUT), not the undocumented
        // slot-empty EBADSTATE. A pending reply is still flushed first.
        let (pid, server, _client, ep_h) = setup();
        time::set_clock(|| 5_000);
        assert_eq!(
            sys_reply_recv(pid, server, ep_h, msg(0x0999, 0), 1),
            Err(ipc::status::ETIMEDOUT)
        );
        // With a pending reply, the expired path still completes it.
        let (pid2, server2, client2, ep_h2) = setup();
        assert_eq!(sys_call(pid2, client2, ep_h2, msg(1, 1)), Ok(0));
        let _ = sys_recv(pid2, server2, ep_h2, false, 0).unwrap();
        assert_eq!(
            sys_reply_recv(pid2, server2, ep_h2, msg(0x0999, 0), 1),
            Err(ipc::status::ETIMEDOUT)
        );
        assert!(matches!(sched::get(client2).unwrap().state, State::Ready));
    }

    #[test]
    fn exit_after_reply_leaves_caller_done() {
        // A reply that raced in first owns the completion: a later exit must
        // not mark the caller's (already finished) call dead.
        let (pid, server, client, ep_h) = setup();
        assert_eq!(sys_call(pid, client, ep_h, msg(1, 1)), Ok(0));
        let _ = sys_recv(pid, server, ep_h, false, 0).unwrap();
        let env = Envelope::new(msg(2, 0), server);
        assert_eq!(reply_only_for_test(server, env), Ok(ipc::status::OK));
        assert!(matches!(sched::get(client).unwrap().state, State::Ready));
        // The reply consumed the pair — exit has nothing to wake.
        assert_eq!(sys_exit(server, 0), Ok(false));
        assert!(!sched::get(client).unwrap().call_dead);
    }
    #[test]
    fn failed_sender_descriptor_nulls_wire_word() {
        // DS ABI audit: a failed sender-side descriptor must become NULL +
        // FLAG_CAP_PARTIAL — the sender's raw handle must never reach the
        // wire (confused-deputy surface).
        let (pid, _server, client, ep_h) = setup();
        // Client references a handle that doesn't exist in its table.
        let mut m = msg(0x0111, 1);
        m.tag = m.tag.with_caps(2);
        // desc 0: bad handle (unmapped)
        m.set_descriptor(0, ipc::CapSlot::pack(999, ipc::Rights::READ))
            .unwrap();
        // desc 1: valid frame cap
        let frame_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(0xCAFE),
                typ: ObjType::Frame,
                rights: ipc::Rights::READ.union(ipc::Rights::GRANT),
            },
        )
        .unwrap();
        m.set_descriptor(1, ipc::CapSlot::pack(frame_h, ipc::Rights::READ))
            .unwrap();
        assert_eq!(sys_send(pid, client, ep_h, m, false), Ok(0));

        let got = sys_recv(pid, _server, ep_h, false, 0).unwrap().unwrap();
        assert!(
            got.tag.flags() & ipc::flags::CAP_PARTIAL != 0,
            "partial flag set"
        );
        assert_eq!(got.descriptor(0).unwrap().0, 0, "failed descriptor is NULL");
        assert_ne!(
            got.descriptor(1).unwrap().0,
            0,
            "valid descriptor transferred"
        );
        // The NULL word must NOT contain the sender's raw handle value (999).
        assert_ne!(got.words[2], 999);
    }

    #[test]
    fn park_result_completes_recv_and_notified_wake() {
        let (pid, server, _client, ep_h) = setup();

        // Server parks in recv (mailbox empty).
        assert_eq!(sys_recv(pid, server, ep_h, false, 0), Ok(None));
        assert!(matches!(
            sched::get(server).unwrap().state,
            crate::sched::State::Blocked(_)
        ));

        // Client sends: direct hand-off delivers the envelope; server wakes.
        assert_eq!(sys_send(pid, _client, ep_h, msg(0x0110, 5), false), Ok(0));
        assert_eq!(
            sched::get(server).unwrap().state,
            crate::sched::State::Ready
        );

        // On resume, park_result completes the recv (message + caps).
        let r = park_result(server).expect("completed recv on resume");
        assert_eq!(r.status, ipc::status::OK as i64);
        assert_eq!(r.w[0], 5);

        // NOTIFIED wake: bind a notification, park in recv again.
        let n = notification::create().unwrap();
        {
            let mut guard = SCHED.lock();
            guard.as_mut().unwrap().slots.threads[server.0 as usize]
                .as_mut()
                .unwrap()
                .bound_notification = Some(n);
        }
        assert_eq!(sys_recv(pid, server, ep_h, false, 0), Ok(None));
        notification::signal(n, 0b110).unwrap();
        assert_eq!(
            sched::get(server).unwrap().state,
            crate::sched::State::Ready
        );
        let r = park_result(server).expect("notified resume");
        assert_eq!(r.status, ipc::status::OK as i64);
        assert_eq!(r.tag.label(), ipc::labels::kernel::NOTIFY);
        assert!(r.tag.flags() & ipc::flags::NOTIFIED != 0);
        assert_eq!(r.w[0], 0b110, "mask consumed");
    }

    #[test]
    fn thread_invoke_kill_priority_and_death_binding() {
        let (pid, _server, client, _ep) = setup();
        // Server gets a Thread cap over client (CONTROL).
        let tc = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(client.0),
                typ: ObjType::Thread,
                rights: ipc::Rights::CONTROL,
            },
        )
        .unwrap();

        // SET_PRIORITY (id 5).
        let m = msg(5, 200);
        let r = crate::entry::thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, 0);
        assert_eq!(sched::get(client).unwrap().priority, 200);

        // BIND_DEATH_NOTIFICATION (id 12): caps[0] = notification.
        let n = notification::create().unwrap();
        let n_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: caps::ObjId(n.0),
                typ: ObjType::Notification,
                rights: ipc::Rights::RECV,
            },
        )
        .unwrap();
        let mut m = msg(12, 0);
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, ipc::CapSlot::pack(n_h, ipc::Rights::RECV))
            .unwrap();
        let r = crate::entry::thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, 0);

        // KILL (id 2) → client exits, death notification fires.
        let m = msg(2, 0);
        let r = crate::entry::thread_invoke_for_test(pid, tc, m);
        assert_eq!(r.status, 0);
        assert!(matches!(
            sched::get(client).unwrap().state,
            crate::sched::State::Exited(-1)
        ));
        assert_eq!(
            notification::pending(n),
            Ok(1 | ((-1i32 as u32 as u64) << 32)),
            "death payload: bit 0 = event, bits 32.. = raw exit status"
        );
    }

    #[test]
    fn process_death_retires_objects_and_blocks_transfer() {
        // ADR-026 end-to-end: the last thread of a process exits → its
        // kernel objects retire → caps to them can no longer transfer.
        let (pid, server, _client, _ep) = setup();
        // Give the server its own process identity: spawn a dedicated child
        // process via Factory::NEW_THREAD semantics — simpler: register an
        // endpoint owned by a standalone process id and exit its only thread.
        let owner_pid = proc::create().unwrap();
        let owner_thread = sched::spawn(ObjRef(owner_pid.0), 100).unwrap();
        let ep = endpoint::create_endpoint().unwrap();
        crate::objreg::register(ObjId(ep.0), ObjType::Endpoint, owner_pid);
        assert!(crate::objreg::is_alive(ObjId(ep.0)));

        // Install a cap to it in the server's table (simulating a prior
        // transfer), then kill the owner.
        let ep_h = proc::install_cap(
            pid,
            caps::Capability {
                obj: ObjId(ep.0),
                typ: ObjType::Endpoint,
                rights: ipc::Rights::SEND.union(ipc::Rights::GRANT),
            },
        )
        .unwrap();
        assert_eq!(
            sys_exit(owner_thread, 0),
            Ok(false),
            "no death notification bound"
        );

        assert!(
            !crate::objreg::is_alive(ObjId(ep.0)),
            "endpoint retired with owner"
        );
        // The server still holds the handle, but transfer now fails: the
        // descriptor becomes NULL + CAP_PARTIAL.
        let mut m = msg(0x0111, 1);
        m.tag = m.tag.with_caps(1);
        m.set_descriptor(0, ipc::CapSlot::pack(ep_h, ipc::Rights::SEND))
            .unwrap();
        assert_eq!(sys_send(pid, server, _ep, m, false), Ok(0));
        let got = sys_recv(pid, server, _ep, false, 0).unwrap().unwrap();
        assert!(got.tag.flags() & ipc::flags::CAP_PARTIAL != 0);
        assert_eq!(got.descriptor(0).unwrap().0, 0, "dead cap -> NULL");
        // Old handles in OTHER processes surface EREVOKED at use (send on
        // the retired endpoint fails as dead).
        assert_eq!(
            sys_send(pid, server, ep_h, msg(1, 1), false),
            Err(ipc::status::EBADCAP),
            "dead endpoint cap refuses send"
        );
    }
    #[test]
    fn last_thread_exit_clean_halts() {
        use std::string::{String, ToString};
        // ADR-028: when the final user thread exits, the kernel clean-halts
        // via the registered code hook (QEMU exit code 0, ADR-013).
        let (_pid, _server, client, _ep) = setup();
        // Register a code hook that panics so the test can observe the call.
        crate::panic::set_exit_code(|code| {
            std::panic::panic_any(format_args!("CLEAN_EXIT_{}", code).to_string());
        });
        // Exit both threads of the only live process; the last one halts.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sys_exit(_server, 0);
            let _ = sys_exit(client, 0);
        }));
        match result {
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .unwrap_or_default();
                assert_eq!(msg, "CLEAN_EXIT_0", "clean halt must use code 0");
            }
            Ok(_) => panic!("expected clean halt"),
        }
    }

    /// ADR-078: the launcher process (pid 1) dying while other user threads
    /// are still live shuts the system down deterministically (code 0) — a
    /// failed boot must not idle with parked servers until the harness
    /// timeout. A launcher thread exiting while its process still has live
    /// threads must NOT halt (the ADR-026/ADR-028 paths are unchanged).
    #[test]
    fn launcher_exit_with_live_threads_shuts_down() {
        use std::string::{String, ToString};
        let (_pid, _server, _client, _ep) = setup();
        // A second process ("a server") whose thread stays live.
        let srv_pid = proc::create().unwrap();
        let _srv_thread = sched::spawn(ObjRef(srv_pid.0), 100).unwrap();
        crate::panic::set_exit_code(|code| {
            std::panic::panic_any(format_args!("LAUNCHER_SHUTDOWN_{}", code).to_string());
        });
        // Launcher thread exits, but the launcher process still has a live
        // thread: no retire, no halt.
        assert_eq!(sys_exit(_server, 0), Ok(false));
        // The launcher process's LAST thread exits while the server thread is
        // live: deterministic shutdown with code 0 (ADR-013).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = sys_exit(_client, 2097141);
        }));
        match result {
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .unwrap_or_default();
                assert_eq!(
                    msg, "LAUNCHER_SHUTDOWN_0",
                    "launcher shutdown must use code 0 (ADR-013)"
                );
            }
            Ok(_) => panic!("expected deterministic launcher shutdown"),
        }
    }

    /// ADR-078 negative: a non-launcher process's death never halts the
    /// system — only the launcher process (pid 1) ends the boot.
    #[test]
    fn non_launcher_process_death_does_not_halt() {
        let (_pid, _server, _client, _ep) = setup();
        let owner_pid = proc::create().unwrap(); // pid 2 — not the launcher
        let owner_thread = sched::spawn(ObjRef(owner_pid.0), 100).unwrap();
        // No hook registered: even a pid-1 exit must not panic here (the
        // ADR-078 path is inert without a hook, like ADR-028's).
        assert_eq!(sys_exit(_server, 0), Ok(false));
        assert_eq!(sys_exit(owner_thread, 0), Ok(false));
        assert_eq!(sched::thread_count(), 1, "the launcher client stays live");
    }

    /// ADR-041: park with a past deadline → ETIMEDOUT without parking.
    #[test]
    fn recv_expired_deadline_returns_timedout() {
        let (pid, server, _client, ep_h) = setup();
        time::set_clock(|| 5_000);
        // Deadline 1ns is long past.
        assert_eq!(
            sys_recv(pid, server, ep_h, false, 1),
            Err(ipc::status::ETIMEDOUT)
        );
        // Nothing parked, nothing queued.
        assert!(matches!(
            sched::get(server).unwrap().state,
            State::Ready | State::Running
        ));
    }

    /// ADR-041: expire_timeouts wakes an endpoint-parked thread past its
    /// deadline; unqueued so a later send finds no waiter; park_result
    /// reports ETIMEDOUT.
    #[test]
    fn expire_unqueues_endpoint_park_and_reports_timeout() {
        let (pid, server, _client, ep_h) = setup();
        time::set_clock(|| 0);
        assert_eq!(sys_recv(pid, server, ep_h, false, 1_000), Ok(None));
        assert!(matches!(
            sched::get(server).unwrap().state,
            State::Blocked(BlockReason::Recv(_))
        ));
        // Tick past the deadline (dispatch-entry path).
        assert_eq!(sched::expire_timeouts(2_000), 1);
        assert_eq!(sched::get(server).unwrap().state, State::Ready);
        // park_result (on resume) reports ETIMEDOUT and clears the flag.
        let r = park_result(server);
        assert!(
            matches!(r, Some(crate::entry::SyscallReturn { status, .. }) if status == ipc::status::ETIMEDOUT as i64)
        );
        // Flag consumed: no spurious second ETIMEDOUT.
        assert!(
            park_result(server).is_none() || {
                // Without a park record the second call returns None.
                true
            }
        );
        // A later sender finds no parked receiver (unqueued): mailbox.
        assert_eq!(
            endpoint::try_send(ObjRef(1), Envelope::new(msg(1, 1), _client)).map(|_| ()),
            Ok(())
        );
    }

    /// ADR-041: a message that raced the deadline wins (delivery priority).
    #[test]
    fn delivery_beats_expiry() {
        let (pid, server, client, ep_h) = setup();
        time::set_clock(|| 0);
        assert_eq!(sys_recv(pid, server, ep_h, false, 1_000), Ok(None));
        // Deliver before expiry (direct hand-off → Ready + delivered env).
        assert_eq!(sys_send(pid, client, ep_h, msg(0x0101, 7), false), Ok(0));
        assert_eq!(sched::get(server).unwrap().state, State::Ready);
        // Expiry only collects Blocked threads: the raced (delivered, Ready)
        // thread is skipped; its stale deadline is overwritten at next park.
        assert_eq!(sched::expire_timeouts(2_000), 0);
        // park_result: the delivered message is consumed first (priority);
        // clear_park clears the stale flag.
        let r = park_result(server).expect("delivery completes the recv");
        assert_eq!(r.status, 0);
        assert_eq!(r.w[0], 7);
        // Flag cleared: no spurious ETIMEDOUT on the next resume.
        assert!(park_result(server).is_none());
    }
}
