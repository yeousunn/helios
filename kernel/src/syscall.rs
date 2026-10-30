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
use ipc::{flags, CapSlot, Message};
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

fn clear_reply(callee: ThreadId) {
    if let Some(k) = reply_key(callee) {
        REPLY.lock().who[k] = None;
    }
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
                if cap.rights.contains(Rights::GRANT) {
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
fn install_transfers(pid: ProcessId, env: &mut Envelope) {
    let mut partial = false;
    for i in 0..env.msg.cap_count() {
        let Some(cap) = env.caps[i] else { continue };
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
    // Reply-only send.
    if dst_handle == REPLY_CAP_SENTINEL {
        return reply_only(tid, msg);
    }
    let cap = proc::get_cap(pid, dst_handle).map_err(|e| err(map_proc(e)))?;
    match cap.typ {
        ObjType::Endpoint => {
            if !cap.rights.contains(Rights::SEND) {
                return Err(err(ipc::status::ERIGHTS));
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

fn reply_only(tid: ThreadId, msg: Message) -> SysResult<i32> {
    match take_reply(tid) {
        Some(caller) => {
            // Deliver the reply to the blocked caller (must be Blocked(Reply)).
            let mut d = crate::endpoint::DELIVERED_FOR_REPLY.lock();
            d.insert(caller, Envelope::new(msg, tid));
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
    let (env, _) = resolve_transfers(pid, &msg, tid);
    // Send (nonblocking park path is the same for call).
    match endpoint::try_send(ObjRef(cap.obj.0), env) {
        Ok(()) => {}
        Err(IpcError::EndpointFull) => {
            endpoint::park_send(ObjRef(cap.obj.0), tid, env).map_err(|e| err(map_ipc(e)))?;
        }
        Err(e) => return Err(err(map_ipc(e))),
    }
    // Park awaiting reply.
    sched::block(tid, BlockReason::Reply).map_err(|_| err(ipc::status::ENOMEM))?;
    Ok(ipc::status::OK)
}

/// SYS 3: `recv`. Returns (status, delivered message or none).
/// `woken_by_notification` is surfaced via FLAG_NOTIFIED + label 0.
pub fn sys_recv(pid: ProcessId, tid: ThreadId, src_handle: u32) -> SysResult<Option<Message>> {
    // A pending reply for a `call` takes priority (woken by reply_only).
    {
        let mut d = crate::endpoint::DELIVERED_FOR_REPLY.lock();
        if let Some(env) = d.take(tid) {
            clear_reply(tid);
            return Ok(Some(env.msg));
        }
    }
    let cap = proc::get_cap(pid, src_handle).map_err(|e| err(map_proc(e)))?;
    match cap.typ {
        ObjType::Endpoint => {
            if !cap.rights.contains(Rights::RECV) {
                return Err(err(ipc::status::ERIGHTS));
            }
            match endpoint::recv(ObjRef(cap.obj.0), tid) {
                Ok(Some(mut env)) => {
                    // Set the implicit reply cap when the message came from a call.
                    set_reply_if_call(&env, tid);
                    install_transfers(pid, &mut env);
                    Ok(Some(env.msg))
                }
                Ok(None) => {
                    // Parked; the reply arrives via DELIVERED_FOR_REPLY or a
                    // plain envelope via take_delivered.
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
                sched::block(tid, BlockReason::Notification(ObjRef(cap.obj.0)))
                    .map_err(|_| err(ipc::status::ENOMEM))?;
                return Ok(None);
            }
            let mut m = Message::new(ipc::labels::kernel::NOTIFY);
            m.words[0] = mask;
            Ok(Some(m))
        }
        _ => Err(err(ipc::status::EBADARG)),
    }
}

fn set_reply_if_call(env: &Envelope, server: ThreadId) {
    // v0 heuristic: every endpoint delivery grants the implicit reply cap
    // (matches `call`/`reply_recv` fast path; plain `send` receivers simply
    // have no pending caller when they reply → EBADSTATE, per syscall-abi §4).
    set_reply(server, env.sender);
}

/// SYS 4: `reply_recv` — reply through the implicit reply cap, then recv.
pub fn sys_reply_recv(
    pid: ProcessId,
    tid: ThreadId,
    src_handle: u32,
    reply: Message,
) -> SysResult<Option<Message>> {
    match take_reply(tid) {
        Some(caller) => {
            crate::endpoint::DELIVERED_FOR_REPLY
                .lock()
                .insert(caller, Envelope::new(reply, tid));
            sched::make_ready(caller).map_err(|_| err(ipc::status::EDEAD))?;
        }
        None => return Err(err(ipc::status::EBADSTATE)),
    }
    sys_recv(pid, tid, src_handle)
}

/// SYS 5: `invoke` — method dispatch on kernel object caps.
/// v0: Notification SIGNAL(1)/CLEAR(2); everything else ENOSYS.
pub fn sys_invoke(pid: ProcessId, _tid: ThreadId, cap_handle: u32, msg: Message) -> SysResult<i32> {
    let cap = proc::get_cap(pid, cap_handle).map_err(|e| err(map_proc(e)))?;
    match cap.typ {
        ObjType::Notification => match msg.tag.label() {
            1 => {
                if !cap.rights.contains(Rights::SIGNAL) {
                    return Err(err(ipc::status::ERIGHTS));
                }
                notification::signal(ObjRef(cap.obj.0), msg.words[0])
                    .map(|_| ipc::status::OK)
                    .map_err(|e| err(map_ipc(e)))
            }
            2 => notification::clear(ObjRef(cap.obj.0), msg.words[0])
                .map(|_| ipc::status::OK)
                .map_err(|e| err(map_ipc(e))),
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

/// SYS 8: `exit`. Fires the bound death notification (ADR-007 §6).
pub fn sys_exit(tid: ThreadId, status: i32) -> SysResult<bool> {
    // Clear any pending reply state so late replies are discarded.
    clear_reply(tid);
    let fired = sched::exit(tid, status).map_err(|_| err(ipc::status::EBADCAP))?;
    if fired {
        // Read the bound notification from the (now Exited) record and signal.
        if let Some(n) = sched::get(tid).ok().and_then(|t| t.bound_notification) {
            let _ = notification::signal(n, 1);
        }
    }
    Ok(fired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::{set_context_backend, SCHED};
    use caps::ObjId;

    struct MockCtx;
    impl crate::sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
    }

    fn setup() -> (ProcessId, ThreadId, ThreadId, u32) {
        *SCHED.lock() = None;
        *REPLY.lock() = ReplyState {
            who: [const { None }; 64],
        };
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
        let req = sys_recv(pid, server, ep_h).unwrap().unwrap();
        assert_eq!(req.words[0], 42);

        // Server replies + recvs again (fast path).
        let rep = sys_reply_recv(pid, server, ep_h, msg(0x0110, 77));
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
    fn reply_sentinel_and_ebadstate() {
        let (pid, server, _client, ep_h) = setup();
        // No implicit reply cap pending → EBADSTATE.
        assert_eq!(
            sys_send(pid, server, REPLY_CAP_SENTINEL, msg(1, 1), false),
            Err(ipc::status::EBADSTATE)
        );

        // Establish one via recv of a call, then reply via sentinel.
        assert_eq!(sys_call(pid, server, ep_h, msg(5, 5)), Ok(0));
        let _req = sys_recv(pid, server, ep_h).unwrap().unwrap();
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
        let got = sys_recv(pid, server, ep_h).unwrap().unwrap();
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
        assert_eq!(sys_invoke(pid, server, n_h, m), Ok(0));

        // recv-on-notification returns and clears the mask.
        let got = sys_recv(pid, server, n_h).unwrap().unwrap();
        assert_eq!(got.tag.label(), ipc::labels::kernel::NOTIFY);
        assert_eq!(got.words[0], 0b1010);

        // Empty → parks the thread.
        assert_eq!(sys_recv(pid, server, n_h), Ok(None));
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
                .bound_notification = Some(n);
        }
        // Client calls so the server holds a reply target.
        assert_eq!(sys_call(pid, client, ep_h, msg(1, 1)), Ok(0));
        let _ = sys_recv(pid, server, ep_h).unwrap();
        // Server exits: notification pending, reply state cleared.
        assert_eq!(sys_exit(server, 0), Ok(true));
        assert_eq!(notification::pending(n), Ok(1));
        assert_eq!(take_reply(server), None);
    }
}
