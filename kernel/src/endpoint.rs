//! Kernel endpoint engine: one-message mailbox + FIFO waiter queues
//! (syscall-abi §3.1, ADR-010 §4).
//!
//! Model:
//! - A waiting receiver parks; the next sender hands off directly (rendezvous).
//! - A lone undelivered message sits in the mailbox for a future receiver.
//! - When the mailbox is full, senders park **with their message queued**
//!   (FIFO); a receiver drains the mailbox, then rotates the head parked
//!   sender's message into the mailbox and wakes it.
//! - Cancel paths (`unqueue_waiter`) also wake the thread.
//!
//! Capability transfer on delivery and implicit reply caps are the next
//! slice; they ride the same queues once kernel cap-install is wired.
#![forbid(unsafe_code)]

use crate::sched::{self, BlockReason, ObjRef, SchedError, ThreadId};
use caps::Capability;
use ipc::Message;
use spin::Mutex;

/// A message in flight, with the capability installs resolved against the
/// sender's table at send time (ADR-011 §1). `caps[i]` corresponds to
/// descriptor `i`; on delivery the syscall layer installs into the
/// receiver's table and rewrites descriptor words.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Envelope {
    pub msg: Message,
    pub caps: [Option<Capability>; ipc::MAX_WORDS],
    pub sender: ThreadId,
}

impl Envelope {
    pub fn new(msg: Message, sender: ThreadId) -> Self {
        Envelope {
            msg,
            caps: [const { None }; ipc::MAX_WORDS],
            sender,
        }
    }
}

const MAX_ENDPOINTS: usize = 32;
/// Waiter capacity; bounded by scheduler capacity.
const MAX_WAITERS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpcError {
    NoSuchEndpoint,
    EndpointFull,
    NoMessage,
    NoWaiterSlot,
    Sched(SchedError),
}

impl From<SchedError> for IpcError {
    fn from(e: SchedError) -> Self {
        IpcError::Sched(e)
    }
}

struct SenderQueue {
    ids: [ThreadId; MAX_WAITERS],
    msgs: [Option<Envelope>; MAX_WAITERS],
    len: usize,
}

impl SenderQueue {
    const fn new() -> Self {
        SenderQueue {
            ids: [sched::IDLE; MAX_WAITERS],
            msgs: [const { None }; MAX_WAITERS],
            len: 0,
        }
    }

    fn push(&mut self, id: ThreadId, msg: Envelope) -> Result<(), IpcError> {
        if self.len >= MAX_WAITERS {
            return Err(IpcError::NoWaiterSlot);
        }
        self.ids[self.len] = id;
        self.msgs[self.len] = Some(msg);
        self.len += 1;
        Ok(())
    }

    /// Remove the head entry (rotates the rest).
    fn pop(&mut self) -> Option<Envelope> {
        if self.len == 0 {
            return None;
        }
        let _id = self.ids[0];
        let msg = self.msgs[0].take();
        self.ids.copy_within(1.., 0);
        self.msgs.copy_within(1.., 0);
        self.len -= 1;
        self.ids[self.len] = sched::IDLE;
        self.msgs[self.len] = None;
        Some(msg.unwrap())
    }

    fn remove(&mut self, id: ThreadId) -> Option<Envelope> {
        for i in 0..self.len {
            if self.ids[i] == id {
                let msg = self.msgs[i].take();
                self.ids.copy_within(i + 1.., i);
                self.msgs.copy_within(i + 1.., i);
                self.len -= 1;
                self.ids[self.len] = sched::IDLE;
                self.msgs[self.len] = None;
                return msg;
            }
        }
        None
    }
}

struct ReceiverQueue {
    ids: [ThreadId; MAX_WAITERS],
    len: usize,
}

impl ReceiverQueue {
    const fn new() -> Self {
        ReceiverQueue {
            ids: [sched::IDLE; MAX_WAITERS],
            len: 0,
        }
    }

    fn push(&mut self, id: ThreadId) -> Result<(), IpcError> {
        if self.len >= MAX_WAITERS {
            return Err(IpcError::NoWaiterSlot);
        }
        self.ids[self.len] = id;
        self.len += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<ThreadId> {
        if self.len == 0 {
            return None;
        }
        let id = self.ids[0];
        self.ids.copy_within(1.., 0);
        self.len -= 1;
        self.ids[self.len] = sched::IDLE;
        Some(id)
    }

    fn remove(&mut self, id: ThreadId) -> bool {
        for i in 0..self.len {
            if self.ids[i] == id {
                self.ids.copy_within(i + 1.., i);
                self.len -= 1;
                self.ids[self.len] = sched::IDLE;
                return true;
            }
        }
        false
    }
}

struct Endpoint {
    mailbox: Option<Envelope>,
    senders: SenderQueue,
    receivers: ReceiverQueue,
}

struct Engine {
    endpoints: [Option<Endpoint>; MAX_ENDPOINTS],
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

/// Create a kernel endpoint object; returns its ObjRef (0 is never returned).
pub fn create_endpoint() -> Result<ObjRef, IpcError> {
    let mut guard = ENGINE.lock();
    let e = guard.get_or_insert_with(|| Engine {
        endpoints: [const { None }; MAX_ENDPOINTS],
    });
    let slot = e
        .endpoints
        .iter()
        .position(|ep| ep.is_none())
        .ok_or(IpcError::NoWaiterSlot)?;
    e.endpoints[slot] = Some(Endpoint {
        mailbox: None,
        senders: SenderQueue::new(),
        receivers: ReceiverQueue::new(),
    });
    Ok(ObjRef(slot as u64 + 1))
}

/// Destroy an endpoint (owner dropped its last cap; kernel cleanup path).
pub fn destroy_endpoint(ep: ObjRef) -> Result<(), IpcError> {
    let mut guard = ENGINE.lock();
    let e = guard.as_mut().ok_or(IpcError::NoSuchEndpoint)?;
    let slot = (ep.0 as usize)
        .checked_sub(1)
        .ok_or(IpcError::NoSuchEndpoint)?;
    if slot >= MAX_ENDPOINTS || e.endpoints[slot].is_none() {
        return Err(IpcError::NoSuchEndpoint);
    }
    e.endpoints[slot] = None;
    Ok(())
}

fn with_ep<T>(
    ep: ObjRef,
    f: impl FnOnce(&mut Endpoint) -> Result<T, IpcError>,
) -> Result<T, IpcError> {
    let mut guard = ENGINE.lock();
    let e = guard.as_mut().ok_or(IpcError::NoSuchEndpoint)?;
    let slot = (ep.0 as usize)
        .checked_sub(1)
        .ok_or(IpcError::NoSuchEndpoint)?;
    match e.endpoints[slot].as_mut() {
        Some(ep_state) => f(ep_state),
        None => Err(IpcError::NoSuchEndpoint),
    }
}

/// Per-thread rendezvous slot for direct hand-off to a parked receiver.
pub(crate) struct Delivered {
    who: [ThreadId; MAX_WAITERS],
    msg: [Option<Envelope>; MAX_WAITERS],
}

pub(crate) static DELIVERED_FOR_REPLY: Mutex<Delivered> = Mutex::new(Delivered {
    who: [sched::IDLE; MAX_WAITERS],
    msg: [const { None }; MAX_WAITERS],
});

impl Delivered {
    pub(crate) fn insert(&mut self, id: ThreadId, msg: Envelope) {
        for i in 0..MAX_WAITERS {
            if self.who[i] == id || self.who[i] == sched::IDLE {
                self.who[i] = id;
                self.msg[i] = Some(msg);
                return;
            }
        }
    }

    pub(crate) fn take(&mut self, id: ThreadId) -> Option<Envelope> {
        for i in 0..MAX_WAITERS {
            if self.who[i] == id {
                let m = self.msg[i].take();
                self.who[i] = sched::IDLE;
                return m;
            }
        }
        None
    }
}

/// Read the envelope handed off to `id` by a sender rendezvous.
pub fn take_delivered(id: ThreadId) -> Option<Envelope> {
    DELIVERED_FOR_REPLY.lock().take(id)
}

/// Bench hook: clear the engine table (criterion benches run on host).
pub fn reset_for_bench() {
    *ENGINE.lock() = None;
}

/// Test hook: clear the engine + rendezvous table.
#[cfg(test)]
pub(crate) fn reset_engine_for_test() {
    *ENGINE.lock() = None;
    *DELIVERED_FOR_REPLY.lock() = Delivered {
        who: [sched::IDLE; MAX_WAITERS],
        msg: [const { None }; MAX_WAITERS],
    };
}

/// Non-blocking send. Fast path: direct hand-off to a parked receiver.
/// Otherwise fills the mailbox, or reports full (caller blocks or returns
/// EWOULDBLOCK per FLAG_NONBLOCK).
pub fn try_send(ep: ObjRef, env: Envelope) -> Result<(), IpcError> {
    with_ep(ep, |e| {
        // Waiting receiver? Direct hand-off.
        if let Some(waiter) = e.receivers.pop() {
            DELIVERED_FOR_REPLY.lock().insert(waiter, env);
            sched::make_ready(waiter)?;
            return Ok(());
        }
        if e.mailbox.is_some() {
            return Err(IpcError::EndpointFull);
        }
        e.mailbox = Some(env);
        Ok(())
    })
}

/// Non-blocking receive: takes the mailbox message if present.
pub fn try_recv(ep: ObjRef) -> Result<Option<Envelope>, IpcError> {
    with_ep(ep, |e| Ok(e.mailbox.take()))
}

/// Full blocking receive (syscall `recv`):
/// 1. mailbox message → deliver it, rotate head parked sender's message into
///    the mailbox, wake that sender;
/// 2. parked sender with message → direct hand-off (rendezvous), wake sender;
/// 3. nothing → park the receiver.
///
/// Returns `Ok(None)` when the receiver parked (message arrives later via
/// `take_delivered`).
pub fn recv(ep: ObjRef, receiver: ThreadId) -> Result<Option<Envelope>, IpcError> {
    with_ep(ep, |e| {
        if let Some(m) = e.mailbox.take() {
            // Rotate the next parked sender's envelope into the mailbox.
            if let Some(env2) = e.senders.pop() {
                sched::make_ready(env2.sender)?;
                e.mailbox = Some(env2);
            }
            return Ok(Some(m));
        }
        if let Some(env2) = e.senders.pop() {
            DELIVERED_FOR_REPLY.lock().insert(receiver, env2);
            sched::make_ready(env2.sender)?;
            // Receiver reads via take_delivered once scheduled.
            return Ok(None);
        }
        e.receivers.push(receiver)?;
        sched::block(receiver, BlockReason::Recv(ep))?;
        Ok(None)
    })
}

/// Full blocking send (syscall `send` without FLAG_NONBLOCK). Assumes
/// `try_send` returned EndpointFull: queue (id, msg) and park the sender.
pub fn park_send(ep: ObjRef, id: ThreadId, env: Envelope) -> Result<(), IpcError> {
    with_ep(ep, |e| {
        e.senders.push(id, env)?;
        sched::block(id, BlockReason::Send(ep))?;
        Ok(())
    })
}

/// Park a receiver when `recv` found nothing (kept for symmetry/tests).
pub fn park_recv(ep: ObjRef, id: ThreadId) -> Result<(), IpcError> {
    with_ep(ep, |e| {
        e.receivers.push(id)?;
        sched::block(id, BlockReason::Recv(ep))?;
        Ok(())
    })
}

/// Cancel a parked thread (timeout/cancel path) and wake it. Returns true if
/// it was parked here.
pub fn unqueue_waiter(ep: ObjRef, id: ThreadId) -> Result<bool, IpcError> {
    with_ep(ep, |e| {
        if e.receivers.remove(id) {
            sched::make_ready(id)?;
            return Ok(true);
        }
        if e.senders.remove(id).is_some() {
            sched::make_ready(id)?;
            return Ok(true);
        }
        Ok(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCtx;
    impl sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    fn setup() -> (ObjRef, ThreadId, ThreadId) {
        *ENGINE.lock() = None;
        *sched::SCHED.lock() = None;
        sched::set_context_backend(&MockCtx);
        let _ = sched::init();
        let ep = create_endpoint().unwrap();
        let a = sched::spawn(ObjRef(1), 100).unwrap();
        let b = sched::spawn(ObjRef(1), 100).unwrap();
        (ep, a, b)
    }

    fn env(label: u16, w0: u64, sender: ThreadId) -> Envelope {
        let mut m = Message::new(label);
        m.words[0] = w0;
        Envelope::new(m, sender)
    }

    #[test]
    fn direct_handoff_wakes_receiver() {
        let (ep, a, b) = setup();
        // b parks as receiver (blocks).
        assert_eq!(recv(ep, b), Ok(None));
        assert!(matches!(
            sched::get(b).unwrap().state,
            crate::sched::State::Blocked(_)
        ));
        // a sends: direct hand-off, b becomes Ready, mailbox stays empty.
        try_send(ep, env(0x0212, 7, a)).unwrap();
        assert_eq!(sched::get(b).unwrap().state, crate::sched::State::Ready);
        assert_eq!(take_delivered(b).unwrap().msg.words[0], 7);
        assert!(try_recv(ep).unwrap().is_none(), "hand-off bypasses mailbox");
    }

    #[test]
    fn mailbox_and_parked_senders_rotate() {
        let (ep, a, b) = setup();
        // a fills the mailbox, then parks with a second message queued.
        try_send(ep, env(1, 100, a)).unwrap();
        assert_eq!(try_send(ep, env(2, 200, a)), Err(IpcError::EndpointFull));
        park_send(ep, a, env(2, 200, a)).unwrap();
        assert!(matches!(
            sched::get(a).unwrap().state,
            crate::sched::State::Blocked(_)
        ));

        // b drains the mailbox: gets msg 1, a wakes, msg 2 rotates into the
        // mailbox.
        assert_eq!(recv(ep, b).unwrap().unwrap().msg.words[0], 100);
        assert_eq!(sched::get(a).unwrap().state, crate::sched::State::Ready);
        assert_eq!(try_recv(ep).unwrap().unwrap().msg.words[0], 200);

        // Direct hand-off path from parked sender: a parks again, b receives
        // via rendezvous.
        park_send(ep, a, env(3, 300, a)).unwrap();
        assert_eq!(recv(ep, b), Ok(None));
        assert_eq!(take_delivered(b).unwrap().msg.words[0], 300);
        assert!(try_recv(ep).unwrap().is_none());
    }

    #[test]
    fn unqueue_cancels_and_wakes() {
        let (ep, a, _b) = setup();
        assert_eq!(recv(ep, a), Ok(None));
        assert!(unqueue_waiter(ep, a).unwrap());
        assert_eq!(sched::get(a).unwrap().state, crate::sched::State::Ready);
        assert!(!unqueue_waiter(ep, a).unwrap());
        assert_eq!(destroy_endpoint(ep), Ok(()));
        assert_eq!(try_recv(ep), Err(IpcError::NoSuchEndpoint));
        assert_eq!(destroy_endpoint(ep), Err(IpcError::NoSuchEndpoint));
    }
}
