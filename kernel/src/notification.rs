//! Kernel notification objects: async signal words (syscall-abi §3, §7).
#![forbid(unsafe_code)]

use crate::sched::{self, ObjRef};
use spin::Mutex;

const MAX_NOTIFICATIONS: usize = 256;

struct Engine {
    /// Pending signal mask per notification (sticky until received/cleared).
    word: [u64; MAX_NOTIFICATIONS],
    used: [bool; MAX_NOTIFICATIONS],
}

static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

fn eng() -> spin::MutexGuard<'static, Option<Engine>> {
    ENGINE.lock()
}

/// Create a notification object; returns its ObjRef.
pub fn create() -> Result<ObjRef, crate::endpoint::IpcError> {
    let mut e = eng();
    let engine = e.get_or_insert_with(|| Engine {
        word: [0; MAX_NOTIFICATIONS],
        used: [false; MAX_NOTIFICATIONS],
    });
    let slot = engine
        .used
        .iter()
        .position(|u| !u)
        .ok_or(crate::endpoint::IpcError::NoWaiterSlot)?;
    engine.used[slot] = true;
    engine.word[slot] = 0;
    Ok(ObjRef(slot as u64 + 1))
}

fn slot_of(n: ObjRef) -> Option<usize> {
    let s = (n.0 as usize).checked_sub(1)?;
    if s < MAX_NOTIFICATIONS {
        Some(s)
    } else {
        None
    }
}

/// Atomically OR `mask` into the notification word (syscall `send` on a
/// Notification cap / `Notification::SIGNAL`). Never blocks.
pub fn signal(n: ObjRef, mask: u64) -> Result<(), crate::endpoint::IpcError> {
    let mut e = eng();
    let engine = e
        .as_mut()
        .ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    let slot = slot_of(n).ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    engine.word[slot] |= mask;
    // Threads blocked receiving on THIS notification: deliver the wake as a
    // durable NOTIFY envelope (park_result priority 1 consumes it,
    // state-independent) *and* requeue them. The envelope matters: the woken
    // thread's resume otherwise depends on re-reading the (already consumed)
    // pending word, a path that wedged PS's `WAIT` on the personality demo's
    // death notification.
    let mask_now = engine.word[slot];
    let direct = sched::blocked_matching(
        |r| matches!(r, crate::sched::BlockReason::Notification(o) if *o == n),
    );
    for tid in direct {
        if tid == sched::IDLE {
            break;
        }
        let mut msg = ipc::Message::new(ipc::labels::kernel::NOTIFY);
        msg.words[0] = mask_now;
        let mut env = crate::endpoint::Envelope::new(msg, sched::IDLE);
        env.reply_requested = false;
        crate::endpoint::DELIVERED_FOR_REPLY.lock().insert(tid, env);
        let _ = sched::make_ready(tid);
    }
    // The §3.1 "select" primitive (ADR-019 §2): threads blocked on ANY
    // endpoint with this notification bound are woken to re-check their own
    // wait — no envelope (they expect an endpoint message, not the mask).
    let bound = sched::blocked_matching(|r| {
        matches!(
            r,
            crate::sched::BlockReason::Recv(_)
                | crate::sched::BlockReason::Send(_)
                | crate::sched::BlockReason::Reply
        )
    });
    for tid in bound {
        if tid == sched::IDLE {
            break;
        }
        if let Ok(t) = sched::get(tid) {
            if t.bound_notification == Some(n) {
                let _ = sched::make_ready(tid);
            }
        }
    }
    Ok(())
}

/// Clear bits without receiving (`Notification::CLEAR`, race-free shutdown).
pub fn clear(n: ObjRef, mask: u64) -> Result<(), crate::endpoint::IpcError> {
    let mut e = eng();
    let engine = e
        .as_mut()
        .ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    let slot = slot_of(n).ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    engine.word[slot] &= !mask;
    Ok(())
}

/// Take the pending mask (recv-on-Notification): returns and clears it.
pub fn take(n: ObjRef) -> Result<u64, crate::endpoint::IpcError> {
    let mut e = eng();
    let engine = e
        .as_mut()
        .ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    let slot = slot_of(n).ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    let w = engine.word[slot];
    engine.word[slot] = 0;
    Ok(w)
}

/// Peek without clearing (thread wake policy checks).
pub fn pending(n: ObjRef) -> Result<u64, crate::endpoint::IpcError> {
    let e = eng();
    let engine = e
        .as_ref()
        .ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    let slot = slot_of(n).ok_or(crate::endpoint::IpcError::NoSuchEndpoint)?;
    Ok(engine.word[slot])
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_for_test() {
    *ENGINE.lock() = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::{set_context_backend, BlockReason, ThreadId, SCHED};

    struct MockCtx;
    impl sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    #[test]
    fn signal_take_clear_lifecycle() {
        *ENGINE.lock() = None;
        *SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = sched::init();
        let n = create().unwrap();
        assert_eq!(pending(n), Ok(0));
        signal(n, 0b101).unwrap();
        assert_eq!(pending(n), Ok(0b101));
        // OR semantics.
        signal(n, 0b010).unwrap();
        assert_eq!(pending(n), Ok(0b111));
        assert_eq!(take(n), Ok(0b111));
        assert_eq!(pending(n), Ok(0), "take clears");
        clear(n, 0b001).unwrap();
        signal(n, 0b011).unwrap();
        clear(n, 0b010).unwrap();
        assert_eq!(take(n), Ok(0b001));
    }

    #[test]
    fn signal_wakes_bound_blocked_thread() {
        *ENGINE.lock() = None;
        *SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = sched::init();
        let n = create().unwrap();
        let t = sched::spawn(ObjRef(1), 100).unwrap();
        let _ = sched::pick_next(); // t now Running
                                    // Bind + block on notification.
        {
            let mut guard = SCHED.lock();
            let s = guard.as_mut().unwrap();
            s.slots.threads[t.0 as usize]
                .as_mut()
                .unwrap()
                .bound_notification = Some(n);
        }
        sched::block(t, BlockReason::Notification(n)).unwrap();
        signal(n, 1).unwrap();
        assert_eq!(sched::get(t).unwrap().state, crate::sched::State::Ready);
    }
}
