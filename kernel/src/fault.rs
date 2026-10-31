//! Arch-independent page-fault entry (ADR-007): in-kernel pool resolution,
//! FAULT_PAGE-as-call routing to the fault endpoint, reply install.
//!
//! The arch trap handler (ADR-012) decodes (vaddr, access) and calls
//! [`handle_page_fault`]. All policy lives here — host-testable.
#![forbid(unsafe_code)]

use crate::aspace::{self, MapFlags, Vaddr};
use crate::frame::PhysAddr;
use crate::proc::{self, ProcessId};
use crate::sched::{self, BlockReason, ObjRef, ThreadId};
use crate::syscall;
use caps::{ObjId, ObjType, Rights};
#[allow(unused_imports)]
use ipc::CapSlot;
use ipc::{labels, Message};

/// Access kind bits (syscall-abi §9: bit0 R, bit1 W, bit2 X).
pub const ACCESS_READ: u32 = 1;
pub const ACCESS_WRITE: u32 = 1 << 1;
pub const ACCESS_EXEC: u32 = 1 << 2;

/// Fault kinds (syscall-abi §9).
pub const FAULT_NOT_PRESENT: u64 = 0;
pub const FAULT_WRITE_COW: u64 = 1;
pub const FAULT_PERM: u64 = 2;
pub const FAULT_POOL_EMPTY: u64 = 3;

/// Outcome of a fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultOutcome {
    /// Resolved in-kernel (pool) or by a pager reply — thread continues.
    Resolved,
    /// Routed to the fault endpoint; the thread is blocked on the reply.
    Routed,
    /// No fault endpoint (or dead resolver): thread killed.
    Killed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultError {
    NoSuchThread,
    BadVaddr,
}

/// Pending fault per blocked thread (reply correlation).
struct Pending {
    who: [Option<(ThreadId, u64)>; 64], // (tid, vaddr)
}

static PENDING: spin::Mutex<Pending> = spin::Mutex::new(Pending {
    who: [const { None }; 64],
});

fn set_pending(tid: ThreadId, vaddr: u64) {
    let mut p = PENDING.lock();
    for slot in p.who.iter_mut() {
        if slot.is_none() {
            *slot = Some((tid, vaddr));
            return;
        }
    }
}

fn take_pending(tid: ThreadId) -> Option<u64> {
    let mut p = PENDING.lock();
    for slot in p.who.iter_mut() {
        if let Some((t, v)) = slot {
            if *t == tid {
                let v = *v;
                *slot = None;
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    *PENDING.lock() = Pending {
        who: [const { None }; 64],
    };
}

/// Page-fault entry point (ADR-007 §1-4, §9). `pid`/`tid` identify the
/// faulting context (from the arch trap frame via CurrentContext).
pub fn handle_page_fault(
    pid: ProcessId,
    tid: ThreadId,
    vaddr: u64,
    access: u32,
) -> Result<FaultOutcome, FaultError> {
    if !vaddr.is_multiple_of(aspace::PAGE_SIZE as u64) {
        return Err(FaultError::BadVaddr);
    }
    let v = Vaddr(vaddr);
    let write = access & ACCESS_WRITE != 0;
    let as_id = proc::as_of(pid).unwrap_or(aspace::DEFAULT_AS);

    // 1. In-kernel resolution (ANON zero-fill, COW copy/promote, pool).
    match aspace::resolve_fault(as_id, v, write) {
        Ok(_) => Ok(FaultOutcome::Resolved),
        Err(aspace::VmmError::NoWritePerm) => route_to_pager(pid, tid, vaddr, access, FAULT_PERM),
        Err(aspace::VmmError::NotFound) | Err(aspace::VmmError::NoBackend) => {
            route_to_pager(pid, tid, vaddr, access, FAULT_NOT_PRESENT)
        }
        Err(aspace::VmmError::PoolEmpty) => {
            route_to_pager(pid, tid, vaddr, access, FAULT_POOL_EMPTY)
        }
        Err(aspace::VmmError::NoPool) => route_to_pager(pid, tid, vaddr, access, FAULT_WRITE_COW),
        Err(_) => Err(FaultError::BadVaddr),
    }
}

fn route_to_pager(
    pid: ProcessId,
    tid: ThreadId,
    vaddr: u64,
    access: u32,
    kind: u64,
) -> Result<FaultOutcome, FaultError> {
    // 2. No fault endpoint → kill the thread (ADR-007 §1).
    let Some(ep) = sched::get(tid).ok().and_then(|t| t.fault_ep) else {
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    };

    // 3. FAULT_PAGE as a call to the fault endpoint (ADR-007 §2).
    let cap_handle = match find_ep_cap(pid, ep) {
        Some(h) => h,
        None => {
            let _ = syscall::sys_exit(tid, -1);
            return Ok(FaultOutcome::Killed);
        }
    };
    let mut m = Message::new(labels::kernel::FAULT_PAGE);
    m.words[0] = kind;
    m.words[1] = vaddr;
    m.words[2] = access as u64;
    if syscall::sys_call(pid, tid, cap_handle, m).is_err() {
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    }
    // The call parked the thread Blocked(Reply); re-tag the reason so
    // wake-scan paths can distinguish fault waits if needed.
    set_pending(tid, vaddr);
    Ok(FaultOutcome::Routed)
}

fn find_ep_cap(pid: ProcessId, ep: ObjRef) -> Option<u32> {
    // Scan the process table for a SEND cap on this endpoint (kernel-side;
    // the fault EP is usually handle 2 from NEW_THREAD caps[1]).
    for handle in 1..=1024u32 {
        if let Ok(cap) = proc::get_cap(pid, handle) {
            if cap.typ == ObjType::Endpoint
                && cap.obj == ObjId(ep.0)
                && cap.rights.contains(Rights::SEND)
            {
                return Some(handle);
            }
        }
    }
    None
}

/// The pager's FAULT_RESOLVE reply (ADR-007 §2): w0 = echoed vaddr,
/// w1 = mapping flags, caps[0] = frame. The kernel installs the mapping
/// from the reply and wakes the faulting thread.
/// Non-OK resolution (status != OK) kills the faulting thread.
pub fn handle_resolve_reply(
    pid: ProcessId,
    pager_tid: ThreadId,
    status_ok: bool,
    reply: Message,
) -> Result<FaultOutcome, FaultError> {
    let _ = pid;
    let _ = pager_tid;
    // Find the thread blocked in Reply state whose pending fault matches.
    let blocked = sched::blocked_matching(|r| matches!(r, BlockReason::Reply));
    let mut target: Option<(ThreadId, u64)> = None;
    for t in blocked {
        if t == sched::IDLE {
            break;
        }
        if let Some(v) = take_pending(t) {
            target = Some((t, v));
            break;
        }
    }
    let Some((tid, pending_vaddr)) = target else {
        return Err(FaultError::NoSuchThread);
    };

    if !status_ok {
        // ADR-007 §3: non-OK reply → kill the faulting thread.
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    }

    let echoed = reply.words[0];
    if echoed != pending_vaddr {
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    }
    let flags_raw = reply.words[1] as u32;
    let mask = MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::EXEC);
    let flags = MapFlags(flags_raw & mask.0);

    // caps[0] = frame (delivered into the pager's table by envelope transfer;
    // the kernel reads the descriptor to learn the frame handle → cap → addr).
    let Some(cs) = reply.descriptor(0) else {
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    };
    let frame_addr = proc::get_cap(pid, cs.handle())
        .map(|c| c.obj.0)
        .unwrap_or(0);
    if frame_addr == 0 {
        let _ = syscall::sys_exit(tid, -1);
        return Ok(FaultOutcome::Killed);
    }

    match aspace::install_from_reply(
        proc::as_of(pid).unwrap_or(aspace::DEFAULT_AS),
        Vaddr(pending_vaddr),
        PhysAddr::new(frame_addr),
        flags,
    ) {
        Ok(_) => {
            sched::make_ready(tid).map_err(|_| FaultError::NoSuchThread)?;
            Ok(FaultOutcome::Resolved)
        }
        Err(_) => {
            let _ = syscall::sys_exit(tid, -1);
            Ok(FaultOutcome::Killed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint;
    use crate::notification;
    use crate::sched::{set_context_backend, SCHED};
    #[allow(unused_imports)]
    use caps::Capability;
    #[allow(unused_imports)]
    use ipc::CapSlot;

    struct MockCtx;
    impl crate::sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    fn setup() -> ProcessId {
        proc::reset_for_test();
        endpoint::reset_engine_for_test();
        notification::reset_for_test();
        syscall::reset_reply_for_test();
        reset_for_test();
        let _ = aspace::init_default();
        *SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = sched::init();
        proc::create().unwrap()
    }

    #[test]
    fn no_fault_ep_kills_thread() {
        let pid = setup();
        let t = sched::spawn(ObjRef(1), 100).unwrap();
        let _ = sched::pick_next();
        // Unmapped vaddr, no pool, no fault EP → Killed.
        assert_eq!(
            handle_page_fault(pid, t, 0x500_000, ACCESS_READ),
            Ok(FaultOutcome::Killed)
        );
        assert!(matches!(
            sched::get(t).unwrap().state,
            sched::State::Exited(-1)
        ));
    }

    #[test]
    fn fault_routes_to_pager_and_reply_resolves() {
        let pid = setup();
        let victim = sched::spawn(ObjRef(1), 100).unwrap();
        let pager = sched::spawn(ObjRef(1), 100).unwrap();

        // Pager owns the fault endpoint.
        let ep = endpoint::create_endpoint().unwrap();
        let _ep_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(ep.0),
                typ: ObjType::Endpoint,
                rights: Rights::SEND.union(Rights::RECV),
            },
        )
        .unwrap();
        {
            let mut guard = SCHED.lock();
            guard.as_mut().unwrap().slots.threads[victim.0 as usize]
                .as_mut()
                .unwrap()
                .fault_ep = Some(ep);
        }

        // Victim faults on an unmapped page → routed (blocked on reply).
        let vaddr = 0x700_000;
        assert_eq!(
            handle_page_fault(pid, victim, vaddr, ACCESS_WRITE),
            Ok(FaultOutcome::Routed)
        );
        assert!(matches!(
            sched::get(victim).unwrap().state,
            sched::State::Blocked(BlockReason::Reply)
        ));

        // Pager receives the FAULT_PAGE call.
        let req = endpoint::recv(ep, pager).unwrap().unwrap();
        assert_eq!(req.msg.tag.label(), labels::kernel::FAULT_PAGE);
        assert_eq!(req.msg.words[1], vaddr);

        // Pager "mints" a frame (fixed address; the reply-install path does
        // not touch the frame allocator) and replies FAULT_RESOLVE.
        let frame = PhysAddr::new(0x30_0000);
        let frame_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(frame.as_u64()),
                typ: ObjType::Frame,
                rights: Rights::READ.union(Rights::WRITE),
            },
        )
        .unwrap();
        let mut rep = Message::new(labels::kernel::FAULT_RESOLVE);
        rep.words[0] = vaddr;
        rep.words[1] = MapFlags::READ.union(MapFlags::WRITE).0 as u64;
        rep.tag = rep.tag.with_caps(1);
        rep.set_descriptor(0, CapSlot::pack(frame_h, Rights::READ.union(Rights::WRITE)))
            .unwrap();
        assert_eq!(
            handle_resolve_reply(pid, pager, true, rep),
            Ok(FaultOutcome::Resolved)
        );

        // Victim is ready again; the mapping is installed.
        assert_eq!(sched::get(victim).unwrap().state, sched::State::Ready);
        assert_eq!(
            aspace::translate(proc::as_of(pid).unwrap_or(aspace::DEFAULT_AS), Vaddr(vaddr)),
            Ok((frame, MapFlags::READ.union(MapFlags::WRITE)))
        );
    }

    #[test]
    fn non_ok_reply_kills_faulting_thread() {
        let pid = setup();
        let victim = sched::spawn(ObjRef(1), 100).unwrap();
        let ep = endpoint::create_endpoint().unwrap();
        let _ep_h = proc::install_cap(
            pid,
            Capability {
                obj: ObjId(ep.0),
                typ: ObjType::Endpoint,
                rights: Rights::SEND.union(Rights::RECV),
            },
        )
        .unwrap();
        {
            let mut guard = SCHED.lock();
            guard.as_mut().unwrap().slots.threads[victim.0 as usize]
                .as_mut()
                .unwrap()
                .fault_ep = Some(ep);
        }
        assert_eq!(
            handle_page_fault(pid, victim, 0x710_000, ACCESS_READ),
            Ok(FaultOutcome::Routed)
        );
        let rep = Message::new(labels::kernel::FAULT_RESOLVE);
        assert_eq!(
            handle_resolve_reply(pid, ThreadId(9), false, rep),
            Ok(FaultOutcome::Killed)
        );
        assert!(matches!(
            sched::get(victim).unwrap().state,
            sched::State::Exited(-1)
        ));
    }
}
