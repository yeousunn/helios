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
use ipc::{flags, Message, Tag};
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
    /// rax / x0 / a0: status (0 or negative errno).
    pub status: i32,
    /// rdx / x1 / a1: returned tag.
    pub tag: Tag,
    /// returned w0..w3.
    pub w: [u64; 4],
}

/// Reserved sentinel: the thread parked inside the syscall (ADR-019 §1).
/// The arch entry must NOT return to userspace; it schedules another thread
/// and later consults [`park_result`] when the thread is scheduled again.
pub const PARKED_STATUS: i32 = i32::MIN;

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
            status,
            tag: Tag(0),
            w: [0; 4],
        }
    }

    pub const fn ok(tag: Tag, w: [u64; 4]) -> Self {
        SyscallReturn {
            status: ipc::status::OK,
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
    if let Some(mut env) = crate::endpoint::take_delivered(tid) {
        let (pid, _) = current();
        syscall::install_transfers(pid, &mut env);
        syscall::set_reply_if_call(&env, tid);
        return Some(SyscallReturn::ok(env.msg.tag, env.msg.words));
    }

    // 2. Bound notification that fired.
    let thread = sched::get(tid).ok()?;
    let n = thread.bound_notification?;
    let mask = match crate::notification::pending(n) {
        Ok(m) => m,
        Err(_) => return None,
    };
    if mask > 0 {
        let _ = crate::notification::clear(n, mask);
        return Some(SyscallReturn::ok(
            Tag::new(0).with_flags(flags::NOTIFIED),
            [mask as u64, 0, 0, 0],
        ));
    }

    // 3. Still parked.
    None
}

/// The single dispatch point for every syscall (arch entry calls this).
pub fn dispatch(args: SyscallArgs) -> SyscallReturn {
    let (pid, tid) = current();
    match args.num {
        num::YIELD => syscall::sys_yield(tid)
            .map(|_| SyscallReturn::ok(Tag(0), [0; 4]))
            .unwrap_or_else(SyscallReturn::err),
        num::SEND => match syscall::sys_send(pid, tid, args.cap, args.message(), args.nonblock) {
            Ok(status) => SyscallReturn {
                status,
                tag: Tag(0),
                w: [0; 4],
            },
            Err(e) => SyscallReturn::err(e),
        },
        num::CALL => match syscall::sys_call(pid, tid, args.cap, args.message()) {
            Ok(status) => SyscallReturn {
                status,
                tag: Tag(0),
                w: [0; 4],
            },
            Err(e) => SyscallReturn::err(e),
        },
        num::RECV => match syscall::sys_recv(pid, tid, args.cap) {
            Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
            Ok(None) => SyscallReturn::parked(), // ADR-019 §1
            Err(e) => SyscallReturn::err(e),
        },
        num::REPLY_RECV => match syscall::sys_reply_recv(pid, tid, args.cap, args.message()) {
            Ok(Some(m)) => SyscallReturn::ok(m.tag, m.words),
            Ok(None) => SyscallReturn::parked(), // ADR-019 §1
            Err(e) => SyscallReturn::err(e),
        },
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
        _ => match syscall::sys_invoke(pid, tid, args.cap, args.message()) {
            Ok(status) => SyscallReturn {
                status,
                tag: Tag(0),
                w: [0; 4],
            },
            Err(e) => SyscallReturn::err(e),
        },
    }
}

/// Thread methods (syscall-abi §7, ADR-019 §3). cap.obj = target ThreadId;
/// CONTROL right required for everything except... everything (all methods
/// control the target).
fn thread_invoke(
    pid: ProcessId,
    _tid: ThreadId,
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
        _ => SyscallReturn::err(ipc::status::ENOSYS),
    }
}

/// Test hook for syscall.rs tests (thread_invoke is private).
#[cfg(test)]
pub(crate) fn thread_invoke_for_test(
    pid: ProcessId,
    tid: ThreadId,
    cap: &Capability,
    msg: Message,
) -> i32 {
    match thread_invoke(
        pid,
        tid,
        cap,
        &SyscallArgs {
            num: crate::entry::num::INVOKE,
            cap: 0,
            tag: msg.tag,
            w: msg.words,
            nonblock: false,
        },
    ) {
        r if r.status == PARKED_STATUS => 0,
        r => r.status,
    }
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
            Ok(ep) => install_ret(
                pid,
                ep.0,
                ObjType::Endpoint,
                Rights::SEND.union(Rights::RECV).union(Rights::GRANT),
                msg.tag,
            ),
            Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
        },
        NEW_NOTIFICATION => match crate::notification::create() {
            Ok(n) => install_ret(
                pid,
                n.0,
                ObjType::Notification,
                Rights::SIGNAL.union(Rights::RECV),
                msg.tag,
            ),
            Err(_) => SyscallReturn::err(ipc::status::ENOMEM),
        },
        NEW_ADDRESS_SPACE => {
            // v0: kernel-wide VMM (ADR-008); per-process AS objects arrive
            // with process server integration (Phase 2).
            install_ret(
                pid,
                0xA5A5,
                ObjType::AddressSpace,
                Rights::MAP.union(Rights::GRANT),
                msg.tag,
            )
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
        Ok(h) => SyscallReturn::ok(tag, [h as u64, 0, 0, 0]),
        Err(e) => SyscallReturn::err(map_proc(e)),
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

    // Child thread cap (CONTROL) minted into the parent's table.
    match proc::install_cap(
        pid,
        Capability {
            obj: ObjId(child_tid.0),
            typ: ObjType::Thread,
            rights: Rights::CONTROL,
        },
    ) {
        Ok(h) => SyscallReturn::ok(msg.tag, [h as u64, entry_pc, child_pid.0, child_tid.0]),
        Err(e) => SyscallReturn::err(map_proc(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::set_context_backend;
    use std::boxed::Box;

    struct MockCtx;
    impl crate::sched::ContextBackend for MockCtx {
        fn switch(&self, _f: ThreadId, _t: ThreadId) {}
        fn start_first(&self, _t: ThreadId) {}
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

    fn setup() -> (ProcessId, ThreadId, u32) {
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
            assert_eq!(r.status, ipc::status::OK, "label {label}");
            assert_eq!(proc::get_cap(pid, r.w[0] as u32).unwrap().typ, typ);
        }

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
        assert_eq!(r.status, ipc::status::OK, "NEW_THREAD must succeed");
        let thread_h = r.w[0] as u32;
        let child_pid = ObjId(r.w[2]);

        // Child thread cap with CONTROL in parent's table; entry echoed in w1.
        let tc = proc::get_cap(pid, thread_h).unwrap();
        assert_eq!(tc.typ, ObjType::Thread);
        assert!(tc.rights.contains(Rights::CONTROL));
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
        assert_eq!(r.status, ipc::status::ENOSYS);
    }
}
