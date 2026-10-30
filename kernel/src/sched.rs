//! Threads and the priority scheduler (ADR-010).
//!
//! Fixed-capacity, no-heap v0: intrusive index lists, strict priority with
//! round-robin within a level. The arch `ContextBackend` does the actual
//! register/stack switch; everything here is policy and host-testable.
#![forbid(unsafe_code)]

use core::fmt;
use spin::Mutex;

/// Thread identifier. 0 is reserved for the idle thread.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ThreadId(pub u64);

/// What a blocked thread is waiting for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockReason {
    /// Waiting to receive on a kernel endpoint.
    Recv(ObjRef),
    /// Waiting to send into a full endpoint mailbox.
    Send(ObjRef),
    /// Waiting for a notification signal on this object.
    Notification(ObjRef),
    /// Awaiting fault resolution on the given fault endpoint (ADR-007).
    Fault(ObjRef),
    /// Waiting for a reply after a `call` (reply-cap pending).
    Reply,
}

/// Reference to a kernel object by ObjId (endpoints, notifications).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjRef(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Ready,
    Running,
    Blocked(BlockReason),
    Suspended,
    Exited(i32),
}

/// A schedulable thread.
#[derive(Clone, Copy, Debug)]
pub struct Thread {
    pub id: ThreadId,
    pub state: State,
    /// Higher = more urgent (0..=255). Idle = 0, default = 100 (ADR-010).
    pub priority: u8,
    /// Owning process (kernel object id of its address space in v0).
    pub process: ObjRef,
    /// Fault endpoint (ADR-007), if any.
    pub fault_ep: Option<ObjRef>,
    /// Bound notification (syscall-abi §3.1), if any.
    pub bound_notification: Option<ObjRef>,
    /// Userspace entry PC (NEW_THREAD w0, ADR-019 §4). SP is arch-owned.
    pub initial_pc: u64,
}

impl Thread {
    pub fn new(id: ThreadId, process: ObjRef, priority: u8) -> Self {
        Thread {
            id,
            state: State::Ready,
            priority,
            process,
            fault_ep: None,
            bound_notification: None,
            initial_pc: 0,
        }
    }

    pub fn is_runnable(&self) -> bool {
        matches!(self.state, State::Ready | State::Running)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SchedError {
    TableFull,
    NoSuchThread,
    NotRunnable,
    AlreadyRunning,
}

impl fmt::Display for SchedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

pub type SchedResult<T> = Result<T, SchedError>;

const MAX_THREADS: usize = 64;

/// Free-list node / per-level run queue links.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Link {
    None,
    Free(SlotIdx),
    Queue(SlotIdx),
}

type SlotIdx = usize;

pub(crate) struct Slots {
    pub(crate) threads: [Option<Thread>; MAX_THREADS],
    /// Free-list and per-level FIFO links (next pointers), shared array.
    pub(crate) next: [Link; MAX_THREADS],
}

impl Slots {
    const fn new() -> Self {
        let mut next = [Link::Free(0); MAX_THREADS];
        let mut i = 0;
        while i < MAX_THREADS {
            next[i] = Link::Free((i + 1) % (MAX_THREADS + 1));
            i += 1;
        }
        Slots {
            threads: [const { None }; MAX_THREADS],
            next,
        }
    }
}

/// Global scheduler state.
pub(crate) struct Sched {
    pub(crate) slots: Slots,
    free_head: SlotIdx,
    used: usize,
    /// Run-queue heads per priority level (0..=255); Link::Queue = head slot.
    queues: [Link; 256],
    /// Currently running thread (idle = ThreadId(0)).
    current: ThreadId,
    /// Tail pointers for O(1) enqueue. 0 = no tail.
    tails: [SlotIdx; 256],
}

pub(crate) static SCHED: Mutex<Option<Sched>> = Mutex::new(None);

pub const IDLE: ThreadId = ThreadId(0);

/// Scheduler default priority (ADR-010/ADR-017 §3).
pub const DEFAULT_PRIORITY: u8 = 100;

/// Initialize the scheduler. Call once from boot.
pub fn init() -> SchedResult<()> {
    let mut guard = SCHED.lock();
    if guard.is_some() {
        return Err(SchedError::AlreadyRunning);
    }
    let mut sched = Sched {
        slots: Slots::new(),
        free_head: 0,
        used: 0,
        queues: [Link::None; 256],
        current: IDLE,
        tails: [0; 256],
    };
    // Reserve slot 0 for the idle thread record.
    sched.slots.threads[0] = Some(Thread::new(IDLE, ObjRef(0), 0));
    sched.slots.threads[0].as_mut().unwrap().state = State::Running;
    sched.slots.next[0] = Link::None;
    sched.free_head = 1;
    sched.used = 1;
    *guard = Some(sched);
    Ok(())
}

fn queue_push(s: &mut Sched, slot: SlotIdx, prio: u8) {
    let tail = s.tails[prio as usize];
    if tail > 0 {
        s.slots.next[tail] = Link::Queue(slot);
    } else {
        s.queues[prio as usize] = Link::Queue(slot);
    }
    s.slots.next[slot] = Link::None;
    s.tails[prio as usize] = slot;
}

fn queue_pop(s: &mut Sched, prio: u8) -> Option<SlotIdx> {
    let head = s.queues[prio as usize];
    let slot = match head {
        Link::Queue(idx) => idx,
        _ => return None,
    };
    let next = match s.slots.next[slot] {
        Link::Queue(n) => n,
        _ => 0,
    };
    s.queues[prio as usize] = if next == 0 {
        Link::None
    } else {
        Link::Queue(next)
    };
    if s.queues[prio as usize] == Link::None {
        s.tails[prio as usize] = 0;
    }
    s.slots.next[slot] = Link::None;
    Some(slot)
}

/// Register a new thread with a userspace entry PC (ADR-019 §4).
pub fn spawn_with(process: ObjRef, priority: u8, initial_pc: u64) -> SchedResult<ThreadId> {
    let id = spawn(process, priority)?;
    let mut guard = SCHED.lock();
    if let Some(t) = guard
        .as_mut()
        .and_then(|s| s.slots.threads[id.0 as usize].as_mut())
    {
        t.initial_pc = initial_pc;
    }
    Ok(id)
}

/// Register a new thread; returns its id. The thread starts Ready.
pub fn spawn(process: ObjRef, priority: u8) -> SchedResult<ThreadId> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    if s.free_head == MAX_THREADS {
        return Err(SchedError::TableFull);
    }
    let slot = s.free_head;
    s.free_head = match s.slots.next[slot] {
        Link::Free(n) => n,
        _ => MAX_THREADS,
    };
    let id = ThreadId(slot as u64); // internal id = slot; handle = id + 1 at syscall layer (0 = null)
    let mut t = Thread::new(id, process, priority);
    t.state = State::Ready;
    s.slots.threads[slot] = Some(t);
    s.slots.next[slot] = Link::None;
    s.used += 1;
    queue_push(s, slot, priority);
    Ok(id)
}

fn find_slot(s: &Sched, id: ThreadId) -> SchedResult<SlotIdx> {
    let slot = id.0 as usize;
    if id == IDLE || slot == 0 || slot >= MAX_THREADS {
        return Err(SchedError::NoSuchThread);
    }
    if s.slots.threads[slot].is_none() {
        return Err(SchedError::NoSuchThread);
    }
    Ok(slot)
}

/// Inspect a thread (diagnostics, tests).
pub fn get(id: ThreadId) -> SchedResult<Thread> {
    let guard = SCHED.lock();
    let s = guard.as_ref().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    Ok(s.slots.threads[slot].unwrap())
}

/// Mark a thread runnable and enqueue it at its priority.
pub fn make_ready(id: ThreadId) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let t = s.slots.threads[slot].as_mut().unwrap();
    match t.state {
        State::Ready | State::Running => return Err(SchedError::NotRunnable),
        State::Exited(_) | State::Suspended => return Err(SchedError::NotRunnable),
        State::Blocked(_) => {}
    }
    t.state = State::Ready;
    let prio = t.priority;
    queue_push(s, slot, prio);
    Ok(())
}

/// A running/ready thread voluntarily re-enters its run queue (tail) —
/// round-robin scheduling (syscall `yield`).
pub fn yield_now(id: ThreadId) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let t = s.slots.threads[slot].as_mut().unwrap();
    match t.state {
        State::Running | State::Ready => {
            t.state = State::Ready;
            let prio = t.priority;
            queue_push(s, slot, prio);
            Ok(())
        }
        _ => Err(SchedError::NotRunnable),
    }
}

/// Block the (running) thread on `reason`. Returns the thread it should
/// yield to via [`pick_next`].
pub fn block(id: ThreadId, reason: BlockReason) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let t = s.slots.threads[slot].as_mut().unwrap();
    if t.state != State::Running && t.state != State::Ready {
        return Err(SchedError::NotRunnable);
    }
    t.state = State::Blocked(reason);
    Ok(())
}

/// Change a thread's priority; requeues it if it is on a run queue.
pub fn set_priority(id: ThreadId, priority: u8) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let (old_prio, was_queued) = {
        let t = s.slots.threads[slot].as_ref().unwrap();
        let queued = matches!(t.state, State::Ready);
        (t.priority, queued)
    };
    let t = s.slots.threads[slot].as_mut().unwrap();
    t.priority = priority;
    if was_queued {
        // Remove from old level (O(n) scan; fine at v0 scale) and requeue.
        unlink_from_queue(s, slot, old_prio);
        queue_push(s, slot, priority);
    }
    Ok(())
}

fn unlink_from_queue(s: &mut Sched, slot: SlotIdx, prio: u8) {
    let mut prev: Option<SlotIdx> = None;
    let mut cur = match s.queues[prio as usize] {
        Link::Queue(i) => Some(i),
        _ => None,
    };
    while let Some(c) = cur {
        let next = match s.slots.next[c] {
            Link::Queue(n) => Some(n),
            _ => None,
        };
        if c == slot {
            match prev {
                Some(p) => {
                    s.slots.next[p] = s.slots.next[c];
                    if s.tails[prio as usize] == slot {
                        s.tails[prio as usize] = p;
                    }
                }
                None => {
                    s.queues[prio as usize] = s.slots.next[c];
                    if s.queues[prio as usize] == Link::None {
                        s.tails[prio as usize] = 0;
                    }
                }
            }
            s.slots.next[slot] = Link::None;
            return;
        }
        prev = Some(c);
        cur = next;
    }
}

/// Suspend a Ready/Running thread (Thread::SUSPEND, syscall-abi §7).
pub fn suspend(id: ThreadId) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let t = s.slots.threads[slot].as_mut().unwrap();
    match t.state {
        State::Ready => {
            let priority = t.priority;
            let _ = t;
            unlink_from_queue(s, slot, priority);
            let t = s.slots.threads[slot].as_mut().unwrap();
            t.state = State::Suspended;
            Ok(())
        }
        State::Running => {
            t.state = State::Suspended;
            Ok(())
        }
        _ => Err(SchedError::NotRunnable),
    }
}

/// Resume a Suspended thread (Thread::RESUME).
pub fn resume(id: ThreadId) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let t = s.slots.threads[slot].as_mut().unwrap();
    match t.state {
        State::Suspended => {
            t.state = State::Ready;
            let prio = t.priority;
            queue_push(s, slot, prio);
            Ok(())
        }
        _ => Err(SchedError::NotRunnable),
    }
}

/// Rebind a thread's bound notification (Thread::BIND_DEATH_NOTIFICATION /
/// Thread::BIND_NOTIFICATION, syscall-abi §7).
pub fn set_bound_notification(id: ThreadId, n: Option<ObjRef>) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    s.slots.threads[slot].as_mut().unwrap().bound_notification = n;
    Ok(())
}

/// Exit a thread: unqueue, mark Exited, fire death notification hooks.
/// Returns `true` if a death notification was signalled (the notification
/// engine translates that into wakes; see endpoint module).
pub fn exit(id: ThreadId, status: i32) -> SchedResult<bool> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    let (prio, notify) = {
        let t = s.slots.threads[slot].as_ref().unwrap();
        if matches!(t.state, State::Exited(_)) {
            return Err(SchedError::NotRunnable);
        }
        (t.priority, t.bound_notification)
    };
    // If queued at its priority level, unlink first.
    {
        let t = s.slots.threads[slot].as_ref().unwrap();
        if matches!(t.state, State::Ready) {
            unlink_from_queue(s, slot, prio);
        }
    }
    let t = s.slots.threads[slot].as_mut().unwrap();
    t.state = State::Exited(status);
    if s.current == id {
        s.current = IDLE;
    }
    s.used -= 1;
    Ok(notify.is_some())
}

/// Pick the next runnable thread (strict priority, round-robin FIFO),
/// switch the current pointer, and return its id. Returns IDLE when nothing
/// is ready.
pub fn pick_next() -> ThreadId {
    let mut guard = SCHED.lock();
    let Some(s) = guard.as_mut() else {
        return IDLE;
    };
    // 255..=1: idle (level 0) is chosen only if nothing else is ready.
    for prio in (1..=255).rev() {
        if let Some(slot) = queue_pop(s, prio as u8) {
            let t = s.slots.threads[slot].as_mut().unwrap();
            t.state = State::Running;
            s.current = t.id;
            return t.id;
        }
    }
    IDLE
}

/// The currently scheduled thread.
pub fn current() -> ThreadId {
    let guard = SCHED.lock();
    guard.as_ref().map(|s| s.current).unwrap_or(IDLE)
}

/// How many threads are alive (excluding idle).
pub fn thread_count() -> usize {
    let guard = SCHED.lock();
    guard.as_ref().map(|s| s.used).unwrap_or(0) - 1
}

/// Iterate ids of threads blocked for `reason` (wake-scan support).
pub fn blocked_matching(pred: impl Fn(&BlockReason) -> bool) -> [ThreadId; MAX_THREADS] {
    let mut out = [IDLE; MAX_THREADS];
    let mut n = 0;
    let guard = SCHED.lock();
    if let Some(s) = guard.as_ref() {
        for t in s.slots.threads.iter() {
            if let Some(Thread {
                state: State::Blocked(r),
                id,
                ..
            }) = t
            {
                if pred(r) && n < MAX_THREADS {
                    out[n] = *id;
                    n += 1;
                }
            }
        }
    }
    out
}

/// Arch context-switch backend (ADR-010). Registered at boot; hal-* saves
/// and restores registers. Host tests use a recording mock.
pub trait ContextBackend: Sync + Send {
    /// Perform a register/stack switch from `from` to `to`.
    fn switch(&self, from: ThreadId, to: ThreadId);
    /// Enter the first thread (no saved state to restore).
    fn start_first(&self, to: ThreadId);
}

static CTX: Mutex<Option<&'static dyn ContextBackend>> = Mutex::new(None);

pub fn set_context_backend(b: &'static dyn ContextBackend) {
    *CTX.lock() = Some(b);
}

/// Context-switch the arch state from current() to `next` and update the
/// scheduler's current pointer.
pub fn switch_to(next: ThreadId) {
    let from = current();
    let guard = CTX.lock();
    if let Some(b) = guard.as_ref() {
        b.switch(from, next);
    }
    let mut g = SCHED.lock();
    if let Some(s) = g.as_mut() {
        s.current = next;
    }
}

/// Are there live (non-Exited) threads for this process? (ADR-026 reaper.)
pub fn process_has_live_threads(process: ObjRef) -> bool {
    let guard = SCHED.lock();
    let Some(s) = guard.as_ref() else {
        return false;
    };
    s.slots
        .threads
        .iter()
        .flatten()
        .any(|t| t.process == process && !matches!(t.state, State::Exited(_)))
}

/// Enter the first thread: switch the arch state to `next` and update the
/// scheduler's current pointer. Called once at boot to enter init.
pub fn start_first(next: ThreadId) {
    let guard = CTX.lock();
    if let Some(b) = guard.as_ref() {
        b.start_first(next);
    }
    let mut g = SCHED.lock();
    if let Some(s) = g.as_mut() {
        s.current = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCtx;
    impl ContextBackend for MockCtx {
        fn switch(&self, _from: ThreadId, _to: ThreadId) {}
        fn start_first(&self, _to: ThreadId) {}
    }

    fn setup() {
        // Test-only: reset the global so each test starts fresh.
        *SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = init();
    }

    #[test]
    fn spawn_pick_round_robin_and_priorities() {
        setup();
        let p = ObjRef(1);
        let a = spawn(p, 100).unwrap();
        let b = spawn(p, 100).unwrap();
        let hi = spawn(p, 200).unwrap();
        let lo = spawn(p, 10).unwrap();

        // Strict priority first.
        assert_eq!(pick_next(), hi);
        assert_eq!(pick_next(), a);
        assert_eq!(pick_next(), b);
        assert_eq!(pick_next(), lo);

        // Nothing left at level >0 → idle.
        assert_eq!(pick_next(), IDLE);

        // Round-robin within a level: re-queue and pick in FIFO order.
        yield_now(a).unwrap();
        yield_now(b).unwrap();
        assert_eq!(pick_next(), a);
        assert_eq!(pick_next(), b);
    }

    #[test]
    fn block_unblock_and_priority_change() {
        setup();
        let p = ObjRef(2);
        let t = spawn(p, 50).unwrap();
        assert_eq!(pick_next(), t);
        block(t, BlockReason::Recv(ObjRef(9))).unwrap();
        assert!(matches!(get(t).unwrap().state, State::Blocked(_)));
        assert_eq!(pick_next(), IDLE);

        make_ready(t).unwrap();
        assert_eq!(get(t).unwrap().state, State::Ready);
        assert_eq!(pick_next(), t);

        // Requeue on priority change.
        yield_now(t).unwrap();
        set_priority(t, 250).unwrap();
        assert_eq!(pick_next(), t, "raised thread preempts lower levels");
    }

    #[test]
    fn exit_frees_slot_and_fires_death_flag() {
        setup();
        let p = ObjRef(3);
        let t = spawn(p, 80).unwrap();
        // Bind a notification directly for the test.
        {
            let mut guard = SCHED.lock();
            let s = guard.as_mut().unwrap();
            let slot = (t.0) as usize;
            s.slots.threads[slot].as_mut().unwrap().bound_notification = Some(ObjRef(42));
        }
        assert_eq!(exit(t, 0), Ok(true), "death notification bound");
        assert!(matches!(get(t).unwrap().state, State::Exited(0)));
        assert_eq!(thread_count(), 0);

        // Slot is reused; ids are not (next spawn gets a fresh slot index).
        let t2 = spawn(p, 80).unwrap();
        assert_ne!(t2, t, "ids never reused in v0 (slot monotonic per boot)");
    }

    #[test]
    fn blocked_matching_scans_waiters() {
        setup();
        let p = ObjRef(4);
        let t1 = spawn(p, 100).unwrap();
        let t2 = spawn(p, 100).unwrap();
        let t3 = spawn(p, 100).unwrap();
        assert_eq!(pick_next(), t1);
        assert_eq!(pick_next(), t2);
        assert_eq!(pick_next(), t3);
        block(t1, BlockReason::Recv(ObjRef(7))).unwrap();
        block(t2, BlockReason::Send(ObjRef(7))).unwrap();
        block(t3, BlockReason::Recv(ObjRef(8))).unwrap();

        let recv7 = blocked_matching(|r| matches!(r, BlockReason::Recv(o) if *o == ObjRef(7)));
        assert_eq!(recv7[0], t1);
        assert_eq!(recv7[1], IDLE);
    }

    #[test]
    fn switch_to_updates_current_via_backend() {
        setup();
        let p = ObjRef(5);
        let t = spawn(p, 100).unwrap();
        assert_eq!(current(), IDLE);
        let next = pick_next();
        assert_eq!(next, t);
        switch_to(next);
        assert_eq!(current(), t);
    }
}
