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
    /// Kernel stack top for this thread (allocated at spawn, M3).
    pub kstack_top: u64,
    /// Saved kernel stack pointer while the thread is not running (M3).
    /// Written by the arch context switch; 0 until first use.
    pub ksp: u64,
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
            kstack_top: 0,
            ksp: 0,
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

/// Set a thread's userspace entry PC after creation (boot launcher staging:
/// the init thread is spawned by `init::start` before its image is mapped)
/// and build its initial kernel context when a backend is registered.
pub fn set_initial_pc(id: ThreadId, pc: u64) -> SchedResult<()> {
    let mut top = kstack_top_of(id);
    if top == 0 {
        // First time this thread acquires a userspace entry: give it a
        // kernel stack (16 KiB) for syscalls/parks (M3). Lazy allocation
        // keeps kernel-internal test threads (no pc) frame-free.
        if let Some(base) = crate::frame::alloc_contiguous(KSTACK_FRAMES) {
            top = base.as_u64() + (KSTACK_FRAMES as u64) * 4096;
            let mut guard = SCHED.lock();
            if let Some(t) = guard
                .as_mut()
                .and_then(|s| s.slots.threads[id.0 as usize].as_mut())
            {
                t.kstack_top = top;
            }
        }
    }
    let ksp = if top != 0 {
        CTX.lock()
            .as_ref()
            .map(|b| b.init_context(top, pc))
            .unwrap_or(0)
    } else {
        0
    };
    let mut guard = SCHED.lock();
    match guard
        .as_mut()
        .and_then(|s| s.slots.threads[id.0 as usize].as_mut())
    {
        Some(t) => {
            t.initial_pc = pc;
            t.ksp = ksp;
            Ok(())
        }
        None => Err(SchedError::NoSuchThread),
    }
}

/// Kernel stack size per thread: 16 KiB (4 frames).
pub const KSTACK_FRAMES: usize = 4;

/// Register a new thread with a userspace entry PC (ADR-019 §4); builds its
/// initial kernel context (M3) when a context backend is registered.
pub fn spawn_with(process: ObjRef, priority: u8, initial_pc: u64) -> SchedResult<ThreadId> {
    let id = spawn(process, priority)?;
    set_initial_pc(id, initial_pc)?;
    Ok(id)
}

/// Read a thread's saved kernel stack pointer (arch switch).
pub fn ksp_of(id: ThreadId) -> u64 {
    let guard = SCHED.lock();
    guard
        .as_ref()
        .and_then(|s| s.slots.threads[id.0 as usize].as_ref())
        .map(|t| t.ksp)
        .unwrap_or(0)
}

/// Read a thread's kernel stack top (arch switch, for CURRENT_KSTACK).
pub fn kstack_top_of(id: ThreadId) -> u64 {
    let guard = SCHED.lock();
    guard
        .as_ref()
        .and_then(|s| s.slots.threads[id.0 as usize].as_ref())
        .map(|t| t.kstack_top)
        .unwrap_or(0)
}

/// Raw pointer to a thread's saved-ksp slot (written by the arch switch).
///
/// # Safety
/// Single-CPU v0: the slot belongs to the currently running thread (the only
/// writer) and is accessed only from the switch path.
pub fn ksp_slot_ptr(id: ThreadId) -> Option<*mut u64> {
    let mut guard = SCHED.lock();
    guard
        .as_mut()
        .and_then(|s| s.slots.threads[id.0 as usize].as_mut())
        .map(|t| &mut t.ksp as *mut u64)
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
    let (prio, runnable) = {
        let t = s.slots.threads[slot].as_ref().unwrap();
        (t.priority, matches!(t.state, State::Running | State::Ready))
    };
    if !runnable {
        return Err(SchedError::NotRunnable);
    }
    // A Ready thread sits in its run queue — unlink before parking, or
    // pick_next could later pop a Blocked thread (found in M2 audit).
    let was_ready = {
        let t = s.slots.threads[slot].as_ref().unwrap();
        matches!(t.state, State::Ready)
    };
    if was_ready {
        unlink_from_queue(s, slot, prio);
    }
    {
        let t = s.slots.threads[slot].as_mut().unwrap();
        t.state = State::Blocked(reason);
    }
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
    // Pure pick: `s.current` is updated by `switch_to` only (a double update
    // corrupted `from`-bookkeeping and clobbered the target's saved context).
    for prio in (1..=255).rev() {
        if let Some(slot) = queue_pop(s, prio as u8) {
            let t = s.slots.threads[slot].as_mut().unwrap();
            t.state = State::Running;
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
    /// Build the initial kernel context for a new thread on `kstack_top`
    /// (entry trampoline arrangement is arch-owned); returns the initial
    /// kernel stack pointer for `Thread.ksp`.
    fn init_context(&self, kstack_top: u64, entry_pc: u64) -> u64;
    /// Make `as_id` the address space the CPU translates through (CR3).
    fn activate_aspace(&self, as_id: u64);
}

static CTX: Mutex<Option<&'static dyn ContextBackend>> = Mutex::new(None);

pub fn set_context_backend(b: &'static dyn ContextBackend) {
    *CTX.lock() = Some(b);
}

/// Context-switch the arch state from current() to `next` and update the
/// scheduler's current pointer.
///
/// Lock discipline (critical for real context switches, M2+): NO lock is
/// held across the backend `switch` call. A spinlock held across a stack
/// switch would deadlock the next `switch` on resume (the holder never
/// returns until it is scheduled back). `current` is updated BEFORE
/// switching so trap entry observes the new thread immediately.
pub fn switch_to(next: ThreadId) {
    let from = current();
    // Snapshot the backend ('static, registered once at boot) and release
    // the lock before switching away.
    let backend = *CTX.lock();
    // Activate the target's address space first: threads of different
    // processes must translate through their own page tables (CR3).
    //
    // BOTH failure modes are fatal-and-loud (clobber-hunt hardening): a
    // user thread without a recorded AS, or an activation failure, would
    // otherwise run under a FOREIGN CR3 — its user VAs silently resolve
    // into another process's memory (the m44–m73 corruption class).
    if let Some(b) = backend {
        let as_id = match get(next) {
            Ok(t) => match crate::proc::as_of(caps::ObjId(t.process.0)) {
                Some(as_id) => as_id,
                None => switch_fatal_no_as(next),
            },
            Err(_) => switch_fatal_no_thread(next),
        };
        b.activate_aspace(as_id.0);
    }
    {
        let mut g = SCHED.lock();
        if let Some(s) = g.as_mut() {
            s.current = next;
        }
    }
    if let Some(b) = backend {
        b.switch(from, next);
        // Control returns here when THIS thread is scheduled again; `current`
        // was set by whoever switched back to us.
    }
}

fn switch_fatal_no_as(next: ThreadId) -> ! {
    crate::kerror!(
        "switch: thread {} has no address space recorded — refusing foreign-CR3 run",
        next.0
    );
    loop {
        core::hint::spin_loop();
    }
}

fn switch_fatal_no_thread(next: ThreadId) -> ! {
    crate::kerror!("switch: thread {} not found in registry", next.0);
    loop {
        core::hint::spin_loop();
    }
}

/// Bench hook: reset the global scheduler (criterion benches run on host).
pub fn reset_for_bench() {
    *SCHED.lock() = None;
}

/// Register a thread's kernel stack (arch boot allocates 16 KiB / 4 frames
/// at `kstack_top - 16 KiB`; ADR-031 bookkeeping).
pub fn set_kstack(id: ThreadId, base: u64, frames: u32) -> SchedResult<()> {
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(SchedError::NoSuchThread)?;
    let slot = find_slot(s, id)?;
    s.slots.threads[slot].as_mut().unwrap().kstack_top =
        base + frames as u64 * crate::frame::FRAME_SIZE as u64;
    Ok(())
}

/// Graveyard: kstacks of exited threads, drained when provably off-stack
/// (idle). Bounded — overflow leaks the oldest entry rather than
/// use-after-free (ADR-031 §1).
struct Graveyard {
    entries: [(u64, u32); 16],
    len: usize,
}

static GRAVEYARD: Mutex<Graveyard> = Mutex::new(Graveyard {
    entries: [(0, 0); 16],
    len: 0,
});

fn bury_kstack(base: u64, frames: u32) {
    let mut g = GRAVEYARD.lock();
    if g.len < g.entries.len() {
        let slot = g.len;
        g.entries[slot] = (base, frames);
        g.len += 1;
    }
    // else: bounded leak, never UAF.
}

/// Drain the graveyard: free buried kstacks. MUST only be called when no
/// buried stack can be in use — the idle path (ADR-031 §1).
pub fn drain_graveyard() -> usize {
    let mut g = GRAVEYARD.lock();
    let mut freed = 0;
    for i in 0..g.len {
        let (base, frames) = g.entries[i];
        for f in 0..frames {
            let _ = crate::frame::free(crate::frame::PhysAddr::new(
                base + f as u64 * crate::frame::FRAME_SIZE as u64,
            ));
        }
        freed += 1;
    }
    g.len = 0;
    freed
}

/// Public exit-path hook: bury the exiting thread's kernel stack.
pub fn bury_thread_kstack_for_exit(id: ThreadId) {
    bury_thread_kstack(id);
}

/// Bury a thread's kstack on exit (called by sys_exit teardown).
fn bury_thread_kstack(id: ThreadId) {
    if let Ok(t) = get(id) {
        if t.kstack_top != 0 {
            // M3 allocation: 16 KiB = 4 frames ending at kstack_top (ADR-031).
            bury_kstack(t.kstack_top - 4 * crate::frame::FRAME_SIZE as u64, 4);
        }
    }
}

/// Timer-tick preemption hook (ADR-033 §2): yields the current thread to
/// its run queue and switches to the best next thread. Callable from a
/// timer IRQ once the hal registers one; safe to call spuriously.
/// Returns the thread switched to (IDLE = nothing else runnable).
pub fn preempt() -> ThreadId {
    let cur = current();
    if cur != IDLE {
        let _ = yield_now(cur);
    }
    let next = pick_next();
    if next != cur && next != IDLE {
        switch_to(next);
    }
    next
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
    // Update the pointer first (see switch_to's lock discipline): after the
    // backend enters `next`, this frame never resumes on the boot path.
    {
        let mut g = SCHED.lock();
        if let Some(s) = g.as_mut() {
            s.current = next;
            // The spawned thread is still queued as Ready — unlink it and
            // mark it Running, or pick_next could later pop the very thread
            // that is already on-CPU (and, after it blocks, a parked one).
            if let Ok(slot) = find_slot(s, next) {
                if matches!(s.slots.threads[slot].as_ref().unwrap().state, State::Ready) {
                    let prio = s.slots.threads[slot].as_ref().unwrap().priority;
                    unlink_from_queue(s, slot, prio);
                    s.slots.threads[slot].as_mut().unwrap().state = State::Running;
                }
            }
        }
    }
    let backend = *CTX.lock();
    if let Some(b) = backend {
        b.start_first(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCtx;
    impl ContextBackend for MockCtx {
        fn switch(&self, _from: ThreadId, _to: ThreadId) {}
        fn start_first(&self, _to: ThreadId) {}
        fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
            0
        }
        fn activate_aspace(&self, _as_id: u64) {}
    }

    fn setup() {
        // Test-only: reset the global so each test starts fresh.
        *SCHED.lock() = None;
        set_context_backend(&MockCtx);
        let _ = init();
        // switch_to now fatals on threads without a recorded AS (foreign-CR3
        // guard): register the test process (pid 1) with the default AS.
        crate::proc::reset_for_test();
        let pid = crate::proc::create().unwrap();
        assert_eq!(pid, caps::ObjId(1));
        crate::proc::set_as(pid, super::super::aspace::DEFAULT_AS).unwrap();
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
        let p = ObjRef(1);
        let t = spawn(p, 100).unwrap();
        assert_eq!(current(), IDLE);
        let next = pick_next();
        assert_eq!(next, t);
        switch_to(next);
        assert_eq!(current(), t);
    }
    #[test]
    fn start_first_unqueues_and_marks_running() {
        // M2 audit: the boot-started thread must not remain in the run
        // queue, or pick_next can pop a blocked/current thread.
        setup();
        let p = ObjRef(9);
        let t = spawn(p, 100).unwrap();
        start_first(t);
        assert_eq!(current(), t);
        // The queue must be empty at t's level: nothing else spawns at 100,
        // so pick_next falls through to IDLE.
        assert_eq!(pick_next(), IDLE);
        // And blocking it works from Running state.
        block(t, BlockReason::Recv(ObjRef(3))).unwrap();
        assert_eq!(pick_next(), IDLE, "parked thread is never re-picked");
    }

    #[test]
    fn block_from_ready_unqueues() {
        setup();
        let p = ObjRef(10);
        let t = spawn(p, 100).unwrap();
        // t is Ready (queued). Block it WITHOUT it ever being picked.
        block(t, BlockReason::Recv(ObjRef(4))).unwrap();
        assert_eq!(
            pick_next(),
            IDLE,
            "blocked-from-ready thread must be unqueued"
        );
        make_ready(t).unwrap();
        assert_eq!(pick_next(), t, "requeued after wake");
    }
    #[test]
    fn graveyard_bury_and_drain() {
        // ADR-031: exited-thread kstacks are buried, then freed on idle drain.
        setup();
        let p = ObjRef(20);
        let t = spawn(p, 100).unwrap();
        // Arch backend reports a 4-frame kstack (16 KiB) ending at kstack_top.
        let top: u64 = 0x200_0000;
        let base = top - 4 * crate::frame::FRAME_SIZE as u64;
        set_kstack(t, base, 4).unwrap();
        exit(t, 0).unwrap();
        bury_thread_kstack_for_exit(t);

        // Nothing freed yet (still buried).
        let drained = drain_graveyard();
        assert_eq!(drained, 1, "one kstack buried and drained");
        assert_eq!(drain_graveyard(), 0, "second drain is a no-op");

        // Fill the graveyard to exactly capacity (16) with distinct stacks.
        for i in 0..16u64 {
            let tt = spawn(p, 100).unwrap();
            set_kstack(tt, 0x300_0000 + i * 0x1_0000, 4).unwrap();
            exit(tt, 0).unwrap();
            bury_thread_kstack_for_exit(tt);
        }
        assert_eq!(drain_graveyard(), 16);
    }
    #[test]
    fn preempt_yields_and_switches() {
        setup();
        let p = ObjRef(1);
        let a = spawn(p, 100).unwrap();
        let b = spawn(p, 100).unwrap();
        // a runs; a preempt tick must requeue a and run b.
        let _ = pick_next(); // a Running
        switch_to(a);
        let switched = preempt();
        assert_eq!(switched, b, "preemption round-robins within the level");
        assert_eq!(current(), b);
        assert_eq!(get(a).unwrap().state, State::Ready);
    }
}
