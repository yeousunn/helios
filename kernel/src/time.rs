//! Monotonic time (ADR-034): registered clock, nanoseconds since boot.
#![forbid(unsafe_code)]

use spin::Mutex;

type ClockFn = fn() -> u64;

static CLOCK: Mutex<Option<ClockFn>> = Mutex::new(None);

/// Register the monotonic clock (arch boot; typically the hal Timer TSC
/// reader). Call once.
pub fn set_clock(f: ClockFn) {
    *CLOCK.lock() = Some(f);
}

/// Nanoseconds since boot; 0 until a clock is registered.
pub fn now_ns() -> u64 {
    match CLOCK.lock().as_ref() {
        Some(f) => f(),
        None => 0,
    }
}

/// IRQ-safe tick marker (ADR-042): the PIT handler runs on the interrupt
/// stack with scheduler locks potentially held by the interrupted syscall
/// context on this CPU — taking them there would self-deadlock the spin
/// locks (the ADR-038 deferred-wake pattern). The handler only sets this
/// flag; `drain_tick` (dispatch entry / pre-idle) performs the expiry.
static TICK_PENDING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Record a timer tick. IRQ-context safe: lock-free, no reentry.
pub fn tick_pending() {
    TICK_PENDING.store(true, core::sync::atomic::Ordering::Release);
}

/// Consume a pending tick: expire parked recv/send deadlines (ADR-041).
/// Returns true if a tick was pending. Called from dispatch entry (syscall
/// context) and from the pre-idle drain (before `hlt`), never from IRQ
/// context.
pub fn drain_tick() -> bool {
    if TICK_PENDING.swap(false, core::sync::atomic::Ordering::AcqRel) {
        crate::sched::expire_timeouts(now_ns());
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_clock_reads_zero_then_registered() {
        *CLOCK.lock() = None;
        assert_eq!(now_ns(), 0);
        set_clock(|| 1234);
        assert_eq!(now_ns(), 1234);
        set_clock(|| 5678);
        assert_eq!(now_ns(), 5678, "re-registration replaces");
        *CLOCK.lock() = None;
    }
}
