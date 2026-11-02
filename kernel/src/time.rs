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
