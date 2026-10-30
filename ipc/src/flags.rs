//! Tag flag bits (schema §4).
#![forbid(unsafe_code)]

/// send/call: return `EWOULDBLOCK` instead of blocking.
pub const NONBLOCK: u8 = 1 << 0;
/// Set by the kernel on delivery if any descriptor failed (never by senders).
pub const CAP_PARTIAL: u8 = 1 << 1;
/// Set on recv return when a bound notification (not a message) woke the
/// thread; label = 0, w0 = pending notification mask.
pub const NOTIFIED: u8 = 1 << 2;
