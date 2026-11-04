//! console server — the v0 text sink of the system (design §2.3: stdio
//! endpoints are caller-supplied; this server is the thing on the other end
//! of the write-only console endpoint).
//!
//! Protocol: [`sdk::methods::console`] — `WRITE` messages carry up to 32
//! bytes of text in their words; the server forwards each message verbatim
//! to the kernel debug endpoint it was spawned with (`optional[1]`), which
//! prints it on the serial line. v0 has no CONNECT: the endpoint itself is
//! the stream, and the endpoint mailbox serializes concurrent writers.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub use sdk::methods::console;

#[cfg(test)]
mod tests {
    use super::console;

    #[test]
    fn console_constants_are_stable() {
        assert_eq!(console::WRITE, 0x0301);
        assert_eq!(console::TEXT_BYTES, 32);
    }
}
