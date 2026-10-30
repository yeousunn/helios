//! Helios native SDK. `no_std`; the first userspace processes link this crate
//! directly (a full Rust `std` port comes later).
//!
//! The syscall ABI is `sdk/docs/syscall-abi.md`; the wire format is
//! `ipc/` (ADR-005). [`syscall`] is the only module allowed `unsafe` (the
//! `syscall` instruction); it is built on a `RawSyscalls` trait so all packing
//! and status logic is host-testable.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bootinfo;
pub mod bootstrap;
pub mod layout;
pub mod methods;
pub mod syscall;

#[cfg(test)]
extern crate std;
