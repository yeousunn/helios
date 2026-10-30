//! Helios process server (design: `servers/docs/process-and-vfs-design.md` §2).
//!
//! Slice 1: protocol codecs, the kernel/transport abstractions the server
//! needs, and the connection/spawn/wait/kill core — all host-testable against
//! mock backends. The real syscall runtime (`sdk/`) implements
//! [`runtime::Transport`] and [`runtime::KernelOps`] once the kernel's
//! threads/paging land; this crate contains no `unsafe` and no syscalls.
//!
//! `no_std + alloc` (ADR-020): the eventual server binary links no `std` —
//! a userspace global allocator over carved frames comes with the SDK runtime.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod proto;
pub mod runtime;
pub mod runtime_impl;
pub mod server;

#[cfg(test)]
mod test_support;
