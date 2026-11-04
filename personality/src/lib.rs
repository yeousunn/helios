//! personality — the POSIX personality layer: a `no_std` runtime over the
//! Helios IPC services (PLAN.md §3 compatibility strategy; design
//! `servers/docs/process-and-vfs-design.md`).
//!
//! First slice: the native runtime wrappers — the path from a bootstrap
//! package to a usable POSIX-ish process (heap + VFS client + local fd
//! table) with an open/read/write/close subset. Linux binary emulation
//! (musl loader, syscall trampolines) builds on this in later slices; the
//! design keeps POSIX semantics out of the kernel and servers, so this is
//! the only layer that needs to grow for compatibility.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod layout;
pub mod posix;
pub mod ps;
pub mod runtime;
pub mod vfs;
