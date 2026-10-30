//! Helios VFS server (design: `servers/docs/process-and-vfs-design.md` §3).
//!
//! Slice 1: protocol codecs, ramfs core (walk/open/read/write/create/unlink/
//! rename/readdir with POSIX-ish pending deletes), per-connection handle
//! tables, and the serving loop — all host-testable against mock backends.
//! No `unsafe`; no kernel calls.
//!
//! `no_std + alloc` (ADR-020): see the process server crate.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod proto;
pub mod ramfs;
pub mod runtime;
pub mod runtime_impl;
pub mod server;

#[cfg(test)]
mod test_support;
