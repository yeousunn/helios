//! Helios VFS server (design: `servers/docs/process-and-vfs-design.md` §3).
//!
//! Slice 1: protocol codecs, ramfs core (walk/open/read/write/create/unlink/
//! rename/readdir with POSIX-ish pending deletes), per-connection handle
//! tables, and the serving loop — all host-testable against mock backends.
//! No `unsafe`; no kernel calls.
#![forbid(unsafe_code)]

pub mod proto;
pub mod ramfs;
pub mod runtime;
pub mod runtime_impl;
pub mod server;

#[cfg(test)]
mod test_support;
