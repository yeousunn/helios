//! `invoke` method ids for kernel objects (syscall-abi §7). The method id is
//! carried in `tag.label` of an `invoke` message.
//!
//! These mirror the ratified tables; the kernel dispatch is authoritative.
//! Cross-check with GLM when the syscall entry lands (candidates for moving
//! into `ipc/` if the kernel exposes them).

pub mod factory {
    pub const NEW_ENDPOINT: u16 = 1;
    pub const NEW_NOTIFICATION: u16 = 2;
    pub const NEW_ADDRESS_SPACE: u16 = 3;
    pub const NEW_THREAD: u16 = 4;
}

pub mod region {
    pub const CARVE: u16 = 1;
}

pub mod thread {
    pub const EXIT: u16 = 1;
    pub const KILL: u16 = 2;
    pub const SUSPEND: u16 = 3;
    pub const RESUME: u16 = 4;
    pub const SET_PRIORITY: u16 = 5;
    pub const SET_AFFINITY: u16 = 6;
    pub const SET_FAULT_EP: u16 = 7;
    pub const BIND_NOTIFICATION: u16 = 8;
    pub const REGS_READ: u16 = 9;
    pub const REGS_WRITE: u16 = 10;
    pub const SET_TLS: u16 = 11;
    pub const BIND_DEATH_NOTIFICATION: u16 = 12;
}

pub mod aspace {
    pub const MAP: u16 = 1;
    pub const UNMAP: u16 = 2;
    pub const PROTECT: u16 = 3;
    pub const SET_FAULT_POOL: u16 = 4;
    pub const FORK: u16 = 5;
    pub const DESTROY: u16 = 6;
}

pub mod notification {
    pub const SIGNAL: u16 = 1;
    pub const CLEAR: u16 = 2;
}

pub mod irq {
    pub const ACK: u16 = 1;
}

/// VFS server protocol labels (design §3.3, `servers/vfs/src/proto.rs`).
/// Full wire labels for requests over a VFS connection.
pub mod vfs {
    pub const CONNECT: u16 = 0x0201;
    pub const WALK: u16 = 0x0210;
    pub const OPEN: u16 = 0x0211;
    pub const READ: u16 = 0x0212;
    pub const READ_BULK: u16 = 0x0213;
    pub const WRITE: u16 = 0x0214;
    pub const CLOSE: u16 = 0x0215;
    pub const STAT: u16 = 0x0217;
}

/// VFS OPEN flags (`proto.rs`).
pub mod vfs_open {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
}

/// Process server protocol labels (design §2.6,
/// `servers/docs/process-and-vfs-design.md`). These are full wire labels
/// (`tag.label` of the request message), not invoke method ids.
pub mod process {
    pub const CONNECT: u16 = 0x0101;
    pub const PACKAGE: u16 = 0x0102;
    pub const SPAWN: u16 = 0x0110;
    pub const WAIT: u16 = 0x0111;
    pub const KILL: u16 = 0x0112;
    pub const EXEC: u16 = 0x0113;
    pub const FORK: u16 = 0x0114;
    pub const THREAD_CREATE: u16 = 0x0115;
    pub const THREAD_EXIT: u16 = 0x0116;
    pub const GETPID: u16 = 0x0117;
}

/// `AddressSpace::MAP` flag bits (wire-compatible with syscall-abi §7).
pub mod map_flags {
    pub const R: u32 = 1 << 0;
    pub const W: u32 = 1 << 1;
    pub const X: u32 = 1 << 2;
    pub const COW: u32 = 1 << 3;
    pub const ANON: u32 = 1 << 4;
}
