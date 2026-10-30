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

/// `AddressSpace::MAP` flag bits (wire-compatible with syscall-abi §7).
pub mod map_flags {
    pub const R: u32 = 1 << 0;
    pub const W: u32 = 1 << 1;
    pub const X: u32 = 1 << 2;
    pub const COW: u32 = 1 << 3;
    pub const ANON: u32 = 1 << 4;
}
