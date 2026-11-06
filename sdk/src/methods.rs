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
    /// ADR-033 §1: new thread in the target's process (shares AS + cap table).
    pub const THREAD_CREATE: u16 = 13;
    /// ADR-039: rewrite a quiescent thread's entry PC + rebuild its context.
    pub const SET_ENTRY: u16 = 14;
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
    pub const READDIR: u16 = 0x0218;
    pub const CREATE: u16 = 0x0219;
    pub const MKDIR: u16 = 0x021A;
    pub const UNLINK: u16 = 0x021B;
    pub const RENAME: u16 = 0x021C;
}

/// Console protocol labels (v0): the stdio endpoints a launcher supplies to
/// children (design §2.3). Write-only endpoint: each message carries up to
/// 32 bytes of text in `w0..w3` (little-endian, zero-padded).
pub mod console {
    pub const WRITE: u16 = 0x0301;
    /// End-of-stream on a stream endpoint (pipes): sent by a writer's
    /// `Runtime::exit` before it dies; readers stop there, sink-style
    /// consumers (the console) ignore it.
    pub const EOF: u16 = 0x0302;
    /// Text bytes per console message.
    pub const TEXT_BYTES: usize = 32;
}

/// Pack up to [`console::TEXT_BYTES`] bytes of text into console message
/// words (little-endian, zero-padded). Extra bytes are ignored.
pub fn pack_console_text(text: &[u8]) -> [u64; 4] {
    let mut words = [0u64; 4];
    for (i, b) in text.iter().take(console::TEXT_BYTES).enumerate() {
        words[i / 8] |= (*b as u64) << ((i % 8) * 8);
    }
    words
}

/// VFS OPEN flags (`proto.rs`).
pub mod vfs_open {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    /// Truncate an existing file on open (O_TRUNC).
    pub const TRUNC: u32 = 1 << 3;
    /// Create the file if it does not exist (O_CREAT).
    pub const CREATE: u32 = 1 << 4;
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
    /// Mint a pipe (an endpoint pair): reply carries descriptors 0 = read
    /// end, 1 = write end (both `SEND|RECV|GRANT` downgraded to taste).
    pub const PIPE: u16 = 0x0117;
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
