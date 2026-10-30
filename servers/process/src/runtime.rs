//! What the process server needs from its environment, abstracted for host
//! testing. The real implementation (in `sdk/`, once the kernel is ready)
//! wraps the syscalls from `sdk/docs/syscall-abi.md`; mocks live in tests.

use alloc::vec::Vec;

use ipc::{Message, Rights};

use crate::proto::Status;

pub type Handle = u32;

/// Address-space mapping flags, wire-compatible with syscall-abi §7
/// `AddressSpace::MAP`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MapFlags(pub u32);

impl MapFlags {
    pub const R: Self = Self(1 << 0);
    pub const W: Self = Self(1 << 1);
    pub const X: Self = Self(1 << 2);
    pub const COW: Self = Self(1 << 3);
    pub const ANON: Self = Self(1 << 4);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Kernel object operations (`invoke` dispatch, syscall-abi §7) and the
/// syscalls the server issues directly. Handles are in the server's own
/// capability space.
pub trait KernelOps {
    fn new_endpoint(&mut self) -> Result<Handle, Status>;
    fn new_notification(&mut self) -> Result<Handle, Status>;
    fn new_address_space(&mut self) -> Result<Handle, Status>;

    /// `Factory::NEW_THREAD` (ADR-005, extended by ADR-009): optional fault and
    /// bootstrap endpoints; the bootstrap endpoint is installed into the new
    /// process at handle 1.
    fn new_thread(
        &mut self,
        aspace: Handle,
        entry: u64,
        stack_top: u64,
        priority: u8,
        fault_ep: Option<Handle>,
        bootstrap_ep: Option<Handle>,
    ) -> Result<Handle, Status>;

    fn bind_death_notification(
        &mut self,
        thread: Handle,
        notif: Option<Handle>,
    ) -> Result<(), Status>;

    /// `Region::CARVE`: allocate a frame from a region capability.
    fn carve_frame(&mut self, region: Handle, len: u64, align: u64) -> Result<Handle, Status>;

    fn map_frame(
        &mut self,
        aspace: Handle,
        frame: Handle,
        vaddr: u64,
        flags: MapFlags,
    ) -> Result<(), Status>;

    fn set_fault_pool(&mut self, aspace: Handle, region: Handle) -> Result<(), Status>;

    fn mint_here(&mut self, src: Handle, rights: Rights) -> Result<Handle, Status>;

    fn kill_thread(&mut self, thread: Handle) -> Result<(), Status>;

    fn signal(&mut self, notif: Handle, mask: u64) -> Result<(), Status>;
}

/// Message-passing surface (syscall-abi §3). `send` with the ADR-009
/// `REPLY_CAP` sentinel is the reply-only escape hatch; the reply path for
/// served requests is `reply_recv`.
pub trait Transport {
    fn recv(&mut self, on: Handle) -> Result<Message, Status>;
    fn reply(&mut self, msg: &Message) -> Result<(), Status>;
    fn reply_recv(&mut self, on: Handle, msg: &Message) -> Result<Message, Status>;
    fn call(&mut self, on: Handle, msg: &Message) -> Result<Message, Status>;
    fn send(&mut self, on: Handle, msg: &Message) -> Result<(), Status>;
}

/// One mapped segment of a program image.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment {
    pub frame: Handle,
    pub vaddr: u64,
    pub len: u64,
    pub flags: MapFlags,
}

/// A program image ready to be mapped into a fresh address space.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadedImage {
    pub segments: Vec<Segment>,
    pub entry: u64,
    pub stack_size: u64,
}

/// Resolves a program (by name, from the connection's window) into frames.
/// The real implementation reads through the PS's VFS connection; the mock
/// returns a canned image.
pub trait ProgramLoader {
    fn load(&mut self, program: &[u8]) -> Result<LoadedImage, Status>;
}

/// Reads bytes out of a connection window. Windows are frames mapped into the
/// server's address space — this is a memory read, not a kernel operation; the
/// trait exists so the serving logic stays host-testable.
pub trait Windows {
    fn read(&mut self, window: Handle, span: crate::proto::Span) -> Result<Vec<u8>, Status>;
}
