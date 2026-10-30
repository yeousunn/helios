//! What the VFS server needs from its environment, abstracted for host
//! testing (mirrors `servers/process::runtime`). The real implementation will
//! wrap the SDK syscalls once the process/server binaries are brought up.

use alloc::vec::Vec;

use crate::proto::{Span, Status};

pub type Handle = u32;

pub trait VfsKernel {
    fn new_endpoint(&mut self) -> Result<Handle, Status>;
    /// Monotonic nanosecond clock for mtime stamps (the timer server lands in
    /// Phase 2; v0 mocks a counter).
    fn now_ns(&mut self) -> u64;
}

pub trait Transport {
    fn recv(&mut self, on: Handle) -> Result<ipc::Message, Status>;
    fn reply(&mut self, msg: &ipc::Message) -> Result<(), Status>;
    fn reply_recv(&mut self, on: Handle, msg: &ipc::Message) -> Result<ipc::Message, Status>;
    fn send(&mut self, on: Handle, msg: &ipc::Message) -> Result<(), Status>;
}

/// Window access: frames mapped into the server's address space (a memory
/// operation, not a kernel operation). VFS reads request arguments and writes
/// results, so it needs both directions.
pub trait Windows {
    fn read(&mut self, window: Handle, span: Span) -> Result<Vec<u8>, Status>;
    fn write(&mut self, window: Handle, span: Span, data: &[u8]) -> Result<(), Status>;
}
