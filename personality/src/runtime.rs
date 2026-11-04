//! Runtime: turns a bootstrap package into a usable POSIX-ish process.
//!
//! The launcher (PS, design §2.3) delivers `[aspace, thread, region, session
//! x4, ps_ep]` plus the optional tail; for regular processes the caller-
//! supplied VFS service endpoint arrives as `optional[0]`. The heap must be
//! initialized by the binary before `Runtime::new` (the global allocator is
//! per-binary).

use sdk::bootstrap::BootstrapPackage;
use sdk::syscall::{RawSyscalls, Status, Syscalls};

use crate::posix::ENOENT;
use crate::vfs::VfsClient;

/// A live personality process: its package, and a connected VFS client.
pub struct Runtime {
    pub package: BootstrapPackage,
    pub vfs: VfsClient,
}

impl Runtime {
    /// Connect to the VFS using the package's `optional[0]` service endpoint
    /// and one of the four session notifications.
    pub fn new<R: RawSyscalls>(
        sys: &mut Syscalls<R>,
        package: BootstrapPackage,
    ) -> Result<Self, Status> {
        let vfs_ep = package
            .optional
            .first()
            .copied()
            .flatten()
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(ENOENT)?;
        let session = package.session_notifications[0];
        let vfs = VfsClient::connect(sys, package.aspace, package.region, vfs_ep, session)?;
        Ok(Self { package, vfs })
    }
}

/// Terminate the process with `status` (never returns).
pub fn exit<R: RawSyscalls>(sys: &mut Syscalls<R>, status: i32) -> ! {
    sys.exit(status)
}
