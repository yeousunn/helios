//! Runtime: turns a bootstrap package into a usable POSIX-ish process.
//!
//! The launcher (PS, design §2.3) delivers `[aspace, thread, region, session
//! x4, ps_ep]` plus the optional tail; for regular processes the caller-
//! supplied VFS service endpoint arrives as `optional[0]`. The heap must be
//! initialized by the binary before `Runtime::new` (the global allocator is
//! per-binary).

use ipc::Message;
use sdk::bootstrap::BootstrapPackage;
use sdk::syscall::{Handle, RawSyscalls, Status, Syscalls};

use crate::posix::ENOENT;
use crate::vfs::VfsClient;

/// A live personality process: its package, a connected VFS client, and the
/// caller-supplied stdout endpoint (package `optional[2]`, design §2.3).
pub struct Runtime {
    pub package: BootstrapPackage,
    pub vfs: VfsClient,
    stdout: Option<Handle>,
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
        let stdout = package
            .optional
            .get(2)
            .copied()
            .flatten()
            .map(|cs| cs.handle())
            .filter(|h| *h != 0);
        Ok(Self {
            package,
            vfs,
            stdout,
        })
    }

    /// Write text to the process's stdout (the caller-supplied console
    /// endpoint): up to 32 bytes per message, little-endian packed
    /// (`sdk::methods::console`). No-op when the launcher supplied none.
    pub fn write_stdout<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        text: &[u8],
    ) -> Result<(), Status> {
        let Some(ep) = self.stdout else {
            return Ok(());
        };
        for chunk in text.chunks(sdk::methods::console::TEXT_BYTES) {
            let mut m = Message::new(sdk::methods::console::WRITE);
            m.words = sdk::methods::pack_console_text(chunk);
            sys.send(ep, &m)?;
        }
        Ok(())
    }
}

/// Terminate the process with `status` (never returns).
pub fn exit<R: RawSyscalls>(sys: &mut Syscalls<R>, status: i32) -> ! {
    sys.exit(status)
}
