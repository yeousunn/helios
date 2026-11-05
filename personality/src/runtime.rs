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
use crate::ps::PsClient;
use crate::vfs::VfsClient;

/// A live personality process: its package, connected VFS and PS clients, and
/// the caller-supplied stdout endpoint (package `optional[2]`, design §2.3).
pub struct Runtime {
    pub package: BootstrapPackage,
    pub vfs: VfsClient,
    pub ps: PsClient,
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
        // The process server connection uses its own session notification and
        // its own window pair (the fixed package slot carries its endpoint).
        let ps = PsClient::connect(
            sys,
            package.aspace,
            package.region,
            package.process_server_ep,
            package.session_notifications[1],
            package.pid,
        )?;
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
            ps,
            stdout,
        })
    }

    /// The stdout endpoint handle (if the launcher supplied one), for passing
    /// onward to spawned children.
    pub fn stdout_handle(&self) -> Option<Handle> {
        self.stdout
    }

    /// The stdin endpoint handle (package `optional[1]`), if any.
    pub fn stdin_handle(&self) -> Option<Handle> {
        self.package
            .optional
            .get(1)
            .copied()
            .flatten()
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
    }

    /// Exit, first signalling end-of-stream on stdout so pipe readers stop
    /// (`console::EOF`; sinks like the console ignore it).
    pub fn exit<R: RawSyscalls>(&mut self, sys: &mut Syscalls<R>, status: i32) -> ! {
        if let Some(out) = self.stdout {
            let _ = sys.send(out, &Message::new(sdk::methods::console::EOF));
        }
        crate::runtime::exit(sys, status)
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
