//! Linux-syscall emulation core (the musl / unmodified-binary compatibility
//! layer). The kernel (ADR-044) routes a *foreign-flagged* thread's raw
//! `syscall` to a personality emulator as a `FOREIGN_SYSCALL` call carrying
//! the number and the register frame; the emulator decodes it here and
//! performs native Helios operations through a [`Host`], then replies with
//! the Linux result (negative errno on failure, as Linux does).
//!
//! This module is pure logic — no kernel or IPC types — so it is unit-tested
//! on the host with a mock [`Host`]. The production `Host` is implemented over
//! [`crate::runtime::Runtime`] (stdio over the console endpoint, fds over the
//! VFS client, the heap over the region). Memory args (pointers) are read and
//! written through `Host::mem_*`: the emulator and the emulated image share an
//! address space in the v0 model, so a pointer is just an address.

/// Linux x86_64 syscall numbers (a starter subset; `linux/syscall_64.tbl`).
pub mod linux {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const BRK: u64 = 12;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const GETPID: u64 = 39;
    pub const EXIT: u64 = 60;
    pub const UNAME: u64 = 63;
    pub const GETTID: u64 = 186;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const EXIT_GROUP: u64 = 231;
    pub const SET_ROBUST_LIST: u64 = 273;
    pub const RSEQ: u64 = 334;
}

/// Linux errno values (returned negated, as Linux does).
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const EBADF: i64 = -9;
pub const ENOSYS: i64 = -38;
pub const EPERM: i64 = -1;

/// The emulator's decision for one foreign syscall.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Reply to the parked foreign thread with this value (Linux convention:
    /// `>= 0` success, `< 0` = `-errno`).
    Return(i64),
    /// Terminate the emulated process with this status (`exit`/`exit_group`).
    Exit(i32),
}

/// Native operations the emulator performs on behalf of the emulated binary.
/// Implemented over the personality `Runtime` in production; recorded by a
/// mock in tests.
pub trait Host {
    /// Read `out.len()` bytes from emulated address `addr`; returns the count
    /// read (`>= 0`) or a negative errno.
    fn mem_read(&mut self, addr: u64, out: &mut [u8]) -> i64;
    /// Write `data` to emulated address `addr`; returns the count (`>= 0`) or
    /// a negative errno.
    fn mem_write(&mut self, addr: u64, data: &[u8]) -> i64;
    /// Write to file descriptor `fd`.
    fn write_fd(&mut self, fd: i32, data: &[u8]) -> i64;
    /// Read from file descriptor `fd` into `out`.
    fn read_fd(&mut self, fd: i32, out: &mut [u8]) -> i64;
    /// Close a file descriptor.
    fn close_fd(&mut self, fd: i32) -> i64;
    /// The emulated process id.
    fn getpid(&mut self) -> i64;
    /// The emulated thread id.
    fn gettid(&mut self) -> i64;
    /// Adjust the program break; returns the (possibly unchanged) break.
    fn brk(&mut self, requested: u64) -> i64;
}

/// Decode one foreign syscall and act via `host`. `args` are the six integer
/// arguments in Linux order (rdi, rsi, rdx, r10, r8, r9).
pub fn dispatch<H: Host>(num: u64, args: [u64; 6], host: &mut H) -> Action {
    match num {
        linux::WRITE => {
            let fd = args[0] as i32;
            let len = args[2] as usize;
            let mut buf = [0u8; 4096];
            let want = len.min(buf.len());
            let r = host.mem_read(args[1], &mut buf[..want]);
            if r < 0 {
                return Action::Return(EFAULT);
            }
            Action::Return(host.write_fd(fd, &buf[..r as usize]))
        }
        linux::READ => {
            let fd = args[0] as i32;
            let want = (args[2] as usize).min(4096);
            let mut buf = [0u8; 4096];
            let r = host.read_fd(fd, &mut buf[..want]);
            if r < 0 {
                return Action::Return(r);
            }
            let w = host.mem_write(args[1], &buf[..r as usize]);
            if w < 0 {
                return Action::Return(EFAULT);
            }
            Action::Return(r)
        }
        linux::CLOSE => Action::Return(host.close_fd(args[0] as i32)),
        linux::GETPID => Action::Return(host.getpid()),
        linux::GETTID => Action::Return(host.gettid()),
        linux::SET_TID_ADDRESS => {
            // Record the tid at *args[0] (best effort) and return it.
            let tid = host.gettid();
            let bytes = (tid as i32).to_le_bytes();
            let _ = host.mem_write(args[0], &bytes);
            Action::Return(tid)
        }
        linux::BRK => Action::Return(host.brk(args[0])),
        linux::EXIT | linux::EXIT_GROUP => Action::Exit(args[0] as i32),
        linux::ARCH_PRCTL => {
            // ARCH_SET_FS(0x1002)/ARCH_SET_GS(0x1001)/GET_FS/GET_GS: v0 has no
            // segment-base support for the emulated image — accept as a no-op.
            Action::Return(0)
        }
        linux::UNAME => {
            // struct utsname: six 65-byte NUL-terminated fields.
            let mut u = [0u8; 65 * 6];
            let fields: [&[u8]; 6] = [b"Linux", b"helios", b"0.1.0", b"helios", b"x86_64", b""];
            for (i, f) in fields.iter().enumerate() {
                let off = i * 65;
                let n = f.len().min(64);
                u[off..off + n].copy_from_slice(&f[..n]);
            }
            if host.mem_write(args[0], &u) < 0 {
                return Action::Return(EFAULT);
            }
            Action::Return(0)
        }
        // Accepted no-ops that unmodified startup sequences issue. They must
        // succeed or libc bails before main.
        linux::RT_SIGACTION | linux::RT_SIGPROCMASK | linux::MPROTECT => Action::Return(0),
        linux::SET_ROBUST_LIST | linux::RSEQ => Action::Return(0),
        // Deliberately unimplemented: a real implementation needs the AS
        // allocator (mmap) / device fds (ioctl) — refuse cleanly so the
        // emulated program sees a normal error rather than garbage.
        linux::MMAP | linux::IOCTL => Action::Return(ENOSYS),
        _ => Action::Return(ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records calls and returns canned values; a 4 KiB scratch "memory".
    struct Mock {
        mem: [u8; 4096],
        out: [u8; 256],
        out_len: usize,
        closed: i32,
        break_: u64,
    }
    impl Mock {
        fn new() -> Self {
            Mock {
                mem: [0u8; 4096],
                out: [0u8; 256],
                out_len: 0,
                closed: -1,
                break_: 0x1000,
            }
        }
    }
    impl Host for Mock {
        fn mem_read(&mut self, addr: u64, out: &mut [u8]) -> i64 {
            let a = addr as usize;
            if a + out.len() > self.mem.len() {
                return EFAULT;
            }
            out.copy_from_slice(&self.mem[a..a + out.len()]);
            out.len() as i64
        }
        fn mem_write(&mut self, addr: u64, data: &[u8]) -> i64 {
            let a = addr as usize;
            if a + data.len() > self.mem.len() {
                return EFAULT;
            }
            self.mem[a..a + data.len()].copy_from_slice(data);
            data.len() as i64
        }
        fn write_fd(&mut self, _fd: i32, data: &[u8]) -> i64 {
            let n = data.len().min(self.out.len() - self.out_len);
            self.out[self.out_len..self.out_len + n].copy_from_slice(&data[..n]);
            self.out_len += n;
            n as i64
        }
        fn read_fd(&mut self, _fd: i32, out: &mut [u8]) -> i64 {
            for (i, b) in out.iter_mut().enumerate() {
                *b = i as u8;
            }
            out.len() as i64
        }
        fn close_fd(&mut self, fd: i32) -> i64 {
            self.closed = fd;
            0
        }
        fn getpid(&mut self) -> i64 {
            42
        }
        fn gettid(&mut self) -> i64 {
            7
        }
        fn brk(&mut self, requested: u64) -> i64 {
            if requested >= 0x1000 && requested < 0x2000 {
                self.break_ = requested;
            }
            self.break_ as i64
        }
    }

    #[test]
    fn write_reads_guest_memory_then_writes_fd() {
        let mut m = Mock::new();
        m.mem[16..21].copy_from_slice(b"hello");
        let a = dispatch(linux::WRITE, [1, 16, 5, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(5));
        assert_eq!(&m.out[..5], b"hello");
    }

    #[test]
    fn write_bad_pointer_is_efault() {
        let mut m = Mock::new();
        let a = dispatch(linux::WRITE, [1, 100_000, 5, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(EFAULT));
    }

    #[test]
    fn read_writes_guest_memory() {
        let mut m = Mock::new();
        let a = dispatch(linux::READ, [0, 64, 4, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(4));
        assert_eq!(&m.mem[64..68], &[0, 1, 2, 3]);
    }

    #[test]
    fn exit_and_exit_group_terminate() {
        assert_eq!(
            dispatch(linux::EXIT, [3, 0, 0, 0, 0, 0], &mut Mock::new()),
            Action::Exit(3)
        );
        assert_eq!(
            dispatch(linux::EXIT_GROUP, [9, 0, 0, 0, 0, 0], &mut Mock::new()),
            Action::Exit(9)
        );
    }

    #[test]
    fn pid_tid_and_set_tid_address() {
        let mut m = Mock::new();
        assert_eq!(dispatch(linux::GETPID, [0; 6], &mut m), Action::Return(42));
        assert_eq!(dispatch(linux::GETTID, [0; 6], &mut m), Action::Return(7));
        // set_tid_address writes the tid to *addr and returns it.
        let a = dispatch(linux::SET_TID_ADDRESS, [32, 0, 0, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(7));
        assert_eq!(&m.mem[32..36], &7i32.to_le_bytes());
    }

    #[test]
    fn brk_and_uname_and_noops() {
        let mut m = Mock::new();
        assert_eq!(
            dispatch(linux::BRK, [0x1500, 0, 0, 0, 0, 0], &mut m),
            Action::Return(0x1500)
        );
        assert_eq!(
            dispatch(linux::UNAME, [100, 0, 0, 0, 0, 0], &mut m),
            Action::Return(0)
        );
        assert_eq!(&m.mem[100..105], b"Linux");
        assert_eq!(&m.mem[100 + 65 * 4..100 + 65 * 4 + 6], b"x86_64");
        // Startup no-ops succeed; unimplemented calls refuse with ENOSYS.
        assert_eq!(
            dispatch(linux::RT_SIGACTION, [0; 6], &mut m),
            Action::Return(0)
        );
        assert_eq!(dispatch(linux::MPROTECT, [0; 6], &mut m), Action::Return(0));
        assert_eq!(
            dispatch(linux::MMAP, [0; 6], &mut m),
            Action::Return(ENOSYS)
        );
        assert_eq!(dispatch(0xDEAD, [0; 6], &mut m), Action::Return(ENOSYS));
    }

    #[test]
    fn close_and_arch_prctl() {
        let mut m = Mock::new();
        assert_eq!(
            dispatch(linux::CLOSE, [5, 0, 0, 0, 0, 0], &mut m),
            Action::Return(0)
        );
        assert_eq!(m.closed, 5);
        assert_eq!(
            dispatch(linux::ARCH_PRCTL, [0x1002, 0, 0, 0, 0, 0], &mut m),
            Action::Return(0)
        );
    }
}
