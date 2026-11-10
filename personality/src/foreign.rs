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
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const WRITEV: u64 = 20;
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
    pub const OPENAT: u64 = 257;
    pub const READLINKAT: u64 = 267;
    pub const GETRANDOM: u64 = 318;
    pub const GETDENTS64: u64 = 217;
    pub const FUTEX: u64 = 202;
    pub const LSEEK: u64 = 8;
    pub const GETUID: u64 = 102;
    pub const GETGID: u64 = 104;
    pub const GETEUID: u64 = 107;
    pub const GETEGID: u64 = 108;
    pub const NANOSLEEP: u64 = 35;
    pub const RT_SIGRETURN: u64 = 15;
    pub const CLOCK_GETTIME: u64 = 228;
}

/// `arch_prctl` sub-codes.
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

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
    /// Linux `getdents64`: fill `out` with linux_dirent64 records (the host
    /// formats them from its directory source). Returns bytes written.
    fn getdents(&mut self, fd: i32, out: &mut [u8]) -> i64;
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
    /// Map `len` anonymous zeroed bytes; returns the base address or a
    /// negative errno (libc uses this for the heap/TLS/thread stacks).
    fn mmap_anon(&mut self, len: usize) -> i64;
    /// Set this thread's `IA32_FS_BASE` (TLS); `arch_prctl(ARCH_SET_FS)`.
    fn set_tls(&mut self, base: u64) -> i64;
    /// `openat(dirfd, path, flags, mode)` -> fd or negative errno. `path` is
    /// the NUL-trimmed guest string.
    fn openat(&mut self, dirfd: i32, path: &[u8], flags: u32) -> i64;
    /// `readlinkat(dirfd, path, buf)` -> the link target into `out`, or a
    /// negative errno.
    fn readlink(&mut self, path: &[u8], out: &mut [u8]) -> i64;
    /// Fill `out` with entropy (`getrandom`).
    fn getrandom(&mut self, out: &mut [u8]) -> i64;
}

/// `mmap` `flags` bit: anonymous (not file-backed).
pub const MAP_ANONYMOUS: u64 = 0x20;

/// Read a NUL-terminated guest string at `addr` into `out` (bounded); returns
/// the length (without the NUL).
fn read_cstr<H: Host>(host: &mut H, addr: u64, out: &mut [u8]) -> usize {
    let n = host.mem_read(addr, out);
    if n < 0 {
        return 0;
    }
    let n = n as usize;
    out[..n].iter().position(|&b| b == 0).unwrap_or(n)
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
        linux::GETDENTS64 => {
            let want = (args[2] as usize).min(4096);
            let mut buf = [0u8; 4096];
            let r = host.getdents(args[0] as i32, &mut buf[..want]);
            if r < 0 {
                return Action::Return(r);
            }
            let w = host.mem_write(args[1], &buf[..r as usize]);
            Action::Return(if w < 0 { EFAULT } else { r })
        }
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
        linux::ARCH_PRCTL => match args[0] {
            // Set the thread's TLS base (musl/libc startup does this before
            // any %fs access). The kernel applies it via Thread::SET_TLS.
            ARCH_SET_FS => Action::Return(host.set_tls(args[1])),
            ARCH_SET_GS => Action::Return(0), // no %gs use in v0 userspace
            ARCH_GET_FS | ARCH_GET_GS => Action::Return(0),
            _ => Action::Return(EINVAL),
        },
        // musl's stdio `__stdio_write` emits `writev` (gather of up to three
        // iovecs: the FILE's pending buffer + the new data). iov is an array
        // of { u64 base, u64 len }.
        linux::WRITEV => {
            let fd = args[0] as i32;
            let iov = args[1];
            let cnt = (args[2] as usize).min(64);
            let mut total = 0i64;
            for i in 0..cnt {
                let mut e = [0u8; 16];
                if host.mem_read(iov + (i as u64) * 16, &mut e) < 0 {
                    return Action::Return(EFAULT);
                }
                let base = u64::from_le_bytes([e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]]);
                let len = u64::from_le_bytes([e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]])
                    as usize;
                if len == 0 {
                    continue;
                }
                let mut buf = [0u8; 4096];
                let want = len.min(buf.len());
                let r = host.mem_read(base, &mut buf[..want]);
                if r < 0 {
                    return Action::Return(EFAULT);
                }
                let w = host.write_fd(fd, &buf[..r as usize]);
                if w < 0 {
                    return Action::Return(if total > 0 { total } else { w });
                }
                total += w;
            }
            Action::Return(total)
        }
        // Legacy `open(2)` (musl's `open` uses this on x86_64): path is arg0
        // (no dirfd), flags arg1, mode arg2 — dirfd is implicitly AT_FDCWD.
        linux::OPEN => {
            let mut p = [0u8; 256];
            let n = read_cstr(host, args[0], &mut p);
            Action::Return(host.openat(-100, &p[..n], args[1] as u32))
        }
        linux::OPENAT => {
            let mut p = [0u8; 256];
            let n = read_cstr(host, args[1], &mut p);
            Action::Return(host.openat(args[0] as i32, &p[..n], args[2] as u32))
        }
        linux::READLINKAT => {
            let mut p = [0u8; 256];
            let n = read_cstr(host, args[1], &mut p);
            let mut out = [0u8; 256];
            let want = (args[3] as usize).min(out.len());
            let r = host.readlink(&p[..n], &mut out[..want]);
            if r < 0 {
                return Action::Return(r);
            }
            let w = host.mem_write(args[2], &out[..r as usize]);
            Action::Return(if w < 0 { EFAULT } else { r })
        }
        linux::GETRANDOM => {
            let mut b = [0u8; 256];
            let want = (args[1] as usize).min(b.len());
            let r = host.getrandom(&mut b[..want]);
            if r < 0 {
                return Action::Return(r);
            }
            let w = host.mem_write(args[0], &b[..r as usize]);
            Action::Return(if w < 0 { EFAULT } else { r })
        }
        // Single-threaded v0: futexes/sleeps are no-ops (no contention).
        linux::FUTEX => Action::Return(0),
        linux::NANOSLEEP => Action::Return(0),
        linux::RT_SIGRETURN => Action::Return(0),
        linux::GETUID | linux::GETGID | linux::GETEUID | linux::GETEGID => Action::Return(0),
        linux::CLOCK_GETTIME => {
            let ts = [0u64; 2];
            let mut bytes = [0u8; 16];
            for (i, v) in ts.iter().enumerate() {
                bytes[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            if host.mem_write(args[1], &bytes) < 0 {
                Action::Return(EFAULT)
            } else {
                Action::Return(0)
            }
        }
        linux::LSEEK => Action::Return(0), // offset 0 (v0 fds are stream-like)
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
        linux::MMAP => {
            // Anonymous mappings (libc heap/TLS/stacks) are backed by the
            // Host allocator; file/device mappings are not supported yet.
            let flags = args[3];
            if flags & MAP_ANONYMOUS != 0 {
                Action::Return(host.mmap_anon(args[1] as usize))
            } else {
                Action::Return(ENOSYS)
            }
        }
        // Deliberately unimplemented: device fds need a device layer — refuse
        // cleanly so the emulated program sees a normal error, not garbage.
        linux::IOCTL => Action::Return(ENOSYS),
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
        mmap_bump: u64,
        tls: u64,
    }
    impl Mock {
        fn new() -> Self {
            Mock {
                mem: [0u8; 4096],
                out: [0u8; 256],
                out_len: 0,
                closed: -1,
                break_: 0x1000,
                mmap_bump: 0x1000_0000,
                tls: 0,
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
        fn getdents(&mut self, _fd: i32, out: &mut [u8]) -> i64 {
            // One fake entry: ino=7, off=1, reclen=24, type=8(DT_REG), "a\0".
            if out.len() < 24 {
                return 0;
            }
            out[..24].fill(0);
            out[0..8].copy_from_slice(&7u64.to_le_bytes());
            out[8..16].copy_from_slice(&1u64.to_le_bytes());
            out[16..18].copy_from_slice(&24u16.to_le_bytes());
            out[18] = 8;
            out[19] = b'a';
            24
        }
        fn getpid(&mut self) -> i64 {
            42
        }
        fn gettid(&mut self) -> i64 {
            7
        }
        fn brk(&mut self, requested: u64) -> i64 {
            if (0x1000..0x2000).contains(&requested) {
                self.break_ = requested;
            }
            self.break_ as i64
        }
        fn mmap_anon(&mut self, len: usize) -> i64 {
            let base = self.mmap_bump;
            self.mmap_bump += (len as u64).max(4096);
            base as i64
        }
        fn set_tls(&mut self, base: u64) -> i64 {
            self.tls = base;
            0
        }
        fn openat(&mut self, _dirfd: i32, _path: &[u8], _flags: u32) -> i64 {
            3
        }
        fn readlink(&mut self, _path: &[u8], out: &mut [u8]) -> i64 {
            let s = b"/proc/self/exe";
            let n = s.len().min(out.len());
            out[..n].copy_from_slice(&s[..n]);
            n as i64
        }
        fn getrandom(&mut self, out: &mut [u8]) -> i64 {
            for (i, b) in out.iter_mut().enumerate() {
                *b = 0x30 + i as u8;
            }
            out.len() as i64
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
    fn writev_writes_all_iovecs() {
        let mut m = Mock::new();
        m.mem[16..19].copy_from_slice(b"abc");
        m.mem[32..34].copy_from_slice(b"de");
        // iovec[0] = {base 16, len 3}; iovec[1] = {base 32, len 2} at 64.
        m.mem[64..72].copy_from_slice(&16u64.to_le_bytes());
        m.mem[72..80].copy_from_slice(&3u64.to_le_bytes());
        m.mem[80..88].copy_from_slice(&32u64.to_le_bytes());
        m.mem[88..96].copy_from_slice(&2u64.to_le_bytes());
        let a = dispatch(linux::WRITEV, [1, 64, 2, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(5));
        assert_eq!(&m.out[..5], b"abcde");
    }

    #[test]
    fn getdents_writes_dirent64() {
        let mut m = Mock::new();
        let a = dispatch(linux::GETDENTS64, [3, 64, 128, 0, 0, 0], &mut m);
        assert_eq!(a, Action::Return(24));
        assert_eq!(m.mem[64], 7); // d_ino
        assert_eq!(m.mem[72], 1); // d_off
        assert_eq!(u16::from_le_bytes([m.mem[80], m.mem[81]]), 24); // d_reclen
        assert_eq!(m.mem[82], 8); // d_type = DT_REG
        assert_eq!(m.mem[83], b'a'); // d_name
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
        assert_eq!(dispatch(0xDEAD, [0; 6], &mut m), Action::Return(ENOSYS));
    }

    #[test]
    fn mmap_anonymous_allocates_file_returns_enosys() {
        let mut m = Mock::new();
        // mmap(0, len, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) -> an address.
        let flags = MAP_ANONYMOUS | 0x02;
        let a = dispatch(linux::MMAP, [0, 8192, 3, flags, u64::MAX, 0], &mut m);
        assert_eq!(a, Action::Return(0x1000_0000));
        // A second mapping advances the bump allocator.
        let b = dispatch(linux::MMAP, [0, 4096, 3, flags, u64::MAX, 0], &mut m);
        assert_eq!(b, Action::Return(0x1000_2000));
        // Non-anonymous (file) mappings are not supported yet.
        let f = dispatch(linux::MMAP, [0, 4096, 3, 0x02, 3, 0], &mut m);
        assert_eq!(f, Action::Return(ENOSYS));
    }

    #[test]
    fn tls_openat_getrandom() {
        let mut m = Mock::new();
        // arch_prctl(ARCH_SET_FS, base) sets the thread TLS base.
        assert_eq!(
            dispatch(
                linux::ARCH_PRCTL,
                [ARCH_SET_FS, 0x7f00_1000, 0, 0, 0, 0],
                &mut m
            ),
            Action::Return(0)
        );
        assert_eq!(m.tls, 0x7f00_1000);
        // openat(AT_FDCWD, "/x", 0) -> fd 3 (mock).
        m.mem[200] = b'/';
        m.mem[201] = b'x';
        m.mem[202] = 0;
        assert_eq!(
            dispatch(linux::OPENAT, [(-100i64) as u64, 200, 0, 0, 0, 0], &mut m),
            Action::Return(3)
        );
        // getrandom(buf, 4) fills 4 bytes.
        assert_eq!(
            dispatch(linux::GETRANDOM, [300, 4, 0, 0, 0, 0], &mut m),
            Action::Return(4)
        );
        assert_eq!(&m.mem[300..304], &[0x30, 0x31, 0x32, 0x33]);
        // readlinkat writes the target.
        assert_eq!(
            dispatch(
                linux::READLINKAT,
                [(-100i64) as u64, 200, 400, 32, 0, 0],
                &mut m
            ),
            Action::Return(14)
        );
        assert_eq!(&m.mem[400..414], b"/proc/self/exe");
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
