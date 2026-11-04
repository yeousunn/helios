//! VFS client for personality processes: one connection per process, a local
//! fd table multiplexing file handles (design §1.10: "the POSIX personality
//! keeps fds in its own process").
//!
//! Wire format: `servers/vfs/src/proto.rs` (mirrored labels in
//! `sdk::methods::vfs`). The client owns the connection's arg/result windows
//! (`layout::{ARG,RESULT}_WINDOW_VA`), carves the two frame caps from the
//! process's package region, and speaks the request/reply shapes directly.

use ipc::{status, CapSlot, Message, Rights};
use sdk::methods;
use sdk::syscall::{Handle, RawSyscalls, Status, Syscalls};

use crate::layout::{ARG_WINDOW_VA, RESULT_WINDOW_VA};
use crate::posix::{EBADF, EINVAL, O_CREAT};

/// Local fd table size (v0).
pub const MAX_FDS: usize = 16;
/// Connection window size (design §1.3: 4 KiB each).
pub const WINDOW: usize = 4096;

#[derive(Clone, Copy)]
struct Fd {
    handle: u64,
    offset: u64,
}

/// A connected VFS client with a local fd table.
pub struct VfsClient {
    conn: Handle,
    root: u64,
    fds: [Option<Fd>; MAX_FDS],
}

impl VfsClient {
    /// Connect to the VFS service endpoint: carve + map the two windows into
    /// our own AS, then `CONNECT` with the session notification from the
    /// package (regular processes have no Factory: one session cap per
    /// server connection, design §1.5/§2.3).
    pub fn connect<R: RawSyscalls>(
        sys: &mut Syscalls<R>,
        aspace: Handle,
        region: Handle,
        vfs_ep: Handle,
        session: Handle,
    ) -> Result<Self, Status> {
        let mut frames = [0 as Handle; 2];
        for (i, va) in [ARG_WINDOW_VA, RESULT_WINDOW_VA].iter().enumerate() {
            let mut carve = Message::new(methods::region::CARVE);
            carve.words[0] = WINDOW as u64;
            carve.words[1] = WINDOW as u64;
            let reply = sys.invoke(region, &carve)?;
            let frame = reply.words[0] as Handle;
            if frame == 0 {
                return Err(status::ENOMEM);
            }
            frames[i] = frame;

            let mut map = Message::new(methods::aspace::MAP);
            map.tag = map.tag.with_caps(1);
            map.words[0] = *va;
            map.words[1] = 0b011; // R | W
            let _ = map.set_descriptor(0, CapSlot::pack(frame, Rights::READ.union(Rights::WRITE)));
            sys.invoke(aspace, &map)?;
        }

        let mut connect = Message::new(methods::vfs::CONNECT);
        connect.tag = connect.tag.with_caps(3);
        connect.words[0] = 1; // protocol version
        let _ = connect.set_descriptor(0, CapSlot::pack(session, Rights::SIGNAL));
        let _ = connect.set_descriptor(
            1,
            CapSlot::pack(frames[0], Rights::READ.union(Rights::WRITE)),
        );
        let _ = connect.set_descriptor(
            2,
            CapSlot::pack(
                frames[1],
                Rights::READ.union(Rights::WRITE).union(Rights::MAP),
            ),
        );
        let reply = sys.call(vfs_ep, &connect)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let conn = reply
            .descriptor(0)
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(status::EBADCAP)?;
        let root = reply.words[2];
        if root == 0 {
            return Err(status::EBADCAP);
        }
        Ok(Self {
            conn,
            root,
            fds: [None; MAX_FDS],
        })
    }

    /// Open (or create, with [`O_CREAT`]) `name` under the connection root.
    /// Returns a local fd.
    pub fn open<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        name: &[u8],
        flags: u32,
    ) -> Result<u32, Status> {
        if name.is_empty() || name.len() > WINDOW {
            return Err(EINVAL);
        }
        let slot = self.fds.iter().position(|f| f.is_none()).ok_or(EMFILE)?;
        // SAFETY: the arg window is mapped R|W into this process's AS by
        // `connect` (frames carved + MAP-invoked before use).
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), ARG_WINDOW_VA as *mut u8, name.len());
        }
        let mut req = Message::new(if flags & O_CREAT != 0 {
            methods::vfs::CREATE
        } else {
            methods::vfs::OPEN
        });
        // POSIX convention: O_RDONLY == 0 means "read", not "no access" —
        // translate to the VFS's explicit access flags (the server rejects a
        // request with neither READ nor WRITE).
        let vfs_flags = if flags & crate::posix::O_WRONLY != 0 {
            sdk::methods::vfs_open::WRITE
        } else {
            sdk::methods::vfs_open::READ
        };
        req.words[0] = self.root;
        req.words[1] = name.len() as u64; // Span { off 0, len }
        req.words[2] = vfs_flags as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let handle = reply.words[1];
        if handle == 0 {
            return Err(status::EBADCAP);
        }
        self.fds[slot] = Some(Fd { handle, offset: 0 });
        Ok(slot as u32)
    }

    /// Read up to `buf.len()` bytes from `fd` at its current offset.
    pub fn read<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        fd: u32,
        buf: &mut [u8],
    ) -> Result<usize, Status> {
        let mut entry = self.fds.get(fd as usize).copied().flatten().ok_or(EBADF)?;
        let mut got = 0usize;
        while got < buf.len() {
            let want = (buf.len() - got).min(WINDOW);
            let mut req = Message::new(methods::vfs::READ);
            req.words[0] = entry.handle;
            req.words[1] = entry.offset;
            req.words[2] = want as u64;
            req.words[3] = 0; // result-window offset
            let reply = sys.call(self.conn, &req)?;
            if reply.words[0] != 0 {
                return Err(reply.words[0] as i64 as i32);
            }
            let count = (reply.words[1] as usize).min(WINDOW);
            if count == 0 {
                break;
            }
            // SAFETY: result window mapped R|W by `connect`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    RESULT_WINDOW_VA as *const u8,
                    buf[got..].as_mut_ptr(),
                    count,
                );
            }
            got += count;
            entry.offset += count as u64;
            if count < want {
                break;
            }
        }
        self.fds[fd as usize] = Some(entry);
        Ok(got)
    }

    /// Write `data` at `fd`'s current offset.
    pub fn write<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        fd: u32,
        data: &[u8],
    ) -> Result<usize, Status> {
        let mut entry = self.fds.get(fd as usize).copied().flatten().ok_or(EBADF)?;
        let mut sent = 0usize;
        while sent < data.len() {
            let chunk = (data.len() - sent).min(WINDOW);
            // SAFETY: arg window mapped R|W by `connect`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data[sent..].as_ptr(),
                    ARG_WINDOW_VA as *mut u8,
                    chunk,
                );
            }
            let mut req = Message::new(methods::vfs::WRITE);
            req.words[0] = entry.handle;
            req.words[1] = entry.offset;
            req.words[2] = chunk as u64; // Span { off 0, len }
            let reply = sys.call(self.conn, &req)?;
            if reply.words[0] != 0 {
                return Err(reply.words[0] as i64 as i32);
            }
            let count = (reply.words[1] as usize).min(chunk);
            if count == 0 {
                break;
            }
            sent += count;
            entry.offset += count as u64;
            if count < chunk {
                break;
            }
        }
        self.fds[fd as usize] = Some(entry);
        Ok(sent)
    }

    /// Close `fd`.
    pub fn close<R: RawSyscalls>(&mut self, sys: &mut Syscalls<R>, fd: u32) -> Result<(), Status> {
        let entry = self.fds.get(fd as usize).copied().flatten().ok_or(EBADF)?;
        let mut req = Message::new(methods::vfs::CLOSE);
        req.words[0] = entry.handle;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        self.fds[fd as usize] = None;
        Ok(())
    }

    /// Convenience: open + read + close.
    pub fn read_file<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, Status> {
        let fd = self.open(sys, path, crate::posix::O_RDONLY)?;
        let n = self.read(sys, fd, buf);
        let _ = self.close(sys, fd);
        n
    }

    /// Convenience: create + write + close.
    pub fn write_file<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        data: &[u8],
    ) -> Result<usize, Status> {
        let fd = self.open(sys, path, O_CREAT)?;
        let n = self.write(sys, fd, data);
        let _ = self.close(sys, fd);
        n
    }
}

const EMFILE: Status = status::EMFILE;
