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
use sdk::sys::raw_copy_from_va;
use sdk::syscall::{Handle, RawSyscalls, Status, Syscalls};
use sdk::window::{MappedWindow, WindowMapper, FLAG_READ, FLAG_WRITE};

use crate::layout::ARG_WINDOW_VA;
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

/// A connected VFS client with a local fd table and a working directory
/// (a handle stack: `cd name` walks down, `cd ..` pops).
pub struct VfsClient {
    conn: Handle,
    root: u64,
    cwd: u64,
    cwd_stack: [u64; MAX_CWD_DEPTH],
    cwd_depth: usize,
    fds: [Option<Fd>; MAX_FDS],
    /// The connection's arg window, mapped R|W at [`ARG_WINDOW_VA`]: every
    /// request payload travels through [`MappedWindow::write`], which bounds
    /// the copy against the frame.
    arg: MappedWindow,
    /// The connection's result window, mapped R|W by the same mapper at
    /// `RESULT_WINDOW_VA` (one frame above the arg window): every reply
    /// payload is read through [`read_into`], the no-alloc counterpart of
    /// [`MappedWindow::write`].
    result: MappedWindow,
}

/// Maximum `cd` nesting the client tracks for `cd ..`.
pub const MAX_CWD_DEPTH: usize = 8;

/// Read `dst.len()` bytes at `offset` out of a mapped window without touching
/// the heap: the bounds check mirrors [`MappedWindow::write`] and the copy is
/// the SDK's raw window copy, so no `Vec` per 4 KiB read (which leaks on the
/// bump heap, ADR-055) is ever allocated. This is the no-alloc counterpart of
/// `MappedWindow::read`; it stands in for `MappedWindow::read_into` (U4c2b,
/// DS), which will also cover ps.rs's five result-window reads.
fn read_into(window: MappedWindow, offset: u32, dst: &mut [u8]) -> Result<(), Status> {
    if offset + dst.len() as u32 > WINDOW as u32 {
        return Err(status::ETOOBIG);
    }
    raw_copy_from_va(window.va() + offset as u64, dst);
    Ok(())
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
        for slot in frames.iter_mut() {
            let mut carve = Message::new(methods::region::CARVE);
            carve.words[0] = WINDOW as u64;
            carve.words[1] = WINDOW as u64;
            let reply = sys.invoke(region, &carve)?;
            let frame = reply.words[0] as Handle;
            if frame == 0 {
                return Err(status::ENOMEM);
            }
            *slot = frame;
        }

        // Map both windows through the SDK's `WindowMapper` (the same type the
        // servers use): it performs the `AS::MAP` and hands back a bounds-
        // checked `MappedWindow`. The mapper lays windows out consecutively
        // from `ARG_WINDOW_VA`, and `layout.rs` puts `RESULT_WINDOW_VA` exactly
        // one frame above it, so the arg window lands at `ARG_WINDOW_VA` and
        // the result window at `RESULT_WINDOW_VA` as before.
        let mut windows = WindowMapper::new(aspace, ARG_WINDOW_VA, frames.len());
        let arg = windows.window_of(sys, frames[0], FLAG_READ | FLAG_WRITE)?;
        let result = windows.window_of(sys, frames[1], FLAG_READ | FLAG_WRITE)?;

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
            cwd: root,
            cwd_stack: [0; MAX_CWD_DEPTH],
            cwd_depth: 0,
            fds: [None; MAX_FDS],
            arg,
            result,
        })
    }

    /// The current working directory handle.
    pub fn cwd(&self) -> u64 {
        self.cwd
    }

    /// `WALK` from the cwd into `name`; returns the child dir handle without
    /// changing the cwd (the shell's `cd` uses [`Self::chdir`]).
    pub fn walk<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        name: &[u8],
    ) -> Result<u64, Status> {
        let dir = self.cwd;
        self.walk_from(sys, dir, name)
    }

    fn walk_from<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        dir: u64,
        name: &[u8],
    ) -> Result<u64, Status> {
        if name.is_empty() || name.len() > WINDOW {
            return Err(EINVAL);
        }
        // The arg window is mapped R|W into this AS by `connect`, and
        // `name.len() <= WINDOW` was checked above, so the span fits the frame.
        self.arg.write(0, name)?;
        let mut req = Message::new(methods::vfs::WALK);
        req.words[0] = dir;
        req.words[1] = name.len() as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let handle = reply.words[1];
        if handle == 0 {
            return Err(status::EBADCAP);
        }
        Ok(handle)
    }

    /// Walk the FULL path to its final component (which must be a directory)
    /// and return that dir's handle. A leading '/' starts at the root;
    /// '.'/empty components skip; ".." is passed through to the server, whose
    /// walk clamps at the root.
    pub fn walk_path<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
    ) -> Result<u64, Status> {
        let mut rest = path;
        let mut dir = self.cwd;
        if rest.first() == Some(&b'/') {
            dir = self.root;
            rest = &rest[1..];
        }
        while rest.last() == Some(&b'/') {
            rest = &rest[..rest.len() - 1];
        }
        if rest.is_empty() {
            // "/" or "" (with a leading slash) = the root.
            return if path.first() == Some(&b'/') {
                Ok(dir)
            } else {
                Err(EINVAL)
            };
        }
        for comp in rest.split(|&b| b == b'/') {
            if comp.is_empty() || comp == b"." {
                continue;
            }
            dir = self.walk_from(sys, dir, comp)?;
        }
        Ok(dir)
    }

    /// `cd name`: walk into `name` from the cwd (pushes the old cwd).
    pub fn chdir<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        name: &[u8],
    ) -> Result<(), Status> {
        if self.cwd_depth == MAX_CWD_DEPTH {
            return Err(status::ENOMEM);
        }
        let next = self.walk(sys, name)?;
        self.cwd_stack[self.cwd_depth] = self.cwd;
        self.cwd_depth += 1;
        self.cwd = next;
        Ok(())
    }

    /// `cd ..`: pop to the previous cwd.
    pub fn chdir_up(&mut self) -> Result<(), Status> {
        if self.cwd_depth == 0 {
            return Err(status::EBADCAP);
        }
        self.cwd_depth -= 1;
        self.cwd = self.cwd_stack[self.cwd_depth];
        Ok(())
    }

    /// Open (or create, with [`O_CREAT`]) `name` under the connection root.
    /// Returns a local fd.
    /// Resolve a path's PARENT directory by walking intermediate components
    /// (split on '/'; a leading '/' starts at the root, otherwise the cwd).
    /// The final component is copied into `last`; returns (parent, len).
    /// v0: no ".." components inside paths; "." and empty components skip.
    pub fn resolve<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        last: &mut [u8],
    ) -> Result<(u64, usize), Status> {
        let mut rest = path;
        let mut dir = self.cwd;
        if rest.first() == Some(&b'/') {
            dir = self.root;
            rest = &rest[1..];
        }
        while rest.last() == Some(&b'/') {
            rest = &rest[..rest.len() - 1];
        }
        if rest.is_empty() || rest.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut comps = rest.split(|&b| b == b'/').peekable();
        while let Some(comp) = comps.next() {
            if comps.peek().is_none() {
                // The final component: the operation's target name.
                if comp.is_empty() {
                    return Err(EINVAL);
                }
                if comp.len() > last.len() {
                    return Err(status::ETOOBIG);
                }
                last[..comp.len()].copy_from_slice(comp);
                return Ok((dir, comp.len()));
            }
            if comp.is_empty() || comp == b"." {
                continue;
            }
            dir = self.walk_from(sys, dir, comp)?;
        }
        Err(EINVAL)
    }

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
        let mut last = [0u8; 64];
        let (dir, len) = self.resolve(sys, name, &mut last)?;
        // The arg window is mapped R|W into this AS by `connect`; `len` is at
        // most `last.len()` (64) and well inside the 4 KiB frame.
        self.arg.write(0, &last[..len])?;
        // Both create-if-missing and truncate are open *flags* (the server's
        // OPEN path handles them); a dedicated CREATE label would EEXIST on an
        // existing file and could not truncate, which `>` redirection needs.
        let mut req = Message::new(methods::vfs::OPEN);
        // POSIX convention: O_RDONLY == 0 means "read", not "no access" —
        // translate to the VFS's explicit access flags (the server rejects a
        // request with neither READ nor WRITE).
        let mut vfs_flags = if flags & crate::posix::O_WRONLY != 0 {
            sdk::methods::vfs_open::WRITE
        } else {
            sdk::methods::vfs_open::READ
        };
        if flags & O_CREAT != 0 {
            vfs_flags |= sdk::methods::vfs_open::CREATE;
        }
        if flags & crate::posix::O_TRUNC != 0 {
            vfs_flags |= sdk::methods::vfs_open::TRUNC;
        }
        req.words[0] = dir;
        req.words[1] = len as u64; // Span { off 0, len }
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
            // Result window mapped R|W by `connect`; `count <= WINDOW` was
            // clamped above, so the read stays inside the frame.
            read_into(self.result, 0, &mut buf[got..got + count])?;
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
            // Arg window mapped R|W by `connect`; `chunk <= WINDOW`, so the
            // span fits the frame.
            self.arg.write(0, &data[sent..sent + chunk])?;
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

    /// Convenience: create/truncate + write + close (`>` semantics).
    pub fn write_file<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        data: &[u8],
    ) -> Result<usize, Status> {
        let fd = self.open(
            sys,
            path,
            crate::posix::O_WRONLY | O_CREAT | crate::posix::O_TRUNC,
        )?;
        let n = self.write(sys, fd, data);
        let _ = self.close(sys, fd);
        n
    }
}

/// Stat result (wire packing: `kind | mode << 8`, size, mtime).
#[derive(Clone, Copy)]
pub struct Stat {
    pub kind: u8,
    pub mode: u32,
    pub size: u64,
}

pub const KIND_FILE: u8 = 1;
pub const KIND_DIR: u8 = 2;

const STAT_BY_NAME: u32 = 1;
const STAT_BY_HANDLE: u32 = 0;

const EMFILE: Status = status::EMFILE;

impl VfsClient {
    /// The connection's root directory handle (v0: always 1).
    pub fn root(&self) -> u64 {
        self.root
    }

    /// `STAT` by name under the root.
    /// `fstat` by VFS **fd slot** (Linux `fstat`): stats the slot's handle.
    pub fn stat_fd<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        fd: u32,
    ) -> Result<Stat, Status> {
        let entry = self.fds.get(fd as usize).copied().flatten().ok_or(EBADF)?;
        let mut req = Message::new(methods::vfs::STAT);
        req.words[0] = entry.handle;
        req.words[1] = 0;
        req.words[2] = STAT_BY_HANDLE as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let packed = reply.words[1];
        Ok(Stat {
            kind: packed as u8,
            mode: ((packed >> 8) & 0xFF_FFFF) as u32,
            size: reply.words[2],
        })
    }

    pub fn stat<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        name: &[u8],
    ) -> Result<Stat, Status> {
        if name.is_empty() || name.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut last = [0u8; 64];
        let (dir, len) = self.resolve(sys, name, &mut last)?;
        // Arg window mapped R|W by `connect`; `len <= 64` fits the frame.
        self.arg.write(0, &last[..len])?;
        let mut req = Message::new(methods::vfs::STAT);
        req.words[0] = dir;
        req.words[1] = len as u64; // Span { off 0, len }
        req.words[2] = STAT_BY_NAME as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let packed = reply.words[1];
        Ok(Stat {
            kind: packed as u8,
            mode: ((packed >> 8) & 0xFF_FFFF) as u32,
            size: reply.words[2],
        })
    }

    /// `MKDIR` a directory under the root.
    pub fn mkdir<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        name: &[u8],
    ) -> Result<(), Status> {
        if name.is_empty() || name.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut last = [0u8; 64];
        let (dir, len) = self.resolve(sys, name, &mut last)?;
        // Arg window mapped R|W by `connect`; `len <= 64` fits the frame.
        self.arg.write(0, &last[..len])?;
        let mut req = Message::new(methods::vfs::MKDIR);
        req.words[0] = dir;
        req.words[1] = len as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        Ok(())
    }

    /// `RENAME` (move) `src` to `dst` (both cwd/parent-relative; the ramfs
    /// replaces an existing destination file but never a directory).
    pub fn rename<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        src: &[u8],
        dst: &[u8],
    ) -> Result<(), Status> {
        if src.is_empty() || dst.is_empty() || src.len() > WINDOW || dst.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut src_last = [0u8; 64];
        let mut dst_last = [0u8; 64];
        let (src_dir, src_len) = self.resolve(sys, src, &mut src_last)?;
        let (dst_dir, dst_len) = self.resolve(sys, dst, &mut dst_last)?;
        // Both names travel in the arg window: source at 0, destination at 64.
        // Arg window mapped R|W by `connect`; 64+64 < 4096.
        self.arg.write(0, &src_last[..src_len])?;
        self.arg.write(64, &dst_last[..dst_len])?;
        let mut req = Message::new(methods::vfs::RENAME);
        req.words[0] = src_dir;
        req.words[1] = src_len as u64; // Span { off 0, len }
        req.words[2] = dst_dir;
        req.words[3] = (64u64 << 32) | dst_len as u64; // Span { off 64, len }
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        Ok(())
    }

    /// `RMDIR` a path (must be an empty directory).
    pub fn rmdir<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
    ) -> Result<(), Status> {
        if path.is_empty() || path.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut last = [0u8; 64];
        let (dir, len) = self.resolve(sys, path, &mut last)?;
        // Arg window mapped R|W by `connect`; `len <= 64` fits the frame.
        self.arg.write(0, &last[..len])?;
        let mut req = Message::new(methods::vfs::RMDIR);
        req.words[0] = dir;
        req.words[1] = len as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        Ok(())
    }

    /// `UNLINK` a path (a file, or an empty directory).
    pub fn unlink<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
    ) -> Result<(), Status> {
        if path.is_empty() || path.len() > WINDOW {
            return Err(EINVAL);
        }
        let mut last = [0u8; 64];
        let (dir, len) = self.resolve(sys, path, &mut last)?;
        // Arg window mapped R|W by `connect`; `len <= 64` fits the frame.
        self.arg.write(0, &last[..len])?;
        let mut req = Message::new(methods::vfs::UNLINK);
        req.words[0] = dir;
        req.words[1] = len as u64;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        Ok(())
    }

    /// One step of `READDIR` on `dir`: `Ok(Some((next_cookie, kind, name_len)))`
    /// with the name copied into `name_out`; `Ok(None)` at end-of-directory.
    pub fn readdir<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        dir: u64,
        cookie: u64,
        name_out: &mut [u8],
    ) -> Result<Option<(u64, u8, usize)>, Status> {
        let mut req = Message::new(methods::vfs::READDIR);
        req.words[0] = dir;
        req.words[1] = cookie;
        let reply = sys.call(self.conn, &req)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let next = reply.words[1];
        let packed = reply.words[2]; // name Span in the result window
        let len = (packed & 0xFFFF_FFFF) as usize;
        // The end-of-directory reply is `next_cookie = 0` **with an empty
        // name span**; the final *entry* also reports `next_cookie = 0` but
        // carries its name — keying on the cookie alone drops it.
        if next == 0 && len == 0 {
            return Ok(None);
        }
        if len > WINDOW || len > name_out.len() {
            return Err(status::ETOOBIG);
        }
        // Result window mapped R|W by `connect`; `len <= WINDOW` and
        // `len <= name_out.len()` were checked above.
        read_into(self.result, 0, &mut name_out[..len])?;
        Ok(Some((next, reply.words[3] as u8, len)))
    }
    /// Open a **directory** by path into an fd slot (the emulator's
    /// `open(O_DIRECTORY)`): uses `walk_path`, which resolves `"/"` to the
    /// root (`resolve` rejects a bare `/` — it wants a final component).
    pub fn open_dir<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
    ) -> Result<u32, Status> {
        let handle = self.walk_path(sys, path)?;
        let slot = self.fds.iter().position(|f| f.is_none()).ok_or(EMFILE)?;
        self.fds[slot] = Some(Fd { handle, offset: 0 });
        Ok(slot as u32)
    }

    /// One `READDIR` step addressed by VFS **fd slot** (the emulator's
    /// `getdents`): uses the slot's handle with an explicit `cookie` (the
    /// caller keeps the cursor, since a caller that cannot fit an entry into
    /// its output buffer must be able to re-read it).
    pub fn readdir_fd<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        fd: u32,
        cookie: u64,
        name_out: &mut [u8],
    ) -> Result<Option<(u64, u8, usize)>, Status> {
        let entry = self.fds.get(fd as usize).copied().flatten().ok_or(EBADF)?;
        self.readdir(sys, entry.handle, cookie, name_out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{ARG_WINDOW_VA, RESULT_WINDOW_VA};
    use ipc::{status, Tag};
    use sdk::syscall::{number, SysReply};

    /// A recording `RawSyscalls`: every raw call is kept for inspection.
    /// `CARVE` replies hand out a fresh frame handle; the `CONNECT` call is
    /// answered the way the server answers it (`words[0] = 0`, the connection
    /// cap in the trailing descriptor word, the root in `words[2]`).
    struct Mock {
        calls: [(u32, [u64; 6]); 16],
        n: usize,
        next_frame: u32,
    }

    impl Mock {
        fn new() -> Self {
            Self {
                calls: [(0, [0; 6]); 16],
                n: 0,
                next_frame: 100,
            }
        }

        /// The message label of recorded call `i`.
        fn label(&self, i: usize) -> u16 {
            self.calls[i].1[1] as u16
        }
    }

    impl RawSyscalls for Mock {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls[self.n] = (number, args);
            self.n += 1;
            if number == number::CALL && args[1] as u16 == methods::vfs::CONNECT {
                return SysReply {
                    status: status::OK,
                    tag: Tag::new(methods::vfs::CONNECT).with_caps(1).0,
                    // words[0] = 0 (ok), words[2] = root handle, and the
                    // trailing word carries the connection cap descriptor.
                    words: [
                        0,
                        0,
                        7,
                        CapSlot::pack(42, Rights::READ.union(Rights::WRITE)).0,
                    ],
                };
            }
            self.next_frame += 1;
            SysReply {
                status: status::OK,
                tag: 0,
                words: [self.next_frame as u64, 0, 0, 0],
            }
        }
    }

    /// The arg/result windows are carved from the package region and mapped
    /// through the SDK `WindowMapper` at the two layout VAs, R|W, before the
    /// `CONNECT` message hands the two frame caps to the server.
    #[test]
    fn connect_carves_both_frames_then_maps_them_at_the_layout_window_vas() {
        let mut raw = Mock::new();
        let client = {
            let mut sys = Syscalls::new(&mut raw);
            VfsClient::connect(&mut sys, 6, 5, 9, 8).expect("connect")
        };

        // Both frames are carved from the package region (one per window).
        for i in 0..2 {
            assert_eq!(raw.calls[i].0, number::INVOKE, "carve {i}");
            assert_eq!(raw.label(i), methods::region::CARVE, "carve {i}");
            assert_eq!(raw.calls[i].1[0], 5, "carve {i} goes to the region cap");
            assert_eq!(raw.calls[i].1[2], WINDOW as u64, "carve {i}: one window");
            assert_eq!(raw.calls[i].1[3], WINDOW as u64, "carve {i}: aligned");
        }
        // The mapper then maps both frames into our AS at the layout VAs.
        for (i, va) in [ARG_WINDOW_VA, RESULT_WINDOW_VA].into_iter().enumerate() {
            let idx = 2 + i;
            assert_eq!(raw.calls[idx].0, number::INVOKE, "map {i}");
            assert_eq!(raw.label(idx), methods::aspace::MAP, "map {i}");
            assert_eq!(raw.calls[idx].1[0], 6, "map {i} goes to the AS cap");
            assert_eq!(raw.calls[idx].1[2], va, "map {i} vaddr");
            assert_eq!(raw.calls[idx].1[3], 0b011, "map {i} flags = R | W");
            // caps[0] is the carved frame (packed in the trailing word).
            let frame = CapSlot(raw.calls[idx].1[5]).handle();
            assert_eq!(frame, 101 + i as u32, "map {i} carries the carved frame");
        }

        // CONNECT finally hands the session and both frames to the server.
        let idx = 4;
        assert_eq!(raw.calls[idx].0, number::CALL, "connect");
        assert_eq!(raw.label(idx), methods::vfs::CONNECT);
        assert_eq!(raw.calls[idx].1[0], 9, "connect goes to the VFS endpoint");
        assert_eq!(
            CapSlot(raw.calls[idx].1[3]).handle(),
            8,
            "caps[0] = the session notification"
        );
        assert_eq!(
            CapSlot(raw.calls[idx].1[4]).handle(),
            101,
            "caps[1] = the arg window frame"
        );
        assert_eq!(
            CapSlot(raw.calls[idx].1[5]).handle(),
            102,
            "caps[2] = the result window frame"
        );

        assert_eq!(client.root(), 7, "root handle from the reply");
        assert_eq!(raw.n, 5, "carve x2, map x2, connect x1");
    }

    /// The result-window read allocates nothing and rejects an over-long span
    /// before touching memory: a fake window is mapped over a host buffer via
    /// the SDK `WindowMapper` (mock invoke), then read out with `read_into`.
    #[test]
    fn result_window_read_is_no_alloc_and_bounds_checked() {
        let mut backing = [0u8; WINDOW];
        backing[8..13].copy_from_slice(b"hello");
        let window = {
            let mut raw = Mock::new();
            let mut sys = Syscalls::new(&mut raw);
            let mut mapper = WindowMapper::new(6, backing.as_mut_ptr() as u64, 1);
            mapper
                .window_of(&mut sys, 21, FLAG_READ | FLAG_WRITE)
                .expect("map the fake window")
        };
        let mut dst = [0u8; 5];
        read_into(window, 8, &mut dst).expect("read inside the window");
        assert_eq!(&dst, b"hello");
        assert_eq!(
            read_into(window, WINDOW as u32, &mut dst).err(),
            Some(status::ETOOBIG)
        );
        assert_eq!(
            read_into(window, WINDOW as u32 - 1, &mut [0u8; 2]).err(),
            Some(status::ETOOBIG)
        );
    }
}
