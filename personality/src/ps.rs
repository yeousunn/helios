//! PS client for personality processes: process control over the process
//! server (design §2.6). One connection per process; `spawn` loads a program
//! through the VFS (the caller supplies its VFS service endpoint), `wait`
//! polls the child's death notification cooperatively (PS's WAIT is
//! non-blocking in v0 — deferred replies need a kernel reply-handle
//! primitive).
//!
//! The spawn payload lives in the connection's **arg window** (design §2.6:
//! "argv/env in the arg window") — see `sdk::spawn` for the blob layout:
//! SPAWN carries 3 capability descriptors and `Message` descriptors overlay
//! the trailing words, so no data words remain.

use ipc::{status, CapSlot, Message, Rights};
use sdk::methods;
use sdk::syscall::{Handle, RawSyscalls, Status, Syscalls};

use crate::layout::{PS_ARG_WINDOW_VA, PS_RESULT_WINDOW_VA};
use crate::vfs::WINDOW;

/// A connected PS client.
pub struct PsClient {
    conn: Handle,
}

impl PsClient {
    /// Connect to the process server: carve + map the two windows into our
    /// own AS, then `CONNECT` with a session notification from the package.
    pub fn connect<R: RawSyscalls>(
        sys: &mut Syscalls<R>,
        aspace: Handle,
        region: Handle,
        ps_ep: Handle,
        session: Handle,
        self_pid: u64,
    ) -> Result<Self, Status> {
        let mut frames = [0 as Handle; 2];
        for (i, va) in [PS_ARG_WINDOW_VA, PS_RESULT_WINDOW_VA].iter().enumerate() {
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

        let mut connect = Message::new(methods::process::CONNECT);
        connect.tag = connect.tag.with_caps(3);
        // w0 = version | caller-pid << 32: with 3 capability descriptors the
        // trailing words belong to the descriptors (`Message` overlay), so the
        // caller identity rides in w0's upper half (PS resolves EXEC by it).
        connect.words[0] = 1 | (self_pid << 32);
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
        let reply = sys.call(ps_ep, &connect)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        let conn = reply
            .descriptor(0)
            .map(|cs| cs.handle())
            .filter(|h| *h != 0)
            .ok_or(status::EBADCAP)?;
        Ok(Self { conn })
    }

    /// `SPAWN` a program by VFS path. `vfs` is the caller's VFS service
    /// endpoint (needed by PS to load the image); `stdout` optionally gives
    /// the child a console endpoint (installed at the package's stdio slot).
    /// Returns the child pid.
    pub fn spawn<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        argv: &[&[u8]],
        env: &[&[u8]],
        vfs: Option<Handle>,
        stdout: Option<Handle>,
    ) -> Result<u64, Status> {
        let ok = sdk::spawn::write_spawn_blob(PS_ARG_WINDOW_VA, path, argv, env);
        if ok.is_none() {
            return Err(status::EBADARG);
        }
        let mut m = Message::new(methods::process::SPAWN);
        m.tag = m.tag.with_caps(3);
        let _ = m.set_descriptor(
            0,
            match vfs {
                Some(h) => CapSlot::pack(h, Rights::SEND.union(Rights::GRANT)),
                None => CapSlot::NULL,
            },
        );
        let _ = m.set_descriptor(1, CapSlot::NULL); // stdin
        let _ = m.set_descriptor(
            2,
            match stdout {
                Some(h) => CapSlot::pack(h, Rights::SEND.union(Rights::GRANT)),
                None => CapSlot::NULL,
            },
        );
        let reply = sys.call(self.conn, &m)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        if reply.words[1] == 0 {
            return Err(status::EBADARG);
        }
        Ok(reply.words[1])
    }

    /// `EXEC`: replace this process's image with `path` (argv/env in the
    /// connection's arg window; no capabilities — PS reuses the VFS endpoint
    /// recorded at spawn). On success the CALLER MUST exit its thread: PS has
    /// already created the replacement thread running the new image, sharing
    /// this process's address space and capability table.
    pub fn exec<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        path: &[u8],
        argv: &[&[u8]],
        env: &[&[u8]],
    ) -> Result<(), Status> {
        if sdk::spawn::write_spawn_blob(PS_ARG_WINDOW_VA, path, argv, env).is_none() {
            return Err(status::EBADARG);
        }
        let m = Message::new(methods::process::EXEC);
        let reply = sys.call(self.conn, &m)?;
        if reply.words[0] != 0 {
            return Err(reply.words[0] as i64 as i32);
        }
        Ok(())
    }

    /// `WAIT` for the child, polling cooperatively (`EWOULDBLOCK` until the
    /// death notification fires; the caller yields between polls).
    pub fn wait<R: RawSyscalls>(&mut self, sys: &mut Syscalls<R>, pid: u64) -> Result<i32, Status> {
        loop {
            let mut m = Message::new(methods::process::WAIT);
            m.words[0] = pid;
            let reply = sys.call(self.conn, &m)?;
            if reply.words[0] == 0 {
                return Ok(reply.words[1] as u32 as i32);
            }
            if reply.words[0] as i64 as i32 == status::EWOULDBLOCK {
                sys.yield_now()?;
                continue;
            }
            return Err(reply.words[0] as i64 as i32);
        }
    }
}
