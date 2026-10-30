//! VFS server core: connections, per-connection handle tables, and the
//! request-serving loop over the ramfs core.
//!
//! Handles are server-private `u64`s bound to a connection (design doc §1.4):
//! another connection presenting a borrowed handle fails the table lookup.
//! Every connection starts with exactly one handle — its root directory.

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use ipc::{status, CapSlot, Message, Rights};

use crate::proto::{
    self, label, vstatus, ConnectReply, ConnectRequest, CountReply, HandleReply, HandleRequest,
    NameRequest, ReadRequest, ReaddirReply, ReaddirRequest, RenameRequest, Span, StatReply,
    StatRequest, Status, StatusReply, WriteRequest, KIND_DIR, OPEN_APPEND, OPEN_CREATE, OPEN_READ,
    OPEN_TRUNC, OPEN_WRITE, STAT_BY_HANDLE,
};
use crate::ramfs::{NodeId, RamFs, MODE_DIR_DEFAULT, MODE_FILE_DEFAULT};
use crate::runtime::{Handle as KernelHandle, Transport, VfsKernel, Windows};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleEntry {
    pub node: NodeId,
    pub dir: bool,
    pub flags: u32,
}

pub struct Connection {
    pub id: u64,
    pub endpoint: KernelHandle,
    pub session_notification: KernelHandle,
    pub arg_window: KernelHandle,
    pub result_window: KernelHandle,
    pub open: bool,
    pub handles: BTreeMap<u64, HandleEntry>,
    pub next_handle: u64,
}

/// Serving loop control flow (mirrors the process server).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Next {
    Continue,
}

pub struct VfsServer<K: VfsKernel, T: Transport> {
    fs: RamFs,
    kernel: K,
    transport: T,
    service_ep: KernelHandle,
    next_conn_id: u64,
    conns: BTreeMap<u64, Connection>,
}

impl<K: VfsKernel, T: Transport> VfsServer<K, T> {
    pub fn new(kernel: K, transport: T, service_ep: KernelHandle) -> Self {
        Self {
            fs: RamFs::new(),
            kernel,
            transport,
            service_ep,
            next_conn_id: 0,
            conns: BTreeMap::new(),
        }
    }

    pub fn connection(&self, id: u64) -> Option<&Connection> {
        self.conns.get(&id)
    }

    pub fn fs(&mut self) -> &mut RamFs {
        &mut self.fs
    }

    pub fn conn_by_endpoint(&self, endpoint: KernelHandle) -> Option<u64> {
        self.conns
            .values()
            .find(|c| c.endpoint == endpoint)
            .map(|c| c.id)
    }

    /// Handle a validated `CONNECT`: mint the connection endpoint, open the
    /// connection's root handle, park the record.
    pub fn connect(&mut self, req: &ConnectRequest) -> Result<(u64, KernelHandle, u64), Status> {
        let endpoint = self.kernel.new_endpoint()?;
        let root = self.fs.root();
        self.fs.node_open(root)?;
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        let mut handles = BTreeMap::new();
        let root_handle = 1u64;
        handles.insert(
            root_handle,
            HandleEntry {
                node: root,
                dir: true,
                flags: OPEN_READ,
            },
        );
        self.conns.insert(
            id,
            Connection {
                id,
                endpoint,
                session_notification: req.session_notification.handle(),
                arg_window: req.arg_window.handle(),
                result_window: req.result_window.handle(),
                open: true,
                handles,
                next_handle: 2,
            },
        );
        Ok((id, endpoint, root_handle))
    }

    /// Client death / protocol end: close every handle the connection holds.
    pub fn disconnect(&mut self, conn_id: u64) {
        if let Some(mut conn) = self.conns.remove(&conn_id) {
            conn.open = false;
            for entry in conn.handles.values() {
                self.fs.node_close(entry.node);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Serving loop
    // -----------------------------------------------------------------------

    pub fn serve_one(
        &mut self,
        cap: KernelHandle,
        windows: &mut impl Windows,
    ) -> Result<Next, Status> {
        let msg = self.transport.recv(cap)?;
        self.handle(cap, &msg, windows)
    }

    pub fn handle(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Result<Next, Status> {
        // Ops convert every protocol failure into an encoded error reply; only
        // the transport (recv/reply) can fail at this level.
        let reply = match msg.tag.label() {
            label::CONNECT => return self.handle_connect(cap, msg),
            label::WALK => self.op_walk(cap, msg, windows),
            label::OPEN => self.op_open(cap, msg, windows),
            label::READ => self.op_read(cap, msg, windows),
            label::WRITE => self.op_write(cap, msg, windows),
            label::CREATE => self.op_create(cap, msg, windows, false),
            label::MKDIR => self.op_create(cap, msg, windows, true),
            label::READDIR => self.op_readdir(cap, msg, windows),
            label::STAT => self.op_stat(cap, msg, windows),
            label::UNLINK => self.op_unlink(cap, msg, windows),
            label::RENAME => self.op_rename(cap, msg, windows),
            label::CLOSE | label::FSYNC | label::TRUNCATE | label::DUP => {
                self.op_handle_only(cap, msg)
            }
            other => StatusReply {
                status: status::ENOSYS,
            }
            .encode(other),
        };
        self.transport.reply(&reply)?;
        Ok(Next::Continue)
    }

    fn handle_connect(&mut self, cap: KernelHandle, msg: &Message) -> Result<Next, Status> {
        let reply = if cap != self.service_ep {
            ConnectReply {
                status: status::EBADCAP,
                connection_id: 0,
                root_handle: 0,
                endpoint: None,
            }
        } else {
            match ConnectRequest::decode(msg) {
                Ok(req) => match self.connect(&req) {
                    Ok((id, endpoint, root)) => ConnectReply {
                        status: status::OK,
                        connection_id: id,
                        root_handle: root,
                        endpoint: Some(CapSlot::pack(endpoint, Rights::SEND.union(Rights::GRANT))),
                    },
                    Err(e) => ConnectReply {
                        status: e,
                        connection_id: 0,
                        root_handle: 0,
                        endpoint: None,
                    },
                },
                Err(e) => ConnectReply {
                    status: e,
                    connection_id: 0,
                    root_handle: 0,
                    endpoint: None,
                },
            }
        };
        self.transport.reply(&reply.encode())?;
        Ok(Next::Continue)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn conn(&self, cap: KernelHandle) -> Result<u64, Status> {
        self.conn_by_endpoint(cap).ok_or(status::EBADCAP)
    }

    fn entry(&self, conn_id: u64, handle: u64) -> Result<HandleEntry, Status> {
        let conn = self.conns.get(&conn_id).ok_or(status::EBADCAP)?;
        conn.handles.get(&handle).copied().ok_or(status::EBADCAP)
    }

    fn new_handle(&mut self, conn_id: u64, entry: HandleEntry) -> Result<u64, Status> {
        let conn = self.conns.get_mut(&conn_id).ok_or(status::EBADCAP)?;
        let h = conn.next_handle;
        conn.next_handle += 1;
        conn.handles.insert(h, entry);
        Ok(h)
    }

    fn dir_of(&mut self, conn_id: u64, cap: KernelHandle, handle: u64) -> Result<NodeId, Status> {
        let _ = cap;
        let entry = self.entry(conn_id, handle)?;
        if !entry.dir {
            return Err(vstatus::ENOTDIR);
        }
        Ok(entry.node)
    }

    fn read_name(
        &mut self,
        conn_id: u64,
        span: Span,
        windows: &mut impl Windows,
    ) -> Result<String, Status> {
        if !span.fits(proto::WIN_SIZE) {
            return Err(status::EBADARG);
        }
        let conn = self.conns.get(&conn_id).ok_or(status::EBADCAP)?;
        let bytes = windows.read(conn.arg_window, span)?;
        String::from_utf8(bytes).map_err(|_| status::EBADARG)
    }

    // -----------------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------------

    fn op_walk(&mut self, cap: KernelHandle, msg: &Message, windows: &mut impl Windows) -> Message {
        let label = label::WALK;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = NameRequest::decode(msg, label)?;
            let dir = self.dir_of(conn, cap, req.dir)?;
            let name = self.read_name(conn, req.name, windows)?;
            let node = self.fs.walk(dir, &name)?;
            let stat = self.fs.stat(node)?;
            self.fs.node_open(node)?;
            let h = self.new_handle(
                conn,
                HandleEntry {
                    node,
                    dir: stat.kind == KIND_DIR,
                    flags: OPEN_READ,
                },
            )?;
            Ok::<_, Status>(
                HandleReply {
                    status: status::OK,
                    handle: h,
                    stat: Some(stat),
                }
                .encode(label),
            )
        })();
        reply.unwrap_or_else(|e| {
            HandleReply {
                status: e,
                handle: 0,
                stat: None,
            }
            .encode(label)
        })
    }

    fn op_open(&mut self, cap: KernelHandle, msg: &Message, windows: &mut impl Windows) -> Message {
        let label = label::OPEN;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = NameRequest::decode(msg, label)?;
            let dir = self.dir_of(conn, cap, req.dir)?;
            let name = self.read_name(conn, req.name, windows)?;

            let flags = req.flags;
            if flags & (OPEN_READ | OPEN_WRITE) == 0 {
                return Err(status::EBADARG);
            }
            if flags & OPEN_TRUNC != 0 && flags & OPEN_WRITE == 0 {
                return Err(vstatus::EACCES);
            }

            let node = match self.fs.walk(dir, &name) {
                Ok(node) => node,
                Err(vstatus::ENOENT) if flags & OPEN_CREATE != 0 => {
                    self.fs
                        .create_file(dir, &name, MODE_FILE_DEFAULT, self.kernel.now_ns())?
                }
                Err(e) => return Err(e),
            };
            let stat = self.fs.stat(node)?;
            if stat.kind == KIND_DIR {
                if flags & (OPEN_WRITE | OPEN_TRUNC | OPEN_CREATE) != 0 {
                    return Err(vstatus::EISDIR);
                }
            } else if flags & OPEN_TRUNC != 0 {
                self.fs.truncate(node, 0, self.kernel.now_ns())?;
            }
            self.fs.node_open(node)?;
            let h = self.new_handle(
                conn,
                HandleEntry {
                    node,
                    dir: stat.kind == KIND_DIR,
                    flags,
                },
            )?;
            Ok::<_, Status>(
                HandleReply {
                    status: status::OK,
                    handle: h,
                    stat: Some(stat),
                }
                .encode(label),
            )
        })();
        reply.unwrap_or_else(|e| {
            HandleReply {
                status: e,
                handle: 0,
                stat: None,
            }
            .encode(label)
        })
    }

    fn op_read(&mut self, cap: KernelHandle, msg: &Message, windows: &mut impl Windows) -> Message {
        let label = label::READ;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = ReadRequest::decode(msg)?;
            let entry = self.entry(conn, req.handle)?;
            if entry.dir {
                return Err(vstatus::EISDIR);
            }
            if entry.flags & OPEN_READ == 0 {
                return Err(vstatus::EACCES);
            }
            let end = req.result_offset as u64 + req.len as u64;
            if end > proto::WIN_SIZE as u64 {
                return Err(status::ETOOBIG);
            }
            let mut buf = std::vec![0u8; req.len as usize];
            let n = self.fs.read(entry.node, req.offset, &mut buf)?;
            let out = self.conns.get(&conn).ok_or(status::EBADCAP)?;
            windows.write(
                out.result_window,
                Span::new(req.result_offset, n as u32),
                &buf[..n],
            )?;
            Ok::<_, Status>(
                CountReply {
                    status: status::OK,
                    count: n as u64,
                }
                .encode(label),
            )
        })();
        reply.unwrap_or_else(|e| {
            CountReply {
                status: e,
                count: 0,
            }
            .encode(label)
        })
    }

    fn op_write(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Message {
        let label = label::WRITE;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = WriteRequest::decode(msg)?;
            let entry = self.entry(conn, req.handle)?;
            if entry.dir {
                return Err(vstatus::EISDIR);
            }
            if entry.flags & OPEN_WRITE == 0 {
                return Err(vstatus::EACCES);
            }
            if !req.data.fits(proto::WIN_SIZE) {
                return Err(status::EBADARG);
            }
            let data = self.read_window(conn, req.data, windows)?;
            let offset = if entry.flags & OPEN_APPEND != 0 {
                self.fs.stat(entry.node)?.size
            } else {
                req.offset
            };
            let n = self
                .fs
                .write(entry.node, offset, &data, self.kernel.now_ns())?;
            Ok::<_, Status>(
                CountReply {
                    status: status::OK,
                    count: n as u64,
                }
                .encode(label),
            )
        })();
        reply.unwrap_or_else(|e| {
            CountReply {
                status: e,
                count: 0,
            }
            .encode(label)
        })
    }

    fn op_create(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
        mkdir: bool,
    ) -> Message {
        let label = if mkdir { label::MKDIR } else { label::CREATE };
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = NameRequest::decode(msg, label)?;
            let dir = self.dir_of(conn, cap, req.dir)?;
            let name = self.read_name(conn, req.name, windows)?;
            let now = self.kernel.now_ns();
            let node = if mkdir {
                self.fs.mkdir(dir, &name, MODE_DIR_DEFAULT, now)?
            } else {
                self.fs.create_file(dir, &name, MODE_FILE_DEFAULT, now)?
            };
            let stat = self.fs.stat(node)?;
            self.fs.node_open(node)?;
            let h = self.new_handle(
                conn,
                HandleEntry {
                    node,
                    dir: mkdir,
                    flags: OPEN_READ | OPEN_WRITE,
                },
            )?;
            Ok::<_, Status>(
                HandleReply {
                    status: status::OK,
                    handle: h,
                    stat: Some(stat),
                }
                .encode(label),
            )
        })();
        reply.unwrap_or_else(|e| {
            HandleReply {
                status: e,
                handle: 0,
                stat: None,
            }
            .encode(label)
        })
    }

    fn op_readdir(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Message {
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = ReaddirRequest::decode(msg)?;
            let dir = self.dir_of(conn, cap, req.dir)?;
            match self.fs.readdir(dir, req.cookie)? {
                Some((next, name, id)) => {
                    let kind = self.fs.stat(id)?.kind;
                    let bytes = name.into_bytes();
                    let out = self.conns.get(&conn).ok_or(status::EBADCAP)?;
                    windows.write(out.result_window, Span::new(0, bytes.len() as u32), &bytes)?;
                    Ok::<_, Status>(
                        ReaddirReply {
                            status: status::OK,
                            next_cookie: next,
                            name: Span::new(0, bytes.len() as u32),
                            kind,
                        }
                        .encode(),
                    )
                }
                None => Ok::<_, Status>(
                    ReaddirReply {
                        status: status::OK,
                        next_cookie: 0,
                        name: Span::default(),
                        kind: 0,
                    }
                    .encode(),
                ),
            }
        })();
        reply.unwrap_or_else(|e| {
            ReaddirReply {
                status: e,
                next_cookie: 0,
                name: Span::default(),
                kind: 0,
            }
            .encode()
        })
    }

    fn op_stat(&mut self, cap: KernelHandle, msg: &Message, windows: &mut impl Windows) -> Message {
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = StatRequest::decode(msg)?;
            let stat = if req.selector == STAT_BY_HANDLE {
                let entry = self.entry(conn, req.target)?;
                self.fs.stat(entry.node)?
            } else {
                let dir = self.dir_of(conn, cap, req.target)?;
                let name = self.read_name(conn, req.name, windows)?;
                let node = self.fs.walk(dir, &name)?;
                self.fs.stat(node)?
            };
            Ok::<_, Status>(
                StatReply {
                    status: status::OK,
                    stat,
                }
                .encode(),
            )
        })();
        reply.unwrap_or_else(|e| {
            StatReply {
                status: e,
                stat: Default::default(),
            }
            .encode()
        })
    }

    fn op_unlink(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Message {
        let label = label::UNLINK;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = NameRequest::decode(msg, label)?;
            let dir = self.dir_of(conn, cap, req.dir)?;
            let name = self.read_name(conn, req.name, windows)?;
            self.fs.unlink(dir, &name)?;
            Ok::<_, Status>(StatusReply { status: status::OK }.encode(label))
        })();
        reply.unwrap_or_else(|e| StatusReply { status: e }.encode(label))
    }

    fn op_rename(
        &mut self,
        cap: KernelHandle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Message {
        let label = label::RENAME;
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = RenameRequest::decode(msg)?;
            let src_dir = self.dir_of(conn, cap, req.src_dir)?;
            let src_name = self.read_name(conn, req.src_name, windows)?;
            let dst_dir = self.dir_of(conn, cap, req.dst_dir)?;
            let dst_name = self.read_name(conn, req.dst_name, windows)?;
            let now = self.kernel.now_ns();
            self.fs
                .rename(src_dir, &src_name, dst_dir, &dst_name, now)?;
            Ok::<_, Status>(StatusReply { status: status::OK }.encode(label))
        })();
        reply.unwrap_or_else(|e| StatusReply { status: e }.encode(label))
    }

    fn op_handle_only(&mut self, cap: KernelHandle, msg: &Message) -> Message {
        let label = msg.tag.label();
        let reply = (|| {
            let conn = self.conn(cap)?;
            let req = HandleRequest::decode(msg, label)?;
            match label {
                label::CLOSE => {
                    let entry = self.entry(conn, req.handle)?;
                    let c = self.conns.get_mut(&conn).ok_or(status::EBADCAP)?;
                    c.handles.remove(&req.handle);
                    self.fs.node_close(entry.node);
                    Ok::<_, Status>(StatusReply { status: status::OK }.encode(label))
                }
                label::FSYNC => {
                    self.entry(conn, req.handle)?;
                    Ok(StatusReply { status: status::OK }.encode(label))
                }
                label::TRUNCATE => {
                    let entry = self.entry(conn, req.handle)?;
                    if entry.dir {
                        return Err(vstatus::EISDIR);
                    }
                    if entry.flags & OPEN_WRITE == 0 {
                        return Err(vstatus::EACCES);
                    }
                    self.fs
                        .truncate(entry.node, req.arg, self.kernel.now_ns())?;
                    Ok(StatusReply { status: status::OK }.encode(label))
                }
                label::DUP => {
                    let entry = self.entry(conn, req.handle)?;
                    self.fs.node_open(entry.node)?;
                    let h = self.new_handle(conn, entry)?;
                    Ok(HandleReply {
                        status: status::OK,
                        handle: h,
                        stat: None,
                    }
                    .encode(label))
                }
                _ => unreachable!("dispatch filtered"),
            }
        })();
        reply.unwrap_or_else(|e| match label {
            label::DUP => HandleReply {
                status: e,
                handle: 0,
                stat: None,
            }
            .encode(label),
            l => StatusReply { status: e }.encode(l),
        })
    }

    fn read_window(
        &mut self,
        conn_id: u64,
        span: Span,
        windows: &mut impl Windows,
    ) -> Result<Vec<u8>, Status> {
        let conn = self.conns.get(&conn_id).ok_or(status::EBADCAP)?;
        let arg = conn.arg_window;
        windows.read(arg, span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MockKernel, MockTransport, MockWindows};

    fn connect_req() -> ConnectRequest {
        ConnectRequest {
            version: proto::PROTO_VERSION,
            flags: 0,
            session_notification: CapSlot::pack(30, Rights::SIGNAL.union(Rights::GRANT)),
            arg_window: CapSlot::pack(31, Rights::READ.union(Rights::GRANT)),
            result_window: CapSlot::pack(32, Rights::WRITE.union(Rights::MAP).union(Rights::GRANT)),
        }
    }

    fn server() -> VfsServer<MockKernel, MockTransport> {
        VfsServer::new(MockKernel::default(), MockTransport::default(), 8)
    }

    fn put_arg(w: &mut MockWindows, off: u32, s: &str) {
        let window = w.data.entry(31).or_default();
        let start = off as usize;
        if window.len() < start + s.len() {
            window.resize(start + s.len(), 0);
        }
        window[start..start + s.len()].copy_from_slice(s.as_bytes());
    }

    fn name_req(dir: u64, off: u32, s: &str, flags: u32) -> NameRequest {
        NameRequest {
            dir,
            name: Span::new(off, s.len() as u32),
            flags,
        }
    }

    fn connect(s: &mut VfsServer<MockKernel, MockTransport>, w: &mut MockWindows) -> (u32, u64) {
        s.transport.incoming.push_back((8, connect_req().encode()));
        s.serve_one(8, w).unwrap();
        let rep = ConnectReply::decode(s.transport.replies.last().unwrap()).unwrap();
        assert_eq!(rep.status, status::OK);
        (rep.endpoint.unwrap().handle(), rep.root_handle)
    }

    fn reply(s: &mut VfsServer<MockKernel, MockTransport>) -> Message {
        *s.transport.replies.last().unwrap()
    }

    #[test]
    fn connect_rejects_non_service_cap() {
        let mut s = server();
        let mut w = MockWindows::default();
        s.transport.incoming.push_back((99, connect_req().encode()));
        s.serve_one(99, &mut w).unwrap();
        let rep = ConnectReply::decode(&reply(&mut s)).unwrap();
        assert_eq!(rep.status, status::EBADCAP);
    }

    #[test]
    fn end_to_end_create_write_read_readdir_unlink() {
        let mut s = server();
        let mut w = MockWindows::default();
        let (ep, root) = connect(&mut s, &mut w);
        assert_eq!(root, 1, "connection root handle");

        // MKDIR "etc" under root.
        put_arg(&mut w, 0, "etc");
        s.transport
            .incoming
            .push_back((ep, name_req(root, 0, "etc", 0).encode(label::MKDIR)));
        s.serve_one(ep, &mut w).unwrap();
        let mk = HandleReply::decode(&reply(&mut s), label::MKDIR).unwrap();
        assert_eq!(mk.status, status::OK);
        let etc = mk.handle;

        // CREATE "motd" in "etc".
        put_arg(&mut w, 0, "motd");
        s.transport
            .incoming
            .push_back((ep, name_req(etc, 0, "motd", 0).encode(label::CREATE)));
        s.serve_one(ep, &mut w).unwrap();
        let cr = HandleReply::decode(&reply(&mut s), label::CREATE).unwrap();
        assert_eq!(cr.status, status::OK);
        let motd = cr.handle;

        // WRITE "hi\n" from the arg window (offset 16).
        put_arg(&mut w, 16, "hi\n");
        s.transport.incoming.push_back((
            ep,
            WriteRequest {
                handle: motd,
                offset: 0,
                data: Span::new(16, 3),
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let wr = CountReply::decode(&reply(&mut s), label::WRITE).unwrap();
        assert_eq!((wr.status, wr.count), (status::OK, 3));

        // READ back into result window offset 8.
        s.transport.incoming.push_back((
            ep,
            ReadRequest {
                handle: motd,
                offset: 0,
                len: 16,
                result_offset: 8,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let rd = CountReply::decode(&reply(&mut s), label::READ).unwrap();
        assert_eq!((rd.status, rd.count), (status::OK, 3));
        let result = w.data.get(&32).unwrap();
        assert_eq!(&result[8..11], b"hi\n");

        // STAT by handle.
        s.transport.incoming.push_back((
            ep,
            StatRequest {
                target: motd,
                name: Span::default(),
                selector: STAT_BY_HANDLE,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let st = StatReply::decode(&reply(&mut s)).unwrap();
        assert_eq!(st.status, status::OK);
        assert_eq!(st.stat.size, 3);
        assert_eq!(st.stat.kind, proto::KIND_FILE);

        // READDIR "etc".
        s.transport.incoming.push_back((
            ep,
            ReaddirRequest {
                dir: etc,
                cookie: 0,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let rdd = ReaddirReply::decode(&reply(&mut s)).unwrap();
        assert_eq!(rdd.status, status::OK);
        let names = w.data.get(&32).unwrap();
        assert_eq!(&names[..4], b"motd");
        assert_eq!(rdd.kind, proto::KIND_FILE);

        // DUP + CLOSE original: read still works through the duplicate.
        s.transport.incoming.push_back((
            ep,
            HandleRequest {
                handle: motd,
                arg: 0,
            }
            .encode(label::DUP),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let dup = HandleReply::decode(&reply(&mut s), label::DUP).unwrap();
        assert_eq!(dup.status, status::OK);
        s.transport.incoming.push_back((
            ep,
            HandleRequest {
                handle: motd,
                arg: 0,
            }
            .encode(label::CLOSE),
        ));
        s.serve_one(ep, &mut w).unwrap();

        // UNLINK while open; WALK then fails; READ through dup still works.
        s.transport
            .incoming
            .push_back((ep, name_req(etc, 0, "motd", 0).encode(label::UNLINK)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            StatusReply::decode(&reply(&mut s), label::UNLINK)
                .unwrap()
                .status,
            status::OK
        );

        s.transport
            .incoming
            .push_back((ep, name_req(etc, 0, "motd", 0).encode(label::WALK)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            HandleReply::decode(&reply(&mut s), label::WALK)
                .unwrap()
                .status,
            vstatus::ENOENT
        );

        s.transport.incoming.push_back((
            ep,
            ReadRequest {
                handle: dup.handle,
                offset: 0,
                len: 4,
                result_offset: 0,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let rd2 = CountReply::decode(&reply(&mut s), label::READ).unwrap();
        assert_eq!((rd2.status, rd2.count), (status::OK, 3));
    }

    #[test]
    fn error_paths() {
        let mut s = server();
        let mut w = MockWindows::default();
        let (ep, root) = connect(&mut s, &mut w);

        // WALK missing name.
        put_arg(&mut w, 0, "nope");
        s.transport
            .incoming
            .push_back((ep, name_req(root, 0, "nope", 0).encode(label::WALK)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            HandleReply::decode(&reply(&mut s), label::WALK)
                .unwrap()
                .status,
            vstatus::ENOENT
        );

        // OPEN without READ/WRITE flags.
        s.transport
            .incoming
            .push_back((ep, name_req(root, 0, "nope", 0).encode(label::OPEN)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            HandleReply::decode(&reply(&mut s), label::OPEN)
                .unwrap()
                .status,
            status::EBADARG
        );

        // CREATE then WRITE without WRITE right on the handle: use a WALK
        // handle (read-only) and expect EACCES.
        s.transport.incoming.push_back((
            ep,
            name_req(root, 0, "ro", OPEN_READ | OPEN_WRITE | OPEN_CREATE).encode(label::OPEN),
        ));
        s.serve_one(ep, &mut w).unwrap();
        let opened = HandleReply::decode(&reply(&mut s), label::OPEN).unwrap();
        assert_eq!(opened.status, status::OK);

        s.transport
            .incoming
            .push_back((ep, name_req(root, 0, "ro", 0).encode(label::WALK)));
        s.serve_one(ep, &mut w).unwrap();
        let ro = HandleReply::decode(&reply(&mut s), label::WALK).unwrap();
        assert_eq!(ro.status, status::OK, "walk grants READ-only handle");

        put_arg(&mut w, 32, "x");
        s.transport.incoming.push_back((
            ep,
            WriteRequest {
                handle: ro.handle,
                offset: 0,
                data: Span::new(32, 1),
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            CountReply::decode(&reply(&mut s), label::WRITE)
                .unwrap()
                .status,
            vstatus::EACCES
        );

        // WALK on a file handle (use "ro" file handle) → ENOTDIR.
        s.transport
            .incoming
            .push_back((ep, name_req(opened.handle, 0, "x", 0).encode(label::WALK)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            HandleReply::decode(&reply(&mut s), label::WALK)
                .unwrap()
                .status,
            vstatus::ENOTDIR
        );

        // Forged handle from nowhere.
        s.transport.incoming.push_back((
            ep,
            ReadRequest {
                handle: 9999,
                offset: 0,
                len: 1,
                result_offset: 0,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            CountReply::decode(&reply(&mut s), label::READ)
                .unwrap()
                .status,
            status::EBADCAP
        );

        // Unknown label.
        s.transport.incoming.push_back((ep, Message::new(0x02FF)));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(reply(&mut s).words[0] as i32, status::ENOSYS);
    }

    #[test]
    fn hostile_messages_never_panic_and_always_reply() {
        // PLAN §6 spirit: arbitrary bytes over IPC must never take the server
        // down. Random labels, cap counts, descriptors, and words on both the
        // service endpoint and a live connection.
        let mut s = server();
        let mut w = MockWindows::default();
        let (ep, _root) = connect(&mut s, &mut w);

        let mut seed = 0xD1B5_4A32_D192_ED03u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for i in 0..1000usize {
            let cap = match i % 4 {
                0 => 8,             // service endpoint
                1 => ep,            // live connection
                _ => next() as u32, // never-seen caps
            };
            let mut m = Message::new(next() as u16);
            if i % 2 == 0 {
                m.tag = m.tag.with_caps((next() % 6) as u8);
            } else {
                m.tag = ipc::Tag(next());
            }
            m.words = [next(), next(), next(), next()];
            s.transport.incoming.push_back((cap, m));

            let before = s.transport.replies.len();
            s.serve_one(cap, &mut w)
                .unwrap_or_else(|e| panic!("iteration {i} returned Err({e})"));
            assert!(
                s.transport.replies.len() > before,
                "iteration {i}: no reply"
            );
        }
    }

    #[test]
    fn rename_via_protocol_and_disconnect_closes_handles() {
        let mut s = server();
        let mut w = MockWindows::default();
        let (ep, root) = connect(&mut s, &mut w);

        put_arg(&mut w, 0, "a");
        s.transport
            .incoming
            .push_back((ep, name_req(root, 0, "a", 0).encode(label::CREATE)));
        s.serve_one(ep, &mut w).unwrap();
        let a = HandleReply::decode(&reply(&mut s), label::CREATE)
            .unwrap()
            .handle;

        put_arg(&mut w, 8, "b");
        s.transport.incoming.push_back((
            ep,
            RenameRequest {
                src_dir: root,
                src_name: Span::new(0, 1),
                dst_dir: root,
                dst_name: Span::new(8, 1),
            }
            .encode(),
        ));
        s.serve_one(ep, &mut w).unwrap();
        assert_eq!(
            StatusReply::decode(&reply(&mut s), label::RENAME)
                .unwrap()
                .status,
            status::OK
        );

        put_arg(&mut w, 16, "b");
        s.transport
            .incoming
            .push_back((ep, name_req(root, 16, "b", 0).encode(label::WALK)));
        s.serve_one(ep, &mut w).unwrap();
        let b = HandleReply::decode(&reply(&mut s), label::WALK).unwrap();
        assert_eq!(b.status, status::OK);
        assert_ne!(b.handle, a, "new handle for the walked name");

        let conn = s.conn_by_endpoint(ep).unwrap();
        s.disconnect(conn);
        assert!(s.conn_by_endpoint(ep).is_none());
        assert_eq!(s.fs().stat(1).unwrap().kind, proto::KIND_DIR, "fs intact");
    }
}
