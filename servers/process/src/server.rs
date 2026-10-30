//! Process server core: connections, spawn pipeline, wait/kill bookkeeping,
//! and the request-serving loop.
//!
//! Serving model (design doc §1.2): the service endpoint handles `CONNECT`; the
//! endpoint minted there serves all later operations, and every context can be
//! host-tested. A blocking `WAIT` parks its serving thread (`Next::Parked`) —
//! v0 has no reply-cap save, so the parked request occupies its connection
//! (clients that wait and work concurrently use separate connections).

use std::collections::BTreeMap;

use ipc::{status, CapSlot, Message, Rights};

use crate::proto::{
    self, label, ConnectReply, ConnectRequest, KillReply, KillRequest, Span, SpawnHeader,
    SpawnReply, SpawnRequest, Status, WaitReply, WaitRequest,
};
use crate::runtime::{Handle, KernelOps, LoadedImage, MapFlags, ProgramLoader, Transport, Windows};

/// Session notifications minted per child (design doc §1.5, v0 pool).
pub const SESSION_POOL: usize = 4;

/// v0 user stack placement/size (ADR-017: the top is an arch ABI constant).
pub use sdk::layout::USER_STACK_TOP;
pub const DEFAULT_STACK_SIZE: u64 = 64 * 1024;
/// Process server policy: children run at this priority (applied via
/// `Thread::SET_PRIORITY` since creation uses the scheduler default).
pub const DEFAULT_PRIORITY: u8 = 8;

/// Rights the heap region capability is granted to children with. NOTE: the
/// `Region` object type is not yet in `caps::ObjType` / the rights table
/// (papercut to resolve with GLM); v0 uses GRANT only.
const REGION_RIGHTS: Rights = Rights::GRANT;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Connection {
    pub id: u64,
    pub endpoint: Handle,
    pub session_notification: Handle,
    pub arg_window: Handle,
    pub result_window: Handle,
    pub open: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProcessRecord {
    pub pid: u64,
    pub parent_conn: u64,
    pub aspace: Handle,
    pub main_thread: Handle,
    pub death_notification: Handle,
    pub session_notifications: [Handle; SESSION_POOL],
    pub exit_notification: Handle,
    pub exit_status: Option<Status>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpawnOutcome {
    pub pid: u64,
    pub thread_control: Handle,
    pub exit_notification: Handle,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitOutcome {
    Exited(Status),
    Pending,
}

/// A blocked WAIT that can now be answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Wakeup {
    pub conn_id: u64,
    pub pid: u64,
    pub exit_status: Status,
}

/// Control flow of the serving loop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Next {
    Continue,
    /// A blocking `WAIT` is still open; the serving thread parks (see module
    /// docs) and later calls [`ProcessServer::resolve_wait`].
    Parked {
        conn_id: u64,
        pid: u64,
    },
}

pub struct ProcessServer<K: KernelOps, L: ProgramLoader, T: Transport> {
    kernel: K,
    loader: L,
    transport: T,
    heap_region: Handle,
    ps_service_ep: Handle,
    next_conn_id: u64,
    next_pid: u64,
    conns: BTreeMap<u64, Connection>,
    procs: BTreeMap<u64, ProcessRecord>,
    waiters: Vec<(u64, u64)>,
}

impl<K: KernelOps, L: ProgramLoader, T: Transport> ProcessServer<K, L, T> {
    pub fn new(
        kernel: K,
        loader: L,
        transport: T,
        heap_region: Handle,
        ps_service_ep: Handle,
    ) -> Self {
        Self {
            kernel,
            loader,
            transport,
            heap_region,
            ps_service_ep,
            next_conn_id: 0,
            next_pid: 0,
            conns: BTreeMap::new(),
            procs: BTreeMap::new(),
            waiters: Vec::new(),
        }
    }

    pub fn connection(&self, id: u64) -> Option<&Connection> {
        self.conns.get(&id)
    }

    pub fn process(&self, pid: u64) -> Option<&ProcessRecord> {
        self.procs.get(&pid)
    }

    pub fn conn_by_endpoint(&self, endpoint: Handle) -> Option<u64> {
        self.conns
            .values()
            .find(|c| c.endpoint == endpoint)
            .map(|c| c.id)
    }

    // -----------------------------------------------------------------------
    // Serving loop
    // -----------------------------------------------------------------------

    /// Receive on `cap` and handle one request, reply included.
    pub fn serve_one(&mut self, cap: Handle, windows: &mut impl Windows) -> Result<Next, Status> {
        let msg = self.transport.recv(cap)?;
        self.handle(cap, &msg, windows)
    }

    /// Dispatch an already-received request.
    pub fn handle(
        &mut self,
        cap: Handle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Result<Next, Status> {
        match msg.tag.label() {
            label::CONNECT => self.handle_connect(cap, msg),
            label::SPAWN => self.handle_spawn(cap, msg, windows),
            label::WAIT => self.handle_wait(cap, msg),
            label::KILL => self.handle_kill(cap, msg),
            _ => {
                self.transport
                    .reply(&error_reply(msg.tag.label(), status::ENOSYS))?;
                Ok(Next::Continue)
            }
        }
    }

    fn handle_connect(&mut self, cap: Handle, msg: &Message) -> Result<Next, Status> {
        let reply = if cap != self.ps_service_ep {
            ConnectReply {
                status: status::EBADCAP,
                connection_id: 0,
                endpoint: None,
            }
        } else {
            match ConnectRequest::decode(msg) {
                Ok(req) => match self.connect(&req) {
                    Ok((id, endpoint)) => ConnectReply {
                        status: status::OK,
                        connection_id: id,
                        endpoint: Some(CapSlot::pack(endpoint, Rights::SEND.union(Rights::GRANT))),
                    },
                    Err(e) => ConnectReply {
                        status: e,
                        connection_id: 0,
                        endpoint: None,
                    },
                },
                Err(e) => ConnectReply {
                    status: e,
                    connection_id: 0,
                    endpoint: None,
                },
            }
        };
        self.transport.reply(&reply.encode())?;
        Ok(Next::Continue)
    }

    fn handle_spawn(
        &mut self,
        cap: Handle,
        msg: &Message,
        windows: &mut impl Windows,
    ) -> Result<Next, Status> {
        let reply = match (self.conn_by_endpoint(cap), SpawnRequest::decode(msg)) {
            (Some(conn_id), Ok(req)) => match self.spawn_from_window(conn_id, &req, windows) {
                Ok(r) => r,
                Err(e) => spawn_err(e),
            },
            (None, _) => spawn_err(status::EBADCAP),
            (_, Err(e)) => spawn_err(e),
        };
        self.transport.reply(&reply.encode())?;
        Ok(Next::Continue)
    }

    /// Resolve the SPAWN argument window (header + program name) and run the
    /// spawn pipeline.
    fn spawn_from_window(
        &mut self,
        conn_id: u64,
        req: &SpawnRequest,
        windows: &mut impl Windows,
    ) -> Result<SpawnReply, Status> {
        let conn = *self.conns.get(&conn_id).ok_or(status::EBADCAP)?;
        let header_bytes = windows.read(
            conn.arg_window,
            Span::new(0, proto::SPAWN_HEADER_LEN as u32),
        )?;
        let header = SpawnHeader::decode(&header_bytes)?;
        let program = windows.read(conn.arg_window, header.program)?;
        let outcome = self.spawn(conn_id, req, &header, &program, proto::WIN_SIZE)?;
        Ok(SpawnReply {
            status: status::OK,
            pid: outcome.pid,
            thread_control: Some(CapSlot::pack(outcome.thread_control, Rights::CONTROL)),
            exit_notif: Some(CapSlot::pack(
                outcome.exit_notification,
                Rights::SIGNAL.union(Rights::RECV),
            )),
        })
    }

    fn handle_wait(&mut self, cap: Handle, msg: &Message) -> Result<Next, Status> {
        let reply = match (self.conn_by_endpoint(cap), WaitRequest::decode(msg)) {
            (Some(conn_id), Ok(req)) => match self.wait(conn_id, req.pid, req.nonblock()) {
                Ok(WaitOutcome::Exited(s)) => WaitReply {
                    status: status::OK,
                    exit_status: s,
                },
                Ok(WaitOutcome::Pending) => {
                    return Ok(Next::Parked {
                        conn_id,
                        pid: req.pid,
                    })
                }
                Err(e) => WaitReply {
                    status: e,
                    exit_status: 0,
                },
            },
            (None, _) => WaitReply {
                status: status::EBADCAP,
                exit_status: 0,
            },
            (_, Err(e)) => WaitReply {
                status: e,
                exit_status: 0,
            },
        };
        self.transport.reply(&reply.encode())?;
        Ok(Next::Continue)
    }

    fn handle_kill(&mut self, cap: Handle, msg: &Message) -> Result<Next, Status> {
        let reply = match (self.conn_by_endpoint(cap), KillRequest::decode(msg)) {
            (Some(conn_id), Ok(req)) => match self.kill(conn_id, req.pid, req.raw_status) {
                Ok(()) => KillReply { status: status::OK },
                Err(e) => KillReply { status: e },
            },
            (None, _) => KillReply {
                status: status::EBADCAP,
            },
            (_, Err(e)) => KillReply { status: e },
        };
        self.transport.reply(&reply.encode())?;
        Ok(Next::Continue)
    }

    /// Reply to a parked `WAIT` once the reaper produced a [`Wakeup`].
    pub fn resolve_wait(&mut self, wake: &Wakeup) -> Result<(), Status> {
        self.transport.reply(
            &WaitReply {
                status: status::OK,
                exit_status: wake.exit_status,
            }
            .encode(),
        )
    }

    // -----------------------------------------------------------------------
    // Operations (also driven directly by tests)
    // -----------------------------------------------------------------------

    /// Handle a validated `CONNECT`: mint the connection endpoint and park the
    /// record. The caller replies and spawns the connection context for
    /// `endpoint`.
    pub fn connect(&mut self, req: &ConnectRequest) -> Result<(u64, Handle), Status> {
        let endpoint = self.kernel.new_endpoint()?;
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        self.conns.insert(
            id,
            Connection {
                id,
                endpoint,
                session_notification: req.session_notification.handle(),
                arg_window: req.arg_window.handle(),
                result_window: req.result_window.handle(),
                open: true,
            },
        );
        Ok((id, endpoint))
    }

    /// Close a connection (client death or protocol end). Process records are
    /// kept until reaped so `WAIT` from another connection still works.
    pub fn disconnect(&mut self, conn_id: u64) {
        if let Some(c) = self.conns.get_mut(&conn_id) {
            c.open = false;
        }
    }

    /// Spawn pipeline (design doc §2.4). `program` is the resolved program name
    /// bytes from the connection's argument window; `arg_window_len` bounds
    /// the header spans.
    pub fn spawn(
        &mut self,
        conn_id: u64,
        req: &SpawnRequest,
        header: &SpawnHeader,
        program: &[u8],
        arg_window_len: u32,
    ) -> Result<SpawnOutcome, Status> {
        match self.conns.get(&conn_id) {
            Some(c) if c.open => {}
            _ => return Err(status::EBADCAP),
        }
        if !header.fits(arg_window_len) {
            return Err(status::EBADARG);
        }

        let image = self.loader.load(program)?;
        self.spawn_image(conn_id, req, &image)
    }

    fn spawn_image(
        &mut self,
        conn_id: u64,
        req: &SpawnRequest,
        image: &LoadedImage,
    ) -> Result<SpawnOutcome, Status> {
        let aspace = self.kernel.new_address_space()?;
        for seg in &image.segments {
            self.kernel
                .map_frame(aspace, seg.frame, seg.vaddr, seg.flags)?;
        }

        let stack_size = image.stack_size.max(4096);
        let stack_frame = self
            .kernel
            .carve_frame(self.heap_region, stack_size, 4096)?;
        self.kernel.map_frame(
            aspace,
            stack_frame,
            USER_STACK_TOP - stack_size,
            MapFlags::R.union(MapFlags::W),
        )?;
        self.kernel.set_fault_pool(aspace, self.heap_region)?;

        let fault_ep = self.kernel.new_endpoint()?;
        let bootstrap_ep = self.kernel.new_endpoint()?;
        let thread = self.kernel.new_thread(
            aspace,
            image.entry,
            USER_STACK_TOP,
            DEFAULT_PRIORITY,
            Some(fault_ep),
            Some(bootstrap_ep),
        )?;

        // The thread exists: from here on any failure must reap it, so no
        // half-spawned process lingers in the scheduler.
        match self.finish_spawn(conn_id, req, aspace, thread, bootstrap_ep) {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                let _ = self.kernel.kill_thread(thread);
                Err(e)
            }
        }
    }

    fn finish_spawn(
        &mut self,
        conn_id: u64,
        req: &SpawnRequest,
        aspace: Handle,
        thread: Handle,
        bootstrap_ep: Handle,
    ) -> Result<SpawnOutcome, Status> {
        let death_notification = self.kernel.new_notification()?;
        self.kernel
            .bind_death_notification(thread, Some(death_notification))?;

        let mut session_notifications = [0u32; SESSION_POOL];
        for slot in session_notifications.iter_mut() {
            *slot = self.kernel.new_notification()?;
        }
        let exit_notification = self.kernel.new_notification()?;

        self.deliver_package(req, aspace, thread, &session_notifications, bootstrap_ep)?;

        let pid = self.next_pid;
        self.next_pid += 1;
        self.procs.insert(
            pid,
            ProcessRecord {
                pid,
                parent_conn: conn_id,
                aspace,
                main_thread: thread,
                death_notification,
                session_notifications,
                exit_notification,
                exit_status: None,
            },
        );
        Ok(SpawnOutcome {
            pid,
            thread_control: thread,
            exit_notification,
        })
    }

    /// Bootstrap capability package (design doc §2.3, ADR-009): header with the
    /// cap count, then chunks of <= 4 descriptors. Rights are the child's
    /// requested subset; the kernel applies `min(granted, requested)`.
    fn deliver_package(
        &mut self,
        req: &SpawnRequest,
        aspace: Handle,
        thread: Handle,
        session_notifications: &[Handle; SESSION_POOL],
        bootstrap_ep: Handle,
    ) -> Result<(), Status> {
        let mut caps: Vec<CapSlot> = Vec::with_capacity(1 + 1 + 1 + SESSION_POOL + 1 + 4);
        caps.push(CapSlot::pack(aspace, Rights::MAP.union(Rights::GRANT)));
        caps.push(CapSlot::pack(thread, Rights::CONTROL));
        caps.push(CapSlot::pack(self.heap_region, REGION_RIGHTS));
        for n in session_notifications {
            caps.push(CapSlot::pack(
                *n,
                Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT),
            ));
        }
        caps.push(CapSlot::pack(
            self.ps_service_ep,
            Rights::SEND.union(Rights::GRANT),
        ));
        for slot in req.caps.iter().flatten() {
            caps.push(*slot);
        }

        self.transport
            .send(bootstrap_ep, &proto::package_header(caps.len() as u32))?;
        for chunk in caps.chunks(ipc::MAX_WORDS) {
            let msg = proto::package_chunk(chunk)?;
            self.transport.send(bootstrap_ep, &msg)?;
        }
        Ok(())
    }

    /// Handle `WAIT` bookkeeping (design doc §2.6). `Pending` means the serving
    /// context must park; `on_process_exit` will produce the `Wakeup`.
    pub fn wait(&mut self, conn_id: u64, pid: u64, nonblock: bool) -> Result<WaitOutcome, Status> {
        let rec = self.procs.get(&pid).ok_or(status::EBADCAP)?;
        if rec.parent_conn != conn_id {
            return Err(status::EBADCAP);
        }
        if let Some(s) = rec.exit_status {
            return Ok(WaitOutcome::Exited(s));
        }
        if nonblock {
            return Err(status::EWOULDBLOCK);
        }
        self.waiters.push((conn_id, pid));
        Ok(WaitOutcome::Pending)
    }

    /// Reaper entry point (called when `N_dead` fires or a fault kills the
    /// process). Blind-signals the child's session notifications and the
    /// parent's wait notification, then wakes any blocked `WAIT`.
    pub fn on_process_exit(
        &mut self,
        pid: u64,
        exit_status: Status,
    ) -> Result<Vec<Wakeup>, Status> {
        let rec = self.procs.get_mut(&pid).ok_or(status::EBADCAP)?;
        if rec.exit_status.is_some() {
            return Err(status::EBADSTATE);
        }
        rec.exit_status = Some(exit_status);
        let session_notifications = rec.session_notifications;
        let exit_notification = rec.exit_notification;

        for n in session_notifications {
            self.kernel.signal(n, 1)?;
        }
        self.kernel.signal(exit_notification, 1)?;

        let mut wakes = Vec::new();
        let mut i = 0;
        while i < self.waiters.len() {
            let (c, p) = self.waiters[i];
            if p == pid {
                self.waiters.swap_remove(i);
                wakes.push(Wakeup {
                    conn_id: c,
                    pid,
                    exit_status,
                });
            } else {
                i += 1;
            }
        }
        Ok(wakes)
    }

    /// Handle `KILL`. v0: only the spawning connection may kill; the parent's
    /// `thread_control` capability will be the real gate once the reply path
    /// carries it.
    pub fn kill(&mut self, conn_id: u64, pid: u64, _raw_status: u64) -> Result<(), Status> {
        let rec = self.procs.get(&pid).ok_or(status::EBADCAP)?;
        if rec.parent_conn != conn_id {
            return Err(status::EBADCAP);
        }
        let thread = rec.main_thread;
        self.kernel.kill_thread(thread)
    }
}

fn error_reply(label: u16, status: Status) -> Message {
    let mut m = Message::new(label);
    m.words[0] = status as u64;
    m
}

fn spawn_err(status: Status) -> SpawnReply {
    SpawnReply {
        status,
        pid: 0,
        thread_control: None,
        exit_notif: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{spawn_window, MockKernel, MockLoader, MockTransport, MockWindows};
    use std::collections::VecDeque;

    fn connect_req() -> ConnectRequest {
        ConnectRequest {
            version: proto::PROTO_VERSION,
            flags: 0,
            session_notification: CapSlot::pack(30, Rights::SIGNAL.union(Rights::GRANT)),
            arg_window: CapSlot::pack(31, Rights::READ.union(Rights::GRANT)),
            result_window: CapSlot::pack(32, Rights::WRITE.union(Rights::MAP).union(Rights::GRANT)),
        }
    }

    fn spawn_req() -> SpawnRequest {
        SpawnRequest {
            flags: 0,
            caps: [
                Some(CapSlot::pack(40, Rights::SEND.union(Rights::GRANT))),
                Some(CapSlot::pack(41, Rights::RECV.union(Rights::GRANT))),
                Some(CapSlot::pack(42, Rights::SEND.union(Rights::GRANT))),
                None,
            ],
        }
    }

    fn server() -> ProcessServer<MockKernel, MockLoader, MockTransport> {
        ProcessServer::new(
            MockKernel::default(),
            MockLoader::ok(),
            MockTransport::default(),
            7,
            8,
        )
    }

    fn header() -> SpawnHeader {
        SpawnHeader {
            program: Span::new(24, 6),
            argv: Span::new(30, 10),
            env: Span::new(40, 2),
        }
    }

    #[test]
    fn connect_records_connection_and_mints_endpoint() {
        let mut s = server();
        let (id, endpoint) = s.connect(&connect_req()).unwrap();
        assert_eq!(id, 0);
        assert_eq!(endpoint, 1, "first mock handle");
        let conn = s.connection(0).unwrap();
        assert_eq!(conn.endpoint, endpoint);
        assert_eq!(conn.session_notification, 30);
        assert!(conn.open);

        let (id2, ep2) = s.connect(&connect_req()).unwrap();
        assert_eq!(id2, 1);
        assert_ne!(ep2, endpoint);
        assert_eq!(s.conn_by_endpoint(endpoint), Some(0));
        assert_eq!(s.conn_by_endpoint(999), None);
    }

    #[test]
    fn spawn_happy_path_builds_package_and_records_process() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        let outcome = s
            .spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap();

        assert_eq!(outcome.pid, 0);
        let rec = s.process(0).unwrap();
        assert_eq!(rec.main_thread, outcome.thread_control);
        assert_eq!(rec.exit_notification, outcome.exit_notification);
        assert_eq!(rec.exit_status, None);

        // Kernel op order (skipping connect's `new_endpoint`): AS, 2 segment
        // maps, stack map, pool, 2 endpoints, thread, death notif + bind,
        // 4 session notifs, exit notif.
        assert_eq!(s.kernel.ops[0], "new_endpoint", "from connect");
        let ops = &s.kernel.ops[1..];
        assert_eq!(ops[0], "new_address_space");
        assert_eq!(ops[1], "map_frame");
        assert_eq!(ops[2], "map_frame");
        assert_eq!(ops[3], "carve_frame");
        assert_eq!(ops[4], "map_frame");
        assert_eq!(ops[5], "set_fault_pool");
        assert_eq!(ops[6], "new_endpoint");
        assert_eq!(ops[7], "new_endpoint");
        assert_eq!(ops[8], "new_thread");
        assert_eq!(ops[9], "new_notification");
        assert_eq!(ops[10], "bind_death");
        assert_eq!(&ops[11..15], ["new_notification"; 4]);
        assert_eq!(ops[15], "new_notification");

        // Package: header + 3 chunks (11 caps: AS, thread, region, 4 session,
        // ps_ep, vfs, stdin, stdout — stderr was null and is trimmed).
        let sent = &s.transport.sent;
        assert_eq!(sent.len(), 4);
        assert_eq!(proto::parse_package_header(&sent[0].1).unwrap(), 11);
        let cap_count: usize = sent[1..].iter().map(|(_, m)| m.cap_count()).sum();
        assert_eq!(cap_count, 11);
        assert_eq!(sent[1].1.tag.label(), label::PACKAGE);

        // First chunk: AS (MAP|GRANT), thread (CONTROL), region (GRANT),
        // first session notification (SIGNAL|RECV|GRANT).
        let c0 = sent[1].1.descriptor(0).unwrap();
        assert_eq!(c0.handle(), rec.aspace);
        assert_eq!(c0.rights(), Rights::MAP.union(Rights::GRANT));
        let c1 = sent[1].1.descriptor(1).unwrap();
        assert_eq!(c1.rights(), Rights::CONTROL);
        let c3 = sent[1].1.descriptor(3).unwrap();
        assert_eq!(c3.handle(), rec.session_notifications[0]);
        assert_eq!(
            c3.rights(),
            Rights::SIGNAL.union(Rights::RECV).union(Rights::GRANT)
        );
    }

    #[test]
    fn spawn_rejects_bad_span_before_loading() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        let bad = SpawnHeader {
            program: Span::new(0, 100),
            ..header()
        };
        let err = s
            .spawn(conn, &spawn_req(), &bad, b"/hello", 10)
            .unwrap_err();
        assert_eq!(err, status::EBADARG);
        assert_eq!(s.loader.calls, 0, "must validate before resolving");
    }

    #[test]
    fn spawn_rejects_unknown_connection() {
        let mut s = server();
        let err = s
            .spawn(9, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap_err();
        assert_eq!(err, status::EBADCAP);
    }

    #[test]
    fn spawn_failure_after_thread_kills_it() {
        let mut s = ProcessServer::new(
            MockKernel::default(),
            MockLoader::ok(),
            MockTransport {
                fail_send: true,
                ..Default::default()
            },
            7,
            8,
        );
        let (conn, _) = s.connect(&connect_req()).unwrap();
        let err = s
            .spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap_err();
        assert_eq!(err, status::EDEAD);
        assert_eq!(s.kernel.killed.len(), 1, "half-spawned thread reaped");
        assert_eq!(s.process(0), None, "no record for a failed spawn");
    }

    #[test]
    fn wait_blocks_then_reaper_wakes_and_signals() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        s.spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap();
        let rec = *s.process(0).unwrap();

        assert_eq!(s.wait(conn, 0, true), Err(status::EWOULDBLOCK));
        assert_eq!(s.wait(conn, 0, false).unwrap(), WaitOutcome::Pending);

        let wakes = s.on_process_exit(0, 7).unwrap();
        assert_eq!(
            wakes,
            vec![Wakeup {
                conn_id: conn,
                pid: 0,
                exit_status: 7
            }]
        );

        // Session notifications + exit notification signalled exactly once.
        assert_eq!(s.kernel.signals.len(), SESSION_POOL + 1);
        assert_eq!(s.kernel.signals[0], (rec.session_notifications[0], 1));
        assert_eq!(s.kernel.signals[SESSION_POOL], (rec.exit_notification, 1));

        assert_eq!(s.wait(conn, 0, false), Ok(WaitOutcome::Exited(7)));
        assert_eq!(s.on_process_exit(0, 7), Err(status::EBADSTATE));
    }

    #[test]
    fn wait_requires_parent_connection() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        let (other, _) = s.connect(&connect_req()).unwrap();
        s.spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap();
        assert_eq!(s.wait(other, 0, true), Err(status::EBADCAP));
        assert_eq!(s.kill(other, 0, 0), Err(status::EBADCAP));
    }

    #[test]
    fn kill_requires_parent_connection_and_kills_thread() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        let outcome = s
            .spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap();
        s.kill(conn, 0, 9).unwrap();
        assert_eq!(s.kernel.killed, vec![outcome.thread_control]);
    }

    #[test]
    fn disconnect_marks_connection_closed() {
        let mut s = server();
        let (conn, _) = s.connect(&connect_req()).unwrap();
        s.disconnect(conn);
        assert!(!s.connection(conn).unwrap().open);
        let err = s
            .spawn(conn, &spawn_req(), &header(), b"/hello", proto::WIN_SIZE)
            .unwrap_err();
        assert_eq!(err, status::EBADCAP);
    }

    #[test]
    fn connect_on_non_service_cap_is_rejected() {
        let mut s = server();
        let mut windows = MockWindows::default();
        s.transport.incoming.push_back((99, connect_req().encode()));
        assert_eq!(s.serve_one(99, &mut windows).unwrap(), Next::Continue);
        let rep = ConnectReply::decode(&s.transport.replies[0]).unwrap();
        assert_eq!(rep.status, status::EBADCAP);
        assert!(rep.endpoint.is_none());
    }

    #[test]
    fn end_to_end_client_flow_over_connection_endpoint() {
        let mut s = server();
        let mut windows = MockWindows::default();

        // 1. CONNECT on the service endpoint (8).
        s.transport.incoming.push_back((8, connect_req().encode()));
        assert_eq!(s.serve_one(8, &mut windows).unwrap(), Next::Continue);
        let connect_rep = ConnectReply::decode(&s.transport.replies[0]).unwrap();
        assert_eq!(connect_rep.status, status::OK);
        assert_eq!(connect_rep.connection_id, 0);
        let ep = connect_rep.endpoint.unwrap().handle();

        // 2. SPAWN on the connection endpoint, program name in window 31.
        windows.data.insert(31, spawn_window(b"/hello"));
        s.transport.incoming.push_back((ep, spawn_req().encode()));
        assert_eq!(s.serve_one(ep, &mut windows).unwrap(), Next::Continue);
        let spawn_rep = SpawnReply::decode(&s.transport.replies[1]).unwrap();
        assert_eq!(spawn_rep.status, status::OK);
        assert_eq!(spawn_rep.pid, 0);
        assert!(spawn_rep.thread_control.is_some());
        assert!(spawn_rep.exit_notif.is_some());

        // 3. Non-blocking WAIT: immediate EWOULDBLOCK reply.
        s.transport.incoming.push_back((
            ep,
            WaitRequest {
                pid: 0,
                flags: proto::WAIT_NONBLOCK,
            }
            .encode(),
        ));
        s.serve_one(ep, &mut windows).unwrap();
        let w = WaitReply::decode(s.transport.replies.last().unwrap()).unwrap();
        assert_eq!(w.status, status::EWOULDBLOCK);

        // 4. Blocking WAIT parks the serving context and does not reply.
        s.transport
            .incoming
            .push_back((ep, WaitRequest { pid: 0, flags: 0 }.encode()));
        assert_eq!(
            s.serve_one(ep, &mut windows).unwrap(),
            Next::Parked { conn_id: 0, pid: 0 }
        );
        let replies_before = s.transport.replies.len();

        // 5. The reaper resolves the parked WAIT.
        let wakes = s.on_process_exit(0, 7).unwrap();
        assert_eq!(wakes.len(), 1);
        s.resolve_wait(&wakes[0]).unwrap();
        assert_eq!(s.transport.replies.len(), replies_before + 1);
        let w = WaitReply::decode(s.transport.replies.last().unwrap()).unwrap();
        assert_eq!((w.status, w.exit_status), (status::OK, 7));

        // 6. Unknown label: ENOSYS reply mirroring the request label.
        s.transport.incoming.push_back((ep, Message::new(0x01FF)));
        s.serve_one(ep, &mut windows).unwrap();
        let last = s.transport.replies.last().unwrap();
        assert_eq!(last.tag.label(), 0x01FF);
        assert_eq!(last.words[0] as i32, status::ENOSYS);
    }

    #[test]
    fn spawn_via_window_rejects_missing_window_bytes() {
        let mut s = server();
        let mut windows = MockWindows::default();
        s.transport.incoming.push_back((8, connect_req().encode()));
        s.serve_one(8, &mut windows).unwrap();
        let ep = ConnectReply::decode(&s.transport.replies[0])
            .unwrap()
            .endpoint
            .unwrap()
            .handle();

        // No window data registered for window 31.
        s.transport.incoming.push_back((ep, spawn_req().encode()));
        s.serve_one(ep, &mut windows).unwrap();
        let rep = SpawnReply::decode(s.transport.replies.last().unwrap()).unwrap();
        assert_eq!(rep.status, status::EBADCAP);
        assert_eq!(s.loader.calls, 0);
    }

    #[test]
    fn hostile_messages_never_panic_and_always_reply() {
        // PLAN §6 spirit: arbitrary bytes over IPC must never take a server
        // down. Random labels, cap counts, descriptors, and words — every
        // request must produce a reply (or a legitimate park), never a panic.
        let mut s = server();
        let mut w = MockWindows::default();
        let (_, ep) = s.connect(&connect_req()).unwrap();

        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };

        for i in 0..1000usize {
            let cap = if i % 5 == 0 { next() as u32 } else { ep };
            let mut m = Message::new(next() as u16);
            if i % 2 == 0 {
                m.tag = m.tag.with_caps((next() % 6) as u8);
            } else {
                m.tag = ipc::Tag(next());
            }
            m.words = [next(), next(), next(), next()];
            s.transport.incoming.push_back((cap, m));

            let before = s.transport.replies.len();
            let outcome = s
                .serve_one(cap, &mut w)
                .unwrap_or_else(|e| panic!("iteration {i} returned Err({e})"));
            if outcome == Next::Continue {
                assert!(
                    s.transport.replies.len() > before,
                    "iteration {i}: Continue without a reply"
                );
            }
        }
    }

    #[test]
    fn mock_incoming_is_fifo_per_cap() {
        let mut t = MockTransport {
            incoming: VecDeque::from(vec![
                (1, Message::new(label::GETPID)),
                (1, Message::new(label::CONNECT)),
            ]),
            ..Default::default()
        };
        assert_eq!(t.recv(1).unwrap().tag.label(), label::GETPID);
        assert_eq!(t.recv(1).unwrap().tag.label(), label::CONNECT);
        assert_eq!(t.recv(1), Err(status::EDEAD));
    }
}
