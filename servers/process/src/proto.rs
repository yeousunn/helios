//! Process server protocol codecs (design doc §2.6).
//!
//! Conventions:
//! - Wire messages are `ipc::Message` (ADR-005). Reply label = request label.
//! - `w0` of every reply is a shared `ipc::status` code.
//! - Variable-length data (paths, argv, env) lives in the connection's argument
//!   window; registers carry only `(offset, len)` spans and flags.
//! - Windows are fixed 64 KiB in v0 (CONNECT has 3 cap descriptors, so only one
//!   payload word is free — sizes need no negotiation yet).

use ipc::{status, CapSlot, Message, Rights};

/// Logical protocol version, carried in CONNECT `w0`.
pub const PROTO_VERSION: u16 = 1;

/// v0 window size for CONNECT maps (both directions).
pub const WIN_SIZE: u32 = 64 * 1024;

/// Operation labels inside `ipc::labels::process` (0x0100–0x01FF).
pub mod label {
    pub const CONNECT: u16 = 0x0101;
    pub const PACKAGE: u16 = 0x0102;
    pub const SPAWN: u16 = 0x0110;
    pub const WAIT: u16 = 0x0111;
    pub const KILL: u16 = 0x0112;
    pub const EXEC: u16 = 0x0113;
    pub const FORK: u16 = 0x0114;
    pub const THREAD_CREATE: u16 = 0x0115;
    pub const THREAD_EXIT: u16 = 0x0116;
    pub const GETPID: u16 = 0x0117;
}

/// Status codes share the `ipc::status` space; servers never invent codes.
pub type Status = i32;

/// `(offset, len)` span into a connection window, packed into one word.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Span {
    pub offset: u32,
    pub len: u32,
}

impl Span {
    pub const fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    pub const fn from_word(w: u64) -> Self {
        Self {
            offset: (w >> 32) as u32,
            len: w as u32,
        }
    }

    pub const fn to_word(self) -> u64 {
        ((self.offset as u64) << 32) | self.len as u64
    }

    pub const fn end(self) -> u64 {
        self.offset as u64 + self.len as u64
    }

    pub const fn fits(self, window_len: u32) -> bool {
        self.end() <= window_len as u64
    }
}

fn expect(msg: &Message, label: u16) -> Result<(), Status> {
    if !msg.tag.is_valid() || msg.tag.label() != label || msg.tag.flags() != 0 {
        return Err(status::EBADARG);
    }
    Ok(())
}

fn set_desc(m: &mut Message, i: usize, slot: CapSlot) {
    let _ = m.set_descriptor(i, slot);
}

// ---------------------------------------------------------------------------
// CONNECT (0x0101)
// ---------------------------------------------------------------------------

pub const CONNECT_CAPS: u8 = 3;

/// Client -> server: open a connection. Descriptors: session notification,
/// argument window (server reads), result window (server writes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectRequest {
    pub version: u16,
    pub flags: u16,
    pub session_notification: CapSlot,
    pub arg_window: CapSlot,
    pub result_window: CapSlot,
}

impl ConnectRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::CONNECT);
        m.tag = m.tag.with_caps(CONNECT_CAPS);
        m.words[0] = self.version as u64 | ((self.flags as u64) << 16);
        set_desc(&mut m, 0, self.session_notification);
        set_desc(&mut m, 1, self.arg_window);
        set_desc(&mut m, 2, self.result_window);
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::CONNECT)?;
        if m.tag.cap_count() != CONNECT_CAPS {
            return Err(status::EBADARG);
        }
        let version = m.words[0] as u16;
        if version != PROTO_VERSION {
            return Err(status::ENOSYS);
        }
        let session_notification = m.descriptor(0).ok_or(status::EBADARG)?;
        let arg_window = m.descriptor(1).ok_or(status::EBADARG)?;
        let result_window = m.descriptor(2).ok_or(status::EBADARG)?;
        if session_notification.handle() == ipc::NULL_HANDLE
            || arg_window.handle() == ipc::NULL_HANDLE
            || result_window.handle() == ipc::NULL_HANDLE
        {
            return Err(status::EBADCAP);
        }
        if !arg_window.rights().contains(Rights::READ) {
            return Err(status::ERIGHTS);
        }
        if !result_window
            .rights()
            .contains(Rights::WRITE.union(Rights::MAP))
        {
            return Err(status::ERIGHTS);
        }
        Ok(Self {
            version,
            flags: (m.words[0] >> 16) as u16,
            session_notification,
            arg_window,
            result_window,
        })
    }
}

/// Server -> client: connection accepted; `endpoint` is the connection's
/// dedicated endpoint (client talks there from now on).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectReply {
    pub status: Status,
    pub connection_id: u64,
    pub endpoint: Option<CapSlot>,
}

impl ConnectReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::CONNECT);
        if let Some(ep) = self.endpoint {
            m.tag = m.tag.with_caps(1);
            set_desc(&mut m, 0, ep);
        }
        m.words[0] = self.status as u64;
        m.words[1] = self.connection_id;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::CONNECT)?;
        let status = m.words[0] as i32;
        let endpoint = match m.tag.cap_count() {
            0 => None,
            1 => Some(m.descriptor(0).ok_or(status::EBADARG)?),
            _ => return Err(status::EBADARG),
        };
        Ok(Self {
            status,
            connection_id: m.words[1],
            endpoint,
        })
    }
}

// ---------------------------------------------------------------------------
// PACKAGE (0x0102): bootstrap capability delivery (ADR-009, design doc §2.4)
// ---------------------------------------------------------------------------

/// Header message preceding the package chunks: `w0` = total caps that follow.
pub fn package_header(total_caps: u32) -> Message {
    let mut m = Message::new(label::PACKAGE);
    m.words[0] = total_caps as u64;
    m
}

pub fn package_chunk(caps: &[CapSlot]) -> Result<Message, Status> {
    if caps.len() > ipc::MAX_WORDS {
        return Err(status::ETOOBIG);
    }
    let mut m = Message::new(label::PACKAGE);
    m.tag = m.tag.with_caps(caps.len() as u8);
    for (i, slot) in caps.iter().enumerate() {
        set_desc(&mut m, i, *slot);
    }
    Ok(m)
}

pub fn parse_package_header(m: &Message) -> Result<u32, Status> {
    expect(m, label::PACKAGE)?;
    if m.tag.cap_count() != 0 {
        return Err(status::EBADARG);
    }
    Ok(m.words[0] as u32)
}

// ---------------------------------------------------------------------------
// SPAWN (0x0110)
// ---------------------------------------------------------------------------

pub const SPAWN_CAP_VFS: usize = 0;
pub const SPAWN_CAP_STDIN: usize = 1;
pub const SPAWN_CAP_STDOUT: usize = 2;
pub const SPAWN_CAP_STDERR: usize = 3;

/// Client -> server. Descriptors (in order, nulls allowed): vfs endpoint,
/// stdin, stdout, stderr. Spans live in the argument window header (below).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SpawnRequest {
    pub flags: u32,
    pub caps: [Option<CapSlot>; 4],
}

/// 24-byte header at the start of the argument window for SPAWN; all spans are
/// window-relative and point at UTF-8/NUL-joined data the client wrote there.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SpawnHeader {
    pub program: Span,
    pub argv: Span,
    pub env: Span,
}

pub const SPAWN_HEADER_LEN: usize = 24;

impl SpawnHeader {
    pub fn encode(self) -> [u8; SPAWN_HEADER_LEN] {
        let mut out = [0u8; SPAWN_HEADER_LEN];
        out[0..8].copy_from_slice(&self.program.to_word().to_le_bytes());
        out[8..16].copy_from_slice(&self.argv.to_word().to_le_bytes());
        out[16..24].copy_from_slice(&self.env.to_word().to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Status> {
        if bytes.len() < SPAWN_HEADER_LEN {
            return Err(status::EBADARG);
        }
        let word = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("8 bytes"));
        Ok(Self {
            program: Span::from_word(word(0)),
            argv: Span::from_word(word(8)),
            env: Span::from_word(word(16)),
        })
    }

    pub fn fits(&self, window_len: u32) -> bool {
        self.program.fits(window_len) && self.argv.fits(window_len) && self.env.fits(window_len)
    }
}

impl SpawnRequest {
    pub fn encode(&self) -> Message {
        // Positions are meaningful (vfs, stdin, stdout, stderr), so interior
        // nulls are sent as explicit NULL descriptors; trailing nulls are
        // trimmed. Descriptor words overlay the *trailing* payload words, so
        // `cap_count` must be final before any descriptor is written.
        let n = self
            .caps
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |i| i + 1);
        let mut m = Message::new(label::SPAWN);
        m.tag = m.tag.with_caps(n as u8);
        m.words[0] = self.flags as u64;
        for (i, slot) in self.caps.iter().take(n).enumerate() {
            set_desc(&mut m, i, slot.unwrap_or(CapSlot::NULL));
        }
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::SPAWN)?;
        let n = m.tag.cap_count() as usize;
        if n > 4 {
            return Err(status::EBADARG);
        }
        let mut caps = [None; 4];
        for (i, slot) in caps.iter_mut().enumerate().take(n) {
            let c = m.descriptor(i).ok_or(status::EBADARG)?;
            if c.handle() != ipc::NULL_HANDLE {
                *slot = Some(c);
            }
        }
        Ok(Self {
            flags: m.words[0] as u32,
            caps,
        })
    }
}

/// Server -> client on success: `thread_control` (CONTROL) and `exit_notif`
/// (SIGNAL|RECV) are installed into the caller via descriptors.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpawnReply {
    pub status: Status,
    pub pid: u64,
    pub thread_control: Option<CapSlot>,
    pub exit_notif: Option<CapSlot>,
}

impl SpawnReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::SPAWN);
        m.words[0] = self.status as u64;
        m.words[1] = self.pid;
        // `cap_count` first: descriptor words overlay the trailing payload
        // words, so writing a descriptor before the final count corrupts them.
        let n = (self.thread_control.is_some() as u8) + (self.exit_notif.is_some() as u8);
        m.tag = m.tag.with_caps(n);
        if let Some(tc) = self.thread_control {
            set_desc(&mut m, 0, tc);
        }
        if let Some(en) = self.exit_notif {
            let i = self.thread_control.is_some() as usize;
            set_desc(&mut m, i, en);
        }
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::SPAWN)?;
        let n = m.tag.cap_count() as usize;
        if n > 2 {
            return Err(status::EBADARG);
        }
        Ok(Self {
            status: m.words[0] as i32,
            pid: m.words[1],
            thread_control: if n > 0 {
                Some(m.descriptor(0).ok_or(status::EBADARG)?)
            } else {
                None
            },
            exit_notif: if n > 1 {
                Some(m.descriptor(1).ok_or(status::EBADARG)?)
            } else {
                None
            },
        })
    }
}

// ---------------------------------------------------------------------------
// WAIT (0x0111) / KILL (0x0112)
// ---------------------------------------------------------------------------

pub const WAIT_NONBLOCK: u32 = 1 << 0;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct WaitRequest {
    pub pid: u64,
    pub flags: u32,
}

impl WaitRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::WAIT);
        m.words[0] = self.pid;
        m.words[1] = self.flags as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::WAIT)?;
        if m.tag.cap_count() != 0 {
            return Err(status::EBADARG);
        }
        Ok(Self {
            pid: m.words[0],
            flags: m.words[1] as u32,
        })
    }

    pub fn nonblock(&self) -> bool {
        self.flags & WAIT_NONBLOCK != 0
    }
}

/// Reply: `status` is the outcome of the call (OK, EWOULDBLOCK, ...),
/// `exit_status` is the reaped child's status when `status == OK`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WaitReply {
    pub status: Status,
    pub exit_status: Status,
}

impl WaitReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::WAIT);
        m.words[0] = self.status as u64;
        m.words[1] = self.exit_status as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::WAIT)?;
        Ok(Self {
            status: m.words[0] as i32,
            exit_status: m.words[1] as i32,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KillReply {
    pub status: Status,
}

impl KillReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::KILL);
        m.words[0] = self.status as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::KILL)?;
        Ok(Self {
            status: m.words[0] as i32,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KillRequest {
    pub pid: u64,
    pub raw_status: u64,
}

impl KillRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::KILL);
        m.words[0] = self.pid;
        m.words[1] = self.raw_status;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::KILL)?;
        if m.tag.cap_count() != 0 {
            return Err(status::EBADARG);
        }
        Ok(Self {
            pid: m.words[0],
            raw_status: m.words[1],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt_caps() -> (CapSlot, CapSlot, CapSlot) {
        (
            CapSlot::pack(3, Rights::SIGNAL.union(Rights::GRANT)),
            CapSlot::pack(4, Rights::READ.union(Rights::GRANT)),
            CapSlot::pack(5, Rights::WRITE.union(Rights::MAP).union(Rights::GRANT)),
        )
    }

    fn connect_request() -> ConnectRequest {
        let (n, a, r) = pt_caps();
        ConnectRequest {
            version: PROTO_VERSION,
            flags: 0,
            session_notification: n,
            arg_window: a,
            result_window: r,
        }
    }

    #[test]
    fn span_roundtrip_and_bounds() {
        let s = Span::new(16, 32);
        assert_eq!(Span::from_word(s.to_word()), s);
        assert_eq!(s.end(), 48);
        assert!(s.fits(48));
        assert!(!s.fits(47));
        assert!(Span::default().fits(0));
    }

    #[test]
    fn connect_roundtrip() {
        let req = connect_request();
        let decoded = ConnectRequest::decode(&req.encode()).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn connect_rejects_bad_shape() {
        let req = connect_request();

        let other = SpawnRequest::default().encode();
        assert_eq!(
            ConnectRequest::decode(&other),
            Err(status::EBADARG),
            "wrong label"
        );

        let mut no_caps = req.encode();
        no_caps.tag = no_caps.tag.with_caps(0);
        assert_eq!(
            ConnectRequest::decode(&no_caps),
            Err(status::EBADARG),
            "cap count must be 3"
        );

        let mut version_bump = req.encode();
        version_bump.words[0] = 0xFFFF;
        assert_eq!(
            ConnectRequest::decode(&version_bump),
            Err(status::ENOSYS),
            "version mismatch"
        );

        let mut flags = req.encode();
        flags.tag = flags.tag.with_flags(1 << 0);
        assert_eq!(
            ConnectRequest::decode(&flags),
            Err(status::EBADARG),
            "request flags must be zero"
        );
    }

    #[test]
    fn connect_rights_are_checked() {
        let (n, _, r) = pt_caps();
        let weak_arg = ConnectRequest {
            version: PROTO_VERSION,
            flags: 0,
            session_notification: n,
            arg_window: CapSlot::pack(4, Rights::GRANT),
            result_window: r,
        };
        assert_eq!(
            ConnectRequest::decode(&weak_arg.encode()),
            Err(status::ERIGHTS),
            "arg window needs READ"
        );

        let weak_result = ConnectRequest {
            version: PROTO_VERSION,
            flags: 0,
            session_notification: n,
            arg_window: CapSlot::pack(4, Rights::READ),
            result_window: CapSlot::pack(5, Rights::WRITE.union(Rights::GRANT)),
        };
        assert_eq!(
            ConnectRequest::decode(&weak_result.encode()),
            Err(status::ERIGHTS),
            "result window needs WRITE|MAP"
        );
    }

    #[test]
    fn connect_reply_roundtrip() {
        let reply = ConnectReply {
            status: status::OK,
            connection_id: 7,
            endpoint: Some(CapSlot::pack(9, Rights::SEND.union(Rights::GRANT))),
        };
        let decoded = ConnectReply::decode(&reply.encode()).unwrap();
        assert_eq!(decoded, reply);

        let err = ConnectReply {
            status: status::ENOMEM,
            connection_id: 0,
            endpoint: None,
        };
        assert_eq!(ConnectReply::decode(&err.encode()).unwrap(), err);
    }

    #[test]
    fn package_header_and_chunks() {
        let header = package_header(12);
        assert_eq!(parse_package_header(&header).unwrap(), 12);

        let caps: Vec<CapSlot> = (1..=4).map(|h| CapSlot::pack(h, Rights::SEND)).collect();
        let chunk = package_chunk(&caps).unwrap();
        assert_eq!(chunk.tag.cap_count(), 4);
        assert_eq!(chunk.descriptor(3).unwrap().handle(), 4);

        assert_eq!(package_chunk(&[CapSlot::NULL; 5]), Err(status::ETOOBIG));
    }

    #[test]
    fn spawn_roundtrip_with_nulls() {
        let req = SpawnRequest {
            flags: 1,
            caps: [
                Some(CapSlot::pack(10, Rights::SEND.union(Rights::GRANT))),
                None,
                Some(CapSlot::pack(12, Rights::SEND)),
                None,
            ],
        };
        let decoded = SpawnRequest::decode(&req.encode()).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.caps[1], None);
    }

    #[test]
    fn spawn_header_roundtrip_and_validation() {
        let h = SpawnHeader {
            program: Span::new(24, 10),
            argv: Span::new(34, 20),
            env: Span::new(54, 4),
        };
        assert_eq!(SpawnHeader::decode(&h.encode()).unwrap(), h);
        assert!(h.fits(58));
        assert!(!h.fits(57));
        assert_eq!(SpawnHeader::decode(&h.encode()[..8]), Err(status::EBADARG));
    }

    #[test]
    fn spawn_reply_roundtrip() {
        let reply = SpawnReply {
            status: status::OK,
            pid: 42,
            thread_control: Some(CapSlot::pack(20, Rights::CONTROL)),
            exit_notif: Some(CapSlot::pack(21, Rights::SIGNAL.union(Rights::RECV))),
        };
        assert_eq!(SpawnReply::decode(&reply.encode()).unwrap(), reply);
    }

    #[test]
    fn wait_and_kill_roundtrip() {
        let w = WaitRequest {
            pid: 2,
            flags: WAIT_NONBLOCK,
        };
        assert!(WaitRequest::decode(&w.encode()).unwrap().nonblock());
        let wr = WaitReply {
            status: status::OK,
            exit_status: -7,
        };
        assert_eq!(WaitReply::decode(&wr.encode()).unwrap(), wr);

        let k = KillRequest {
            pid: 2,
            raw_status: 9,
        };
        assert_eq!(KillRequest::decode(&k.encode()).unwrap(), k);
        assert_eq!(
            KillReply::decode(&KillReply { status: status::OK }.encode()).unwrap(),
            KillReply { status: status::OK }
        );
    }

    #[test]
    fn reply_labels_mirror_requests() {
        assert_eq!(connect_request().encode().tag.label(), label::CONNECT);
        assert_eq!(
            SpawnReply {
                status: 0,
                pid: 0,
                thread_control: None,
                exit_notif: None
            }
            .encode()
            .tag
            .label(),
            label::SPAWN
        );
    }
}
