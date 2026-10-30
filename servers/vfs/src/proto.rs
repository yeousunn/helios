//! VFS protocol codecs (design doc §3.3). Reply label = request label; reply
//! `w0` is a shared status code.
//!
//! Status codes: the shared `ipc::status` space. The VFS set (ENOENT, EEXIST,
//! ENOTEMPTY, ENOTDIR, EISDIR, EINVAL, EACCES) is appended in
//! `sdk/docs/ipc-schema.md` §7; until GLM mirrors it into `ipc::status`, this
//! module defines the values locally with a test that pins them to the doc.
//!
//! Stat words: WALK/OPEN/CREATE/MKDIR replies carry `w2 = kind|mode`,
//! `w3 = size` (mtime has no slot — STAT carries the full triple). This is the
//! narrow exception the design doc §3.3 notes.

use ipc::{status, CapSlot, Message, Rights};

/// Logical protocol version carried in CONNECT `w0`.
pub const PROTO_VERSION: u16 = 1;

/// v0 window size (CONNECT has 3 cap descriptors — one payload word).
pub const WIN_SIZE: u32 = 64 * 1024;

/// Operation labels inside `ipc::labels::vfs` (0x0200–0x02FF).
pub mod label {
    pub const CONNECT: u16 = 0x0201;
    pub const WALK: u16 = 0x0210;
    pub const OPEN: u16 = 0x0211;
    pub const READ: u16 = 0x0212;
    pub const READ_BULK: u16 = 0x0213;
    pub const WRITE: u16 = 0x0214;
    pub const CLOSE: u16 = 0x0215;
    pub const FSYNC: u16 = 0x0216;
    pub const STAT: u16 = 0x0217;
    pub const READDIR: u16 = 0x0218;
    pub const CREATE: u16 = 0x0219;
    pub const MKDIR: u16 = 0x021A;
    pub const UNLINK: u16 = 0x021B;
    pub const RENAME: u16 = 0x021C;
    pub const TRUNCATE: u16 = 0x021D;
    pub const DUP: u16 = 0x021E;
}

pub type Status = i32;

/// VFS status codes pending the `ipc::status` mirror (schema §7, -15..-21).
pub mod vstatus {
    pub const ENOENT: i32 = -15;
    pub const EEXIST: i32 = -16;
    pub const ENOTEMPTY: i32 = -17;
    pub const ENOTDIR: i32 = -18;
    pub const EISDIR: i32 = -19;
    pub const EINVAL: i32 = -20;
    pub const EACCES: i32 = -21;
}

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

/// Node kinds on the wire (STAT packed `w1`, READDIR `w3`).
pub const KIND_FILE: u8 = 1;
pub const KIND_DIR: u8 = 2;

/// Open flags (OPEN/CREATE `flags` word).
pub const OPEN_READ: u32 = 1 << 0;
pub const OPEN_WRITE: u32 = 1 << 1;
pub const OPEN_APPEND: u32 = 1 << 2;
pub const OPEN_TRUNC: u32 = 1 << 3;
pub const OPEN_CREATE: u32 = 1 << 4;

fn expect(msg: &Message, label: u16) -> Result<(), Status> {
    if !msg.tag.is_valid() || msg.tag.label() != label || msg.tag.flags() != 0 {
        return Err(status::EBADARG);
    }
    Ok(())
}

fn set_desc(m: &mut Message, i: usize, slot: CapSlot) {
    let _ = m.set_descriptor(i, slot);
}

fn no_caps(msg: &Message) -> Result<(), Status> {
    if msg.tag.cap_count() != 0 {
        return Err(status::EBADARG);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CONNECT (0x0201) — same shape as the process server (design doc §1.2)
// ---------------------------------------------------------------------------

pub const CONNECT_CAPS: u8 = 3;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConnectReply {
    pub status: Status,
    pub connection_id: u64,
    /// VFS extension over the generic handshake: the connection's root
    /// directory handle (`w2`; 0 on error). No ambient namespace — this handle
    /// is the connection's whole visible tree.
    pub root_handle: u64,
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
        m.words[2] = self.root_handle;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::CONNECT)?;
        let endpoint = match m.tag.cap_count() {
            0 => None,
            1 => Some(m.descriptor(0).ok_or(status::EBADARG)?),
            _ => return Err(status::EBADARG),
        };
        Ok(Self {
            status: m.words[0] as i32,
            connection_id: m.words[1],
            root_handle: m.words[2],
            endpoint,
        })
    }
}

// ---------------------------------------------------------------------------
// Stat
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stat {
    pub kind: u8,
    pub mode: u32,
    pub size: u64,
    pub mtime_ns: u64,
}

impl Stat {
    /// `(kind|mode, size, mtime)`.
    pub fn to_words(self) -> (u64, u64, u64) {
        let packed = self.kind as u64 | ((self.mode as u64 & 0xFF_FFFF) << 8);
        (packed, self.size, self.mtime_ns)
    }

    pub fn from_words(w1: u64, w2: u64, w3: u64) -> Self {
        Self {
            kind: w1 as u8,
            mode: ((w1 >> 8) & 0xFF_FFFF) as u32,
            size: w2,
            mtime_ns: w3,
        }
    }
}

// ---------------------------------------------------------------------------
// WALK (0x0210) / OPEN (0x0211) / CREATE (0x0219) / MKDIR (0x021A)
// ---------------------------------------------------------------------------

/// Name-based op on a directory: `w0` = dir handle, `w1` = name span,
/// `w2` = flags (unused for WALK/UNLINK).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NameRequest {
    pub dir: u64,
    pub name: Span,
    pub flags: u32,
}

impl NameRequest {
    pub fn encode(&self, label: u16) -> Message {
        let mut m = Message::new(label);
        m.words[0] = self.dir;
        m.words[1] = self.name.to_word();
        m.words[2] = self.flags as u64;
        m
    }

    pub fn decode(m: &Message, label: u16) -> Result<Self, Status> {
        expect(m, label)?;
        no_caps(m)?;
        Ok(Self {
            dir: m.words[0],
            name: Span::from_word(m.words[1]),
            flags: m.words[2] as u32,
        })
    }
}

/// Reply carrying a new handle (WALK/OPEN/CREATE/MKDIR): `w1` = handle,
/// `w2` = kind|mode, `w3` = size.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleReply {
    pub status: Status,
    pub handle: u64,
    pub stat: Option<Stat>,
}

impl HandleReply {
    pub fn encode(&self, label: u16) -> Message {
        let mut m = Message::new(label);
        m.words[0] = self.status as u64;
        m.words[1] = self.handle;
        if let Some(stat) = self.stat {
            let (packed, size, _mtime) = stat.to_words();
            m.words[2] = packed;
            m.words[3] = size;
        }
        m
    }

    pub fn decode(m: &Message, label: u16) -> Result<Self, Status> {
        expect(m, label)?;
        Ok(Self {
            status: m.words[0] as i32,
            handle: m.words[1],
            stat: None,
        })
    }
}

// ---------------------------------------------------------------------------
// READ (0x0212): w0 handle, w1 offset, w2 len, w3 result-window offset
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReadRequest {
    pub handle: u64,
    pub offset: u64,
    pub len: u32,
    pub result_offset: u32,
}

impl ReadRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::READ);
        m.words[0] = self.handle;
        m.words[1] = self.offset;
        m.words[2] = self.len as u64;
        m.words[3] = self.result_offset as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::READ)?;
        no_caps(m)?;
        Ok(Self {
            handle: m.words[0],
            offset: m.words[1],
            len: m.words[2] as u32,
            result_offset: m.words[3] as u32,
        })
    }
}

/// `w1` = bytes transferred (success) — for READ into window / WRITE / READDIR.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CountReply {
    pub status: Status,
    pub count: u64,
}

impl CountReply {
    pub fn encode(&self, label: u16) -> Message {
        let mut m = Message::new(label);
        m.words[0] = self.status as u64;
        m.words[1] = self.count;
        m
    }

    pub fn decode(m: &Message, label: u16) -> Result<Self, Status> {
        expect(m, label)?;
        Ok(Self {
            status: m.words[0] as i32,
            count: m.words[1],
        })
    }
}

// ---------------------------------------------------------------------------
// READ_BULK (0x0213): w0 handle, w1 offset, w2 len; caps[0] = dest frame
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReadBulkRequest {
    pub handle: u64,
    pub offset: u64,
    pub len: u32,
    pub frame: CapSlot,
}

impl ReadBulkRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::READ_BULK);
        m.tag = m.tag.with_caps(1);
        m.words[0] = self.handle;
        m.words[1] = self.offset;
        m.words[2] = self.len as u64;
        set_desc(&mut m, 0, self.frame);
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::READ_BULK)?;
        if m.tag.cap_count() != 1 {
            return Err(status::EBADARG);
        }
        let frame = m.descriptor(0).ok_or(status::EBADARG)?;
        if frame.handle() == ipc::NULL_HANDLE {
            return Err(status::EBADCAP);
        }
        if !frame.rights().contains(Rights::WRITE.union(Rights::MAP)) {
            return Err(status::ERIGHTS);
        }
        Ok(Self {
            handle: m.words[0],
            offset: m.words[1],
            len: m.words[2] as u32,
            frame,
        })
    }
}

// ---------------------------------------------------------------------------
// WRITE (0x0214): w0 handle, w1 offset, w2 span into the arg window
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct WriteRequest {
    pub handle: u64,
    pub offset: u64,
    pub data: Span,
}

impl WriteRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::WRITE);
        m.words[0] = self.handle;
        m.words[1] = self.offset;
        m.words[2] = self.data.to_word();
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::WRITE)?;
        no_caps(m)?;
        Ok(Self {
            handle: m.words[0],
            offset: m.words[1],
            data: Span::from_word(m.words[2]),
        })
    }
}

// ---------------------------------------------------------------------------
// Handle-only ops (CLOSE/FSYNC/TRUNCATE/DUP): w0 handle, w1 arg
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HandleRequest {
    pub handle: u64,
    pub arg: u64,
}

impl HandleRequest {
    pub fn encode(&self, label: u16) -> Message {
        let mut m = Message::new(label);
        m.words[0] = self.handle;
        m.words[1] = self.arg;
        m
    }

    pub fn decode(m: &Message, label: u16) -> Result<Self, Status> {
        expect(m, label)?;
        no_caps(m)?;
        Ok(Self {
            handle: m.words[0],
            arg: m.words[1],
        })
    }
}

// ---------------------------------------------------------------------------
// STAT (0x0217): w0 handle or dir, w1 name span, w2 selector (0 = by handle)
// ---------------------------------------------------------------------------

pub const STAT_BY_HANDLE: u32 = 0;
pub const STAT_BY_NAME: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatRequest {
    pub target: u64,
    pub name: Span,
    pub selector: u32,
}

impl StatRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::STAT);
        m.words[0] = self.target;
        m.words[1] = self.name.to_word();
        m.words[2] = self.selector as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::STAT)?;
        no_caps(m)?;
        Ok(Self {
            target: m.words[0],
            name: Span::from_word(m.words[1]),
            selector: m.words[2] as u32,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatReply {
    pub status: Status,
    pub stat: Stat,
}

impl StatReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::STAT);
        m.words[0] = self.status as u64;
        let (w1, w2, w3) = self.stat.to_words();
        m.words[1] = w1;
        m.words[2] = w2;
        m.words[3] = w3;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::STAT)?;
        Ok(Self {
            status: m.words[0] as i32,
            stat: Stat::from_words(m.words[1], m.words[2], m.words[3]),
        })
    }
}

// ---------------------------------------------------------------------------
// READDIR (0x0218): w0 dir handle, w1 cookie (0 = from start)
// Reply: w1 = next cookie (0 = end), w2 = name span in result window,
// w3 = kind
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReaddirRequest {
    pub dir: u64,
    pub cookie: u64,
}

impl ReaddirRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::READDIR);
        m.words[0] = self.dir;
        m.words[1] = self.cookie;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::READDIR)?;
        no_caps(m)?;
        Ok(Self {
            dir: m.words[0],
            cookie: m.words[1],
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ReaddirReply {
    pub status: Status,
    pub next_cookie: u64,
    pub name: Span,
    pub kind: u8,
}

impl ReaddirReply {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::READDIR);
        m.words[0] = self.status as u64;
        m.words[1] = self.next_cookie;
        m.words[2] = self.name.to_word();
        m.words[3] = self.kind as u64;
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::READDIR)?;
        Ok(Self {
            status: m.words[0] as i32,
            next_cookie: m.words[1],
            name: Span::from_word(m.words[2]),
            kind: m.words[3] as u8,
        })
    }
}

// ---------------------------------------------------------------------------
// RENAME (0x021C): w0 src dir, w1 src name span, w2 dst dir, w3 dst name span
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RenameRequest {
    pub src_dir: u64,
    pub src_name: Span,
    pub dst_dir: u64,
    pub dst_name: Span,
}

impl RenameRequest {
    pub fn encode(&self) -> Message {
        let mut m = Message::new(label::RENAME);
        m.words[0] = self.src_dir;
        m.words[1] = self.src_name.to_word();
        m.words[2] = self.dst_dir;
        m.words[3] = self.dst_name.to_word();
        m
    }

    pub fn decode(m: &Message) -> Result<Self, Status> {
        expect(m, label::RENAME)?;
        no_caps(m)?;
        Ok(Self {
            src_dir: m.words[0],
            src_name: Span::from_word(m.words[1]),
            dst_dir: m.words[2],
            dst_name: Span::from_word(m.words[3]),
        })
    }
}

/// Bare status reply (RENAME, UNLINK).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct StatusReply {
    pub status: Status,
}

impl StatusReply {
    pub fn encode(&self, label: u16) -> Message {
        let mut m = Message::new(label);
        m.words[0] = self.status as u64;
        m
    }

    pub fn decode(m: &Message, label: u16) -> Result<Self, Status> {
        expect(m, label)?;
        Ok(Self {
            status: m.words[0] as i32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vfs_status_values_match_schema() {
        assert_eq!(vstatus::ENOENT, -15);
        assert_eq!(vstatus::EEXIST, -16);
        assert_eq!(vstatus::ENOTEMPTY, -17);
        assert_eq!(vstatus::ENOTDIR, -18);
        assert_eq!(vstatus::EISDIR, -19);
        assert_eq!(vstatus::EINVAL, -20);
        assert_eq!(vstatus::EACCES, -21);
    }

    #[test]
    fn connect_roundtrip_and_rights() {
        let req = ConnectRequest {
            version: PROTO_VERSION,
            flags: 0,
            session_notification: CapSlot::pack(3, Rights::SIGNAL.union(Rights::GRANT)),
            arg_window: CapSlot::pack(4, Rights::READ.union(Rights::GRANT)),
            result_window: CapSlot::pack(5, Rights::WRITE.union(Rights::MAP).union(Rights::GRANT)),
        };
        assert_eq!(ConnectRequest::decode(&req.encode()).unwrap(), req);

        let weak = ConnectRequest {
            arg_window: CapSlot::pack(4, Rights::GRANT),
            ..req
        };
        assert_eq!(ConnectRequest::decode(&weak.encode()), Err(status::ERIGHTS));

        let mut version_bump = req.encode();
        version_bump.words[0] = 0xFFFF;
        assert_eq!(ConnectRequest::decode(&version_bump), Err(status::ENOSYS));

        let reply = ConnectReply {
            status: status::OK,
            connection_id: 2,
            root_handle: 1,
            endpoint: Some(CapSlot::pack(9, Rights::SEND)),
        };
        assert_eq!(ConnectReply::decode(&reply.encode()).unwrap(), reply);
    }

    #[test]
    fn stat_packing_roundtrip() {
        let s = Stat {
            kind: KIND_FILE,
            mode: 0o755,
            size: 1234,
            mtime_ns: 5_000,
        };
        let (w1, w2, w3) = s.to_words();
        assert_eq!(Stat::from_words(w1, w2, w3), s);
        assert_eq!(w1 as u8, KIND_FILE);
        assert_eq!((w1 >> 8) as u32, 0o755);
    }

    #[test]
    fn name_request_roundtrip_and_label_check() {
        let r = NameRequest {
            dir: 7,
            name: Span::new(16, 4),
            flags: OPEN_READ | OPEN_WRITE,
        };
        let decoded = NameRequest::decode(&r.encode(label::OPEN), label::OPEN).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(
            NameRequest::decode(&r.encode(label::OPEN), label::WALK),
            Err(status::EBADARG)
        );
    }

    #[test]
    fn handle_reply_carries_kind_mode_size() {
        let r = HandleReply {
            status: status::OK,
            handle: 11,
            stat: Some(Stat {
                kind: KIND_DIR,
                mode: 0o755,
                size: 0,
                mtime_ns: 1,
            }),
        };
        let m = r.encode(label::WALK);
        assert_eq!(m.words[1], 11);
        assert_eq!(m.words[2] as u8, KIND_DIR);
        assert_eq!((m.words[2] >> 8) as u32, 0o755);
        assert_eq!(m.words[3], 0, "size");
        assert_eq!(
            HandleReply::decode(&m, label::WALK).unwrap(),
            HandleReply {
                status: status::OK,
                handle: 11,
                stat: None
            }
        );
    }

    #[test]
    fn read_write_shapes() {
        let r = ReadRequest {
            handle: 3,
            offset: 64,
            len: 100,
            result_offset: 8,
        };
        assert_eq!(ReadRequest::decode(&r.encode()).unwrap(), r);

        let w = WriteRequest {
            handle: 3,
            offset: 64,
            data: Span::new(0, 100),
        };
        assert_eq!(WriteRequest::decode(&w.encode()).unwrap(), w);
    }

    #[test]
    fn read_bulk_requires_frame_with_rights() {
        let r = ReadBulkRequest {
            handle: 3,
            offset: 0,
            len: 4096,
            frame: CapSlot::pack(12, Rights::WRITE.union(Rights::MAP)),
        };
        assert_eq!(ReadBulkRequest::decode(&r.encode()).unwrap(), r);

        let weak = ReadBulkRequest {
            frame: CapSlot::pack(12, Rights::WRITE),
            ..r
        };
        assert_eq!(
            ReadBulkRequest::decode(&weak.encode()),
            Err(status::ERIGHTS)
        );

        let null = ReadBulkRequest {
            frame: CapSlot::NULL,
            ..r
        };
        assert_eq!(
            ReadBulkRequest::decode(&null.encode()),
            Err(status::EBADCAP)
        );
    }

    #[test]
    fn readdir_and_rename_and_stat_roundtrips() {
        let rd = ReaddirReply {
            status: status::OK,
            next_cookie: 3,
            name: Span::new(0, 5),
            kind: KIND_FILE,
        };
        assert_eq!(ReaddirReply::decode(&rd.encode()).unwrap(), rd);

        let rn = RenameRequest {
            src_dir: 1,
            src_name: Span::new(0, 3),
            dst_dir: 2,
            dst_name: Span::new(8, 4),
        };
        assert_eq!(RenameRequest::decode(&rn.encode()).unwrap(), rn);

        let st = StatReply {
            status: status::OK,
            stat: Stat {
                kind: KIND_FILE,
                mode: 0o644,
                size: 99,
                mtime_ns: 7,
            },
        };
        assert_eq!(StatReply::decode(&st.encode()).unwrap(), st);
    }

    #[test]
    fn handle_only_ops_roundtrip() {
        let r = HandleRequest { handle: 7, arg: 0 };
        assert_eq!(
            HandleRequest::decode(&r.encode(label::CLOSE), label::CLOSE).unwrap(),
            r
        );
        let t = HandleRequest {
            handle: 7,
            arg: 512,
        };
        assert_eq!(
            HandleRequest::decode(&t.encode(label::TRUNCATE), label::TRUNCATE)
                .unwrap()
                .arg,
            512
        );
        let s = StatusReply {
            status: vstatus::ENOENT,
        };
        assert_eq!(
            StatusReply::decode(&s.encode(label::UNLINK), label::UNLINK).unwrap(),
            s
        );
    }
}
