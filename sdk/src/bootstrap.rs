//! Bootstrap capability package reception (ADR-009; design doc §2.3/2.4).
//!
//! A spawned process's first act: its launcher (the process server) sent a
//! header — label `0x0102` (PACKAGE), `w0` = number of caps that follow — then
//! chunks of up to 4 capability descriptors, over the bootstrap endpoint the
//! kernel installed at **handle 1** (ADR-009). This module drains that package
//! into a named struct and revokes the bootstrap endpoint.
//!
//! Package layout (process design doc §2.3), fixed prefix first:
//! `[aspace, thread, region, session x4, ps_service_ep]`, then the optional
//! trailing caps in caller order: `[vfs, stdin, stdout, stderr]` (nulls from
//! partial grants or trimmed tails appear as absent).

use ipc::{status, CapSlot};

use crate::syscall::{Handle, RawSyscalls, Status, Syscalls};

/// Kernel convention: `NEW_THREAD` installs the bootstrap endpoint at handle 1.
pub const BOOTSTRAP_HANDLE: Handle = 1;

/// PACKAGE label — keep in sync with `servers/process::proto::label::PACKAGE`
/// (owned by the process server; this constant mirrors the design doc).
pub const PACKAGE_LABEL: u16 = 0x0102;

/// Ready callback: a spawned server, after a successful startup, sends one
/// message to its package's service-endpoint slot (the launcher's endpoint)
/// with this label and [`READY_MAGIC`] in `w0` (+ diagnostics in `w1..w3`)
/// before entering its real loop. Launchers assert on it — it is the proof
/// that the child executed its own code.
pub const READY_LABEL: u16 = 0x5053;
pub const READY_MAGIC: u64 = 0x5053_0000_0001;

/// Session notifications in the fixed prefix.
pub const SESSION_POOL: usize = 4;

/// Fixed prefix: aspace, thread, region, 4 sessions, ps service endpoint.
pub const FIXED_CAPS: usize = 3 + SESSION_POOL + 1;

/// Ceiling on package size (fixed array on the child side, no allocator).
pub const MAX_PACKAGE_CAPS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootstrapPackage {
    pub aspace: Handle,
    pub thread: Handle,
    pub region: Handle,
    pub session_notifications: [Handle; SESSION_POOL],
    pub process_server_ep: Handle,
    /// Optional trailing caps in caller order (vfs, stdin, stdout, stderr);
    /// `None` = trimmed tail or a failed (partial) grant.
    pub optional: [Option<CapSlot>; 4],
}

/// Send a bootstrap package (header + chunks of <= 4 caps) to the child's
/// bootstrap endpoint — the launcher side of [`receive`]. `caps` is the full
/// package in the child's expected order (§2.3 prefix + optional tail).
pub fn deliver<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    bootstrap_ep: Handle,
    caps: &[ipc::CapSlot],
) -> Result<(), Status> {
    if caps.len() > MAX_PACKAGE_CAPS || caps.len() < FIXED_CAPS {
        return Err(status::ETOOBIG);
    }
    let mut header = ipc::Message::new(PACKAGE_LABEL);
    header.words[0] = caps.len() as u64;
    sys.send(bootstrap_ep, &header)?;
    for chunk in caps.chunks(ipc::MAX_WORDS) {
        let mut m = ipc::Message::new(PACKAGE_LABEL);
        m.tag = m.tag.with_caps(chunk.len() as u8);
        for (i, slot) in chunk.iter().enumerate() {
            let _ = m.set_descriptor(i, *slot);
        }
        sys.send(bootstrap_ep, &m)?;
    }
    Ok(())
}

/// Receive and unpack the bootstrap package; then `cap_revoke(DELETE)` the
/// bootstrap endpoint (handle 1). Returns the package or the first error.
pub fn receive<R: RawSyscalls>(sys: &mut Syscalls<R>) -> Result<BootstrapPackage, Status> {
    let header = sys.recv(BOOTSTRAP_HANDLE)?;
    if header.tag.label() != PACKAGE_LABEL || header.tag.cap_count() != 0 {
        return Err(status::EBADARG);
    }
    let total = header.words[0] as usize;
    if !(FIXED_CAPS..=MAX_PACKAGE_CAPS).contains(&total) {
        return Err(status::EBADARG);
    }

    let mut caps = [CapSlot::NULL; MAX_PACKAGE_CAPS];
    let mut got = 0usize;
    while got < total {
        let chunk = sys.recv(BOOTSTRAP_HANDLE)?;
        if chunk.tag.label() != PACKAGE_LABEL {
            return Err(status::EBADARG);
        }
        let n = chunk.cap_count();
        if n == 0 || n > ipc::MAX_WORDS || got + n > total {
            return Err(status::EBADARG);
        }
        for (i, slot) in caps[got..got + n].iter_mut().enumerate() {
            *slot = chunk.descriptor(i).ok_or(status::EBADARG)?;
        }
        got += n;
    }

    // The package is complete; the endpoint has served its purpose.
    sys.cap_revoke(BOOTSTRAP_HANDLE, 1)?;

    let mut session_notifications = [0 as Handle; SESSION_POOL];
    for (i, slot) in session_notifications.iter_mut().enumerate() {
        let handle = caps[3 + i].handle();
        if handle == ipc::NULL_HANDLE {
            return Err(status::EBADCAP);
        }
        *slot = handle;
    }
    for cap in &caps[..FIXED_CAPS] {
        if cap.handle() == ipc::NULL_HANDLE {
            return Err(status::EBADCAP);
        }
    }

    let mut optional = [None; 4];
    for (i, slot) in caps[FIXED_CAPS..total].iter().enumerate() {
        if slot.handle() != ipc::NULL_HANDLE {
            optional[i] = Some(*slot);
        }
    }

    Ok(BootstrapPackage {
        aspace: caps[0].handle(),
        thread: caps[1].handle(),
        region: caps[2].handle(),
        session_notifications,
        process_server_ep: caps[FIXED_CAPS - 1].handle(),
        optional,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SysReply;
    use ipc::Tag;
    use std::collections::VecDeque;
    use std::vec;
    use std::vec::Vec;

    struct QueueRaw {
        replies: VecDeque<SysReply>,
        calls: Vec<(u32, [u64; 6])>,
    }

    impl QueueRaw {
        fn new(messages: impl IntoIterator<Item = ipc::Message>) -> Self {
            let mut replies = VecDeque::new();
            for m in messages {
                replies.push_back(SysReply {
                    status: status::OK,
                    tag: m.tag.0,
                    words: m.words,
                });
            }
            Self {
                replies,
                calls: Vec::new(),
            }
        }
    }

    impl RawSyscalls for QueueRaw {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls.push((number, args));
            self.replies.pop_front().unwrap_or_default()
        }
    }

    fn chunk(caps: &[CapSlot]) -> ipc::Message {
        let mut m = ipc::Message::new(PACKAGE_LABEL);
        m.tag = Tag(m.tag.0).with_caps(caps.len() as u8);
        for (i, c) in caps.iter().enumerate() {
            m.words[ipc::MAX_WORDS - caps.len() + i] = c.0;
        }
        m
    }

    fn header(total: usize) -> ipc::Message {
        let mut m = ipc::Message::new(PACKAGE_LABEL);
        m.words[0] = total as u64;
        m
    }

    fn full_package_caps() -> Vec<CapSlot> {
        let mut caps = Vec::new();
        caps.push(CapSlot::pack(10, ipc::Rights::MAP)); // aspace
        caps.push(CapSlot::pack(11, ipc::Rights::CONTROL)); // thread
        caps.push(CapSlot::pack(12, ipc::Rights::GRANT)); // region
        for h in 13..17 {
            caps.push(CapSlot::pack(h, ipc::Rights::SIGNAL)); // sessions
        }
        caps.push(CapSlot::pack(17, ipc::Rights::SEND)); // ps_ep
        caps.push(CapSlot::pack(18, ipc::Rights::SEND)); // vfs
        caps.push(CapSlot::pack(19, ipc::Rights::RECV)); // stdin
        caps
    }

    fn receive_with(messages: Vec<ipc::Message>) -> (Result<BootstrapPackage, Status>, QueueRaw) {
        let mut raw = QueueRaw::new(messages);
        let result;
        {
            let mut sys = Syscalls::new(&mut raw);
            result = receive(&mut sys);
        }
        (result, raw)
    }

    #[test]
    fn full_package_unpacks_and_revokes_bootstrap_ep() {
        let caps = full_package_caps();
        let (result, raw) = receive_with(vec![
            header(caps.len()),
            chunk(&caps[0..4]),
            chunk(&caps[4..8]),
            chunk(&caps[8..10]),
        ]);
        let package = result.unwrap();
        assert_eq!(package.aspace, 10);
        assert_eq!(package.thread, 11);
        assert_eq!(package.region, 12);
        assert_eq!(package.session_notifications, [13, 14, 15, 16]);
        assert_eq!(package.process_server_ep, 17);
        assert_eq!(package.optional[0].unwrap().handle(), 18);
        assert_eq!(package.optional[1].unwrap().handle(), 19);
        assert_eq!(package.optional[2], None);
        assert_eq!(package.optional[3], None);

        let (number, args) = raw.calls.last().unwrap();
        assert_eq!(*number, crate::syscall::number::CAP_REVOKE);
        assert_eq!(args[0], BOOTSTRAP_HANDLE as u64);
        assert_eq!(args[2], 1, "DELETE mode travels in w0 (raw args[2])");
    }

    #[test]
    fn rejects_wrong_header_and_cap_bounds() {
        let mut bad_header = header(FIXED_CAPS);
        bad_header.tag = Tag(bad_header.tag.0).with_caps(1);
        assert_eq!(
            receive_with(vec![bad_header]).0,
            Err(status::EBADARG),
            "header must carry no caps"
        );

        assert_eq!(
            receive_with(vec![header(FIXED_CAPS - 1)]).0,
            Err(status::EBADARG),
            "package smaller than fixed prefix"
        );
        assert_eq!(
            receive_with(vec![header(MAX_PACKAGE_CAPS + 1)]).0,
            Err(status::EBADARG),
            "package above ceiling"
        );

        let mut wrong_label = header(FIXED_CAPS);
        wrong_label.tag = Tag(0x0999);
        assert_eq!(receive_with(vec![wrong_label]).0, Err(status::EBADARG));
    }

    #[test]
    fn rejects_chunk_overshoot_and_empty_chunks() {
        let caps = full_package_caps();
        assert_eq!(
            receive_with(vec![header(5), chunk(&caps[0..4]), chunk(&caps[4..8])]).0,
            Err(status::EBADARG),
            "chunks must not overshoot the header count"
        );
        assert_eq!(
            receive_with(vec![header(5), chunk(&[])]).0,
            Err(status::EBADARG),
            "empty chunk is malformed"
        );
    }

    #[test]
    fn null_required_cap_is_a_bad_cap() {
        let mut caps = full_package_caps();
        caps[2] = CapSlot::NULL; // region wasn't granted
        let (result, _) = receive_with(vec![
            header(caps.len()),
            chunk(&caps[0..4]),
            chunk(&caps[4..8]),
            chunk(&caps[8..10]),
        ]);
        assert_eq!(result, Err(status::EBADCAP));
    }

    #[test]
    fn null_optional_cap_is_absent() {
        let mut caps = full_package_caps();
        caps[8] = CapSlot::NULL; // vfs was a partial grant
        let (result, _) = receive_with(vec![
            header(caps.len()),
            chunk(&caps[0..4]),
            chunk(&caps[4..8]),
            chunk(&caps[8..10]),
        ]);
        let package = result.unwrap();
        assert_eq!(package.optional[0], None);
        assert_eq!(package.optional[1].unwrap().handle(), 19);
    }

    #[test]
    fn deliver_then_receive_roundtrips_a_full_package() {
        use crate::syscall::number;

        #[derive(Default)]
        struct LoopbackRaw {
            queue: VecDeque<ipc::Message>,
            sends: usize,
        }
        impl RawSyscalls for LoopbackRaw {
            fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
                match number {
                    number::SEND => {
                        let mut m = ipc::Message::new(0);
                        m.tag = Tag(args[1]);
                        m.words = [args[2], args[3], args[4], args[5]];
                        self.queue.push_back(m);
                        self.sends += 1;
                        SysReply::default()
                    }
                    number::RECV => {
                        let m = self.queue.pop_front().unwrap_or(ipc::Message {
                            tag: Tag(0),
                            words: [0; 4],
                        });
                        SysReply {
                            status: status::OK,
                            tag: m.tag.0,
                            words: m.words,
                        }
                    }
                    _ => SysReply::default(),
                }
            }
        }

        let mut caps = Vec::new();
        caps.push(CapSlot::pack(
            10,
            ipc::Rights::MAP.union(ipc::Rights::GRANT),
        ));
        caps.push(CapSlot::pack(11, ipc::Rights::CONTROL));
        caps.push(CapSlot::pack(12, ipc::Rights::GRANT));
        for h in 13..17 {
            caps.push(CapSlot::pack(
                h,
                ipc::Rights::SIGNAL.union(ipc::Rights::RECV),
            ));
        }
        caps.push(CapSlot::pack(17, ipc::Rights::SEND));
        caps.push(CapSlot::pack(18, ipc::Rights::ALL)); // tail[0] = Factory

        let mut raw = LoopbackRaw::default();
        let package;
        {
            let mut sys = Syscalls::new(&mut raw);
            deliver(&mut sys, BOOTSTRAP_HANDLE, &caps).unwrap();
            package = receive(&mut sys).unwrap();
        }
        assert_eq!(raw.sends, 4, "header + 3 chunks for 10 caps");
        assert_eq!(package.aspace, 10);
        assert_eq!(package.thread, 11);
        assert_eq!(package.region, 12);
        assert_eq!(package.session_notifications, [13, 14, 15, 16]);
        assert_eq!(package.process_server_ep, 17);
        assert_eq!(package.optional[0].unwrap().handle(), 18);
        assert_eq!(package.optional[0].unwrap().rights(), ipc::Rights::ALL);
    }

    #[test]
    fn deliver_rejects_bad_lengths() {
        #[derive(Default)]
        struct NoopRaw;
        impl RawSyscalls for NoopRaw {
            fn raw(&mut self, _n: u32, _a: [u64; 6]) -> SysReply {
                SysReply::default()
            }
        }
        let mut raw = NoopRaw;
        let mut sys = Syscalls::new(&mut raw);
        assert_eq!(
            deliver(&mut sys, 1, &[CapSlot::NULL; FIXED_CAPS - 1]),
            Err(status::ETOOBIG)
        );
        assert_eq!(
            deliver(&mut sys, 1, &[CapSlot::NULL; MAX_PACKAGE_CAPS + 1]),
            Err(status::ETOOBIG)
        );
    }

    #[test]
    fn header_only_package_with_exact_prefix() {
        let caps = full_package_caps();
        let (result, _) = receive_with(vec![
            header(FIXED_CAPS),
            chunk(&caps[0..4]),
            chunk(&caps[4..8]),
        ]);
        let package = result.unwrap();
        assert_eq!(package.process_server_ep, 17);
        assert_eq!(package.optional, [None; 4]);
    }
}
