//! Raw syscall layer (syscall-abi §2/§3). Exactly one inline-asm site on
//! x86_64; every wrapper is generic over [`RawSyscalls`] and host-testable.
//!
//! Argument layout for every syscall: `(cap, tag, w0..w3)`.
//! Return layout: `rax` = status, `rdx` = tag, `rsi/rdi/r8/r9` = w0..w3.

use ipc::{Message, Rights, Tag};

/// Status codes are the shared `ipc::status` space (negative = error).
pub type Status = i32;

/// Syscall numbers (frozen set, ADR-005).
pub mod number {
    pub const YIELD: u32 = 0;
    pub const SEND: u32 = 1;
    pub const CALL: u32 = 2;
    pub const RECV: u32 = 3;
    pub const REPLY_RECV: u32 = 4;
    pub const INVOKE: u32 = 5;
    pub const CAP_MINT: u32 = 6;
    pub const CAP_REVOKE: u32 = 7;
    pub const EXIT: u32 = 8;
}

/// `send` to this handle routes through the implicit reply cap (ADR-009).
pub const REPLY_CAP: u32 = 0xFFFF_FFFE;

/// `cap_mint` destination: install into the first free slot (ADR-005).
pub const FIRST_FREE_SLOT: u32 = ipc::FIRST_FREE_SLOT;

/// Raw result of one syscall. `tag` doubles as the first return word —
/// `cap_mint` returns the new handle there (syscall-abi §3).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct SysReply {
    pub status: i32,
    pub tag: u64,
    pub words: [u64; 4],
}

impl SysReply {
    pub fn message(&self) -> Message {
        Message {
            tag: Tag(self.tag),
            words: self.words,
        }
    }
}

/// The single hardware-dependent operation. Test mocks implement this to
/// record arguments; x86_64 uses the `syscall` instruction.
pub trait RawSyscalls {
    fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply;
}

pub type Handle = u32;

fn check(status: i32) -> Result<(), i32> {
    if status == ipc::status::OK {
        Ok(())
    } else {
        Err(status)
    }
}

/// Typed syscall wrappers (syscall-abi §3). Holds a `&mut` raw backend.
pub struct Syscalls<'a, R: RawSyscalls> {
    raw: &'a mut R,
}

impl<'a, R: RawSyscalls> Syscalls<'a, R> {
    pub fn new(raw: &'a mut R) -> Self {
        Self { raw }
    }

    fn pack_args(cap: Handle, msg: &Message) -> [u64; 6] {
        [
            cap as u64,
            msg.tag.0,
            msg.words[0],
            msg.words[1],
            msg.words[2],
            msg.words[3],
        ]
    }

    /// `send` (blocking unless `FLAG_NONBLOCK` is set in the tag).
    pub fn send(&mut self, cap: Handle, msg: &Message) -> Result<(), Status> {
        check(self.raw.raw(number::SEND, Self::pack_args(cap, msg)).status)
    }

    /// `call`: send and wait for the reply.
    pub fn call(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status> {
        let r = self.raw.raw(number::CALL, Self::pack_args(cap, msg));
        check(r.status).map(|_| r.message())
    }

    /// `recv` on an endpoint, notification, or IRQ capability.
    pub fn recv(&mut self, cap: Handle) -> Result<Message, Status> {
        let r = self.raw.raw(number::RECV, [cap as u64, 0, 0, 0, 0, 0]);
        check(r.status).map(|_| r.message())
    }

    /// `reply_recv`: reply through the implicit reply cap, then receive on
    /// `cap` — the server fast path.
    pub fn reply_recv(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status> {
        let r = self.raw.raw(number::REPLY_RECV, Self::pack_args(cap, msg));
        check(r.status).map(|_| r.message())
    }

    /// Reply-only escape hatch (ADR-009): a terminal reply with no follow-up
    /// receive. Equivalent to `send(REPLY_CAP, msg)`.
    pub fn reply(&mut self, msg: &Message) -> Result<(), Status> {
        self.send(REPLY_CAP, msg)
    }

    /// `invoke`: method call on a kernel object capability. `msg.tag`'s label
    /// is the method id (syscall-abi §7).
    pub fn invoke(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status> {
        let r = self.raw.raw(number::INVOKE, Self::pack_args(cap, msg));
        check(r.status).map(|_| r.message())
    }

    /// `cap_mint`: derive a capability. `dst` = `Some(slot)` for an absolute
    /// slot or `None` for first-free. Returns the installed handle.
    pub fn cap_mint(
        &mut self,
        src: Handle,
        rights: Rights,
        dst: Option<u32>,
    ) -> Result<Handle, Status> {
        let slot = dst.unwrap_or(FIRST_FREE_SLOT);
        let args = [src as u64, slot as u64, rights.0 as u64, 0, 0, 0];
        let r = self.raw.raw(number::CAP_MINT, args);
        check(r.status).map(|_| r.tag as u32)
    }

    /// `cap_revoke`: mode 0 = `REVOKE_DERIVED` (keep cap), 1 = `DELETE`.
    pub fn cap_revoke(&mut self, cap: Handle, mode: u32) -> Result<(), Status> {
        let args = [cap as u64, mode as u64, 0, 0, 0, 0];
        check(self.raw.raw(number::CAP_REVOKE, args).status)
    }

    /// `yield`: voluntarily deschedule.
    pub fn yield_now(&mut self) -> Result<(), Status> {
        check(self.raw.raw(number::YIELD, [0; 6]).status)
    }

    /// `exit`: terminate the calling thread. The kernel never resumes it; a
    /// host-test mock returning here is a loud failure.
    pub fn exit(&mut self, status: i32) -> ! {
        let _ = self.raw.raw(number::EXIT, [status as u64, 0, 0, 0, 0, 0]);
        panic!("exit syscall returned");
    }
}

/// x86_64 backend: the `syscall` instruction with the register conventions of
/// syscall-abi §2 (`rcx`/`r11` are clobbered by the instruction; args arrive
/// in `rdi/rsi/rdx/r10/r8/r9`, returns in `rax/rdx/rsi/rdi/r8/r9`).
#[cfg(target_arch = "x86_64")]
pub struct X86_64Syscalls;

#[cfg(target_arch = "x86_64")]
impl RawSyscalls for X86_64Syscalls {
    fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
        let (status, tag, w0, w1, w2, w3): (u64, u64, u64, u64, u64, u64);
        // SAFETY: `syscall` transfers control to the kernel's syscall entry,
        // which per the ratified ABI (sdk/docs/syscall-abi.md §2) reads the
        // number from rax and arguments from rdi/rsi/rdx/r10/r8/r9, returns
        // status in rax and tag/words in rdx/rsi/rdi/r8/r9, and clobbers
        // rcx/r11. It touches no user memory for register-sized messages, so
        // the stack is not used.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") number as u64 => status,
                inlateout("rdi") args[0] => w1,
                inlateout("rsi") args[1] => w0,
                inlateout("rdx") args[2] => tag,
                inlateout("r10") args[3] => _,
                inlateout("r8") args[4] => w2,
                inlateout("r9") args[5] => w3,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack)
            );
        }
        SysReply {
            status: status as i32,
            tag,
            words: [w0, w1, w2, w3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::status;

    /// Records raw calls; returns a canned reply.
    struct MockRaw {
        calls: std::vec::Vec<(u32, [u64; 6])>,
        reply: SysReply,
    }

    impl MockRaw {
        fn ok() -> Self {
            Self {
                calls: std::vec::Vec::new(),
                reply: SysReply::default(),
            }
        }
    }

    impl RawSyscalls for MockRaw {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls.push((number, args));
            self.reply
        }
    }

    fn msg(label: u16) -> Message {
        let mut m = Message::new(label);
        m.words = [10, 20, 30, 40];
        m
    }

    #[test]
    fn send_packs_cap_tag_and_words() {
        let mut raw = MockRaw::ok();
        {
            let mut sys = Syscalls::new(&mut raw);
            sys.send(7, &msg(0x0101)).unwrap();
        }
        let (number, args) = raw.calls[0];
        assert_eq!(number, number::SEND);
        assert_eq!(args[0], 7);
        assert_eq!(args[1], msg(0x0101).tag.0);
        assert_eq!(&args[2..], &[10, 20, 30, 40]);
    }

    #[test]
    fn call_returns_the_reply_message() {
        let mut raw = MockRaw::ok();
        raw.reply = SysReply {
            status: status::OK,
            tag: Tag::new(0x0110).0,
            words: [1, 2, 3, 4],
        };
        let reply;
        {
            let mut sys = Syscalls::new(&mut raw);
            reply = sys.call(9, &msg(0x0110)).unwrap();
        }
        assert_eq!(reply.tag.label(), 0x0110);
        assert_eq!(reply.words, [1, 2, 3, 4]);
    }

    #[test]
    fn negative_status_becomes_err() {
        let mut raw = MockRaw::ok();
        raw.reply.status = status::EBADCAP;
        {
            let mut sys = Syscalls::new(&mut raw);
            assert_eq!(sys.recv(3), Err(status::EBADCAP));
            sys.send(3, &msg(1)).unwrap_err();
            assert_eq!(sys.cap_revoke(3, 0).unwrap_err(), status::EBADCAP);
            assert_eq!(
                sys.cap_mint(3, Rights::SEND, None).unwrap_err(),
                status::EBADCAP
            );
        }
    }

    #[test]
    fn reply_recv_packs_and_returns() {
        let mut raw = MockRaw::ok();
        raw.reply = SysReply {
            status: status::OK,
            tag: Tag::new(0x0111).0,
            words: [5, 0, 0, 0],
        };
        let next;
        {
            let mut sys = Syscalls::new(&mut raw);
            next = sys.reply_recv(4, &msg(0x0110)).unwrap();
        }
        assert_eq!(raw.calls[0].0, number::REPLY_RECV);
        assert_eq!(raw.calls[0].1[0], 4);
        assert_eq!(next.tag.label(), 0x0111);
    }

    #[test]
    fn reply_uses_the_sentinel_cap() {
        let mut raw = MockRaw::ok();
        {
            let mut sys = Syscalls::new(&mut raw);
            sys.reply(&msg(0x0101)).unwrap();
        }
        assert_eq!(raw.calls[0].0, number::SEND);
        assert_eq!(raw.calls[0].1[0], REPLY_CAP as u64);
    }

    #[test]
    fn cap_mint_reads_handle_from_first_return_word_and_defaults_slot() {
        let mut raw = MockRaw::ok();
        raw.reply.tag = 42;
        {
            let mut sys = Syscalls::new(&mut raw);
            let h = sys
                .cap_mint(8, Rights::SEND.union(Rights::GRANT), None)
                .unwrap();
            assert_eq!(h, 42);
            let _ = sys.cap_mint(8, Rights::SEND, Some(11)).unwrap();
        }
        assert_eq!(raw.calls[0].0, number::CAP_MINT);
        assert_eq!(raw.calls[0].1[0], 8, "source handle");
        assert_eq!(raw.calls[0].1[1], FIRST_FREE_SLOT as u64);
        assert_eq!(
            raw.calls[0].1[2],
            Rights::SEND.union(Rights::GRANT).0 as u64
        );
        assert_eq!(raw.calls[1].1[1], 11, "absolute slot");
    }

    #[test]
    fn yield_and_revoke_argument_shapes() {
        let mut raw = MockRaw::ok();
        {
            let mut sys = Syscalls::new(&mut raw);
            sys.yield_now().unwrap();
            sys.cap_revoke(5, 1).unwrap();
        }
        assert_eq!(raw.calls[0], (number::YIELD, [0; 6]));
        assert_eq!(raw.calls[1].0, number::CAP_REVOKE);
        assert_eq!(raw.calls[1].1[..2], [5, 1]);
    }
}
