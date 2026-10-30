//! Real runtime: [`VfsKernel`] and [`Transport`] over the SDK syscalls
//! (`sdk::syscall`), mirroring `servers/process::runtime_impl`. Generic over
//! [`RawSyscalls`] so packing is host-testable; the VFS server binary
//! instantiates it with the x86_64 backend.
//!
//! `now_ns` is a v0 stub: there is no time syscall yet (timer service lands in
//! Phase 2); mtime stamps stay 0 until then.

use ipc::Message;
use sdk::methods;
use sdk::syscall::{RawSyscalls, Syscalls};

use crate::proto::Status;
use crate::runtime::{Handle, Transport, VfsKernel};

pub struct Runtime<'a, R: RawSyscalls> {
    sys: Syscalls<'a, R>,
    factory: Handle,
}

impl<'a, R: RawSyscalls> Runtime<'a, R> {
    pub fn new(raw: &'a mut R, factory: Handle) -> Self {
        Self {
            sys: Syscalls::new(raw),
            factory,
        }
    }
}

impl<R: RawSyscalls> VfsKernel for Runtime<'_, R> {
    fn new_endpoint(&mut self) -> Result<Handle, Status> {
        let msg = Message::new(methods::factory::NEW_ENDPOINT);
        let reply = self.sys.invoke(self.factory, &msg)?;
        let handle = reply.words[0] as Handle;
        if handle == 0 {
            return Err(ipc::status::ENOMEM);
        }
        Ok(handle)
    }

    fn now_ns(&mut self) -> u64 {
        // v0 stub: becomes a timer-server call (or a kernel time syscall) when
        // the timer service exists; returning 0 keeps mtimes deterministic.
        0
    }
}

impl<R: RawSyscalls> Transport for Runtime<'_, R> {
    fn recv(&mut self, on: Handle) -> Result<Message, Status> {
        self.sys.recv(on)
    }

    fn reply(&mut self, msg: &Message) -> Result<(), Status> {
        self.sys.reply(msg)
    }

    fn reply_recv(&mut self, on: Handle, msg: &Message) -> Result<Message, Status> {
        self.sys.reply_recv(on, msg)
    }

    fn send(&mut self, on: Handle, msg: &Message) -> Result<(), Status> {
        self.sys.send(on, msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk::syscall::{number, SysReply};
    use std::vec::Vec;

    #[derive(Default)]
    struct MockRaw {
        calls: Vec<(u32, [u64; 6])>,
        next_handle: u32,
        status: i32,
    }

    impl RawSyscalls for MockRaw {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls.push((number, args));
            self.next_handle = self.next_handle.wrapping_add(1);
            SysReply {
                status: self.status,
                words: [self.next_handle as u64, 0, 0, 0],
                ..SysReply::default()
            }
        }
    }

    #[test]
    fn new_endpoint_is_a_factory_invoke_returning_w0() {
        let mut raw = MockRaw::default();
        let handle = {
            let mut rt = Runtime::new(&mut raw, 8);
            rt.new_endpoint().unwrap()
        };
        assert_eq!(handle, 1);
        let (number, args) = raw.calls[0];
        assert_eq!(number, number::INVOKE);
        assert_eq!(args[0], 8, "factory cap");
        assert_eq!(args[1] as u16, methods::factory::NEW_ENDPOINT);
    }

    #[test]
    fn new_endpoint_propagates_status_and_rejects_null_handle() {
        let mut failing = MockRaw {
            status: ipc::status::EBADCAP,
            ..Default::default()
        };
        {
            let mut rt = Runtime::new(&mut failing, 8);
            assert_eq!(rt.new_endpoint(), Err(ipc::status::EBADCAP));
        }

        // Success status but handle 0 (nothing installed) is ENOMEM.
        let nullish = MockRaw {
            next_handle: u32::MAX,
            ..Default::default()
        };
        let mut nullish = nullish;
        {
            let mut rt = Runtime::new(&mut nullish, 8);
            assert_eq!(rt.new_endpoint(), Err(ipc::status::ENOMEM));
        }
    }

    #[test]
    fn now_ns_is_a_zero_stub() {
        let mut raw = MockRaw::default();
        let mut rt = Runtime::new(&mut raw, 8);
        assert_eq!(rt.now_ns(), 0);
    }

    #[test]
    fn transport_delegates_and_reply_uses_the_sentinel() {
        let mut raw = MockRaw::default();
        let msg = Message::new(0x0201);
        {
            let mut rt = Runtime::new(&mut raw, 8);
            let _ = rt.recv(4);
            rt.reply(&msg).unwrap();
            rt.send(5, &msg).unwrap();
        }
        assert_eq!(raw.calls[0].0, number::RECV);
        assert_eq!(raw.calls[0].1[0], 4);
        assert_eq!(raw.calls[1].0, number::SEND);
        assert_eq!(raw.calls[1].1[0], sdk::syscall::REPLY_CAP as u64);
        assert_eq!(raw.calls[2].1[0], 5);
    }
}
