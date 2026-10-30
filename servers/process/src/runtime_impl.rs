//! Real runtime: [`KernelOps`] and [`Transport`] over the SDK syscalls
//! (`sdk::syscall`). Generic over [`RawSyscalls`] so the exact argument
//! packing is host-testable; the process server binary instantiates it with
//! the x86_64 backend.
//!
//! `NEW_THREAD` packing follows ADR-017: w0 = entry PC, caps positional
//! `[aspace, fault_ep?, bootstrap_ep?]` (NULL = absent), stack top is the
//! `sdk::layout::USER_STACK_TOP` ABI constant, non-default priorities go
//! through `Thread::SET_PRIORITY` right after creation.
//!
//! `Windows` (reading window frames) is intentionally absent: it needs the
//! server's mapped window addresses, which arrive with the first real address
//! space layout (integration milestone).

use alloc::vec::Vec;

use ipc::{CapSlot, Message, Rights};
use sdk::methods;
use sdk::syscall::{RawSyscalls, Syscalls};
use sdk::window::WindowMapper;

use crate::proto::{Span, Status};
use crate::runtime::{Handle, KernelOps, MapFlags, Transport, Windows};

/// Window VA reservations per server (one 4 KiB frame per window, ADR-021).
const MAX_WINDOWS: usize = 64;

/// Builds an `invoke` message for `method` with payload words and capability
/// descriptors. Descriptors overlay the *trailing* words, so `cap_count` is
/// set before the payload is written (words[0] stays free for up to 3 caps).
fn invoke_msg(method: u16, words: [u64; 4], caps: &[CapSlot]) -> Message {
    let mut m = Message::new(method);
    m.tag = m.tag.with_caps(caps.len() as u8);
    m.words = words;
    for (i, c) in caps.iter().enumerate() {
        let _ = m.set_descriptor(i, *c);
    }
    m
}

fn first_word(msg: &Message) -> Result<Handle, Status> {
    Ok(msg.words[0] as Handle)
}

pub struct Runtime<'a, R: RawSyscalls> {
    sys: Syscalls<'a, R>,
    factory: Handle,
    windows: WindowMapper,
}

impl<'a, R: RawSyscalls> Runtime<'a, R> {
    /// `as_cap` = the server's self-AS cap (spawn package); `window_va_base` =
    /// `sdk::layout::PS_WINDOW_VA_BASE`.
    pub fn new(raw: &'a mut R, factory: Handle, as_cap: Handle, window_va_base: u64) -> Self {
        Self {
            sys: Syscalls::new(raw),
            factory,
            windows: WindowMapper::new(as_cap, window_va_base, MAX_WINDOWS),
        }
    }

    fn invoke(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status> {
        self.sys.invoke(cap, msg)
    }

    /// Map a window frame on first use; returns its VA (ADR-021).
    pub fn map_window(&mut self, frame: Handle, flags: u32) -> Result<u64, Status> {
        Ok(self.windows.window_of(&mut self.sys, frame, flags)?.va())
    }

    fn factory_op(&mut self, method: u16) -> Result<Handle, Status> {
        let reply = self.invoke(self.factory, &invoke_msg(method, [0; 4], &[]))?;
        first_word(&reply)
    }
}

impl<R: RawSyscalls> KernelOps for Runtime<'_, R> {
    fn new_endpoint(&mut self) -> Result<Handle, Status> {
        self.factory_op(methods::factory::NEW_ENDPOINT)
    }

    fn new_notification(&mut self) -> Result<Handle, Status> {
        self.factory_op(methods::factory::NEW_NOTIFICATION)
    }

    fn new_address_space(&mut self) -> Result<Handle, Status> {
        self.factory_op(methods::factory::NEW_ADDRESS_SPACE)
    }

    fn new_thread(
        &mut self,
        aspace: Handle,
        entry: u64,
        stack_top: u64,
        priority: u8,
        fault_ep: Option<Handle>,
        bootstrap_ep: Option<Handle>,
    ) -> Result<Handle, Status> {
        if stack_top != sdk::layout::USER_STACK_TOP {
            return Err(ipc::status::EBADARG);
        }
        let mut caps = [CapSlot::NULL; 3];
        caps[0] = CapSlot::pack(aspace, Rights::MAP.union(Rights::GRANT));
        if let Some(ep) = fault_ep {
            caps[1] = CapSlot::pack(ep, Rights::RECV);
        }
        if let Some(ep) = bootstrap_ep {
            caps[2] = CapSlot::pack(ep, Rights::RECV);
        }
        let reply = self.invoke(
            self.factory,
            &invoke_msg(methods::factory::NEW_THREAD, [entry, 0, 0, 0], &caps),
        )?;
        let thread = first_word(&reply)?;
        if priority != sdk::layout::DEFAULT_THREAD_PRIORITY {
            self.invoke(
                thread,
                &invoke_msg(
                    methods::thread::SET_PRIORITY,
                    [priority as u64, 0, 0, 0],
                    &[],
                ),
            )?;
        }
        Ok(thread)
    }

    fn bind_death_notification(
        &mut self,
        thread: Handle,
        notif: Option<Handle>,
    ) -> Result<(), Status> {
        let mut caps = [CapSlot::NULL; 1];
        let n = if let Some(handle) = notif {
            caps[0] = CapSlot::pack(handle, Rights::SIGNAL);
            1
        } else {
            0
        };
        self.invoke(
            thread,
            &invoke_msg(methods::thread::BIND_DEATH_NOTIFICATION, [0; 4], &caps[..n]),
        )
        .map(|_| ())
    }

    fn carve_frame(&mut self, region: Handle, len: u64, align: u64) -> Result<Handle, Status> {
        let reply = self.invoke(
            region,
            &invoke_msg(methods::region::CARVE, [len, align, 0, 0], &[]),
        )?;
        first_word(&reply)
    }

    fn map_frame(
        &mut self,
        aspace: Handle,
        frame: Handle,
        vaddr: u64,
        flags: MapFlags,
    ) -> Result<(), Status> {
        let msg = invoke_msg(
            methods::aspace::MAP,
            [vaddr, flags.0 as u64, 0, 0],
            &[CapSlot::pack(frame, Rights::MAP)],
        );
        self.invoke(aspace, &msg).map(|_| ())
    }

    fn set_fault_pool(&mut self, aspace: Handle, region: Handle) -> Result<(), Status> {
        let msg = invoke_msg(
            methods::aspace::SET_FAULT_POOL,
            [0; 4],
            &[CapSlot::pack(region, Rights::GRANT)],
        );
        self.invoke(aspace, &msg).map(|_| ())
    }

    fn mint_here(&mut self, src: Handle, rights: Rights) -> Result<Handle, Status> {
        self.sys.cap_mint(src, rights, None)
    }

    fn kill_thread(&mut self, thread: Handle) -> Result<(), Status> {
        self.invoke(thread, &invoke_msg(methods::thread::KILL, [0; 4], &[]))
            .map(|_| ())
    }

    fn signal(&mut self, notif: Handle, mask: u64) -> Result<(), Status> {
        self.invoke(
            notif,
            &invoke_msg(methods::notification::SIGNAL, [mask, 0, 0, 0], &[]),
        )
        .map(|_| ())
    }
}

impl<R: RawSyscalls> Windows for Runtime<'_, R> {
    fn read(&mut self, window: Handle, span: Span) -> Result<Vec<u8>, Status> {
        let w = self
            .windows
            .window_of(&mut self.sys, window, sdk::window::FLAG_READ)?;
        w.read(span.offset, span.len)
    }

    fn write(&mut self, window: Handle, span: Span, data: &[u8]) -> Result<(), Status> {
        if span.len as usize != data.len() {
            return Err(ipc::status::EBADARG);
        }
        let w = self
            .windows
            .window_of(&mut self.sys, window, sdk::window::FLAG_WRITE)?;
        w.write(span.offset, data)
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

    fn call(&mut self, on: Handle, msg: &Message) -> Result<Message, Status> {
        self.sys.call(on, msg)
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
    }

    impl RawSyscalls for MockRaw {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls.push((number, args));
            self.next_handle += 1;
            let mut reply = SysReply::default();
            reply.words[0] = self.next_handle as u64;
            reply
        }
    }

    /// (handle, rights) of a descriptor word.
    fn cap(word: u64) -> (u32, u32) {
        (word as u32, (word >> 32) as u32)
    }

    fn runtime(raw: &mut MockRaw) -> Runtime<'_, MockRaw> {
        Runtime::new(raw, 8, 9, sdk::layout::PS_WINDOW_VA_BASE)
    }

    #[test]
    fn map_window_invokes_as_map_at_the_reserved_base() {
        let mut raw = MockRaw::default();
        let va = {
            let mut rt = runtime(&mut raw);
            rt.map_window(30, sdk::window::FLAG_READ).unwrap()
        };
        assert_eq!(va, sdk::layout::PS_WINDOW_VA_BASE);
        let (number, args) = raw.calls[0];
        assert_eq!(number, number::INVOKE);
        assert_eq!(args[0], 9, "invoke on the self-AS cap");
        assert_eq!(args[1] as u16, sdk::methods::aspace::MAP);
        assert_eq!(args[2], va, "w0 = vaddr");
        assert_eq!(args[3], sdk::window::FLAG_READ as u64, "w1 = flags");
        assert_eq!(args[5] as u32, 30, "caps[0] = window frame");
    }

    #[test]
    fn factory_ops_return_fresh_handles() {
        let mut raw = MockRaw::default();
        let (a, b, c) = {
            let mut rt = runtime(&mut raw);
            (
                rt.new_endpoint().unwrap(),
                rt.new_endpoint().unwrap(),
                rt.new_address_space().unwrap(),
            )
        };
        assert_eq!((a, b, c), (1, 2, 3));
        for (i, method) in [
            methods::factory::NEW_ENDPOINT,
            methods::factory::NEW_ENDPOINT,
            methods::factory::NEW_ADDRESS_SPACE,
        ]
        .iter()
        .enumerate()
        {
            let (number, args) = raw.calls[i];
            assert_eq!(number, number::INVOKE);
            assert_eq!(args[0], 8, "factory cap");
            assert_eq!(args[1] as u16, *method);
        }
    }

    #[test]
    fn new_thread_packs_adr017_layout() {
        let mut raw = MockRaw::default();
        {
            let mut rt = runtime(&mut raw);
            rt.new_thread(
                5,
                0x1000,
                sdk::layout::USER_STACK_TOP,
                100,
                Some(6),
                Some(7),
            )
            .unwrap();
        }
        assert_eq!(raw.calls.len(), 1, "default priority needs no SET_PRIORITY");
        let (number, args) = raw.calls[0];
        assert_eq!(number, number::INVOKE);
        assert_eq!(args[0], 8, "invoke on factory");
        let tag = ipc::Tag(args[1]);
        assert_eq!(tag.label(), methods::factory::NEW_THREAD);
        assert_eq!(tag.cap_count(), 3);
        assert_eq!(args[2], 0x1000, "w0 = entry PC");
        let d0 = cap(args[3]);
        let d1 = cap(args[4]);
        let d2 = cap(args[5]);
        assert_eq!(d0.0, 5, "caps[0] = aspace");
        assert_eq!(d0.1, (Rights::MAP.union(Rights::GRANT)).0);
        assert_eq!(d1.0, 6, "caps[1] = fault ep");
        assert_eq!(d2.0, 7, "caps[2] = bootstrap ep");
    }

    #[test]
    fn new_thread_null_descriptors_keep_positions() {
        let mut raw = MockRaw::default();
        {
            let mut rt = runtime(&mut raw);
            rt.new_thread(5, 0x1000, sdk::layout::USER_STACK_TOP, 100, None, Some(7))
                .unwrap();
        }
        let (_, args) = raw.calls[0];
        assert_eq!(
            ipc::Tag(args[1]).cap_count(),
            3,
            "always 3 descriptor slots"
        );
        assert_eq!(
            cap(args[4]).0,
            0,
            "absent fault ep is NULL, not shifted out"
        );
        assert_eq!(cap(args[5]).0, 7, "bootstrap stays at caps[2]");
    }

    #[test]
    fn new_thread_non_default_priority_uses_set_priority() {
        let mut raw = MockRaw::default();
        let thread = {
            let mut rt = runtime(&mut raw);
            rt.new_thread(5, 0x1000, sdk::layout::USER_STACK_TOP, 8, Some(6), Some(7))
                .unwrap()
        };
        assert_eq!(thread, 1, "handle returned by NEW_THREAD");
        assert_eq!(raw.calls.len(), 2);
        let (number, args) = raw.calls[1];
        assert_eq!(number, number::INVOKE);
        assert_eq!(args[0], 1, "invoke on the new thread cap");
        assert_eq!(args[1] as u16, methods::thread::SET_PRIORITY);
        assert_eq!(args[2], 8, "priority in w0");
    }

    #[test]
    fn new_thread_rejects_non_abi_stack_top() {
        let mut raw = MockRaw::default();
        let err = {
            let mut rt = runtime(&mut raw);
            rt.new_thread(
                5,
                0x1000,
                sdk::layout::USER_STACK_TOP - 4096,
                100,
                None,
                None,
            )
            .unwrap_err()
        };
        assert_eq!(err, ipc::status::EBADARG);
        assert!(raw.calls.is_empty());
    }

    #[test]
    fn map_and_pool_invoke_aspace_with_descriptor_overlay() {
        let mut raw = MockRaw::default();
        {
            let mut rt = runtime(&mut raw);
            rt.map_frame(
                3,
                9,
                0x4000,
                MapFlags::R.union(MapFlags::W).union(MapFlags::COW),
            )
            .unwrap();
            rt.set_fault_pool(3, 7).unwrap();
        }
        let (_, args) = raw.calls[0];
        assert_eq!(args[0], 3, "aspace cap");
        assert_eq!(args[1] as u16, methods::aspace::MAP);
        assert_eq!(args[2], 0x4000, "w0 = vaddr");
        assert_eq!(
            args[3],
            (MapFlags::R.union(MapFlags::W).union(MapFlags::COW)).0 as u64,
            "w1 = flags"
        );
        assert_eq!(cap(args[5]).0, 9, "word[3] = frame descriptor");
        assert_eq!(cap(args[5]).1, Rights::MAP.0, "frame mapped with MAP right");

        let (_, args) = raw.calls[1];
        assert_eq!(args[1] as u16, methods::aspace::SET_FAULT_POOL);
        assert_eq!(cap(args[5]).0, 7, "region descriptor");
    }

    #[test]
    fn carve_signal_kill_and_bind_shapes() {
        let mut raw = MockRaw::default();
        {
            let mut rt = runtime(&mut raw);
            let frame = rt.carve_frame(22, 16 * 1024, 4096).unwrap();
            assert_eq!(frame, 1);
            rt.signal(20, 0b101).unwrap();
            rt.kill_thread(21).unwrap();
            rt.bind_death_notification(21, Some(23)).unwrap();
            rt.bind_death_notification(21, None).unwrap();
        }
        let (_, args) = raw.calls[0];
        assert_eq!(args[0], 22, "region cap");
        assert_eq!(args[1] as u16, methods::region::CARVE);
        assert_eq!(args[2], 16 * 1024);
        assert_eq!(args[3], 4096);

        let (_, args) = raw.calls[1];
        assert_eq!(args[0], 20);
        assert_eq!(args[1] as u16, methods::notification::SIGNAL);
        assert_eq!(args[2], 0b101, "mask in w0");

        let (_, args) = raw.calls[2];
        assert_eq!(args[0], 21);
        assert_eq!(args[1] as u16, methods::thread::KILL);

        let (_, args) = raw.calls[3];
        assert_eq!(args[1] as u16, methods::thread::BIND_DEATH_NOTIFICATION);
        assert_eq!(ipc::Tag(args[1]).cap_count(), 1);
        assert_eq!(cap(args[5]).0, 23, "notification descriptor");
        let (_, args) = raw.calls[4];
        assert_eq!(ipc::Tag(args[1]).cap_count(), 0, "clear uses no caps");
    }

    #[test]
    fn mint_uses_the_syscall_not_invoke() {
        let mut raw = MockRaw::default();
        {
            let mut rt = runtime(&mut raw);
            let _ = rt.mint_here(30, Rights::SEND);
        }
        let (number, args) = raw.calls[0];
        assert_eq!(number, number::CAP_MINT);
        assert_eq!(args[0], 30);
        assert_eq!(args[2], Rights::SEND.0 as u64);
    }

    #[test]
    fn transport_delegates_and_reply_uses_the_sentinel() {
        let mut raw = MockRaw::default();
        let msg = Message::new(0x0101);
        {
            let mut rt = runtime(&mut raw);
            let _ = rt.recv(4);
            rt.reply(&msg).unwrap();
        }
        assert_eq!(raw.calls[0].0, number::RECV);
        assert_eq!(raw.calls[0].1[0], 4);
        assert_eq!(raw.calls[1].0, number::SEND);
        assert_eq!(raw.calls[1].1[0], sdk::syscall::REPLY_CAP as u64);
    }
}
