//! Test doubles shared by the unit tests of this crate.

use alloc::vec;
use alloc::vec::Vec;
use std::collections::{BTreeMap, VecDeque};

use ipc::{status, Message, Rights};

use crate::proto::{self, Span, Status};
use crate::runtime::{
    Handle, KernelOps, LoadedImage, MapFlags, ProgramLoader, Segment, Transport, Windows,
};
use crate::server::DEFAULT_STACK_SIZE;

#[derive(Default)]
pub struct MockKernel {
    pub next: Handle,
    pub ops: Vec<&'static str>,
    pub killed: Vec<Handle>,
    pub signals: Vec<(Handle, u64)>,
}

impl MockKernel {
    fn alloc(&mut self) -> Handle {
        self.next += 1;
        self.next
    }
}

impl KernelOps for MockKernel {
    fn new_endpoint(&mut self) -> Result<Handle, Status> {
        self.ops.push("new_endpoint");
        Ok(self.alloc())
    }

    fn new_notification(&mut self) -> Result<Handle, Status> {
        self.ops.push("new_notification");
        Ok(self.alloc())
    }

    fn new_address_space(&mut self) -> Result<Handle, Status> {
        self.ops.push("new_address_space");
        Ok(self.alloc())
    }

    fn new_thread(
        &mut self,
        _aspace: Handle,
        _entry: u64,
        _stack_top: u64,
        _priority: u8,
        fault_ep: Option<Handle>,
        bootstrap_ep: Option<Handle>,
    ) -> Result<Handle, Status> {
        assert!(fault_ep.is_some(), "spawn always sets a fault endpoint");
        assert!(
            bootstrap_ep.is_some(),
            "spawn always sets a bootstrap endpoint"
        );
        self.ops.push("new_thread");
        Ok(self.alloc())
    }

    fn bind_death_notification(
        &mut self,
        _thread: Handle,
        _notif: Option<Handle>,
    ) -> Result<(), Status> {
        self.ops.push("bind_death");
        Ok(())
    }

    fn carve_frame(&mut self, _region: Handle, _len: u64, _align: u64) -> Result<Handle, Status> {
        self.ops.push("carve_frame");
        Ok(self.alloc())
    }

    fn map_frame(
        &mut self,
        _aspace: Handle,
        _frame: Handle,
        _vaddr: u64,
        _flags: MapFlags,
    ) -> Result<(), Status> {
        self.ops.push("map_frame");
        Ok(())
    }

    fn set_fault_pool(&mut self, _aspace: Handle, _region: Handle) -> Result<(), Status> {
        self.ops.push("set_fault_pool");
        Ok(())
    }

    fn mint_here(&mut self, _src: Handle, _rights: Rights) -> Result<Handle, Status> {
        self.ops.push("mint_here");
        Ok(self.alloc())
    }

    fn kill_thread(&mut self, thread: Handle) -> Result<(), Status> {
        self.killed.push(thread);
        Ok(())
    }

    fn signal(&mut self, notif: Handle, mask: u64) -> Result<(), Status> {
        self.signals.push((notif, mask));
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockLoader {
    pub image: Result<LoadedImage, Status>,
    pub calls: usize,
}

impl MockLoader {
    pub fn ok() -> Self {
        Self {
            image: Ok(LoadedImage {
                segments: vec![
                    Segment {
                        frame: 101,
                        vaddr: 0x1000,
                        len: 0x1000,
                        flags: MapFlags::R.union(MapFlags::X),
                    },
                    Segment {
                        frame: 102,
                        vaddr: 0x2000,
                        len: 0x1000,
                        flags: MapFlags::R.union(MapFlags::W),
                    },
                ],
                entry: 0x1000,
                stack_size: DEFAULT_STACK_SIZE,
            }),
            calls: 0,
        }
    }
}

impl ProgramLoader for MockLoader {
    fn load(&mut self, _program: &[u8]) -> Result<LoadedImage, Status> {
        self.calls += 1;
        self.image.clone()
    }
}

#[derive(Default)]
pub struct MockTransport {
    /// Incoming requests, popped front to back by `recv`.
    pub incoming: VecDeque<(Handle, Message)>,
    /// Messages sent through `send` — (destination cap, message).
    pub sent: Vec<(Handle, Message)>,
    /// Messages produced by `reply` (terminal replies).
    pub replies: Vec<Message>,
    /// Messages produced by `reply_recv`, paired with the consumed incoming.
    pub reply_recvs: Vec<Message>,
    pub fail_send: bool,
}

impl Transport for MockTransport {
    fn recv(&mut self, on: Handle) -> Result<Message, Status> {
        match self.incoming.front() {
            Some((cap, _)) if *cap == on => Ok(self.incoming.pop_front().expect("checked").1),
            _ => Err(status::EDEAD),
        }
    }

    fn reply(&mut self, msg: &Message) -> Result<(), Status> {
        self.replies.push(*msg);
        Ok(())
    }

    fn reply_recv(&mut self, on: Handle, msg: &Message) -> Result<Message, Status> {
        self.reply_recvs.push(*msg);
        self.recv(on)
    }

    fn call(&mut self, _on: Handle, _msg: &Message) -> Result<Message, Status> {
        Err(status::ENOSYS)
    }

    fn send(&mut self, on: Handle, msg: &Message) -> Result<(), Status> {
        if self.fail_send {
            return Err(status::EDEAD);
        }
        self.sent.push((on, *msg));
        Ok(())
    }
}

/// Window bytes by window cap handle.
#[derive(Default)]
pub struct MockWindows {
    pub data: BTreeMap<Handle, Vec<u8>>,
}

impl Windows for MockWindows {
    fn read(&mut self, window: Handle, span: Span) -> Result<Vec<u8>, Status> {
        let data = self.data.get(&window).ok_or(status::EBADCAP)?;
        let start = span.offset as usize;
        let end = start + span.len as usize;
        data.get(start..end)
            .map(|s| s.to_vec())
            .ok_or(status::EBADARG)
    }

    fn write(&mut self, window: Handle, span: Span, data: &[u8]) -> Result<(), Status> {
        if span.len as usize != data.len() {
            return Err(status::EBADARG);
        }
        let window_data = self.data.entry(window).or_default();
        let start = span.offset as usize;
        let end = start + data.len();
        if window_data.len() < end {
            window_data.resize(end, 0);
        }
        window_data[start..end].copy_from_slice(data);
        Ok(())
    }
}

/// Window contents for a SPAWN: header + program name at `program.offset`.
pub fn spawn_window(program: &[u8]) -> Vec<u8> {
    let offset = proto::SPAWN_HEADER_LEN as u32;
    let header = proto::SpawnHeader {
        program: Span::new(offset, program.len() as u32),
        argv: Span::new(offset, 0),
        env: Span::new(offset, 0),
    };
    let mut data = header.encode().to_vec();
    data.extend_from_slice(program);
    data
}
