//! Test doubles shared by the VFS unit tests.

use std::collections::{BTreeMap, VecDeque};
use std::vec::Vec;

use ipc::{status, Message};

use crate::proto::{Span, Status};
use crate::runtime::{Handle, Transport, VfsKernel, Windows};

#[derive(Default)]
pub struct MockKernel {
    pub next: Handle,
    pub now: u64,
}

impl VfsKernel for MockKernel {
    fn new_endpoint(&mut self) -> Result<Handle, Status> {
        self.next += 1;
        Ok(self.next)
    }

    fn now_ns(&mut self) -> u64 {
        self.now += 1;
        self.now
    }
}

#[derive(Default)]
pub struct MockTransport {
    pub incoming: VecDeque<(Handle, Message)>,
    pub replies: Vec<Message>,
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
        self.replies.push(*msg);
        self.recv(on)
    }

    fn send(&mut self, _on: Handle, _msg: &Message) -> Result<(), Status> {
        Ok(())
    }
}

/// Window bytes by window cap handle; `write` grows the window as needed.
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
