//! Tiny unsafe island for core memory management (PLAN §2.1: kernel crate
//! forbids `unsafe` except justified islands like this one). Zeroing must
//! live here because `entry`/`frame` are under crate-level `deny`.
#![allow(unsafe_code)]

use crate::frame::{self, PhysAddr};

/// Allocate one frame and zero it (eager ANON resolution for `AS::MAP`).
pub fn alloc_zeroed() -> Option<PhysAddr> {
    let frame = frame::alloc()?;
    // SAFETY: freshly allocated frame; the identity direct map covers all
    // allocator-managed RAM, so writing through the physical address is valid
    // and exclusively ours until mapped elsewhere.
    unsafe {
        core::ptr::write_bytes(frame.as_u64() as *mut u8, 0, frame::FRAME_SIZE);
    }
    Some(frame)
}
