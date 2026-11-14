//! graphics — userspace component.
//!
//! `#![no_std]`, `alloc` only. Pure safe Rust, no MMIO, host-testable. The
//! compositor foundation for Phase 4; a real display server presents scanout
//! memory as a `Framebuffer` view and the driver flushes it.

#![no_std]

extern crate alloc;

pub mod compose;
pub mod display;
pub mod layer;
pub mod virtio_gpu;
pub mod widget;
