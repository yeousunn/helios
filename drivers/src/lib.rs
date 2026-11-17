//! drivers — userspace component.
//!
//! All MMIO access uses the safe `mmio` module (ADR-063). DMA access uses
//! the safe `DmaBuffer` wrapper (ADR-098).

#![no_std]
#![forbid(unsafe_code)]

pub mod virtio_blk;
pub mod virtio_net;
