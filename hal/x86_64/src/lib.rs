//! x86_64 HAL implementation.
//!
//! Provides: UART 16550 (COM1) early console, GDT/IDT setup, early boot
//! entry (`_start`), and a stub framebuffer.

#![no_std]

#[cfg(target_arch = "x86_64")]
mod paging;

#[cfg(target_arch = "x86_64")]
mod layout;

#[cfg(target_arch = "x86_64")]
mod trap;

#[cfg(target_arch = "x86_64")]
mod impl_x86_64;

#[cfg(target_arch = "x86_64")]
pub mod exceptions;

#[cfg(target_arch = "x86_64")]
pub mod syscall_entry;

#[cfg(not(target_arch = "x86_64"))]
mod impl_stub;

#[cfg(target_arch = "x86_64")]
pub use impl_x86_64::*;

#[cfg(target_arch = "x86_64")]
pub use layout::*;

#[cfg(target_arch = "x86_64")]
pub use crate::impl_x86_64::{enable_uart_rx, set_uart_rx_callback};
#[cfg(target_arch = "x86_64")]
pub use paging::{
    activate_as, enable_nx, flush_tlb_all, probe_walk, root_of, BACKEND_FACTORY_X86_64,
};

/// Host builds (aarch64 macOS workspace gate): no UART hardware.
#[cfg(not(target_arch = "x86_64"))]
pub fn set_uart_rx_callback(_f: fn(u8)) {}
#[cfg(not(target_arch = "x86_64"))]
pub fn enable_uart_rx() {}

#[cfg(not(target_arch = "x86_64"))]
pub use impl_stub::*;
