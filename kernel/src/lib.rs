//! Helios microkernel core. See docs/PLAN.md.
//!
//! Crates in the kernel own nothing outside this directory; arch boot code
//! lives in `hal/*` and calls [`boot::early_init`] as its first action.
#![no_std]
#![deny(unsafe_code)]

pub mod aspace;
pub mod boot;
pub mod console;
pub mod console_in;
pub mod endpoint;
pub mod entry;
pub mod fault;
pub mod frame;
pub mod init;
pub mod mem;
pub mod notification;
pub mod objreg;
pub mod panic;
pub mod proc;
pub mod sched;
pub mod syscall;
pub mod time;

#[cfg(test)]
extern crate std;

#[cfg(kani)]
mod kani;
