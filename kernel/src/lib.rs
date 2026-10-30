//! Helios microkernel core. See docs/PLAN.md.
//!
//! Crates in the kernel own nothing outside this directory; arch boot code
//! lives in `hal/*` and calls [`boot::early_init`] as its first action.
#![no_std]
#![forbid(unsafe_code)]

pub mod aspace;
pub mod boot;
pub mod console;
pub mod endpoint;
pub mod frame;
pub mod panic;
pub mod sched;

#[cfg(test)]
extern crate std;
