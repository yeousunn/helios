//! riscv64 HAL implementation.
//!
//! Phase 5 bring-up stubs: `TrapDecode` (host-testable scause/stval decode)
//! plus compile-only `ContextBackend` and `PagingBackend` stubs. The real
//! riscv64 trap handling, context switch and MMU code lands when riscv64 QEMU
//! or hardware is available for end-to-end testing.

#![no_std]

#[cfg(target_arch = "riscv64")]
mod context;
#[cfg(target_arch = "riscv64")]
mod paging;
#[cfg(target_arch = "riscv64")]
mod trap;

#[cfg(target_arch = "riscv64")]
pub use context::ContextBackendRiscv64;
#[cfg(target_arch = "riscv64")]
pub use paging::{BackendFactoryRiscv64, PagingBackendRiscv64};
#[cfg(target_arch = "riscv64")]
pub use trap::{Riscv64TrapFrame, TrapDecodeRiscv64};

/// Non-riscv64 hosts: empty stubs so the crate compiles everywhere.
#[cfg(not(target_arch = "riscv64"))]
mod impl_stub;
#[cfg(not(target_arch = "riscv64"))]
pub use impl_stub::*;
