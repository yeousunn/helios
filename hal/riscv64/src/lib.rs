//! riscv64 HAL implementation.
//!
//! Phase 5 bring-up: `TrapDecode` (host-testable scause/stval decode),
//! `ContextBackend` (initial kernel context, 16-byte aligned stack pointer),
//! and a software `PagingBackend` (Sv39 page-table model). All logic is pure
//! Rust (no riscv64 instructions), so it compiles and is unit-testable on
//! every host. The real riscv64 trap handling, context switch and MMU code
//! lands when riscv64 QEMU or hardware is available for end-to-end testing.

#![no_std]

mod context;
mod paging;
mod trap;

pub use context::ContextBackendRiscv64;
pub use paging::{BackendFactoryRiscv64, PagingBackendRiscv64};
pub use trap::{Riscv64TrapFrame, TrapDecodeRiscv64};
