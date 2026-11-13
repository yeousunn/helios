//! aarch64 HAL implementation.
//!
//! Phase 5 bring-up stubs: `TrapDecode` (host-testable ESR_EL1 decode) plus
//! compile-only `ContextBackend` and `PagingBackend` stubs. The real aarch64
//! MMU, exception-vector and context-switch code lands when aarch64 QEMU or
//! hardware is available for end-to-end testing.

#![no_std]

#[cfg(target_arch = "aarch64")]
mod context;
#[cfg(target_arch = "aarch64")]
mod paging;
#[cfg(target_arch = "aarch64")]
mod trap;

#[cfg(target_arch = "aarch64")]
pub use context::ContextBackendAarch64;
#[cfg(target_arch = "aarch64")]
pub use paging::{BackendFactoryAarch64, PagingBackendAarch64};
#[cfg(target_arch = "aarch64")]
pub use trap::{AArch64TrapFrame, TrapDecodeAarch64};

/// Non-aarch64 hosts: empty stubs so the crate compiles everywhere.
#[cfg(not(target_arch = "aarch64"))]
mod impl_stub;
#[cfg(not(target_arch = "aarch64"))]
pub use impl_stub::*;
