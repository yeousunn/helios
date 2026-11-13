//! riscv64 paging backend (bring-up stub).
//!
//! The real riscv64 Sv39 page-table (PTE entries, satp, sfence.vma) lands with
//! riscv64 QEMU/hardware testing (Phase 5).

use kernel::aspace::{self, MapFlags, PagingBackend, Vaddr};
use kernel::frame::PhysAddr;

/// riscv64 per-address-space paging backend.
pub struct PagingBackendRiscv64;

impl Default for PagingBackendRiscv64 {
    fn default() -> Self {
        Self
    }
}

/// Hands out one riscv64 paging root per address space.
pub struct BackendFactoryRiscv64;

impl Default for BackendFactoryRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl PagingBackend for PagingBackendRiscv64 {
    fn map_page(&self, _vaddr: Vaddr, _paddr: PhysAddr, _flags: MapFlags) {
        unimplemented!("riscv64 map_page: Sv39 page-table not yet implemented");
    }

    fn unmap_page(&self, _vaddr: Vaddr) {
        unimplemented!("riscv64 unmap_page: Sv39 page-table not yet implemented");
    }

    fn protect_page(&self, _vaddr: Vaddr, _flags: MapFlags) {
        unimplemented!("riscv64 protect_page: Sv39 page-table not yet implemented");
    }
}

impl aspace::BackendFactory for BackendFactoryRiscv64 {
    fn create(&self, _as_id: u64) -> Option<&'static dyn PagingBackend> {
        None
    }
}
