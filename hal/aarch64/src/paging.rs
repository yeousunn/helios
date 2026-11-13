//! aarch64 paging backend (bring-up stub).
//!
//! The real aarch64 stage-1 MMU (L0-L3 page-table descriptors, MAIR, TCR,
//! TTBR0/TTBR1 programming) lands with aarch64 QEMU/hardware testing (Phase 5).

use kernel::aspace::{self, MapFlags, PagingBackend, Vaddr};
use kernel::frame::PhysAddr;

/// aarch64 per-address-space paging backend.
pub struct PagingBackendAarch64;

impl Default for PagingBackendAarch64 {
    fn default() -> Self {
        Self
    }
}

/// Hands out one aarch64 paging root per address space.
pub struct BackendFactoryAarch64;

impl Default for BackendFactoryAarch64 {
    fn default() -> Self {
        Self
    }
}

impl PagingBackend for PagingBackendAarch64 {
    fn map_page(&self, _vaddr: Vaddr, _paddr: PhysAddr, _flags: MapFlags) {
        unimplemented!("aarch64 map_page: stage-1 descriptor table not yet implemented");
    }

    fn unmap_page(&self, _vaddr: Vaddr) {
        unimplemented!("aarch64 unmap_page: stage-1 descriptor table not yet implemented");
    }

    fn protect_page(&self, _vaddr: Vaddr, _flags: MapFlags) {
        unimplemented!("aarch64 protect_page: stage-1 descriptor table not yet implemented");
    }
}

impl aspace::BackendFactory for BackendFactoryAarch64 {
    fn create(&self, _as_id: u64) -> Option<&'static dyn PagingBackend> {
        None
    }
}
