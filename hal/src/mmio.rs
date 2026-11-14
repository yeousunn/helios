//! Safe MMIO wrappers for userspace drivers (ADR-052).
//!
//! Userspace drivers must not call `ptr::read_volatile`/`write_volatile` on
//! raw physical addresses. Instead they call these wrappers over a mapped MMIO
//! window granted by an `MmioRegion` capability. The kernel's capability
//! dispatcher enforces that the window is mapped and in range; these functions
//! perform the volatile access so the driver never touches `unsafe` or raw
//! pointers.

use core::ptr;

/// Read a 32-bit value from a mapped MMIO window.
///
/// `base` is the virtual address of a mapped `MmioRegion`; `offset` is the
/// byte offset of the register within the window. The caller must keep
/// `base + offset` inside the granted window (the kernel validates the range
/// when the window is mapped).
pub fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: `base + offset` is a mapped MMIO register granted via an
    // `MmioRegion` capability; the kernel validated the range at map time.
    // Volatile access prevents the access from being reordered or elided.
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

/// Write a 32-bit value to a mapped MMIO window.
pub fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: same as `read32`; the window is writable per the grant.
    unsafe { ptr::write_volatile((base + offset) as *mut u32, value) }
}

/// Read a 64-bit value from a mapped MMIO window.
pub fn read64(base: usize, offset: usize) -> u64 {
    // SAFETY: same as `read32`.
    unsafe { ptr::read_volatile((base + offset) as *const u64) }
}

/// Write a 64-bit value to a mapped MMIO window.
pub fn write64(base: usize, offset: usize, value: u64) {
    // SAFETY: same as `read32`; the window is writable per the grant.
    unsafe { ptr::write_volatile((base + offset) as *mut u64, value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write32_round_trip() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        write32(base, 0, 0xDEAD_BEEF);
        write32(base, 4, 0xCAFE_BABE);
        assert_eq!(read32(base, 0), 0xDEAD_BEEF);
        assert_eq!(read32(base, 4), 0xCAFE_BABE);
    }

    #[test]
    fn read_write64_round_trip() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as usize;
        write64(base, 0, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(read64(base, 0), 0xDEAD_BEEF_CAFE_BABE);
    }
}
