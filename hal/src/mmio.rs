//! Safe MMIO wrappers for userspace drivers (ADR-052).
//!
//! Userspace drivers must not call `ptr::read_volatile`/`write_volatile` on
//! raw physical addresses. Instead they construct an `MmioWindow` over a
//! mapped MMIO window granted by an `MmioRegion` capability. Only an `unsafe`
//! constructor (or the kernel's capability mapping path) can create a window,
//! and every access is bounds- and alignment-checked so safe code can never
//! read or write outside the granted window.

use core::ptr;

/// Error returned by an `MmioWindow` accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    /// `offset` (plus the access size) falls outside `[base, base + len)`.
    OutOfBounds,
    /// `offset` is not aligned to the access size.
    Misaligned,
}

/// A bounds- and alignment-checked window over a mapped MMIO region.
///
/// Only the capability-mapping path (which runs `unsafe`) may construct a
/// window, via [`MmioWindow::new`]. Once constructed, safe code can only
/// access offsets within `[0, len)` that are aligned to the access size.
pub struct MmioWindow {
    base: usize,
    len: usize,
}

impl MmioWindow {
    /// # Safety
    ///
    /// `base` must be the virtual address of a mapped MMIO region of `len`
    /// bytes, granted by an `MmioRegion` capability. The caller guarantees the
    /// range is valid device MMIO; the window then enforces bounds and
    /// alignment on every access.
    pub unsafe fn new(base: usize, len: usize) -> Self {
        Self { base, len }
    }

    /// Returns the window's base address.
    pub fn base(&self) -> usize {
        self.base
    }

    /// Returns the window's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the window has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads a 32-bit value at `offset`. `offset` must be 4-byte aligned and
    /// `offset + 4 <= len`.
    pub fn read32(&self, offset: usize) -> Result<u32, MmioError> {
        let end = offset.checked_add(4).ok_or(MmioError::OutOfBounds)?;
        if end > self.len {
            return Err(MmioError::OutOfBounds);
        }
        if !offset.is_multiple_of(4) {
            return Err(MmioError::Misaligned);
        }
        // SAFETY: `base + offset` lies within `[base, base + len)`, which the
        // unsafe constructor required to be a mapped MMIO region; `offset` is
        // 4-byte aligned.
        Ok(unsafe { ptr::read_volatile((self.base + offset) as *const u32) })
    }

    /// Writes a 32-bit value at `offset`. `offset` must be 4-byte aligned and
    /// `offset + 4 <= len`.
    pub fn write32(&self, offset: usize, value: u32) -> Result<(), MmioError> {
        let end = offset.checked_add(4).ok_or(MmioError::OutOfBounds)?;
        if end > self.len {
            return Err(MmioError::OutOfBounds);
        }
        if !offset.is_multiple_of(4) {
            return Err(MmioError::Misaligned);
        }
        // SAFETY: `base + offset` lies within `[base, base + len)`, which the
        // unsafe constructor required to be a mapped MMIO region; `offset` is
        // 4-byte aligned.
        unsafe { ptr::write_volatile((self.base + offset) as *mut u32, value) }
        Ok(())
    }

    /// Reads a 64-bit value at `offset`. `offset` must be 8-byte aligned and
    /// `offset + 8 <= len`.
    pub fn read64(&self, offset: usize) -> Result<u64, MmioError> {
        let end = offset.checked_add(8).ok_or(MmioError::OutOfBounds)?;
        if end > self.len {
            return Err(MmioError::OutOfBounds);
        }
        if !offset.is_multiple_of(8) {
            return Err(MmioError::Misaligned);
        }
        // SAFETY: `base + offset` lies within `[base, base + len)`, which the
        // unsafe constructor required to be a mapped MMIO region; `offset` is
        // 8-byte aligned.
        Ok(unsafe { ptr::read_volatile((self.base + offset) as *const u64) })
    }

    /// Writes a 64-bit value at `offset`. `offset` must be 8-byte aligned and
    /// `offset + 8 <= len`.
    pub fn write64(&self, offset: usize, value: u64) -> Result<(), MmioError> {
        let end = offset.checked_add(8).ok_or(MmioError::OutOfBounds)?;
        if end > self.len {
            return Err(MmioError::OutOfBounds);
        }
        if !offset.is_multiple_of(8) {
            return Err(MmioError::Misaligned);
        }
        // SAFETY: `base + offset` lies within `[base, base + len)`, which the
        // unsafe constructor required to be a mapped MMIO region; `offset` is
        // 8-byte aligned.
        unsafe { ptr::write_volatile((self.base + offset) as *mut u64, value) }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write32_round_trip() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        win.write32(0, 0xDEAD_BEEF).unwrap();
        win.write32(4, 0xCAFE_BABE).unwrap();
        assert_eq!(win.read32(0).unwrap(), 0xDEAD_BEEF);
        assert_eq!(win.read32(4).unwrap(), 0xCAFE_BABE);
    }

    #[test]
    fn read_write64_round_trip() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        win.write64(0, 0xDEAD_BEEF_CAFE_BABE).unwrap();
        assert_eq!(win.read64(0).unwrap(), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn read32_out_of_bounds() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        assert_eq!(win.read32(13), Err(MmioError::OutOfBounds));
        assert_eq!(win.write32(13, 0), Err(MmioError::OutOfBounds));
    }

    #[test]
    fn read64_out_of_bounds() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        assert_eq!(win.read64(9), Err(MmioError::OutOfBounds));
        assert_eq!(win.write64(9, 0), Err(MmioError::OutOfBounds));
    }

    #[test]
    fn read32_misaligned() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        assert_eq!(win.read32(1), Err(MmioError::Misaligned));
        assert_eq!(win.write32(1, 0), Err(MmioError::Misaligned));
    }

    #[test]
    fn read64_misaligned() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        assert_eq!(win.read64(4), Err(MmioError::Misaligned));
        assert_eq!(win.write64(4, 0), Err(MmioError::Misaligned));
    }

    #[test]
    fn overflow_offset_rejected() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { MmioWindow::new(base, buf.len()) };
        assert_eq!(win.read32(usize::MAX), Err(MmioError::OutOfBounds));
    }
}
