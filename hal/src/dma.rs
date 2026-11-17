//! Safe DMA buffer wrappers (ADR-016 / `hal::Dma`).
//!
//! Userspace drivers receive DMA-safe, physically-contiguous memory as a
//! granted `Frame` (mapped into the driver via `AS::MAP`); they never
//! allocate DMA themselves. `DmaBuffer` wraps such a region and exposes only
//! safe, bounds- and alignment-checked volatile accessors so driver code never
//! calls `ptr::read_volatile`/`ptr::write_volatile` on a raw DMA address
//! directly.
//!
//! Only the `unsafe` constructor may create a buffer (the caller guarantees
//! the region is valid DMA memory); after that, safe code can read/write
//! within `[0, len)` at the access size's natural alignment.

use core::ptr;

use crate::Dma;

/// Error returned by a `DmaBuffer` accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// `offset` (plus the access size) falls outside `[0, len)`.
    OutOfBounds,
    /// `offset` is not aligned to the access size.
    Misaligned,
}

/// A safe, bounds-checked view over a DMA-safe, physically contiguous region.
///
/// `virt` is the virtual address the driver accesses; `phys` is the
/// device-visible address of the same region. Both come from a prior grant
/// (e.g. a `Frame` mapped via `AS::MAP`) or from `hal::Dma::alloc_dma`.
pub struct DmaBuffer {
    virt: usize,
    phys: usize,
    len: usize,
}

impl DmaBuffer {
    /// # Safety
    ///
    /// `virt` must be the virtual address of `len` bytes of DMA-safe,
    /// physically contiguous memory and `phys` its device-visible address.
    /// The caller guarantees the range is valid for the device; the buffer
    /// then enforces bounds and alignment on every access.
    pub unsafe fn new(virt: usize, phys: usize, len: usize) -> Self {
        Self { virt, phys, len }
    }

    /// Returns the buffer's virtual address.
    pub fn virt_addr(&self) -> usize {
        self.virt
    }

    /// Returns the buffer's device-visible physical address.
    pub fn phys_addr(&self) -> usize {
        self.phys
    }

    /// Returns the buffer's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the buffer has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the whole buffer as a byte slice, for zeroing and type-punning.
    ///
    /// The slice is bounded to `[0, len)` so every access stays within the
    /// granted DMA region; this replaces raw `&mut *(virt as *mut Type)`
    /// type-punning in driver code.
    pub fn as_slice(&self) -> Result<&[u8], DmaError> {
        // SAFETY: `[self.virt, self.virt + self.len)` is valid DMA memory
        // guaranteed by the unsafe constructor; the slice length is exactly
        // `len`, so it cannot overrun the region.
        Ok(unsafe { core::slice::from_raw_parts(self.virt as *const u8, self.len) })
    }

    /// Zero the entire buffer.
    ///
    /// # Safety
    ///
    /// The constructor guaranteed `[virt, virt + len)` is valid DMA memory,
    /// so a byte-wise `write_bytes` over it is sound.
    pub fn zero(&mut self) {
        // SAFETY: `[self.virt, self.virt + self.len)` is valid DMA memory
        // guaranteed by the unsafe constructor.
        unsafe {
            ptr::write_bytes(self.virt as *mut u8, 0, self.len);
        }
    }

    /// Zero the entire buffer, replacing a raw `ptr::write_bytes` call.
    ///
    /// # Safety
    ///
    /// The constructor guaranteed `[virt, virt + len)` is valid DMA memory,
    /// so a byte-wise `write_bytes` over it is sound.
    pub fn clear(&mut self) {
        // SAFETY: `[self.virt, self.virt + self.len)` is valid DMA memory
        // guaranteed by the unsafe constructor.
        unsafe {
            ptr::write_bytes(self.virt as *mut u8, 0, self.len);
        }
    }

    fn check_offset(&self, offset: usize, size: usize) -> Result<(), DmaError> {
        let end = offset.checked_add(size).ok_or(DmaError::OutOfBounds)?;
        if end > self.len {
            return Err(DmaError::OutOfBounds);
        }
        Ok(())
    }

    /// Reads an 8-bit value at `offset`. `offset < len`.
    pub fn read8(&self, offset: usize) -> Result<u8, DmaError> {
        self.check_offset(offset, 1)?;
        // SAFETY: `offset < len`; byte access has no alignment constraint.
        Ok(unsafe { ptr::read_volatile((self.virt + offset) as *const u8) })
    }

    /// Writes an 8-bit value at `offset`. `offset < len`.
    pub fn write8(&mut self, offset: usize, value: u8) -> Result<(), DmaError> {
        self.check_offset(offset, 1)?;
        // SAFETY: `offset < len`; byte access has no alignment constraint.
        unsafe {
            ptr::write_volatile((self.virt + offset) as *mut u8, value);
        }
        Ok(())
    }

    /// Reads a 16-bit value at `offset`. `offset` must be 2-byte aligned and
    /// `offset + 2 <= len`.
    pub fn read16(&self, offset: usize) -> Result<u16, DmaError> {
        self.check_offset(offset, 2)?;
        if !offset.is_multiple_of(2) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 2)` is within `[0, len)` and 2-byte
        // aligned.
        Ok(unsafe { ptr::read_volatile((self.virt + offset) as *const u16) })
    }

    /// Writes a 16-bit value at `offset`. `offset` must be 2-byte aligned and
    /// `offset + 2 <= len`.
    pub fn write16(&mut self, offset: usize, value: u16) -> Result<(), DmaError> {
        self.check_offset(offset, 2)?;
        if !offset.is_multiple_of(2) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 2)` is within `[0, len)` and 2-byte
        // aligned.
        unsafe {
            ptr::write_volatile((self.virt + offset) as *mut u16, value);
        }
        Ok(())
    }

    /// Reads a 32-bit value at `offset`. `offset` must be 4-byte aligned and
    /// `offset + 4 <= len`.
    pub fn read32(&self, offset: usize) -> Result<u32, DmaError> {
        self.check_offset(offset, 4)?;
        if !offset.is_multiple_of(4) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 4)` is within `[0, len)` and 4-byte
        // aligned.
        Ok(unsafe { ptr::read_volatile((self.virt + offset) as *const u32) })
    }

    /// Writes a 32-bit value at `offset`. `offset` must be 4-byte aligned and
    /// `offset + 4 <= len`.
    pub fn write32(&mut self, offset: usize, value: u32) -> Result<(), DmaError> {
        self.check_offset(offset, 4)?;
        if !offset.is_multiple_of(4) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 4)` is within `[0, len)` and 4-byte
        // aligned.
        unsafe {
            ptr::write_volatile((self.virt + offset) as *mut u32, value);
        }
        Ok(())
    }

    /// Reads a 64-bit value at `offset`. `offset` must be 8-byte aligned and
    /// `offset + 8 <= len`.
    pub fn read64(&self, offset: usize) -> Result<u64, DmaError> {
        self.check_offset(offset, 8)?;
        if !offset.is_multiple_of(8) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 8)` is within `[0, len)` and 8-byte
        // aligned.
        Ok(unsafe { ptr::read_volatile((self.virt + offset) as *const u64) })
    }

    /// Writes a 64-bit value at `offset`. `offset` must be 8-byte aligned and
    /// `offset + 8 <= len`.
    pub fn write64(&mut self, offset: usize, value: u64) -> Result<(), DmaError> {
        self.check_offset(offset, 8)?;
        if !offset.is_multiple_of(8) {
            return Err(DmaError::Misaligned);
        }
        // SAFETY: `[offset, offset + 8)` is within `[0, len)` and 8-byte
        // aligned.
        unsafe {
            ptr::write_volatile((self.virt + offset) as *mut u64, value);
        }
        Ok(())
    }

    /// Copy `src.len()` bytes from `src` into the buffer at `offset`.
    /// `offset + src.len() <= len`.
    pub fn copy_from_slice(&mut self, offset: usize, src: &[u8]) -> Result<(), DmaError> {
        self.check_offset(offset, src.len())?;
        // SAFETY: `[offset, offset + src.len())` is within `[0, len)` and the
        // source and destination do not overlap (a driver slice is never the
        // DMA buffer).
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), (self.virt + offset) as *mut u8, src.len());
        }
        Ok(())
    }

    /// Copy `dst.len()` bytes from the buffer at `offset` into `dst`.
    /// `offset + dst.len() <= len`.
    pub fn copy_to_slice(&self, offset: usize, dst: &mut [u8]) -> Result<(), DmaError> {
        self.check_offset(offset, dst.len())?;
        // SAFETY: `[offset, offset + dst.len())` is within `[0, len)` and the
        // source and destination do not overlap (a driver slice is never the
        // DMA buffer).
        unsafe {
            ptr::copy_nonoverlapping(
                (self.virt + offset) as *const u8,
                dst.as_mut_ptr(),
                dst.len(),
            );
        }
        Ok(())
    }

    /// Sync the buffer for device access (the device will write to it).
    /// Delegates to `hal::Dma::sync_for_device`; on cache-coherent platforms
    /// (x86_64) this is a no-op.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent CPU access to the buffer while the
    /// device uses it.
    pub fn sync_for_device(&mut self, dma: &mut impl Dma) {
        // SAFETY: `[self.virt, self.virt + self.len)` is valid DMA memory
        // guaranteed by the unsafe constructor.
        unsafe {
            dma.sync_for_device(self.virt, self.len as u64);
        }
    }

    /// Sync the buffer for CPU access (the device finished writing).
    /// Delegates to `hal::Dma::sync_for_cpu`; on cache-coherent platforms
    /// (x86_64) this is a no-op.
    ///
    /// # Safety
    ///
    /// The caller must ensure the device has finished writing to the buffer.
    pub fn sync_for_cpu(&mut self, dma: &mut impl Dma) {
        // SAFETY: `[self.virt, self.virt + self.len)` is valid DMA memory
        // guaranteed by the unsafe constructor.
        unsafe {
            dma.sync_for_cpu(self.virt, self.len as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write32_round_trip() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        win.write32(0, 0xDEAD_BEEF).unwrap();
        win.write32(4, 0xCAFE_BABE).unwrap();
        assert_eq!(win.read32(0).unwrap(), 0xDEAD_BEEF);
        assert_eq!(win.read32(4).unwrap(), 0xCAFE_BABE);
        assert_eq!(win.virt_addr(), base);
        assert_eq!(win.phys_addr(), base);
        assert_eq!(win.len(), 16);
        assert!(!win.is_empty());
    }

    #[test]
    fn read_write64_round_trip() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        win.write64(0, 0xDEAD_BEEF_CAFE_BABE).unwrap();
        assert_eq!(win.read64(0).unwrap(), 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn zero_clears_the_buffer() {
        let mut buf = [0xAAu8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        win.zero();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn copy_from_and_to_slice() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        let src = [1u8, 2, 3, 4];
        win.copy_from_slice(4, &src).unwrap();
        let mut dst = [0u8; 4];
        win.copy_to_slice(4, &mut dst).unwrap();
        assert_eq!(dst, src);
    }

    #[test]
    fn read32_out_of_bounds() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        assert_eq!(win.read32(13), Err(DmaError::OutOfBounds));
        assert_eq!(win.write32(13, 0), Err(DmaError::OutOfBounds));
    }

    #[test]
    fn read64_out_of_bounds() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        assert_eq!(win.read64(9), Err(DmaError::OutOfBounds));
        assert_eq!(win.write64(9, 0), Err(DmaError::OutOfBounds));
    }

    #[test]
    fn read32_misaligned() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        assert_eq!(win.read32(1), Err(DmaError::Misaligned));
        assert_eq!(win.write32(1, 0), Err(DmaError::Misaligned));
    }

    #[test]
    fn read64_misaligned() {
        let mut buf = [0u8; 32];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        assert_eq!(win.read64(4), Err(DmaError::Misaligned));
        assert_eq!(win.write64(4, 0), Err(DmaError::Misaligned));
    }

    #[test]
    fn overflow_offset_rejected() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        assert_eq!(win.read32(usize::MAX), Err(DmaError::OutOfBounds));
    }

    #[test]
    fn clear_zeroes_the_buffer() {
        let mut buf = [0xAAu8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        win.clear();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn as_slice_round_trip() {
        let mut buf = [0u8; 16];
        let base = buf.as_mut_ptr() as usize;
        let mut win = unsafe { DmaBuffer::new(base, base, buf.len()) };
        win.write32(0, 0xDEAD_BEEF).unwrap();
        let slice = win.as_slice().unwrap();
        assert_eq!(slice.len(), 16);
        assert_eq!(&slice[0..4], &0xDEAD_BEEF_u32.to_le_bytes());
        let mut copy = [0u8; 16];
        copy.copy_from_slice(slice);
        assert_eq!(copy, buf);
    }
}
