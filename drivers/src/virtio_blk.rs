//! Virtio-blk block device driver (capability-based, per ADR-052).
//!
//! The driver never touches raw HAL traits or physical addresses directly. It
//! receives:
//!  * a mapped MMIO window base (`mmio_base`) — the virtual address of an
//!    `MmioRegion` capability the kernel dispatcher mapped over the device's
//!    MMIO BAR, and
//!  * a single physically-contiguous DMA page (`dma_virt` / `dma_phys`) — a
//!    `Frame` capability the launcher mapped into the driver's address space,
//!    used for the virtqueue (descriptors + available ring + used ring + the
//!    request header/data area).
//!
//! All device register access goes through the mapped MMIO window via the
//! safe `MmioWindow` wrapper defined below. DMA allocation is the launcher's
//! job (Frame cap + `AS::MAP`), so the driver does not depend on `hal::Dma`
//! either. HAL traits stay kernel-internal.

use core::ptr;

mod mmio {
    use core::ptr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MmioError {
        OutOfBounds,
        Misaligned,
    }

    pub struct MmioWindow {
        base: usize,
        len: usize,
    }

    impl MmioWindow {
        pub unsafe fn new(base: usize, len: usize) -> Self {
            Self { base, len }
        }

        pub fn read32(&self, offset: usize) -> Result<u32, MmioError> {
            let end = offset.checked_add(4).ok_or(MmioError::OutOfBounds)?;
            if end > self.len {
                return Err(MmioError::OutOfBounds);
            }
            if !offset.is_multiple_of(4) {
                return Err(MmioError::Misaligned);
            }
            Ok(unsafe { ptr::read_volatile((self.base + offset) as *const u32) })
        }

        pub fn write32(&self, offset: usize, value: u32) -> Result<(), MmioError> {
            let end = offset.checked_add(4).ok_or(MmioError::OutOfBounds)?;
            if end > self.len {
                return Err(MmioError::OutOfBounds);
            }
            if !offset.is_multiple_of(4) {
                return Err(MmioError::Misaligned);
            }
            unsafe {
                ptr::write_volatile((self.base + offset) as *mut u32, value);
            }
            Ok(())
        }

        #[allow(dead_code)]
        pub fn read64(&self, offset: usize) -> Result<u64, MmioError> {
            let end = offset.checked_add(8).ok_or(MmioError::OutOfBounds)?;
            if end > self.len {
                return Err(MmioError::OutOfBounds);
            }
            if !offset.is_multiple_of(8) {
                return Err(MmioError::Misaligned);
            }
            Ok(unsafe { ptr::read_volatile((self.base + offset) as *const u64) })
        }

        #[allow(dead_code)]
        pub fn write64(&self, offset: usize, value: u64) -> Result<(), MmioError> {
            let end = offset.checked_add(8).ok_or(MmioError::OutOfBounds)?;
            if end > self.len {
                return Err(MmioError::OutOfBounds);
            }
            if !offset.is_multiple_of(8) {
                return Err(MmioError::Misaligned);
            }
            unsafe { ptr::write_volatile((self.base + offset) as *mut u64, value) }
            Ok(())
        }
    }
}

/// Virtio PCI vendor ID (Red Hat / virtio).
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// Virtio-blk device ID.
const VIRTIO_ID_BLOCK: u16 = 0x1001;

/// Legacy virtio MMIO register offsets.
const MMIO_MAGIC: usize = 0x00;
const MMIO_VERSION: usize = 0x04;
const MMIO_DEVICE_ID: usize = 0x08;
const MMIO_VENDOR_ID: usize = 0x0C;
const _MMIO_HOST_FEATURES: usize = 0x10;
const _MMIO_HOST_FEATURES_SEL: usize = 0x14;
const _MMIO_GUEST_FEATURES: usize = 0x20;
const _MMIO_GUEST_FEATURES_SEL: usize = 0x24;
const MMIO_QUEUE_SEL: usize = 0x30;
const MMIO_QUEUE_NUM_MAX: usize = 0x34;
const MMIO_QUEUE_NUM: usize = 0x38;
const MMIO_QUEUE_PFN: usize = 0x40;
const MMIO_QUEUE_READY: usize = 0x44;
const MMIO_QUEUE_NOTIFY: usize = 0x50;
const MMIO_STATUS: usize = 0x60;
const MMIO_ISR: usize = 0x68;
const MMIO_CONFIG_GEN: usize = 0x64;

/// Device status bits.
const STATUS_ACKNOWLEDGE: u32 = 0x1;
const STATUS_DRIVER: u32 = 0x2;
const STATUS_DRIVER_OK: u32 = 0x4;
const STATUS_FEATURES_OK: u32 = 0x8;

/// Sector size (bytes).
const SECTOR_SIZE: usize = 512;
/// Number of descriptors in the virtqueue.
const QUEUE_SIZE: u16 = 16;
/// DMA page size (bytes).
const DMA_PAGE: usize = 4096;

/// Descriptor flags.
const DESC_FLAG_NEXT: u16 = 0x1;
const DESC_FLAG_WRITE: u16 = 0x2;

/// One virtqueue descriptor (16 bytes).
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Available ring (host reads from this).
#[repr(C, align(2))]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    used_event: u16,
}

/// Used ring (device writes to this).
#[repr(C, align(4))]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QUEUE_SIZE as usize],
    avail_event: u16,
}

/// The full virtqueue (descriptor table + available ring + used ring), laid
/// out contiguously in one DMA page.
#[repr(C, align(4096))]
struct VirtQueue {
    desc: [Desc; QUEUE_SIZE as usize],
    avail: Avail,
    used: Used,
}

/// A virtio-blk block device.
pub struct VirtioBlk {
    /// Mapped MMIO window over the device BAR (from an `MmioRegion` cap).
    mmio: mmio::MmioWindow,
    capacity_sectors: u64,
    /// Virtual address of the DMA page holding the virtqueue (from a `Frame`
    /// cap mapped via `AS::MAP`), or None until `init`.
    queue_vaddr: Option<usize>,
    /// Physical address of the DMA page (device sees this).
    queue_paddr: usize,
    next_desc_idx: u16,
    next_avail_idx: u16,
}

impl VirtioBlk {
    /// Create a new virtio-blk driver over a kernel-granted MMIO window.
    /// `mmio_base` is the virtual address of a mapped `MmioRegion` covering the
    /// device's MMIO BAR; the caller (kernel dispatcher or init) holds the cap
    /// and has already mapped the region.
    pub fn new(mmio_base: usize, mmio_len: usize) -> Self {
        Self {
            mmio: unsafe { mmio::MmioWindow::new(mmio_base, mmio_len) },
            capacity_sectors: 0,
            queue_vaddr: None,
            queue_paddr: 0,
            next_desc_idx: 0,
            next_avail_idx: 0,
        }
    }

    /// Read a u32 from a virtio MMIO register.
    fn rd32(&self, offset: usize) -> Result<u32, &'static str> {
        self.mmio.read32(offset).map_err(|_| "MMIO read error")
    }

    /// Write a u32 to a virtio MMIO register.
    fn wr32(&self, offset: usize, value: u32) -> Result<(), &'static str> {
        self.mmio
            .write32(offset, value)
            .map_err(|_| "MMIO write error")
    }

    /// Probe the device: verify magic/version/vendor/device IDs. Returns
    /// `true` if a virtio-blk device is present at `mmio_base`.
    pub fn probe(&self) -> bool {
        let magic = match self.rd32(MMIO_MAGIC) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if magic != 0x7472_6976 {
            return false;
        }
        let version = match self.rd32(MMIO_VERSION) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if version != 1 {
            return false;
        }
        let device_id = match self.rd32(MMIO_DEVICE_ID) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if device_id != VIRTIO_ID_BLOCK as u32 {
            return false;
        }
        let vendor_id = match self.rd32(MMIO_VENDOR_ID) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if vendor_id != VIRTIO_VENDOR_ID as u32 {
            return false;
        }
        true
    }

    /// Read the device capacity (in 512-byte sectors) from config space.
    pub fn capacity(&self) -> u64 {
        let lo = match self.rd32(MMIO_CONFIG_GEN + 4) {
            Ok(v) => v as u64,
            Err(_) => return 0,
        };
        let hi = match self.rd32(MMIO_CONFIG_GEN + 8) {
            Ok(v) => v as u64,
            Err(_) => return 0,
        };
        lo | (hi << 32)
    }

    /// Initialize the device: reset, acknowledge driver, negotiate features,
    /// and set up the virtqueue in the caller-provided DMA page. Returns the
    /// device capacity in sectors on success.
    ///
    /// `dma_virt`/`dma_phys` are the virtual/physical address of a
    /// page-sized, physically-contiguous DMA buffer granted via a `Frame`
    /// capability and mapped into this driver's address space (the launcher
    /// used `AS::MAP`; the driver never allocates DMA itself).
    pub fn init(&mut self, dma_virt: usize, dma_phys: usize) -> Result<u64, &'static str> {
        // 1. Reset: write 0 to status.
        self.wr32(MMIO_STATUS, 0)?;

        // 2. Acknowledge: we've seen the device.
        let status_ack = self.rd32(MMIO_STATUS)?;
        self.wr32(MMIO_STATUS, status_ack | STATUS_ACKNOWLEDGE)?;

        // 3. Driver: we know how to drive it.
        self.wr32(MMIO_STATUS, status_ack | STATUS_DRIVER)?;

        // 4. Feature negotiation (v0: accept no extra features; device must
        //    work with the default feature set).
        self.wr32(MMIO_STATUS, status_ack | STATUS_FEATURES_OK)?;

        // 5. Driver OK: we're ready.
        self.wr32(MMIO_STATUS, status_ack | STATUS_DRIVER_OK)?;

        // 6. Read capacity from config space (offset 0 in config region).
        let capacity = self.capacity();
        if capacity == 0 {
            return Err("virtio-blk: zero capacity");
        }
        self.capacity_sectors = capacity;

        // 7. Set up the virtqueue in the granted DMA page.
        self.setup_queue(dma_virt, dma_phys)?;

        Ok(capacity)
    }

    /// Program the virtqueue into the granted DMA page.
    fn setup_queue(&mut self, dma_virt: usize, dma_phys: usize) -> Result<(), &'static str> {
        // Tell the device the queue size.
        self.wr32(MMIO_QUEUE_SEL, 0)?; // select queue 0
        let max = self.rd32(MMIO_QUEUE_NUM_MAX)?;
        if max < QUEUE_SIZE as u32 {
            return Err("virtio-blk: queue too small");
        }
        self.wr32(MMIO_QUEUE_NUM, QUEUE_SIZE as u32)?;
        self.wr32(MMIO_QUEUE_PFN, (dma_phys / DMA_PAGE) as u32)?;
        self.wr32(MMIO_QUEUE_READY, 1)?;

        // Zero the queue page.
        // SAFETY: `dma_virt` is the granted DMA page, exclusively ours.
        unsafe { ptr::write_bytes(dma_virt as *mut u8, 0, DMA_PAGE) };

        self.queue_vaddr = Some(dma_virt);
        self.queue_paddr = dma_phys;
        self.next_desc_idx = 0;
        self.next_avail_idx = 0;

        Ok(())
    }

    /// Submit a one-sector read. The device fills `buf` (512 bytes) with
    /// sector `sector` contents. `buf` need not be DMA-accessible; the data
    /// stages through the granted DMA page.
    pub fn read_sector(
        &mut self,
        sector: u64,
        buf: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), &'static str> {
        let queue_vaddr = self.queue_vaddr.ok_or("virtio-blk: queue not set up")?;
        let queue_paddr = self.queue_paddr as u64;

        let header_addr = core::mem::size_of::<VirtQueue>();
        let data_addr = header_addr + 16; // header + padding to data
        let header_phys = queue_paddr + header_addr as u64;
        let data_phys = queue_paddr + data_addr as u64;

        // Build the request header + stage the data into the DMA page.
        // SAFETY: writing to the granted DMA page we own; header/data offsets
        // are within the 4 KiB page.
        unsafe {
            let base = queue_vaddr as *mut u8;
            let header_ptr = base.add(header_addr) as *mut u32;
            ptr::write_volatile(header_ptr, 0); // type = read
            ptr::write_volatile(header_ptr.add(4), 0); // reserved
            ptr::write_volatile(header_ptr.add(8) as *mut u64, sector); // sector
            ptr::copy_nonoverlapping(buf.as_ptr(), base.add(data_addr), SECTOR_SIZE);
        }

        // Descriptor chain, via a temporary reference over the DMA page.
        // SAFETY: `queue_vaddr` is an aligned VirtQueue over the granted DMA
        // page; descriptor phys addrs are `queue_paddr + offset`.
        unsafe {
            let queue = &mut *(queue_vaddr as *mut VirtQueue);
            queue.desc[0].addr = header_phys;
            queue.desc[0].len = 16;
            queue.desc[0].flags = DESC_FLAG_NEXT;
            queue.desc[0].next = 1;
            queue.desc[1].addr = data_phys;
            queue.desc[1].len = SECTOR_SIZE as u32;
            queue.desc[1].flags = DESC_FLAG_WRITE;
            queue.desc[1].next = 0;

            // Publish descriptor chain head to the available ring.
            queue.avail.ring[self.next_avail_idx as usize % QUEUE_SIZE as usize] =
                self.next_desc_idx;
            queue.avail.idx = self.next_avail_idx.wrapping_add(1);
        }
        self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
        self.next_desc_idx = (self.next_desc_idx + 2) % QUEUE_SIZE;

        // Notify the device (`Virtio::notify` -> MMIO_QUEUE_NOTIFY write).
        self.wr32(MMIO_QUEUE_NOTIFY, 0)?;

        // Wait for the device to signal completion (spin on the used ring).
        let target_idx = self.next_avail_idx.wrapping_sub(1);
        let mut spins = 0;
        let used_idx = unsafe {
            let queue = &*(queue_vaddr as *const VirtQueue);
            let used_idx_ptr = &queue.used.idx as *const u16;
            // SAFETY: `used_idx_ptr` points into the granted DMA page; a
            // volatile read of the device-written used index.
            ptr::read_volatile(used_idx_ptr)
        };
        let mut used_idx = used_idx;
        while used_idx != target_idx {
            core::hint::spin_loop();
            used_idx = unsafe {
                let queue = &*(queue_vaddr as *const VirtQueue);
                // SAFETY: `used_idx_ptr` points into the granted DMA page;
                // re-read the device-written used index.
                ptr::read_volatile(&queue.used.idx as *const u16)
            };
            spins += 1;
            if spins > 1_000_000 {
                return Err("virtio-blk: device did not complete request");
            }
        }

        // Read back the data (device wrote it into the DMA page).
        // SAFETY: reading from the granted DMA page we own.
        unsafe {
            let base = queue_vaddr as *mut u8;
            ptr::copy_nonoverlapping(base.add(data_addr), buf.as_mut_ptr(), SECTOR_SIZE);
        }

        // Acknowledge the used buffer (`Virtio::ack_used` -> MMIO_ISR read).
        let _ = self.rd32(MMIO_ISR);

        Ok(())
    }

    /// The device capacity in sectors.
    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    /// The device capacity in bytes.
    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors * SECTOR_SIZE as u64
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Fake MMIO region: all reads return 0, so the magic check fails.
    struct MmioStub {
        base: *mut u8,
    }

    impl MmioStub {
        fn new(len: usize) -> Self {
            // Leak a real buffer so the test has valid memory to read from.
            let buf = std::boxed::Box::leak(std::vec![0u8; len].into_boxed_slice());
            Self {
                base: buf.as_mut_ptr(),
            }
        }
    }

    #[test]
    fn probe_rejects_invalid_magic() {
        let mmio = MmioStub::new(4096);
        let driver = VirtioBlk::new(mmio.base as usize, 4096);
        assert!(!driver.probe());
    }

    #[test]
    fn init_zero_capacity_is_rejected() {
        let mmio = MmioStub::new(4096);
        let dma = std::boxed::Box::leak(std::vec![0u8; DMA_PAGE].into_boxed_slice());
        let mut driver = VirtioBlk::new(mmio.base as usize, 4096);
        // All MMIO reads return 0 → capacity 0 → rejected.
        assert_eq!(
            driver.init(dma.as_ptr() as usize, dma.as_ptr() as usize),
            Err("virtio-blk: zero capacity")
        );
        assert!(!driver.queue_vaddr.is_some());
    }
}
