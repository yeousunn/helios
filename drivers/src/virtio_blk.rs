//! Virtio-blk block device driver.

use hal::{Dma, Virtio};

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
const MMIO_STATUS: usize = 0x60;
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
#[derive(Clone, Copy)]
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
/// out contiguously in one DMA frame.
#[repr(C, align(4096))]
struct VirtQueue {
    desc: [Desc; QUEUE_SIZE as usize],
    avail: Avail,
    used: Used,
}

/// A virtio-blk block device.
pub struct VirtioBlk<V: Virtio, D: Dma> {
    virtio: V,
    dma: D,
    mmio_base: usize,
    capacity_sectors: u64,
    queue: Option<VirtQueue>,
    queue_paddr: usize,
    next_desc_idx: u16,
    next_avail_idx: u16,
}

impl<V: Virtio, D: Dma> VirtioBlk<V, D> {
    /// Create a new virtio-blk driver wrapping HAL implementations. The
    /// caller must have already discovered the device (via `PciBus`) and
    /// mapped its MMIO BAR (via `MmioRegion::map_mmio`), passing the mapped
    /// address as `mmio_base`.
    pub fn new(virtio: V, dma: D, mmio_base: usize) -> Self {
        Self {
            virtio,
            dma,
            mmio_base,
            capacity_sectors: 0,
            queue: None,
            queue_paddr: 0,
            next_desc_idx: 0,
            next_avail_idx: 0,
        }
    }

    /// Read a u32 from a virtio MMIO register.
    fn rd32(&self, offset: usize) -> u32 {
        // SAFETY: `mmio_base` points at a mapped virtio-blk device MMIO region.
        unsafe { core::ptr::read_volatile((self.mmio_base + offset) as *const u32) }
    }

    /// Write a u32 to a virtio MMIO register.
    fn wr32(&self, offset: usize, value: u32) {
        // SAFETY: `mmio_base` points at a mapped writable virtio-blk device
        // MMIO region.
        unsafe {
            core::ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
    }

    /// Probe the device: verify magic/version/vendor/device IDs. Returns
    /// `true` if a virtio-blk device is present at `mmio_base`.
    pub fn probe(&self) -> bool {
        if self.rd32(MMIO_MAGIC) != 0x7472_6976
        /* "virt" */
        {
            return false;
        }
        if self.rd32(MMIO_VERSION) != 1 {
            return false;
        }
        if self.rd32(MMIO_DEVICE_ID) != VIRTIO_ID_BLOCK as u32 {
            return false;
        }
        if self.rd32(MMIO_VENDOR_ID) != VIRTIO_VENDOR_ID as u32 {
            return false;
        }
        true
    }

    /// Read the device capacity (in 512-byte sectors) from config space.
    pub fn capacity(&self) -> u64 {
        // SAFETY: reading config space; the device is present.
        let lo = unsafe {
            core::ptr::read_volatile((self.mmio_base + MMIO_CONFIG_GEN + 4) as *const u32)
        } as u64;
        let hi = unsafe {
            core::ptr::read_volatile((self.mmio_base + MMIO_CONFIG_GEN + 8) as *const u32)
        } as u64;
        lo | (hi << 32)
    }

    /// Initialize the device: reset, acknowledge driver, negotiate features,
    /// and set up the virtqueue. Returns the device capacity in sectors on
    /// success.
    pub fn init(&mut self) -> Result<u64, &'static str> {
        // 1. Reset: write 0 to status.
        self.wr32(MMIO_STATUS, 0);

        // 2. Acknowledge: we've seen the device.
        self.wr32(MMIO_STATUS, self.rd32(MMIO_STATUS) | STATUS_ACKNOWLEDGE);

        // 3. Driver: we know how to drive it.
        self.wr32(MMIO_STATUS, self.rd32(MMIO_STATUS) | STATUS_DRIVER);

        // 4. Feature negotiation (v0: accept no extra features; device must
        //    work with the default feature set).
        self.wr32(MMIO_STATUS, self.rd32(MMIO_STATUS) | STATUS_FEATURES_OK);

        // 5. Driver OK: we're ready.
        self.wr32(MMIO_STATUS, self.rd32(MMIO_STATUS) | STATUS_DRIVER_OK);

        // 6. Read capacity from config space (offset 0 in config region).
        let capacity = self.capacity();
        if capacity == 0 {
            return Err("virtio-blk: zero capacity");
        }
        self.capacity_sectors = capacity;

        // 7. Set up the virtqueue.
        self.setup_queue()?;

        Ok(capacity)
    }

    /// Allocate a DMA frame and program the virtqueue.
    fn setup_queue(&mut self) -> Result<(), &'static str> {
        // Allocate one page for the virtqueue.
        let (vaddr, paddr) =
            unsafe { self.dma.alloc_dma(4096, 4096) }.ok_or("virtio-blk: DMA alloc failed")?;

        // Zero the queue.
        let queue_ptr = vaddr as *mut VirtQueue;
        // SAFETY: freshly allocated DMA frame, exclusively ours.
        unsafe { core::ptr::write_bytes(queue_ptr, 0, core::mem::size_of::<VirtQueue>()) };

        // Initialize available ring indices.
        // SAFETY: `queue_ptr` points at a freshly allocated, zeroed, aligned
        // VirtQueue frame.
        unsafe {
            (*queue_ptr).avail.idx = 0;
            (*queue_ptr).used.idx = 0;
        }

        // Tell the device the queue size.
        self.wr32(MMIO_QUEUE_SEL, 0); // select queue 0
        let max = self.rd32(MMIO_QUEUE_NUM_MAX);
        if max < QUEUE_SIZE as u32 {
            return Err("virtio-blk: queue too small");
        }
        self.wr32(MMIO_QUEUE_NUM, QUEUE_SIZE as u32);
        self.wr32(MMIO_QUEUE_PFN, (paddr / 4096) as u32);
        self.wr32(MMIO_QUEUE_READY, 1);

        self.queue = Some(unsafe { core::ptr::read(queue_ptr) });
        self.queue_paddr = paddr;
        self.next_desc_idx = 0;
        self.next_avail_idx = 0;

        Ok(())
    }

    /// Submit a one-sector read. The device fills `buf` (must be 512 bytes,
    /// DMA-accessible) with sector `sector` contents.
    pub fn read_sector(
        &mut self,
        sector: u64,
        buf: &mut [u8; SECTOR_SIZE],
    ) -> Result<(), &'static str> {
        let queue = self.queue.as_mut().ok_or("virtio-blk: queue not set up")?;

        // Build a single-descriptor chain: read-only header (12 bytes) +
        // write-only data buffer (512 bytes).
        //
        // The virtio-blk request header:
        //   type (u32) = 0 (read)
        //   reserved (u32)
        //   sector (u64)
        let header_addr = self.queue_paddr + core::mem::size_of::<VirtQueue>();
        let data_addr = header_addr + 16; // header + padding to data

        // SAFETY: writing to the DMA-allocated virtqueue frame.
        unsafe {
            core::ptr::write_volatile(
                (self.queue_paddr as *mut u8).add(header_addr) as *mut u32,
                0, // read
            );
            core::ptr::write_volatile(
                (self.queue_paddr as *mut u8).add(header_addr + 4) as *mut u32,
                0, // reserved
            );
            core::ptr::write_volatile(
                (self.queue_paddr as *mut u8).add(header_addr + 8) as *mut u64,
                sector,
            );
            // Copy the sector data into place after the header.
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (self.queue_paddr as *mut u8).add(data_addr),
                SECTOR_SIZE,
            );
        }

        // Descriptor 0: header (read-only).
        queue.desc[0].addr = header_addr as u64;
        queue.desc[0].len = 16;
        queue.desc[0].flags = DESC_FLAG_NEXT;
        queue.desc[0].next = 1;

        // Descriptor 1: data buffer (write-only).
        queue.desc[1].addr = data_addr as u64;
        queue.desc[1].len = SECTOR_SIZE as u32;
        queue.desc[1].flags = DESC_FLAG_WRITE;
        queue.desc[1].next = 0;

        // Publish descriptor chain head to available ring.
        queue.avail.ring[self.next_avail_idx as usize % QUEUE_SIZE as usize] = self.next_desc_idx;
        queue.avail.idx = self.next_avail_idx.wrapping_add(1);
        self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
        self.next_desc_idx = (self.next_desc_idx + 2) % QUEUE_SIZE;

        // Notify the device.
        unsafe { self.virtio.notify(0) };

        // Wait for the device to signal completion (spin on used ring).
        let mut used_idx = unsafe { core::ptr::read_volatile(&queue.used.idx as *const u16) };
        let target_idx = self.next_avail_idx.wrapping_sub(1);
        let mut spins = 0;
        while used_idx != target_idx {
            core::hint::spin_loop();
            used_idx = unsafe { core::ptr::read_volatile(&queue.used.idx as *const u16) };
            spins += 1;
            if spins > 1_000_000 {
                return Err("virtio-blk: device did not complete request");
            }
        }

        // Read back the data (device wrote it into the buffer).
        unsafe {
            core::ptr::copy_nonoverlapping(
                (self.queue_paddr as *mut u8).add(data_addr),
                buf.as_mut_ptr(),
                SECTOR_SIZE,
            );
        }

        // Acknowledge used buffer.
        unsafe { self.virtio.ack_used() };

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

    /// Mock HAL implementations for host testing.
    struct MockVirtio;
    struct MockDma;

    impl Default for MockVirtio {
        fn default() -> Self {
            Self
        }
    }
    impl Default for MockDma {
        fn default() -> Self {
            Self
        }
    }

    impl Virtio for MockVirtio {
        unsafe fn notify(&mut self, _queue_sel: u16) {}
        unsafe fn read_isr(&mut self) -> u8 {
            0
        }
        unsafe fn ack_used(&mut self) {}
    }

    impl Dma for MockDma {
        unsafe fn alloc_dma(&mut self, bytes: u64, _align: u64) -> Option<(usize, usize)> {
            // Leak a real buffer so the test has valid memory to write to.
            let buf = std::boxed::Box::leak(std::vec![0u8; bytes as usize].into_boxed_slice());
            Some((buf.as_ptr() as usize, buf.as_ptr() as usize))
        }
        unsafe fn free_dma(&mut self, _virt: usize, _phys: usize) {}
        unsafe fn sync_for_device(&mut self, _virt: usize, _bytes: u64) {}
        unsafe fn sync_for_cpu(&mut self, _virt: usize, _bytes: u64) {}
    }

    #[test]
    fn probe_rejects_invalid_magic() {
        // Allocate a fake MMIO region (reads return 0 → magic check fails).
        let mmio = std::boxed::Box::leak(std::vec![0u8; 4096].into_boxed_slice());
        let driver = VirtioBlk::new(
            MockVirtio::default(),
            MockDma::default(),
            mmio.as_ptr() as usize,
        );
        assert!(!driver.probe());
    }
}
