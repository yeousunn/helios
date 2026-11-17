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
//! safe `hal::mmio::MmioWindow` wrapper. DMA allocation is the launcher's
//! job (Frame cap + `AS::MAP`), so the driver does not depend on `hal::Dma`
//! either. HAL traits stay kernel-internal.

use hal::dma::DmaBuffer;
use hal::mmio::MmioWindow;

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
#[derive(Clone, Copy, Default)]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    used_event: u16,
}

/// Used ring (device writes to this).
#[repr(C, align(4))]
#[derive(Clone, Copy, Default)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
#[derive(Clone, Copy, Default)]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QUEUE_SIZE as usize],
    avail_event: u16,
    _pad: u16, // Padding to make size a multiple of align (4)
}

/// The full virtqueue (descriptor table + available ring + used ring), laid
/// out contiguously in one DMA page.
/// NOTE: Not Pod due to inter-field padding and page-size trailing padding.
/// Components are copied separately.
#[repr(C, align(4096))]
#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
struct VirtQueue {
    desc: [Desc; QUEUE_SIZE as usize],
    avail: Avail,
    used: Used,
}

/// A virtio-blk block device.
pub struct VirtioBlk {
    /// Mapped MMIO window over the device BAR (from an `MmioRegion` cap).
    mmio: MmioWindow,
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
            mmio: MmioWindow::from_cap(mmio_base, mmio_len).expect("MMIO window validation failed"),
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

        // Zero the queue page using the safe DmaBuffer wrapper.
        let mut dma = DmaBuffer::from_cap(dma_virt, dma_phys, DMA_PAGE)
            .map_err(|_| "DMA buffer validation failed")?;
        dma.zero();

        self.queue_vaddr = Some(dma_virt);
        self.queue_paddr = dma_phys;
        self.next_desc_idx = 0;
        self.next_avail_idx = 0;

        Ok(())
    }

    /// Submit a one-sector read. The device fills `buf` (512 bytes) with
    /// sector `sector` contents. `buf` need not be DMA-accessible; the data
    /// stages through the granted DMA page.
    #[allow(clippy::field_reassign_with_default, clippy::needless_range_loop)]
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

        let mut dma = DmaBuffer::from_cap(queue_vaddr, queue_paddr as usize, DMA_PAGE)
            .map_err(|_| "DMA buffer validation failed")?;

        // Read desc array from DMA (16 descriptors, each 16 bytes at offset 0)
        let mut desc = [Desc::default(); QUEUE_SIZE as usize];
        for i in 0..QUEUE_SIZE as usize {
            let base = i * 16;
            desc[i].addr = dma.read64(base).map_err(|_| "DMA read failed")?;
            desc[i].len = dma.read32(base + 8).map_err(|_| "DMA read failed")?;
            desc[i].flags = dma.read16(base + 12).map_err(|_| "DMA read failed")?;
            desc[i].next = dma.read16(base + 14).map_err(|_| "DMA read failed")?;
        }

        // Read avail from DMA (offset 256)
        let avail_base = 256;
        let mut avail: Avail = Default::default();
        avail.flags = dma.read16(avail_base).map_err(|_| "DMA read failed")?;
        avail.idx = dma.read16(avail_base + 2).map_err(|_| "DMA read failed")?;
        for i in 0..QUEUE_SIZE as usize {
            avail.ring[i] = dma
                .read16(avail_base + 4 + i * 2)
                .map_err(|_| "DMA read failed")?;
        }
        avail.used_event = dma
            .read16(avail_base + 4 + QUEUE_SIZE as usize * 2)
            .map_err(|_| "DMA read failed")?;

        // Read used from DMA (offset 296)
        let used_base = 296;
        let mut used: Used = Default::default();
        used.flags = dma.read16(used_base).map_err(|_| "DMA read failed")?;
        used.idx = dma.read16(used_base + 2).map_err(|_| "DMA read failed")?;
        for i in 0..QUEUE_SIZE as usize {
            let elem_base = used_base + 4 + i * 8;
            used.ring[i].id = dma.read32(elem_base).map_err(|_| "DMA read failed")?;
            used.ring[i].len = dma.read32(elem_base + 4).map_err(|_| "DMA read failed")?;
        }
        used.avail_event = dma
            .read16(used_base + 4 + QUEUE_SIZE as usize * 8)
            .map_err(|_| "DMA read failed")?;
        used._pad = dma
            .read16(used_base + 6 + QUEUE_SIZE as usize * 8)
            .map_err(|_| "DMA read failed")?;

        // Build the request header in the data area (after the VirtQueue struct).
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&0u32.to_le_bytes()); // type = read
        header[4..8].copy_from_slice(&0u32.to_le_bytes()); // reserved
        header[8..16].copy_from_slice(&sector.to_le_bytes()); // sector
        dma.copy_from_slice(data_addr, &header)
            .map_err(|_| "DMA copy failed")?;

        // Set up descriptor chain.
        desc[0].addr = header_phys;
        desc[0].len = 16;
        desc[0].flags = DESC_FLAG_NEXT;
        desc[0].next = 1;
        desc[1].addr = data_phys;
        desc[1].len = SECTOR_SIZE as u32;
        desc[1].flags = DESC_FLAG_WRITE;
        desc[1].next = 0;

        // Publish descriptor chain head to the available ring.
        avail.ring[self.next_avail_idx as usize % QUEUE_SIZE as usize] = self.next_desc_idx;
        avail.idx = self.next_avail_idx.wrapping_add(1);

        // Write the updated virtqueue components back to DMA.
        for i in 0..QUEUE_SIZE as usize {
            let base = i * 16;
            dma.write64(base, desc[i].addr)
                .map_err(|_| "DMA write failed")?;
            dma.write32(base + 8, desc[i].len)
                .map_err(|_| "DMA write failed")?;
            dma.write16(base + 12, desc[i].flags)
                .map_err(|_| "DMA write failed")?;
            dma.write16(base + 14, desc[i].next)
                .map_err(|_| "DMA write failed")?;
        }

        dma.write16(avail_base, avail.flags)
            .map_err(|_| "DMA write failed")?;
        dma.write16(avail_base + 2, avail.idx)
            .map_err(|_| "DMA write failed")?;
        for i in 0..QUEUE_SIZE as usize {
            dma.write16(avail_base + 4 + i * 2, avail.ring[i])
                .map_err(|_| "DMA write failed")?;
        }
        dma.write16(avail_base + 4 + QUEUE_SIZE as usize * 2, avail.used_event)
            .map_err(|_| "DMA write failed")?;

        dma.write16(used_base, used.flags)
            .map_err(|_| "DMA write failed")?;
        dma.write16(used_base + 2, used.idx)
            .map_err(|_| "DMA write failed")?;
        for i in 0..QUEUE_SIZE as usize {
            let elem_base = used_base + 4 + i * 8;
            dma.write32(elem_base, used.ring[i].id)
                .map_err(|_| "DMA write failed")?;
            dma.write32(elem_base + 4, used.ring[i].len)
                .map_err(|_| "DMA write failed")?;
        }
        dma.write16(used_base + 4 + QUEUE_SIZE as usize * 8, used.avail_event)
            .map_err(|_| "DMA write failed")?;
        dma.write16(used_base + 6 + QUEUE_SIZE as usize * 8, used._pad)
            .map_err(|_| "DMA write failed")?;

        self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
        self.next_desc_idx = (self.next_desc_idx + 2) % QUEUE_SIZE;

        // Notify the device (`Virtio::notify` -> MMIO_QUEUE_NOTIFY write).
        self.wr32(MMIO_QUEUE_NOTIFY, 0)?;

        // Wait for the device to signal completion (spin on the used ring).
        let target_idx = self.next_avail_idx.wrapping_sub(1);
        let mut spins = 0;
        let used_idx_offset = 296 + core::mem::offset_of!(Used, idx);
        loop {
            // Copy the used index from DMA.
            let used_idx = dma.read16(used_idx_offset).map_err(|_| "DMA read failed")?;

            if used_idx == target_idx {
                break;
            }
            core::hint::spin_loop();
            spins += 1;
            if spins > 1_000_000 {
                return Err("virtio-blk: device did not complete request");
            }
        }

        // Read back the data (device wrote it into the DMA page).
        let mut data = [0u8; SECTOR_SIZE];
        dma.copy_to_slice(data_addr, &mut data)
            .map_err(|_| "DMA copy failed")?;
        buf.copy_from_slice(&data);

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

    /// Whether the virtqueue has been set up.
    pub fn queue_ready(&self) -> bool {
        self.queue_vaddr.is_some()
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
