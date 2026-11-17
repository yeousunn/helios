//! Virtio-gpu display driver (capability-based, per ADR-052).
//!
//! The driver receives:
//!  * a mapped MMIO window base (`mmio_base`) — the virtual address of an
//!    `MmioRegion` capability the kernel dispatcher mapped over the device's
//!    MMIO BAR, and
//!  * a single physically-contiguous DMA page (`dma_virt` / `dma_phys`) — a
//!    `Frame` capability the launcher mapped into the driver's address space,
//!    used for the virtqueue (descriptors + rings + command/data area).
//!
//! All device register access goes through the mapped MMIO window via the
//! safe `hal::mmio::MmioWindow` wrapper. DMA allocation is the launcher's
//! job (Frame cap + `AS::MAP`), so the driver does not depend on `hal::Dma`
//! either. HAL traits stay kernel-internal.

use hal::dma::DmaBuffer;
use hal::mmio::MmioWindow;

/// Virtio PCI vendor ID (Red Hat / virtio).
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// Virtio-gpu device ID.
const VIRTIO_ID_GPU: u16 = 0x0901;

/// Legacy virtio MMIO register offsets.
const MMIO_MAGIC: usize = 0x00;
const MMIO_VERSION: usize = 0x04;
const MMIO_DEVICE_ID: usize = 0x08;
const MMIO_VENDOR_ID: usize = 0x0C;
const MMIO_QUEUE_SEL: usize = 0x30;
const MMIO_QUEUE_NUM_MAX: usize = 0x34;
const MMIO_QUEUE_NUM: usize = 0x38;
const MMIO_QUEUE_PFN: usize = 0x40;
const MMIO_QUEUE_READY: usize = 0x44;
const MMIO_QUEUE_NOTIFY: usize = 0x50;
const MMIO_STATUS: usize = 0x60;

/// Device status bits.
const STATUS_ACKNOWLEDGE: u32 = 0x1;
const STATUS_DRIVER: u32 = 0x2;
const STATUS_DRIVER_OK: u32 = 0x4;
const STATUS_FEATURES_OK: u32 = 0x8;

/// DMA page size (bytes).
const DMA_PAGE: usize = 4096;

/// Number of descriptors in the virtqueue.
const QUEUE_SIZE: u16 = 16;

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

/// A virtio-gpu display device.
pub struct VirtioGpu {
    /// Mapped MMIO window over the device BAR (from an `MmioRegion` cap).
    mmio: MmioWindow,
    /// Virtual address of the DMA page holding the virtqueue (from a `Frame`
    /// cap mapped via `AS::MAP`), or None until `init`.
    queue_vaddr: Option<usize>,
    /// Physical address of the DMA page (device sees this).
    queue_paddr: usize,
    /// Scanout framebuffer width in pixels.
    width: u32,
    /// Scanout framebuffer height in pixels.
    height: u32,
    next_avail_idx: u16,
}

impl VirtioGpu {
    /// Create a new virtio-gpu driver over a kernel-granted MMIO window.
    /// `mmio_base` is the virtual address of a mapped `MmioRegion` covering the
    /// device's MMIO BAR; the caller holds the cap and has already mapped the
    /// region.
    pub fn new(mmio_base: usize, mmio_len: usize) -> Self {
        Self {
            mmio: MmioWindow::from_cap(mmio_base, mmio_len).expect("MMIO window validation failed"),
            queue_vaddr: None,
            queue_paddr: 0,
            width: 0,
            height: 0,
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
    /// `true` if a virtio-gpu device is present at `mmio_base`.
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
        if device_id != VIRTIO_ID_GPU as u32 {
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

    /// Initialize the device: reset, acknowledge driver, negotiate features,
    /// and set up the virtqueue in the caller-provided DMA page.
    ///
    /// `dma_virt`/`dma_phys` are the virtual/physical address of a
    /// page-sized, physically-contiguous DMA buffer granted via a `Frame`
    /// capability and mapped into this driver's address space (the launcher
    /// used `AS::MAP`; the driver never allocates DMA itself).
    pub fn init(&mut self, dma_virt: usize, dma_phys: usize) -> Result<(), &'static str> {
        // 1. Reset: write 0 to status.
        self.wr32(MMIO_STATUS, 0)?;

        // 2. Acknowledge: we've seen the device.
        let status_ack = self.rd32(MMIO_STATUS)?;
        self.wr32(MMIO_STATUS, status_ack | STATUS_ACKNOWLEDGE)?;

        // 3. Driver: we know how to drive it.
        self.wr32(MMIO_STATUS, status_ack | STATUS_DRIVER)?;

        // 4. Feature negotiation (v0: accept no extra features).
        self.wr32(MMIO_STATUS, status_ack | STATUS_FEATURES_OK)?;

        // 5. Driver OK: we're ready.
        self.wr32(MMIO_STATUS, status_ack | STATUS_DRIVER_OK)?;

        // 6. Set up the virtqueue in the granted DMA page.
        self.setup_queue(dma_virt, dma_phys)?;

        Ok(())
    }

    /// Program the virtqueue into the granted DMA page.
    fn setup_queue(&mut self, dma_virt: usize, dma_phys: usize) -> Result<(), &'static str> {
        self.wr32(MMIO_QUEUE_SEL, 0)
            .map_err(|_| "MMIO write error")?; // select queue 0
        let max = self
            .rd32(MMIO_QUEUE_NUM_MAX)
            .map_err(|_| "MMIO read error")?;
        if max < QUEUE_SIZE as u32 {
            return Err("virtio-gpu: queue too small");
        }
        self.wr32(MMIO_QUEUE_NUM, QUEUE_SIZE as u32)
            .map_err(|_| "MMIO write error")?;
        self.wr32(MMIO_QUEUE_PFN, (dma_phys / DMA_PAGE) as u32)
            .map_err(|_| "MMIO write error")?;
        self.wr32(MMIO_QUEUE_READY, 1)
            .map_err(|_| "MMIO write error")?;

        let mut dma = DmaBuffer::from_cap(dma_virt, dma_phys, DMA_PAGE)
            .map_err(|_| "DMA buffer validation failed")?;
        dma.zero();

        // Copy desc array (offset 0) - 16 descriptors, each 16 bytes
        for i in 0..QUEUE_SIZE as usize {
            let base = i * 16;
            dma.write64(base, 0).map_err(|_| "DMA write failed")?; // addr
            dma.write32(base + 8, 0).map_err(|_| "DMA write failed")?; // len
            dma.write16(base + 12, 0).map_err(|_| "DMA write failed")?; // flags
            dma.write16(base + 14, 0).map_err(|_| "DMA write failed")?; // next
        }

        // Copy avail (offset 256 = 16 * 16)
        let avail_base = 256;
        dma.write16(avail_base, 0).map_err(|_| "DMA write failed")?; // flags
        dma.write16(avail_base + 2, 0)
            .map_err(|_| "DMA write failed")?; // idx
        for i in 0..QUEUE_SIZE as usize {
            dma.write16(avail_base + 4 + i * 2, 0)
                .map_err(|_| "DMA write failed")?; // ring[i]
        }
        dma.write16(avail_base + 4 + QUEUE_SIZE as usize * 2, 0)
            .map_err(|_| "DMA write failed")?; // used_event

        // Copy used (offset 296 = 256 + 38 + 2 padding)
        let used_base = 296;
        dma.write16(used_base, 0).map_err(|_| "DMA write failed")?; // flags
        dma.write16(used_base + 2, 0)
            .map_err(|_| "DMA write failed")?; // idx
        for i in 0..QUEUE_SIZE as usize {
            let elem_base = used_base + 4 + i * 8;
            dma.write32(elem_base, 0).map_err(|_| "DMA write failed")?; // id
            dma.write32(elem_base + 4, 0)
                .map_err(|_| "DMA write failed")?; // len
        }
        dma.write16(used_base + 4 + QUEUE_SIZE as usize * 8, 0)
            .map_err(|_| "DMA write failed")?; // avail_event
        dma.write16(used_base + 6 + QUEUE_SIZE as usize * 8, 0)
            .map_err(|_| "DMA write failed")?; // _pad

        self.queue_vaddr = Some(dma_virt);
        self.queue_paddr = dma_phys;
        self.next_avail_idx = 0;

        Ok(())
    }

    /// Notify the device that the available ring has new entries
    /// (`Virtio::notify` -> MMIO_QUEUE_NOTIFY write).
    pub fn notify_queue(&self) -> Result<(), &'static str> {
        self.wr32(MMIO_QUEUE_NOTIFY, 0)
    }

    /// The scanout framebuffer width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// The scanout framebuffer height in pixels.
    pub fn height(&self) -> u32 {
        self.height
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
        let gpu = VirtioGpu::new(mmio.base as usize, 4096);
        assert!(!gpu.probe());
        assert!(!gpu.queue_ready());
    }

    #[test]
    fn init_zeroes_dma_page_and_marks_queue_ready() {
        let mmio = MmioStub::new(4096);
        let dma = std::boxed::Box::leak(std::vec![0xAAu8; DMA_PAGE].into_boxed_slice());
        let mut gpu = VirtioGpu::new(mmio.base as usize, 4096);
        // All MMIO reads return 0 → queue num max 0 < QUEUE_SIZE → rejected.
        assert_eq!(
            gpu.init(dma.as_ptr() as usize, dma.as_ptr() as usize),
            Err("virtio-gpu: queue too small")
        );
        assert!(!gpu.queue_ready());
    }
}
