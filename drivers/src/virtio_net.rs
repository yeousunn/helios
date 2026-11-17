//! Virtio-net network device driver (capability-based, per ADR-052).
//!
//! The driver never touches raw HAL traits or physical addresses directly. It
//! receives:
//!  * a mapped MMIO window base (`mmio_base`) — the virtual address of an
//!    `MmioRegion` capability the kernel dispatcher mapped over the device's
//!    MMIO BAR, and
//!  * a single physically-contiguous DMA page (`dma_virt` / `dma_phys`) — a
//!    `Frame` capability the launcher mapped into the driver's address space,
//!    used for the virtqueue (descriptors + available ring + used ring + the
//!    frame buffer).
//!
//! All device register access goes through the mapped MMIO window via the
//! safe `hal::mmio::MmioWindow` wrapper. DMA allocation is the launcher's
//! job (Frame cap + `AS::MAP`), so the driver does not depend on `hal::Dma`
//! either. HAL traits stay kernel-internal.

use hal::dma::DmaBuffer;
use hal::mmio::MmioWindow;

/// Virtio PCI vendor ID (Red Hat / virtio).
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
/// Virtio-net device ID.
const VIRTIO_ID_NET: u16 = 0x1005;

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
const MMIO_ISR: usize = 0x68;
const MMIO_CONFIG_GEN: usize = 0x64;

/// Device status bits.
const STATUS_ACKNOWLEDGE: u32 = 0x1;
const STATUS_DRIVER: u32 = 0x2;
const STATUS_DRIVER_OK: u32 = 0x4;
const STATUS_FEATURES_OK: u32 = 0x8;

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

/// A virtio-net network device.
pub struct VirtioNet {
    /// Mapped MMIO window over the device BAR (from an `MmioRegion` cap).
    mmio: MmioWindow,
    /// MAC address read from config space.
    mac_addr: [u8; 6],
    /// MTU read from config space.
    mtu: u16,
    /// Virtual address of the DMA page holding the virtqueue (from a `Frame`
    /// cap mapped via `AS::MAP`), or None until `init`.
    queue_vaddr: Option<usize>,
    /// Physical address of the DMA page (device sees this).
    queue_paddr: usize,
    next_desc_idx: u16,
    next_avail_idx: u16,
}

impl VirtioNet {
    /// Create a new virtio-net driver over a kernel-granted MMIO window.
    /// `mmio_base` is the virtual address of a mapped `MmioRegion` covering the
    /// device's MMIO BAR; the caller (kernel dispatcher or init) holds the cap
    /// and has already mapped the region.
    pub fn new(mmio_base: usize, mmio_len: usize) -> Self {
        Self {
            mmio: MmioWindow::from_cap(mmio_base, mmio_len).expect("MMIO window validation failed"),
            mac_addr: [0; 6],
            mtu: 1500,
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
    /// `true` if a virtio-net device is present at `mmio_base`.
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
        if device_id != VIRTIO_ID_NET as u32 {
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

    /// Read the MAC address (6 bytes) and MTU from config space.
    fn read_config(&mut self) -> bool {
        let lo = match self.rd32(MMIO_CONFIG_GEN + 4) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let hi = match self.rd32(MMIO_CONFIG_GEN + 8) {
            Ok(v) => v,
            Err(_) => return false,
        };
        self.mac_addr = [
            lo as u8,
            (lo >> 8) as u8,
            (lo >> 16) as u8,
            (lo >> 24) as u8,
            hi as u8,
            (hi >> 8) as u8,
        ];
        self.mtu = (hi >> 16) as u16;
        true
    }

    /// Initialize the device: reset, acknowledge driver, negotiate features,
    /// read the MAC/MTU from config space, and set up the virtqueue in the
    /// caller-provided DMA page.
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

        // 4. Feature negotiation (v0: accept no extra features; device must
        //    work with the default feature set).
        self.wr32(MMIO_STATUS, status_ack | STATUS_FEATURES_OK)?;

        // 5. Driver OK: we're ready.
        self.wr32(MMIO_STATUS, status_ack | STATUS_DRIVER_OK)?;

        // 6. Read the MAC address and MTU from config space.
        if !self.read_config() {
            return Err("virtio-net: config read failed");
        }

        // 7. Set up the virtqueue in the granted DMA page.
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
            return Err("virtio-net: queue too small");
        }
        self.wr32(MMIO_QUEUE_NUM, QUEUE_SIZE as u32)
            .map_err(|_| "MMIO write error")?;
        self.wr32(MMIO_QUEUE_PFN, (dma_phys / DMA_PAGE) as u32)
            .map_err(|_| "MMIO write error")?;
        self.wr32(MMIO_QUEUE_READY, 1)
            .map_err(|_| "MMIO write error")?;

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

    /// The device MAC address.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_addr
    }

    /// The device MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Submit a descriptor chain (header + one data buffer), notify the device,
    /// and poll the used ring for completion.
    ///
    /// `data_len` is the number of valid bytes in `data`; `write` selects
    /// whether the data descriptor is device-to-driver (receive) or
    /// `tx` is the transmit source (read by the device, may be empty) and `rx`
    /// is the receive destination (written by the device, may be empty).
    /// Exactly one of them should be non-empty. Returns the byte count the
    /// device wrote on the used ring (0 for a pure transmit).
    #[allow(clippy::field_reassign_with_default, clippy::needless_range_loop)]
    fn submit(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<usize, &'static str> {
        let queue_vaddr = self.queue_vaddr.ok_or("virtio-net: queue not set up")?;
        let queue_paddr = self.queue_paddr as u64;

        let header_addr = core::mem::size_of::<VirtQueue>();
        let data_addr = header_addr + 12; // 12-byte virtio-net header
        let data_phys = queue_paddr + data_addr as u64;
        let data_len = tx.len().max(rx.len());

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

        // Stage the header (zeroed) and transmit data into the DMA page.
        let header = [0u8; 12];
        dma.copy_from_slice(data_addr, &header)
            .map_err(|_| "DMA copy failed")?;
        if !tx.is_empty() {
            dma.copy_from_slice(data_addr + 12, tx)
                .map_err(|_| "DMA copy failed")?;
        }

        // Descriptor chain: header (read-only) + data.
        desc[0].addr = queue_paddr + header_addr as u64;
        desc[0].len = 12;
        desc[0].flags = DESC_FLAG_NEXT;
        desc[0].next = 1;
        desc[1].addr = data_phys;
        desc[1].len = data_len as u32;
        desc[1].flags = if !rx.is_empty() { DESC_FLAG_WRITE } else { 0 };
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

        let head = self.next_avail_idx;
        self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
        self.next_desc_idx = (self.next_desc_idx + 2) % QUEUE_SIZE;

        // Notify the device.
        self.wr32(MMIO_QUEUE_NOTIFY, 0)
            .map_err(|_| "MMIO write error")?;

        // Wait for the device to signal completion (spin on the used ring).
        let target_idx = head.wrapping_sub(1);
        let mut spins = 0;
        let used_idx_offset = 296 + core::mem::offset_of!(Used, idx);
        loop {
            // Read the used index from DMA.
            let used_idx = dma.read16(used_idx_offset).map_err(|_| "DMA read failed")?;

            if used_idx == target_idx {
                break;
            }
            core::hint::spin_loop();
            spins += 1;
            if spins > 1_000_000 {
                return Err("virtio-net: device did not complete request");
            }
        }

        // The device completed the head of our chain; its used element holds
        // the byte count it wrote (receive) or echoed (transmit).
        let slot = (target_idx.wrapping_sub(1)) as usize % QUEUE_SIZE as usize;
        let used_ring_offset = 296
            + core::mem::offset_of!(Used, ring)
            + slot * core::mem::size_of::<UsedElem>()
            + core::mem::offset_of!(UsedElem, len);
        let written = dma
            .read32(used_ring_offset)
            .map_err(|_| "DMA read failed")? as usize;

        // For a receive, copy the frame (after the 12-byte header) back out.
        let mut copied = 0;
        if !rx.is_empty() {
            let copy_len = written.min(rx.len());
            let mut data = [0u8; 1536]; // Max MTU + header
            dma.copy_to_slice(data_addr, &mut data[..copy_len])
                .map_err(|_| "DMA copy failed")?;
            copied = copy_len;
            rx[..copied].copy_from_slice(&data[..copied]);
        }

        // Acknowledge the used buffer.
        let _ = self.rd32(MMIO_ISR);

        Ok(copied)
    }

    /// Transmit a single Ethernet frame. The frame is staged into the granted
    /// DMA page after a 12-byte zeroed virtio-net header, then the device is
    /// notified and the used ring is polled for completion.
    ///
    /// Returns an error if the device does not signal completion within the
    /// spin bound (e.g. no device is attached).
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let mut _nop: &mut [u8] = &mut [];
        self.submit(frame, _nop)?;
        Ok(())
    }

    /// Receive a single Ethernet frame into `buf`. The device writes the frame
    /// (after its 12-byte header) into the granted DMA page; the used ring is
    /// polled for completion and the frame is copied back to `buf`. Returns the
    /// number of bytes copied.
    pub fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        self.submit(&[], buf)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// Fake MMIO region: a u32 register array indexed by offset/4.
    struct MmioStub {
        regs: std::vec::Vec<u32>,
    }

    impl MmioStub {
        fn new(len: usize) -> Self {
            // Leak a real buffer so the test has valid memory to read from.
            Self {
                regs: std::vec![0u32; len],
            }
        }

        fn base(&self) -> usize {
            self.regs.as_ptr() as usize
        }

        fn wr32(&mut self, offset: usize, value: u32) {
            let i = offset / 4;
            if let Some(slot) = self.regs.get_mut(i) {
                *slot = value;
            }
        }

        fn with_device(mut self, magic: u32, version: u32, device: u32, vendor: u32) -> Self {
            self.wr32(MMIO_MAGIC, magic);
            self.wr32(MMIO_VERSION, version);
            self.wr32(MMIO_DEVICE_ID, device);
            self.wr32(MMIO_VENDOR_ID, vendor);
            self
        }
    }

    #[test]
    fn probe_rejects_invalid_magic() {
        let mmio = MmioStub::new(4096);
        let driver = VirtioNet::new(mmio.base(), 4096);
        assert!(!driver.probe());
    }

    #[test]
    fn probe_rejects_wrong_device_id() {
        let mmio = MmioStub::new(4096).with_device(0x7472_6976, 1, 0x9999, VIRTIO_VENDOR_ID as u32);
        let driver = VirtioNet::new(mmio.base(), 4096);
        assert!(!driver.probe());
    }

    #[test]
    fn probe_accepts_valid_device() {
        let mmio = MmioStub::new(4096).with_device(
            0x7472_6976,
            1,
            VIRTIO_ID_NET as u32,
            VIRTIO_VENDOR_ID as u32,
        );
        let driver = VirtioNet::new(mmio.base(), 4096);
        assert!(driver.probe());
    }

    #[test]
    fn init_reads_mac_and_mtu() {
        let mut mmio = MmioStub::new(4096).with_device(
            0x7472_6976,
            1,
            VIRTIO_ID_NET as u32,
            VIRTIO_VENDOR_ID as u32,
        );
        // MAC 02:03:04:05:06:07 at config bytes 0..5, MTU 1500 at bytes 6..7.
        mmio.wr32(MMIO_CONFIG_GEN + 4, 0x05040302);
        mmio.wr32(MMIO_CONFIG_GEN + 8, 0x05DC_0706);
        // QUEUE_NUM_MAX large enough to accept QUEUE_SIZE.
        mmio.wr32(MMIO_QUEUE_NUM_MAX, 64);
        let dma = std::boxed::Box::leak(std::vec![0u8; DMA_PAGE].into_boxed_slice());

        let mut driver = VirtioNet::new(mmio.base(), 4096);
        assert!(driver
            .init(dma.as_ptr() as usize, dma.as_ptr() as usize)
            .is_ok());
        assert_eq!(driver.mac_address(), [0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(driver.mtu(), 1500);
        assert!(driver.queue_vaddr.is_some());
    }

    #[test]
    fn init_rejects_queue_too_small() {
        let mut mmio = MmioStub::new(4096).with_device(
            0x7472_6976,
            1,
            VIRTIO_ID_NET as u32,
            VIRTIO_VENDOR_ID as u32,
        );
        mmio.wr32(MMIO_QUEUE_NUM_MAX, 8);
        let mut driver = VirtioNet::new(mmio.base(), 4096);
        assert_eq!(driver.init(0, 0), Err("virtio-net: queue too small"));
        assert!(!driver.queue_vaddr.is_some());
    }
}
