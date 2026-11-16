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

use core::ptr;

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
            mmio: unsafe { MmioWindow::new(mmio_base, mmio_len) },
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

        // Zero the queue page.
        unsafe {
            ptr::write_bytes(dma_virt as *mut u8, 0, DMA_PAGE);
        }

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
    fn submit(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<usize, &'static str> {
        let queue_vaddr = self.queue_vaddr.ok_or("virtio-net: queue not set up")?;
        let queue_paddr = self.queue_paddr as u64;

        let header_addr = core::mem::size_of::<VirtQueue>();
        let data_addr = header_addr + 12; // 12-byte virtio-net header
        let data_phys = queue_paddr + data_addr as u64;
        let data_len = tx.len().max(rx.len());

        // Stage the header (zeroed) and transmit data into the DMA page. The
        // receive data region is left zeroed for the device to fill.
        // SAFETY: writing to the granted DMA page we own; header/data offsets
        // are within the 4 KiB page.
        unsafe {
            let base = queue_vaddr as *mut u8;
            ptr::write_bytes(base.add(header_addr), 0, 12);
            if !tx.is_empty() {
                ptr::copy_nonoverlapping(tx.as_ptr(), base.add(data_addr), tx.len());
            }
        }

        // Descriptor chain: header (read-only) + data.
        // SAFETY: `queue_vaddr` is an aligned VirtQueue over the granted DMA
        // page; descriptor phys addrs are `queue_paddr + offset`.
        unsafe {
            let queue = &mut *(queue_vaddr as *mut VirtQueue);
            queue.desc[0].addr = queue_paddr + header_addr as u64;
            queue.desc[0].len = 12;
            queue.desc[0].flags = DESC_FLAG_NEXT;
            queue.desc[0].next = 1;
            queue.desc[1].addr = data_phys;
            queue.desc[1].len = data_len as u32;
            queue.desc[1].flags = if !rx.is_empty() { DESC_FLAG_WRITE } else { 0 };
            queue.desc[1].next = 0;

            // Publish descriptor chain head to the available ring.
            queue.avail.ring[self.next_avail_idx as usize % QUEUE_SIZE as usize] =
                self.next_desc_idx;
            queue.avail.idx = self.next_avail_idx.wrapping_add(1);
        }
        let head = self.next_avail_idx;
        self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
        self.next_desc_idx = (self.next_desc_idx + 2) % QUEUE_SIZE;

        // Notify the device.
        self.wr32(MMIO_QUEUE_NOTIFY, 0)
            .map_err(|_| "MMIO write error")?;

        // Wait for the device to signal completion (spin on the used ring).
        let target_idx = head.wrapping_sub(1);
        let mut spins = 0;
        let mut used_idx = unsafe {
            let queue = &*(queue_vaddr as *const VirtQueue);
            // SAFETY: `used_idx_ptr` points into the granted DMA page; a
            // volatile read of the device-written used index.
            ptr::read_volatile(&queue.used.idx as *const u16)
        };
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
                return Err("virtio-net: device did not complete request");
            }
        }

        // The device completed the head of our chain; its used element holds
        // the byte count it wrote (receive) or echoed (transmit).
        let written = unsafe {
            let queue = &*(queue_vaddr as *const VirtQueue);
            let slot = (target_idx.wrapping_sub(1)) as usize % QUEUE_SIZE as usize;
            ptr::read_volatile(&queue.used.ring[slot].len as *const u32) as usize
        };

        // For a receive, copy the frame (after the 12-byte header) back out.
        let mut copied = 0;
        if !rx.is_empty() {
            unsafe {
                let base = queue_vaddr as *mut u8;
                copied = written.min(rx.len());
                ptr::copy_nonoverlapping(base.add(data_addr), rx.as_mut_ptr(), copied);
            }
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
