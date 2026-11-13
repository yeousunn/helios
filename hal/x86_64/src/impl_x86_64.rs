//! x86_64-specific HAL implementation.
//! Only compiled on `target_arch = "x86_64"`.

use core::fmt::{self, Write};

use crate::host::{
    cpuid_leaf1_logical_processors, cpuid_topology_ncpus, fs_base_is_canonical_user,
    pci_config_addr, FS_BASE_USER_CEIL, PCI_CONFIG_ADDR, PCI_CONFIG_DATA,
};
use crate::host::{CpuidTopologyEntry, CPUID_LEAF_1, CPUID_LEAF_TOPOLOGY};
use crate::paging::{enable_nx, BackendFactoryX86_64};
use caps::ObjId;
use hal::{
    AcpiParser, BootInfo, CpuTopology, DeviceTree, Dma, Halt, Ipi, MmioRegion, PciBus,
    SecondaryBoot, Virtio,
};
use hal::{EarlyBoot, Framebuffer, Gdt as HalGdt, Idt as HalIdt, Irq, Timer, Uart};
use kernel::aspace;
use kernel::console::Level;
use kernel::entry;
use kernel::frame;
use kernel::sched;

/// COM1 I/O base address.
const COM1: u16 = 0x3F8;

/// 16550 register offsets.
const REG_THR: u16 = 0; // Transmitter holding register (write)
const REG_IER: u16 = 1; // Interrupt enable register
const REG_FCR: u16 = 2; // FIFO control register (write)
const REG_LCR: u16 = 3; // Line control register
const REG_MCR: u16 = 4; // Modem control register
const REG_LSR: u16 = 5; // Line status register

/// Line status: transmitter holding register empty.
const LSR_THRE: u8 = 0x20;

/// 8259 PIC I/O ports.
const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;

/// PIC remap base: IRQs 0..15 map to IDT vectors 0x20..0x2F.
const PIC_VECTOR_BASE: u8 = 0x20;

/// PIC ICW1: ICW4 needed.
const PIC_ICW1_ICW4: u8 = 0x11;
/// PIC ICW4: 8086 mode, normal EOI.
const PIC_ICW4_8086: u8 = 0x01;

/// EOI command.
const PIC_EOI: u8 = 0x20;

/// Handler signature for an IRQ line.
type IrqHandler = fn(u8) -> bool;

/// PIT channel 0 data port and mode register.
const PIT_CH0: u16 = 0x40;
const PIT_MODE: u16 = 0x43;
/// PIT base frequency ~1.193182 MHz.
const PIT_BASE_HZ: u64 = 1_193_182;

/// QEMU isa-debug-exit I/O port (x86_64). Writing an exit code here terminates
/// QEMU with that status.
const QEMU_EXIT_PORT: u16 = 0x501;
/// Exit status reported to QEMU on clean bring-up halt.
const QEMU_EXIT_SUCCESS: u8 = 0;

/// GDT selectors.
#[allow(dead_code)]
const SEL_NULL: u16 = 0x00;
#[allow(dead_code)]
const SEL_CODE: u16 = 0x08;
const SEL_DATA: u16 = 0x10;

/// Concrete UART type for COM1.
pub struct Com1Uart;

/// Concrete early-boot type.
pub struct X86_64EarlyBoot;

/// GDT table: null, code, data descriptors.
#[repr(C, align(8))]
pub struct Gdt {
    /// Layout (fixed ABI for iretq/sysret selectors):
    /// 0 null | 1 kernel code 64 (0x08) | 2 kernel data (0x10) |
    /// 3 user data (0x18 → 0x1B) | 4 user code 64 (0x20 → 0x23) |
    /// 5+6 64-bit TSS descriptor (0x28) | 7 spare.
    entries: [u64; 8],
}

/// IDT table: 256 entries, each 8 bytes.
#[repr(C, align(8))]
pub struct Idt {
    entries: [u64; 256],
}

/// GDTR / IDTR descriptor register value.
#[repr(C, packed)]
pub struct TablePtr {
    limit: u16,
    base: u64,
}

/// Stub framebuffer (no real video mode yet).
#[derive(Default)]
pub struct StubFramebuffer {
    width: usize,
    height: usize,
    stride: usize,
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn port_outb(port: u16, value: u8) {
    // SAFETY: Raw I/O port write; COM1 is a safe, well-known UART port.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack));
    }
}

#[inline(always)]
unsafe fn port_inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Raw I/O port read; COM1 is a safe, well-known UART port.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, lateout("al") value, options(nostack));
    }
    value
}

#[inline(always)]
unsafe fn port_outl(port: u16, value: u32) {
    // SAFETY: Raw 32-bit I/O port write; PCI config address/data ports are safe.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack));
    }
}

#[inline(always)]
unsafe fn port_inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: Raw 32-bit I/O port read; PCI config address/data ports are safe.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, lateout("eax") value, options(nostack));
    }
    value
}

// ---------------------------------------------------------------------------
// PCI config space (IO-port mechanism, ADR-016 PciBus)
// ---------------------------------------------------------------------------

/// Read a vendor ID to test whether a PCI function exists.
fn pci_function_present(bus: u8, dev: u8, fn_: u8) -> bool {
    // SAFETY: PCI config address/data ports are safe to program.
    unsafe {
        port_outl(PCI_CONFIG_ADDR, pci_config_addr(bus, dev, fn_, 0));
        port_inl(PCI_CONFIG_DATA) != 0xFFFF_FFFF
    }
}

// ---------------------------------------------------------------------------
// UART 16550
// ---------------------------------------------------------------------------

impl Uart for Com1Uart {
    unsafe fn init(&mut self) {
        // SAFETY: Initializing COM1 UART; no shared mutable state.
        port_outb(COM1 + REG_IER, 0x00); // Disable all interrupts
        port_outb(COM1 + REG_LCR, 0x80); // Enable DLAB to set baud divisor
        port_outb(COM1 + REG_THR, 0x01); // Divisor low byte = 1 (115200 baud)
        port_outb(COM1 + REG_IER, 0x00); // Divisor high byte = 0
        port_outb(COM1 + REG_LCR, 0x03); // 8N1, DLAB clear
        port_outb(COM1 + REG_FCR, 0xC7); // Enable FIFO, clear RX/TX
        port_outb(COM1 + REG_MCR, 0x0B); // RTS/DSR, IRQ enable
    }

    unsafe fn write_byte(&mut self, byte: u8) {
        // Wait until the transmitter holding register is empty.
        // SAFETY: Reading COM1 line status register.
        while port_inb(COM1 + REG_LSR) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        // SAFETY: Writing to COM1 transmitter holding register.
        port_outb(COM1 + REG_THR, byte);
    }
}

impl Write for Com1Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            // SAFETY: write_byte only touches the COM1 UART port.
            unsafe {
                self.write_byte(byte);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 8259 PIC — IRQ controller
// ---------------------------------------------------------------------------

/// Programmable Interrupt Controller (dual 8259). Holds the per-IRQ handler
/// table so the (future) IDT stub can dispatch to registered handlers.
pub struct Pic {
    handlers: [Option<IrqHandler>; 16],
    mask: u16,
}

impl Pic {
    pub const fn new() -> Self {
        Self {
            handlers: [None; 16],
            mask: 0xFFFF,
        }
    }
}

impl Irq for Pic {
    unsafe fn register_handler(&mut self, irq: u8, handler: fn(u8) -> bool) {
        // SAFETY: Called single-threaded during early boot; `irq < 16` checked.
        assert!(irq < 16, "irq out of range");
        self.handlers[irq as usize] = Some(handler);
        // The IDT is not yet wired to invoke handlers; registration records
        // the intent for the scheduler/IRQ dispatch layer (Phase 1).
    }

    unsafe fn unmask(&mut self, irq: u8) {
        assert!(irq < 16, "irq out of range");
        let data = if irq < 8 {
            PIC_MASTER_DATA
        } else {
            PIC_SLAVE_DATA
        };
        // SAFETY: PIC data ports are safe to program during early boot.
        unsafe {
            let mut imr = port_inb(data);
            imr &= !(1 << (irq % 8));
            port_outb(data, imr);
        }
        self.mask &= !(1u16 << irq);
    }

    unsafe fn mask(&mut self, irq: u8) {
        assert!(irq < 16, "irq out of range");
        let data = if irq < 8 {
            PIC_MASTER_DATA
        } else {
            PIC_SLAVE_DATA
        };
        // SAFETY: PIC data ports are safe to program during early boot.
        // Per-port bit = irq % 8 (the slave bank's bits are 0..7 — the old
        // `1u8 << irq` overflowed in debug builds for irq >= 8, and even in
        // release set the wrong slave bit).
        unsafe {
            let mut imr = port_inb(data);
            imr |= 1 << (irq % 8);
            port_outb(data, imr);
        }
        self.mask |= 1u16 << irq;
    }

    unsafe fn ack(&mut self, irq: u8) {
        // SAFETY: EOI to the PIC(s) is safe during early boot.
        unsafe {
            if irq >= 8 {
                port_outb(PIC_SLAVE_CMD, PIC_EOI);
            }
            port_outb(PIC_MASTER_CMD, PIC_EOI);
        }
    }
}

impl Default for Pic {
    fn default() -> Self {
        Self::new()
    }
}

/// Remap the dual 8259 PIC so IRQs 0..15 map to IDT vectors 0x20..0x2F, then
/// mask every line. Call once during early boot.
///
/// # Safety
///
/// Programs the PIC data/command ports; safe during single-threaded bring-up.
unsafe fn pic_remap() {
    // ICW1: edge triggered, cascade, ICW4 needed.
    port_outb(PIC_MASTER_CMD, PIC_ICW1_ICW4);
    port_outb(PIC_SLAVE_CMD, PIC_ICW1_ICW4);
    // ICW2: vector base.
    port_outb(PIC_MASTER_DATA, PIC_VECTOR_BASE);
    port_outb(PIC_SLAVE_DATA, PIC_VECTOR_BASE + 8);
    // ICW3: master IRQ2 -> slave; slave's cascade identity = 2.
    port_outb(PIC_MASTER_DATA, 0x04);
    port_outb(PIC_SLAVE_DATA, 0x02);
    // ICW4: 8086 mode, normal EOI.
    port_outb(PIC_MASTER_DATA, PIC_ICW4_8086);
    port_outb(PIC_SLAVE_DATA, PIC_ICW4_8086);
    // Mask all IRQs on both chips.
    port_outb(PIC_MASTER_DATA, 0xFF);
    port_outb(PIC_SLAVE_DATA, 0xFF);
}

// ---------------------------------------------------------------------------
// PIT + TSC — timer source
// ---------------------------------------------------------------------------

/// Programmable Interval Timer channel 0 + TSC timebase.
pub struct TimerSrc {}

impl TimerSrc {
    pub const fn new() -> Self {
        Self {}
    }
}

impl Timer for TimerSrc {
    unsafe fn set_oneshot(&mut self, deadline_ns: u64) {
        // Convert ns to PIT ticks (channel 0, mode 0 = oneshot, binary).
        let ticks = deadline_ns * PIT_BASE_HZ / 1_000_000_000;
        let ticks = ticks.clamp(1, 0xFFFF);
        // SAFETY: PIT ports are safe to program during early boot.
        unsafe {
            port_outb(PIT_MODE, 0x30); // ch0, lobyte/hibyte, mode 0, binary
            port_outb(PIT_CH0, (ticks & 0xFF) as u8);
            port_outb(PIT_CH0, ((ticks >> 8) & 0xFF) as u8);
        }
    }

    fn now_ns(&self) -> u64 {
        // SAFETY: `rdtsc` is serializing enough for a coarse timebase; safe.
        let lo: u64;
        let hi: u64;
        unsafe {
            core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, readonly));
        }
        let tsc = (hi << 32) | lo;
        // Approximate ns: assume ~2.5 GHz (TSC); fine for bring-up scheduling hints.
        tsc * 1_000_000_000 / 2_500_000_000
    }

    fn expired(&self) -> bool {
        // PIT channel 0 count-down reaches zero → expired. Readback via latch
        // command is complex; treat any non-zero deadline as not-yet-expired
        // until the scheduler owns the timer. Conservative bring-up default.
        false
    }
}

impl Default for TimerSrc {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// ADR-014: CPU topology + SMP — x86_64 stubs (LAPIC-based, wired when SMP lands)
// ===========================================================================

/// x86_64 CPU topology: probes CPUID leaf 0x0B (falling back to leaf 1
/// EBX[23:16]) to report the online logical-processor count. Single-CPU QEMU
/// bring-up reports 1; the struct is `Default`-able (single-CPU fallback) so
/// existing construction sites keep working.
pub struct CpuTopologyX86_64 {
    ncpus: u32,
}

impl Default for CpuTopologyX86_64 {
    fn default() -> Self {
        Self { ncpus: 1 }
    }
}

impl CpuTopologyX86_64 {
    /// Probe the boot CPU's topology via CPUID leaf 0x0B sub-leaves 0..=2
    /// (bounded so an unsupported leaf can't loop), then fall back to leaf 1
    /// EBX[23:16] ("logical processors per package"), then to 1.
    pub fn probe() -> Self {
        let mut entries: [CpuidTopologyEntry; 3] = [
            CpuidTopologyEntry::default(),
            CpuidTopologyEntry::default(),
            CpuidTopologyEntry::default(),
        ];
        let mut count = 0;
        for subleaf in 0..3u32 {
            let (eax, ebx, ecx, _edx) = cpuid(CPUID_LEAF_TOPOLOGY, subleaf);
            if eax == 0 {
                break; // invalid sub-leaf: end of enumeration
            }
            entries[count] = CpuidTopologyEntry {
                logical_processors: eax,
                x2apic_id: ebx,
                level_type: ecx,
            };
            count += 1;
        }
        let mut ncpus = if count > 0 {
            cpuid_topology_ncpus(&entries[..count])
        } else {
            1
        };
        if ncpus == 1 {
            // Leaf 0xB unavailable or reported a single domain: try leaf 1.
            let (_eax, ebx, _ecx, _edx) = cpuid(CPUID_LEAF_1, 0);
            let leaf1 = cpuid_leaf1_logical_processors(ebx);
            if leaf1 != 0 {
                ncpus = leaf1;
            }
        }
        Self { ncpus }
    }
}

impl CpuTopology for CpuTopologyX86_64 {
    fn ncpus(&self) -> u32 {
        self.ncpus
    }
    fn cpu_info(&self, id: u32) -> Option<hal::CpuInfo> {
        if id >= self.ncpus {
            return None;
        }
        Some(hal::CpuInfo {
            id,
            r#type: hal::CpuType::Performance,
            numa_node: 0,
            cache_kib: 0,
        })
    }
    fn bsp_id(&self) -> u32 {
        0
    }
}

/// x86_64 SMP stub: LAPIC IPI + secondary boot not yet wired.
pub struct SmpX86_64;

impl Default for SmpX86_64 {
    fn default() -> Self {
        Self
    }
}

impl Ipi for SmpX86_64 {
    unsafe fn send_ipi(&mut self, _target_cpu: u32) {
        // SAFETY: No-op stub; LAPIC IPI programming lands with SMP bring-up.
    }
    unsafe fn send_ipi_all_but_self(&mut self) {
        // SAFETY: No-op stub.
    }
}

impl SecondaryBoot for SmpX86_64 {
    unsafe fn park_cpu(&mut self, _id: u32) {
        // SAFETY: No-op stub.
    }
    unsafe fn start_cpu(&mut self, _id: u32, _entry: usize, _stack_top: usize) {
        // SAFETY: No-op stub; AP bring-up lands with SMP bring-up.
    }
}

impl Halt for SmpX86_64 {
    unsafe fn halt(&mut self) {
        // SAFETY: `hlt` is safe when interrupts may be pending.
        unsafe {
            core::arch::asm!("hlt", options(nostack));
        }
    }
}

// ===========================================================================
// ADR-015: Boot protocol — x86_64 stubs (UEFI/ACPI wired when bootloader lands)
// ===========================================================================

pub struct BootInfoX86_64;

impl Default for BootInfoX86_64 {
    fn default() -> Self {
        Self
    }
}

impl BootInfo for BootInfoX86_64 {
    fn firmware_type(&self) -> &'static str {
        "stub"
    }
    fn mem_regions(&self) -> &[hal::MemRegion] {
        &[]
    }
    fn framebuffer_info(&self) -> Option<hal::FramebufferInfo> {
        None
    }
    fn cmdline(&self) -> &str {
        ""
    }
}

pub struct AcpiParserX86_64;

impl Default for AcpiParserX86_64 {
    fn default() -> Self {
        Self
    }
}

impl AcpiParser for AcpiParserX86_64 {
    unsafe fn find_rsdp(&self) -> Option<u64> {
        // SAFETY: No-op stub; RSDP scan lands with ACPI bring-up.
        None
    }
    unsafe fn parse_madt(&self, _rsdp: u64, _out: &mut [hal::CpuInfo]) -> usize {
        // SAFETY: No-op stub.
        0
    }
    unsafe fn parse_mcfg(&self, _rsdp: u64) -> Option<u64> {
        // SAFETY: No-op stub.
        None
    }
}

pub struct DeviceTreeX86_64;

impl Default for DeviceTreeX86_64 {
    fn default() -> Self {
        Self
    }
}

impl DeviceTree for DeviceTreeX86_64 {
    unsafe fn find_compatible(&self, _dtb: u64, _compatible: &str) -> Option<u64> {
        // SAFETY: No-op stub.
        None
    }
    unsafe fn read_reg(&self, _node: u64, _out: &mut [(u64, u64)]) -> usize {
        // SAFETY: No-op stub.
        0
    }
    unsafe fn read_interrupts(&self, _node: u64, _out: &mut [u32]) -> usize {
        // SAFETY: No-op stub.
        0
    }
}

// ===========================================================================
// ADR-016: Driver / HAL bus interfaces — x86_64 stubs (PCI/virtio/DMA wired
// when drivers land in Phase 2)
// ===========================================================================

pub struct PciBusX86_64;

impl Default for PciBusX86_64 {
    fn default() -> Self {
        Self
    }
}

impl PciBus for PciBusX86_64 {
    fn enumerate(&mut self, out: &mut [(u8, u8, u8)]) -> usize {
        // x86_64 bring-up targets a single PCI bus (bus 0). Scan every device
        // / function and record the ones that respond with a valid vendor ID.
        let mut count = 0;
        for dev in 0..32u8 {
            if !pci_function_present(0, dev, 0) {
                continue;
            }
            if count < out.len() {
                out[count] = (0, dev, 0);
                count += 1;
            }
            // Multi-function device? Bit 7 of the header-type byte (config reg
            // 0x0C, byte 3) indicates additional functions on this device.
            // SAFETY: PCI config space reads are safe.
            let header = unsafe { self.config_read32(0, dev, 0, 0x0C) };
            let multi_fn = (header >> 16) & 0x80 != 0;
            if multi_fn {
                for fn_ in 1..8u8 {
                    if pci_function_present(0, dev, fn_) && count < out.len() {
                        out[count] = (0, dev, fn_);
                        count += 1;
                    }
                }
            }
        }
        count
    }

    unsafe fn config_read32(&mut self, bus: u8, dev: u8, fn_: u8, offset: u8) -> u32 {
        // SAFETY: PCI config address/data ports are safe to program.
        unsafe {
            port_outl(PCI_CONFIG_ADDR, pci_config_addr(bus, dev, fn_, offset));
            port_inl(PCI_CONFIG_DATA)
        }
    }

    unsafe fn config_write32(&mut self, bus: u8, dev: u8, fn_: u8, offset: u8, value: u32) {
        // SAFETY: PCI config address/data ports are safe to program.
        unsafe {
            port_outl(PCI_CONFIG_ADDR, pci_config_addr(bus, dev, fn_, offset));
            port_outl(PCI_CONFIG_DATA, value);
        }
    }

    unsafe fn set_bus_master(&mut self, bus: u8, dev: u8, fn_: u8, enable: bool) {
        // Command register is at offset 0x04; bus-master enable is bit 2.
        // SAFETY: PCI config space reads/writes are safe.
        let cmd = unsafe { self.config_read32(bus, dev, fn_, 0x04) };
        let mask: u32 = 1 << 2;
        let cmd = if enable { cmd | mask } else { cmd & !mask };
        unsafe { self.config_write32(bus, dev, fn_, 0x04, cmd) };
    }

    unsafe fn bar_info(&mut self, bus: u8, dev: u8, fn_: u8, bar: u8) -> Option<(u64, u64)> {
        if bar >= 6 {
            return None;
        }
        let offset = 0x10 + bar * 4;
        // SAFETY: PCI config space reads/writes are safe.
        let base = unsafe { self.config_read32(bus, dev, fn_, offset) };
        if base == 0 || base == 0xFFFF_FFFF {
            return None;
        }
        let is_mmio = (base & 1) == 0;
        let addr_mask = if is_mmio { 0xFFFFFFF0 } else { 0xFFFFFFFC };
        let addr = base & addr_mask;
        // Probe the BAR size: write all 1s, read back the writable mask.
        let orig = base;
        // SAFETY: PCI config space write is safe.
        unsafe { self.config_write32(bus, dev, fn_, offset, 0xFFFF_FFFF) };
        let size_raw = unsafe { self.config_read32(bus, dev, fn_, offset) };
        // Restore the original BAR value.
        // SAFETY: PCI config space write is safe.
        unsafe { self.config_write32(bus, dev, fn_, offset, orig) };
        let size_mask = if is_mmio { 0xFFFFFFF0 } else { 0xFFFFFFFC };
        let size = ((!size_raw) & size_mask).wrapping_add(1);
        if size == 0 {
            return None;
        }
        if is_mmio {
            // 64-bit BAR: the next register holds the high 32 bits of the address.
            // SAFETY: PCI config space read is safe.
            let base_hi = unsafe { self.config_read32(bus, dev, fn_, offset + 4) };
            let pa = (addr as u64) | ((base_hi as u64) << 32);
            Some((pa, size as u64))
        } else {
            Some((addr as u64, size as u64))
        }
    }
}

/// Virtio device over MMIO. Holds the device's mapped MMIO base address so
/// the trait methods (which take no device argument) can address it.
#[derive(Default)]
pub struct VirtioX86_64 {
    mmio_base: usize,
}

impl VirtioX86_64 {
    /// Configure the device's MMIO base address (from a PCI BAR via
    /// `PciBus::bar_info` + `MmioRegion::map_mmio`). Call before any virtio
    /// operation.
    pub fn set_mmio_base(&mut self, base: usize) {
        self.mmio_base = base;
    }

    /// Read a u32 from a virtio MMIO register offset.
    fn mmio_read32(&self, offset: usize) -> u32 {
        // SAFETY: `mmio_base` points at a mapped virtio device MMIO region.
        unsafe { core::ptr::read_volatile((self.mmio_base + offset) as *const u32) }
    }

    /// Write a u32 to a virtio MMIO register offset.
    fn mmio_write32(&self, offset: usize, value: u32) {
        // SAFETY: `mmio_base` points at a mapped writable virtio MMIO region.
        unsafe {
            core::ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
    }
}

/// Virtio MMIO register offsets (legacy 0x10000-byte device layout).
const VIRTIO_MMIO_QUEUE_NOTIFY: usize = 0x4C;
const VIRTIO_MMIO_INTERRUPT_STATUS: usize = 0x50;
const VIRTIO_MMIO_INTERRUPT_ACK: usize = 0x54;

impl Virtio for VirtioX86_64 {
    unsafe fn notify(&mut self, queue_sel: u16) {
        // SAFETY: writing the QueueNotify register kicks the virtio device.
        self.mmio_write32(VIRTIO_MMIO_QUEUE_NOTIFY, queue_sel as u32);
    }
    unsafe fn read_isr(&mut self) -> u8 {
        // SAFETY: reading the InterruptStatus register.
        (self.mmio_read32(VIRTIO_MMIO_INTERRUPT_STATUS) & 0xFF) as u8
    }
    unsafe fn ack_used(&mut self) {
        // SAFETY: writing the InterruptACK register acknowledges used-buffer
        // interrupts.
        self.mmio_write32(VIRTIO_MMIO_INTERRUPT_ACK, 0xFFFF_FFFF);
    }
}

/// DMA-safe, physically contiguous memory allocator.
pub struct DmaX86_64;

impl Default for DmaX86_64 {
    fn default() -> Self {
        Self
    }
}

impl Dma for DmaX86_64 {
    unsafe fn alloc_dma(&mut self, bytes: u64, _align: u64) -> Option<(usize, usize)> {
        // Allocate contiguous frames. Alignment is honored by rounding the
        // byte count up; the frame allocator hands out page-aligned frames.
        let pages = bytes.div_ceil(frame::FRAME_SIZE as u64) as usize;
        let paddr = frame::alloc_contiguous(pages)?;
        // SAFETY: freshly allocated frames, identity-mapped through the
        // shared higher-half window via phys_to_virt.
        let va = kernel::mem::phys_to_virt(paddr.as_u64()) as usize;
        Some((va, paddr.as_u64() as usize))
    }
    unsafe fn free_dma(&mut self, _virt: usize, _phys: usize) {
        // v0: DMA frames are intentionally leaked (no size tracked by the
        // trait). Reclaim lands with a proper DMA pool in Phase 4.
    }
    unsafe fn sync_for_device(&mut self, _virt: usize, _bytes: u64) {
        // x86_64 is cache-coherent; no explicit sync needed.
    }
    unsafe fn sync_for_cpu(&mut self, _virt: usize, _bytes: u64) {
        // x86_64 is cache-coherent; no explicit sync needed.
    }
}

/// Memory-mapped I/O region access. On x86_64 the shared higher-half
/// identity window (ADR-045 slice 2) already maps every physical page below
/// 1 GiB at `0xFFFFFFFF80000000 + PA`, so mapping an MMIO region is just an
/// address translation.
pub struct MmioRegionX86_64;

impl Default for MmioRegionX86_64 {
    fn default() -> Self {
        Self
    }
}

impl MmioRegion for MmioRegionX86_64 {
    unsafe fn map_mmio(&mut self, paddr: u64, _len: u64) -> Option<usize> {
        // SAFETY: `paddr` must describe a valid device MMIO region below
        // 1 GiB (covered by the higher-half identity window).
        Some(kernel::mem::phys_to_virt(paddr) as usize)
    }
    unsafe fn unmap_mmio(&mut self, _virt: usize, _len: u64) {
        // The higher-half identity map is permanent; nothing to unmap.
    }
}

// ---------------------------------------------------------------------------
// GDT
// ---------------------------------------------------------------------------

#[allow(clippy::new_without_default)]
impl Gdt {
    pub const fn new() -> Self {
        Self { entries: [0; 8] }
    }

    /// Build a code / data GDT (kernel + user); TSS descriptor slots 5/6 are
    /// filled by [`install_tss`]. Installs the GDTR.
    pub fn install(&mut self) {
        self.entries[0] = 0x0000000000000000; // null
        self.entries[1] = 0x00AF9A000000FFFF; // kernel code (64-bit), ring 0
        self.entries[2] = 0x00CF92000000FFFF; // kernel data, ring 0
        self.entries[3] = 0x00CFF2000000FFFF; // user data, ring 3 (SS 0x1B)
        self.entries[4] = 0x00AFFA000000FFFF; // user code (64-bit), ring 3 (CS 0x23)
        self.entries[5] = 0x0000000000000000; // TSS low (install_tss)
        self.entries[6] = 0x0000000000000000; // TSS high (install_tss)
        self.entries[7] = 0x0000000000000000; // spare

        // SAFETY: Loading a freshly-constructed GDT into the CPU.
        unsafe { Self::load_gdt(self) };
        // Reload data segment registers. In 64-bit mode only FS/GS can be
        // loaded directly; DS/ES/SS are forced to 0 by the CPU.
        // SAFETY: Reloading segment registers with valid GDT selectors.
        unsafe {
            core::arch::asm!(
                "mov fs, ax",
                "mov gs, ax",
                in("ax") SEL_DATA,
                options(nostack),
            );
        }
        // Note: CS is reloaded via a far jump in `_start` / kernel entry.
    }

    unsafe fn load_gdt(gdt: &Gdt) {
        let ptr = TablePtr {
            limit: (core::mem::size_of_val(&gdt.entries) - 1) as u16,
            base: gdt.entries.as_ptr() as u64,
        };
        // SAFETY: `lgdt` writes the GDTR; `ptr` points to a valid descriptor.
        core::arch::asm!("lgdt [{0}]", in(reg) &ptr, options(nostack, readonly));
    }
}

impl HalGdt for Gdt {
    unsafe fn load(&self) {
        // SAFETY: `load_gdt` only writes the GDTR with a valid descriptor.
        unsafe { Self::load_gdt(self) };
        // SAFETY: Reloading segment registers with valid GDT selectors.
        unsafe {
            core::arch::asm!(
                "mov fs, ax",
                "mov gs, ax",
                in("ax") SEL_DATA,
                options(nostack),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// IDT
// ---------------------------------------------------------------------------

#[allow(clippy::new_without_default)]
impl Idt {
    pub const fn new() -> Self {
        Self { entries: [0; 256] }
    }

    pub fn install(&mut self) {
        // All entries remain zero (invalid); lidt still requires a valid table.
        // SAFETY: Loading a zeroed IDT; no interrupts will be enabled yet.
        unsafe { Self::load_idt(self) };
    }

    /// Install a 64-bit interrupt gate (DPL0) for `vector`.
    pub fn set_gate(&mut self, vector: u8, handler: u64, selector: u16) {
        let lo = (handler & 0xFFFF)
            | ((selector as u64) << 16)
            | (0x8E_u64 << 40)
            | (((handler >> 16) & 0xFFFF) << 48);
        let hi = (handler >> 32) & 0xFFFF_FFFF;
        self.entries[vector as usize * 2] = lo;
        self.entries[vector as usize * 2 + 1] = hi;
    }

    unsafe fn load_idt(idt: &Idt) {
        let ptr = TablePtr {
            limit: (core::mem::size_of_val(&idt.entries) - 1) as u16,
            base: idt.entries.as_ptr() as u64,
        };
        // SAFETY: `lidt` writes the IDTR; `ptr` points to a valid descriptor.
        core::arch::asm!("lidt [{0}]", in(reg) &ptr, options(nostack, readonly));
    }
}

impl HalIdt for Idt {
    unsafe fn load(&self) {
        // SAFETY: `load_idt` only writes the IDTR with a valid descriptor.
        unsafe { Self::load_idt(self) };
    }
}

// ---------------------------------------------------------------------------
// Framebuffer stub
// ---------------------------------------------------------------------------

impl Framebuffer for StubFramebuffer {
    unsafe fn init(&mut self) {
        // Stub: no real video mode detection yet. drivers/graphics will own
        // real framebuffer setup.
    }

    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    fn stride(&self) -> usize {
        self.stride
    }

    unsafe fn buffer(&mut self) -> &mut [u8] {
        // SAFETY: The stub framebuffer has no real video memory; returns an
        // empty slice so callers can't write to nowhere.
        &mut []
    }
}

// ---------------------------------------------------------------------------
// Early boot
// ---------------------------------------------------------------------------

impl EarlyBoot for X86_64EarlyBoot {
    fn stack_top() -> usize {
        // The initial boot stack is provided by the linker / bootloader.
        // Placeholder: a fixed address above the kernel load region.
        0x1000_0000
    }

    unsafe fn early_init() {
        // SAFETY: Early boot runs single-threaded before the kernel exists.
        let mut uart = Com1Uart;
        Uart::init(&mut uart);

        // Remap + mask the PIC before any IDT work (ADR-005: IRQs masked until
        // the kernel registers handlers and explicitly unmasks).
        pic_remap();
        let mut pic = Pic::new();
        for irq in 0..16u8 {
            Irq::mask(&mut pic, irq);
        }

        // GDT/IDT must live for the whole kernel lifetime: static storage, not
        // stack locals (a stack-local GDTR base gets clobbered by later stack
        // use — found via the first ring-3 entry #GP).
        {
            // SAFETY: single-threaded boot; exclusive boot-time access.
            let gdt = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_GDT) };
            Gdt::install(gdt);
            // SAFETY: as above.
            let idt = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_IDT) };
            Idt::install(idt);
        }

        let _timer = TimerSrc::new(); // PIT oneshot/TSC timebase ready.
        let _fb = StubFramebuffer::default();
        // Framebuffer init is a stub for now.
    }
}

/// Early console writer: `fn(&str)` shim over the COM1 UART, passed to
/// [`kernel::boot::early_init`] (ADR-001).
pub fn uart_writer(s: &str) {
    let mut uart = Com1Uart;
    for &byte in s.as_bytes() {
        // SAFETY: `write_byte` only touches the COM1 UART port.
        unsafe {
            uart.write_byte(byte);
        }
    }
}

/// QEMU exit hook: terminate QEMU via the isa-debug-exit port, then spin.
/// Registered with the kernel via [`kernel::boot::early_init`] (ADR-001).
pub fn qemu_exit() -> ! {
    qemu_exit_code(QEMU_EXIT_SUCCESS as u32)
}

/// Code-parameterized QEMU exit (ADR-028 `set_exit_code` hook). QEMU's
/// `isa-debug-exit` reports process exit status `(value << 1) | 1`; the
/// harness maps that back (ADR-013, see `tools/qemu-test.sh`).
pub fn qemu_exit_code(value: u32) -> ! {
    // SAFETY: `isa-debug-exit` is a QEMU-specific x86_64 port; safe to invoke
    // during bring-up to report kernel status to the test harness.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") QEMU_EXIT_PORT,
            in("al") value as u8,
            options(nostack),
        );
    }
    loop {
        core::hint::spin_loop();
    }
}

// ===========================================================================
// ADR-010: ContextBackend — x86_64 register save/restore + stack switch
// ===========================================================================

/// x86_64 context switch backend (stub for v0 bring-up).
///
/// v0 is single-CPU; the real register save/restore implementation lands
/// with SMP (Phase 5). For bring-up, `switch()` is a no-op (the same thread
/// stays on the same CPU) and `start_first()` sets up the initial stack.
pub struct ContextBackendX86_64;

impl Default for ContextBackendX86_64 {
    fn default() -> Self {
        Self
    }
}

/// BootInfo VA handed to the first userspace entry in `rdi` (set by the boot
/// crate before `start_first`).
pub static BOOTINFO_VA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Kernel-lifetime GDT/IDT storage (loaded once at `early_init`).
static mut BOOT_GDT: Gdt = Gdt::new();
static mut BOOT_IDT: Idt = Idt::new();

/// Install exception/interrupt stub gates (vectors 0..=47) into the boot IDT
/// and reload it. Bring-up safety net: a fault reports (vector/error/CR2/RIP)
/// and halts instead of triple-faulting silently.
///
/// # Safety
/// Boot-time only; must run after `X86_64EarlyBoot::early_init`.
pub unsafe fn install_exception_stubs() {
    // SAFETY: boot-time exclusive access to the static IDT.
    let idt = unsafe { &mut *core::ptr::addr_of_mut!(BOOT_IDT) };
    for vector in 0..48u8 {
        // Vectors 32..47 are IRQ gates (iretq-capable); 0..31 stay fatal.
        let addr = if (32..48).contains(&vector) {
            crate::exceptions::irq_stub_addr(vector)
        } else {
            crate::exceptions::stub_addr(vector)
        };
        if let Some(addr) = addr {
            idt.set_gate(vector, addr, SEL_CODE);
        }
    }
    // SAFETY: reloading the IDTR with the table we just populated.
    unsafe { Idt::load_idt(idt) };
}

/// 64-bit Task State Segment (only `rsp0` is meaningful in v0: the ring-0
/// stack used when an interrupt/exception is delivered from ring 3).
#[repr(C, packed)]
pub struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

/// Ring-0 stack used for exception delivery from userspace.
#[repr(C, align(16))]
struct ExcStack([u8; 16384]);

static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved1: 0,
    ist: [0; 7],
    reserved2: 0,
    reserved3: 0,
    iomap_base: 0xFFFF,
};

static mut EXC_STACK: ExcStack = ExcStack([0; 16384]);

/// Install the TSS (GDT slots 5/6, selector 0x28) and load TR. Without it,
/// any exception already in ring 3 cannot switch stacks and turns into a
/// triple fault — hiding the real fault.
///
/// # Safety
/// Boot-time only; GDT must be installed first.
pub unsafe fn install_tss() {
    // SAFETY: boot-time exclusive access to the statics.
    unsafe {
        let tss = &mut *core::ptr::addr_of_mut!(TSS);
        let stack_top = core::ptr::addr_of!(EXC_STACK).add(1) as u64;
        tss.rsp0 = stack_top;

        let base = tss as *const Tss as u64;
        let limit: u64 = core::mem::size_of::<Tss>() as u64 - 1;
        let gdt = &mut *core::ptr::addr_of_mut!(BOOT_GDT);
        gdt.entries[5] = (limit & 0xFFFF)
            | ((base & 0xFF_FFFF) << 16)
            | (0x89_u64 << 40)          // available 64-bit TSS
            | (((limit >> 16) & 0xF) << 48)
            | (((base >> 24) & 0xFF) << 56);
        gdt.entries[6] = (base >> 32) & 0xFFFF_FFFF;

        // Load TR with selector 0x28.
        core::arch::asm!("ltr ax", in("ax") 0x28u16, options(nostack));
    }
}

/// Kernel stack top of the currently running thread (updated by `switch` and
/// at boot). The syscall entry stacks onto this address.
#[no_mangle]
pub static CURRENT_KSTACK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// ADR-044/046: the CPU's currently-loaded FS base (a mirror; the MSR is
/// written only on change). IA32_FS_BASE = 0xC0000100.
pub static CURRENT_FS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Write IA32_FS_BASE (musl TLS via Thread::SET_TLS).
pub fn write_fs_base(va: u64) {
    // S3b: reject a non-canonical or kernel-range FS base before touching the
    // MSR — a bad base faults in ring 0 at the next switch.
    if !fs_base_is_canonical_user(va) {
        panic!(
            "write_fs_base: non-canonical/user FS base {:#x} (must be < {:#x})",
            va, FS_BASE_USER_CEIL
        );
    }
    // SAFETY: `wrmsr` writes the FS-base MSR; single-CPU v0, kernel context;
    // `va` is a canonical user base (checked above).
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0100u32,
            in("eax") va as u32,
            in("edx") (va >> 32) as u32,
            options(nostack)
        );
    }
}

/// CR4 bit: Supervisor-Mode Execution Prevention (SMEP). Blocks supervisor
/// execution of user-mode pages. CR4 bit 20.
const CR4_SMEP: u64 = 1 << 20;
/// CR4 bit: Supervisor-Mode Access Prevention (SMAP). Blocks supervisor
/// data access to user-mode pages unless bracketed by STAC/CLAC. CR4 bit 21.
///
/// SMAP is CPUID-checked here but deliberately NOT enabled yet: the kernel has
/// no user-copy helper (STAC/CLAC wrappers around user-memory access), so
/// setting CR4.SMAP would fault on any existing kernel dereference of user
/// pointers. Enablement waits for that helper — see ADR-051.
#[allow(dead_code)] // SMAP enablement awaits the user-copy helper (ADR-051).
const CR4_SMAP: u64 = 1 << 21;
/// CR4 bit: User-Mode Instruction Prevention (UMIP). Blocks SGDT/SIDT/SLDT/
/// SMSW/STR in user mode. CR4 bit 11.
const CR4_UMIP: u64 = 1 << 11;

/// Read the current CR4 register.
fn cr4_read() -> u64 {
    let v: u64;
    // SAFETY: reading CR4 is architecturally safe; no memory side effects.
    unsafe { core::arch::asm!("mov {0}, cr4", out(reg) v, options(nostack)) };
    v
}

/// Write CR4 with `value`.
///
/// # Safety
/// Writes architectural CPU state; call once at boot with only SMEP/SMAP/UMIP
/// bits OR'd into the existing value.
unsafe fn cr4_write(value: u64) {
    // SAFETY: caller guarantees only SMEP/SMAP/UMIP bits are set; single-CPU
    // boot, no concurrent CR4 users.
    core::arch::asm!("mov cr4, {0}", in(reg) value, options(nostack));
}

/// CPUID leaf 7, sub-leaf 0: return (EBX, ECX) feature bits.
///
/// EBX holds SMEP (bit 7) and SMAP (bit 20); ECX holds UMIP (bit 2).
/// `cpuid` clobbers EBX, which LLVM treats as callee-saved and cannot name as
/// an operand, so RBX is saved before the instruction and restored after;
/// EBX's output is read back into a general register between the two.
#[inline(never)]
fn cpuid_leaf7() -> (u32, u32) {
    let mut subleaf: u32 = crate::host::CPUID_SUB_LEAF_0; // in: 0, out: ECX
    let mut ebx: u64 = 0;
    let rbx_save: u64;
    // SAFETY: `cpuid` leaf 7 sub-leaf 0 is always valid on x86_64.
    unsafe {
        core::arch::asm!("mov {0}, rbx", out(reg) rbx_save, options(nostack));
        core::arch::asm!("cpuid",
            in("eax") crate::host::CPUID_LEAF_FEATURES,
            inout("ecx") subleaf,
            options(nostack));
        core::arch::asm!("mov {0}, rbx", out(reg) ebx, options(nostack));
        core::arch::asm!("mov rbx, {0}", in(reg) rbx_save, options(nostack));
    }
    (ebx as u32, subleaf)
}

/// Read CPUID `(leaf, subleaf)` into `(eax, ebx, ecx, edx)`. `cpuid` clobbers
/// RBX (callee-saved in the SysV ABI), so RBX is saved/restored around it and
/// the EBX output is read back into a general register.
///
/// # Safety
///
/// `cpuid` is architecturally safe on x86_64; no memory side effects.
#[inline(never)]
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let mut eax: u32 = leaf;
    let mut ebx: u32 = 0;
    let mut ecx: u32 = subleaf;
    let mut edx: u32 = 0;
    let rbx_save: u64;
    // SAFETY: `cpuid` is always valid on x86_64; RBX is preserved for LLVM.
    unsafe {
        core::arch::asm!("mov {0}, rbx", out(reg) rbx_save, options(nostack));
        core::arch::asm!("cpuid",
            inout("eax") eax,
            inout("ecx") ecx,
            out("edx") edx,
            options(nostack));
        core::arch::asm!("mov {0:e}, rbx", out(reg) ebx, options(nostack));
        core::arch::asm!("mov rbx, {0}", in(reg) rbx_save, options(nostack));
    }
    (eax, ebx, ecx, edx)
}

/// Enable supervisor-mode protections (SMEP + UMIP now; SMAP once a user-copy
/// helper exists — ADR-051). Each bit is set only if CPUID leaf 7 sub-leaf 0
/// advertises the feature (SMEP/SMAP via EBX, UMIP via ECX), so the function
/// is safe on CPUs that lack any of them. Returns the mask of features
/// actually enabled.
///
/// # Safety
/// Writes CR4 (architectural state); call once at boot, after paging is on.
pub unsafe fn enable_supervisor_protections() -> u64 {
    let (ebx, ecx) = cpuid_leaf7();
    let mut mask: u64 = 0;
    if crate::host::cpuid_ebx_has(ebx, crate::host::CPUID_EBX_SMEP) {
        mask |= CR4_SMEP;
    }
    if crate::host::cpuid_ecx_has(ecx, crate::host::CPUID_ECX_UMIP) {
        mask |= CR4_UMIP;
    }
    // SMAP: CPUID-checked (EBX[20]) and ready, but not set until a user-copy
    // helper (STAC/CLAC around user-memory access) exists — ADR-051.
    if mask == 0 {
        return 0;
    }
    let cr4 = cr4_read();
    // SAFETY: only SMEP/UMIP bits (verified CPUID-supported) are OR'd in.
    cr4_write(cr4 | mask);
    mask
}

/// Set the running thread's kernel stack top (boot: the initial boot stack).
pub fn set_kstack(top: u64) {
    CURRENT_KSTACK.store(top, core::sync::atomic::Ordering::Relaxed);
}

fn switch_fatal(msg: &str) -> ! {
    crate::uart_writer(msg);
    loop {
        // SAFETY: halting after a fatal context-switch condition.
        unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)) };
    }
}

impl sched::ContextBackend for ContextBackendX86_64 {
    fn switch(&self, from: sched::ThreadId, to: sched::ThreadId) {
        let Some(from_slot) = kernel::sched::ksp_slot_ptr(from) else {
            switch_fatal("\n[kernel] switch: no saved-state slot for caller\n");
        };
        let to_ksp = kernel::sched::ksp_of(to);
        let to_top = kernel::sched::kstack_top_of(to);
        if to_ksp == 0 || to_top == 0 {
            switch_fatal("\n[kernel] switch: target thread has no kernel context\n");
        }
        // ADR-045 slice 2b: kstack_top/ksp are PHYSICAL; the syscall entry
        // stacks through the shared higher-half window.
        set_kstack(kernel::mem::phys_to_virt(to_top));
        // ADR-044/046 (Thread::SET_TLS): load the target's FS base when it
        // differs from the CPU's current value (single-CPU v0: the mirror is
        // authoritative; the MSR write takes effect for the resumed thread).
        let to_fs = kernel::sched::fs_base_of(to);
        if to_fs != CURRENT_FS.load(core::sync::atomic::Ordering::Relaxed) {
            write_fs_base(to_fs);
            CURRENT_FS.store(to_fs, core::sync::atomic::Ordering::Relaxed);
        }
        // SAFETY: pure-asm cooperative switch (syscall_entry.S). `from_slot`
        // belongs to the running thread (only writer); `to_ksp` is either a
        // context saved by a previous switch (resuming mid-dispatch) or a
        // fresh frame built by `init_context` (starting at the trampoline).
        // Control returns here when this thread is scheduled again.
        unsafe {
            crate::syscall_entry::switch_to_context(from_slot, to_ksp);
        }
    }

    fn activate_aspace(&self, as_id: u64) {
        if !crate::paging::activate_as(as_id) {
            switch_fatal("\n[kernel] switch: target AS has no paging root\n");
        }
    }

    fn init_context(&self, kstack_top: u64, entry_pc: u64) -> u64 {
        // Fresh-thread kernel stack layout (top-down):
        //   [top-8] arg (rdi) | [top-16] user RSP | [top-24] entry |
        //   [top-32] trampoline | [top-40..top-80] rbx,rbp,r12..r15
        // `switch` pops the six callee-saved regs and `ret`s into the
        // trampoline, which iretqs to ring 3.
        let top = kernel::mem::phys_to_virt(kstack_top) as *mut u64;
        // SAFETY: `kstack_top` is the top of a freshly allocated kernel stack
        // (reached through the shared higher-half window, ADR-045 slice 2);
        // the writes stay within that stack.
        unsafe {
            *top.sub(1) = 0; // arg: v0 children take none
            *top.sub(2) = crate::layout::USER_STACK_TOP as u64;
            *top.sub(3) = entry_pc;
            *top.sub(4) = crate::syscall_entry::thread_trampoline_addr();
            for i in 5..=10 {
                *top.sub(i) = 0;
            }
        }
        // ADR-045 slice 2b: the saved ksp must be the HIGH alias — `switch`
        // loads it into RSP, and the low identity window is retired.
        kernel::mem::phys_to_virt(kstack_top) - 10 * 8
    }

    fn start_first(&self, to: sched::ThreadId) {
        let pc = match kernel::sched::get(to) {
            Ok(t) => t.initial_pc,
            Err(_) => 0,
        };
        if pc == 0 {
            crate::uart_writer("start_first: thread has no entry PC (staging missing)\n");
            loop {
                core::hint::spin_loop();
            }
        }
        // The first user thread's syscalls must stack on ITS kernel stack, not
        // the boot stack: `start_first` bypasses `switch` (which is the only
        // place that arms `CURRENT_KSTACK`), and dispatching on the boot stack
        // leaked kernel frames into the wrong place (KSTACK GUARD, "live-local
        // clobbering" family).
        let top = kernel::sched::kstack_top_of(to);
        if top != 0 {
            // ADR-045 slice 2b: `kstack_top` is stored as a PHYSICAL address;
            // the syscall entry stacks through the shared higher-half window
            // (the per-AS PML4[0] identity window is retired).
            set_kstack(kernel::mem::phys_to_virt(top));
        }
        let bootinfo = BOOTINFO_VA.load(core::sync::atomic::Ordering::Relaxed);
        // SAFETY: ring-3 segments exist in the installed GDT (`Gdt::install`)
        // and the page tables already contain the user mappings staged by the
        // boot crate; boot is single-threaded at this point.
        unsafe { enter_user(pc, bootinfo) }
    }
}

/// `iretq` to ring 3: RIP=`entry`, RSP=`USER_STACK_TOP`, `rdi`=`bootinfo`.
///
/// # Safety
/// Call once, after: GDT installed with ring-3 segments, user pages mapped,
/// syscall MSRs configured (if userspace will issue syscalls).
unsafe fn enter_user(entry: u64, bootinfo: u64) -> ! {
    let stack = crate::layout::USER_STACK_TOP as u64;
    // SAFETY: pushes the iretq frame (SS,RSP,RFLAGS,CS,RIP) on the current
    // kernel stack and transfers control to ring 3; never returns.
    //
    // `bootinfo` is bound with `in("rdi")` (the SysV `_start` argument
    // register) instead of a free `in(reg)` + `mov rdi`: a free operand can
    // be ALLOCATED to RDI, and the explicit `mov rdi, {bi}` then clobbers it
    // (undeclared to the compiler) — found in the dev profile, where the
    // allocator picked RDI for the entry operand and iretq jumped to the
    // bootinfo address instead of the entry PC.
    unsafe {
        core::arch::asm!(
            "push 0x1B",        // SS: user data
            "push {sp}",        // RSP
            "push 0x202",       // RFLAGS: IF | reserved
            "push 0x23",        // CS: user code
            "push {ip}",        // RIP
            "iretq",
            sp = in(reg) stack,
            ip = in(reg) entry,
            in("rdi") bootinfo,
            options(noreturn)
        );
    }
}

pub static CONTEXT_BACKEND_X86_64: ContextBackendX86_64 = ContextBackendX86_64;

// ===========================================================================
// IRQ dispatch (v0 console input): global PIC state + the IRQ gate path.
// ===========================================================================

static IRQ_PIC: spin::Mutex<Pic> = spin::Mutex::new(Pic::new());
static UART_RX_CB: spin::Mutex<Option<fn(u8)>> = spin::Mutex::new(None);

/// Register the UART RX byte sink (kernel console_in line discipline).
pub fn set_uart_rx_callback(f: fn(u8)) {
    *UART_RX_CB.lock() = Some(f);
}

/// Enable COM1 RX interrupts (IER bit 0) + route IRQ4 through the PIC.
pub fn enable_uart_rx() {
    let mut pic = IRQ_PIC.lock();
    // SAFETY: single-threaded boot registration; raw I/O to COM1/IRQ4.
    unsafe {
        Irq::register_handler(&mut *pic, 4, uart_irq4);
        Irq::unmask(&mut *pic, 4);
        let ier = port_inb(COM1 + REG_IER);
        port_outb(COM1 + REG_IER, ier | 0x01);
    }
}

/// Enable the PIT timer tick (ADR-042): register the IRQ0 handler, unmask it,
/// and arm the initial 10 ms oneshot. Mirrors `enable_uart_rx`.
pub fn enable_timer_tick() {
    let mut pic = IRQ_PIC.lock();
    // SAFETY: single-threaded boot registration; raw I/O to PIC/PIT ch0.
    unsafe {
        Irq::register_handler(&mut *pic, 0, timer_irq0);
        Irq::unmask(&mut *pic, 0);
        // Initial arm: 10 ms oneshot (PIT ch0, mode 0, binary).
        let ticks = 10_000_000 * PIT_BASE_HZ / 1_000_000_000;
        let ticks = ticks.clamp(1, 0xFFFF);
        port_outb(PIT_MODE, 0x30); // ch0, lobyte/hibyte, mode 0, binary
        port_outb(PIT_CH0, (ticks & 0xFF) as u8);
        port_outb(PIT_CH0, ((ticks >> 8) & 0xFF) as u8);
    }
}

/// COM1 RX interrupt (IRQ4): drain every available byte into the sink.
fn uart_irq4(_irq: u8) -> bool {
    // SAFETY: COM1 LSR/RBR raw I/O; the interrupt means data is ready.
    unsafe {
        while port_inb(COM1 + 5) & 0x01 != 0 {
            let b = port_inb(COM1);
            if let Some(f) = UART_RX_CB.lock().as_ref() {
                f(b);
            }
        }
    }
    false // v0: no reschedule-on-IRQ (cooperative scheduler)
}

/// PIT channel 0 / IRQ0 timer tick (ADR-042): lock-free mark + deferred drain.
/// Sets `kernel::time::TICK_PENDING` and re-arms the 10 ms oneshot. No locks
/// are taken (the interrupted syscall context may hold scheduler locks on this
/// CPU — the ADR-038 deferred-wake pattern; `drain_tick` runs in dispatch).
fn timer_irq0(_irq: u8) -> bool {
    // SAFETY: PIT ch0 raw I/O; IRQ-context safe (mark only + port writes).
    unsafe {
        kernel::time::tick_pending();
        // Re-arm PIT channel 0 oneshot for the next 10 ms tick.
        let ticks = 10_000_000 * PIT_BASE_HZ / 1_000_000_000;
        let ticks = ticks.clamp(1, 0xFFFF);
        port_outb(PIT_MODE, 0x30); // ch0, lobyte/hibyte, mode 0, binary
        port_outb(PIT_CH0, (ticks & 0xFF) as u8);
        port_outb(PIT_CH0, ((ticks >> 8) & 0xFF) as u8);
    }
    false // v0: no reschedule-on-IRQ (cooperative scheduler)
}

/// IRQ gate dispatcher (called from the irq_stub_N asm for vectors 32..47):
/// runs the registered handler, then EOI on the owning PIC bank.
#[no_mangle]
pub extern "sysv64" fn hal_irq_dispatcher(vector: u64) {
    let irq = (vector - PIC_VECTOR_BASE as u64) as u8;
    let pic = IRQ_PIC.lock();
    let handler = pic.handlers[irq as usize];
    if let Some(f) = handler {
        f(irq);
    }
    // SAFETY: PIC EOI raw I/O; the dispatcher runs with the PIC lock held.
    unsafe {
        if irq >= 8 {
            port_outb(PIC_SLAVE_CMD, 0x20);
        }
        port_outb(PIC_MASTER_CMD, 0x20);
    }
}

// ===========================================================================
// ADR-010/011: CurrentContext — pid/tid of the interrupted context
// ===========================================================================

/// x86_64 current context provider (stub for v0 bring-up).
///
/// v0 runs a single process; returns a fixed pid/tid. Multi-process support
/// arrives with the arch trap entry that records the interrupted thread.
pub struct CurrentContextX86_64;

impl Default for CurrentContextX86_64 {
    fn default() -> Self {
        Self
    }
}

impl entry::CurrentContext for CurrentContextX86_64 {
    /// Owning process of the scheduled thread (multi-process correctness:
    /// a child's syscalls must act on the child's capability table).
    fn pid(&self) -> kernel::proc::ProcessId {
        let tid = sched::current();
        kernel::sched::get(tid)
            .ok()
            .map(|t| ObjId(t.process.0))
            .unwrap_or(ObjId(1))
    }

    fn tid(&self) -> sched::ThreadId {
        sched::current()
    }
}

pub static CURRENT_CONTEXT_X86_64: CurrentContextX86_64 = CurrentContextX86_64;

// ===========================================================================
// Early boot entry point
// ===========================================================================

/// Arch boot entry: called by `kernel/src/main.rs::_start`.
///
/// Per ADR-001, arch boot code must call [`kernel::boot::early_init`] as its
/// first action, passing its own UART writer (`fn(&str)`) and panic-exit hook,
/// before using any other kernel API. The HAL performs low-level init (UART,
/// GDT, IDT) then hands over to the kernel via `kernel::init::start()`.
///
/// # Safety
///
/// Called by `kernel/src/main.rs::_start` before any Rust runtime exists.
pub unsafe fn arch_boot() -> ! {
    // SAFETY: Early boot runs single-threaded before the kernel exists.
    unsafe {
        // 1. HAL low-level init: UART 16550, GDT, IDT.
        X86_64EarlyBoot::early_init();

        // 2. Enable NXE (required for PTE_NX bit).
        enable_nx();

        // 3. Register the paging backend factory (ADR-022).
        aspace::set_backend_factory(&BackendFactoryX86_64);

        // 4. Register the context backend (ADR-010).
        sched::set_context_backend(&CONTEXT_BACKEND_X86_64);

        // 5. Register the current context provider (ADR-010/011).
        entry::set_current_context(&CURRENT_CONTEXT_X86_64);

        // 6. Register the kernel early console + panic-exit hook (ADR-001).
        kernel::boot::early_init(uart_writer, Level::Info, qemu_exit);

        // 7. Create init process, grant Factory + Region caps, spawn init thread.
        //    Hardcoded memory region for v0 bring-up: 16 MiB–256 MiB.
        const MEMORY_BASE: u64 = 0x1000_0000;
        const MEMORY_LEN: u64 = 0x0F00_0000;
        let regions = [kernel::init::BootRegion {
            base: kernel::frame::PhysAddr::new(MEMORY_BASE),
            len: MEMORY_LEN,
        }];
        kernel::init::start(&regions).expect("kernel::init::start failed");
    }

    // Enter the init thread via the context backend. Never returns.
    sched::start_first(sched::ThreadId(1));

    // Should never reach here: start_first switches to init and never comes back.
    loop {
        core::hint::spin_loop();
    }
}

// S3b host unit tests: the canonical-user FS-base check. `write_fs_base`
// panics on a bad base before reaching `wrmsr`, so `catch_unwind` runs it
// safely on the host (dev profile unwinds; the privileged instruction is
// never executed for a rejected base).
#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_base_is_canonical_user_bounds() {
        // Canonical user addresses (lower half) are accepted.
        assert!(fs_base_is_canonical_user(0));
        assert!(fs_base_is_canonical_user(0x7FFF_FFFF_FFFF));
        assert!(fs_base_is_canonical_user(0x0000_7FFF_FFFF_FFFF));
        // Just above the ceiling is not a canonical user address.
        assert!(!fs_base_is_canonical_user(FS_BASE_USER_CEIL));
        assert!(!fs_base_is_canonical_user(FS_BASE_USER_CEIL + 1));
        // Kernel range is not a valid user FS base.
        assert!(!fs_base_is_canonical_user(0xFFFF_8000_0000_0000));
        // Non-canonical high half is rejected.
        assert!(!fs_base_is_canonical_user(0xFFFF_7FFF_FFFF_FFFF));
    }

    #[test]
    fn write_fs_base_rejects_non_canonical_base() {
        // A kernel-range base must panic before `wrmsr` (which would fault in
        // ring 0). On host this unwinds cleanly instead of executing the
        // privileged instruction.
        let result = std::panic::catch_unwind(|| {
            write_fs_base(0xFFFF_8000_0000_0000);
        });
        assert!(
            result.is_err(),
            "expected write_fs_base to panic on a kernel-range FS base"
        );
    }
}
