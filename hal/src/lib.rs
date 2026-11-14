//! Hardware Abstraction Layer traits. Implementation crates per-arch.
//!
//! The kernel never touches registers directly; all platform-specific
//! hardware access goes through these traits. Each arch crate (`hal-x86-64`,
//! `hal-aarch64`, `hal-riscv64`) provides one concrete type per trait.
//!
//! # Safety
//!
//! Implementations may use `unsafe` to perform raw I/O port / MMIO access,
//! each justified with a `// SAFETY:` comment.

#![no_std]

pub mod mmio;

use core::fmt::Write;

/// A serial UART used for early boot logging and the early console.
pub trait Uart: Write {
    /// Initialize the UART at its default base address.
    ///
    /// # Safety
    ///
    /// Touches raw I/O ports / MMIO registers.
    unsafe fn init(&mut self);

    /// Transmit a single byte.
    ///
    /// # Safety
    ///
    /// Touches raw I/O ports / MMIO registers.
    unsafe fn write_byte(&mut self, byte: u8);
}

/// A linear framebuffer used for early video output before a graphics server
/// is running.
pub trait Framebuffer {
    /// Initialize the framebuffer (detect mode, map video memory).
    ///
    /// # Safety
    ///
    /// Touches MMIO and may walk firmware tables.
    unsafe fn init(&mut self);

    /// Framebuffer width in pixels.
    fn width(&self) -> usize;

    /// Framebuffer height in pixels.
    fn height(&self) -> usize;

    /// Stride in bytes between consecutive rows.
    fn stride(&self) -> usize;

    /// Mutable slice over the framebuffer pixel memory.
    ///
    /// # Safety
    ///
    /// The returned slice aliases video memory.
    unsafe fn buffer(&mut self) -> &mut [u8];
}

/// CPU segment descriptor table (GDT on x86_64, equivalent on other archs).
pub trait Gdt {
    /// Load the GDT and reload segment registers.
    ///
    /// # Safety
    ///
    /// Writes CPU control registers / segment registers.
    unsafe fn load(&self);
}

/// Interrupt descriptor table.
pub trait Idt {
    /// Load the IDT.
    ///
    /// # Safety
    ///
    /// Writes the IDTR CPU register.
    unsafe fn load(&self);
}

/// Early boot context provided by the HAL before the kernel takes over.
pub trait EarlyBoot {
    /// Top of the initial boot stack (stack grows down).
    fn stack_top() -> usize;

    /// Called by `_start` before jumping to the kernel's `main`.
    ///
    /// # Safety
    ///
    /// Performs low-level CPU and hardware initialization.
    unsafe fn early_init();
}

/// A hardware interrupt line.
pub trait Irq {
    /// Register a handler for `irq`. The handler is invoked (in interrupt
    /// context) when the line fires; it must return `true` if it handled the
    /// interrupt and wants an EOI/ACK, `false` to leave it masked.
    ///
    /// # Safety
    ///
    /// Touches the IDT / interrupt controller and installs a handler.
    unsafe fn register_handler(&mut self, irq: u8, handler: fn(u8) -> bool);

    /// Unmask (enable) delivery of `irq` to the CPU.
    ///
    /// # Safety
    ///
    /// Writes the interrupt controller.
    unsafe fn unmask(&mut self, irq: u8);

    /// Mask (disable) delivery of `irq`.
    ///
    /// # Safety
    ///
    /// Writes the interrupt controller.
    unsafe fn mask(&mut self, irq: u8);

    /// Acknowledge / EOI `irq` after it has been handled.
    ///
    /// # Safety
    ///
    /// Writes the interrupt controller.
    unsafe fn ack(&mut self, irq: u8);
}

/// A timer / deadline source used by the scheduler.
pub trait Timer {
    /// Program a one-shot deadline at `deadline_ns` nanoseconds from now.
    ///
    /// # Safety
    ///
    /// Writes timer / lapic / pit registers.
    unsafe fn set_oneshot(&mut self, deadline_ns: u64);

    /// Current time in nanoseconds since an arbitrary (boot) epoch.
    fn now_ns(&self) -> u64;

    /// Has the programmed deadline expired?
    fn expired(&self) -> bool;
}

// ===========================================================================
// ADR-012: HAL trap-decode trait (arch → kernel fault reporting)
// ===========================================================================

/// Decoded access kind from a page-fault error code.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AccessKind(pub u32);

impl AccessKind {
    /// The fault was caused by a read.
    pub const READ: AccessKind = AccessKind(1 << 0);
    /// The fault was caused by a write.
    pub const WRITE: AccessKind = AccessKind(1 << 1);
    /// The fault was caused by an instruction fetch / execute.
    pub const EXEC: AccessKind = AccessKind(1 << 2);

    pub const fn contains(self, other: AccessKind) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two access kinds (bitwise OR).
    pub const fn union(self, other: AccessKind) -> AccessKind {
        AccessKind(self.0 | other.0)
    }
}

/// Arch-specific trap frame — opaque to the kernel; defined per-arch.
pub trait ArchFrame {
    /// Faulting virtual address (e.g. CR2 on x86_64, FAR on aarch64).
    fn fault_addr(&self) -> u64;

    /// Architectural trap error code (e.g. x86_64 #PF error code).
    /// Returns 0 if the arch doesn't use error codes.
    fn err_code(&self) -> u32 {
        0
    }
}

/// Decodes an arch trap frame into a kernel-understandable fault report.
///
/// `hal/` performs only trap decoding + register extraction; policy
/// (kill thread, send FAULT_PAGE, COW resolution) stays in `kernel/`.
///
/// The address is returned as a raw `u64` because `hal` cannot depend on
/// `kernel`; the arch entry converts it to `kernel::aspace::Vaddr` before
/// calling `kernel::fault::handle_page_fault`.
///
/// # Safety
///
/// Reads raw CPU state from the trap frame; safe when called from the arch
/// trap entry with a valid frame pointer.
pub trait TrapDecode {
    /// Given an arch-specific trap frame, return the faulting virtual address
    /// (raw `u64`) and access kind, or `None` if this is not a page fault.
    ///
    /// # Safety
    ///
    /// Reads raw CPU state from the trap frame; safe when called from the arch
    /// trap entry with a valid frame pointer.
    unsafe fn decode_fault(&self, frame: &dyn ArchFrame) -> Option<(u64, AccessKind)>;
}

// ===========================================================================
// ADR-014: CPU topology + SMP traits
// ===========================================================================

/// CPU type classification for scheduler placement (Big.LITTLE etc.).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CpuType {
    /// Unknown / not yet classified.
    #[default]
    Unknown,
    /// High-performance core (e.g. P-core, big).
    Performance,
    /// High-efficiency core (e.g. E-core, LITTLE).
    Efficiency,
}

/// Topology of one CPU.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuInfo {
    /// Logical CPU index (0..ncpus).
    pub id: u32,
    /// Core type (performance / efficiency / unknown).
    pub r#type: CpuType,
    /// NUMA node this CPU belongs to (0 if NUMA not present).
    pub numa_node: u32,
    /// L1i + L1d + L2 cache size in KiB (0 if unknown).
    pub cache_kib: u32,
}

/// Enumerates online CPUs and their topology.
pub trait CpuTopology {
    /// Number of online CPUs.
    fn ncpus(&self) -> u32;

    /// Information about CPU `id`. Returns `None` if `id >= ncpus()`.
    fn cpu_info(&self, id: u32) -> Option<CpuInfo>;

    /// The BSP (bootstrap processor) CPU id.
    fn bsp_id(&self) -> u32;
}

/// Inter-processor interrupt delivery.
pub trait Ipi {
    /// Send an IPI to a single CPU.
    ///
    /// # Safety
    ///
    /// Writes the local APIC / GIC / PLIC IPI registers.
    unsafe fn send_ipi(&mut self, target_cpu: u32);

    /// Send an IPI to all CPUs except the calling one.
    ///
    /// # Safety
    ///
    /// Writes the local APIC / GIC / PLIC IPI registers.
    unsafe fn send_ipi_all_but_self(&mut self);
}

/// Brings up secondary (application) processors.
pub trait SecondaryBoot {
    /// Park CPU `id` until the scheduler assigns it work.
    ///
    /// # Safety
    ///
    /// Writes CPU control registers and stack pointers.
    unsafe fn park_cpu(&mut self, id: u32);

    /// Start CPU `id` at `entry` with `stack_top` as its initial stack.
    ///
    /// # Safety
    ///
    /// Writes CPU control registers and stack pointers; mutates another CPU's
    /// execution state.
    unsafe fn start_cpu(&mut self, id: u32, entry: usize, stack_top: usize);
}

/// Low-power idle state for the scheduler idle loop.
pub trait Halt {
    /// Enter a low-power / halt state until the next interrupt.
    ///
    /// # Safety
    ///
    /// Executes `hlt` / `wfe` / `wfi`; safe when interrupts are enabled.
    unsafe fn halt(&mut self);
}

// ===========================================================================
// ADR-015: HAL boot protocol (UEFI / ACPI / device tree)
// ===========================================================================

/// Memory region type reported by firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MemType {
    #[default]
    Usable,
    Reserved,
    AcpiReclaim,
    AcpiNvs,
    Bad,
}

/// One physical memory region from the firmware memory map.
#[derive(Clone, Copy, Debug, Default)]
pub struct MemRegion {
    pub base: u64,
    pub len: u64,
    pub r#type: MemType,
}

/// Pixel format reported by UEFI GOP or firmware framebuffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PixelFormat {
    #[default]
    Rgb,
    Bgr,
    Bitmask,
}

/// Boot information handed from firmware/bootloader to the kernel.
pub trait BootInfo {
    /// Firmware type: UEFI, BIOS, SBI, OpenBoot, etc.
    fn firmware_type(&self) -> &'static str;

    /// Physical memory map: usable / reserved / ACPI / NVS regions.
    fn mem_regions(&self) -> &[MemRegion];

    /// Framebuffer info, if a firmware framebuffer is available.
    fn framebuffer_info(&self) -> Option<FramebufferInfo>;

    /// Boot command line (if any).
    fn cmdline(&self) -> &str;
}

/// Framebuffer metadata from firmware (UEFI GOP, OpenBoot, etc.).
#[derive(Clone, Copy, Debug, Default)]
pub struct FramebufferInfo {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
}

/// ACPI table parser: locate RSDP, parse MADT/FADT/MCFG/HPET.
pub trait AcpiParser {
    /// Find the RSDP physical address.
    ///
    /// # Safety
    ///
    /// Scans physical memory for the RSDP signature.
    unsafe fn find_rsdp(&self) -> Option<u64>;

    /// Parse the MADT (Multiple APIC Description Table) into CPU info.
    /// Fills `out` with CPU descriptors; returns the number written.
    ///
    /// # Safety
    ///
    /// Reads ACPI tables at physical addresses.
    unsafe fn parse_madt(&self, rsdp: u64, out: &mut [CpuInfo]) -> usize;

    /// Parse the MCFG (PCI Express Memory Mapped Configuration Space) base.
    ///
    /// # Safety
    ///
    /// Reads ACPI tables at physical addresses.
    unsafe fn parse_mcfg(&self, rsdp: u64) -> Option<u64>;
}

/// Flattened device tree parser.
pub trait DeviceTree {
    /// Find a node by compatible string.
    ///
    /// # Safety
    ///
    /// Reads the device tree blob at a physical address.
    unsafe fn find_compatible(&self, dtb: u64, compatible: &str) -> Option<u64>;

    /// Read the `reg` property of a node (list of (address, size) pairs).
    /// Fills `out`; returns the number of entries written.
    ///
    /// # Safety
    ///
    /// Reads the device tree blob at a physical address.
    unsafe fn read_reg(&self, node: u64, out: &mut [(u64, u64)]) -> usize;

    /// Read the `interrupts` property of a node.
    /// Fills `out`; returns the number of entries written.
    ///
    /// # Safety
    ///
    /// Reads the device tree blob at a physical address.
    unsafe fn read_interrupts(&self, node: u64, out: &mut [u32]) -> usize;
}

// ===========================================================================
// ADR-016: Driver / HAL bus interfaces (PCI / virtio / DMA)
// ===========================================================================

/// PCI bus enumeration and configuration space access.
pub trait PciBus {
    /// Enumerate PCI functions; fills `out` with (bus, device, function)
    /// triples; returns the number written.
    fn enumerate(&mut self, out: &mut [(u8, u8, u8)]) -> usize;

    /// Read a 32-bit word from PCI config space.
    ///
    /// # Safety
    ///
    /// Touches PCI config space ports / MMIO.
    unsafe fn config_read32(&mut self, bus: u8, dev: u8, fn_: u8, offset: u8) -> u32;

    /// Write a 32-bit word to PCI config space.
    ///
    /// # Safety
    ///
    /// Touches PCI config space ports / MMIO.
    unsafe fn config_write32(&mut self, bus: u8, dev: u8, fn_: u8, offset: u8, value: u32);

    /// Enable bus mastering for a device.
    ///
    /// # Safety
    ///
    /// Touches PCI config space command register.
    unsafe fn set_bus_master(&mut self, bus: u8, dev: u8, fn_: u8, enable: bool);

    /// Read the BAR base and size for a function (returns None if not a BAR).
    ///
    /// # Safety
    ///
    /// Touches PCI config space.
    unsafe fn bar_info(&mut self, bus: u8, dev: u8, fn_: u8, bar: u8) -> Option<(u64, u64)>;
}

/// Virtio virtqueue and device notification.
pub trait Virtio {
    /// Notify the device that the available ring has new entries.
    ///
    /// # Safety
    ///
    /// Writes the virtio device notification register (MMIO or I/O port).
    unsafe fn notify(&mut self, queue_sel: u16);

    /// Read the virtio ISR status register.
    ///
    /// # Safety
    ///
    /// Reads the virtio ISR register (MMIO or I/O port).
    unsafe fn read_isr(&mut self) -> u8;

    /// Acknowledge a used-buffer interrupt (clear ISR bit).
    ///
    /// # Safety
    ///
    /// Writes the virtio ISR register.
    unsafe fn ack_used(&mut self);
}

/// Physically contiguous DMA-safe memory allocation.
pub trait Dma {
    /// Allocate `bytes` of DMA-safe, physically contiguous memory.
    ///
    /// Returns (virt_addr, phys_addr). May return None if out of DMA memory.
    ///
    /// # Safety
    ///
    /// Touches the page allocator / IOMMU.
    unsafe fn alloc_dma(&mut self, bytes: u64, align: u64) -> Option<(usize, usize)>;

    /// Free DMA memory allocated by `alloc_dma`.
    ///
    /// # Safety
    ///
    /// `virt` and `phys` must come from a prior `alloc_dma` call.
    unsafe fn free_dma(&mut self, virt: usize, phys: usize);

    /// Sync a DMA region for device access (device will write to it).
    ///
    /// # Safety
    ///
    /// Touches the IOMMU / cache coherency.
    unsafe fn sync_for_device(&mut self, virt: usize, bytes: u64);

    /// Sync a DMA region for CPU access (device finished writing).
    ///
    /// # Safety
    ///
    /// Touches the IOMMU / cache coherency.
    unsafe fn sync_for_cpu(&mut self, virt: usize, bytes: u64);
}

/// Memory-mapped I/O region for device register access.
pub trait MmioRegion {
    /// Map a physical MMIO range `[paddr, paddr + len)` into the driver's
    /// address space. Returns a virtual address that can be used to access
    /// the device registers.
    ///
    /// # Safety
    ///
    /// Touches page tables; `paddr`/`len` must describe a valid device region.
    unsafe fn map_mmio(&mut self, paddr: u64, len: u64) -> Option<usize>;

    /// Unmap a previously mapped MMIO region.
    ///
    /// # Safety
    ///
    /// `virt` must come from a prior `map_mmio` call.
    unsafe fn unmap_mmio(&mut self, virt: usize, len: u64);
}
