//! Non-x86_64 stub for `hal-x86-64`.
//! The real implementation lives in `impl_x86_64.rs` and is only compiled
//! on `target_arch = "x86_64"`.

use core::fmt::{self, Write};

use hal::{
    AcpiParser, BootInfo, CpuTopology, DeviceTree, Dma, Halt, Ipi, MmioRegion, PciBus,
    SecondaryBoot, Virtio,
};
use hal::{EarlyBoot, Framebuffer, Gdt as HalGdt, Idt as HalIdt, Irq, Timer, Uart};

/// COM1 I/O base address (unused on non-x86_64).
pub const COM1: u16 = 0;

/// Concrete UART type (stub).
pub struct Com1Uart;

/// Concrete early-boot type (stub).
pub struct X86_64EarlyBoot;

/// GDT table (stub).
#[repr(C, align(8))]
#[derive(Default)]
pub struct Gdt {
    _private: (),
}

/// IDT table (stub).
#[repr(C, align(8))]
#[derive(Default)]
pub struct Idt {
    _private: (),
}

/// GDTR / IDTR descriptor (stub).
#[repr(C, packed)]
pub struct TablePtr {
    _private: (),
}

/// Stub framebuffer.
#[derive(Default)]
pub struct StubFramebuffer {
    width: usize,
    height: usize,
    stride: usize,
}

/// PIC stub.
#[derive(Default)]
pub struct Pic {
    _private: (),
}

/// Timer stub.
#[derive(Default)]
pub struct TimerSrc {
    _private: (),
}

impl Uart for Com1Uart {
    unsafe fn init(&mut self) {}
    unsafe fn write_byte(&mut self, _byte: u8) {}
}

impl Write for Com1Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = s;
        Ok(())
    }
}

#[allow(clippy::new_without_default)]
impl Gdt {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn install(&mut self) {}
}

impl HalGdt for Gdt {
    unsafe fn load(&self) {}
}

#[allow(clippy::new_without_default)]
impl Idt {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn install(&mut self) {}
}

impl HalIdt for Idt {
    unsafe fn load(&self) {}
}

impl Irq for Pic {
    unsafe fn register_handler(&mut self, _irq: u8, _handler: fn(u8) -> bool) {}
    unsafe fn unmask(&mut self, _irq: u8) {}
    unsafe fn mask(&mut self, _irq: u8) {}
    unsafe fn ack(&mut self, _irq: u8) {}
}

/// CPU topology stub.
#[derive(Default)]
pub struct CpuTopologyStub;

/// SMP stub.
#[derive(Default)]
pub struct SmpStub;

/// Boot info stub.
#[derive(Default)]
pub struct BootInfoStub;

/// ACPI parser stub.
#[derive(Default)]
pub struct AcpiParserStub;

/// Device tree stub.
#[derive(Default)]
pub struct DeviceTreeStub;

/// PCI bus stub.
#[derive(Default)]
pub struct PciBusStub;

/// Virtio stub.
#[derive(Default)]
pub struct VirtioStub;

/// DMA stub.
#[derive(Default)]
pub struct DmaStub;

/// MMIO region stub.
#[derive(Default)]
pub struct MmioRegionStub;

impl CpuTopology for CpuTopologyStub {
    fn ncpus(&self) -> u32 {
        1
    }
    fn cpu_info(&self, _id: u32) -> Option<hal::CpuInfo> {
        Some(hal::CpuInfo {
            id: 0,
            r#type: hal::CpuType::Performance,
            numa_node: 0,
            cache_kib: 0,
        })
    }
    fn bsp_id(&self) -> u32 {
        0
    }
}

impl Ipi for SmpStub {
    unsafe fn send_ipi(&mut self, _target_cpu: u32) {}
    unsafe fn send_ipi_all_but_self(&mut self) {}
}

impl SecondaryBoot for SmpStub {
    unsafe fn park_cpu(&mut self, _id: u32) {}
    unsafe fn start_cpu(&mut self, _id: u32, _entry: usize, _stack_top: usize) {}
}

impl Halt for SmpStub {
    unsafe fn halt(&mut self) {
        core::hint::spin_loop();
    }
}

impl BootInfo for BootInfoStub {
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

impl AcpiParser for AcpiParserStub {
    unsafe fn find_rsdp(&self) -> Option<u64> {
        None
    }
    unsafe fn parse_madt(&self, _rsdp: u64, _out: &mut [hal::CpuInfo]) -> usize {
        0
    }
    unsafe fn parse_mcfg(&self, _rsdp: u64) -> Option<u64> {
        None
    }
}

impl DeviceTree for DeviceTreeStub {
    unsafe fn find_compatible(&self, _dtb: u64, _compatible: &str) -> Option<u64> {
        None
    }
    unsafe fn read_reg(&self, _node: u64, _out: &mut [(u64, u64)]) -> usize {
        0
    }
    unsafe fn read_interrupts(&self, _node: u64, _out: &mut [u32]) -> usize {
        0
    }
}

impl PciBus for PciBusStub {
    fn enumerate(&mut self, _out: &mut [(u8, u8, u8)]) -> usize {
        0
    }
    unsafe fn config_read32(&mut self, _bus: u8, _dev: u8, _fn: u8, _offset: u8) -> u32 {
        0
    }
    unsafe fn config_write32(&mut self, _bus: u8, _dev: u8, _fn: u8, _offset: u8, _value: u32) {}
    unsafe fn set_bus_master(&mut self, _bus: u8, _dev: u8, _fn: u8, _enable: bool) {}
    unsafe fn bar_info(&mut self, _bus: u8, _dev: u8, _fn: u8, _bar: u8) -> Option<(u64, u64)> {
        None
    }
}

impl Virtio for VirtioStub {
    unsafe fn notify(&mut self, _queue_sel: u16) {}
    unsafe fn read_isr(&mut self) -> u8 {
        0
    }
    unsafe fn ack_used(&mut self) {}
}

impl Dma for DmaStub {
    unsafe fn alloc_dma(&mut self, _bytes: u64, _align: u64) -> Option<(usize, usize)> {
        None
    }
    unsafe fn free_dma(&mut self, _virt: usize, _phys: usize) {}
    unsafe fn sync_for_device(&mut self, _virt: usize, _bytes: u64) {}
    unsafe fn sync_for_cpu(&mut self, _virt: usize, _bytes: u64) {}
}

impl MmioRegion for MmioRegionStub {
    unsafe fn map_mmio(&mut self, _paddr: u64, _len: u64) -> Option<usize> {
        None
    }
    unsafe fn unmap_mmio(&mut self, _virt: usize, _len: u64) {}
}

impl Timer for TimerSrc {
    unsafe fn set_oneshot(&mut self, _deadline_ns: u64) {}
    fn now_ns(&self) -> u64 {
        0
    }
    fn expired(&self) -> bool {
        false
    }
}

impl Framebuffer for StubFramebuffer {
    unsafe fn init(&mut self) {}
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
        &mut []
    }
}

impl EarlyBoot for X86_64EarlyBoot {
    fn stack_top() -> usize {
        0
    }
    unsafe fn early_init() {}
}

/// Early boot entry point symbol (stub).
///
/// # Safety
///
/// Called by the bootloader/firmware before any Rust runtime exists. On
/// non-x86_64 hosts this is a no-op halt loop.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
