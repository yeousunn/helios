//! Kernel boot binary for x86_64 (ADR-025): the only arch-glue crate.
//!
//! `boot.S` (multiboot2 header + 32→64-bit trampoline) enters long mode with
//! the first 1 GiB identity-mapped and calls [`kernel_main`], which performs
//! the ADR-001 boot handshake, registers the arch backends, initializes the
//! frame allocator, and launches init (`kernel::init::start`).
//!
//! Build (bare-metal only; the pipeline passes `--features boot`):
//! ```text
//! cargo build -p kernel-boot --features boot --target x86_64-unknown-none --release
//! qemu-system-x86_64 -kernel target/x86_64-unknown-none/release/kernel-boot ...
//! ```

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::global_asm;

use core::sync::atomic::Ordering;

use hal::EarlyBoot;
use kernel::console::Level;

global_asm!(include_str!("boot.S"));

include!(concat!(env!("OUT_DIR"), "/init_image.rs"));

/// Final binaries own the panic handler and delegate to the kernel policy
/// (ADR-027: log, then exit/ halt).
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kernel::panic::handle_panic(info)
}

/// The kernel is allocation-free by design; linking the SDK's ELF parser
/// pulls in `alloc`. Any kernel allocation is a bug — fail it loudly (null)
/// instead of relying on heap behavior in kernel context.
struct NoAlloc;

// SAFETY: `alloc` always returns null (allocation failure, never UB) and
// `dealloc` ignores its pointer (nothing was ever allocated).
unsafe impl core::alloc::GlobalAlloc for NoAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {}
}

#[global_allocator]
static NO_ALLOC: NoAlloc = NoAlloc;

/// Physical region handed to the frame allocator + init Region caps
/// (16 MiB..256 MiB; the kernel image and boot stack live below 16 MiB).
const FRAME_REGION_BASE: u64 = 0x100_0000;
const FRAME_REGION_LEN: u64 = 0xF00_0000;

/// Rust entry, called from `boot.S` after long mode is up. Never returns.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // SAFETY: single-threaded early boot, before any other kernel API
    // (ADR-001 handshake happens immediately after).
    unsafe {
        hal_x86_64::X86_64EarlyBoot::early_init();
    }

    kernel::boot::early_init(hal_x86_64::uart_writer, Level::Info, hal_x86_64::qemu_exit);
    dump_boot_state();
    hal_x86_64::uart_writer("boot: 1 hooks\n");
    kernel::panic::set_exit_code(hal_x86_64::qemu_exit_code);
    // Clobber-hunt debug walker: the kernel debug-EP walk op reads live
    // hardware PTEs through the identity map (temporary; removed post-smoke).
    kernel::debug::set_hw_walker(|va| hal_x86_64::debug_walk_live(va));

    // Enable NX (PTE bit 63 is reserved while EFER.NXE=0) and install fault
    // reporting stubs before any mapping/staging work.
    hal_x86_64::enable_nx();
    // SAFETY: boot-time, after early_init installed the GDT/IDT.
    unsafe {
        hal_x86_64::install_exception_stubs();
        hal_x86_64::install_tss();
    }
    hal_x86_64::uart_writer("boot: 2 panic hook + nx + idt stubs + tss\n");

    kernel::aspace::set_backend_factory(&hal_x86_64::BACKEND_FACTORY_X86_64);
    kernel::sched::set_context_backend(&hal_x86_64::CONTEXT_BACKEND_X86_64);
    kernel::entry::set_current_context(&hal_x86_64::CURRENT_CONTEXT_X86_64);

    // Scheduler must be initialized before init::start spawns the first
    // thread (found via smoke debug: spawn hit an uninitialized table).
    kernel::sched::init().expect("sched::init");
    hal_x86_64::uart_writer("boot: 3 backends\n");

    let region = kernel::frame::Region::new(
        kernel::frame::PhysAddr::new(FRAME_REGION_BASE),
        FRAME_REGION_LEN,
    )
    .expect("invalid frame region");
    kernel::frame::init(&[region]).expect("frame::init");
    hal_x86_64::uart_writer("boot: 4 frames\n");

    let regions = [kernel::init::BootRegion {
        base: kernel::frame::PhysAddr::new(FRAME_REGION_BASE),
        len: FRAME_REGION_LEN,
    }];
    let launch = kernel::init::start(&regions).expect("kernel::init::start");

    kernel::kinfo!(
        "kernel boot ok; init pid={} thread={} regions={}",
        launch.pid.0,
        launch.thread.0,
        launch.bootinfo.region_count
    );

    if HAS_INIT_IMAGE {
        // M2: stage the init ELF into the default AS and enter ring 3.
        let (entry, bootinfo_va) = stage_init(&launch, INIT_IMAGE);
        kernel::sched::set_initial_pc(launch.thread, entry).expect("set_initial_pc");
        // SAFETY: GDT with ring-3 segments is installed (hal early_init);
        // user pages are mapped by stage_init above.
        unsafe { hal_x86_64::syscall_entry::enable() };
        // The boot stack serves as init's kernel stack until the first
        // context switch saves a per-thread stack (M3).
        extern "C" {
            static stack_top: u8;
        }
        // SAFETY: the linker symbol is the boot stack top defined in boot.S.
        let boot_stack_top = core::ptr::addr_of!(stack_top) as u64;
        hal_x86_64::set_kstack(boot_stack_top);
        hal_x86_64::BOOTINFO_VA.store(bootinfo_va, Ordering::Relaxed);
        kernel::kinfo!(
            "M2: entering userspace: entry={:#x} bootinfo={:#x}",
            entry,
            bootinfo_va
        );
        kernel::sched::start_first(launch.thread);
        unreachable!("start_first returned");
    }

    // M1 terminus (no init image embedded): halt cleanly (ADR-028 → ADR-013).
    kernel::panic::clean_exit();
}

/// Physical-frames direct-map helpers (boot tables identity-map all RAM).
///
/// # Safety
/// `phys` must point to allocated RAM below the identity-mapped range and
/// `offset + bytes.len()` must stay inside the allocation.
unsafe fn write_phys(phys: u64, offset: u64, bytes: &[u8]) {
    // SAFETY: caller contract above.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), (phys + offset) as *mut u8, bytes.len());
    }
}

/// # Safety
/// `phys..phys+len` must be allocated, identity-mapped RAM.
unsafe fn zero_phys(phys: u64, len: u64) {
    // SAFETY: caller contract above.
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, len as usize) };
}

/// Map the embedded init ELF into the default AS, map its stack, and write
/// BootInfo into the first stack page. Returns `(entry, bootinfo_va)`.
fn stage_init(launch: &kernel::init::InitLaunch, image: &[u8]) -> (u64, u64) {
    use kernel::aspace::{self, MapFlags, Vaddr, DEFAULT_AS};

    let elf = sdk::elf::ElfImage::parse(image).expect("init ELF parse");
    kernel::kinfo!(
        "stage: init image {} bytes, entry={:#x}, {} segments",
        image.len(),
        elf.entry,
        elf.segment_count
    );

    for i in 0..elf.segment_count {
        let seg = elf.segment(i).expect("segment in range");
        let first = seg.vaddr & !0xFFF;
        let end = seg.vaddr + seg.memsz;
        let pages = (end - first).div_ceil(4096);
        let phys =
            kernel::frame::alloc_contiguous(pages as usize).expect("frames for init segment");
        // SAFETY: freshly allocated frames below the identity-mapped range.
        unsafe {
            zero_phys(phys.as_u64(), pages * 4096);
            if seg.filesz > 0 {
                let bytes = &image[seg.offset as usize..(seg.offset + seg.filesz) as usize];
                write_phys(phys.as_u64(), seg.vaddr - first, bytes);
            }
        }
        aspace::map(
            DEFAULT_AS,
            Vaddr(first),
            pages,
            Some(phys),
            MapFlags(seg.flags),
        )
        .expect("map init segment");
    }

    // Stack + BootInfo page: 64 KiB below USER_STACK_TOP.
    const STACK_PAGES: u64 = 16;
    let stack_bottom = hal_x86_64::USER_STACK_TOP as u64 - STACK_PAGES * 4096;
    let sp = kernel::frame::alloc_contiguous(STACK_PAGES as usize).expect("frames for init stack");
    // SAFETY: freshly allocated, identity-mapped frames.
    unsafe { zero_phys(sp.as_u64(), STACK_PAGES * 4096) };
    aspace::map(
        DEFAULT_AS,
        Vaddr(stack_bottom),
        STACK_PAGES,
        Some(sp),
        MapFlags(0b011), // R | W
    )
    .expect("map init stack");

    // BootInfo lands in the first (lowest) stack page; userspace receives the
    // pointer in `rdi` and reads it through its own mapping.
    let n = {
        // SAFETY: identity-mapped stack frames; the ADR-018 writer bounds-checks.
        let buf = unsafe { core::slice::from_raw_parts_mut(sp.as_u64() as *mut u8, 4096) };
        kernel::init::write_bootinfo(buf, &launch.bootinfo)
    };
    assert!(n > 0, "bootinfo write failed");

    // Switch the CPU to the staged address space (DEFAULT_AS = id 1) — the
    // mappings above went into its tables; running on the boot root would
    // leave top-level branches (e.g. the stack's PML4 entry) invisible.
    assert!(hal_x86_64::activate_as(1), "DEFAULT_AS has no paging root");
    // Post-staging TLB invalidate (covers huge-page splits done by the maps).
    hal_x86_64::flush_tlb_all();

    // Bring-up aid: show the permission chain for the entry page (bit 2 =
    // USER must be set at EVERY level for ring 3 to fetch the entry).
    dump_pte_chain(elf.entry);
    dump_boot_state();

    (elf.entry, stack_bottom)
}

/// Print GDTR/IDTR (bring-up diagnosis: exception delivery in ring 3 needs a
/// valid IDT base in static storage).
fn dump_boot_state() {
    let mut gdtr = [0u64; 2];
    let mut idtr = [0u64; 2];
    // SAFETY: sidt/sgdt write 10 bytes into the provided buffers.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
        core::arch::asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack));
    }
    kernel::kinfo!(
        "boot state: GDTR base={:#x} limit={:#x}; IDTR base={:#x} limit={:#x}",
        gdtr[0] >> 16,
        gdtr[0] & 0xFFFF,
        idtr[0] >> 16,
        idtr[0] & 0xFFFF
    );
}

/// Print the PML4/PDPT/PD(/PT) entries covering `va` (bring-up diagnosis).
fn dump_pte_chain(va: u64) {
    let idx = |va: u64, sh: u32| ((va >> sh) & 0x1FF) as u64;
    // SAFETY: reading the current page tables through the identity map.
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
        let rd = |p: u64| core::ptr::read_volatile(p as *const u64);
        let pml4e = rd(cr3 + idx(va, 39) * 8);
        let pdpte = rd((pml4e & !0xFFF) + idx(va, 30) * 8);
        let pde = rd((pdpte & !0xFFF) + idx(va, 21) * 8);
        if pde & 0x80 != 0 {
            kernel::kinfo!(
                "pte-chain {:#x}: pml4e={:#x} pdpte={:#x} pde={:#x} (2MiB huge)",
                va,
                pml4e,
                pdpte,
                pde
            );
        } else {
            let pte = rd((pde & !0xFFF) + idx(va, 12) * 8);
            kernel::kinfo!(
                "pte-chain {:#x}: pml4e={:#x} pdpte={:#x} pde={:#x} pte={:#x}",
                va,
                pml4e,
                pdpte,
                pde,
                pte
            );
        }
    }
}
