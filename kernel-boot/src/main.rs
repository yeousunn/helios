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

use hal::EarlyBoot;
use kernel::console::Level;

global_asm!(include_str!("boot.S"));

/// Final binaries own the panic handler and delegate to the kernel policy
/// (ADR-027: log, then exit/ halt).
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    kernel::panic::handle_panic(info)
}

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
    hal_x86_64::uart_writer("boot: 1 hooks\n");
    kernel::panic::set_exit_code(hal_x86_64::qemu_exit_code);
    hal_x86_64::uart_writer("boot: 2 panic hook\n");

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
        "M1: kernel boot ok; init pid={} thread={} regions={}",
        launch.pid.0,
        launch.thread.0,
        launch.bootinfo.region_count
    );

    // M1 terminus: every subsystem that can be exercised without userspace is
    // up; halt with the clean exit code (ADR-028 → ADR-013). Userspace entry
    // (init image staging + ring 3) replaces this as the next milestone.
    kernel::panic::clean_exit();
}
