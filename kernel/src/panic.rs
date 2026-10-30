//! Kernel panic policy (ADR-002): log the panic, then exit via the arch
//! hook if one was registered, else spin forever.
#![forbid(unsafe_code)]

use core::panic::PanicInfo;
use spin::Mutex;

type ExitFn = fn() -> !;

static EXIT_HOOK: Mutex<Option<ExitFn>> = Mutex::new(None);

/// Register the exit hook used after a panic (e.g. QEMU isa-debug-exit).
/// Called by arch boot code via [`crate::boot::early_init`].
pub fn set_exit(f: ExitFn) {
    *EXIT_HOOK.lock() = Some(f);
}

#[cfg_attr(test, allow(dead_code))]
fn panic_exit() -> ! {
    if let Some(f) = EXIT_HOOK.lock().take() {
        f();
    }
    loop {
        core::hint::spin_loop();
    }
}

#[cfg_attr(test, allow(dead_code))]
/// The kernel panic policy (ADR-027). Final binaries own the actual
/// `#[panic_handler]` attribute and delegate here.
pub fn handle_panic(info: &PanicInfo<'_>) -> ! {
    crate::kerror!("PANIC: {}", info);
    panic_exit();
}
