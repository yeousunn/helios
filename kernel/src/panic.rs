//! Kernel panic policy (ADR-002): log the panic, then exit via the arch
//! hook if one was registered, else spin forever.
#![forbid(unsafe_code)]

use core::panic::PanicInfo;
use spin::Mutex;

type ExitFn = fn() -> !;
type ExitCodeFn = fn(u32) -> !;

static EXIT_HOOK: Mutex<Option<ExitFn>> = Mutex::new(None);
static EXIT_CODE_HOOK: Mutex<Option<ExitCodeFn>> = Mutex::new(None);

/// Register the exit hook used after a panic (e.g. QEMU isa-debug-exit).
/// Called by arch boot code via [`crate::boot::early_init`].
pub fn set_exit(f: ExitFn) {
    *EXIT_HOOK.lock() = Some(f);
}

/// Register a code-parameterized exit hook (ADR-028): used for the clean
/// halt when the last user thread exits (QEMU exit code 0, ADR-013).
pub fn set_exit_code(f: ExitCodeFn) {
    *EXIT_CODE_HOOK.lock() = Some(f);
}

fn exit_with(code: u32) -> ! {
    if let Some(f) = EXIT_CODE_HOOK.lock().take() {
        f(code);
    }
    panic_exit()
}

/// True when any exit hook is registered (test guard).
pub fn has_exit_hook() -> bool {
    EXIT_HOOK.lock().is_some() || EXIT_CODE_HOOK.lock().is_some()
}

/// Clean halt: all user threads have exited (ADR-028). Code 0 per ADR-013.
pub fn clean_exit() -> ! {
    crate::kinfo!("all threads exited — clean halt");
    exit_with(0)
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
