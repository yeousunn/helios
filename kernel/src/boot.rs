//! Boot handshake: the single entry point arch boot code (hal-*) must call
//! before using any other kernel API. See ADR-001.
#![forbid(unsafe_code)]

use crate::console::{self, Level};
use crate::panic;

/// Initialize the early console and panic exit hook.
///
/// Arch boot entry (`_start` in hal-x86_64 etc.) must call this first, passing
/// its serial/framebuffer writer and its QEMU/shutdown exit function.
pub fn early_init(writer: fn(&str), max_level: Level, exit: fn() -> !) {
    console::init(writer, max_level);
    panic::set_exit(exit);
    crate::kinfo!("helios kernel: early init ok");
}
