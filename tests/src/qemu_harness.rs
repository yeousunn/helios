//! QEMU integration-test harness.
//!
//! Gated behind the `qemu` feature. Boots the `kernel-boot` PVH ELF (ADR-025)
//! with the `build/initrd.img` staging image, captures the serial (UART) log,
//! and asserts on the QEMU exit code decoded per ADR-029 / ADR-013.
//!
//! Boot path (NV):
//!   `cargo build -p kernel-boot --features boot --target x86_64-unknown-none`
//!   produces `target/x86_64-unknown-none/{debug,release}/kernel-boot`, a PVH
//!   ELF that QEMU loads with `-kernel` and enters at `_start` in 32-bit
//!   protected mode (see `kernel-boot/src/boot.S`).
//!
//! Exit-code contract (ADR-029, amending ADR-013): QEMU `isa-debug-exit`
//! reports process status `(value << 1) | 1` (always odd), so kernel codes
//! decode as:
//!   status 1  = value 0  = clean bring-up halt        (CI pass)
//!   status 3  = value 1  = kernel panic
//!   status 5  = value 2  = unhandled fault / shutdown
//!   status 7  = value 3  = boot timeout
//!   status 124          = harness timeout killed QEMU
//!   status 4            = userspace test process failure
//!   status 255          = QEMU failed to launch / harness error
//!   status 0            = clean (non-exit-device paths)

#![cfg(feature = "qemu")]

use std::process::Command;

/// Path (relative to workspace root) to the bootable kernel ELF, once built.
/// Override with the `KERNEL_ELF` env var.
const KERNEL_ELF_DEFAULT: &str = "target/x86_64-unknown-none/debug/kernel-boot";

/// Staging initrd image. Override with the `INITRD` env var.
const INITRD_DEFAULT: &str = "build/initrd.img";

/// QEMU `isa-debug-exit` I/O port (x86_64).
const QEMU_EXIT_PORT: u16 = 0x501;

/// Launch QEMU with `kernel_elf` (+ optional `initrd`), capture serial output,
/// return the raw QEMU process exit status code.
pub fn run_qemu(kernel_elf: &str, initrd: Option<&str>) -> std::io::Result<i32> {
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.arg("-machine")
        .arg("accel=tcg")
        .arg("-cpu")
        .arg("max")
        .arg("-m")
        .arg("256M")
        .arg("-kernel")
        .arg(kernel_elf);
    if let Some(initrd) = initrd {
        cmd.arg("-initrd").arg(initrd);
    }
    cmd.arg("-serial")
        .arg("file:/tmp/helios-harness-serial.log")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-device")
        .arg(&format!(
            "isa-debug-exit,iobase={},iosize=0x02",
            QEMU_EXIT_PORT
        ))
        .arg("-nographic");
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(255))
}

/// Decode a raw QEMU exit status into a CI exit code (ADR-029 / ADR-013).
/// Returns `0` on clean bring-up halt; nonzero on failure.
pub fn qemu_status_to_ci(status: i32) -> i32 {
    match status {
        0 => 0,     // non-exit-device path: clean
        1 => 0,     // isa-debug-exit: value 0  = clean bring-up halt
        3 => 1,     // isa-debug-exit: value 1  = kernel panic
        5 => 2,     // isa-debug-exit: value 2  = unhandled fault / shutdown
        7 => 3,     // isa-debug-exit: value 3  = boot timeout
        124 => 3,   // harness timeout killed QEMU
        4 => 5,     // userspace test process failure
        255 => 255, // QEMU failed to launch / harness error
        _ => 1,     // unexpected QEMU exit code
    }
}

/// Convenience: build the default kernel ELF path from the workspace target dir.
pub fn default_kernel_elf() -> String {
    std::env::var("KERNEL_ELF").unwrap_or(KERNEL_ELF_DEFAULT.to_string())
}

/// Convenience: build the default initrd path from the workspace root.
pub fn default_initrd() -> String {
    std::env::var("INITRD").unwrap_or(INITRD_DEFAULT.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_decode_clean_halt() {
        assert_eq!(qemu_status_to_ci(1), 0); // isa-debug-exit value 0
        assert_eq!(qemu_status_to_ci(0), 0); // non-device path
    }

    #[test]
    fn exit_code_decode_failures() {
        assert_eq!(qemu_status_to_ci(3), 1); // kernel panic
        assert_eq!(qemu_status_to_ci(5), 2); // unhandled fault / shutdown
        assert_eq!(qemu_status_to_ci(7), 3); // boot timeout
        assert_eq!(qemu_status_to_ci(124), 3); // harness timeout
        assert_eq!(qemu_status_to_ci(4), 5); // userspace test failure
        assert_eq!(qemu_status_to_ci(255), 255); // infra error
        assert_eq!(qemu_status_to_ci(99), 1); // unexpected -> generic fail
    }

    #[test]
    fn default_paths() {
        assert_eq!(default_kernel_elf(), KERNEL_ELF_DEFAULT);
        assert_eq!(default_initrd(), INITRD_DEFAULT);
    }

    #[test]
    fn harness_compiles() {
        // Placeholder: the harness must at least compile under the `qemu`
        // feature. Real boot assertions land once a bootable image exists.
        let _ = default_kernel_elf();
        let _ = default_initrd();
    }
}
