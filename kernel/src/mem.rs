//! Tiny unsafe island for core memory management (PLAN §2.1: kernel crate
//! forbids `unsafe` except justified islands like this one). Zeroing must
//! live here because `entry`/`frame` are under crate-level `deny`.
#![allow(unsafe_code)]

use crate::frame::{self, PhysAddr};

/// Paint a byte range through the identity direct map (kstack high-water
/// accounting, ADR-037 follow-up; debug builds only).
#[cfg(debug_assertions)]
pub fn paint_range(base: u64, len: u64, pattern: u8) {
    // SAFETY: the range is kernel-allocated RAM, reached through the shared
    // higher-half window (phys_to_virt), not yet in use below the built
    // context.
    unsafe {
        core::ptr::write_bytes(phys_to_virt(base) as *mut u8, pattern, len as usize);
    }
}

/// Count pattern bytes overwritten from the START of a painted range
/// (returns bytes consumed — the high-water depth).
#[cfg(debug_assertions)]
pub fn high_water(base: u64, len: u64, pattern: u8) -> u64 {
    // SAFETY: as paint_range — kernel-owned identity-mapped RAM.
    unsafe {
        let p = phys_to_virt(base) as *const u8;
        let mut i = 0usize;
        while i < len as usize && p.add(i).read_volatile() == pattern {
            i += 1;
        }
        i as u64
    }
}

/// Allocate one frame and zero it (eager ANON resolution for `AS::MAP`).
pub fn alloc_zeroed() -> Option<PhysAddr> {
    let frame = frame::alloc()?;
    // The identity direct map only exists on the metal; host tests hold
    // simulated addresses that are not mapped, so skip the wipe there.
    #[cfg(not(test))]
    {
        // SAFETY: freshly allocated frame; the identity direct map covers all
        // allocator-managed RAM, so writing through the physical address is
        // valid and exclusively ours until mapped elsewhere.
        unsafe {
            core::ptr::write_bytes(
                phys_to_virt(frame.as_u64()) as *mut u8,
                0,
                frame::FRAME_SIZE,
            );
        }
    }
    Some(frame)
}

/// Read a kernel-context register image (10 qwords below kstack_top) into
/// `out` — REGS_READ backing (ADR-039 §regs; debug/diag and fork contexts).
pub fn read_reg_image(kstack_top: u64, out: &mut [u64; 10]) {
    // SAFETY: the kstack frame is kernel-owned, identity-mapped RAM; the
    // thread is quiescent so nothing else writes it.
    unsafe {
        let top = phys_to_virt(kstack_top) as *const u64;
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = *top.sub(i + 1);
        }
    }
}

/// Write a kernel-context register image (REGS_WRITE backing).
pub fn write_reg_image(kstack_top: u64, image: &[u64; 10]) {
    // SAFETY: as read_reg_image.
    unsafe {
        let top = phys_to_virt(kstack_top) as *mut u64;
        for (i, val) in image.iter().enumerate() {
            *top.sub(i + 1) = *val;
        }
    }
}

/// ADR-045 slice 2: the shared higher-half window maps every physical page
/// below 1 GiB at `0xFFFFFFFF80000000 + PA` in every address space (boot.S
/// alias for the boot CR3, the shared PML4[511] window for user ASes) — the
/// kernel's frame/table access path. Host tests use fake addresses that are
/// never dereferenced through real mappings — pass through unchanged there.
#[cfg(not(test))]
pub const HIGH_HALF_BASE: u64 = 0xFFFF_FFFF_8000_0000;
#[cfg(test)]
pub const HIGH_HALF_BASE: u64 = 0;

/// ADR-045 slice 3 hardening: the translation discipline is assert-checked
/// in debug builds. `phys_to_virt` of an ALREADY-high VA (the
/// double-translation bug class — a VA passed where a PA was expected)
/// overflows the 1 GiB window and is caught here instead of corrupting
/// memory far away. Host tests pass fake addresses through unchanged.
#[cfg(not(test))]
pub fn phys_to_virt(pa: u64) -> u64 {
    debug_assert!(
        pa < 0x4000_0000,
        "phys_to_virt: {pa:#x} is not a physical address below 1 GiB (already a high VA?)"
    );
    HIGH_HALF_BASE + pa
}

#[cfg(test)]
pub fn phys_to_virt(pa: u64) -> u64 {
    pa
}

#[cfg(not(test))]
pub fn virt_to_phys(va: u64) -> u64 {
    debug_assert!(
        va >= HIGH_HALF_BASE,
        "virt_to_phys: {va:#x} is not a higher-half VA (a PA passed where a VA was expected?)"
    );
    va - HIGH_HALF_BASE
}

#[cfg(test)]
pub fn virt_to_phys(va: u64) -> u64 {
    va
}
