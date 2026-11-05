//! Tiny unsafe island for core memory management (PLAN §2.1: kernel crate
//! forbids `unsafe` except justified islands like this one). Zeroing must
//! live here because `entry`/`frame` are under crate-level `deny`.
#![allow(unsafe_code)]

use crate::frame::{self, PhysAddr};

/// Paint a byte range through the identity direct map (kstack high-water
/// accounting, ADR-037 follow-up; debug builds only).
#[cfg(debug_assertions)]
pub fn paint_range(base: u64, len: u64, pattern: u8) {
    // SAFETY: the range is kernel-allocated, identity-mapped RAM, not yet in
    // use below the built context.
    unsafe {
        core::ptr::write_bytes(base as *mut u8, pattern, len as usize);
    }
}

/// Count pattern bytes overwritten from the START of a painted range
/// (returns bytes consumed — the high-water depth).
#[cfg(debug_assertions)]
pub fn high_water(base: u64, len: u64, pattern: u8) -> u64 {
    // SAFETY: as paint_range — kernel-owned identity-mapped RAM.
    unsafe {
        let p = base as *const u8;
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
            core::ptr::write_bytes(frame.as_u64() as *mut u8, 0, frame::FRAME_SIZE);
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
        let top = kstack_top as *const u64;
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = *top.sub(i + 1);
        }
    }
}

/// Write a kernel-context register image (REGS_WRITE backing).
pub fn write_reg_image(kstack_top: u64, image: &[u64; 10]) {
    // SAFETY: as read_reg_image.
    unsafe {
        let top = kstack_top as *mut u64;
        for (i, val) in image.iter().enumerate() {
            *top.sub(i + 1) = *val;
        }
    }
}
