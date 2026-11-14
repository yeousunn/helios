//! aarch64 context-switch backend.
//!
//! v0 is single-CPU; `switch` is a no-op (the same thread resumes). The real
//! aarch64 register save/restore, stack switch and ERET-to-EL0 entry code
//! (`start_first`) plus TTBR0/MAIR/TCR programming (`activate_aspace`) land
//! with aarch64 QEMU or hardware bring-up (Phase 5). `init_context` is
//! implementable in pure Rust: it returns the initial kernel stack pointer,
//! which aarch64 requires to be 16-byte aligned (AAPCS64).

use kernel::sched;

/// aarch64 context-switch backend.
pub struct ContextBackendAarch64;

impl Default for ContextBackendAarch64 {
    fn default() -> Self {
        Self
    }
}

impl sched::ContextBackend for ContextBackendAarch64 {
    fn switch(&self, _from: sched::ThreadId, _to: sched::ThreadId) {
        // v0 bring-up: single CPU, the same thread resumes — no-op.
    }

    fn start_first(&self, _to: sched::ThreadId) {
        unimplemented!("aarch64 start_first: ERET-to-EL0 entry not yet implemented");
    }

    /// Build the initial kernel context: return the initial kernel stack
    /// pointer for `Thread.ksp`. aarch64 requires the stack pointer to be
    /// 16-byte aligned on exception entry, so round `kstack_top` down.
    fn init_context(&self, kstack_top: u64, _entry_pc: u64) -> u64 {
        kstack_top & !0x0F
    }

    fn activate_aspace(&self, _as_id: u64) {
        unimplemented!("aarch64 activate_aspace: TTBR0/TTBR1/MAIR/TCR not yet programmed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::sched::ContextBackend;

    #[test]
    fn init_context_returns_16_byte_aligned_stack_pointer() {
        let backend = ContextBackendAarch64::default();
        let ksp = backend.init_context(0x_0000_7FFF_FFFF_F017, 0x_1000);
        assert_eq!(ksp, 0x_0000_7FFF_FFFF_F010);
        assert_eq!(ksp & 0x0F, 0);
    }

    #[test]
    fn init_context_already_aligned_is_unchanged() {
        let backend = ContextBackendAarch64::default();
        assert_eq!(backend.init_context(0x_1000, 0), 0x_1000);
        assert_eq!(backend.init_context(0x_0FFF_F000, 0), 0x_0FFF_F000);
    }
}
