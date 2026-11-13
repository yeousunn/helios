//! aarch64 context-switch backend (bring-up stub).
//!
//! v0 is single-CPU; the real aarch64 register save/restore, stack switch and
//! ERET-to-EL0 entry code lands with SMP/aarch64 bring-up testing (Phase 5).

use kernel::sched;

/// aarch64 context-switch backend.
///
/// All methods are bring-up stubs: `switch` is a no-op (single CPU), and the
/// actual context-switch / first-entry / address-space-activation routines
/// require aarch64 assembly that cannot be validated without aarch64 QEMU.
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

    fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
        unimplemented!("aarch64 init_context: initial kernel context not yet implemented");
    }

    fn activate_aspace(&self, _as_id: u64) {
        unimplemented!("aarch64 activate_aspace: TTBR0/TTBR1/MAIR/TCR not yet programmed");
    }
}
