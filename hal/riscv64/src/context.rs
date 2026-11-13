//! riscv64 context-switch backend (bring-up stub).
//!
//! v0 is single-CPU; the real riscv64 register save/restore, stack switch and
//! MRET-to-U-mode entry code lands with SMP/riscv64 bring-up testing (Phase 5).

use kernel::sched;

/// riscv64 context-switch backend.
///
/// All methods are bring-up stubs: `switch` is a no-op (single CPU), and the
/// actual context-switch / first-entry / address-space-activation routines
/// require riscv64 assembly that cannot be validated without riscv64 QEMU.
pub struct ContextBackendRiscv64;

impl Default for ContextBackendRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl sched::ContextBackend for ContextBackendRiscv64 {
    fn switch(&self, _from: sched::ThreadId, _to: sched::ThreadId) {
        // v0 bring-up: single CPU, the same thread resumes — no-op.
    }

    fn start_first(&self, _to: sched::ThreadId) {
        unimplemented!("riscv64 start_first: MRET-to-U-mode entry not yet implemented");
    }

    fn init_context(&self, _kstack_top: u64, _entry_pc: u64) -> u64 {
        unimplemented!("riscv64 init_context: initial kernel context not yet implemented");
    }

    fn activate_aspace(&self, _as_id: u64) {
        unimplemented!("riscv64 activate_aspace: satp not yet programmed");
    }
}
