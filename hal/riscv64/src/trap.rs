//! riscv64 trap decode (ADR-012).
//! Decodes riscv64 synchronous-exception trap frames into kernel-understandable
//! fault reports: the faulting virtual address (stval) and the access kind
//! (read/write/exec) decoded from scause.
//!
//! The faulting address is returned as a raw `u64` because `hal` cannot depend
//! on `kernel`; the arch entry converts it to `kernel::aspace::Vaddr` before
//! calling `kernel::fault::handle_page_fault`.

#![allow(dead_code)]

use hal::{AccessKind, ArchFrame, TrapDecode};

// scause (64-bit): bit 63 = interrupt (1 = interrupt, 0 = exception);
// low bits = exception code / interrupt cause.
const SCAUSE_INTERRUPT: u64 = 1 << 63;

const EXC_INSTR_ACCESS_FAULT: u64 = 1; // instruction fetch page fault
const EXC_LOAD_ACCESS_FAULT: u64 = 5; // load page fault
const EXC_STORE_ACCESS_FAULT: u64 = 7; // store/AMO page fault

/// riscv64 synchronous-exception trap frame.
///
/// Populated by the arch trap entry from `stval` and `scause`. `stval` holds
/// the faulting virtual address; `scause` holds the exception cause register.
/// `decode_fault` is invoked with synchronous-exception frames only (the arch
/// entry routes interrupts separately), so bit 63 of scause is always 0 here.
#[repr(C)]
pub struct Riscv64TrapFrame {
    /// Faulting virtual address (`stval`).
    pub stval: u64,
    /// Exception cause register (`scause`).
    pub scause: u64,
}

impl ArchFrame for Riscv64TrapFrame {
    fn fault_addr(&self) -> u64 {
        self.stval
    }

    fn err_code(&self) -> u32 {
        self.scause as u32
    }
}

pub struct TrapDecodeRiscv64;

impl Default for TrapDecodeRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl TrapDecode for TrapDecodeRiscv64 {
    /// Decode a synchronous-exception frame into `(fault_addr, access_kind)`.
    /// Returns `None` when the cause is not a page-fault exception
    /// (e.g. an illegal instruction, environment call, or breakpoint).
    ///
    /// # Safety
    ///
    /// Reads raw CPU state from the trap frame; safe when called from the arch
    /// trap entry with a valid frame pointer.
    unsafe fn decode_fault(&self, frame: &dyn ArchFrame) -> Option<(u64, AccessKind)> {
        let addr = frame.fault_addr();
        let cause = frame.err_code() as u64;

        let kind = match cause {
            EXC_INSTR_ACCESS_FAULT => AccessKind::EXEC,
            EXC_LOAD_ACCESS_FAULT => AccessKind::READ,
            EXC_STORE_ACCESS_FAULT => AccessKind::WRITE,
            _ => return None,
        };

        Some((addr, kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(scause: u64, stval: u64) -> Riscv64TrapFrame {
        Riscv64TrapFrame { stval, scause }
    }

    #[test]
    fn load_access_fault_is_read() {
        let decoder = TrapDecodeRiscv64::default();
        let tf = frame(EXC_LOAD_ACCESS_FAULT, 0x_0000_AAAA_0000_1000);
        let (addr, kind) = unsafe { decoder.decode_fault(&tf).expect("load fault decodes") };
        assert_eq!(addr, 0x_0000_AAAA_0000_1000);
        assert!(kind.contains(AccessKind::READ));
        assert!(!kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::EXEC));
    }

    #[test]
    fn store_access_fault_is_write() {
        let decoder = TrapDecodeRiscv64::default();
        let tf = frame(EXC_STORE_ACCESS_FAULT, 0x_4000);
        let (_, kind) = unsafe { decoder.decode_fault(&tf).expect("store fault decodes") };
        assert!(kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::READ));
    }

    #[test]
    fn instr_access_fault_is_exec() {
        let decoder = TrapDecodeRiscv64::default();
        let tf = frame(EXC_INSTR_ACCESS_FAULT, 0x_8000);
        let (_, kind) = unsafe { decoder.decode_fault(&tf).expect("instr fault decodes") };
        assert!(kind.contains(AccessKind::EXEC));
        assert!(!kind.contains(AccessKind::READ));
        assert!(!kind.contains(AccessKind::WRITE));
    }

    #[test]
    fn non_page_fault_cause_is_none() {
        let decoder = TrapDecodeRiscv64::default();
        // illegal instruction (2), breakpoint (3), env call from U-mode (8)
        // are not page faults.
        for cause in [2u64, 3, 8] {
            let tf = frame(cause, 0);
            assert!(unsafe { decoder.decode_fault(&tf) }.is_none());
        }
    }
}
