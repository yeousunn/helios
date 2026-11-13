//! aarch64 trap decode (ADR-012).
//! Decodes aarch64 synchronous-exception trap frames into kernel-understandable
//! fault reports: the faulting virtual address (FAR_EL1) and the access kind
//! (read/write/exec) decoded from ESR_EL1.
//!
//! The faulting address is returned as a raw `u64` because `hal` cannot depend
//! on `kernel`; the arch entry converts it to `kernel::aspace::Vaddr` before
//! calling `kernel::fault::handle_page_fault`.

#![allow(dead_code)]

use hal::{AccessKind, ArchFrame, TrapDecode};

// ESR_EL1 [31:26] = Exception Class (EC) for synchronous exceptions taken
// from the current or a lower EL.
const ESR_EC_SHIFT: u32 = 26;
const ESR_EC_MASK: u32 = 0x3F << ESR_EC_SHIFT;
/// WnR bit: 1 = the faulting access was a write, 0 = a read (data aborts).
const ESR_WNR: u32 = 1 << 6;

const EC_INST_ABORT_SAME: u32 = 0x20; // instruction abort, same EL
const EC_INST_ABORT_LOWER: u32 = 0x24; // instruction abort, from lower EL
const EC_DATA_ABORT_SAME: u32 = 0x28; // data abort, same EL
const EC_DATA_ABORT_LOWER: u32 = 0x2C; // data abort, from lower EL

/// aarch64 synchronous-exception trap frame.
///
/// Populated by the arch trap entry from the saved general-purpose registers
/// and the `FAR_EL1` / `ESR_EL1` system registers. `far` holds the faulting
/// virtual address; `esr` holds the exception syndrome register.
#[repr(C)]
pub struct AArch64TrapFrame {
    /// Faulting virtual address (`FAR_EL1`).
    pub far: u64,
    /// Exception syndrome register (`ESR_EL1`).
    pub esr: u32,
}

impl ArchFrame for AArch64TrapFrame {
    fn fault_addr(&self) -> u64 {
        self.far
    }

    fn err_code(&self) -> u32 {
        self.esr
    }
}

pub struct TrapDecodeAarch64;

impl Default for TrapDecodeAarch64 {
    fn default() -> Self {
        Self
    }
}

impl TrapDecode for TrapDecodeAarch64 {
    /// Decode a synchronous exception frame into `(fault_addr, access_kind)`.
    /// Returns `None` when the exception is not a synchronous abort (e.g. an
    /// IRQ, FIQ, SError or BRK), in which case the fault is not a page fault.
    ///
    /// # Safety
    ///
    /// Reads raw CPU state from the trap frame; safe when called from the arch
    /// trap entry with a valid frame pointer.
    unsafe fn decode_fault(&self, frame: &dyn ArchFrame) -> Option<(u64, AccessKind)> {
        let addr = frame.fault_addr();
        let esr = frame.err_code();
        let ec = (esr & ESR_EC_MASK) >> ESR_EC_SHIFT;

        let kind = match ec {
            EC_INST_ABORT_SAME | EC_INST_ABORT_LOWER => AccessKind::EXEC,
            EC_DATA_ABORT_SAME | EC_DATA_ABORT_LOWER => {
                if esr & ESR_WNR != 0 {
                    AccessKind::WRITE
                } else {
                    AccessKind::READ
                }
            }
            _ => return None,
        };

        Some((addr, kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(esr: u32, far: u64) -> AArch64TrapFrame {
        AArch64TrapFrame { far, esr }
    }

    fn data_abort(wnr: bool) -> u32 {
        (EC_DATA_ABORT_SAME << ESR_EC_SHIFT) | if wnr { ESR_WNR } else { 0 }
    }

    #[test]
    fn data_abort_read_is_read() {
        let decoder = TrapDecodeAarch64::default();
        let tf = frame(data_abort(false), 0x_0000_AAAA_0000_1000);
        let (addr, kind) = unsafe { decoder.decode_fault(&tf).expect("data abort decodes") };
        assert_eq!(addr, 0x_0000_AAAA_0000_1000);
        assert!(kind.contains(AccessKind::READ));
        assert!(!kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::EXEC));
    }

    #[test]
    fn data_abort_write_is_write() {
        let decoder = TrapDecodeAarch64::default();
        let tf = frame(data_abort(true), 0x_4000);
        let (_, kind) = unsafe { decoder.decode_fault(&tf).expect("data abort decodes") };
        assert!(kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::READ));
    }

    #[test]
    fn instruction_abort_is_exec() {
        let decoder = TrapDecodeAarch64::default();
        let tf = frame(EC_INST_ABORT_SAME << ESR_EC_SHIFT, 0x_8000);
        let (_, kind) = unsafe {
            decoder
                .decode_fault(&tf)
                .expect("instruction abort decodes")
        };
        assert!(kind.contains(AccessKind::EXEC));
        assert!(!kind.contains(AccessKind::READ));
        assert!(!kind.contains(AccessKind::WRITE));
    }

    #[test]
    fn non_abort_exception_is_none() {
        let decoder = TrapDecodeAarch64::default();
        // EC = 0x00 (unknown) / 0x01 (WFI/WFE) / 0x06 (BRK) — not a page fault.
        for esr in [
            0x00 << ESR_EC_SHIFT,
            0x01 << ESR_EC_SHIFT,
            0x06 << ESR_EC_SHIFT,
        ] {
            let tf = frame(esr, 0);
            assert!(unsafe { decoder.decode_fault(&tf) }.is_none());
        }
    }
}
