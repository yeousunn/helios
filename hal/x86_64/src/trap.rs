//! x86_64 trap decode (ADR-012).
//! Decodes x86_64 page-fault trap frames into kernel-understandable fault
//! reports: faulting linear address (CR2) and access kind (error code bits).
//!
//! The faulting address is returned as a raw `u64` because `hal` cannot
//! depend on `kernel`; the arch entry converts it to
//! `kernel::aspace::Vaddr` before calling `kernel::fault::handle_page_fault`.

#![allow(dead_code)]

use hal::{AccessKind, ArchFrame, TrapDecode};

/// x86_64 page-fault error code bits.
const PF_ERR_WR: u32 = 1 << 1; // 0 = read, 1 = write
const PF_ERR_ID: u32 = 1 << 4; // 0 = data access, 1 = instruction fetch

/// x86_64 trap frame as pushed by the #PF IDT handler.
///
/// The arch trap entry pushes registers and passes a pointer here to
/// [`TrapDecode::decode_fault`]. Layout matches the CPU's automatic error-code
/// push plus the general-purpose register save area.
#[repr(C)]
pub struct X86_64TrapFrame {
    /// Hardware-pushed error code (#PF specific).
    pub err_code: u32,
    _pad0: u32,
    /// Hardware-pushed RIP (faulting instruction pointer).
    pub rip: u64,
    /// Hardware-pushed CS.
    pub cs: u64,
    /// Hardware-pushed RFLAGS.
    pub rflags: u64,
    /// Hardware-pushed RSP (faulting stack pointer).
    pub rsp: u64,
    /// Hardware-pushed SS.
    pub ss: u64,
    /// General-purpose registers (saved by the arch asm trampoline).
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp2: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// x86_64 trap decoder: reads CR2 (faulting linear address) and decodes the
/// #PF error code into an [`AccessKind`].
pub struct TrapDecodeX86_64;

impl Default for TrapDecodeX86_64 {
    fn default() -> Self {
        Self
    }
}

impl ArchFrame for X86_64TrapFrame {
    fn fault_addr(&self) -> u64 {
        // SAFETY: `mov cr2, rax` reads the faulting linear address register;
        // safe in kernel context.
        let cr2: u64;
        unsafe {
            core::arch::asm!("mov {0}, cr2", out(reg) cr2, options(nostack, readonly));
        }
        cr2
    }

    fn err_code(&self) -> u32 {
        self.err_code
    }
}

impl TrapDecode for TrapDecodeX86_64 {
    unsafe fn decode_fault(&self, frame: &dyn ArchFrame) -> Option<(u64, AccessKind)> {
        let addr = frame.fault_addr();
        let err = frame.err_code();

        // Decode #PF error code into an AccessKind.
        let mut kind = AccessKind(0);
        if err & PF_ERR_WR != 0 {
            kind = kind.union(AccessKind::WRITE);
        } else {
            kind = kind.union(AccessKind::READ);
        }
        if err & PF_ERR_ID != 0 {
            kind = kind.union(AccessKind::EXEC);
        }

        Some((addr, kind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_kind_bits() {
        assert!(AccessKind::READ.contains(AccessKind::READ));
        assert!(!AccessKind::READ.contains(AccessKind::WRITE));
        assert!(AccessKind::READ
            .union(AccessKind::WRITE)
            .contains(AccessKind::READ));
        assert!(AccessKind::READ
            .union(AccessKind::WRITE)
            .contains(AccessKind::WRITE));
    }

    #[test]
    fn pf_err_decoding() {
        let decoder = TrapDecodeX86_64::default();

        // Not-present, read, supervisor, data.
        let tf = X86_64TrapFrame {
            err_code: 0,
            _pad0: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp2: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        let result = unsafe { decoder.decode_fault(&tf) };
        assert!(result.is_some());
        let (_, kind) = result.unwrap();
        assert!(kind.contains(AccessKind::READ));
        assert!(!kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::EXEC));

        // Write fault.
        let tf = X86_64TrapFrame {
            err_code: PF_ERR_WR,
            _pad0: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp2: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        let result = unsafe { decoder.decode_fault(&tf) };
        let (_, kind) = result.unwrap();
        assert!(kind.contains(AccessKind::WRITE));
        assert!(!kind.contains(AccessKind::READ));

        // Instruction fetch fault.
        let tf = X86_64TrapFrame {
            err_code: PF_ERR_ID,
            _pad0: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp2: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        let result = unsafe { decoder.decode_fault(&tf) };
        let (_, kind) = result.unwrap();
        assert!(kind.contains(AccessKind::EXEC));
    }
}
