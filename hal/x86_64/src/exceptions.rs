//! Exception gate stubs (bring-up safety net): any fault or unexpected
//! interrupt reports vector/error/CR2/RIP over the UART and halts, instead of
//! triple-faulting silently.

use core::arch::global_asm;

global_asm!(include_str!("exceptions.S"));

macro_rules! stubs {
    ($($vec:literal => $name:ident),+ $(,)?) => {
        extern "C" {
            $( fn $name(); )+
        }

        /// Address of the stub for `vector` (None beyond the installed set).
        pub fn stub_addr(vector: u8) -> Option<u64> {
            Some(match vector {
                $( $vec => $name as *const () as u64, )+
                _ => return None,
            })
        }
    };
}

stubs! {
    0 => exc_stub_0,   1 => exc_stub_1,   2 => exc_stub_2,   3 => exc_stub_3,
    4 => exc_stub_4,   5 => exc_stub_5,   6 => exc_stub_6,   7 => exc_stub_7,
    8 => exc_stub_8,   9 => exc_stub_9,   10 => exc_stub_10, 11 => exc_stub_11,
    12 => exc_stub_12, 13 => exc_stub_13, 14 => exc_stub_14, 15 => exc_stub_15,
    16 => exc_stub_16, 17 => exc_stub_17, 18 => exc_stub_18, 19 => exc_stub_19,
    20 => exc_stub_20, 21 => exc_stub_21, 22 => exc_stub_22, 23 => exc_stub_23,
    24 => exc_stub_24, 25 => exc_stub_25, 26 => exc_stub_26, 27 => exc_stub_27,
    28 => exc_stub_28, 29 => exc_stub_29, 30 => exc_stub_30, 31 => exc_stub_31,
    32 => exc_stub_32, 33 => exc_stub_33, 34 => exc_stub_34, 35 => exc_stub_35,
    36 => exc_stub_36, 37 => exc_stub_37, 38 => exc_stub_38, 39 => exc_stub_39,
    40 => exc_stub_40, 41 => exc_stub_41, 42 => exc_stub_42, 43 => exc_stub_43,
    44 => exc_stub_44, 45 => exc_stub_45, 46 => exc_stub_46, 47 => exc_stub_47,
}

/// Called from `exc_common` (SysV64: rdi=vector, rsi=error, rdx=cr2,
/// rcx=rip, r8=cs). Reports and halts; never returns.
#[no_mangle]
extern "sysv64" fn exception_report(vector: u64, error: u64, cr2: u64, rip: u64, cs: u64) -> ! {
    kernel::kerror!(
        "EXCEPTION: vector={} error={:#x} cr2={:#x} rip={:#x} cs={:#x}",
        vector,
        error,
        cr2,
        rip,
        cs
    );
    if rip != 0 {
        // SAFETY: diagnostic read of the (mapped, faulting) code page; the
        // CPU halts right after, so a secondary fault here is fatal anyway.
        let bytes = unsafe { core::ptr::read_unaligned(rip as *const [u8; 8]) };
        kernel::kerror!(
            "  code@rip: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7]
        );
    }
    loop {
        // SAFETY: stopping the CPU after a fatal exception report.
        unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)) };
    }
}
