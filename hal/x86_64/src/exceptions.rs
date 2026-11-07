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

extern "C" {
    fn irq_stub_32();
    fn irq_stub_33();
    fn irq_stub_34();
    fn irq_stub_35();
    fn irq_stub_36();
    fn irq_stub_37();
    fn irq_stub_38();
    fn irq_stub_39();
    fn irq_stub_40();
    fn irq_stub_41();
    fn irq_stub_42();
    fn irq_stub_43();
    fn irq_stub_44();
    fn irq_stub_45();
    fn irq_stub_46();
    fn irq_stub_47();
}

/// IRQ gate stubs (vectors 32..47): iretq-capable interrupt entries.
pub fn irq_stub_addr(vector: u8) -> Option<u64> {
    Some(match vector {
        32 => irq_stub_32 as *const () as u64,
        33 => irq_stub_33 as *const () as u64,
        34 => irq_stub_34 as *const () as u64,
        35 => irq_stub_35 as *const () as u64,
        36 => irq_stub_36 as *const () as u64,
        37 => irq_stub_37 as *const () as u64,
        38 => irq_stub_38 as *const () as u64,
        39 => irq_stub_39 as *const () as u64,
        40 => irq_stub_40 as *const () as u64,
        41 => irq_stub_41 as *const () as u64,
        42 => irq_stub_42 as *const () as u64,
        43 => irq_stub_43 as *const () as u64,
        44 => irq_stub_44 as *const () as u64,
        45 => irq_stub_45 as *const () as u64,
        46 => irq_stub_46 as *const () as u64,
        47 => irq_stub_47 as *const () as u64,
        _ => return None,
    })
}

/// Called from `exc_common` (SysV64: rdi=vector, rsi=error, rdx=cr2,
/// rcx=rip, r8=cs). Reports and halts; never returns.
#[no_mangle]
extern "sysv64" fn exception_report(vector: u64, error: u64, cr2: u64, rip: u64, cs: u64) -> ! {
    let cr3: u64;
    // SAFETY: reading CR3 in the fatal handler.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)) };
    kernel::kerror!(
        "EXCEPTION: vector={} error={:#x} cr2={:#x} rip={:#x} cs={:#x} cr3={:#x}",
        vector,
        error,
        cr2,
        rip,
        cs,
        cr3
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
    if vector == 14 {
        // Registry↔hardware PTE discriminator (clobber hunt): for page
        // faults, walk the CURRENT AS root's hardware PTE for cr2 and print
        // it next to the kernel registry's view. CR3 identifies the active
        // AS root directly (roots are physical PML4 addresses).
        if let Some(pa) = crate::paging::probe_walk(cr3 as usize, cr2) {
            kernel::kerror!("  pte@cr2: hw-physical={:#x} (present)", pa);
        } else {
            kernel::kerror!("  pte@cr2: hw=NOT-PRESENT (cr3={:#x})", cr3);
        }
        // Full 4-level chain dump: which level is missing and which frames
        // are involved (soft/hardware divergence diagnosis — found the
        // flag-only PTE write class this way).
        {
            let shifts = [39u64, 30, 21, 12];
            let names = ["pml4", "pdpt", "pd", "pt"];
            let mut tbl = cr3 & !0xFFF;
            for (lvl, sh) in shifts.iter().enumerate() {
                let idx = (cr2 >> sh) & 0x1FF;
                let va = kernel::mem::phys_to_virt(tbl) + idx * 8;
                let ent = unsafe { core::ptr::read_volatile(va as *const u64) };
                kernel::kerror!(
                    "  chain {}: tbl={:#x} idx={} ent={:#x}",
                    names[lvl],
                    tbl,
                    idx,
                    ent
                );
                if ent & 1 == 0 {
                    break;
                }
                tbl = ent & !0xFFF;
            }
        }
        // Root cross-check: walk AS 1's REGISTERED root for cr2 — if it is
        // present there but not under the live CR3, the activation path is
        // loading the wrong root; if both are absent, the backend install
        // never landed (or was cleared).
        if let Some(root1) = crate::paging::root_of(1) {
            kernel::kerror!("  as1-root={:#x} live-cr3={:#x}", root1 as u64, cr3);
            match crate::paging::probe_walk(root1, cr2) {
                Some(pa) => {
                    kernel::kerror!("  pte@cr2 via as1-root: PRESENT phys={:#x}", pa)
                }
                None => kernel::kerror!("  pte@cr2 via as1-root: NOT-PRESENT"),
            }
        } else {
            kernel::kerror!("  as1-root: not registered");
        }
        // Kernel registry view (translate) for the same address.
        let pid = kernel::proc::from_ref(kernel::sched::ObjRef(kernel::sched::current().0));
        match kernel::proc::as_of(pid) {
            Some(as_id) => match kernel::aspace::translate(as_id, kernel::aspace::Vaddr(cr2)) {
                Ok((pa, fl)) => kernel::kerror!(
                    "  registry@cr2: as={} -> phys={:#x} flags={}",
                    as_id.0,
                    pa.as_u64(),
                    fl
                ),
                Err(e) => kernel::kerror!(
                    "  registry@cr2: as={} -> {:?} (registry/hardware DIVERGE if hw present)",
                    as_id.0,
                    e
                ),
            },
            None => kernel::kerror!("  registry@cr2: current thread has NO recorded AS"),
        }
    }
    loop {
        // SAFETY: stopping the CPU after a fatal exception report.
        unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)) };
    }
}
