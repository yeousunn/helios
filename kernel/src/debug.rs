//! Bring-up debug facility (temporary, clobber-hunt): registered hardware
//! page-walk + registry cross-print. Removed once the VFS smoke converges.
#![forbid(unsafe_code)]

use crate::aspace::{self, Vaddr};
use spin::Mutex;

type HwWalker = fn(vaddr: u64) -> Option<u64>;

static HW_WALKER: Mutex<Option<HwWalker>> = Mutex::new(None);

/// Register the arch hardware page-walker (hal boot; reads the live CR3
/// root through the identity map).
pub fn set_hw_walker(f: HwWalker) {
    *HW_WALKER.lock() = Some(f);
}

/// Debug-EP op (label `0xFFFE`): sweep the caller's whole user stack —
/// 16 pages below USER_STACK_TOP — hardware + registry, one line per page.
/// Catches vanishing stack PTEs regardless of depth (the page-15-only probe
/// missed page-14 loss, DS bisect m90+).
pub fn debug_stack_sweep() {
    let (pid, _tid) = (
        crate::proc::from_ref(crate::sched::ObjRef(crate::sched::current().0)),
        (),
    );
    let as_id = crate::proc::as_of(pid);
    let top = 0x0000_7FFF_FFFF_F000u64;
    for i in 0..16u64 {
        let va = top - (i + 1) * 4096;
        let hw = HW_WALKER.lock().as_ref().and_then(|f| f(va));
        let reg = as_id.and_then(|a| aspace::translate(a, Vaddr(va)).ok());
        match (hw, reg) {
            (Some(pa), Some((rpa, fl))) => crate::kinfo!(
                "SWEEP p{} va={:#x} hw=phys {:#x} reg=phys {:#x} {}",
                15 - i,
                va,
                pa,
                rpa.as_u64(),
                fl
            ),
            (Some(pa), None) => crate::kinfo!(
                "SWEEP p{} va={:#x} hw=phys {:#x} reg=unmapped",
                15 - i,
                va,
                pa
            ),
            (None, Some((rpa, fl))) => crate::kinfo!(
                "SWEEP p{} va={:#x} hw=NOT-PRESENT reg=phys {:#x} {}",
                15 - i,
                va,
                rpa.as_u64(),
                fl
            ),
            (None, None) => {
                crate::kinfo!("SWEEP p{} va={:#x} hw=NOT-PRESENT reg=unmapped", 15 - i, va)
            }
        }
    }
}

/// Debug-EP op (label `0xFFFF`): walk `w0` for the CURRENT process's AS —
/// hardware view + kernel registry view, one line each.
pub fn debug_walk(va: u64) {
    let (pid, _tid) = (
        crate::proc::from_ref(crate::sched::ObjRef(crate::sched::current().0)),
        (),
    );
    match HW_WALKER.lock().as_ref().map(|f| f(va)) {
        Some(Some(pa)) => crate::kinfo!("WALK va={:#x} hw=phys {:#x}", va, pa),
        Some(None) => crate::kinfo!("WALK va={:#x} hw=NOT-PRESENT", va),
        None => crate::kinfo!("WALK va={:#x} hw-walker: not registered", va),
    }
    match crate::proc::as_of(pid) {
        Some(as_id) => match aspace::translate(as_id, Vaddr(va)) {
            Ok((pa, fl)) => crate::kinfo!(
                "WALK va={:#x} registry as={} phys={:#x} flags={}",
                va,
                as_id.0,
                pa.as_u64(),
                fl
            ),
            Err(e) => crate::kinfo!("WALK va={:#x} registry as={} -> {:?}", va, as_id.0, e),
        },
        None => crate::kinfo!("WALK va={:#x} registry: no AS for current process", va),
    }
}
