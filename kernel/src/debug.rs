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
