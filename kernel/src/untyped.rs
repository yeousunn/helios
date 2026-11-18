//! Untyped memory (RFC-0001 §4.1.1, M1; ADR-064 as corrected by ADR-088 and
//! implemented per ADR-103): raw physical memory as a kernel object — the
//! only source of kernel memory. A Retype charges the source Untyped for the
//! kernel state a created object occupies and shrinks it in place.
//!
//! v0: object STATE still lives in the kernel's const-staged engine pools
//! (ADR-037 am2); the charge is the accounting move (the principal pays for
//! kernel state, PLAN.md principle 3). Physically carving object storage out
//! of the Untyped's range is the M1a2/b rework.
//!
//! Same-Untyped carving is ordered by construction: syscalls run to
//! completion on the single v0 core, so the validate-then-apply sequence
//! across the flat (non-nested) untyped/endpoint/notification locks cannot
//! interleave (ADR-103 §6). The apply re-validates anyway and the Retype
//! caller rolls the created object back if it ever fires.
#![forbid(unsafe_code)]

use caps::ObjId;
use core::fmt;
use spin::Mutex;

/// Untyped object ids start here. Every other id space sits far below 4 GiB
/// (pool-slot ids 1..=256, Region 0x100+, AS slot+1, Frame ids = physical
/// addresses) and `objreg` keys by `ObjId` alone — a disjoint base keeps
/// them from ever overlapping.
const ID_BASE: u64 = 0x1_0000_0000;

/// v0 table bound. M1's exit removes fixed limits; until then this bounds
/// how many distinct Untyped objects can exist (one per boot region at
/// M1a2, plus carved Untypeds once Retype targets Untyped — it does not:
/// 8 is excluded from the M1 target set).
const MAX_UNTYPED: usize = 32;

/// One Untyped object (RFC-0001 §4.1.1): a physical range with `size` bytes
/// remaining. `carve` advances `base` and shrinks `size` in place
/// (RFC-0001 §4.1.2); a depleted entry (size 0) stays registered — see
/// ADR-103 §5 for why the cap is not deleted until the derivation tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Untyped {
    pub base: u64,
    pub size: u64,
    /// NUMA node (v0: single node 0). Carved objects inherit it (ADR-088:
    /// RFC-0001's w3 was dropped — the source's node/tier is the child's).
    pub node: u16,
    /// Memory tier (v0: 0 = DRAM).
    pub tier: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UntypedError {
    TableFull,
    NoSuchUntyped,
    Depleted,
    RangeOverflow,
}

impl fmt::Display for UntypedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The M1 retype target set (RFC-0001 §4.1.2; the spec/abi FACTORY_RETYPE
/// `target_type` description is normative): wire discriminants from
/// `spec/abi::capability::ObjType`. Excluded: None (0), Irq (6), Untyped
/// (8 — a source, never a target), Reply (14), Factory (15), Any (0xFF).
/// Discriminant identity with `caps::ObjType` is pinned by a kernel test.
pub const M1_TARGET_SET: &[u64] = &[
    helios_abi::ObjType::Endpoint as u64,
    helios_abi::ObjType::Notification as u64,
    helios_abi::ObjType::AddressSpace as u64,
    helios_abi::ObjType::Thread as u64,
    helios_abi::ObjType::Frame as u64,
    helios_abi::ObjType::CNode as u64,
    helios_abi::ObjType::Region as u64,
    helios_abi::ObjType::SchedContext as u64,
    helios_abi::ObjType::Domain as u64,
    helios_abi::ObjType::IOSpace as u64,
    helios_abi::ObjType::CoreGrant as u64,
    helios_abi::ObjType::Port as u64,
    helios_abi::ObjType::Ring as u64,
];

struct Table {
    slots: [Option<Untyped>; MAX_UNTYPED],
}

/// Const-staged in .bss (ADR-037 am2: large tables are const statics, never
/// stack values).
static TABLE: Mutex<Option<Table>> = Mutex::new(Some(Table {
    slots: [const { None }; MAX_UNTYPED],
}));

fn with_table<T>(
    f: impl FnOnce(&mut [Option<Untyped>; MAX_UNTYPED]) -> Result<T, UntypedError>,
) -> Result<T, UntypedError> {
    let mut guard = TABLE.lock();
    let Some(t) = guard.as_mut() else {
        return Err(UntypedError::NoSuchUntyped);
    };
    f(&mut t.slots)
}

/// Create an Untyped object over `[base, base + size)` owned by `owner`;
/// returns its ObjId. The object registers in the objreg under `owner` so
/// owner-death cleanup frees the table slot (ADR-103). The physical range
/// is NOT verified against the frame allocator here — the boot path (M1a2)
/// hands out ranges it already owns; Retype never targets Untyped, so no
/// other creator exists.
pub fn create(
    base: u64,
    size: u64,
    node: u16,
    tier: u8,
    owner: crate::objreg::ProcessId,
) -> Result<ObjId, UntypedError> {
    if size == 0 {
        return Err(UntypedError::RangeOverflow);
    }
    base.checked_add(size).ok_or(UntypedError::RangeOverflow)?;
    let obj = with_table(|slots| {
        let slot = slots
            .iter()
            .position(|s| s.is_none())
            .ok_or(UntypedError::TableFull)?;
        slots[slot] = Some(Untyped {
            base,
            size,
            node,
            tier,
        });
        Ok(ObjId(ID_BASE + slot as u64))
    })?;
    crate::objreg::register(obj, caps::ObjType::Untyped, owner);
    Ok(obj)
}

/// Free an Untyped object's table slot (owner-death cleanup, syscall exit).
pub fn destroy(obj: ObjId) {
    let _ = with_table(|slots| {
        if let Some(slot) = slot_of(obj) {
            slots[slot] = None;
        }
        Ok(())
    });
}

fn slot_of(obj: ObjId) -> Option<usize> {
    if obj.0 < ID_BASE {
        return None;
    }
    let off = (obj.0 - ID_BASE) as usize;
    if off < MAX_UNTYPED {
        Some(off)
    } else {
        None
    }
}

/// Bytes remaining in `obj` (`NoSuchUntyped` = a foreign/dead Untyped id —
/// no table entry).
pub fn remaining(obj: ObjId) -> Result<u64, UntypedError> {
    with_table(|slots| {
        let slot = slot_of(obj).ok_or(UntypedError::NoSuchUntyped)?;
        slots[slot]
            .as_ref()
            .map(|u| u.size)
            .ok_or(UntypedError::NoSuchUntyped)
    })
}

/// Current (base, size, node, tier) of `obj`.
pub fn state(obj: ObjId) -> Result<Untyped, UntypedError> {
    with_table(|slots| {
        let slot = slot_of(obj).ok_or(UntypedError::NoSuchUntyped)?;
        slots[slot].ok_or(UntypedError::NoSuchUntyped)
    })
}

/// Charge `bytes` against `obj`: advance `base`, shrink `size` in place
/// (RFC-0001 §4.1.2). Returns the remaining size. `Depleted` (and no state
/// change) when fewer bytes remain than requested.
pub fn carve(obj: ObjId, bytes: u64) -> Result<u64, UntypedError> {
    with_table(|slots| {
        let slot = slot_of(obj).ok_or(UntypedError::NoSuchUntyped)?;
        let u = slots[slot].as_mut().ok_or(UntypedError::NoSuchUntyped)?;
        if bytes == 0 || u.size < bytes {
            return Err(UntypedError::Depleted);
        }
        u.base = u
            .base
            .checked_add(bytes)
            .ok_or(UntypedError::RangeOverflow)?;
        u.size -= bytes;
        Ok(u.size)
    })
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    if let Some(t) = TABLE.lock().as_mut() {
        t.slots = [const { None }; MAX_UNTYPED];
    }
}

#[cfg(test)]
pub(crate) fn create_for_test(base: u64, size: u64, owner: crate::objreg::ProcessId) -> ObjId {
    create(base, size, 0, 0, owner).expect("test Untyped")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_carve_deplete_lifecycle() {
        reset_for_test();
        crate::objreg::reset_for_test();
        let base = 0x2000_0000;
        let obj = create_for_test(base, 4096, caps::ObjId(1));
        assert!(
            crate::objreg::is_alive(obj),
            "creation registers the object for owner tracking"
        );
        assert_eq!(obj.0 & ID_BASE, ID_BASE, "ids live in the reserved range");
        let u = state(obj).unwrap();
        assert_eq!((u.base, u.size, u.node, u.tier), (base, 4096, 0, 0));

        assert_eq!(carve(obj, 1000).unwrap(), 3096);
        let u = state(obj).unwrap();
        assert_eq!(u.base, base + 1000, "base advances in place");
        assert_eq!(u.size, 3096);

        assert_eq!(carve(obj, 3096).unwrap(), 0, "exact depletion");
        assert_eq!(carve(obj, 1), Err(UntypedError::Depleted));
        assert_eq!(
            carve(obj, 0),
            Err(UntypedError::Depleted),
            "0 is never a charge"
        );
        assert_eq!(
            state(obj).unwrap().size,
            0,
            "depleted entry stays registered"
        );

        destroy(obj);
        assert_eq!(state(obj), Err(UntypedError::NoSuchUntyped));
    }

    #[test]
    fn foreign_ids_and_overflow_are_rejected() {
        reset_for_test();
        crate::objreg::reset_for_test();
        let obj = create_for_test(0x1000, 0x2000, caps::ObjId(1));
        // A non-Untyped id (small pool-slot range) never matches a slot.
        assert_eq!(remaining(ObjId(7)), Err(UntypedError::NoSuchUntyped));
        // carve past the end leaves the state untouched.
        assert_eq!(carve(obj, 0x2001), Err(UntypedError::Depleted));
        assert_eq!(state(obj).unwrap().size, 0x2000);
        // Zero-size and base+size overflow are rejected at creation.
        assert_eq!(
            create(0x5000, 0, 0, 0, caps::ObjId(1)),
            Err(UntypedError::RangeOverflow)
        );
        assert_eq!(
            create(u64::MAX - 1, 4, 0, 0, caps::ObjId(1)),
            Err(UntypedError::RangeOverflow)
        );
    }

    #[test]
    fn table_is_bounded() {
        reset_for_test();
        crate::objreg::reset_for_test();
        let mut first = ObjId(0);
        for i in 0..MAX_UNTYPED {
            let id = create_for_test(0x3000_0000, 16, caps::ObjId(1));
            if i == 0 {
                first = id;
            }
        }
        assert_eq!(
            create(0x3000_0000, 16, 0, 0, caps::ObjId(1)),
            Err(UntypedError::TableFull),
            "v0 table bound (M1 removes fixed limits)"
        );
        // Freeing one slot makes room again.
        destroy(first);
        assert!(create(0x3000_0000, 16, 0, 0, caps::ObjId(1)).is_ok());
    }

    #[test]
    fn owner_retire_frees_the_table_slot() {
        reset_for_test();
        crate::objreg::reset_for_test();
        let pid = caps::ObjId(1);
        let obj = create_for_test(0x6000_0000, 128, pid);
        crate::objreg::retire_owner(pid);
        assert!(
            !crate::objreg::is_alive(obj),
            "the objreg marks the dead owner's Untyped dead"
        );
        destroy(obj);
        assert_eq!(state(obj), Err(UntypedError::NoSuchUntyped));
    }
}
