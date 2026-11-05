//! Capability types and tables (ADR-004, amended by ADR-005). Authority in
//! Helios is entirely capability-based: unforgeable, delegable, revocable.
//!
//! `Rights` is the canonical wire vocabulary from `ipc/` (re-exported here).
//! Wire handles (`u32`, 0 = null) map to slots as `handle = slot + 1`; the
//! kernel owns that mapping, this table is 0-based.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

pub use ipc::Rights;

/// Identifies a kernel object (endpoint, thread, address space, ...).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjId(pub u64);

/// The kind of object a capability grants authority over.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Factory,
    Endpoint,
    Notification,
    AddressSpace,
    Thread,
    Frame,
    Irq,
    Region,
}

/// An unforgeable token granting `rights` over the object `obj`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Capability {
    pub obj: ObjId,
    pub typ: ObjType,
    pub rights: Rights,
}

/// Index of a slot inside a `CapTable`.
pub type SlotIdx = usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Slot {
    Free {
        next_free: SlotIdx,
    },
    Occupied {
        cap: Capability,
        parent: Option<SlotIdx>,
    },
}

/// Fixed-capacity capability table with a free list.
pub struct CapTable {
    slots: [Slot; MAX_SLOTS],
    free_head: SlotIdx,
    used: usize,
}

const MAX_SLOTS: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    TableFull,
    SlotEmpty,
    SlotOccupied,
    BadSlot,
    MissingGrantRight,
    RightsNotSubset,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

type Result<T> = core::result::Result<T, CapError>;

impl CapTable {
    /// Fully-initialized empty table, evaluable at compile time so statics
    /// never build large temporaries on the stack.
    pub const fn empty() -> Self {
        let mut slots = [Slot::Free { next_free: 0 }; MAX_SLOTS];
        let mut i = 0;
        while i < MAX_SLOTS {
            slots[i] = Slot::Free {
                next_free: if i + 1 == MAX_SLOTS { MAX_SLOTS } else { i + 1 },
            };
            i += 1;
        }
        CapTable {
            slots,
            free_head: 0,
            used: 0,
        }
    }

    pub fn new() -> Self {
        Self::empty()
    }

    /// Reset to empty, in place. The assignment `table = CapTable::empty()`
    /// materializes a ~32 KiB temporary in the caller's stack frame (LLVM
    /// builds the return value, then memcpy's it) — which exactly overran
    /// the 32 KiB kernel stack in `proc::create` and wrote stack-probe
    /// stores into the page tables below (the "0x2-into-a-PTE" clobber
    /// family, DS bisect 2026-11-05). Capabilities are plain data (no
    /// `Drop`), so an in-place reset is semantically identical.
    pub fn clear(&mut self) {
        let mut i = 0;
        while i < MAX_SLOTS {
            self.slots[i] = Slot::Free {
                next_free: if i + 1 == MAX_SLOTS { MAX_SLOTS } else { i + 1 },
            };
            i += 1;
        }
        self.free_head = 0;
        self.used = 0;
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Insert a fresh capability (no parent) at the first free slot.
    /// Used by the kernel when minting initial authority for a new process.
    pub fn insert(&mut self, cap: Capability) -> Result<SlotIdx> {
        if self.free_head == MAX_SLOTS {
            return Err(CapError::TableFull);
        }
        let idx = self.free_head;
        match self.slots[idx] {
            Slot::Free { next_free } => self.free_head = next_free,
            Slot::Occupied { .. } => unreachable!("free list invariant"),
        }
        self.slots[idx] = Slot::Occupied { cap, parent: None };
        self.used += 1;
        Ok(idx)
    }

    /// Insert a fresh capability at an exact slot (`cap_mint` absolute
    /// destination, ADR-005). The slot must currently be free; the free list
    /// is repaired by unlinking it (O(free list) worst case).
    pub fn insert_at(&mut self, idx: SlotIdx, cap: Capability) -> Result<SlotIdx> {
        if idx >= MAX_SLOTS {
            return Err(CapError::BadSlot);
        }
        if matches!(self.slots[idx], Slot::Occupied { .. }) {
            return Err(CapError::SlotOccupied);
        }
        // Unlink `idx` from the free list.
        let mut prev: Option<SlotIdx> = None;
        let mut cur = self.free_head;
        loop {
            if cur == MAX_SLOTS {
                return Err(CapError::SlotEmpty);
            }
            match self.slots[cur] {
                Slot::Free { next_free } => {
                    if cur == idx {
                        match prev {
                            Some(p) => {
                                self.slots[p] = Slot::Free { next_free };
                            }
                            None => self.free_head = next_free,
                        }
                        break;
                    }
                    prev = Some(cur);
                    cur = next_free;
                }
                Slot::Occupied { .. } => unreachable!("free list invariant"),
            }
        }
        self.slots[idx] = Slot::Occupied { cap, parent: None };
        self.used += 1;
        Ok(idx)
    }

    /// Read a capability out of a slot (for kernel use; userland never sees
    /// raw ObjIds — kernel mediates all access).
    pub fn get(&self, idx: SlotIdx) -> Result<Capability> {
        match self.slots.get(idx) {
            Some(Slot::Occupied { cap, .. }) => Ok(*cap),
            Some(Slot::Free { .. }) => Err(CapError::SlotEmpty),
            None => Err(CapError::BadSlot),
        }
    }

    /// Derive a child capability into `dst` (usually another process's
    /// table) with `rights ⊆ parent.rights`. Requires GRANT on the parent.
    pub fn mint_into(
        &mut self,
        parent_idx: SlotIdx,
        rights: Rights,
        dst: &mut CapTable,
    ) -> Result<SlotIdx> {
        let parent = self.get(parent_idx)?;
        if !parent.rights.contains(Rights::GRANT) {
            return Err(CapError::MissingGrantRight);
        }
        if !parent.rights.contains(rights) {
            return Err(CapError::RightsNotSubset);
        }
        let child = Capability {
            obj: parent.obj,
            typ: parent.typ,
            rights,
        };
        let child_idx = dst.insert(child)?;
        if let Slot::Occupied { parent: p, .. } = &mut dst.slots[child_idx] {
            *p = Some(parent_idx);
        }
        Ok(child_idx)
    }

    /// Derive a child capability within this same table.
    pub fn mint_here(&mut self, parent_idx: SlotIdx, rights: Rights) -> Result<SlotIdx> {
        let parent = self.get(parent_idx)?;
        if !parent.rights.contains(Rights::GRANT) {
            return Err(CapError::MissingGrantRight);
        }
        if !parent.rights.contains(rights) {
            return Err(CapError::RightsNotSubset);
        }
        let child_idx = self.insert(Capability {
            obj: parent.obj,
            typ: parent.typ,
            rights,
        })?;
        if let Slot::Occupied { parent: p, .. } = &mut self.slots[child_idx] {
            *p = Some(parent_idx);
        }
        Ok(child_idx)
    }

    /// Remove one capability (not its children).
    pub fn remove(&mut self, idx: SlotIdx) -> Result<()> {
        match self.slots.get_mut(idx) {
            Some(Slot::Occupied { .. }) => {
                self.slots[idx] = Slot::Free {
                    next_free: self.free_head,
                };
                self.free_head = idx;
                self.used -= 1;
                Ok(())
            }
            Some(Slot::Free { .. }) => Err(CapError::SlotEmpty),
            None => Err(CapError::BadSlot),
        }
    }

    /// `cap_revoke` REVOKE_DERIVED mode (ADR-005): remove every capability
    /// derived from `root` (transitively) and KEEP `root` itself.
    ///
    /// Parent links crossing to other tables are severed by construction:
    /// children in other tables keep their rights, which is the documented
    /// v1 semantics — cross-table revocation goes through object epochs
    /// (kernel-side registries, ADR-004).
    pub fn revoke_derived(&mut self, root: SlotIdx) -> Result<usize> {
        self.get(root)?;
        // Transitive closure over parent links, root excluded.
        let mut flagged = [false; MAX_SLOTS];
        loop {
            let mut changed = false;
            for (i, slot) in self.slots.iter().enumerate() {
                if let Slot::Occupied {
                    parent: Some(p), ..
                } = slot
                {
                    let marked = p == &root || flagged[*p];
                    if marked && !flagged[i] {
                        flagged[i] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let mut removed = 0;
        for (i, f) in flagged.iter().enumerate() {
            if *f && matches!(self.slots[i], Slot::Occupied { .. }) {
                self.slots[i] = Slot::Free {
                    next_free: self.free_head,
                };
                self.free_head = i;
                self.used -= 1;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// `cap_revoke` DELETE mode (ADR-005): revoke all derived caps AND remove
    /// the root capability itself. Returns the total number of slots freed.
    pub fn delete_cascade(&mut self, root: SlotIdx) -> Result<usize> {
        let removed = self.revoke_derived(root)?;
        self.remove(root)?;
        Ok(removed + 1)
    }

    /// Kernel-diagnostics: `None` = out of range, `Some((false, _))` = free,
    /// `Some((true, obj))` = occupied.
    pub fn slot_debug(&self, idx: usize) -> Option<(bool, Option<u64>)> {
        self.slots.get(idx).map(|s| match s {
            Slot::Free { .. } => (false, None),
            Slot::Occupied { cap, .. } => (true, Some(cap.obj.0)),
        })
    }

    /// Count of slots holding a capability for `obj` (kernel sweep support).
    pub fn count_of(&self, obj: ObjId) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, Slot::Occupied { cap, .. } if cap.obj == obj))
            .count()
    }
}

impl Default for CapTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(id: u64, rights: Rights) -> Capability {
        Capability {
            obj: ObjId(id),
            typ: ObjType::Endpoint,
            rights,
        }
    }

    #[test]
    fn insert_get_remove_cycle() {
        let mut t = CapTable::new();
        assert!(t.is_empty());
        let s = t.insert(ep(1, Rights::SEND)).unwrap();
        assert_eq!(t.get(s).unwrap(), ep(1, Rights::SEND));
        t.remove(s).unwrap();
        assert!(t.get(s).is_err());
        assert!(t.is_empty());
        assert!(t.get(MAX_SLOTS).is_err(), "out of range");
        assert!(t.get(MAX_SLOTS - 1).is_err(), "never-filled slot");
    }

    #[test]
    fn table_exhaustion_and_reuse() {
        let mut t = CapTable::new();
        for i in 0..MAX_SLOTS {
            t.insert(ep(i as u64, Rights::READ)).unwrap();
        }
        assert_eq!(t.len(), MAX_SLOTS);
        assert_eq!(t.insert(ep(9999, Rights::READ)), Err(CapError::TableFull));
        t.remove(5).unwrap();
        // Freed slot 5 is reused first (LIFO free list).
        let s = t.insert(ep(8888, Rights::READ)).unwrap();
        assert_eq!(s, 5);
    }

    #[test]
    fn mint_enforces_rights_subset_and_grant() {
        let mut parent_t = CapTable::new();
        let mut child_t = CapTable::new();
        let p = parent_t
            .insert(ep(7, Rights::SEND.union(Rights::GRANT)))
            .unwrap();

        // Without GRANT on parent, minting fails.
        let no_grant = parent_t.insert(ep(8, Rights::SEND)).unwrap();
        assert_eq!(
            parent_t.mint_into(no_grant, Rights::RECV, &mut child_t),
            Err(CapError::MissingGrantRight)
        );

        // Asking for rights beyond parent fails.
        assert_eq!(
            parent_t.mint_into(p, Rights::WRITE, &mut child_t),
            Err(CapError::RightsNotSubset)
        );

        // Valid mint: child gets exactly the requested subset.
        let c = parent_t.mint_into(p, Rights::SEND, &mut child_t).unwrap();
        assert_eq!(child_t.get(c).unwrap(), ep(7, Rights::SEND));

        // Same-table mint also works.
        let mut t = CapTable::new();
        let r = t.insert(ep(9, Rights::ALL)).unwrap();
        let s = t.mint_here(r, Rights::READ).unwrap();
        assert_eq!(t.get(s).unwrap().rights, Rights::READ);
    }

    #[test]
    fn cascade_revoke_removes_descendants_only() {
        let mut t = CapTable::new();
        let root = t.insert(ep(1, Rights::ALL)).unwrap();
        let a = t
            .mint_here(root, Rights::SEND.union(Rights::RECV).union(Rights::GRANT))
            .unwrap();
        let b = t.mint_here(a, Rights::RECV).unwrap();
        let c = t.insert(ep(2, Rights::READ)).unwrap(); // unrelated

        let removed = t.revoke_derived(root).unwrap();
        assert_eq!(removed, 2, "a + b (root kept per ADR-005)");
        assert!(t.get(root).is_ok(), "REVOKE_DERIVED keeps the cap");
        assert!(t.get(a).is_err());
        assert!(t.get(b).is_err());
        assert!(t.get(c).is_ok(), "unrelated cap survives");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn cascade_revoke_from_middle_keeps_root() {
        let mut t = CapTable::new();
        let root = t.insert(ep(1, Rights::ALL)).unwrap();
        let a = t
            .mint_here(root, Rights::SEND.union(Rights::RECV).union(Rights::GRANT))
            .unwrap();
        let b = t.mint_here(a, Rights::SEND).unwrap();
        // Revoking the middle removes b but not root.
        assert_eq!(t.revoke_derived(a).unwrap(), 1);
        assert!(t.get(root).is_ok());
        assert!(t.get(a).is_ok());
        assert!(t.get(b).is_err());
    }

    #[test]
    fn count_of_finds_all() {
        let mut t = CapTable::new();
        let _ = t.insert(ep(42, Rights::SEND)).unwrap();
        let _ = t.insert(ep(42, Rights::RECV)).unwrap();
        let _ = t.insert(ep(43, Rights::READ)).unwrap();
        assert_eq!(t.count_of(ObjId(42)), 2);
        assert_eq!(t.count_of(ObjId(43)), 1);
        assert_eq!(t.count_of(ObjId(44)), 0);
    }

    #[test]
    fn insert_at_targets_exact_slot_and_repairs_free_list() {
        let mut t = CapTable::new();
        // First-free fills 0,1,2.
        for i in 0..3u64 {
            t.insert(ep(i, Rights::READ)).unwrap();
        }
        t.remove(1).unwrap();
        // Absolute insert into the freed slot.
        t.insert_at(1, ep(99, Rights::WRITE)).unwrap();
        assert_eq!(t.get(1).unwrap().obj, ObjId(99));
        assert_eq!(
            t.insert_at(1, ep(100, Rights::READ)),
            Err(CapError::SlotOccupied)
        );
        assert_eq!(
            t.insert_at(MAX_SLOTS, ep(1, Rights::READ)),
            Err(CapError::BadSlot)
        );

        // Free list must still be consistent: remove two, insert three.
        t.remove(0).unwrap();
        t.remove(2).unwrap();
        assert_eq!(t.len(), 1, "only the absolute-inserted cap remains");
        t.insert(ep(200, Rights::READ)).unwrap();
        t.insert(ep(201, Rights::READ)).unwrap();
        t.insert(ep(202, Rights::READ)).unwrap();
        assert_eq!(t.len(), 4);
        // Every occupied slot reachable and consistent.
        let mut occupied = 0;
        for i in 0..MAX_SLOTS {
            if t.get(i).is_ok() {
                occupied += 1;
            }
        }
        assert_eq!(occupied, 4);
    }

    #[test]
    fn delete_cascade_removes_root_too() {
        let mut t = CapTable::new();
        let root = t.insert(ep(1, Rights::ALL)).unwrap();
        let a = t
            .mint_here(root, Rights::SEND.union(Rights::GRANT))
            .unwrap();
        let b = t.mint_here(a, Rights::SEND).unwrap();
        assert_eq!(t.delete_cascade(a).unwrap(), 2, "a + b");
        assert!(t.get(a).is_err());
        assert!(t.get(b).is_err());
        assert!(t.get(root).is_ok(), "root survives DELETE of a child");
        assert_eq!(t.delete_cascade(root).unwrap(), 1);
        assert!(t.is_empty());
    }
}
