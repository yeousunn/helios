//! Capability types and tables (ADR-004). Authority in Helios is entirely
//! capability-based: unforgeable, delegable, revocable.
#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

/// Identifies a kernel object (endpoint, thread, address space, ...).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjId(pub u64);

/// The kind of object a capability grants authority over.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Endpoint,
    Notification,
    AddressSpace,
    Thread,
    Frame,
    Irq,
}

/// Permission bits carried by a capability. Subsets of parent rights only.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const GRANT: Rights = Rights(1 << 2);
    pub const SEND: Rights = Rights(1 << 3);
    pub const RECV: Rights = Rights(1 << 4);

    /// Every right (used for freshly-minted kernel authority).
    pub const fn all_of() -> Rights {
        Rights(0b1_1111)
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Rights present in both sets (used when masking on delegation).
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Rights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return write!(f, "-");
        }
        const NAMES: [(u32, &str); 5] = [
            (Rights::READ.0, "R"),
            (Rights::WRITE.0, "W"),
            (Rights::GRANT.0, "G"),
            (Rights::SEND.0, "S"),
            (Rights::RECV.0, "V"),
        ];
        for (bit, name) in NAMES {
            if self.0 & bit != 0 {
                write!(f, "{name}")?;
            }
        }
        Ok(())
    }
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

const MAX_SLOTS: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapError {
    TableFull,
    SlotEmpty,
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
    pub fn new() -> Self {
        let mut slots = [Slot::Free { next_free: 0 }; MAX_SLOTS];
        for (i, slot) in slots.iter_mut().enumerate() {
            *slot = Slot::Free {
                next_free: (i + 1) % (MAX_SLOTS + 1),
            };
        }
        CapTable {
            slots,
            free_head: 0,
            used: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.used
    }

    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Insert a fresh capability (no parent). Used by the kernel when minting
    /// initial authority for a new process.
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

    /// Remove the capability at `root` and every capability derived from it
    /// (transitively) in this table. Parent links crossing to other tables
    /// (e.g. the child lives in `dst` of mint) are severed by construction:
    /// children in other tables keep their rights, which is the documented
    /// v1 semantics — cross-table revocation goes through object epochs
    /// (kernel-side registries, ADR-004).
    pub fn revoke_cascade(&mut self, root: SlotIdx) -> Result<usize> {
        self.get(root)?;
        let mut removed = 0;
        // Iterative transitive closure over parent links.
        let mut frontier = [false; MAX_SLOTS];
        frontier[root] = true;
        loop {
            let mut changed = false;
            for (i, slot) in self.slots.iter().enumerate() {
                if let Slot::Occupied {
                    parent: Some(p), ..
                } = slot
                {
                    if frontier[*p] && !frontier[i] {
                        frontier[i] = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for (i, flagged) in frontier.iter().enumerate() {
            if *flagged && matches!(self.slots[i], Slot::Occupied { .. }) {
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
        let r = t.insert(ep(9, Rights::all_of())).unwrap();
        let s = t.mint_here(r, Rights::READ).unwrap();
        assert_eq!(t.get(s).unwrap().rights, Rights::READ);
    }

    #[test]
    fn cascade_revoke_removes_descendants_only() {
        let mut t = CapTable::new();
        let root = t.insert(ep(1, Rights::all_of())).unwrap();
        let a = t
            .mint_here(root, Rights::SEND.union(Rights::RECV).union(Rights::GRANT))
            .unwrap();
        let b = t.mint_here(a, Rights::RECV).unwrap();
        let c = t.insert(ep(2, Rights::READ)).unwrap(); // unrelated

        let removed = t.revoke_cascade(root).unwrap();
        assert_eq!(removed, 3, "root + a + b");
        assert!(t.get(root).is_err());
        assert!(t.get(a).is_err());
        assert!(t.get(b).is_err());
        assert!(t.get(c).is_ok(), "unrelated cap survives");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn cascade_revoke_from_middle_keeps_root() {
        let mut t = CapTable::new();
        let root = t.insert(ep(1, Rights::all_of())).unwrap();
        let a = t
            .mint_here(root, Rights::SEND.union(Rights::RECV).union(Rights::GRANT))
            .unwrap();
        let b = t.mint_here(a, Rights::SEND).unwrap();
        // Revoking the middle removes b but not root.
        assert_eq!(t.revoke_cascade(a).unwrap(), 2);
        assert!(t.get(root).is_ok());
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
}
