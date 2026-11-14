//! riscv64 paging backend.
//!
//! Software Sv39 page-table model (4 KB pages, 39-bit VA, 3 levels L0..L2,
//! 9 index bits per level). Each level holds 512 entries; a leaf PTE carries
//! the physical frame and permission bits. The backend owns its tables (fixed
//! pool, `spin::Mutex` interior mutability) so all trait methods work on any
//! host and are unit-testable without an MMU. The real frame-backed MMU
//! (satp, sfence.vma, `activate_aspace`) lands with riscv64 QEMU or hardware
//! bring-up; `activate_aspace` on `ContextBackend` remains a stub until then.

#![allow(dead_code)]

use kernel::aspace::{self, MapFlags, PagingBackend, Vaddr};
use kernel::frame::PhysAddr;
use spin::Mutex;

/// Page size (4 KB).
pub const PAGE_SIZE: usize = 4096;

/// 39-bit virtual address space (riscv64 Sv39, 3 levels).
const VA_BITS: u64 = 39;
/// Number of entries per page-table level (9 index bits each).
const TABLE_ENTRIES: usize = 512;
/// Index mask for one level.
const IDX_MASK: u64 = 0x1FF;
/// Maximum tables per backend (bounded pool; slot 0 is the L0 root).
const MAX_TABLES: usize = 64;

/// PTE bit 0: entry is valid.
const PTE_VALID: u64 = 1 << 0;
/// PTE bit 1: read permission.
const PTE_READ: u64 = 1 << 1;
/// PTE bit 2: write permission.
const PTE_WRITE: u64 = 1 << 2;
/// PTE bit 3: execute permission.
const PTE_EXEC: u64 = 1 << 3;
/// PTE bit 6 (software convention): entry points to the next table level
/// rather than being a leaf. Sv39 has no such bit in hardware; the software
/// model uses it to distinguish intermediate from leaf entries.
const PTE_TABLE: u64 = 1 << 6;
/// Physical address field: Sv39 holds the physical page number in PTE bits
/// [53:10]; here we store the page-aligned physical address at bits [12:].
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Level index for `level` in `0..3` from a 39-bit Sv39 VA.
const fn level_index(vaddr: u64, level: u8) -> usize {
    let shift = 30 - (level as u64) * 9;
    ((vaddr >> shift) & IDX_MASK) as usize
}

/// Translate `MapFlags` into software PTE permission bits.
const fn map_flags_to_pte(flags: MapFlags) -> u64 {
    let mut pte: u64 = 0;
    if flags.contains(MapFlags::READ) {
        pte |= PTE_READ;
    }
    if flags.contains(MapFlags::WRITE) {
        pte |= PTE_WRITE;
    }
    if flags.contains(MapFlags::EXEC) {
        pte |= PTE_EXEC;
    }
    pte
}

/// All page-table state behind one lock so `walk` + mutation is atomic.
struct BackendState {
    /// `tables[0]` is the L0 root; `tables[1..]` are allocatable intermediates.
    tables: [[u64; TABLE_ENTRIES]; MAX_TABLES],
    /// Next allocatable slot in `tables`.
    next_table: usize,
}

/// riscv64 per-address-space paging backend (software Sv39 model).
pub struct PagingBackendRiscv64 {
    state: Mutex<BackendState>,
}

impl Default for PagingBackendRiscv64 {
    fn default() -> Self {
        Self::new()
    }
}

impl PagingBackendRiscv64 {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BackendState {
                tables: [[0; TABLE_ENTRIES]; MAX_TABLES],
                next_table: 1,
            }),
        }
    }

    /// Allocate a fresh zeroed intermediate table from the pool.
    fn alloc_table(&self, state: &mut BackendState) -> Option<usize> {
        if state.next_table >= MAX_TABLES {
            return None;
        }
        let slot = state.next_table;
        state.next_table += 1;
        state.tables[slot] = [0; TABLE_ENTRIES];
        Some(slot)
    }

    /// Walk to the leaf PTE for `va`, creating intermediate tables when
    /// `create` is true. Returns `(table_index, leaf_slot)` or `None` when an
    /// intermediate entry is absent and `create` is false.
    fn walk_leaf(&self, state: &mut BackendState, va: u64, create: bool) -> Option<(usize, usize)> {
        let mut table_idx: usize = 0; // L0 root is tables[0]
        let mut slot = level_index(va, 0);
        for level in 0..3usize {
            if level == 2 {
                // L2: the leaf entry.
                return Some((table_idx, slot));
            }
            let entry = state.tables[table_idx][slot];
            if entry & PTE_VALID == 0 {
                if !create {
                    return None;
                }
                let new_idx = self.alloc_table(state)?;
                state.tables[table_idx][slot] = (new_idx as u64) << 12 | PTE_VALID | PTE_TABLE;
                table_idx = new_idx;
            } else if entry & PTE_TABLE == 0 {
                // Intermediate slot holds a leaf, not a table: cannot descend.
                return None;
            } else {
                table_idx = ((entry & PTE_ADDR_MASK) >> 12) as usize;
            }
            slot = level_index(va, (level + 1) as u8);
        }
        unreachable!()
    }

    /// Read the leaf PTE for `vaddr` (existing tables only; test/diagnostic).
    fn pte_at(&self, vaddr: u64) -> Option<u64> {
        let mut state = self.state.lock();
        let (table_idx, slot) = self.walk_leaf(&mut state, vaddr, false)?;
        Some(state.tables[table_idx][slot])
    }
}

impl PagingBackend for PagingBackendRiscv64 {
    fn map_page(&self, vaddr: Vaddr, paddr: PhysAddr, flags: MapFlags) {
        if self.map_page_checked(vaddr, paddr, flags).is_err() {
            panic!(
                "riscv64 map_page: failed to install mapping for {:#x}",
                vaddr.as_u64()
            );
        }
    }

    fn map_page_checked(
        &self,
        vaddr: Vaddr,
        paddr: PhysAddr,
        flags: MapFlags,
    ) -> Result<(), aspace::VmmError> {
        let va = vaddr.as_u64();
        // 39-bit Sv39 VA, page-aligned, non-null and page-aligned physical frame.
        if va >= (1u64 << VA_BITS)
            || !vaddr.is_page_aligned()
            || paddr.as_u64() == 0
            || paddr.as_u64() & (PAGE_SIZE as u64 - 1) != 0
        {
            return Err(aspace::VmmError::BadVaddr);
        }
        let mut state = self.state.lock();
        let (table_idx, slot) = self
            .walk_leaf(&mut state, va, true)
            .ok_or(aspace::VmmError::MapFailed)?;
        let pte = PTE_VALID | (paddr.as_u64() & PTE_ADDR_MASK) | map_flags_to_pte(flags);
        state.tables[table_idx][slot] = pte;
        Ok(())
    }

    fn unmap_page(&self, vaddr: Vaddr) {
        let va = vaddr.as_u64();
        if va >= (1u64 << VA_BITS) || !vaddr.is_page_aligned() {
            return;
        }
        let mut state = self.state.lock();
        let Some((table_idx, slot)) = self.walk_leaf(&mut state, va, false) else {
            return;
        };
        state.tables[table_idx][slot] = 0;
    }

    fn protect_page(&self, vaddr: Vaddr, flags: MapFlags) {
        let va = vaddr.as_u64();
        if va >= (1u64 << VA_BITS) || !vaddr.is_page_aligned() {
            return;
        }
        let mut state = self.state.lock();
        let Some((table_idx, slot)) = self.walk_leaf(&mut state, va, false) else {
            return;
        };
        let pte = state.tables[table_idx][slot];
        if pte & PTE_VALID == 0 || pte & PTE_TABLE != 0 {
            return; // no leaf mapping
        }
        state.tables[table_idx][slot] =
            (pte & !(PTE_READ | PTE_WRITE | PTE_EXEC)) | map_flags_to_pte(flags);
    }
}

/// Hands out one riscv64 paging backend per address space.
pub struct BackendFactoryRiscv64;

impl Default for BackendFactoryRiscv64 {
    fn default() -> Self {
        Self
    }
}

impl aspace::BackendFactory for BackendFactoryRiscv64 {
    fn create(&self, _as_id: u64) -> Option<&'static dyn PagingBackend> {
        static POOL: spin::Mutex<[Option<PagingBackendRiscv64>; 1]> = spin::Mutex::new([None]);
        let mut slots = POOL.lock();
        if slots[0].is_none() {
            slots[0] = Some(PagingBackendRiscv64::new());
        }
        let slot_ptr = &slots[0] as *const Option<PagingBackendRiscv64>;
        drop(slots);
        // SAFETY: `slots[0]` is `Some` and lives for `'static` inside `POOL`;
        // the pool entry is never removed, so the returned reference is valid
        // for `'static`. Dropping the lock first is sound because `POOL` is
        // `Sync` and the pointed-to value is immutable after construction.
        unsafe { Some((*slot_ptr).as_ref().unwrap() as &dyn PagingBackend) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> PagingBackendRiscv64 {
        PagingBackendRiscv64::new()
    }

    #[test]
    fn level_indices_extract_39bit_va() {
        let va: u64 = 0x_0000_AAAA_BBBB_CCCC;
        assert_eq!(level_index(va, 0), ((va >> 30) & 0x1FF) as usize);
        assert_eq!(level_index(va, 1), ((va >> 21) & 0x1FF) as usize);
        assert_eq!(level_index(va, 2), ((va >> 12) & 0x1FF) as usize);
        assert_eq!(level_index(1u64 << 38, 0), 0x100);
    }

    #[test]
    fn map_flags_to_pte_bits() {
        let r = map_flags_to_pte(MapFlags::READ);
        assert!(r & PTE_READ != 0);
        assert!(r & PTE_WRITE == 0);
        let rw = map_flags_to_pte(MapFlags::READ.union(MapFlags::WRITE));
        assert!(rw & PTE_READ != 0 && rw & PTE_WRITE != 0);
        let rwx = map_flags_to_pte(MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::EXEC));
        assert!(rwx & PTE_EXEC != 0);
        assert_eq!(map_flags_to_pte(MapFlags::default()), 0);
    }

    #[test]
    fn map_page_installs_leaf_pte() {
        let b = backend();
        let va = Vaddr(0x_0000_1000_0000);
        let pa = PhysAddr::new(0x_0000_2000_0000);
        assert!(b.map_page_checked(va, pa, MapFlags::READ).is_ok());
        let pte = b.pte_at(va.as_u64()).expect("leaf present after map");
        assert!(pte & PTE_VALID != 0);
        assert!(pte & PTE_TABLE == 0); // leaf, not a table
        assert_eq!(pte & PTE_ADDR_MASK, pa.as_u64());
        assert!(pte & PTE_READ != 0);
        assert!(pte & PTE_WRITE == 0);
    }

    #[test]
    fn map_page_rejects_invalid() {
        let b = backend();
        // Beyond 39-bit Sv39 VA.
        assert!(matches!(
            b.map_page_checked(Vaddr(1u64 << 39), PhysAddr::new(0x1000), MapFlags::READ),
            Err(aspace::VmmError::BadVaddr)
        ));
        // Not page-aligned.
        assert!(matches!(
            b.map_page_checked(Vaddr(0x1001), PhysAddr::new(0x2000), MapFlags::READ),
            Err(aspace::VmmError::BadVaddr)
        ));
        // Null physical frame.
        assert!(matches!(
            b.map_page_checked(Vaddr(0x1000), PhysAddr::new(0), MapFlags::READ),
            Err(aspace::VmmError::BadVaddr)
        ));
        // Unaligned physical frame.
        assert!(matches!(
            b.map_page_checked(Vaddr(0x1000), PhysAddr::new(0x1001), MapFlags::READ),
            Err(aspace::VmmError::BadVaddr)
        ));
    }

    #[test]
    fn unmap_page_clears_leaf() {
        let b = backend();
        let va = Vaddr(0x_0000_1000_0000);
        let pa = PhysAddr::new(0x_0000_2000_0000);
        b.map_page(va, pa, MapFlags::READ.union(MapFlags::WRITE));
        assert!(b.pte_at(va.as_u64()).is_some());
        b.unmap_page(va);
        assert_eq!(b.pte_at(va.as_u64()), Some(0));
    }

    #[test]
    fn protect_page_updates_flags() {
        let b = backend();
        let va = Vaddr(0x_0000_1000_0000);
        let pa = PhysAddr::new(0x_0000_2000_0000);
        b.map_page(va, pa, MapFlags::READ);
        assert!(b
            .pte_at(va.as_u64())
            .map(|p| p & PTE_READ != 0)
            .unwrap_or(false));
        assert!(b
            .pte_at(va.as_u64())
            .map(|p| p & PTE_WRITE == 0)
            .unwrap_or(false));
        b.protect_page(va, MapFlags::READ.union(MapFlags::WRITE));
        let pte = b.pte_at(va.as_u64()).expect("leaf still present");
        assert!(pte & PTE_READ != 0);
        assert!(pte & PTE_WRITE != 0);
        assert_eq!(pte & PTE_ADDR_MASK, pa.as_u64());
    }

    #[test]
    fn protect_unmapped_is_noop() {
        let b = backend();
        let va = Vaddr(0x_0000_1000_0000);
        b.protect_page(va, MapFlags::READ); // must not panic
        assert_eq!(b.pte_at(va.as_u64()), None);
    }

    #[test]
    fn intermediate_tables_created_on_demand() {
        let b = backend();
        // A page whose L0/L1 are all empty exercises table creation.
        let va = Vaddr(0x_0001_0000_0000);
        let pa = PhysAddr::new(0x_0000_3000_0000);
        assert!(b.map_page_checked(va, pa, MapFlags::READ).is_ok());
        assert!(b.pte_at(va.as_u64()).is_some());
    }
}
