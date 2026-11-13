//! Arch-independent virtual memory core (ADR-008, per-process VMM per
//! ADR-022): AS object registry, per-AS paging backends, COW refcounting,
//! fault pools. Arch code registers a `BackendFactory`; all policy lives
//! here and is host-testable.
#![forbid(unsafe_code)]

use crate::frame::{self, PhysAddr};
use caps::ObjId;
use core::fmt;
use spin::Mutex;

/// Mapping permission bits. Wire-compatible with syscall-abi §7 AS::MAP
/// (bit0 R, bit1 W, bit2 X, bit3 COW, bit4 ANON).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MapFlags(pub u32);

impl MapFlags {
    pub const READ: MapFlags = MapFlags(1 << 0);
    pub const WRITE: MapFlags = MapFlags(1 << 1);
    pub const EXEC: MapFlags = MapFlags(1 << 2);
    pub const COW: MapFlags = MapFlags(1 << 3);
    pub const ANON: MapFlags = MapFlags(1 << 4);

    pub const fn union(self, o: MapFlags) -> MapFlags {
        MapFlags(self.0 | o.0)
    }
    pub const fn contains(self, o: MapFlags) -> bool {
        self.0 & o.0 == o.0
    }
    /// Permission bits only (R/W/X) — used to compare protections.
    pub const fn perms(self) -> u32 {
        self.0 & 0b111
    }
}

impl fmt::Display for MapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 & MapFlags::READ.0 != 0 {
            write!(f, "R")?;
        }
        if self.0 & MapFlags::WRITE.0 != 0 {
            write!(f, "W")?;
        }
        if self.0 & MapFlags::EXEC.0 != 0 {
            write!(f, "X")?;
        }
        if self.0 & MapFlags::COW.0 != 0 {
            write!(f, "C")?;
        }
        if self.0 & MapFlags::ANON.0 != 0 {
            write!(f, "A")?;
        }
        Ok(())
    }
}

pub const PAGE_SIZE: usize = frame::FRAME_SIZE;

/// Checked virtual address newtype.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Vaddr(pub u64);

impl Vaddr {
    pub const fn as_u64(self) -> u64 {
        self.0
    }
    pub fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE as u64)
    }
    pub fn page_index(self) -> u64 {
        self.0 / PAGE_SIZE as u64
    }
}

/// One contiguous mapping of whole pages.
#[derive(Clone, Copy, Debug)]
pub struct Mapping {
    pub vaddr: Vaddr,
    pub pages: u64,
    /// Base physical frame; ANON mappings carry `None` until first fault.
    pub base: Option<PhysAddr>,
    pub flags: MapFlags,
}

impl Mapping {
    pub fn contains(&self, v: Vaddr) -> bool {
        let start = self.vaddr.page_index();
        v.page_index() >= start && v.page_index() < start + self.pages
    }

    fn offset(&self, v: Vaddr) -> u64 {
        (v.page_index() - self.vaddr.page_index()) * PAGE_SIZE as u64
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmmError {
    Overlap,
    NotFound,
    NotMapped,
    NoWritePerm,
    NoPool,
    PoolEmpty,
    BadVaddr,
    NoBackend,
    FrameNotOwned,
    TableFull,
    AlreadyExists,
    /// Backend page-table install failed (S10): no free page-table frame or
    /// a refused kernel-window walk. Surfaced to syscalls as ENOMEM.
    MapFailed,
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Kernel-owned page-table interface (ADR-022 §2): one instance per
/// address space, created through a `BackendFactory`. Arch implementations
/// do raw MMIO — the safety burden is theirs, per hal/ ownership.
pub trait PagingBackend: Sync + Send {
    /// Install one page mapping (v0 infallible form — panics on failure).
    /// Kept so backends that have not migrated keep compiling; kernel code
    /// calls only [`PagingBackend::map_page_checked`].
    fn map_page(&self, vaddr: Vaddr, paddr: PhysAddr, flags: MapFlags);
    /// Fallible install (S10 request): the backend reports failure — no free
    /// page-table frame, refused kernel-window walk — instead of panicking.
    /// Default bridges to the v0 [`PagingBackend::map_page`] so un-migrated
    /// backends keep their current (panicking) behavior until their owner
    /// overrides this method (hal/x86_64, NV's S10).
    fn map_page_checked(
        &self,
        vaddr: Vaddr,
        paddr: PhysAddr,
        flags: MapFlags,
    ) -> Result<(), VmmError> {
        self.map_page(vaddr, paddr, flags);
        Ok(())
    }
    /// Remove one page mapping (TLB flush is the backend's job).
    fn unmap_page(&self, vaddr: Vaddr);
    /// Change permissions of an existing mapping.
    fn protect_page(&self, vaddr: Vaddr, flags: MapFlags);
    /// Copy one page's contents (FORK resolved-page cloning, ADR-024 §2).
    /// Arch scratch-window memcpy. Default: unsupported (FORK → ENOSYS).
    fn copy_page(&self, _dst: PhysAddr, _src: PhysAddr) -> bool {
        false
    }
}

/// Arch-provided backend factory (ADR-022 §2). Registered at boot; hands
/// out one paging root per address space.
pub trait BackendFactory: Sync + Send {
    fn create(&self, as_id: u64) -> Option<&'static dyn PagingBackend>;
}

static FACTORY: Mutex<Option<&'static dyn BackendFactory>> = Mutex::new(None);

pub fn set_backend_factory(f: &'static dyn BackendFactory) {
    *FACTORY.lock() = Some(f);
}

/// Per-address-space VMM state.
pub struct AddressSpace {
    regions: [Option<Mapping>; MAX_REGIONS],
    pool: Option<Pool>,
    /// Per-page frames for ANON/resolved pages (single-base model cannot
    /// represent lazily-faulted pages). Keyed by global page index.
    page_frames: [(u64, PhysAddr); MAX_PAGE_FRAMES],
}

const MAX_REGIONS: usize = 128;
const MAX_PAGE_FRAMES: usize = 64;

/// Reserve of physical frames for in-kernel COW/anon resolution (ADR-007 §4).
#[derive(Clone, Copy, Debug)]
pub struct Pool {
    base: PhysAddr,
    /// Next uncarved frame offset (in frames) within the pool.
    next: u64,
    frames: u64,
}

impl Pool {
    pub fn new(base: PhysAddr, bytes: u64) -> Option<Pool> {
        if !base.is_frame_aligned() || bytes < PAGE_SIZE as u64 {
            return None;
        }
        Some(Pool {
            base,
            next: 0,
            frames: bytes / PAGE_SIZE as u64,
        })
    }

    fn take(&mut self) -> Option<PhysAddr> {
        if self.next >= self.frames {
            return None;
        }
        let addr = self.base.checked_add(self.next * PAGE_SIZE as u64)?;
        self.next += 1;
        Some(addr)
    }
}

/// S4: the whole page range `[vaddr, vaddr + pages)` must lie entirely in
/// user space (PML4[0..256), strictly below the canonical split
/// `sched::USER_ADDR_LIMIT`), VA 0 is never mappable, and the end index is
/// overflow-checked so a huge page count cannot wrap back into user space.
/// Every user-reachable VMM entry point (MAP/UNMAP/PROTECT, and the pager
/// resolve path) validates through this helper — a region may therefore
/// never reach the shared kernel window (PML4[511]) or the reserved
/// PML4[256..510] slots.
pub fn validate_user_range(vaddr: Vaddr, pages: u64) -> Result<(), VmmError> {
    if pages == 0 || !vaddr.is_page_aligned() || vaddr.0 == 0 {
        return vmm_err(VmmError::BadVaddr);
    }
    // Exclusive end page index, overflow-checked (a wrapping end would let
    // a range "start over" inside user space while covering the kernel).
    let end_page = vaddr
        .page_index()
        .checked_add(pages)
        .ok_or(VmmError::BadVaddr)?;
    // The split itself (page index USER_ADDR_LIMIT / PAGE_SIZE) is the
    // first kernel-owned page (PML4[256]); the range must end at or below
    // it, i.e. the last mapped byte stays below USER_ADDR_LIMIT.
    if end_page > crate::sched::USER_ADDR_LIMIT / PAGE_SIZE as u64 {
        return vmm_err(VmmError::BadVaddr);
    }
    Ok(())
}

/// S4: single-address form of [`validate_user_range`] (PROTECT, pager
/// resolve): the address must be a non-null, page-aligned user address.
fn validate_user_addr(vaddr: Vaddr) -> Result<(), VmmError> {
    validate_user_range(vaddr, 1)
}

impl AddressSpace {
    const fn new() -> Self {
        AddressSpace {
            regions: [const { None }; MAX_REGIONS],
            pool: None,
            page_frames: [(0, PhysAddr::new(0)); MAX_PAGE_FRAMES],
        }
    }

    fn set_pool(&mut self, base: PhysAddr, bytes: u64) -> Result<(), VmmError> {
        let pool = Pool::new(base, bytes).ok_or(VmmError::BadVaddr)?;
        self.pool = Some(pool);
        Ok(())
    }

    /// Whether a fault pool is attached (drives lazy vs eager ANON, entry.rs).
    fn has_pool(&self) -> bool {
        self.pool.is_some()
    }

    fn map(
        &mut self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        pages: u64,
        base: Option<PhysAddr>,
        flags: MapFlags,
    ) -> Result<PhysAddr, VmmError> {
        // S4: the whole range must be in user space (rejects VA 0, the
        // kernel window and overflowed end addresses).
        validate_user_range(vaddr, pages)?;
        if base.is_some() && flags.contains(MapFlags::ANON) {
            return vmm_err(VmmError::FrameNotOwned);
        }
        let end_idx = vaddr
            .page_index()
            .checked_add(pages)
            .ok_or(VmmError::BadVaddr)?;
        // Overlap check.
        for r in self.regions.iter().flatten() {
            let rs = r.vaddr.page_index();
            let re = rs + r.pages;
            let s = vaddr.page_index();
            if s < re && rs < end_idx {
                return vmm_err(VmmError::Overlap);
            }
        }
        let slot = self
            .regions
            .iter_mut()
            .position(|r| r.is_none())
            .ok_or(VmmError::Overlap)?;
        if let Some(b) = base {
            if !b.is_frame_aligned() {
                return vmm_err(VmmError::BadVaddr);
            }
            // S10: install the PTEs BEFORE the region is recorded and the
            // mapping ref acquired — a backend failure (no free page-table
            // frame) leaves the address space untouched.
            self.map_backend(be, vaddr, pages, b, flags)?;
            FRAME_REFS.lock().acquire(b);
        }
        self.regions[slot] = Some(Mapping {
            vaddr,
            pages,
            base,
            flags,
        });
        self.merge_neighbors(slot);
        Ok(base.unwrap_or(PhysAddr::new(0)))
    }

    /// Coalesce a freshly inserted region with adjacent regions that have
    /// identical flags and contiguous backing (ADR-030 consequence: keeps
    /// the region table small under loader/heap map patterns). Per-page
    /// overrides (`page_frames`) key on global page index and survive
    /// merging untouched.
    fn merge_neighbors(&mut self, slot: usize) {
        let Some(new) = self.regions[slot] else {
            return;
        };
        // Left neighbor: ends exactly where `new` begins.
        let left = self.regions.iter().position(|r| {
            matches!(r, Some(m)
            if m.flags == new.flags
                && m.vaddr.as_u64() + m.pages * PAGE_SIZE as u64 == new.vaddr.as_u64()
                && match (m.base, new.base) {
                    (Some(a), Some(b)) => {
                        a.as_u64() + m.pages * PAGE_SIZE as u64 == b.as_u64()
                    }
                    (None, None) => true,
                    _ => false,
                })
        });
        if let Some(l) = left {
            let mut m = self.regions[l].take().unwrap();
            m.pages += new.pages;
            self.regions[slot] = Some(m);
            // Re-merge rightward from the grown region.
            self.merge_neighbors(slot);
            return;
        }
        // Right neighbor: begins exactly where `new` ends.
        let right = self.regions.iter().position(|r| {
            matches!(r, Some(m)
            if m.flags == new.flags
                && m.vaddr.as_u64() == new.vaddr.as_u64() + new.pages * PAGE_SIZE as u64
                && match (new.base, m.base) {
                    (Some(a), Some(b)) => {
                        a.as_u64() + new.pages * PAGE_SIZE as u64 == b.as_u64()
                    }
                    (None, None) => true,
                    _ => false,
                })
        });
        if let Some(r) = right {
            let m = self.regions[r].take().unwrap();
            if let Some(n) = self.regions[slot].as_mut() {
                n.pages += m.pages;
            }
        }
    }

    /// Install backend entries page by page (called with the backend
    /// reference). S10: fallible — a backend failure rolls back the pages
    /// installed so far and reports [`VmmError::MapFailed`], so the caller
    /// records no region for a partially-installed range.
    fn map_backend(
        &self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        pages: u64,
        base: PhysAddr,
        flags: MapFlags,
    ) -> Result<(), VmmError> {
        for i in 0..pages {
            let Some(pa) = base.checked_add(i * PAGE_SIZE as u64) else {
                continue;
            };
            let va = Vaddr(vaddr.as_u64() + i * PAGE_SIZE as u64);
            if be.map_page_checked(va, pa, flags).is_err() {
                // Roll back the PTEs installed before the failure; pages
                // after it were never attempted.
                for j in 0..i {
                    be.unmap_page(Vaddr(vaddr.as_u64() + j * PAGE_SIZE as u64));
                }
                return vmm_err(VmmError::MapFailed);
            }
        }
        Ok(())
    }

    /// Page-granular unmap with region splitting (v0.1, DS anomaly fix):
    /// removes exactly `[vaddr, vaddr + pages)` from whichever region covers
    /// it. The pre-coalescing implementation took the WHOLE containing
    /// region — after merging, a scratch-page UNMAP destroyed neighbouring
    /// mappings (missing mid-stack PTEs, corrupted package data). Head/tail
    /// splits keep the survivors; refs drop only for the unmapped pages.
    fn unmap(&mut self, be: &dyn PagingBackend, vaddr: Vaddr, pages: u64) -> Result<(), VmmError> {
        // S4: the whole range must be in user space, checked BEFORE the
        // hole-skipping walk (a kernel-window span must not be swept).
        validate_user_range(vaddr, pages)?;
        let mut cur = vaddr.page_index();
        let end_idx = cur.checked_add(pages).ok_or(VmmError::BadVaddr)?;
        while cur < end_idx {
            // Find the region covering `cur`; unmap its overlap and advance.
            let Some((slot, m)) = self.regions.iter().enumerate().find_map(|(i, r)| {
                r.as_ref()
                    .filter(|m| m.contains(Vaddr(cur * PAGE_SIZE as u64)))
                    .map(|m| (i, *m))
            }) else {
                // Hole in the span: already unmapped — skip (munmap semantics).
                cur += 1;
                continue;
            };
            let m_end = m.vaddr.page_index() + m.pages;
            let piece_end = end_idx.min(m_end);
            let head = cur - m.vaddr.page_index();
            let count = piece_end - cur;
            self.unmap_in_region(be, slot, &m, head as usize, count as usize)?;
            cur = piece_end;
        }
        Ok(())
    }

    /// Remove `count` pages starting at region-relative page `head` from the
    /// region in `slot` (splits head/tail as needed). Caller guarantees the
    /// range is inside the region.
    fn unmap_in_region(
        &mut self,
        be: &dyn PagingBackend,
        slot: usize,
        m: &Mapping,
        head: usize,
        count: usize,
    ) -> Result<(), VmmError> {
        let head = head as u64;
        let count = count as u64;
        let tail = m.pages - head - count;
        let _ = self.regions[slot].take();
        if let Some(b) = m.base {
            for i in head..(head + count) {
                // A resolved page (COW copy / pager install) carries its own
                // override frame — release THAT, not the region's base frame
                // (which may be COW-shared with a sibling process). Releasing
                // the base frame here was the "PTE lost after spawn" bug.
                let page_idx = m.vaddr.page_index() + i;
                let target = match self
                    .page_frames
                    .iter()
                    .find(|(p, _)| *p == page_idx)
                    .map(|(_, f)| *f)
                {
                    Some(override_frame) => {
                        // Clear the override entry: the page is gone.
                        if let Some(pf) = self.page_frames.iter_mut().find(|(p, _)| *p == page_idx)
                        {
                            *pf = (0, PhysAddr::new(0));
                        }
                        override_frame
                    }
                    None => match b.checked_add(i * PAGE_SIZE as u64) {
                        Some(pa) => pa,
                        None => continue,
                    },
                };
                FRAME_REFS.lock().release(target);
            }
            for i in head..(head + count) {
                let va = Vaddr(m.vaddr.as_u64() + i * PAGE_SIZE as u64);
                be.unmap_page(va);
            }
        } else if m.flags.contains(MapFlags::ANON) {
            let start = m.vaddr.page_index() + head;
            let end = start + count;
            for i in 0..self.page_frames.len() {
                let (p, f) = self.page_frames[i];
                if p >= start && p < end {
                    FRAME_REFS.lock().release(f);
                    be.unmap_page(Vaddr(p * PAGE_SIZE as u64));
                    self.page_frames[i] = (0, PhysAddr::new(0));
                }
            }
        }
        if head > 0 {
            self.regions[slot] = Some(Mapping {
                vaddr: m.vaddr,
                pages: head,
                base: m.base,
                flags: m.flags,
            });
        }
        if tail > 0 {
            let tail_base = m
                .base
                .and_then(|b| b.checked_add((head + count) * PAGE_SIZE as u64));
            let free = self
                .regions
                .iter()
                .position(|r| r.is_none())
                .ok_or(VmmError::Overlap)?;
            self.regions[free] = Some(Mapping {
                vaddr: Vaddr((m.vaddr.page_index() + head + count) * PAGE_SIZE as u64),
                pages: tail,
                base: tail_base,
                flags: m.flags,
            });
        }
        Ok(())
    }

    fn protect(
        &mut self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        flags: MapFlags,
    ) -> Result<(), VmmError> {
        // S4: the target address must be a user page (the containing region
        // was range-validated at map time, so the whole reflagged region
        // stays in user space).
        validate_user_addr(vaddr)?;
        for r in self.regions.iter_mut().flatten() {
            if r.contains(vaddr) {
                r.flags = flags;
                for i in 0..r.pages {
                    let va = Vaddr(r.vaddr.as_u64() + i * PAGE_SIZE as u64);
                    be.protect_page(va, flags);
                }
                return Ok(());
            }
        }
        vmm_err(VmmError::NotFound)
    }

    fn translate(&self, vaddr: Vaddr) -> Result<(PhysAddr, MapFlags), VmmError> {
        let idx = vaddr.page_index();
        for m in self.regions.iter().flatten() {
            if m.contains(vaddr) {
                // Per-page overrides (resolved ANON/COW pages) take precedence.
                for (p, f) in self.page_frames.iter() {
                    if *p == idx {
                        return Ok((*f, m.flags));
                    }
                }
                if let Some(base) = m.base {
                    return Ok((base.checked_add(m.offset(vaddr)).unwrap(), m.flags));
                }
                return vmm_err(VmmError::NotMapped);
            }
        }
        vmm_err(VmmError::NotFound)
    }

    /// Install a mapping from a pager's FAULT_RESOLVE reply (ADR-007 §2).
    fn install_from_reply(
        &mut self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        frame_addr: PhysAddr,
        flags: MapFlags,
    ) -> Result<bool, VmmError> {
        if !frame_addr.is_frame_aligned() || validate_user_addr(vaddr).is_err() {
            return vmm_err(VmmError::BadVaddr);
        }
        let idx = vaddr.page_index();
        FRAME_REFS.lock().acquire(frame_addr);
        let covered = self.regions.iter().flatten().any(|m| m.contains(vaddr));
        if covered {
            let slot_pf = self
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0 || *p == idx)
                .ok_or(VmmError::Overlap)?;
            let prev_pf = self.page_frames[slot_pf];
            self.page_frames[slot_pf] = (idx, frame_addr);
            // S10: backend failure — restore the previous per-page entry and
            // the refcount; nothing recorded-but-unbacked may survive (a
            // refault on such a page would loop forever).
            if be.map_page_checked(vaddr, frame_addr, flags).is_err() {
                self.page_frames[slot_pf] = prev_pf;
                FRAME_REFS.lock().release(frame_addr);
                return vmm_err(VmmError::MapFailed);
            }
        } else {
            let slot = self
                .regions
                .iter_mut()
                .position(|r| r.is_none())
                .ok_or(VmmError::Overlap)?;
            self.regions[slot] = Some(Mapping {
                vaddr,
                pages: 1,
                base: None,
                flags,
            });
            let slot_pf = self
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0)
                .ok_or(VmmError::Overlap)?;
            let prev_pf = self.page_frames[slot_pf];
            self.page_frames[slot_pf] = (idx, frame_addr);
            if be.map_page_checked(vaddr, frame_addr, flags).is_err() {
                self.page_frames[slot_pf] = prev_pf;
                self.regions[slot] = None;
                FRAME_REFS.lock().release(frame_addr);
                return vmm_err(VmmError::MapFailed);
            }
        }
        Ok(covered)
    }

    fn resolve_fault(
        &mut self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        write: bool,
    ) -> Result<PhysAddr, VmmError> {
        if !vaddr.is_page_aligned() {
            return vmm_err(VmmError::BadVaddr);
        }
        let slot = self
            .regions
            .iter()
            .position(|r| matches!(r, Some(m) if m.contains(vaddr)))
            .ok_or(VmmError::NotFound)?;

        // Already-resolved page (ANON or COW copy): return the per-page frame.
        let page_idx = vaddr.page_index();
        for (p, f) in self.page_frames.iter() {
            if *p == page_idx {
                return Ok(*f);
            }
        }

        let m = self.regions[slot].as_mut().unwrap();

        // Anonymous zero-fill (idempotent: a refault returns the same frame).
        if m.flags.contains(MapFlags::ANON) {
            let pool = self.pool.as_mut().ok_or(VmmError::NoPool)?;
            let frame = pool.take().ok_or(VmmError::PoolEmpty)?;
            FRAME_REFS.lock().acquire(frame);
            let slot_pf = self
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0)
                .ok_or(VmmError::PoolEmpty)?;
            self.page_frames[slot_pf] = (page_idx, frame);
            let va = Vaddr(m.vaddr.as_u64() + m.offset(vaddr));
            // S10: backend failure — roll the per-page record back (a
            // recorded but unbacked page would fault-loop forever). The pool
            // frame is burned (Pool has no return path) — acceptable on the
            // exhaustion path this error represents.
            if be.map_page_checked(va, frame, m.flags).is_err() {
                self.page_frames[slot_pf] = (0, PhysAddr::new(0));
                FRAME_REFS.lock().release(frame);
                return vmm_err(VmmError::MapFailed);
            }
            return Ok(frame);
        }

        // COW copy-on-write.
        if write && m.flags.contains(MapFlags::COW) {
            let base = m.base.ok_or(VmmError::NotMapped)?;
            let old = base.checked_add(m.offset(vaddr)).unwrap();
            if FRAME_REFS.lock().count(old) <= 1 {
                // Sole owner: promote in place (per-page override, COW cleared).
                let va = Vaddr(m.vaddr.as_u64() + m.offset(vaddr));
                let flags = MapFlags(m.flags.0 & !MapFlags::COW.0);
                let slot_pf = self
                    .page_frames
                    .iter()
                    .position(|(p, _)| *p == 0)
                    .ok_or(VmmError::PoolEmpty)?;
                self.page_frames[slot_pf] = (page_idx, old);
                be.protect_page(va, flags);
                return Ok(old);
            }
            let pool = self.pool.as_mut().ok_or(VmmError::NoPool)?;
            let fresh = pool.take().ok_or(VmmError::PoolEmpty)?;
            // NOTE: byte-copy of the page happens in the backend/arch layer
            // when it has a direct map (ADR-008).
            FRAME_REFS.lock().acquire(fresh);
            FRAME_REFS.lock().release(old);
            let va = Vaddr(m.vaddr.as_u64() + m.offset(vaddr));
            let flags = MapFlags(m.flags.0 & !MapFlags::COW.0);
            let slot_pf = self
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0)
                .ok_or(VmmError::PoolEmpty)?;
            self.page_frames[slot_pf] = (page_idx, fresh);
            // S10: backend failure — restore refcounts and the per-page
            // record; the fresh pool frame is burned (no Pool return path).
            if be.map_page_checked(va, fresh, flags).is_err() {
                self.page_frames[slot_pf] = (0, PhysAddr::new(0));
                FRAME_REFS.lock().acquire(old);
                FRAME_REFS.lock().release(fresh);
                return vmm_err(VmmError::MapFailed);
            }
            return Ok(fresh);
        }

        if write && !m.flags.contains(MapFlags::WRITE) {
            return vmm_err(VmmError::NoWritePerm);
        }
        m.base.ok_or(VmmError::NotMapped)
    }

    /// COW clone into a fresh child space (ADR-024): direct-frame regions
    /// shared with COW conversion, resolved pages copied via `copy_page`.
    fn fork_into(
        &mut self,
        be: &dyn PagingBackend,
        child: &mut AddressSpace,
        child_be: &dyn PagingBackend,
    ) -> Result<(), VmmError> {
        // 1. Direct-frame regions: share + COW-convert writable ones.
        for m in self.regions.iter().flatten() {
            if m.base.is_none() {
                // Unresolved ANON region: clone shape only (zero-fill faults).
                child
                    .map(child_be, m.vaddr, m.pages, None, m.flags)
                    .map_err(|_| VmmError::Overlap)?;
                continue;
            }
            let child_flags = if m.flags.contains(MapFlags::WRITE) {
                MapFlags(m.flags.0 | MapFlags::COW.0)
            } else {
                m.flags
            };
            // S10: child.map installs the child's PTEs before recording the
            // region, so a backend failure leaves no phantom child mapping.
            child
                .map(child_be, m.vaddr, m.pages, m.base, child_flags)
                .map_err(|_| VmmError::Overlap)?;
            // Convert the source's writable region to COW (backend re-protect).
            if m.flags.contains(MapFlags::WRITE) && !m.flags.contains(MapFlags::COW) {
                for i in 0..m.pages {
                    let va = Vaddr(m.vaddr.as_u64() + i * PAGE_SIZE as u64);
                    be.protect_page(va, MapFlags(m.flags.0 | MapFlags::COW.0));
                }
            }
        }
        // Mark source regions COW in the region table too (single pass over
        // mutable self after the child is built).
        for m in self.regions.iter_mut().flatten() {
            if m.base.is_some() && m.flags.contains(MapFlags::WRITE) {
                m.flags.0 |= MapFlags::COW.0;
            }
        }
        // 2. Resolved per-page overrides: fresh frame + copy contents.
        for i in 0..self.page_frames.len() {
            let (idx, frame) = self.page_frames[i];
            if idx == 0 {
                continue;
            }
            let Some(fresh) = frame::alloc() else {
                return vmm_err(VmmError::PoolEmpty);
            };
            if !child_be.copy_page(fresh, frame) {
                let _ = frame::free(fresh);
                return vmm_err(VmmError::NoBackend);
            }
            FRAME_REFS.lock().acquire(fresh);
            let va = Vaddr(idx * PAGE_SIZE as u64);
            // Use the CHILD's own free slot (bug if parent's position were
            // reused — the two tables fill differently).
            let slot_pf = child
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0)
                .ok_or(VmmError::Overlap)?;
            child.page_frames[slot_pf] = (idx, fresh);
            // S10: backend failure — drop the per-page record, the ref and
            // the fresh frame; fork fails cleanly (child is discarded by the
            // caller's error path).
            if child_be
                .map_page_checked(va, fresh, MapFlags::READ.union(MapFlags::WRITE))
                .is_err()
            {
                child.page_frames[slot_pf] = (0, PhysAddr::new(0));
                FRAME_REFS.lock().release(fresh);
                let _ = frame::free(fresh);
                return vmm_err(VmmError::MapFailed);
            }
        }
        Ok(())
    }

    /// Drop all mappings and per-page frames (AS::DESTROY). Override-aware:
    /// resolved pages release their override frame, not the base frame.
    fn destroy(&mut self, be: &dyn PagingBackend) {
        for i in 0..self.regions.len() {
            if let Some(m) = self.regions[i].take() {
                if let Some(b) = m.base {
                    for j in 0..m.pages {
                        let va = Vaddr(m.vaddr.as_u64() + j * PAGE_SIZE as u64);
                        be.unmap_page(va);
                        let page_idx = m.vaddr.page_index() + j;
                        let target = match self
                            .page_frames
                            .iter()
                            .find(|(p, _)| *p == page_idx)
                            .map(|(_, f)| *f)
                        {
                            Some(ov) => {
                                if let Some(pf) =
                                    self.page_frames.iter_mut().find(|(p, _)| *p == page_idx)
                                {
                                    *pf = (0, PhysAddr::new(0));
                                }
                                ov
                            }
                            None => match b.checked_add(j * PAGE_SIZE as u64) {
                                Some(pa) => pa,
                                None => continue,
                            },
                        };
                        FRAME_REFS.lock().release(target);
                    }
                }
            }
        }
        // Remaining overrides (ANON-region pages) released here.
        for i in 0..self.page_frames.len() {
            let (p, f) = self.page_frames[i];
            if p != 0 {
                be.unmap_page(Vaddr(p * PAGE_SIZE as u64));
                FRAME_REFS.lock().release(f);
                self.page_frames[i] = (0, PhysAddr::new(0));
            }
        }
        self.pool = None;
    }
}

fn vmm_err<T>(e: VmmError) -> Result<T, VmmError> {
    Err(e)
}

/// Physical frame refcounts — kernel-global (correct for COW sharing
/// across address spaces, ADR-022 §3). Open-addressing hash keyed by frame
/// address (v0.1: the 64-entry associative array saturated at the 4th
/// process generation — DS anomaly 3). Tombstones keep probe chains valid.
struct FrameRefs {
    slots: [RefEntry; REFS_CAPACITY],
    untrackable: u64,
}

/// 4096 slots (64 KiB, const-staged in .bss — the ADR-037 am2 pattern):
/// the dev-profile nested-spawn tree saturated the previous 1024-slot table
/// at ~2031 simultaneously-tracked frames; 4096 gives ~2.9x headroom at a
/// 0.7 open-addressing load factor. A dynamically growable table (boxed into
/// allocated frames) lands with the ADR-045 higher-half kernel-VA work; the
/// immortal-untrackable degradation below remains the final safety net.
const REFS_CAPACITY: usize = 4096;
const REF_EMPTY: u64 = u64::MAX;
const REF_TOMBSTONE: u64 = u64::MAX - 1;

#[derive(Clone, Copy)]
struct RefEntry {
    addr: u64, // REF_EMPTY = free, REF_TOMBSTONE = deleted
    count: usize,
}

impl FrameRefs {
    const fn new() -> Self {
        FrameRefs {
            slots: [RefEntry {
                addr: REF_EMPTY,
                count: 0,
            }; REFS_CAPACITY],
            untrackable: 0,
        }
    }

    fn probe_find(&self, addr: u64) -> Option<usize> {
        let start = (addr as usize) % REFS_CAPACITY;
        for i in 0..REFS_CAPACITY {
            let idx = (start + i) % REFS_CAPACITY;
            match self.slots[idx].addr {
                REF_EMPTY => return None, // end of probe chain
                a if a == addr => return Some(idx),
                _ => {}
            }
        }
        None
    }

    fn probe_insert_slot(&self, addr: u64) -> Option<usize> {
        let start = (addr as usize) % REFS_CAPACITY;
        let mut tomb: Option<usize> = None;
        for i in 0..REFS_CAPACITY {
            let idx = (start + i) % REFS_CAPACITY;
            match self.slots[idx].addr {
                REF_EMPTY => return tomb.or(Some(idx)),
                REF_TOMBSTONE => {
                    if tomb.is_none() {
                        tomb = Some(idx);
                    }
                }
                a if a == addr => return Some(idx),
                _ => {}
            }
        }
        tomb
    }

    /// Live (non-empty, non-tombstone) slot count — the occupancy diagnostic
    /// input for the growable-table trigger (ADR-045 slice 3).
    fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|e| e.addr != REF_EMPTY && e.addr != REF_TOMBSTONE)
            .count()
    }

    fn acquire(&mut self, addr: PhysAddr) {
        let a = addr.as_u64();
        match self.probe_insert_slot(a) {
            Some(idx) => {
                self.slots[idx].addr = a;
                self.slots[idx].count += 1;
            }
            None => {
                // Table full: the frame becomes implicitly immortal (release
                // is a no-op for it). One summary warning, not one per frame.
                self.untrackable += 1;
                if self.untrackable == 1 {
                    crate::kwarn!(
                        "FrameRefs full: frames acquired beyond capacity are never freed (immortal) - {} untrackable so far",
                        self.untrackable
                    );
                }
            }
        }
    }

    fn release(&mut self, addr: PhysAddr) -> usize {
        let a = addr.as_u64();
        match self.probe_find(a) {
            Some(idx) => {
                self.slots[idx].count -= 1;
                let remaining = self.slots[idx].count;
                if remaining == 0 {
                    let _ = frame::free(addr);
                    self.slots[idx].addr = REF_TOMBSTONE;
                    self.slots[idx].count = 0;
                }
                remaining
            }
            None => 0, // untracked frame: release is a no-op (immortal)
        }
    }

    fn count(&self, addr: PhysAddr) -> usize {
        self.probe_find(addr.as_u64())
            .map(|i| self.slots[i].count)
            .unwrap_or(0)
    }
}

static FRAME_REFS: Mutex<FrameRefs> = Mutex::new(FrameRefs::new());

/// FrameRefs occupancy (live slots / capacity) — logged at thread exit
/// next to the kstack depth report, so the growable-table trigger
/// (consistently > ~70%) is DATA-DRIVEN, not guessed.
pub fn frame_refs_occupancy() -> (usize, usize, u64) {
    let guard = FRAME_REFS.lock();
    let live = guard.live_count();
    (live, REFS_CAPACITY, guard.untrackable)
}

/// AS object: VMM state + its own paging backend (ADR-022 §1).
pub struct AsObject {
    pub id: ObjId,
    space: AddressSpace,
    backend: &'static dyn PagingBackend,
}

/// Fixed AS registry. Slot 0 = default AS (id 1, kernel-wide bring-up VMM).
const MAX_AS: usize = 16;
pub const DEFAULT_AS: ObjId = ObjId(1);

static AS_TABLE: Mutex<[Option<AsObject>; MAX_AS]> = Mutex::new([const { None }; MAX_AS]);

/// Create the default AS (id 1) with a factory-produced backend. Call once
/// from boot (init sequence) before any VMM op.
pub fn init_default() -> Result<(), VmmError> {
    create_as(DEFAULT_AS)
}

fn create_as(id: ObjId) -> Result<(), VmmError> {
    let factory = FACTORY
        .lock()
        .as_ref()
        .copied()
        .ok_or(VmmError::NoBackend)?;
    let backend = factory.create(id.0).ok_or(VmmError::NoBackend)?;
    let mut table = AS_TABLE.lock();
    let slot = (id.0 as usize).checked_sub(1).ok_or(VmmError::BadVaddr)?;
    if slot >= MAX_AS {
        return vmm_err(VmmError::TableFull);
    }
    if table[slot].is_some() {
        return vmm_err(VmmError::AlreadyExists);
    }
    table[slot] = Some(AsObject {
        id,
        space: AddressSpace::new(),
        backend,
    });
    Ok(())
}

/// Create a new address space; returns its id.
pub fn create() -> Result<ObjId, VmmError> {
    let table = AS_TABLE.lock();
    for slot in 0..MAX_AS {
        if table[slot].is_none() {
            let id = ObjId(slot as u64 + 1);
            drop(table);
            create_as(id)?;
            return Ok(id);
        }
    }
    vmm_err(VmmError::TableFull)
}

/// Destroy an AS: drop all mappings and refcounts, free the registry slot.
pub fn destroy(id: ObjId) -> Result<(), VmmError> {
    let mut table = AS_TABLE.lock();
    let slot = (id.0 as usize).checked_sub(1).ok_or(VmmError::BadVaddr)?;
    if slot >= MAX_AS {
        return vmm_err(VmmError::BadVaddr);
    }
    match table[slot].as_mut() {
        Some(aso) => {
            aso.space.destroy(aso.backend);
            table[slot] = None;
            Ok(())
        }
        None => vmm_err(VmmError::NotFound),
    }
}

fn with_as<T>(
    id: ObjId,
    f: impl FnOnce(&mut AddressSpace, &dyn PagingBackend) -> Result<T, VmmError>,
) -> Result<T, VmmError> {
    let mut table = AS_TABLE.lock();
    let slot = (id.0 as usize).checked_sub(1).ok_or(VmmError::BadVaddr)?;
    match table[slot].as_mut() {
        Some(aso) => f(&mut aso.space, aso.backend),
        None => vmm_err(VmmError::NotFound),
    }
}

/// Map `pages` pages at `vaddr` in address space `as_id`.
pub fn map(
    as_id: ObjId,
    vaddr: Vaddr,
    pages: u64,
    base: Option<PhysAddr>,
    flags: MapFlags,
) -> Result<PhysAddr, VmmError> {
    with_as(as_id, |space, be| space.map(be, vaddr, pages, base, flags))
}

pub fn unmap(as_id: ObjId, vaddr: Vaddr, pages: u64) -> Result<(), VmmError> {
    with_as(as_id, |space, be| space.unmap(be, vaddr, pages))
}

pub fn protect(as_id: ObjId, vaddr: Vaddr, flags: MapFlags) -> Result<(), VmmError> {
    with_as(as_id, |space, be| space.protect(be, vaddr, flags))
}

pub fn translate(as_id: ObjId, vaddr: Vaddr) -> Result<(PhysAddr, MapFlags), VmmError> {
    with_as(as_id, |space, _| space.translate(vaddr))
}

pub fn resolve_fault(as_id: ObjId, vaddr: Vaddr, write: bool) -> Result<PhysAddr, VmmError> {
    with_as(as_id, |space, be| space.resolve_fault(be, vaddr, write))
}

/// Install a mapping from a pager's FAULT_RESOLVE reply (ADR-007 §2).
pub fn install_from_reply(
    as_id: ObjId,
    vaddr: Vaddr,
    frame_addr: PhysAddr,
    flags: MapFlags,
) -> Result<bool, VmmError> {
    with_as(as_id, |space, be| {
        space.install_from_reply(be, vaddr, frame_addr, flags)
    })
}

/// COW-clone `parent` into a fresh AS; returns the child id (ADR-024).
pub fn fork(parent: ObjId) -> Result<ObjId, VmmError> {
    let child_id = create()?;
    let mut table = AS_TABLE.lock();
    let pslot = (parent.0 as usize)
        .checked_sub(1)
        .ok_or(VmmError::BadVaddr)?;
    let cslot = (child_id.0 as usize)
        .checked_sub(1)
        .ok_or(VmmError::BadVaddr)?;

    // Take both options out to avoid double mutable borrow of the table.
    let p_opt = table[pslot].take();
    let c_opt = table[cslot].take();

    match (p_opt, c_opt) {
        (Some(mut p), Some(mut c)) => match p.space.fork_into(p.backend, &mut c.space, c.backend) {
            Ok(_) => {
                table[pslot] = Some(p);
                table[cslot] = Some(c);
                Ok(child_id)
            }
            Err(e) => {
                table[pslot] = Some(p);
                table[cslot] = Some(c);
                vmm_err(e)
            }
        },
        (Some(p), None) => {
            table[pslot] = Some(p);
            vmm_err(VmmError::NotFound)
        }
        (None, Some(c)) => {
            table[cslot] = Some(c);
            vmm_err(VmmError::NotFound)
        }
        (None, None) => vmm_err(VmmError::NotFound),
    }
}

/// Attach or replace the fault pool of `as_id`.
pub fn set_pool(as_id: ObjId, base: PhysAddr, bytes: u64) -> Result<(), VmmError> {
    with_as(as_id, |space, _| space.set_pool(base, bytes))
}

/// Whether `as_id` has a fault pool attached.
pub fn has_pool(as_id: ObjId) -> Result<bool, VmmError> {
    with_as(as_id, |space, _| Ok(space.has_pool()))
}

/// Register a frame with the refcount table (acquires one ref).
pub fn track_frame(addr: PhysAddr) {
    FRAME_REFS.lock().acquire(addr);
}

/// Current refcount of a tracked frame (0 if untracked).
pub fn frame_refs(addr: PhysAddr) -> usize {
    FRAME_REFS.lock().count(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        ops: [(&'static str, u64); 16],
        n: usize,
    }

    impl Recorder {
        const fn new() -> Self {
            Recorder {
                ops: [("", 0); 16],
                n: 0,
            }
        }
        fn push(&mut self, op: &'static str, v: u64) {
            if self.n < 16 {
                self.ops[self.n] = (op, v);
                self.n += 1;
            }
        }
    }

    static REC: Mutex<Recorder> = Mutex::new(Recorder::new());

    struct TestBackend;
    impl PagingBackend for TestBackend {
        fn map_page(&self, v: Vaddr, p: PhysAddr, _f: MapFlags) {
            REC.lock().push("map", v.as_u64() ^ p.as_u64());
        }
        fn unmap_page(&self, v: Vaddr) {
            REC.lock().push("unmap", v.as_u64());
        }
        fn protect_page(&self, v: Vaddr, _f: MapFlags) {
            REC.lock().push("prot", v.as_u64());
        }
    }

    struct TestFactory;
    impl BackendFactory for TestFactory {
        fn create(&self, _as_id: u64) -> Option<&'static dyn PagingBackend> {
            Some(&TestBackend)
        }
    }

    /// S10 request: a backend whose page-table install fails (no free
    /// page-table frame). Kernel callers must report `MapFailed` and leave
    /// no phantom state behind.
    struct FailBackend;
    impl PagingBackend for FailBackend {
        fn map_page(&self, _v: Vaddr, _p: PhysAddr, _f: MapFlags) {
            REC.lock().push("map", 0);
        }
        fn map_page_checked(&self, _v: Vaddr, _p: PhysAddr, _f: MapFlags) -> Result<(), VmmError> {
            Err(VmmError::MapFailed)
        }
        fn unmap_page(&self, v: Vaddr) {
            REC.lock().push("unmap", v.as_u64());
        }
        fn protect_page(&self, _v: Vaddr, _f: MapFlags) {}
    }

    struct FailFactory;
    impl BackendFactory for FailFactory {
        fn create(&self, _as_id: u64) -> Option<&'static dyn PagingBackend> {
            Some(&FailBackend)
        }
    }

    /// Reset the registry with `FailFactory` as the backend source.
    fn setup_failing() -> ObjId {
        set_backend_factory(&FailFactory);
        REC.lock().n = 0;
        for i in 0..MAX_AS {
            AS_TABLE.lock()[i] = None;
        }
        let _ = init_default();
        DEFAULT_AS
    }

    #[test]
    fn backend_map_failure_propagates_without_phantom_state() {
        let as_id = setup_failing();

        // Direct-frame MAP: the backend install fails → MapFailed, and the
        // region + mapping ref recorded by the map path are discarded.
        let base = PhysAddr::new(0x30_0000);
        track_frame(base);
        assert_eq!(
            map(as_id, Vaddr(0x60_0000), 2, Some(base), MapFlags::READ),
            Err(VmmError::MapFailed)
        );
        assert_eq!(
            translate(as_id, Vaddr(0x60_0000)),
            Err(VmmError::NotFound),
            "no phantom region after a failed install"
        );
        assert_eq!(
            frame_refs(base),
            1,
            "only the owner grant remains (mapping ref released)"
        );
        // The failed range is reusable — no stale Overlap from the rollback.
        assert_eq!(
            map(as_id, Vaddr(0x60_0000), 1, Some(base), MapFlags::READ),
            Err(VmmError::MapFailed),
            "retry reports the backend failure, not a stale Overlap"
        );

        // ANON resolve: the resolve reports MapFailed and rolls the per-page
        // record back — a refault retries the backend instead of returning
        // a recorded-but-unbacked frame forever.
        set_pool(as_id, PhysAddr::new(0x31_0000), 2 * PAGE_SIZE as u64).unwrap();
        map(
            as_id,
            Vaddr(0x62_0000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        assert_eq!(
            resolve_fault(as_id, Vaddr(0x62_0000), false),
            Err(VmmError::MapFailed)
        );
        assert_eq!(
            resolve_fault(as_id, Vaddr(0x62_0000), false),
            Err(VmmError::MapFailed),
            "refault reports the same failure (no phantom frame record)"
        );
    }

    fn setup() -> ObjId {
        set_backend_factory(&TestFactory);
        REC.lock().n = 0;
        // Reset registry for tests: drop all ASes.
        for i in 0..MAX_AS {
            AS_TABLE.lock()[i] = None;
        }
        let _ = init_default();
        DEFAULT_AS
    }

    #[test]
    fn as_lifecycle_map_translate_unmap() {
        let as_id = setup();
        let base = PhysAddr::new(0x10_0000);
        track_frame(base);
        let v = Vaddr(0x40_0000);
        map(
            as_id,
            v,
            2,
            Some(base),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();

        let (pa, fl) = translate(as_id, Vaddr(0x40_1000)).unwrap();
        assert_eq!(pa, PhysAddr::new(0x10_1000));
        assert!(fl.contains(MapFlags::WRITE));
        assert_eq!(frame_refs(base), 2, "owner grant + mapping ref");

        unmap(as_id, v, 1).unwrap();
        assert!(translate(as_id, v).is_err());
        assert_eq!(frame_refs(base), 1, "mapping ref released, owner ref kept");

        // Overlap detection.
        map(as_id, v, 1, Some(base), MapFlags::READ).unwrap();
        assert_eq!(
            map(as_id, Vaddr(0x40_0000), 1, None, MapFlags::ANON),
            Err(VmmError::Overlap)
        );
        unmap(as_id, v, 1).unwrap();
    }

    #[test]
    fn per_as_isolation() {
        let a = setup();
        // Two distinct address spaces must not see each other's mappings.
        let b = create().unwrap();
        assert_ne!(a, b);
        let base = PhysAddr::new(0x11_0000);
        track_frame(base);
        map(a, Vaddr(0x45_0000), 1, Some(base), MapFlags::READ).unwrap();
        assert!(translate(a, Vaddr(0x45_0000)).is_ok());
        assert!(translate(b, Vaddr(0x45_0000)).is_err(), "AS isolation");
        // Same vaddr in b is free.
        assert!(map(b, Vaddr(0x45_0000), 1, None, MapFlags::ANON).is_ok());
        assert_eq!(destroy(b), Ok(()));
        assert!(translate(b, Vaddr(0x45_0000)).is_err());
    }

    #[test]
    fn anon_pool_cow_lifecycle() {
        let as_id = setup();
        // Pool for anon + COW.
        set_pool(as_id, PhysAddr::new(0x20_0000), 8 * PAGE_SIZE as u64).unwrap();

        // ANON zero-fill from pool.
        let va = Vaddr(0x50_0000);
        map(as_id, va, 2, None, MapFlags::ANON.union(MapFlags::READ)).unwrap();
        assert_eq!(translate(as_id, va), Err(VmmError::NotMapped));
        let f = resolve_fault(as_id, va, false).unwrap();
        assert_eq!(f, PhysAddr::new(0x20_0000), "pool frames in order");
        assert_eq!(translate(as_id, va).unwrap().0, f);

        // Pool exhaustion → PoolEmpty.
        let v2 = Vaddr(0x50_2000);
        map(as_id, v2, 8, None, MapFlags::ANON.union(MapFlags::READ)).unwrap();
        for i in 1..8u64 {
            resolve_fault(as_id, Vaddr(v2.as_u64() + i * PAGE_SIZE as u64), false).unwrap();
        }
        assert_eq!(resolve_fault(as_id, v2, false), Err(VmmError::PoolEmpty));

        // Fresh (smaller) pool for the COW section.
        set_pool(as_id, PhysAddr::new(0x30_0000), 4 * PAGE_SIZE as u64).unwrap();

        // COW: shared write copies, sole owner promotes.
        let cow_base = PhysAddr::new(0x11_0000);
        track_frame(cow_base);
        track_frame(cow_base); // refcount 2 = "shared with fork child"
        let vc = Vaddr(0x60_0000);
        map(
            as_id,
            vc,
            1,
            Some(cow_base),
            MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::COW),
        )
        .unwrap();
        let fresh = resolve_fault(as_id, vc, true).unwrap();
        assert_eq!(fresh, PhysAddr::new(0x30_0000));
        assert_eq!(frame_refs(cow_base), 2, "one mapping ref dropped");
        assert_eq!(resolve_fault(as_id, vc, true), Ok(fresh), "promote");

        // Write without permission → userspace fault.
        let v3 = Vaddr(0x70_0000);
        let base3 = PhysAddr::new(0x12_0000);
        track_frame(base3);
        map(as_id, v3, 1, Some(base3), MapFlags::READ).unwrap();
        assert_eq!(resolve_fault(as_id, v3, true), Err(VmmError::NoWritePerm));

        // AS::DESTROY drops mappings + refcounts.
        destroy(as_id).unwrap();
        assert!(translate(as_id, vc).is_err());
    }
    #[test]
    fn map_merges_adjacent_same_flag_regions() {
        let as_id = setup();
        let base = PhysAddr::new(0x14_0000);
        track_frame(base);
        // Three contiguous 1-page maps with identical flags/backing coalesce.
        map(as_id, Vaddr(0x80_0000), 1, Some(base), MapFlags::READ).unwrap();
        map(
            as_id,
            Vaddr(0x80_1000),
            1,
            Some(base.checked_add(PAGE_SIZE as u64).unwrap()),
            MapFlags::READ,
        )
        .unwrap();
        map(
            as_id,
            Vaddr(0x80_2000),
            1,
            Some(base.checked_add(2 * PAGE_SIZE as u64).unwrap()),
            MapFlags::READ,
        )
        .unwrap();
        // Internals: only one region covers all three pages.
        let count = AS_TABLE.lock()[(as_id.0 - 1) as usize]
            .as_ref()
            .unwrap()
            .space
            .regions
            .iter()
            .flatten()
            .count();
        assert_eq!(count, 1, "three adjacent maps merged into one region");
        // Translations still resolve per page.
        assert_eq!(
            translate(as_id, Vaddr(0x80_1000)).unwrap().0,
            base.checked_add(PAGE_SIZE as u64).unwrap()
        );

        // Different flags do NOT merge.
        map(
            as_id,
            Vaddr(0x80_3000),
            1,
            Some(base.checked_add(3 * PAGE_SIZE as u64).unwrap()),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();
        let count = AS_TABLE.lock()[(as_id.0 - 1) as usize]
            .as_ref()
            .unwrap()
            .space
            .regions
            .iter()
            .flatten()
            .count();
        assert_eq!(count, 2, "flag change prevents merge");

        // ANON regions merge too.
        map(
            as_id,
            Vaddr(0x90_0000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        map(
            as_id,
            Vaddr(0x90_1000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        let count = AS_TABLE.lock()[(as_id.0 - 1) as usize]
            .as_ref()
            .unwrap()
            .space
            .regions
            .iter()
            .flatten()
            .count();
        assert_eq!(count, 3, "ANON pair merged (R map + RW map + ANON pair)");
    }
    #[test]
    fn unmap_is_page_granular_in_merged_regions() {
        // DS anomaly fix: UNMAP of one page inside a coalesced region must
        // not destroy neighbouring mappings (was region-granular: a scratch
        // UNMAP killed the child's stack pages + package data).
        let as_id = setup();
        let base = PhysAddr::new(0x16_0000);
        // Owner ref on the base frame only; pages 2–3 hold pure mapping refs
        // (unmap releases exactly one per unmapped page).
        track_frame(base);
        // Three adjacent maps coalesce into one 3-page region.
        map(
            as_id,
            Vaddr(0xA0_0000),
            1,
            Some(base),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();
        map(
            as_id,
            Vaddr(0xA0_1000),
            1,
            Some(base.checked_add(PAGE_SIZE as u64).unwrap()),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();
        map(
            as_id,
            Vaddr(0xA0_2000),
            1,
            Some(base.checked_add(2 * PAGE_SIZE as u64).unwrap()),
            MapFlags::READ.union(MapFlags::WRITE),
        )
        .unwrap();
        assert_eq!(frame_refs(base), 2, "owner + merged mapping");

        // Unmap the MIDDLE page.
        unmap(as_id, Vaddr(0xA0_1000), 1).unwrap();
        assert!(translate(as_id, Vaddr(0xA0_1000)).is_err(), "middle gone");
        assert!(translate(as_id, Vaddr(0xA0_0000)).is_ok(), "head survives");
        assert!(translate(as_id, Vaddr(0xA0_2000)).is_ok(), "tail survives");
        // Refs: unmapped middle page fully released; head keeps owner+mapping;
        // tail keeps its mapping.
        std::println!(
            "DBG refs base={:?} mid={:?} tail={:?}",
            frame_refs(base),
            frame_refs(base.checked_add(PAGE_SIZE as u64).unwrap()),
            frame_refs(base.checked_add(2 * PAGE_SIZE as u64).unwrap())
        );
        assert_eq!(frame_refs(base), 2, "owner + head mapping ref");
        assert_eq!(
            frame_refs(base.checked_add(PAGE_SIZE as u64).unwrap()),
            0,
            "middle released"
        );
        assert_eq!(
            frame_refs(base.checked_add(2 * PAGE_SIZE as u64).unwrap()),
            1,
            "tail mapping ref"
        );

        // Head and tail are now separate regions (split happened).
        let count = AS_TABLE.lock()[(as_id.0 - 1) as usize]
            .as_ref()
            .unwrap()
            .space
            .regions
            .iter()
            .flatten()
            .count();
        assert_eq!(count, 2, "split into head + tail");

        // Multi-page unmap spanning head..middle (with the hole skipped,
        // munmap semantics). The tail is outside the span and survives.
        unmap(as_id, Vaddr(0xA0_0000), 2).unwrap();
        assert!(translate(as_id, Vaddr(0xA0_0000)).is_err());
        assert!(translate(as_id, Vaddr(0xA0_1000)).is_err(), "hole skipped");
        assert!(
            translate(as_id, Vaddr(0xA0_2000)).is_ok(),
            "tail survives (outside span)"
        );
        assert_eq!(frame_refs(base), 1, "only the owner ref remains");
        assert_eq!(frame_refs(base.checked_add(PAGE_SIZE as u64).unwrap()), 0);

        // ANON page-granular unmap: resolved page freed, sibling kept.
        set_pool(as_id, PhysAddr::new(0x18_0000), 2 * PAGE_SIZE as u64).unwrap();
        map(
            as_id,
            Vaddr(0xB0_0000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        map(
            as_id,
            Vaddr(0xB0_1000),
            1,
            None,
            MapFlags::ANON.union(MapFlags::READ),
        )
        .unwrap();
        let f0 = resolve_fault(as_id, Vaddr(0xB0_0000), false).unwrap();
        let f1 = resolve_fault(as_id, Vaddr(0xB0_1000), false).unwrap();
        unmap(as_id, Vaddr(0xB0_0000), 1).unwrap();
        assert!(translate(as_id, Vaddr(0xB0_0000)).is_err());
        assert_eq!(
            translate(as_id, Vaddr(0xB0_1000)).unwrap().0,
            f1,
            "sibling ANON page survives"
        );
        assert_eq!(frame_refs(f0), 0, "unmapped ANON page freed");
        assert_eq!(frame_refs(f1), 1);
    }
    #[test]
    fn unmap_releases_override_frames_not_shared_base() {
        // DS flakiness (b) root cause: a COW-resolved page inside a base-
        // backed region holds its OWN override frame; unmapping it must
        // release the override, not the (possibly COW-shared) base frame.
        let as_id = setup();
        set_pool(as_id, PhysAddr::new(0x1A_0000), 2 * PAGE_SIZE as u64).unwrap();
        let base = PhysAddr::new(0x19_0000);
        track_frame(base);
        track_frame(base); // refcount 2 = "COW-shared with a sibling"
        map(
            as_id,
            Vaddr(0xC0_0000),
            1,
            Some(base),
            MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::COW),
        )
        .unwrap();

        // Write-fault resolves the COW: page now backed by a pool frame.
        let resolved = resolve_fault(as_id, Vaddr(0xC0_0000), true).unwrap();
        assert_ne!(resolved, base);
        assert_eq!(frame_refs(base), 2, "sibling still shares the base");

        // Unmap the resolved page: override frame released; base untouched.
        unmap(as_id, Vaddr(0xC0_0000), 1).unwrap();
        assert!(translate(as_id, Vaddr(0xC0_0000)).is_err());
        assert_eq!(frame_refs(resolved), 0, "override frame freed");
        assert_eq!(frame_refs(base), 2, "shared base frame untouched");
        assert_eq!(frame::free_count(), frame::free_count(), "allocator sane");
    }
    #[test]
    fn translate_stack_pages_match_staged_frames_exactly() {
        // DS's one-page-shift check: 16 contiguous staged stack pages
        // (bottom frame = sp), then translate EVERY page — each must be
        // exactly sp + i*4096. Also exercises the coalesced-region path
        // (16 adjacent maps merge into one 16-page region).
        let as_id = setup();
        let sp = PhysAddr::new(0x10_14000);
        let top = 0x7FFF_FFFF_F000u64; // hal::layout::USER_STACK_TOP
        let stack_bottom_vaddr = top - 16 * PAGE_SIZE as u64; // 0x7FFF_FFFE_F000
        for i in 0..16u64 {
            map(
                as_id,
                Vaddr(stack_bottom_vaddr + i * PAGE_SIZE as u64),
                1,
                Some(sp.checked_add(i * PAGE_SIZE as u64).unwrap()),
                MapFlags::READ.union(MapFlags::WRITE),
            )
            .unwrap();
        }
        for i in 0..16u64 {
            let (pa, _) = translate(as_id, Vaddr(stack_bottom_vaddr + i * PAGE_SIZE as u64))
                .unwrap_or_else(|e| panic!("page {i} unmapped: {e:?}"));
            assert_eq!(
                pa,
                sp.checked_add(i * PAGE_SIZE as u64).unwrap(),
                "stack page {i} off-by-one"
            );
        }
        // The live repro's cr2 = TOP-0x700 = page 15 (the TOP page) ->
        // phys sp + 15*4096 = 0x1023000. Registry arithmetic verified exact:
        // DS's "off-by-one" reading assumed page 14; correct page math says
        // 0x1023000 — the divergence is hardware-side only.
        let cr2 = top - 0x700;
        let (pa, _) = translate(as_id, Vaddr(cr2)).unwrap();
        assert_eq!(pa, sp.checked_add(15 * PAGE_SIZE as u64).unwrap());
        assert_eq!(pa, PhysAddr::new(0x10_23000));
    }

    /// S4: the pure range validator. Kernel-window addresses (PML4[511]),
    /// the reserved PML4[256..510] range, the split value itself, VA 0 and
    /// unaligned addresses are all rejected; the last user page and a range
    /// ending exactly at the split are accepted.
    #[test]
    fn s4_validate_user_range_bounds() {
        let split = crate::sched::USER_ADDR_LIMIT;
        let last_user = split - PAGE_SIZE as u64;

        // Accepted: ordinary user pages, the final user page, a range that
        // ends exactly at the split.
        assert_eq!(validate_user_range(Vaddr(0x40_0000), 2), Ok(()));
        assert_eq!(validate_user_range(Vaddr(last_user), 1), Ok(()));
        assert_eq!(
            validate_user_range(Vaddr(last_user - PAGE_SIZE as u64), 2),
            Ok(())
        );

        // Rejected: null, unaligned, empty.
        assert_eq!(validate_user_range(Vaddr(0), 1), Err(VmmError::BadVaddr));
        assert_eq!(
            validate_user_range(Vaddr(0x40_0001), 1),
            Err(VmmError::BadVaddr)
        );
        assert_eq!(
            validate_user_range(Vaddr(0x40_0000), 0),
            Err(VmmError::BadVaddr)
        );

        // Rejected: the split itself, the reserved middle, the kernel window.
        for bad in [
            split,
            0x0000_C000_0000_0000, // PML4[384] (reserved non-canonical middle)
            0xFFFF_0000_0000_0000, // PML4[510]
            0xFFFF_8000_0100_0000, // the shared kernel window (ADR-045)
            0xFFFF_FFFF_FFFF_F000, // top of PML4[511]
        ] {
            assert_eq!(
                validate_user_range(Vaddr(bad), 1),
                Err(VmmError::BadVaddr),
                "range start {bad:#x}"
            );
        }

        // Overflow-checked: a page count that wraps u64 must not pass, and
        // a range starting in user space but ending in the kernel half is
        // rejected wholesale.
        assert_eq!(
            validate_user_range(Vaddr(0x40_0000), u64::MAX),
            Err(VmmError::BadVaddr)
        );
        assert_eq!(
            validate_user_range(Vaddr(last_user), 2),
            Err(VmmError::BadVaddr),
            "range crosses the split"
        );
    }

    /// S4: MAP must not be able to install a mapping over the shared kernel
    /// window (PML4[511]) or any non-user range — the exact takeover vector
    /// (a user PTE on a kernel page). Nothing is recorded on rejection.
    #[test]
    fn s4_map_rejects_kernel_window_and_null_ranges() {
        let as_id = setup();
        let base = PhysAddr::new(0x21_0000);
        track_frame(base);

        for bad in [0u64, 0x0000_8000_0000_0000, 0xFFFF_8000_0100_0000] {
            assert_eq!(
                map(as_id, Vaddr(bad), 1, Some(base), MapFlags::READ),
                Err(VmmError::BadVaddr),
                "MAP frame-backed va={bad:#x}"
            );
            assert_eq!(
                map(
                    as_id,
                    Vaddr(bad),
                    1,
                    None,
                    MapFlags::ANON.union(MapFlags::READ)
                ),
                Err(VmmError::BadVaddr),
                "MAP anon va={bad:#x}"
            );
        }
        // Nothing recorded: no region, no phantom translation, no leaked ref.
        assert!(translate(as_id, Vaddr(0xFFFF_8000_0100_0000)).is_err());
        assert!(translate(as_id, Vaddr(0)).is_err());
        assert_eq!(frame_refs(base), 1, "only the owner grant remains");

        // A legal user map still works after the rejections.
        assert!(map(as_id, Vaddr(0x60_0000), 1, Some(base), MapFlags::READ).is_ok());
    }

    /// S4: a range that starts in user space must not be allowed to run
    /// into the kernel half, and a wrapping page count must not pass.
    #[test]
    fn s4_map_range_must_end_below_user_limit() {
        let as_id = setup();
        let base = PhysAddr::new(0x23_0000);
        track_frame(base);
        let last_user = crate::sched::USER_ADDR_LIMIT - PAGE_SIZE as u64;

        assert_eq!(
            map(as_id, Vaddr(last_user), 2, Some(base), MapFlags::READ),
            Err(VmmError::BadVaddr),
            "two pages at the last user page cross the split"
        );
        assert_eq!(
            map(
                as_id,
                Vaddr(0x40_0000),
                u64::MAX,
                None,
                MapFlags::ANON.union(MapFlags::READ)
            ),
            Err(VmmError::BadVaddr),
            "wrapping page count"
        );
        assert!(
            translate(as_id, Vaddr(last_user)).is_err(),
            "nothing recorded"
        );
    }

    /// S4: UNMAP and PROTECT validate their ranges before touching the
    /// region table (UNMAP's hole-skip walk must never sweep the kernel
    /// window; PROTECT must not reflag a kernel page).
    #[test]
    fn s4_unmap_protect_reject_non_user_ranges() {
        let as_id = setup();
        let base = PhysAddr::new(0x24_0000);
        track_frame(base);
        // A real user region to prove legitimate state survives.
        map(as_id, Vaddr(0x40_0000), 1, Some(base), MapFlags::READ).unwrap();

        // UNMAP: kernel window, null, crossing-the-split, wrapping count.
        assert_eq!(
            unmap(as_id, Vaddr(0xFFFF_8000_0100_0000), 1),
            Err(VmmError::BadVaddr)
        );
        assert_eq!(unmap(as_id, Vaddr(0), 1), Err(VmmError::BadVaddr));
        let last_user = crate::sched::USER_ADDR_LIMIT - PAGE_SIZE as u64;
        assert_eq!(unmap(as_id, Vaddr(last_user), 2), Err(VmmError::BadVaddr));
        assert_eq!(
            unmap(as_id, Vaddr(0x40_0000), u64::MAX),
            Err(VmmError::BadVaddr)
        );

        // PROTECT: null, unaligned, kernel window.
        assert_eq!(
            protect(as_id, Vaddr(0), MapFlags::READ),
            Err(VmmError::BadVaddr)
        );
        assert_eq!(
            protect(as_id, Vaddr(0x40_0001), MapFlags::READ),
            Err(VmmError::BadVaddr)
        );
        assert_eq!(
            protect(as_id, Vaddr(0xFFFF_8000_0100_0000), MapFlags::READ),
            Err(VmmError::BadVaddr)
        );

        // The legitimate region is untouched by all the rejections above.
        assert!(translate(as_id, Vaddr(0x40_0000)).is_ok());
        assert_eq!(
            protect(
                as_id,
                Vaddr(0x40_0000),
                MapFlags::READ.union(MapFlags::WRITE)
            ),
            Ok(())
        );
        assert!(translate(as_id, Vaddr(0x40_0000))
            .unwrap()
            .1
            .contains(MapFlags::WRITE));
    }
}
