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
    /// Install one page mapping.
    fn map_page(&self, vaddr: Vaddr, paddr: PhysAddr, flags: MapFlags);
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

const MAX_REGIONS: usize = 32;
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

    fn map(
        &mut self,
        vaddr: Vaddr,
        pages: u64,
        base: Option<PhysAddr>,
        flags: MapFlags,
    ) -> Result<PhysAddr, VmmError> {
        if !vaddr.is_page_aligned() || pages == 0 {
            return vmm_err(VmmError::BadVaddr);
        }
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
            FRAME_REFS.lock().acquire(b);
        }
        self.regions[slot] = Some(Mapping {
            vaddr,
            pages,
            base,
            flags,
        });
        Ok(base.unwrap_or(PhysAddr::new(0)))
    }

    /// Install backend entries page by page (called by the registry layer
    /// which owns the backend reference).
    fn map_backend(
        &self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        pages: u64,
        base: PhysAddr,
        flags: MapFlags,
    ) {
        for i in 0..pages {
            if let Some(pa) = base.checked_add(i * PAGE_SIZE as u64) {
                let va = Vaddr(vaddr.as_u64() + i * PAGE_SIZE as u64);
                be.map_page(va, pa, flags);
            }
        }
    }

    fn unmap(&mut self, be: &dyn PagingBackend, vaddr: Vaddr) -> Result<(), VmmError> {
        if !vaddr.is_page_aligned() {
            return vmm_err(VmmError::BadVaddr);
        }
        let slot = self
            .regions
            .iter()
            .position(|r| matches!(r, Some(m) if m.contains(vaddr)))
            .ok_or(VmmError::NotFound)?;
        let m = self.regions[slot].take().unwrap();
        if let Some(b) = m.base {
            self.map_backend_unmap(be, m.vaddr, m.pages);
            for i in 0..m.pages {
                if let Some(pa) = b.checked_add(i * PAGE_SIZE as u64) {
                    FRAME_REFS.lock().release(pa);
                }
            }
        } else if m.flags.contains(MapFlags::ANON) {
            // ANON: release every per-page frame in range.
            let start = m.vaddr.page_index();
            let end = start + m.pages;
            for i in 0..self.page_frames.len() {
                let (p, f) = self.page_frames[i];
                if p >= start && p < end {
                    FRAME_REFS.lock().release(f);
                    be.unmap_page(Vaddr(p * PAGE_SIZE as u64));
                    self.page_frames[i] = (0, PhysAddr::new(0));
                }
            }
        }
        Ok(())
    }

    fn map_backend_unmap(&self, be: &dyn PagingBackend, vaddr: Vaddr, pages: u64) {
        for i in 0..pages {
            let va = Vaddr(vaddr.as_u64() + i * PAGE_SIZE as u64);
            be.unmap_page(va);
        }
    }

    fn protect(
        &mut self,
        be: &dyn PagingBackend,
        vaddr: Vaddr,
        flags: MapFlags,
    ) -> Result<(), VmmError> {
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
        if !vaddr.is_page_aligned() || !frame_addr.is_frame_aligned() {
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
            self.page_frames[slot_pf] = (idx, frame_addr);
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
            self.page_frames[slot_pf] = (idx, frame_addr);
        }
        be.map_page(vaddr, frame_addr, flags);
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
            be.map_page(va, frame, m.flags);
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
            be.map_page(va, fresh, flags);
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
                    .map(m.vaddr, m.pages, None, m.flags)
                    .map_err(|_| VmmError::Overlap)?;
                continue;
            }
            let child_flags = if m.flags.contains(MapFlags::WRITE) {
                MapFlags(m.flags.0 | MapFlags::COW.0)
            } else {
                m.flags
            };
            child
                .map(m.vaddr, m.pages, m.base, child_flags)
                .map_err(|_| VmmError::Overlap)?;
            // child.map() already acquired the mapping ref on the base.
            if let Some(b) = m.base {
                child.map_backend(child_be, m.vaddr, m.pages, b, child_flags);
            }
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
            child_be.map_page(va, fresh, MapFlags::READ.union(MapFlags::WRITE));
        }
        Ok(())
    }

    /// Drop all mappings and per-page frames (AS::DESTROY).
    fn destroy(&mut self, be: &dyn PagingBackend) {
        for i in 0..self.regions.len() {
            if let Some(m) = self.regions[i].take() {
                if let Some(b) = m.base {
                    self.map_backend_unmap(be, m.vaddr, m.pages);
                    for j in 0..m.pages {
                        if let Some(pa) = b.checked_add(j * PAGE_SIZE as u64) {
                            FRAME_REFS.lock().release(pa);
                        }
                    }
                }
            }
        }
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
/// across address spaces, ADR-022 §3).
struct FrameRefs {
    counts: [RefEntry; MAX_TRACKED],
}

const MAX_TRACKED: usize = 64;

#[derive(Clone, Copy, Default)]
struct RefEntry {
    addr: Option<PhysAddr>,
    count: usize,
}

impl FrameRefs {
    fn acquire(&mut self, addr: PhysAddr) {
        for e in self.counts.iter_mut() {
            if e.addr == Some(addr) {
                e.count += 1;
                return;
            }
            if e.addr.is_none() {
                *e = RefEntry {
                    addr: Some(addr),
                    count: 1,
                };
                return;
            }
        }
        crate::kwarn!("FrameRefs table full at {}", addr);
    }

    fn release(&mut self, addr: PhysAddr) -> usize {
        for (i, e) in self.counts.iter_mut().enumerate() {
            if e.addr == Some(addr) {
                e.count -= 1;
                let remaining = e.count;
                if remaining == 0 {
                    let _ = frame::free(addr);
                    self.counts[i] = RefEntry::default();
                }
                return remaining;
            }
        }
        0
    }

    fn count(&self, addr: PhysAddr) -> usize {
        self.counts
            .iter()
            .find(|e| e.addr == Some(addr))
            .map(|e| e.count)
            .unwrap_or(0)
    }
}

impl FrameRefs {
    /// Fully const constructor (static init never builds stack temporaries).
    const fn new() -> Self {
        FrameRefs {
            counts: [RefEntry {
                addr: None,
                count: 0,
            }; MAX_TRACKED],
        }
    }
}

static FRAME_REFS: Mutex<FrameRefs> = Mutex::new(FrameRefs::new());

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
    with_as(as_id, |space, be| {
        let mapped = space.map(vaddr, pages, base, flags)?;
        if let Some(b) = base {
            space.map_backend(be, vaddr, pages, b, flags);
        }
        Ok(mapped)
    })
}

pub fn unmap(as_id: ObjId, vaddr: Vaddr) -> Result<(), VmmError> {
    with_as(as_id, |space, be| space.unmap(be, vaddr))
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

        unmap(as_id, v).unwrap();
        assert!(translate(as_id, v).is_err());
        assert_eq!(frame_refs(base), 1, "mapping ref released, owner ref kept");

        // Overlap detection.
        map(as_id, v, 1, Some(base), MapFlags::READ).unwrap();
        assert_eq!(
            map(as_id, Vaddr(0x40_0000), 1, None, MapFlags::ANON),
            Err(VmmError::Overlap)
        );
        unmap(as_id, v).unwrap();
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
}
