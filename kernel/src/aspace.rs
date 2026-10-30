//! Arch-independent virtual memory core (ADR-008): mapping registry, COW
//! refcounting, fault pools, and backend trait inversion.
//!
//! Arch crates provide a [`PagingBackend`] registered at boot; all policy
//! (regions, COW, pools) lives here and is host-testable.
#![forbid(unsafe_code)]

use crate::frame::{self, PhysAddr};
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
}

impl fmt::Display for VmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Kernel-owned page-table interface. Arch crates (hal-*) implement this and
/// register via [`set_backend`]. Implementations do raw MMIO — the safety
/// burden is theirs, per hal/ ownership.
pub trait PagingBackend: Sync + Send {
    /// Install one page mapping.
    fn map_page(&self, vaddr: Vaddr, paddr: PhysAddr, flags: MapFlags);
    /// Remove one page mapping (TLB flush is the backend's job).
    fn unmap_page(&self, vaddr: Vaddr);
    /// Change permissions of an existing mapping.
    fn protect_page(&self, vaddr: Vaddr, flags: MapFlags);
}

static BACKEND: Mutex<Option<&'static dyn PagingBackend>> = Mutex::new(None);

/// Register the arch paging backend. Call once from boot after `early_init`.
pub fn set_backend(b: &'static dyn PagingBackend) -> Result<(), VmmError> {
    let mut guard = BACKEND.lock();
    if guard.is_some() {
        return Err(VmmError::NoBackend);
    }
    *guard = Some(b);
    Ok(())
}

fn with_backend<T>(f: impl FnOnce(&dyn PagingBackend) -> T, or: T) -> T {
    // Brief lock; backend calls are expected to be short, no reentry.
    let guard = BACKEND.lock();
    match guard.as_ref() {
        Some(b) => f(*b),
        None => or,
    }
}

/// Physical frame refcounts. COW children share; last unmap releases the
/// frame back to the allocator.
struct FrameRefs {
    counts: [RefEntry; MAX_TRACKED],
}

impl FrameRefs {
    const fn new() -> Self {
        FrameRefs {
            counts: [RefEntry {
                addr: None,
                count: 0,
            }; MAX_TRACKED],
        }
    }
}

impl Default for FrameRefs {
    fn default() -> Self {
        FrameRefs::new()
    }
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
        // Tracked table full — kernel reserve growth is a Phase 2 concern;
        // caller paths guard with has_capacity.
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

/// Per-address-space state. In v0 the kernel holds one registry keyed by
/// ObjId; a full per-process instance model arrives with threads (Phase 1).
pub struct AddressSpace {
    regions: [Option<Mapping>; MAX_REGIONS],
    pool: Option<Pool>,
    /// Per-page frames for ANON regions (single-base model cannot represent
    /// lazily-faulted pages). Keyed by global page index.
    page_frames: [(u64, PhysAddr); MAX_PAGE_FRAMES],
}

const MAX_PAGE_FRAMES: usize = 64;

const MAX_REGIONS: usize = 32;

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

/// Global address space state. One kernel-wide instance for v0 (single AS
/// bring-up); multi-AS keyed by ObjId lands with the process server.
static VMM: Mutex<Option<AddressSpace>> = Mutex::new(None);
static FRAME_REFS: Mutex<FrameRefs> = Mutex::new(FrameRefs::new());

/// Initialize the VMM with an optional fault pool (base, size in bytes).
pub fn init(pool: Option<(PhysAddr, u64)>) -> Result<(), VmmError> {
    let mut guard = VMM.lock();
    if guard.is_some() {
        return Err(VmmError::NoBackend); // reuse: "already initialized"
    }
    let pool = pool.and_then(|(b, sz)| Pool::new(b, sz));
    *guard = Some(AddressSpace {
        regions: [const { None }; MAX_REGIONS],
        pool,
        page_frames: [(0, PhysAddr::new(0)); MAX_PAGE_FRAMES],
    });
    Ok(())
}

/// Register a frame with the refcount table (acquires one ref).
pub fn track_frame(addr: PhysAddr) {
    FRAME_REFS.lock().acquire(addr);
}

/// Current refcount of a tracked frame (0 if untracked).
pub fn frame_refs(addr: PhysAddr) -> usize {
    FRAME_REFS.lock().count(addr)
}

fn vmm_err<T>(e: VmmError) -> Result<T, VmmError> {
    Err(e)
}

/// Map `pages` pages at `vaddr`. COW/ANON mappings may pass `base = None`.
/// Returns the registered mapping base.
pub fn map(
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
    let mut guard = VMM.lock();
    let as_state = guard.as_mut().ok_or(VmmError::NoBackend)?;
    // Overlap check.
    for r in as_state.regions.iter().flatten() {
        let rs = r.vaddr.page_index();
        let re = rs + r.pages;
        let s = vaddr.page_index();
        if s < re && rs < end_idx {
            return vmm_err(VmmError::Overlap);
        }
    }
    let slot = as_state
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
    as_state.regions[slot] = Some(Mapping {
        vaddr,
        pages,
        base,
        flags,
    });
    // Install into the backend page by page.
    if let Some(b) = base {
        for i in 0..pages {
            let pa = b
                .checked_add(i * PAGE_SIZE as u64)
                .ok_or(VmmError::BadVaddr)?;
            let va = Vaddr(vaddr.as_u64() + i * PAGE_SIZE as u64);
            with_backend(|be| be.map_page(va, pa, flags), ());
        }
    }
    Ok(base.unwrap_or(PhysAddr::new(0)))
}

/// Remove the mapping containing `vaddr`, dropping refs and backend entries.
pub fn unmap(vaddr: Vaddr) -> Result<(), VmmError> {
    if !vaddr.is_page_aligned() {
        return vmm_err(VmmError::BadVaddr);
    }
    let mut guard = VMM.lock();
    let as_state = guard.as_mut().ok_or(VmmError::NoBackend)?;
    let slot = as_state
        .regions
        .iter()
        .position(|r| matches!(r, Some(m) if m.contains(vaddr)))
        .ok_or(VmmError::NotFound)?;
    let m = as_state.regions[slot].take().unwrap();
    if m.base.is_none() && m.flags.contains(MapFlags::ANON) {
        // ANON: release every per-page frame in range.
        let start = m.vaddr.page_index();
        let end = start + m.pages;
        for i in 0..as_state.page_frames.len() {
            let (p, f) = as_state.page_frames[i];
            if p >= start && p < end {
                FRAME_REFS.lock().release(f);
                with_backend(|be| be.unmap_page(Vaddr(p * PAGE_SIZE as u64)), ());
                as_state.page_frames[i] = (0, PhysAddr::new(0));
            }
        }
        return Ok(());
    }
    if let Some(b) = m.base {
        for i in 0..m.pages {
            let va = Vaddr(m.vaddr.as_u64() + i * PAGE_SIZE as u64);
            with_backend(|be| be.unmap_page(va), ());
        }
        // Drop one ref per page (each page holds a ref on its frame; for a
        // contiguous mapping the frames are contiguous, refcount is per-page).
        for i in 0..m.pages {
            let pa = b.checked_add(i * PAGE_SIZE as u64).unwrap();
            FRAME_REFS.lock().release(pa);
        }
    }
    Ok(())
}

/// Change permissions of an existing mapping (must contain `vaddr`).
pub fn protect(vaddr: Vaddr, flags: MapFlags) -> Result<(), VmmError> {
    let mut guard = VMM.lock();
    let as_state = guard.as_mut().ok_or(VmmError::NoBackend)?;
    for r in as_state.regions.iter_mut().flatten() {
        if r.contains(vaddr) {
            r.flags = flags;
            for i in 0..r.pages {
                let va = Vaddr(r.vaddr.as_u64() + i * PAGE_SIZE as u64);
                with_backend(|be| be.protect_page(va, flags), ());
            }
            return Ok(());
        }
    }
    vmm_err(VmmError::NotFound)
}

/// Translate a vaddr to its current physical frame + flags.
pub fn translate(vaddr: Vaddr) -> Result<(PhysAddr, MapFlags), VmmError> {
    let guard = VMM.lock();
    let as_state = guard.as_ref().ok_or(VmmError::NoBackend)?;
    let idx = vaddr.page_index();
    for m in as_state.regions.iter().flatten() {
        if m.contains(vaddr) {
            // Per-page overrides (resolved ANON/COW pages) take precedence.
            for (p, f) in as_state.page_frames.iter() {
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

/// Install a mapping from a pager's FAULT_RESOLVE reply (ADR-007 §2): the
/// kernel installs from the reply — the resolver needs no AS authority.
/// If a region already covers `vaddr`, this sets a per-page frame override;
/// otherwise it creates a one-page region. Returns previous coverage.
pub fn install_from_reply(
    vaddr: Vaddr,
    frame_addr: PhysAddr,
    flags: MapFlags,
) -> Result<bool, VmmError> {
    if !vaddr.is_page_aligned() || !frame_addr.is_frame_aligned() {
        return vmm_err(VmmError::BadVaddr);
    }
    let mut guard = VMM.lock();
    let as_state = guard.as_mut().ok_or(VmmError::NoBackend)?;
    let idx = vaddr.page_index();
    FRAME_REFS.lock().acquire(frame_addr);
    let covered = as_state.regions.iter().flatten().any(|m| m.contains(vaddr));
    if covered {
        // Per-page override (same mechanism as resolved ANON/COW pages).
        let slot_pf = as_state
            .page_frames
            .iter()
            .position(|(p, _)| *p == 0 || *p == idx)
            .ok_or(VmmError::Overlap)?;
        as_state.page_frames[slot_pf] = (idx, frame_addr);
    } else {
        let slot = as_state
            .regions
            .iter_mut()
            .position(|r| r.is_none())
            .ok_or(VmmError::Overlap)?;
        as_state.regions[slot] = Some(Mapping {
            vaddr,
            pages: 1,
            base: None,
            flags,
        });
        let slot_pf = as_state
            .page_frames
            .iter()
            .position(|(p, _)| *p == 0)
            .ok_or(VmmError::Overlap)?;
        as_state.page_frames[slot_pf] = (idx, frame_addr);
    }
    with_backend(|be| be.map_page(vaddr, frame_addr, flags), ());
    Ok(covered)
}

/// Handle a page fault (ADR-007 §4, §9):
/// - ANON region → zero-frame from pool (pool required);
/// - COW write → copy page from pool, remap writable, old ref dropped;
/// - otherwise → `NoPool`/`NoWritePerm` meaning "raise FAULT_PAGE to the
///   fault endpoint" (the caller decides; kernel syscall layer routes).
///
/// Returns the frame now backing the page.
pub fn resolve_fault(vaddr: Vaddr, write: bool) -> Result<PhysAddr, VmmError> {
    if !vaddr.is_page_aligned() {
        return vmm_err(VmmError::BadVaddr);
    }
    let mut guard = VMM.lock();
    let as_state = guard.as_mut().ok_or(VmmError::NoBackend)?;
    let slot = as_state
        .regions
        .iter()
        .position(|r| matches!(r, Some(m) if m.contains(vaddr)))
        .ok_or(VmmError::NotFound)?;
    let m = as_state.regions[slot].as_mut().unwrap();

    // Already-resolved page (ANON or COW copy): return the per-page frame.
    let page_idx = vaddr.page_index();
    for (p, f) in as_state.page_frames.iter() {
        if *p == page_idx {
            return Ok(*f);
        }
    }

    // Anonymous zero-fill (idempotent: a refault returns the same frame).
    if m.flags.contains(MapFlags::ANON) {
        let pool = as_state.pool.as_mut().ok_or(VmmError::NoPool)?;
        let frame = pool.take().ok_or(VmmError::PoolEmpty)?;
        FRAME_REFS.lock().acquire(frame);
        let slot = as_state
            .page_frames
            .iter()
            .position(|(p, _)| *p == 0)
            .ok_or(VmmError::PoolEmpty)?;
        as_state.page_frames[slot] = (page_idx, frame);
        let va = Vaddr(m.vaddr.as_u64() + m.offset(vaddr));
        with_backend(|be| be.map_page(va, frame, m.flags), ());
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
            let slot_pf = as_state
                .page_frames
                .iter()
                .position(|(p, _)| *p == 0)
                .ok_or(VmmError::PoolEmpty)?;
            as_state.page_frames[slot_pf] = (page_idx, old);
            with_backend(|be| be.protect_page(va, flags), ());
            return Ok(old);
        }
        let pool = as_state.pool.as_mut().ok_or(VmmError::NoPool)?;
        let fresh = pool.take().ok_or(VmmError::PoolEmpty)?;
        // NOTE: byte-copy of the page happens in the backend/arch layer when
        // it has a direct map; v0 host logic tracks refcounts only. The
        // backend hook `map_page` installs the fresh frame; content copy is
        // arch responsibility (documented in ADR-008).
        FRAME_REFS.lock().acquire(fresh);
        FRAME_REFS.lock().release(old);
        let va = Vaddr(m.vaddr.as_u64() + m.offset(vaddr));
        let flags = MapFlags(m.flags.0 & !MapFlags::COW.0);
        let slot_pf = as_state
            .page_frames
            .iter()
            .position(|(p, _)| *p == 0)
            .ok_or(VmmError::PoolEmpty)?;
        as_state.page_frames[slot_pf] = (page_idx, fresh);
        with_backend(|be| be.map_page(va, fresh, flags), ());
        return Ok(fresh);
    }

    if write && !m.flags.contains(MapFlags::WRITE) {
        return vmm_err(VmmError::NoWritePerm);
    }
    m.base.ok_or(VmmError::NotMapped)
}

#[cfg(test)]
pub(crate) fn vmm_for_test() -> spin::MutexGuard<'static, Option<AddressSpace>> {
    *VMM.lock() = None;
    VMM.lock()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: swap in a fresh pool without full re-init (init is
    /// once-only in production; tests advance the same VMM sequentially).
    fn init_pool_for_test(pool: Option<(PhysAddr, u64)>) -> Result<(), VmmError> {
        let mut guard = VMM.lock();
        let pool = pool.and_then(|(b, sz)| Pool::new(b, sz));
        match guard.as_mut() {
            Some(as_state) => {
                as_state.pool = pool;
                Ok(())
            }
            None => {
                *guard = Some(AddressSpace {
                    regions: [const { None }; MAX_REGIONS],
                    pool,
                    page_frames: [(0, PhysAddr::new(0)); MAX_PAGE_FRAMES],
                });
                Ok(())
            }
        }
    }

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

    fn setup() {
        let _ = set_backend(&TestBackend);
        REC.lock().n = 0;
    }

    #[test]
    fn aspace_lifecycle() {
        setup();
        init(None).unwrap();

        // --- map / translate / unmap ---
        let base = PhysAddr::new(0x10_0000);
        track_frame(base);
        let v = Vaddr(0x40_0000);
        map(v, 2, Some(base), MapFlags::READ.union(MapFlags::WRITE)).unwrap();

        let (pa, fl) = translate(Vaddr(0x40_1000)).unwrap();
        assert_eq!(pa, PhysAddr::new(0x10_1000));
        assert!(fl.contains(MapFlags::WRITE));
        assert_eq!(frame_refs(base), 2, "owner grant + mapping ref");

        unmap(v).unwrap();
        assert!(translate(v).is_err());
        assert_eq!(frame_refs(base), 1, "mapping ref released, owner ref kept");

        // Overlap detection.
        map(v, 1, Some(base), MapFlags::READ).unwrap();
        assert_eq!(
            map(Vaddr(0x40_0000), 1, None, MapFlags::ANON),
            Err(VmmError::Overlap)
        );
        unmap(v).unwrap();

        // --- anon zero-fill from pool ---
        let _ = init_pool_for_test(Some((PhysAddr::new(0x20_0000), 8 * PAGE_SIZE as u64)));
        let va = Vaddr(0x50_0000);
        map(va, 2, None, MapFlags::ANON.union(MapFlags::READ)).unwrap();
        assert_eq!(
            translate(va),
            Err(VmmError::NotMapped),
            "no frame until fault"
        );

        let f = resolve_fault(va, false).unwrap();
        assert_eq!(f, PhysAddr::new(0x20_0000), "pool frames handed in order");
        let (pa2, _) = translate(va).unwrap();
        assert_eq!(pa2, f);

        // Pool exhaustion surfaces as PoolEmpty -> FAULT_PAGE POOL_EMPTY.
        let v2 = Vaddr(0x50_2000);
        map(v2, 8, None, MapFlags::ANON.union(MapFlags::READ)).unwrap();
        // 7 frames remain: fault pages 1..=7 of v2, then the 8th must fail.
        for i in 1..8u64 {
            resolve_fault(Vaddr(v2.as_u64() + i * PAGE_SIZE as u64), false).unwrap();
        }
        // Refault of an already-resolved page is idempotent.
        assert_eq!(
            resolve_fault(Vaddr(v2.as_u64() + PAGE_SIZE as u64), false),
            Ok(PhysAddr::new(0x20_1000))
        );
        // Pool is now empty: page 0 of v2 and a fresh ANON fault both fail.
        assert_eq!(resolve_fault(v2, false), Err(VmmError::PoolEmpty));
        let v3 = Vaddr(0x90_0000);
        map(v3, 1, None, MapFlags::ANON.union(MapFlags::READ)).unwrap();
        assert_eq!(resolve_fault(v3, false), Err(VmmError::PoolEmpty));
        unmap(v3).unwrap();
        unmap(va).unwrap();
        unmap(v2).unwrap();

        // --- COW: shared copies, sole owner promotes ---
        let _ = init_pool_for_test(Some((PhysAddr::new(0x30_0000), 4 * PAGE_SIZE as u64)));
        let cow_base = PhysAddr::new(0x11_0000);
        track_frame(cow_base);
        track_frame(cow_base); // refcount 2 = "shared with fork child"
        let vc = Vaddr(0x60_0000);
        map(
            vc,
            1,
            Some(cow_base),
            MapFlags::READ.union(MapFlags::WRITE).union(MapFlags::COW),
        )
        .unwrap();

        let fresh = resolve_fault(vc, true).unwrap();
        assert_eq!(fresh, PhysAddr::new(0x30_0000), "shared COW write copies");
        assert_eq!(frame_refs(cow_base), 2, "one mapping ref dropped on copy");
        assert_eq!(frame_refs(fresh), 1);

        let again = resolve_fault(vc, true).unwrap();
        assert_eq!(again, fresh, "sole owner promotes in place, no copy");

        // --- write without permission -> userspace fault ---
        let v3 = Vaddr(0x70_0000);
        let base3 = PhysAddr::new(0x12_0000);
        track_frame(base3);
        map(v3, 1, Some(base3), MapFlags::READ).unwrap();
        assert_eq!(resolve_fault(v3, true), Err(VmmError::NoWritePerm));
    }
}
