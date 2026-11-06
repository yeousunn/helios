//! Physical frame allocator (ADR-003): region list + per-region bitmap.
#![forbid(unsafe_code)]

use core::fmt;
use spin::Mutex;

pub const FRAME_SIZE: usize = 4096;

/// Checked physical address newtype.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PhysAddr(u64);

impl PhysAddr {
    pub const fn new(a: u64) -> Self {
        PhysAddr(a)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, n: u64) -> Option<PhysAddr> {
        self.0.checked_add(n).map(PhysAddr)
    }

    pub fn is_frame_aligned(self) -> bool {
        self.0.is_multiple_of(FRAME_SIZE as u64)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// A contiguous physical memory region usable for frame allocation.
/// Covers `[base, base + len)` rounded to whole frames.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    base: PhysAddr,
    len: u64,
}

impl Region {
    /// The all-zero region (const initializer for staging slots; `len == 0`
    /// means "no region configured"). Never handed out by `alloc`.
    pub const EMPTY: Region = Region {
        base: PhysAddr(0),
        len: 0,
    };

    /// Creates a region, rounding `base` up and `len` down to frame
    /// boundaries. Returns `None` when rounding overflows or the region is
    /// empty.
    pub fn new(base: PhysAddr, len: u64) -> Option<Region> {
        let waste = (FRAME_SIZE as u64 - base.0 % FRAME_SIZE as u64) % FRAME_SIZE as u64;
        let aligned_len = len.checked_sub(waste)?;
        if aligned_len < FRAME_SIZE as u64 {
            return None;
        }
        let base = base.checked_add(waste)?;
        Some(Region {
            base,
            len: aligned_len - aligned_len % FRAME_SIZE as u64,
        })
    }

    fn frame_count(&self) -> usize {
        (self.len / FRAME_SIZE as u64) as usize
    }
}

const MAX_REGIONS: usize = 8;
/// Max frames tracked per region: 1 GiB / 4 KiB = 2^18 bits = 32 KiB.
const MAX_FRAMES_PER_REGION: usize = 1 << 18;
const WORDS: usize = MAX_FRAMES_PER_REGION / 64;

struct RegionState {
    region: Region,
    bitmap: [u64; WORDS],
    used: usize,
}

impl RegionState {
    fn get(&self, i: usize) -> bool {
        self.bitmap[i / 64] >> (i % 64) & 1 == 1
    }

    fn set(&mut self, i: usize, v: bool) {
        if v {
            self.bitmap[i / 64] |= 1 << (i % 64);
        } else {
            self.bitmap[i / 64] &= !(1 << (i % 64));
        }
    }
}

struct Inner {
    regions: [Option<RegionState>; MAX_REGIONS],
    /// False until `init` configures the regions (the slots are const-zeroed
    /// in .bss — see ALLOCATOR — and carry EMPTY regions until then).
    initialized: bool,
}

/// Global allocator; initialized exactly once from boot code (ADR-003).
///
/// The region slots are **const-evaluated into .bss** (256 KiB of zeroed
/// bitmaps) instead of built on the stack in `init`: the stack-built version
/// materialized an ~262 KiB temporary that overflowed the 1 MiB boot stack
/// in debug builds and zeroed boot.S's identity page tables sitting directly
/// below `stack_bottom` (triple fault between "boot: 3 backends" and
/// "boot: 4 frames", silent under `-no-reboot`). Same landmine class as the
/// `CapTable::empty()` temporary (ADR-037 am2): large tables are const
/// statics, never by-value stack values.
static ALLOCATOR: Mutex<Option<Inner>> = Mutex::new(Some(Inner {
    regions: [const {
        Some(RegionState {
            region: Region::EMPTY,
            bitmap: [0; WORDS],
            used: 0,
        })
    }; MAX_REGIONS],
    initialized: false,
}));

/// Register the usable physical memory regions. Call once from boot.
pub fn init(regions: &[Region]) -> Result<(), &'static str> {
    if regions.is_empty() {
        return Err("no memory regions provided");
    }
    if regions.len() > MAX_REGIONS {
        return Err("too many regions");
    }
    for r in regions {
        if r.frame_count() > MAX_FRAMES_PER_REGION {
            return Err("region exceeds allocator capacity");
        }
    }
    let mut guard = ALLOCATOR.lock();
    let Some(inner) = guard.as_mut() else {
        return Err("allocator missing");
    };
    if inner.initialized {
        return Err("frame allocator already initialized");
    }
    // Configure the pre-staged slots in place — no per-slot temporaries.
    // The bitmaps are already zero (const .bss; init runs exactly once and
    // nothing allocates before it).
    for (i, r) in regions.iter().enumerate() {
        let slot = inner.regions[i].as_mut().expect("staged slot");
        slot.region = *r;
        slot.used = 0;
    }
    inner.initialized = true;
    Ok(())
}

/// Mark a physical range as permanently in use (kernel image, boot stack,
/// boot page tables — ADR-035): frames inside a reserved range are never
/// handed out. Call right after `init`, before any allocation. The range is
/// rounded outward to frame boundaries.
pub fn reserve(base: PhysAddr, len: u64) -> Result<(), &'static str> {
    let mut guard = ALLOCATOR.lock();
    let inner = guard.as_mut().ok_or("allocator not initialized")?;
    let mut marked = 0;
    for slot in inner.regions.iter_mut().flatten() {
        let rbase = slot.region.base.as_u64();
        let rframes = slot.region.frame_count() as u64;
        let r_end = rbase + rframes * FRAME_SIZE as u64;
        if base.as_u64() >= r_end || base.as_u64() + len <= rbase {
            continue;
        }
        // Frame-relative range within THIS region (handles the absolute-
        // vs-relative frame numbering: the bitmap is region-local).
        let mark_start = base.as_u64().max(rbase);
        let mark_end = (base.as_u64() + len).min(r_end);
        if mark_end > mark_start {
            let i0 = (mark_start - rbase) / FRAME_SIZE as u64;
            let i1 = (mark_end - rbase).div_ceil(FRAME_SIZE as u64);
            for idx in i0..i1.min(rframes) {
                if !slot.get(idx as usize) {
                    slot.set(idx as usize, true);
                    slot.used += 1;
                    marked += 1;
                }
            }
        }
    }
    if marked == 0 {
        return Err("reserved range outside managed regions");
    }
    Ok(())
}

/// Allocate one frame. Returns its physical address.
pub fn alloc() -> Option<PhysAddr> {
    let mut guard = ALLOCATOR.lock();
    let inner = guard.as_mut()?;
    for slot in inner.regions.iter_mut().flatten() {
        for i in 0..slot.region.frame_count() {
            if !slot.get(i) {
                slot.set(i, true);
                slot.used += 1;
                return Some(PhysAddr::new(
                    slot.region.base.as_u64() + i as u64 * FRAME_SIZE as u64,
                ));
            }
        }
    }
    None
}

/// Allocate `n` contiguous frames, returning the base physical address.
pub fn alloc_contiguous(n: usize) -> Option<PhysAddr> {
    if n == 0 {
        return None;
    }
    let mut guard = ALLOCATOR.lock();
    let inner = guard.as_mut()?;
    for slot in inner.regions.iter_mut().flatten() {
        let frames = slot.region.frame_count();
        let mut run = 0;
        for i in 0..frames {
            if !slot.get(i) {
                run += 1;
                if run == n {
                    let start = i + 1 - n;
                    for j in start..=i {
                        slot.set(j, true);
                    }
                    slot.used += n;
                    return Some(PhysAddr::new(
                        slot.region.base.as_u64() + start as u64 * FRAME_SIZE as u64,
                    ));
                }
            } else {
                run = 0;
            }
        }
    }
    None
}

/// Free a previously allocated frame address.
pub fn free(addr: PhysAddr) -> Result<(), &'static str> {
    if !addr.is_frame_aligned() {
        return Err("unaligned frame address");
    }
    let mut guard = ALLOCATOR.lock();
    let inner = guard.as_mut().ok_or("allocator not initialized")?;
    for slot in inner.regions.iter_mut().flatten() {
        let base = slot.region.base.as_u64();
        let end = base + slot.region.len;
        if addr.as_u64() >= base && addr.as_u64() < end {
            let idx = ((addr.as_u64() - base) / FRAME_SIZE as u64) as usize;
            if !slot.get(idx) {
                return Err("double free");
            }
            slot.set(idx, false);
            slot.used -= 1;
            return Ok(());
        }
    }
    Err("address outside managed regions")
}

/// Frames currently free across all regions.
pub fn free_count() -> usize {
    let guard = ALLOCATOR.lock();
    let Some(inner) = guard.as_ref() else {
        return 0;
    };
    inner
        .regions
        .iter()
        .flatten()
        .map(|r| r.region.frame_count() - r.used)
        .sum()
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    let mut guard = ALLOCATOR.lock();
    // De-configure in place: slots are const-staged; only the flag and the
    // region/used fields ever change (bitmaps re-zeroed per slot).
    if let Some(inner) = guard.as_mut() {
        inner.initialized = false;
        for slot in inner.regions.iter_mut().flatten() {
            slot.region = Region::EMPTY;
            slot.used = 0;
            slot.bitmap = [0; WORDS];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_rounding() {
        let r = Region::new(PhysAddr::new(0x1800), FRAME_SIZE as u64 * 3).unwrap();
        assert_eq!(r.base, PhysAddr::new(0x2000));
        assert_eq!(r.frame_count(), 2);
        assert!(Region::new(PhysAddr::new(0x1800), 0x800).is_none());
    }

    #[test]
    fn full_lifecycle() {
        // Hermetic: reset the allocator (test-only) so this test is
        // independent of what earlier test modules leaked.
        reset_for_test();
        let region = Region::new(PhysAddr::new(0x1000), 64 * FRAME_SIZE as u64).unwrap();
        init(&[region]).expect("init once (post-reset)");
        let base = free_count();
        assert_eq!(base, 64);
        assert!(init(&[region]).is_err(), "re-init must be rejected");

        let a = alloc().unwrap();
        let b = alloc().unwrap();
        assert_eq!(
            b.as_u64(),
            a.as_u64() + FRAME_SIZE as u64,
            "sequential frames"
        );

        let span = alloc_contiguous(4).unwrap();
        assert!(
            span.as_u64() >= b.as_u64() + FRAME_SIZE as u64,
            "span starts after the singles"
        );
        assert_eq!(free_count(), base - 6, "2 singles + 4-span allocated");

        free(a).unwrap();
        assert!(free(a).is_err(), "double free must be rejected");
        assert_eq!(alloc().unwrap(), a, "first-fit reuses lowest free frame");

        assert!(free(PhysAddr::new(a.as_u64() + 1)).is_err(), "unaligned");
        assert!(free(PhysAddr::new(0xDEAD_0000)).is_err(), "foreign");

        let mut count = 0;
        while alloc().is_some() {
            count += 1;
        }
        assert_eq!(count, base - 6);
        assert!(alloc().is_none());
        assert!(alloc_contiguous(1).is_none());
        assert!(free_count() == 0, "everything drained");

        // This test's seeded region: restore every frame it owns. Frames that
        // earlier tests still hold simply weren't allocated here — free() of a
        // freshly drained allocator accepts everything it handed out.
        for i in 0..64u64 {
            let _ = free(PhysAddr::new(0x1000 + i * FRAME_SIZE as u64));
        }
        assert_eq!(free_count(), 64);
        let span = alloc_contiguous(64).expect("full span after free-all");
        // Leave the allocator fully free for subsequent tests in this binary.
        for i in 0..64u64 {
            free(span.checked_add(i * FRAME_SIZE as u64).unwrap()).unwrap();
        }
        assert_eq!(free_count(), 64);
    }
}
