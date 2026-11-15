//! Userspace heap (ADR-020): a chunked bump allocator over frames carved from
//! a Region cap and mapped into the process's own address space (ADR-021/022).
//!
//! Division of labor:
//! - [`BumpAlloc`] — the pure allocation core (host-tested),
//! - [`RegionSource`] — the carve + map glue (tested against mock syscalls),
//! - [`GlobalHeap`] — a thread-safe bump allocator wrapper. **Binaries that need
//!   a global allocator should implement `GlobalAlloc` themselves** (the `GlobalAlloc`
//!   trait requires `unsafe impl`, which is not allowed in this crate per
//!   PLAN.md §7.1). Init and child declare a failing allocator — they are
//!   allocation-free.
//!
//! v0 heaps are fixed-size: the binary maps its chunks once at startup. Growth
//! (allocator hooks) is future work.
#![forbid(unsafe_code)]

use core::alloc::Layout;
use core::ptr::NonNull;

use ipc::{status, CapSlot, Message, Rights};
use spin::Mutex;

use crate::methods;
use crate::syscall::{Handle, RawSyscalls, Status, Syscalls};

/// Mapping flags for heap pages: `MapFlags::R | MapFlags::W`.
pub const HEAP_FLAGS: u32 = 0b011;

/// Alignment-safe bump allocation over a contiguous VA span.
pub struct BumpAlloc {
    start: usize,
    next: usize,
    end: usize,
}

impl BumpAlloc {
    pub const fn empty() -> Self {
        Self {
            start: 0,
            next: 0,
            end: 0,
        }
    }

    pub const fn new(start: usize, len: usize) -> Self {
        Self {
            start,
            next: start,
            end: start + len,
        }
    }

    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let align = layout.align().max(1);
        let start = (self.next + align - 1) & !(align - 1);
        let end = start.checked_add(layout.size())?;
        if end > self.end {
            return None;
        }
        self.next = end;
        NonNull::new(start as *mut u8)
    }

    pub fn used(&self) -> usize {
        self.next - self.start
    }

    pub fn remaining(&self) -> usize {
        self.end - self.next
    }

    pub fn capacity(&self) -> usize {
        self.end - self.start
    }
}

impl Default for BumpAlloc {
    fn default() -> Self {
        Self::empty()
    }
}

/// The carve + map glue: maps consecutive 4 KiB-granular chunks from a Region
/// cap at VA `base + n * chunk` in the caller's address space.
pub struct RegionSource<'a, R: RawSyscalls> {
    sys: Syscalls<'a, R>,
    region: Handle,
    as_cap: Handle,
    chunk: u64,
    next_va: u64,
}

impl<'a, R: RawSyscalls> RegionSource<'a, R> {
    pub fn new(raw: &'a mut R, region: Handle, as_cap: Handle, va_base: u64, chunk: u64) -> Self {
        assert!(
            chunk > 0 && chunk.is_multiple_of(4096),
            "chunk must be page multiples"
        );
        Self {
            sys: Syscalls::new(raw),
            region,
            as_cap,
            chunk,
            next_va: va_base,
        }
    }

    /// Map `count` chunks of the configured size at startup (v0 fixed heaps)
    /// and return the whole backing span for [`GlobalHeap::init`].
    pub fn map_startup(&mut self, count: u64) -> Result<(usize, usize), Status> {
        let start = self.next_va as usize;
        for _ in 0..count {
            self.grow(self.chunk)?;
        }
        Ok((start, (count * self.chunk) as usize))
    }

    /// Carve `len` bytes (page multiple) and map them at the next VA chunk,
    /// **one 4 KiB carve+map per page**: the v1 `AddressSpace::MAP` invoke
    /// maps exactly one page, and a frame cap always resolves to its base
    /// page, so a single multi-page carve/map would leave every page after
    /// the first unmapped (latent until a heap user outgrew 4 KiB/chunk).
    pub fn grow(&mut self, len: u64) -> Result<(usize, usize), Status> {
        let start = self.next_va as usize;
        let pages = len / 4096;
        for i in 0..pages {
            let mut carve = Message::new(methods::region::CARVE);
            carve.words[0] = 4096;
            carve.words[1] = 4096;
            let reply = self.sys.invoke(self.region, &carve)?;
            let frame = reply.words[0] as Handle;
            if frame == 0 {
                return Err(status::ENOMEM);
            }

            let mut map = Message::new(methods::aspace::MAP);
            map.tag = map.tag.with_caps(1);
            map.words[0] = self.next_va + i * 4096;
            map.words[1] = HEAP_FLAGS as u64;
            let _ = map.set_descriptor(0, CapSlot::pack(frame, Rights::default()));
            self.sys.invoke(self.as_cap, &map)?;
        }

        self.next_va += len;
        Ok((start, len as usize))
    }
}

/// `GlobalAlloc` wrapper. A binary opts in with:
/// `#[global_allocator] static A: sdk::heap::GlobalHeap = sdk::heap::GlobalHeap::new();`
/// and calls [`GlobalHeap::init`] once (after mapping its chunks).
pub struct GlobalHeap {
    inner: Mutex<Option<BumpAlloc>>,
}

impl GlobalHeap {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// Install the backing span. Fails with `EBADSTATE` on double-init.
    pub fn init(&self, start: usize, len: usize) -> Result<(), Status> {
        let mut guard = self.inner.lock();
        if guard.is_some() {
            return Err(status::EBADSTATE);
        }
        *guard = Some(BumpAlloc::new(start, len));
        Ok(())
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().as_ref().map_or(0, BumpAlloc::capacity)
    }
}

impl Default for GlobalHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalHeap {
    /// Allocate memory using the inner bump allocator.
    /// Returns `None` on allocation failure (OOM or uninitialized).
    pub fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
        self.inner.lock().as_mut().and_then(|b| b.alloc(layout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{number, SysReply};

    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    #[test]
    fn bump_aligns_and_accounts() {
        let mut b = BumpAlloc::new(0x1000, 256);
        assert_eq!(b.capacity(), 256);
        let p1 = b.alloc(layout(10, 1)).unwrap();
        assert_eq!(p1.as_ptr() as usize, 0x1000);
        let p2 = b.alloc(layout(8, 16)).unwrap();
        assert_eq!(p2.as_ptr() as usize, 0x1010, "rounded up to 16");
        assert_eq!(b.used(), 0x18);
        assert_eq!(b.remaining(), 256 - 0x18);
    }

    #[test]
    fn bump_exhaustion_returns_none_and_exact_fit_succeeds() {
        // (VA 0 is never a real heap base — NonNull rejects it.)
        let mut b = BumpAlloc::new(0x1000, 16);
        let p = b.alloc(layout(16, 1)).unwrap();
        assert_eq!(p.as_ptr() as usize, 0x1000);
        assert!(b.alloc(layout(1, 1)).is_none());
        assert_eq!(b.used(), 16);
    }

    #[test]
    fn zero_sized_allocation_moves_nothing() {
        let mut b = BumpAlloc::new(0x2000, 16);
        let p = b.alloc(layout(0, 8)).unwrap();
        assert_eq!(p.as_ptr() as usize, 0x2000);
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn region_source_carves_maps_and_advances_va() {
        #[derive(Default)]
        struct MockRaw {
            calls: std::vec::Vec<(u32, [u64; 6])>,
            next_frame: u32,
        }
        impl RawSyscalls for MockRaw {
            fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
                self.calls.push((number, args));
                self.next_frame += 1;
                SysReply {
                    status: status::OK,
                    words: [self.next_frame as u64, 0, 0, 0],
                    ..Default::default()
                }
            }
        }

        let mut raw = MockRaw::default();
        let (first, second);
        {
            let mut src = RegionSource::new(&mut raw, 5, 6, 0xAA00_0000, 0x2000);
            first = src.grow(0x2000).unwrap();
            second = src.grow(0x1000).unwrap();
        }
        assert_eq!(first, (0xAA00_0000, 0x2000));
        assert_eq!(
            second,
            (0xAA00_2000, 0x1000),
            "next VA follows the first chunk"
        );

        // Per-page carve+map (v1 MAP maps one page; a frame cap always
        // resolves to its base page).
        let (num, args) = raw.calls[0];
        assert_eq!(num, number::INVOKE);
        assert_eq!(args[0], 5, "invoke on the Region cap");
        assert_eq!(args[1] as u16, methods::region::CARVE);
        assert_eq!(args[2], 4096, "w0 = one page");
        assert_eq!(args[3], 4096, "w1 = alignment");

        let (num, args) = raw.calls[1];
        assert_eq!(num, number::INVOKE);
        assert_eq!(args[0], 6, "invoke on the self-AS cap");
        assert_eq!(args[1] as u16, methods::aspace::MAP);
        assert_eq!(args[2], 0xAA00_0000, "w0 = vaddr");
        assert_eq!(args[3], HEAP_FLAGS as u64, "w1 = R|W");
        assert_eq!(args[5] as u32, 1, "caps[0] = carved frame");

        let (num, args) = raw.calls[2];
        assert_eq!(num, number::INVOKE);
        assert_eq!(args[1] as u16, methods::region::CARVE);
        let (num, args) = raw.calls[3];
        assert_eq!(num, number::INVOKE);
        assert_eq!(args[1] as u16, methods::aspace::MAP);
        assert_eq!(args[2], 0xAA00_1000, "second page of the chunk");
    }

    #[test]
    fn map_startup_backs_a_whole_fixed_heap() {
        #[derive(Default)]
        struct MockRaw {
            count: u32,
        }
        impl RawSyscalls for MockRaw {
            fn raw(&mut self, _number: u32, _args: [u64; 6]) -> SysReply {
                self.count += 1;
                SysReply {
                    status: status::OK,
                    words: [1, 0, 0, 0],
                    ..Default::default()
                }
            }
        }
        let mut raw = MockRaw::default();
        let span;
        {
            let mut src = RegionSource::new(&mut raw, 5, 6, 0xBB00_0000, 0x2000);
            span = src.map_startup(3).unwrap();
        }
        assert_eq!(span, (0xBB00_0000, 3 * 0x2000));
        assert_eq!(
            raw.count, 12,
            "3 chunks × 2 pages × (carve + map) — per-page, see grow()"
        );
    }

    #[test]
    fn global_heap_init_once() {
        let heap = GlobalHeap::new();
        assert_eq!(heap.capacity(), 0);
        heap.init(0x1000, 4096).unwrap();
        assert_eq!(heap.capacity(), 4096);
        assert_eq!(heap.init(0x2000, 4096), Err(status::EBADSTATE));
        // Allocations go through the safe alloc method.
        let p = heap.alloc(layout(8, 1)).unwrap();
        assert_eq!(p.as_ptr() as usize, 0x1000);
    }
}
