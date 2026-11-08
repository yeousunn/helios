//! x86_64 4-level paging backend support.
//!
//! Architecture-specific page table constants, PTE flag bits, and page-table
//! walking helpers. Implements [`kernel::aspace::PagingBackend`] for x86_64,
//! plus [`kernel::aspace::BackendFactory`] for per-AS paging roots (ADR-022).
//!
//! Boot flow: arch `_start` calls `enable_nx()` once, then registers
//! `BackendFactoryX86_64` with `kernel::aspace::set_backend_factory()`. The
//! factory hands out one `PagingBackendX86_64` (owning a PML4 root page) per
//! address space.

#![allow(dead_code)]

use kernel::aspace::{BackendFactory, MapFlags, PagingBackend, Vaddr};
use kernel::frame::{self, PhysAddr};
use spin::Mutex;

/// Page size (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Page table entry count per level (512 entries, 9 bits each).
pub const PT_ENTRIES: usize = 512;

/// Page table index bit widths (x86_64 4-level paging, 9 bits per level).
const PML4_SHIFT: usize = 39;
const PDPT_SHIFT: usize = 30;
const PD_SHIFT: usize = 21;
const PT_SHIFT: usize = 12;

/// Page table index masks.
const PT_INDEX_MASK: usize = 0x1FF;

/// Physical address mask for PTE page frame address (bits 12..51).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// PTE flag: Present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE flag: Read/Write (1 = writable).
const PTE_WRITABLE: u64 = 1 << 1;
/// PTE flag: User/Supervisor (1 = user-accessible).
const PTE_USER: u64 = 1 << 2;
/// PTE flag: Accessed (set by CPU on access).
const PTE_ACCESSED: u64 = 1 << 5;
/// PTE flag: Dirty (set by CPU on write).
const PTE_DIRTY: u64 = 1 << 6;
/// PTE flag: Page Size (1 = huge page, only valid in PD/PDPT entries).
const PTE_PAGE_SIZE: u64 = 1 << 7;

/// ADR-045 slice 2: table pages are reached through the shared higher-half
/// window (works under every CR3), not the low identity map.
fn pt_va(pa: usize) -> usize {
    kernel::mem::phys_to_virt(pa as u64) as usize
}
/// PTE flag: Global (not flushed on CR3 write).
const PTE_GLOBAL: u64 = 1 << 8;
/// PTE flag: No Execute (NX bit, requires EFER.NXE).
const PTE_NX: u64 = 1 << 63;

/// MapFlags -> x86_64 PTE flag translation.
fn map_flags_to_pte(flags: MapFlags) -> u64 {
    let mut pte = PTE_PRESENT | PTE_USER; // v0: all mapped pages are user-accessible
    if flags.contains(MapFlags::WRITE) {
        pte |= PTE_WRITABLE;
    }
    if flags.contains(MapFlags::EXEC) {
        // Executable: do NOT set NX.
    } else {
        pte |= PTE_NX;
    }
    pte
}

/// A page table entry (8 bytes).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct Pte(u64);

impl Pte {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn is_present(self) -> bool {
        self.0 & PTE_PRESENT != 0
    }

    pub fn addr(self) -> usize {
        (self.0 & PTE_ADDR_MASK) as usize
    }

    pub fn flags(self) -> u64 {
        self.0 & !PTE_ADDR_MASK
    }

    pub fn set_present(&mut self) {
        self.0 |= PTE_PRESENT;
    }

    pub fn set_writable(&mut self) {
        self.0 |= PTE_WRITABLE;
    }

    pub fn set_user(&mut self) {
        self.0 |= PTE_USER;
    }

    pub fn set_nx(&mut self) {
        self.0 |= PTE_NX;
    }

    pub fn set_frame(&mut self, paddr: usize) {
        self.0 = (self.0 & !PTE_ADDR_MASK) | (paddr as u64 & PTE_ADDR_MASK);
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Page table (512 entries, 4 KiB, aligned).
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [Pte; PT_ENTRIES],
}

impl PageTable {
    pub const fn new() -> Self {
        Self {
            entries: [Pte::empty(); PT_ENTRIES],
        }
    }

    pub fn entry(&mut self, index: usize) -> &mut Pte {
        &mut self.entries[index]
    }
}

/// Extract the page table index at a given level from a virtual address.
#[inline(always)]
fn pt_index(vaddr: usize, shift: usize) -> usize {
    (vaddr >> shift) & PT_INDEX_MASK
}

/// Read the current CR3 value (page table base).
#[inline(always)]
pub fn read_cr3() -> usize {
    let cr3: usize;
    // SAFETY: `mov cr3, rax` reads a control register; safe in kernel context.
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nostack, readonly));
    }
    cr3
}

/// Write CR3 (switch page tables / flush TLB).
#[inline(always)]
pub fn write_cr3(cr3: usize) {
    // SAFETY: `mov cr3, rax` writes a control register; safe in kernel context.
    unsafe {
        core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack));
    }
}

/// Invalidate a single TLB entry for `vaddr`.
#[inline(always)]
pub fn flush_tlb_page(vaddr: usize) {
    // SAFETY: `invlpg` invalidates one TLB entry; safe in kernel context.
    unsafe {
        core::arch::asm!("invlpg [{0}]", in(reg) vaddr, options(nostack));
    }
}

/// Flush the entire TLB by rewriting CR3.
#[inline(always)]
pub fn flush_tlb_all() {
    let cr3 = read_cr3();
    write_cr3(cr3);
}

/// Paging mode bits in EFER (IA32_EFER MSR).
const EFER_NXE: u64 = 1 << 11;

/// Read IA32_EFER MSR.
fn read_efer() -> u64 {
    let lo: u32;
    let hi: u32;
    let msr: u32 = 0xC0000080;
    // SAFETY: `rdmsr` reads a model-specific register; safe in kernel context.
    unsafe {
        core::arch::asm!("rdmsr", out("eax") lo, out("edx") hi, in("ecx") msr, options(nostack, readonly));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Enable the NXE bit in EFER (required for the PTE_NX bit).
/// Called once at boot before any PagingBackendX86_64 is created.
pub fn enable_nx() {
    let efer = read_efer() | EFER_NXE;
    let lo = efer as u32;
    let hi = (efer >> 32) as u32;
    let msr: u32 = 0xC0000080;
    // SAFETY: `wrmsr` writes a model-specific register; safe in kernel context.
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi, options(nostack));
    }
}

/// Maximum number of per-AS paging roots (matches `aspace::MAX_REGIONS`).
const MAX_BACKENDS: usize = 16;

/// Static pool of per-AS paging backends.
static BACKEND_POOL: Mutex<[Option<PagingBackendX86_64>; MAX_BACKENDS]> =
    Mutex::new([None; MAX_BACKENDS]);

/// x86_64 paging backend: walks a 4-level page table and installs mappings
/// into the PML4 rooted at `pml4_paddr`. One instance per address space.
#[derive(Clone, Copy)]
pub struct PagingBackendX86_64 {
    /// Physical address of the PML4 page.
    pml4_paddr: usize,
}

#[allow(dead_code)]
#[allow(clippy::mut_from_ref)]
impl PagingBackendX86_64 {
    /// Create a new backend from a PML4 page already allocated and zeroed at
    /// `pml4_paddr`. Does NOT enable NXE or install CR3 — those are boot-time
    /// actions done once globally.
    ///
    /// # Safety
    ///
    /// `pml4_paddr` must point to a valid, zeroed 4 KiB page of physical
    /// memory.
    fn new(pml4_paddr: usize) -> Self {
        Self { pml4_paddr }
    }

    /// Get a mutable reference to the PML4 page table.
    ///
    /// # Safety
    ///
    /// Assumes `pml4_paddr` is a valid, mapped, writable page table page.
    unsafe fn pml4_mut(&self) -> &mut PageTable {
        &mut *(pt_va(self.pml4_paddr) as *mut PageTable)
    }

    /// Allocate and zero one page-table page from the frame allocator.
    ///
    /// # Safety
    /// The frame allocator must be initialized (boot sequence guarantees it
    /// before any AS operation).
    unsafe fn new_table() -> Option<usize> {
        let paddr = frame::alloc()?;
        // SAFETY: fresh frame; identity direct map covers allocated RAM.
        unsafe {
            core::ptr::write_bytes(
                kernel::mem::phys_to_virt(paddr.as_u64()) as *mut u8,
                0,
                PAGE_SIZE,
            );
        }
        Some(paddr.as_u64() as usize)
    }

    /// Pointer-style entry for an intermediate table (present|rw|user).
    fn table_entry(addr: usize) -> u64 {
        (addr as u64 & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE | PTE_USER
    }

    /// Walk the 4-level page table for `vaddr`, **creating intermediate
    /// tables from the frame allocator as needed** and splitting 2 MiB PD
    /// huge pages into 4 KiB tables (boot identity map) so leaf permissions
    /// can be adjusted. Returns the leaf PTE.
    ///
    /// # Safety
    ///
    /// All reachable table pages must be identity-mapped and writable (true
    /// for kernel/frame memory in the v0 direct map), and `pml4_paddr` valid.
    unsafe fn walk_create(&self, vaddr: usize) -> Option<&mut Pte> {
        // PML4 -> PDPT
        let pml4 = self.pml4_mut();
        let e = pml4.entry(pt_index(vaddr, PML4_SHIFT));
        if !e.is_present() {
            let t = unsafe { Self::new_table() }?;
            e.0 = Self::table_entry(t);
        }
        // Existing (boot-created) intermediate entries must allow user access
        // at every level or ring-3 leaves under them fault regardless of leaf
        // permissions (x86 requires U/S=1 on all levels; leaves still govern).
        e.0 |= PTE_USER;
        // SAFETY: entry holds a valid page-table physical address per above.
        let pdpt = unsafe { &mut *(pt_va(e.addr()) as *mut PageTable) };

        // PDPT -> PD
        let e = pdpt.entry(pt_index(vaddr, PDPT_SHIFT));
        if !e.is_present() {
            let t = unsafe { Self::new_table() }?;
            e.0 = Self::table_entry(t);
        }
        e.0 |= PTE_USER;
        // SAFETY: as above.
        let pd = unsafe { &mut *(pt_va(e.addr()) as *mut PageTable) };

        // PD -> PT (splitting 2 MiB huge pages if the boot map used them)
        let pd_idx = pt_index(vaddr, PD_SHIFT);
        let e = pd.entry(pd_idx);
        if e.is_present() && (e.0 & PTE_PAGE_SIZE) != 0 {
            // Split: materialize a PT replicating the huge page. The split
            // leaves keep the huge page's own permissions (boot identity map
            // is supervisor) — the caller's per-page map sets the leaf.
            let base = e.addr();
            let old = e.0;
            let t = unsafe { Self::new_table() }?;
            let pt = unsafe { &mut *(pt_va(t) as *mut PageTable) };
            let keep = old & (PTE_USER | PTE_WRITABLE | PTE_NX | PTE_GLOBAL);
            for i in 0..512 {
                pt.entry(i).0 = ((base as u64 + (i as u64) * PAGE_SIZE as u64) & PTE_ADDR_MASK)
                    | keep
                    | PTE_PRESENT;
            }
            // The PD entry now points at a 4 KiB table and must carry U/S=1
            // so user leaves under it can be reached.
            e.0 = Self::table_entry(t);
            flush_tlb_all();
        } else if !e.is_present() {
            let t = unsafe { Self::new_table() }?;
            e.0 = Self::table_entry(t);
        } else {
            // Existing 4 KiB table: intermediates need U/S=1 (leaves govern).
            e.0 |= PTE_USER;
        }
        // SAFETY: entry holds a valid page-table physical address per above.
        let pt = unsafe { &mut *(pt_va(e.addr()) as *mut PageTable) };

        Some(pt.entry(pt_index(vaddr, PT_SHIFT)))
    }

    /// Walk the 4-level tables for `vaddr` WITHOUT creating anything and
    /// without splitting huge pages. Returns the leaf PTE only when every
    /// level (and the leaf) is present as a 4 KiB entry. `intermediate_ok`
    /// additionally reports whether the path down to the parent level exists
    /// (used by unmap/protect to no-op cleanly on absent chains instead of
    /// materializing tables — GLM's walk audit finding).
    unsafe fn walk_existing(&self, vaddr: usize, intermediate_ok: &mut bool) -> Option<&mut Pte> {
        *intermediate_ok = false;
        // SAFETY: read-only walk; table memory is identity-mapped and valid.
        unsafe {
            let e = self.pml4_mut().entry(pt_index(vaddr, PML4_SHIFT));
            if !e.is_present() || (e.0 & PTE_PAGE_SIZE) != 0 {
                return None;
            }
            let pdpt = &mut *(pt_va(e.addr()) as *mut PageTable);
            let e = pdpt.entry(pt_index(vaddr, PDPT_SHIFT));
            if !e.is_present() || (e.0 & PTE_PAGE_SIZE) != 0 {
                return None;
            }
            let pd = &mut *(pt_va(e.addr()) as *mut PageTable);
            let e = pd.entry(pt_index(vaddr, PD_SHIFT));
            if !e.is_present() {
                return None;
            }
            if (e.0 & PTE_PAGE_SIZE) != 0 {
                // Huge 2 MiB page: the parent levels exist; no leaf PTE.
                *intermediate_ok = true;
                return None;
            }
            let pt = &mut *(pt_va(e.addr()) as *mut PageTable);
            *intermediate_ok = true;
            let e = pt.entry(pt_index(vaddr, PT_SHIFT));
            if !e.is_present() {
                return None;
            }
            Some(e)
        }
    }
}

impl PagingBackend for PagingBackendX86_64 {
    fn map_page(&self, vaddr: Vaddr, paddr: PhysAddr, flags: MapFlags) {
        let va = vaddr.as_u64() as usize;
        let pa = paddr.as_u64() as usize;
        let pte_flags = map_flags_to_pte(flags);
        // SAFETY: Walk/create page tables and install the PTE.
        unsafe {
            let Some(pte) = self.walk_create(va) else {
                // Intermediate page table missing — allocation not yet wired
                // to the frame allocator. In v0 this is a hard failure since
                // we cannot silently drop mappings.
                panic!("page table allocation not yet wired to frame allocator");
            };
            pte.set_frame(pa);
            pte.set_present();
            pte.0 |= pte_flags;
            flush_tlb_page(va);
        }
    }

    fn unmap_page(&self, vaddr: Vaddr) {
        let va = vaddr.as_u64() as usize;
        // Walk-only: an unmap must never allocate tables or split huge pages
        // (GLM's walk audit finding). Absent chain → nothing mapped → no-op.
        let mut _ok = false;
        // SAFETY: Clear the leaf PTE for `vaddr` when fully present.
        unsafe {
            if let Some(pte) = self.walk_existing(va, &mut _ok) {
                pte.0 = 0;
                flush_tlb_page(va);
            }
        }
    }

    fn protect_page(&self, vaddr: Vaddr, flags: MapFlags) {
        let va = vaddr.as_u64() as usize;
        let pte_flags = map_flags_to_pte(flags);
        // Walk-only: protecting an unmapped VA must not materialize tables.
        let mut _ok = false;
        // SAFETY: Update an existing leaf PTE's flags in place.
        unsafe {
            if let Some(pte) = self.walk_existing(va, &mut _ok) {
                let old = pte.0;
                let new_flags = pte_flags | (old & PTE_ADDR_MASK);
                pte.0 = new_flags;
                flush_tlb_page(va);
            }
        }
    }
}

/// Root PML4 physical addresses by AS id (index = `as_id - 1`). 0 = none.
static AS_ROOTS: Mutex<[usize; MAX_BACKENDS]> = Mutex::new([0; MAX_BACKENDS]);

/// Kernel-side hardware page-table walk (diagnostics): the physical address
/// behind `vaddr` under the PML4 at `pml4_paddr`, or `None` when the walk
/// stops at a not-present entry. Reads via the identity direct map.
pub fn probe_walk(pml4_paddr: usize, vaddr: u64) -> Option<u64> {
    const P: u64 = 1;
    const PS: u64 = 1 << 7;
    const ADDR: u64 = 0x000F_FFFF_FFFF_F000;
    // SAFETY: physical addresses are identity-map readable in kernel context;
    // this is a read-only diagnostics walk.
    unsafe {
        let e4 = *((pt_va(pml4_paddr) as *const u64).add(((vaddr >> 39) & 0x1FF) as usize));
        if e4 & P == 0 {
            return None;
        }
        let pdpt = (e4 & ADDR) as usize;
        let e3 = *((pt_va(pdpt) as *const u64).add(((vaddr >> 30) & 0x1FF) as usize));
        if e3 & P == 0 {
            return None;
        }
        if e3 & PS != 0 {
            return Some(e3 & 0x000F_FFFF_C000_0000);
        }
        let pd = (e3 & ADDR) as usize;
        let e2 = *((pt_va(pd) as *const u64).add(((vaddr >> 21) & 0x1FF) as usize));
        if e2 & P == 0 {
            return None;
        }
        if e2 & PS != 0 {
            return Some(e2 & 0x000F_FFFF_FFE0_0000);
        }
        let pt = (e2 & ADDR) as usize;
        let e1 = *((pt_va(pt) as *const u64).add(((vaddr >> 12) & 0x1FF) as usize));
        if e1 & P == 0 {
            return None;
        }
        Some(e1 & ADDR)
    }
}

/// The registered root page for `as_id`, if any.
pub fn root_of(as_id: u64) -> Option<usize> {
    let idx = (as_id as usize).wrapping_sub(1);
    if idx >= MAX_BACKENDS {
        return None;
    }
    let r = AS_ROOTS.lock()[idx];
    (r != 0).then_some(r)
}

/// Activate an address space: load `as_id`'s root into CR3 (v0: no PCID;
/// full TLB flush via the CR3 write). Returns false when the AS has no root.
pub fn activate_as(as_id: u64) -> bool {
    let idx = (as_id as usize).wrapping_sub(1);
    if idx >= MAX_BACKENDS {
        return false;
    }
    let root = AS_ROOTS.lock()[idx];
    if root == 0 {
        return false;
    }
    write_cr3(root);
    true
}

/// x86_64 backend factory: hands out one `PagingBackendX86_64` per address
/// space. Allocates a PML4 page from the kernel frame allocator for each AS.
pub struct BackendFactoryX86_64;

impl Default for BackendFactoryX86_64 {
    fn default() -> Self {
        Self
    }
}

/// Kernel identity window per AS: first 16 MiB (kernel image + boot stack +
/// statics + the 8..16 MiB gap, closed per GLM's walk audit) and 16..256 MiB
/// (frame allocator region). Supervisor 2 MiB pages, PRIVATE to this AS —
/// sharing the boot chain leaked mappings across address spaces (found when
/// a child's segment mappings overwrote the parent's live code).
// (The per-AS PML4[0] window constants — KERNEL_LOW_MIB, FRAME_REGION_* —
// retired with the ADR-045 slice 2b window removal.)

/// ADR-045: the shared higher-half kernel window (PDPT phys, PD phys).
/// Built once from the frame allocator; every AS's PML4[511] points here.
static SHARED_HIGH: Mutex<Option<(kernel::frame::PhysAddr, kernel::frame::PhysAddr)>> =
    Mutex::new(None);

fn shared_high_window() -> Option<(kernel::frame::PhysAddr, kernel::frame::PhysAddr)> {
    let mut guard = SHARED_HIGH.lock();
    if let Some(s) = *guard {
        return Some(s);
    }
    let pdpt = frame::alloc()?;
    let pd = frame::alloc()?;
    // SAFETY: freshly allocated frames, written through the boot identity
    // map (the builder runs on the boot CR3 where VA == PA for < 1 GiB).
    unsafe {
        core::ptr::write_bytes(pdpt.as_u64() as *mut u8, 0, PAGE_SIZE);
        core::ptr::write_bytes(pd.as_u64() as *mut u8, 0, PAGE_SIZE);
        let entries = pd.as_u64() as *mut u64;
        let huge = PTE_PRESENT | PTE_WRITABLE | PTE_PAGE_SIZE;
        for i in 0..512u64 {
            *entries.add(i as usize) = (i * 0x20_0000) | huge;
        }
    }
    *guard = Some((pdpt, pd));
    Some((pdpt, pd))
}

impl BackendFactory for BackendFactoryX86_64 {
    fn create(&self, as_id: u64) -> Option<&'static dyn PagingBackend> {
        // ADR-045 slice 1: every AS shares the higher-half kernel window
        // (PML4[511] -> PDPT[510] -> 2 MiB identity pages, VA
        // 0xFFFFFFFF80000000 + PA) — the kernel's own code/statics must be
        // reachable under every CR3 it ever executes under. One PDPT+PD,
        // built once, referenced by every PML4.
        let shared = shared_high_window()?;
        // Allocate a PML4 page from the kernel frame allocator.
        let paddr = frame::alloc()?;
        let pml4 = paddr.as_u64() as usize;
        // ADR-045 slice 2b: the per-AS PML4[0] private kernel window is
        // RETIRED. User space owns PML4[0..511] exclusively; kernel memory is
        // reachable ONLY through the shared PML4[511] higher-half window. A
        // kernel bug dereferencing a user integer now faults at a small VA
        // instead of silently corrupting identity-mapped RAM.
        //
        // SAFETY: freshly allocated frame; the shared high window covers it.
        unsafe {
            core::ptr::write_bytes(
                kernel::mem::phys_to_virt(pml4 as u64) as *mut u8,
                0,
                PAGE_SIZE,
            );
            // Higher-half kernel window (shared; see above).
            let pml4e511 = (kernel::mem::phys_to_virt(pml4 as u64) as *mut u64).add(511);
            *pml4e511 = (shared.0.as_u64() & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE;
            let pdpte510 = (kernel::mem::phys_to_virt(shared.0.as_u64()) as *mut u64).add(510);
            *pdpte510 = (shared.1.as_u64() & PTE_ADDR_MASK) | PTE_PRESENT | PTE_WRITABLE;
        }

        // Slot in the static pool, keyed by AS id. AS ids are recycled
        // (`aspace::destroy` frees the table slot and `create` reuses it), so
        // re-creating an id overwrites its own dead backend. A flat
        // first-free scan leaked one pool slot per address space EVER created
        // and exhausted MAX_BACKENDS mid-run (every later NEW_ADDRESS_SPACE
        // returned ENOMEM — hit once the smoke passed ~16 total spawns).
        let as_idx = (as_id as usize).wrapping_sub(1);
        if as_idx >= MAX_BACKENDS {
            return None;
        }
        let mut slots = BACKEND_POOL.lock();
        slots[as_idx] = Some(PagingBackendX86_64::new(paddr.as_u64() as usize));
        AS_ROOTS.lock()[as_idx] = paddr.as_u64() as usize;
        let slot_ptr = &slots[as_idx] as *const Option<PagingBackendX86_64>;
        drop(slots);

        unsafe { Some((*slot_ptr).as_ref().unwrap() as &dyn PagingBackend) }
    }
}

/// Static factory instance registered with `kernel::aspace::set_backend_factory`.
pub static BACKEND_FACTORY_X86_64: BackendFactoryX86_64 = BackendFactoryX86_64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pte_roundtrip() {
        let mut pte = Pte::empty();
        pte.set_frame(0x123_4000);
        pte.set_present();
        pte.set_writable();
        pte.set_user();
        assert!(pte.is_present());
        assert_eq!(pte.addr(), 0x123_4000);
    }

    #[test]
    fn pt_index_bits() {
        assert_eq!(pt_index(0x123_4567_89AB, PML4_SHIFT), 0x123);
        assert_eq!(pt_index(0x123_4567_89AB, PDPT_SHIFT), 0x456);
        assert_eq!(pt_index(0x123_4567_89AB, PD_SHIFT), 0x789);
        assert_eq!(pt_index(0x123_4567_89AB, PT_SHIFT), 0xAAB);
    }

    #[test]
    fn map_flags_translation() {
        let r = map_flags_to_pte(MapFlags::READ);
        assert!(r & PTE_PRESENT != 0);
        assert!(r & PTE_WRITABLE == 0);
        assert!(r & PTE_NX != 0); // non-executable -> NX set
        let rw = map_flags_to_pte(MapFlags::READ.union(MapFlags::WRITE));
        assert!(rw & PTE_WRITABLE != 0);
        let rx = map_flags_to_pte(MapFlags::READ.union(MapFlags::EXEC));
        assert!(rx & PTE_NX == 0); // executable -> NX clear
    }
}
