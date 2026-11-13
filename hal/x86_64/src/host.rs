//! Pure, register-free x86_64 HAL logic compiled on **every** host
//! (E11). Address checks, page-table-index/PTE math, and PCI config-space
//! address building live here so `cargo test -p hal-x86-64` runs on
//! non-x86_64 hosts (e.g. the arm64 build host) instead of reporting 0 tests.
//! No CPU instructions, no port/MMIO access, no `unsafe` — safe to unit-test
//! on the dev host. The arch-specific wrappers (`impl_x86_64`, `paging`)
//! import from this module rather than duplicating the constants.

#![allow(dead_code)]

/// Ceiling for a canonical x86_64 user address: bits 63..47 must all be
/// zero (the lower half). A kernel-range or non-canonical FS base faults in
/// ring 0 at the next context switch, so reject it here as defense in depth
/// for `Thread::SET_TLS` (S3). `write_fs_base` asserts this before `wrmsr`.
pub const FS_BASE_USER_CEIL: u64 = 0x0000_8000_0000_0000;

/// True iff `va` is a canonical x86_64 user address (lower half):
/// `va < 0x0000_8000_0000_0000`.
pub const fn fs_base_is_canonical_user(va: u64) -> bool {
    va < FS_BASE_USER_CEIL
}

/// Page table index bit widths (x86_64 4-level paging, 9 bits per level).
pub const PML4_SHIFT: usize = 39;
pub const PDPT_SHIFT: usize = 30;
pub const PD_SHIFT: usize = 21;
pub const PT_SHIFT: usize = 12;

/// Page table index mask (9 bits).
pub const PT_INDEX_MASK: usize = 0x1FF;

/// Extract the page table index at a given level from a virtual address.
pub const fn pt_index(vaddr: usize, shift: usize) -> usize {
    (vaddr >> shift) & PT_INDEX_MASK
}

/// PCI configuration address register (IO port).
pub const PCI_CONFIG_ADDR: u16 = 0xCF8;
/// PCI configuration data register (IO port).
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PML4 slots reserved for the kernel (S5). Userspace owns PML4[0..256) per
/// ADR-045; the shared higher-half kernel window lives at slot 511 and slots
/// 256..510 are reserved. A page-table walk into 256..=511 must be refused so
/// a user process can never install PTE_USER on a shared kernel entry.
pub const PML4_KERNEL_FIRST: usize = 256;
pub const PML4_KERNEL_LAST: usize = 511;

/// CPUID leaf: processor feature information (leaf 7, sub-leaf 0).
pub const CPUID_LEAF_FEATURES: u32 = 0x0000_0007;
/// Sub-leaf 0 of the features leaf: ECX holds SMEP/SMAP/UMIP etc.
pub const CPUID_SUB_LEAF_0: u32 = 0x0000_0000;

/// CPUID leaf 7, sub-leaf 0, EBX feature bit: Supervisor-Mode Execution
/// Prevention (SMEP). CR4.SMEP is bit 20; CPUID advertises it as EBX[7].
pub const CPUID_EBX_SMEP: u32 = 1 << 7;
/// CPUID leaf 7, sub-leaf 0, EBX feature bit: Supervisor-Mode Access
/// Prevention (SMAP). CR4.SMAP is bit 21; CPUID advertises it as EBX[20].
pub const CPUID_EBX_SMAP: u32 = 1 << 20;
/// CPUID leaf 7, sub-leaf 0, ECX feature bit: User-Mode Instruction
/// Prevention (UMIP). CR4.UMIP is bit 11; CPUID advertises it as ECX[2].
pub const CPUID_ECX_UMIP: u32 = 1 << 2;

/// True iff `bit` of `ecx` (the CPUID leaf-7 sub-leaf-0 ECX result) is set,
/// i.e. the CPU advertises the corresponding feature. Pure: no CPU
/// instructions, host-testable on any target.
pub const fn cpuid_ecx_has(ecx: u32, bit: u32) -> bool {
    ecx & bit != 0
}

/// True iff `bit` of `ebx` (the CPUID leaf-7 sub-leaf-0 EBX result) is set,
/// i.e. the CPU advertises the corresponding feature. Pure: no CPU
/// instructions, host-testable on any target.
pub const fn cpuid_ebx_has(ebx: u32, bit: u32) -> bool {
    ebx & bit != 0
}

// ===========================================================================
// CPUID topology leaf (leaf 0x0B): pure decoding used by `CpuTopology` for SMP
// bring-up (ADR-014). The raw CPUID instruction itself is arch-specific; the
// decoding below is pure and host-testable on any target.
// ===========================================================================

/// CPUID leaf 1: processor feature / brand information. EBX[23:16] holds the
/// number of logical processors per physical package.
pub const CPUID_LEAF_1: u32 = 0x0000_0001;
/// CPUID extended topology leaf (leaf 0x0B): enumerate logical processors
/// and cores via x2APIC ID across sub-leaves 0..N.
pub const CPUID_LEAF_TOPOLOGY: u32 = 0x0000_000B;

/// Level type reported by CPUID leaf 0xB, sub-leaf N, ECX: level 0 = logical
/// processors (SMT thread), level 1 = core.
pub const CPUID_TOPOLOGY_LEVEL_THREAD: u32 = 0;
pub const CPUID_TOPOLOGY_LEVEL_CORE: u32 = 1;

/// Decode CPUID leaf 1 EBX: bits 23..16 give the number of logical
/// processors per physical package (Initial APIC ID max + 1). Returns 0 if the
/// field is absent; callers fall back to 1 (single-CPU).
///
/// Pure: no CPU instructions, host-testable on any target.
pub const fn cpuid_leaf1_logical_processors(ebx: u32) -> u32 {
    (ebx >> 16) & 0xFF
}

/// One entry from CPUID leaf 0xB, sub-leaf `level`.
///
/// `logical_processors` (EAX) = number of logical processors in the domain
/// identified by `x2apic_id` (EBX) at `level_type` (ECX).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidTopologyEntry {
    /// Logical processors in this domain (EAX).
    pub logical_processors: u32,
    /// x2APIC ID of the domain (EBX).
    pub x2apic_id: u32,
    /// Level type: 0 = thread/SMT, 1 = core (ECX).
    pub level_type: u32,
}

/// Decode CPUID leaf 0xB sub-leaf output registers (EAX, EBX, ECX) into a
/// [`CpuidTopologyEntry`].
///
/// Pure: no CPU instructions, host-testable on any target.
pub const fn cpuid_topology_level(eax: u32, ebx: u32, ecx: u32) -> CpuidTopologyEntry {
    CpuidTopologyEntry {
        logical_processors: eax,
        x2apic_id: ebx,
        level_type: ecx,
    }
}

/// Compute the online logical-processor count from CPUID leaf 0xB topology
/// entries: the largest `logical_processors` domain (the top level, e.g.
/// package) is the total. Returns `1` (single-CPU fallback) when `entries` is
/// empty or every domain reports zero.
///
/// Pure: no CPU instructions, host-testable on any target. Used by
/// `CpuTopologyX86_64::probe()` on x86_64.
pub fn cpuid_topology_ncpus(entries: &[CpuidTopologyEntry]) -> u32 {
    entries
        .iter()
        .map(|e| e.logical_processors)
        .max()
        .unwrap_or(1)
        .max(1)
}

/// True iff `vaddr` falls in a kernel-reserved PML4 slot (256..=511).
pub const fn pml4_slot_is_kernel(vaddr: usize) -> bool {
    let idx = pt_index(vaddr, PML4_SHIFT);
    idx >= PML4_KERNEL_FIRST && idx <= PML4_KERNEL_LAST
}

/// Build the PCI config-space address for `bus`/`device`/`function`/`offset`.
///
/// `offset` must be 4-byte aligned; the low 2 bits are masked out.
pub const fn pci_config_addr(bus: u8, dev: u8, fn_: u8, offset: u8) -> u32 {
    (1u32 << 31) // enable bit
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((fn_ as u32) << 8)
        | ((offset as u32) & 0xFC)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_base_is_canonical_user_bounds() {
        // Canonical user addresses (lower half) are accepted.
        assert!(fs_base_is_canonical_user(0));
        assert!(fs_base_is_canonical_user(0x7FFF_FFFF_FFFF));
        assert!(fs_base_is_canonical_user(0x0000_7FFF_FFFF_FFFF));
        // Just above the ceiling is not a canonical user address.
        assert!(!fs_base_is_canonical_user(FS_BASE_USER_CEIL));
        assert!(!fs_base_is_canonical_user(FS_BASE_USER_CEIL + 1));
        // Kernel range is not a valid user FS base.
        assert!(!fs_base_is_canonical_user(0xFFFF_8000_0000_0000));
        // Non-canonical high half is rejected.
        assert!(!fs_base_is_canonical_user(0xFFFF_7FFF_FFFF_FFFF));
    }

    #[test]
    fn pt_index_bits() {
        assert_eq!(pt_index(0, PML4_SHIFT), 0);
        assert_eq!(pt_index(1usize << PML4_SHIFT, PML4_SHIFT), 1);
        assert_eq!(pt_index(0x123 << PML4_SHIFT, PML4_SHIFT), 0x123);
        assert_eq!(pt_index(0x045 << PDPT_SHIFT, PDPT_SHIFT), 0x045);
        assert_eq!(pt_index(0x078 << PD_SHIFT, PD_SHIFT), 0x078);
        assert_eq!(pt_index(0x0AB << PT_SHIFT, PT_SHIFT), 0x0AB);
        // Mask keeps only the 9 low bits of the selected slice.
        assert_eq!(pt_index(0x1FF << PT_SHIFT, PT_SHIFT), 0x1FF);
        assert_eq!(pt_index(0xFFF, PT_SHIFT), 0); // bits below the slice are dropped
    }

    #[test]
    fn pci_config_addr_layout() {
        // Enable bit set, function/offset fields packed.
        let a = pci_config_addr(0x00, 0x1F, 0x07, 0xFC);
        assert_eq!(a >> 31, 1);
        assert_eq!((a >> 16) & 0xFF, 0x00); // bus
        assert_eq!((a >> 11) & 0x1F, 0x1F); // device
        assert_eq!((a >> 8) & 0x07, 0x07); // function
        assert_eq!(a & 0xFC, 0xFC); // offset, low 2 bits clear
                                    // Offset low 2 bits are masked out.
        assert_eq!(pci_config_addr(0, 0, 0, 3) & 0xFC, 0);
        assert_eq!(pci_config_addr(0, 0, 0, 3) & 0x3, 0);
    }

    #[test]
    fn pml4_slot_is_kernel_bounds() {
        // Userspace low half: PML4 slots 0..256 are not kernel slots.
        assert!(!pml4_slot_is_kernel(0));
        assert!(!pml4_slot_is_kernel(0x0000_7FFF_FFFF_F000)); // slot 255, top of user range
                                                              // The FS-base user ceiling (S3) is exactly the first kernel slot.
        assert!(pml4_slot_is_kernel(FS_BASE_USER_CEIL as usize)); // slot 256
        assert!(pml4_slot_is_kernel(256 << PML4_SHIFT));
        assert!(pml4_slot_is_kernel(511 << PML4_SHIFT));
        assert!(pml4_slot_is_kernel(0xFFFF_8000_0000_0000)); // higher-half base -> slot 511
    }

    #[test]
    fn cpuid_ecx_has_bits() {
        let ecx: u32 = CPUID_ECX_UMIP;
        assert!(cpuid_ecx_has(ecx, CPUID_ECX_UMIP));
        assert!(!cpuid_ecx_has(ecx, CPUID_EBX_SMEP));
        assert!(!cpuid_ecx_has(0, CPUID_ECX_UMIP));
    }

    #[test]
    fn cpuid_ebx_has_bits() {
        let ebx: u32 = CPUID_EBX_SMEP | CPUID_EBX_SMAP;
        assert!(cpuid_ebx_has(ebx, CPUID_EBX_SMEP));
        assert!(cpuid_ebx_has(ebx, CPUID_EBX_SMAP));
        assert!(!cpuid_ebx_has(ebx, CPUID_ECX_UMIP));
        assert!(!cpuid_ebx_has(0, CPUID_EBX_SMEP));
    }

    #[test]
    fn cpuid_leaf1_logical_processors_bits() {
        // EBX[23:16] = logical processors per package.
        assert_eq!(cpuid_leaf1_logical_processors(4u32 << 16), 4);
        assert_eq!(cpuid_leaf1_logical_processors(1u32 << 16), 1);
        assert_eq!(cpuid_leaf1_logical_processors(16u32 << 16), 16);
        assert_eq!(cpuid_leaf1_logical_processors(0), 0);
    }

    #[test]
    fn cpuid_topology_level_decode() {
        let e = cpuid_topology_level(8, 0x123, CPUID_TOPOLOGY_LEVEL_CORE);
        assert_eq!(e.logical_processors, 8);
        assert_eq!(e.x2apic_id, 0x123);
        assert_eq!(e.level_type, CPUID_TOPOLOGY_LEVEL_CORE);
        let t = cpuid_topology_level(2, 0, CPUID_TOPOLOGY_LEVEL_THREAD);
        assert_eq!(t.level_type, CPUID_TOPOLOGY_LEVEL_THREAD);
        assert_eq!(t.logical_processors, 2);
        assert_eq!(t.x2apic_id, 0);
    }

    #[test]
    fn cpuid_topology_constants() {
        assert_eq!(CPUID_LEAF_1, 1);
        assert_eq!(CPUID_LEAF_TOPOLOGY, 0x0B);
        assert_eq!(CPUID_TOPOLOGY_LEVEL_THREAD, 0);
        assert_eq!(CPUID_TOPOLOGY_LEVEL_CORE, 1);
    }

    #[test]
    fn cpuid_topology_ncpus_max_domain() {
        // Empty input: single-CPU fallback.
        assert_eq!(cpuid_topology_ncpus(&[]), 1);
        // Single thread domain.
        assert_eq!(
            cpuid_topology_ncpus(&[cpuid_topology_level(1, 0, CPUID_TOPOLOGY_LEVEL_THREAD)]),
            1
        );
        // Top (package) domain reports the total logical processors.
        let entries = [
            cpuid_topology_level(1, 0, CPUID_TOPOLOGY_LEVEL_THREAD), // 1 thread / core
            cpuid_topology_level(2, 0, CPUID_TOPOLOGY_LEVEL_CORE),   // 2 threads / package
        ];
        assert_eq!(cpuid_topology_ncpus(&entries), 2);
        // Zero-valued domains fall back to 1.
        assert_eq!(
            cpuid_topology_ncpus(&[cpuid_topology_level(0, 0, CPUID_TOPOLOGY_LEVEL_THREAD)]),
            1
        );
    }
}
