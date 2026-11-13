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
}
