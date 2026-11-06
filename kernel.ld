/*
 * Linker script for the Helios kernel boot binary (x86_64, ADR-025).
 *
 * QEMU's multiboot2/PVH loader reads PHYSICAL addresses (LMAs) and enters
 * `_start` in 32-bit protected mode with paging off. The 32-bit trampoline
 * (.text.boot) and its data (.boot.*) stay at low VMAs — they run before
 * long mode / with the identity map only.
 *
 * ADR-045 slice 1: the Rust kernel (.text/.rodata/.data/.bss) is linked at
 * HIGH virtual addresses in PML4[511] (0xFFFF_8000_0100_0000 alias of the
 * 1 MiB load address) while its LMAs stay low (the loaders' view). boot.S
 * installs PML4[511] -> the same PDPT as PML4[0] before entering long mode,
 * so the high alias is live the moment paging starts; kernel_main is
 * entered at its high VA and never runs at low addresses.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_BASE = 0xFFFFFFFF80100000;
KERNEL_LOAD = 0x100000;

SECTIONS
{
    . = KERNEL_LOAD;

    /* Multiboot2 header must come first (near the file start). */
    .multiboot2.header : ALIGN(8)
    {
        KEEP(*(.multiboot2.header))
    }

    /* PVH boot note must survive (QEMU reads it from the ELF file). */
    .note.Xen : ALIGN(4)
    {
        KEEP(*(.note.Xen))
    }

    /* Boot trampoline (32-bit trampoline + 64-bit hand-off). LOW VMA: the
     * 32-bit half cannot reach the high half. */
    .text.boot : ALIGN(4096)
    {
        *(.text.boot)
        *(.text.boot.*)
    }

    /* Boot-only data: GDT (lgdt in 32-bit code), page tables, boot stack.
     * LOW VMA — the trampoline programs absolute low addresses, and the
     * identity map covers them for the kernel's `stack_top` extern. */
    .boot.data : ALIGN(16)
    {
        *(.boot.rodata)
        *(.boot.rodata.*)
    }

    .boot.bss (NOLOAD) : ALIGN(4096)
    {
        *(.boot.bss)
        *(.boot.bss.*)
    }

    _boot_end = .;

    /* ---- Rust kernel: HIGH VMA, low LMA (AT) ---- */
    /* Alias constraint (2 MiB pages from PA 0): VMA - 0xFFFFFFFF80000000
     * must equal the LMA — the kernel image loads at _boot_end (after the
     * boot pieces, past the 2 MiB boot stack) and is read through
     * 0xFFFFFFFF80000000 + LMA. */
    . = KERNEL_BASE + (_boot_end - KERNEL_LOAD);

    _kernel_lma = _boot_end;

    /* Each section's LMA = VMA - 0xFFFFFFFF80000000 exactly — the 2 MiB
     * alias pages translate VA to PA, so the loaded bytes must sit at
     * precisely the aliased physical offset (a running _kernel_lma chain
     * drifts at every VMA ALIGN gap). */
    .text : AT(ADDR(.text) - 0xFFFFFFFF80000000) ALIGN(4096)
    {
        *(.text)
        *(.text.*)
    }

    .rodata : AT(ADDR(.rodata) - 0xFFFFFFFF80000000) ALIGN(4096)
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data : AT(ADDR(.data) - 0xFFFFFFFF80000000) ALIGN(4096)
    {
        *(.data)
        *(.data.*)
    }

    /* GOT/relro orphans must sit WITHIN ±2 GiB of the code — place them
     * explicitly next to .data (lld otherwise scatters them out of range). */
    .got : AT(ADDR(.got) - 0xFFFFFFFF80000000) ALIGN(8)
    {
        *(.got)
        *(.got.plt)
    }

    .bss (NOLOAD) : AT(ADDR(.bss) - 0xFFFFFFFF80000000) ALIGN(4096)
    {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame*)
        *(.gcc_except_table*)
    }

    _end = .;
}
