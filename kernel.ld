/*
 * Linker script for the Helios kernel boot binary (x86_64, ADR-025).
 *
 * QEMU's multiboot2 loader needs the header within the first 32 KiB of the
 * file and loads ELF segments at their physical addresses; the kernel is
 * linked at 1 MiB and is position-dependent (the boot trampoline uses
 * absolute low addresses).
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    /* Multiboot2 header must come first (near the file start). */
    .multiboot2.header : ALIGN(8)
    {
        KEEP(*(.multiboot2.header))
    }

    /* Boot trampoline (32-bit trampoline + 64-bit hand-off). */
    .text.boot : ALIGN(4096)
    {
        *(.text.boot)
        *(.text.boot.*)
    }

    .text : ALIGN(4096)
    {
        *(.text)
        *(.text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata)
        *(.rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data)
        *(.data.*)
    }

    /* PVH boot note must survive (QEMU reads it from the ELF file). */
    .note.Xen : ALIGN(4)
    {
        KEEP(*(.note.Xen))
    }

    .bss : ALIGN(4096)
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
