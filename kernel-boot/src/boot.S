/*
 * x86_64 boot entry (ADR-025): multiboot2 header, 32→64-bit trampoline.
 *
 * QEMU (`-kernel`) finds the multiboot2 header, loads the ELF segments at
 * their physical addresses, and enters `_start` in 32-bit protected mode with
 * paging off. This code:
 *   1. loads a flat GDT (32-bit, 64-bit, data, user segments)
 *   2. enables protected mode (already on under multiboot; harmless)
 *   3. builds identity page tables (first 1 GiB, 2 MiB pages) and enters
 *      long mode
 *   4. sets up a stack and jumps to Rust `kernel_main`
 *
 * All state is in .bss (zero-filled by the loader); PML4/PDPT/PD entries and
 * the identity PD are programmed at runtime before enabling paging.
 */

/* ---- multiboot2 header (must sit within the first 32 KiB of the file) ---- */
.section .multiboot2.header,"a",@progbits
.align 8
mb2_start:
    .long 0xe85250d6                                    /* magic */
    .long 0                                             /* arch: i386 */
    .long mb2_end - mb2_start                           /* header length */
    .long -(0xe85250d6 + (mb2_end - mb2_start))         /* checksum */
    /* end tag */
    .align 8
    .short 0                                            /* type: end */
    .short 0                                            /* flags */
    .long 8                                             /* size */
mb2_end:

/* ---- PVH boot note (XEN_ELFNOTE_PHYS32_ENTRY): QEMU loads the ELF with
 * `-kernel` and enters `_start` in 32-bit protected mode with paging off —
 * exactly the state this trampoline expects. ---- */
.section .note.Xen,"a",@note
.align 4
    .long 4                 /* namesz: "Xen\0" */
    .long 4                 /* descsz: one 4-byte entry address */
    .long 18                /* XEN_ELFNOTE_PHYS32_ENTRY */
    .asciz "Xen"
    .align 4
    .long _start
    .align 4

/* ---- 32-bit entry ---- */
.section .text.boot,"ax",@progbits
.code32
.global _start
_start:
    cli
    cld

    lgdt gdt_ptr32

    mov eax, cr0
    or eax, 1                    /* CR0.PE */
    mov cr0, eax
    .byte 0xea
    .long _start32
    .word 0x08

.code32
_start32:
    mov ax, 0x10                 /* flat 32-bit data */
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, offset stack_top

    /* PML4[0] -> PDPT (present|rw) */
    mov edi, offset pml4_table
    mov eax, offset pdpt_table
    or eax, 0x3
    mov [edi], eax
    mov dword ptr [edi + 4], 0

    /* Higher-half alias (ADR-045 slice 1): PML4[511] -> PDPT, and
     * PDPT[510] -> PD — VA 0xFFFFFFFF_80000000 + X maps via PML4[511],
     * PDPT[510], PD[X >> 21] to physical X (the canonical top-2-GiB kernel
     * half is PML4[511]/PDPT[510], NOT PDPT[511]). The Rust kernel, linked
     * at 0xFFFFFFFF_80100000, is mapped the moment paging starts. */
    mov edi, offset pml4_table
    add edi, 511 * 8
    mov eax, offset pdpt_table
    or eax, 0x3
    mov [edi], eax
    mov dword ptr [edi + 4], 0

    mov edi, offset pdpt_table
    add edi, 510 * 8
    mov eax, offset pd_table
    or eax, 0x3
    mov [edi], eax
    mov dword ptr [edi + 4], 0

    /* PDPT[0] -> PD (present|rw) */
    mov edi, offset pdpt_table
    mov eax, offset pd_table
    or eax, 0x3
    mov [edi], eax
    mov dword ptr [edi + 4], 0

    /* PD: 512 x 2 MiB identity entries (present|rw|ps) */
    mov edi, offset pd_table
    mov eax, 0x83                /* present | rw | 2 MiB page */
    mov ecx, 512
_fill_pd:
    mov [edi], eax
    mov dword ptr [edi + 4], 0
    add eax, 0x200000
    add edi, 8
    loop _fill_pd

    mov eax, offset pml4_table
    mov cr3, eax

    mov eax, cr4
    or eax, (1 << 5)             /* CR4.PAE */
    mov cr4, eax

    mov ecx, 0xC0000080          /* IA32_EFER */
    rdmsr
    or eax, (1 << 8)             /* EFER.LME */
    wrmsr

    mov eax, cr0
    or eax, (1 << 31)            /* CR0.PG -> long mode */
    mov cr0, eax

    .byte 0xea
    .long _start64
    .word 0x18

/* ---- 64-bit entry ---- */
.code64
_start64:
    mov ax, 0x10                 /* flat data (works as flat 64-bit base) */
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    mov rsp, offset stack_top
    xor rbp, rbp

    /* kernel_main is linked at the higher-half VMA (ADR-045): beyond rel32
     * range from the low trampoline — 64-bit immediate, jump through a
     * register. */
    movabs rax, offset kernel_main
    jmp rax

/* ---- GDT: null | 32-bit code | data | 64-bit code | user code | user data ---- */
.section .boot.rodata,"a",@progbits
.align 16
gdt_start:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff     /* 0x08: ring0 32-bit code */
    .quad 0x00cf92000000ffff     /* 0x10: ring0 data */
    .quad 0x00af9a000000ffff     /* 0x18: ring0 64-bit code */
    .quad 0x00affa000000ffff     /* 0x20: ring3 64-bit code */
    .quad 0x00cff2000000ffff     /* 0x28: ring3 data */
gdt_end:

gdt_ptr32:
    .word gdt_end - gdt_start - 1
    .long gdt_start              /* 32-bit base (low 4 GiB load address) */

/* ---- page tables + boot stack in .boot.bss (LOW VMA: the 32-bit
 * trampoline programs these tables by address; the kernel's `stack_top`
 * extern still resolves — the identity map covers the low half) ---- */
.section .boot.bss,"aw",@nobits
.align 4096
pml4_table:
    .skip 4096
pdpt_table:
    .skip 4096
pd_table:
    .skip 4096

.align 16
.global stack_top
stack_bottom:
    .skip 2097152               /* 2 MiB: frame::init and boot-path frames
                                   materialize large tables (the 256 KiB
                                   allocator staging lived on the stack until
                                   it was moved to const .bss; debug-profile
                                   frames are ~2x release — 1 MiB overflowed
                                   into the page tables below stack_bottom
                                   and self-zeroed the identity map) */
stack_top:
