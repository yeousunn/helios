// x86_64 BIOS boot sector - 512 bytes
// Reads kernel from disk sectors 2+ into memory at 0x0
// and jumps to the kernel entry point at 0x1010

__attribute__((naked))
void _start(void) {
    __asm__ volatile (
        "cli\n\t"
        "xor %%ax, %%ax\n\t"
        "mov %%ax, %%ss\n\t"
        "mov $0x7C00, %%sp\n\t"
        "sti\n\t"

        /* Read kernel from disk sectors 2+ into memory at 0x0 */
        "xor %%ax, %%ax\n\t"     /* ES = 0x0 -> segment base 0x0 */
        "mov %%ax, %%es\n\t"
        "xor %%bx, %%bx\n\t"       /* BX = 0x0000 -> ES:BX = 0x00000 */
        "mov $0x0200, %%ax\n\t"    /* AH = 0x02 (read sectors), AL = 0x00 */
        "movb $128, %%al\n\t"      /* AL = 128 sectors (512 KiB) */
        "movw $0x0000, %%cx\n\t"   /* CH = 0 (cylinder 0), CL = 0 (sector 0) */
        "incb %%cl\n\t"            /* CL = 2 (start at sector 2) */
        "movb $0x00, %%dh\n\t"     /* DH = 0 (head 0) */
        "movb $0x00, %%dl\n\t"     /* DL = 0 (drive 0 = first floppy) */
        "int $0x13\n\t"            /* BIOS disk read */
        "jc disk_error\n\t"        /* Jump if carry set (error) */

        /* Jump to kernel entry point at 0x1010 */
        "ljmp $0x0000, $0x1010\n\t"

        "disk_error:\n\t"
        "cli\n\t"
        "hlt\n\t"
        "jmp disk_error\n\t"
        :
        :
        : "ax", "bx", "cx", "dx", "memory"
    );
}
