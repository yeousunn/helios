# lin_args — argv test (ADR-044, slice 29).
#
# Freestanding static x86_64-linux ELF, no libc: writes argv[0], whose length
# it computes by scanning for the NUL terminator, then exits. linrun crafts a
# Linux startup block on the emulated stack, so argv[0] is the string the
# emulator placed there ("helios-linux-abi").
#
# Build (see ../build.sh):
#   zig cc -target x86_64-linux-musl -nostdlib -static -s -o lin_args lin_args.s

.text
.global _start
_start:
    mov 8(%rsp), %rsi       # argv[0] (argv sits right above argc at rsp)
    xor %rdx, %rdx          # len = 0
Lstrlen:
    cmpb $0, (%rsi,%rdx)
    je Lwrite
    inc %rdx
    jmp Lstrlen
Lwrite:
    mov $1, %rax            # SYS_write
    mov $1, %rdi            # fd = stdout
    syscall
    mov $60, %rax           # SYS_exit
    xor %rdi, %rdi          # status = 0
    syscall
    hlt                     # not reached
