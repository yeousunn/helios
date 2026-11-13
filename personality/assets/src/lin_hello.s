# lin_hello — first foreign (Linux-ABI) test artifact (ADR-044).
#
# Freestanding static x86_64-linux ELF, no libc: one raw write(2) then
# exit_group(2). It prints "helios-linux-abi" and is loaded by the linrun
# emulator, which routes its raw `syscall`s back to userspace.
#
# Build (see ../build.sh):
#   zig cc -target x86_64-linux-musl -nostdlib -static -s -o lin_hello lin_hello.s

.text
.global _start
_start:
    mov $1, %rax            # SYS_write
    mov $1, %rdi            # fd = stdout
    lea msg(%rip), %rsi     # buf
    mov $17, %rdx           # len (includes the trailing newline)
    syscall
    mov $60, %rax           # SYS_exit
    xor %rdi, %rdi          # status = 0
    syscall
    hlt                     # not reached
msg:
    .ascii "helios-linux-abi\n"
