/*!
 * `syscall` entry stub (syscall-abi §2). Single-CPU v0: one static kernel
 * entry stack, one user-RSP cell, one 6-word return cell. The Rust
 * dispatcher (`helios_syscall_dispatch`) reads the raw registers as its
 * arguments and writes `SYS_RET`; this stub then `sysretq`s.
 *
 * Register shuffle (syscall ABI -> SysV64 call ABI):
 *   num=rax, cap=rdi, tag=rsi, w0=rdx, w1=r10, w2=r8, w3=r9
 *   -> rdi=num, rsi=cap, rdx=tag, rcx=w0, r8=w1, r9=w2, [rsp]=w3
 */

.section .text
.global helios_syscall_entry
helios_syscall_entry:
    mov [rip + SYS_USER_RSP_TMP], rsp
    mov rsp, [rip + CURRENT_KSTACK]  /* per-thread kernel stack (M3) */

    push qword ptr [rip + SYS_USER_RSP_TMP]
    push rcx                    /* user RIP (sysret consumes rcx) */
    push r11                    /* user RFLAGS (r11) */
    push r9                     /* 7th argument: w3 */

    mov r9, r8                  /* w2 */
    mov r8, r10                 /* w1 */
    mov r10, rdx                /* temp: w0 */
    mov rdx, rsi                /* tag */
    mov rsi, rdi                /* cap */
    mov rdi, rax                /* num */
    mov rcx, r10                /* w0 */

    call helios_syscall_dispatch

    add rsp, 8                  /* drop 7th arg */
    pop r11
    pop rcx
    pop rsp                     /* restore user RSP (pushed first) */

    mov rax, [rip + SYS_RET + 0]
    mov rdx, [rip + SYS_RET + 8]
    mov rsi, [rip + SYS_RET + 16]
    mov rdi, [rip + SYS_RET + 24]
    mov r8,  [rip + SYS_RET + 32]
    mov r9,  [rip + SYS_RET + 40]
    sysretq

/* Cooperative kernel context switch (M3). C ABI: rdi = &from_thread.ksp,
 * rsi = to_thread.ksp. Saves the callee-saved registers and stack pointer
 * into `*rdi`, loads the target's stack, restores its registers and returns
 * into its saved context (or the fresh-thread trampoline below). Pure asm —
 * no compiler-generated code participates in the switch. */
.global helios_switch
helios_switch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

/* Fresh-thread entry (M3): `switch` pops the callee-saved registers and
 * returns here with the stack holding [rsp]=entry, [rsp+8]=user RSP,
 * [rsp+16]=arg. iretq to ring 3. */
.global thread_trampoline
thread_trampoline:
    pop rax                     /* entry PC */
    pop rbx                     /* user RSP */
    pop rdi                     /* arg */
    push 0x1B                   /* SS: user data */
    push rbx                    /* RSP */
    push 0x202                  /* RFLAGS */
    push 0x23                   /* CS: user code */
    push rax                    /* RIP */
    iretq

.section .bss
.global SYS_RET
.align 8
SYS_RET:
    .skip 48
.global SYS_USER_RSP_TMP
SYS_USER_RSP_TMP:
    .skip 8
