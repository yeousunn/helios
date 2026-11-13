/*
 * Exception entry stubs (vectors 0..=255). Every stub funnels into
 * `exc_common`, which calls the Rust reporter with (vector, error_code, cr2,
 * faulting RIP). The reporter never returns (it halts the CPU), so faults
 * during bring-up are loudly visible instead of triple-faulting silently.
 *
 * Stack layout at `exc_common` (kernel-mode fault):
 *   [rsp]    vector (pushed by the stub)
 *   [rsp+8]  error code (CPU-pushed, or 0 dummy)
 *   [rsp+16] faulting RIP (CPU-pushed frame)
 */

.macro EXC_NOERR vec
.global exc_stub_\vec
exc_stub_\vec:
    push 0
    push \vec
    jmp exc_common
.endm

.macro EXC_ERR vec
.global exc_stub_\vec
exc_stub_\vec:
    push \vec
    jmp exc_common
.endm

.section .text
/* Vectors that push an error code: 8, 10..14, 17, 21, 29, 30. */
EXC_NOERR 0
EXC_NOERR 1
EXC_NOERR 2
EXC_NOERR 3
EXC_NOERR 4
EXC_NOERR 5
EXC_NOERR 6
EXC_NOERR 7
EXC_ERR   8
EXC_NOERR 9
EXC_ERR   10
EXC_ERR   11
EXC_ERR   12
EXC_ERR   13
EXC_ERR   14
EXC_NOERR 15
EXC_NOERR 16
EXC_ERR   17
EXC_NOERR 18
EXC_NOERR 19
EXC_NOERR 20
EXC_ERR   21
EXC_NOERR 22
EXC_NOERR 23
EXC_NOERR 24
EXC_NOERR 25
EXC_NOERR 26
EXC_NOERR 27
EXC_NOERR 28
EXC_ERR   29
EXC_ERR   30
EXC_NOERR 31

EXC_NOERR 32
EXC_NOERR 33
EXC_NOERR 34
EXC_NOERR 35
EXC_NOERR 36
EXC_NOERR 37
EXC_NOERR 38
EXC_NOERR 39
EXC_NOERR 40
EXC_NOERR 41
EXC_NOERR 42
EXC_NOERR 43
EXC_NOERR 44
EXC_NOERR 45
EXC_NOERR 46
EXC_NOERR 47

/* IRQ stubs (vectors 32..47 = IRQs 0..15): preserve the interruptee's
 * volatile registers, dispatch through the Rust PIC layer, then iretq.
 * Interrupts from ring 3 switch to the TSS rsp0 kernel stack (CPU pushes
 * SS:RSP:RFLAGS:CS:RIP; IRQs carry no error code). */
.macro IRQ vec
.global irq_stub_\vec
irq_stub_\vec:
    cld                             /* S7: user DF must not reach kernel string ops */
    push qword ptr \vec
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov rdi, \vec
    call hal_irq_dispatcher
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    add rsp, 8
    iretq
.endm

IRQ 32
IRQ 33
IRQ 34
IRQ 35
IRQ 36
IRQ 37
IRQ 38
IRQ 39
IRQ 40
IRQ 41
IRQ 42
IRQ 43
IRQ 44
IRQ 45
IRQ 46
IRQ 47
/* Vectors >= 48 do not occur in v0; no gates are installed past 47. */

exc_common:
    cld                             /* S7: user DF must not reach kernel string ops */
    cli
    mov rdi, [rsp]          /* vector */
    mov rsi, [rsp + 8]      /* error code */
    mov rdx, cr2            /* faulting address (valid for #PF) */
    mov rcx, [rsp + 16]     /* faulting RIP */
    mov r8, [rsp + 24]      /* CS */
    call exception_report
1:
    hlt
    jmp 1b
