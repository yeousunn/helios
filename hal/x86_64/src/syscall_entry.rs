//! `syscall`/`sysret` entry and dispatch marshaling (syscall-abi §2,
//! ADR-011). The asm stub lives in `syscall_entry.S`; this module enables the
//! MSRs, provides the Rust dispatcher, and owns the parked-policy stopgap.
//!
//! v0 scope: synchronous syscalls only. A syscall that *parks* (ADR-019:
//! `dispatch` returns `PARKED_STATUS`) halts with a loud message — context
//! switching (M3) is not wired yet; the M2 init binary never parks.

use core::arch::{asm, global_asm};

use ipc::{flags, Tag};
use kernel::entry::{self, SyscallArgs, SyscallReturn, PARKED_STATUS};

global_asm!(include_str!("syscall_entry.S"));

extern "C" {
    fn helios_syscall_entry();
    fn thread_trampoline();
    fn helios_switch(from_slot: *mut u64, to_ksp: u64);
    static mut SYS_RET: [u64; 7];
}

/// Address of the fresh-thread ring-3 entry trampoline (used by
/// `ContextBackend::init_context`).
pub fn thread_trampoline_addr() -> u64 {
    thread_trampoline as *const () as u64
}

/// Perform the raw kernel context switch (pure asm; see `syscall_entry.S`).
///
/// # Safety
/// `from_slot` must point to the running thread's saved-ksp slot and
/// `to_ksp` must be a valid kernel stack pointer (saved context or freshly
/// built thread frame). Returns when this thread is switched back in.
pub(crate) unsafe fn switch_to_context(from_slot: *mut u64, to_ksp: u64) {
    // SAFETY: caller contract above.
    unsafe { helios_switch(from_slot, to_ksp) };
}

const IA32_EFER: u32 = 0xC000_0080;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;
const EFER_SCE: u64 = 1 << 0;
/// IF (0x200), TF (0x100), DF (0x400), AC (0x40000) and NT (0x4000) cleared
/// on syscall entry so a user-controlled RFLAGS cannot re-enable interrupts,
/// single-step, reverse string ops or the alignment-check/Nested-Task bits in
/// the kernel (S7).
const FMASK: u64 = 0x47700;

/// Enable `syscall`/`sysret`: EFER.SCE, STAR (kernel CS 0x08; sysret computes
/// user CS/SS as STAR[63:48]+16/+8 → user code 0x23, user data 0x1B), LSTAR,
/// FMASK. Call once at boot after the GDT is installed.
///
/// # Safety
///
/// Programs architectural MSRs (EFER, STAR, LSTAR, FMASK); must be called once
/// at boot after the GDT is installed, before any userspace `syscall`.
pub unsafe fn enable() {
    // SAFETY: MSR programming is IA32 architectural state; values assembled
    // from the fixed GDT layout (see `Gdt` docs).
    unsafe {
        let mut efer_lo: u32;
        let mut efer_hi: u32;
        asm!("rdmsr", in("ecx") IA32_EFER, out("eax") efer_lo, out("edx") efer_hi, options(nostack));
        let efer = ((efer_hi as u64) << 32 | efer_lo as u64) | EFER_SCE;
        asm!("wrmsr", in("ecx") IA32_EFER, in("eax") efer as u32, in("edx") (efer >> 32) as u32, options(nostack));

        let star: u64 = (0x10_u64 << 48) | (0x08_u64 << 32);
        asm!("wrmsr", in("ecx") IA32_STAR, in("eax") star as u32, in("edx") (star >> 32) as u32, options(nostack));

        let lstar = helios_syscall_entry as *const () as u64;
        asm!("wrmsr", in("ecx") IA32_LSTAR, in("eax") lstar as u32, in("edx") (lstar >> 32) as u32, options(nostack));

        asm!("wrmsr", in("ecx") IA32_FMASK, in("eax") FMASK as u32, in("edx") 0u32, options(nostack));
    }
}

/// SysV64 dispatcher called by `helios_syscall_entry` with the raw syscall
/// registers shuffled into the C argument order. Writes the return registers
/// into `SYS_RET` for the stub, and performs cooperative scheduling when the
/// calling thread parked or exited (M3).
#[no_mangle]
extern "sysv64" fn helios_syscall_dispatch(
    num: u64,
    cap: u64,
    tag: u64,
    w0: u64,
    w1: u64,
    w2: u64,
    w3: u64,
) {
    let t = Tag(tag);
    let args = SyscallArgs {
        num,
        cap,
        tag: t,
        w: [w0, w1, w2, w3],
        nonblock: t.flags() & flags::NONBLOCK != 0,
    };
    kstack_guard();
    let ret = entry::dispatch(args);
    if ret.status == PARKED_STATUS {
        // Parked inside recv/reply_recv: the result materializes on resume.
        resume_loop(None);
        return;
    }
    store_ret(ret);
    if !thread_is_runnable() {
        // Blocked (send/recv park) or exited: do not sysret now; the thread
        // resumes here later (with its result re-stored) or never (exit).
        resume_loop(Some(ret));
    } else if num == 0 {
        // `yield`: the thread stays runnable (yield_now requeues it), so the
        // runnable check above would skip the switch and the "yield" becomes
        // a no-op — the caller then spins on-CPU forever and starves every
        // other thread (found: the VFS polling accept loop). Route it
        // through the resume machinery explicitly: switch to the next
        // thread; when this one is picked again, park_result is None, the
        // state is Ready, and the saved (Ok) result is re-stored and
        // returned.
        resume_loop(Some(ret));
    }
}

/// Kernel-stack canary (clobber hunt, DS m49–m64): verify the dispatch is
/// running on the CURRENT thread's registered kernel stack. A mismatch means
/// a syscall entered with a stale `CURRENT_KSTACK` — the entry frame then
/// lands on another thread's (or a drained, reused) stack, which is exactly
/// the "kernel-dispatch data in user locals" corruption shape. Loud + fatal:
/// deterministic beats silent.
fn kstack_guard() {
    let tid = kernel::sched::current();
    let Ok(t) = kernel::sched::get(tid) else {
        return;
    };
    let top = t.kstack_top;
    if top == 0 {
        return; // boot thread before registration
    }
    // ADR-045 slice 2b: kstack_top is physical; the guard compares against
    // the shared-window high alias (the dispatch RSP lives there).
    let top = kernel::mem::phys_to_virt(top);
    let rsp: u64;
    // SAFETY: reads the current stack pointer; no memory access.
    unsafe { core::arch::asm!("mov {0}, rsp", out(reg) rsp, options(nostack)) };
    // The dispatcher frame must sit within this thread's kernel stack
    // (KSTACK_FRAMES × 4 KiB, kernel/src/sched.rs — 64 KiB since the
    // 2026-11-05 clobber fix; the window must track that constant, not a
    // stale literal, or legitimate deep frames false-trip the guard).
    let kstack_bytes = (kernel::sched::KSTACK_FRAMES as u64) * 4096;
    if rsp > top || rsp <= top - kstack_bytes {
        crate::uart_writer(
            "
[kernel] KSTACK GUARD: dispatch off-stack
",
        );
        crate::uart_writer("  tid=");
        uart_hex(tid.0);
        crate::uart_writer(" rsp=");
        uart_hex(rsp);
        crate::uart_writer(" expected_top=");
        uart_hex(top);
        crate::uart_writer(
            "
",
        );
        // Halt loudly instead of corrupting further.
        loop {
            // SAFETY: halting on a detected kernel-stack violation.
            unsafe { core::arch::asm!("cli; hlt", options(nostack, nomem)) };
        }
    }
}

fn uart_hex(v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut buf = [0u8; 16];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = HEX[((v >> (60 - i * 4)) & 0xF) as usize];
    }
    crate::uart_writer(core::str::from_utf8(&buf).unwrap_or(""));
}

fn thread_is_runnable() -> bool {
    let tid = kernel::sched::current();
    matches!(
        kernel::sched::get(tid).map(|t| t.state),
        Ok(kernel::sched::State::Ready) | Ok(kernel::sched::State::Running)
    )
}

/// Cooperative scheduling: switch to the next runnable thread and, when this
/// thread is later resumed, complete its syscall (parked result or the saved
/// return value). Never returns unless the syscall may sysret.
fn resume_loop(saved: Option<SyscallReturn>) {
    let tid = kernel::sched::current();
    loop {
        if kernel::sched::thread_count() == 0 {
            kernel::panic::clean_exit();
        }
        let mut next = kernel::sched::pick_next();
        if next.0 == 0 {
            // Idle: nothing runnable. Drain the kstack graveyard first
            // (ADR-031): this context is provably not on any buried stack.
            kernel::sched::drain_graveyard();
            crate::uart_writer("\n[kernel] idle: no runnable thread\n");
            // (ADR-042): `sti; hlt; cli` lets a pending IRQ wake the CPU —
            // pending IRQs do NOT wake `hlt` at IF=0. `drain_tick` runs
            // lock-free before re-picking to expire parked recv/send
            // deadlines. Re-pick until a thread is runnable.
            loop {
                // SAFETY: `sti; hlt; cli` briefly enables interrupts so a
                // pending IRQ wakes `hlt`, then re-disables for dispatch.
                unsafe {
                    asm!("sti", options(nostack));
                    asm!("hlt", options(nostack));
                    asm!("cli", options(nostack));
                }
                kernel::time::drain_tick();
                let picked = kernel::sched::pick_next();
                if picked.0 != 0 {
                    next = picked;
                    break;
                }
            }
        }
        kernel::sched::switch_to(next);

        // Resumed: was this thread completed while parked?
        if let Some(r) = entry::park_result(tid) {
            store_ret(r);
            return;
        }
        let runnable = matches!(
            kernel::sched::get(tid).map(|t| t.state),
            Ok(kernel::sched::State::Ready) | Ok(kernel::sched::State::Running)
        );
        if runnable {
            match saved {
                // Re-store: other threads overwrote SYS_RET while we parked.
                Some(r) => store_ret(r),
                // Runnable without any completion data: impossible for a
                // well-formed park. Returning would sysret STALE `SYS_RET`
                // (another thread's handles!) into userspace — re-block and
                // keep waiting instead (found via PS spawning its child).
                None => {
                    let reason = match kernel::sched::get(tid).map(|t| t.state) {
                        Ok(kernel::sched::State::Blocked(r)) => r,
                        _ => kernel::sched::BlockReason::Reply,
                    };
                    let _ = kernel::sched::block(tid, reason);
                }
            }
            return;
        }
        // Still blocked (woken spuriously): keep waiting.
    }
}

fn store_ret(ret: SyscallReturn) {
    // SAFETY: single-CPU v0; `SYS_RET` is only touched on the syscall path.
    unsafe {
        let p = core::ptr::addr_of_mut!(SYS_RET) as *mut u64;
        p.write_volatile(ret.status as u64);
        p.add(1).write_volatile(ret.tag.0);
        p.add(2).write_volatile(ret.w[0]);
        p.add(3).write_volatile(ret.w[1]);
        p.add(4).write_volatile(ret.w[2]);
        p.add(5).write_volatile(ret.w[3]);
        p.add(6).write_volatile(ret.r10);
    }
}
