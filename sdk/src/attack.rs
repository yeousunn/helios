//! S11 attack program core (Phase H).
//!
//! The `attack` program runs a list of *bad calls* — one per kernel security
//! fix in S1–S10 — and asserts the kernel rejects each with an error. A bad
//! call that is *not* rejected is a security regression, so the program exits
//! with a nonzero status identifying the offending case.
//!
//! The harness lives in the SDK library (not a standalone bin) so the runner
//! is generic over [`RawSyscalls`] and therefore host-testable with a mock
//! kernel. The userspace side is the `child` payload's `argv[0] == "attack"`
//! mode (`sdk/src/bin/child.rs`): init spawns it through the process server as
//! a new marker step, exactly like the other smoke programs.
//!
//! Case list policy: a case is added the moment its kernel S-task lands; until
//! then the bad call cannot be asserted (it would either succeed or, worse,
//! fault the machine). Case 0 is a harness self-test that holds on any kernel
//! and proves the runner detects a rejection correctly.

use crate::bootstrap::BootstrapPackage;
use crate::syscall::{RawSyscalls, Syscalls};
use ipc::{CapSlot, Message, Rights};

/// A kernel-window (higher-half) virtual address: canonical but `>= USER_ADDR_LIMIT`
/// (`0x0000_8000_0000_0000`), so it must never be accepted as a user PC/FS base (S2/S3).
const KERNEL_PC: u64 = 0xFFFF_8000_0000_0000;

/// A genuinely non-canonical virtual address (`bit 48` set, bits 63..=48 not all
/// equal to bit 47). It is far outside the user half, so `is_user_addr` rejects
/// it (S3). Distinct from [`KERNEL_PC`], which is canonical but kernel-only.
const NON_CANONICAL: u64 = 0x0001_0000_0000_0000;

/// A canonical user PC for the scratch thread case 3 creates. The thread is
/// suspended before it could run, and the PC is never entered — only the S2
/// address check matters.
const SCRATCH_PC: u64 = 0x401000;

/// Exit status base for a failure: `FAIL_BASE | (case_index + 1)`.
///
/// The low byte identifies the case (index 0 → `0x...01`); the prefix keeps
/// it clear of the numeric argv statuses (`42`, `9`) the other children use.
pub const FAIL_BASE: i32 = 0x0A77_0000;

/// Exit status reported when the bootstrap package itself cannot be received
/// (the harness never reached its cases).
pub const FAIL_NO_PACKAGE: i32 = FAIL_BASE | 0x100;

/// Run every case against the live kernel; return `0` if all bad calls were
/// rejected, else `FAIL_BASE | (index + 1)` for the first one that was not.
pub fn run<R: RawSyscalls>(sys: &mut Syscalls<R>, pkg: &BootstrapPackage) -> i32 {
    // Append one entry per S-task as it lands. Keep the order stable: the
    // index is part of the failure status.
    //
    // Still pending (no case yet): S6/S7 (CR4 supervisor bits and the kernel
    // syscall/exception flag mask are not observable from ring 3; a bad call
    // would fault, not return an error), S8 GRANT-check on THREAD_CREATE/
    // NEW_THREAD, S9 oversized UNMAP count. S1's REGS_* path is covered where
    // a child can reach it (case 1: the non-Frame cap rejection); the deeper
    // masking lives in kernel tests (ADR-050).
    let outcomes = [
        case_orphan_handle(sys),
        case_regs_write_non_frame_cap(sys, pkg),
        case_thread_create_kernel_pc(sys, pkg), // S2
        case_set_entry_kernel_pc(sys, pkg),     // S2
        case_set_tls_non_canonical(sys, pkg),   // S3
        case_map_kernel_window(sys, pkg),       // S4/S5
        case_unmap_kernel_window(sys, pkg),     // S4
        case_protect_kernel_window(sys, pkg),   // S4
        case_map_null(sys, pkg),                // S4
    ];
    classify(&outcomes)
}

/// Turn per-case outcomes into the exit status. Pure and host-tested.
pub fn classify(outcomes: &[bool]) -> i32 {
    for (i, &rejected) in outcomes.iter().enumerate() {
        if !rejected {
            return FAIL_BASE | (i as i32 + 1);
        }
    }
    0
}

/// A handle the process does not hold must be rejected. Case 0.
fn case_orphan_handle<R: RawSyscalls>(sys: &mut Syscalls<R>) -> bool {
    sys.invoke(u32::MAX, &Message::new(crate::methods::thread::REGS_READ))
        .is_err()
}

/// `REGS_WRITE` requires a `Frame` cap in `caps[0]` (ADR-050 §6). Passing the
/// address-space cap — which is never a `Frame` — must be rejected, and must
/// not touch any register image. Case 1 (the S1 path a child can reach: it
/// holds no Frame cap).
fn case_regs_write_non_frame_cap<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    pkg: &BootstrapPackage,
) -> bool {
    let mut m = Message::new(crate::methods::thread::REGS_WRITE);
    m.tag = m.tag.with_caps(1);
    let _ = m.set_descriptor(0, CapSlot::pack(pkg.aspace, Rights::READ));
    sys.invoke(pkg.thread, &m).is_err()
}

/// `THREAD_CREATE` with a kernel-window entry PC must be rejected before any
/// thread is created (S2). Pre-fix the call returned OK and the new thread
/// entered ring 3 at a kernel address. Case 2.
fn case_thread_create_kernel_pc<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    pkg: &BootstrapPackage,
) -> bool {
    let mut m = Message::new(crate::methods::thread::THREAD_CREATE);
    m.words[0] = KERNEL_PC;
    sys.invoke(pkg.thread, &m).is_err()
}

/// `SET_ENTRY` with a kernel-window PC must be rejected (S2). Case 3.
///
/// `SET_ENTRY` only accepts a Suspended/Blocked target, so the case first
/// creates a scratch thread and suspends it (it never runs: no yield happens
/// between the create and the suspend, and the thread is off the run queue
/// once suspended). Overwriting its entry with a kernel-window PC pre-fix
/// returned OK and pointed a user thread at the shared kernel window;
/// post-fix it is EBADARG. The scratch thread's cap is revoked afterwards.
fn case_set_entry_kernel_pc<R: RawSyscalls>(sys: &mut Syscalls<R>, pkg: &BootstrapPackage) -> bool {
    let mut create = Message::new(crate::methods::thread::THREAD_CREATE);
    create.words[0] = SCRATCH_PC;
    let Ok(reply) = sys.invoke(pkg.thread, &create) else {
        return false;
    };
    let scratch = reply.words[0] as u32;
    if sys
        .invoke(scratch, &Message::new(crate::methods::thread::SUSPEND))
        .is_err()
    {
        return false;
    }
    let mut set = Message::new(crate::methods::thread::SET_ENTRY);
    set.words[0] = KERNEL_PC;
    let rejected = sys.invoke(scratch, &set).is_err();
    // Kill the scratch thread (a suspended thread is otherwise never reaped,
    // which would leak a live thread and stop the boot from reaching its clean
    // halt), then drop its cap.
    let _ = sys.invoke(scratch, &Message::new(crate::methods::thread::KILL));
    let _ = sys.cap_revoke(scratch, 1);
    rejected
}

/// `SET_TLS` with a non-canonical FS base must be rejected (S3). Pre-fix the
/// base was stored and faulted in ring 0 at the next arch switch (a machine
/// halt); post-fix EBADARG. The running caller is the target, so the check is
/// side-effect-free. Case 4.
fn case_set_tls_non_canonical<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    pkg: &BootstrapPackage,
) -> bool {
    let mut m = Message::new(crate::methods::thread::SET_TLS);
    m.words[0] = NON_CANONICAL;
    sys.invoke(pkg.thread, &m).is_err()
}

/// `AS::MAP` of a kernel-window VA must be rejected (S4) before any frame is
/// allocated, and must never create a user-writable entry over the shared
/// kernel window (S5, `walk_create`). The `ANON` flag makes the call reach the
/// range check without a `Frame` cap, which the attack child does not hold.
/// Pre-fix this mapped a user page into PML4[511]. Case 5.
fn case_map_kernel_window<R: RawSyscalls>(sys: &mut Syscalls<R>, pkg: &BootstrapPackage) -> bool {
    use crate::methods::map_flags;
    let mut m = Message::new(crate::methods::aspace::MAP);
    m.words[0] = KERNEL_PC;
    m.words[1] = u64::from(map_flags::R | map_flags::W | map_flags::ANON);
    sys.invoke(pkg.aspace, &m).is_err()
}

/// `AS::UNMAP` of a kernel-window VA must be rejected (S4): the range walk
/// must never touch the shared kernel window. Uses a legal page count so only
/// the address is at fault. Case 6.
fn case_unmap_kernel_window<R: RawSyscalls>(sys: &mut Syscalls<R>, pkg: &BootstrapPackage) -> bool {
    let mut m = Message::new(crate::methods::aspace::UNMAP);
    m.words[0] = KERNEL_PC;
    m.words[1] = 1;
    sys.invoke(pkg.aspace, &m).is_err()
}

/// `AS::PROTECT` of a kernel-window VA must be rejected (S4): PROTECT must not
/// reflag a kernel page. Case 7.
fn case_protect_kernel_window<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    pkg: &BootstrapPackage,
) -> bool {
    use crate::methods::map_flags;
    let mut m = Message::new(crate::methods::aspace::PROTECT);
    m.words[0] = KERNEL_PC;
    m.words[2] = u64::from(map_flags::R);
    sys.invoke(pkg.aspace, &m).is_err()
}

/// `AS::MAP` at VA 0 must be rejected (S4): the null page is never mappable.
/// Case 8.
fn case_map_null<R: RawSyscalls>(sys: &mut Syscalls<R>, pkg: &BootstrapPackage) -> bool {
    use crate::methods::map_flags;
    let mut m = Message::new(crate::methods::aspace::MAP);
    m.words[0] = 0;
    m.words[1] = u64::from(map_flags::R | map_flags::W | map_flags::ANON);
    sys.invoke(pkg.aspace, &m).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SysReply;

    /// Replays one status per raw syscall, in order. The cases make a fixed
    /// number of raw calls (case 3 creates, suspends, sets the entry and
    /// revokes; the rest make one); the mock replays the matching statuses.
    struct MockKernel {
        statuses: [i32; 13],
        len: usize,
        i: usize,
    }

    impl MockKernel {
        /// A kernel that rejects each bad call with the error the case names.
        ///
        /// Index: 0 orphan, 1 non-Frame, 2 THREAD_CREATE(kernel pc),
        /// 3 THREAD_CREATE(valid), 4 SUSPEND, 5 SET_ENTRY(kernel pc),
        /// 6 KILL, 7 cap_revoke, 8 SET_TLS, 9 MAP(kernel window),
        /// 10 UNMAP(kernel window), 11 PROTECT(kernel window), 12 MAP(null).
        fn rejects() -> Self {
            use ipc::status::{EBADARG, EBADCAP, OK};
            MockKernel {
                statuses: [
                    EBADCAP, EBADARG, EBADARG, OK, OK, EBADARG, OK, OK, EBADARG, EBADARG, EBADARG,
                    EBADARG, EBADARG,
                ],
                len: 13,
                i: 0,
            }
        }

        /// A kernel that accepts every bad call (a security regression).
        fn accepts() -> Self {
            MockKernel {
                statuses: [ipc::status::OK; 13],
                len: 13,
                i: 0,
            }
        }
    }

    impl RawSyscalls for MockKernel {
        fn raw(&mut self, _number: u32, _args: [u64; 6]) -> SysReply {
            let status = if self.i < self.len {
                self.statuses[self.i]
            } else {
                ipc::status::OK
            };
            self.i += 1;
            // words[0] = 1: the scratch-thread handle case 3 receives.
            SysReply {
                status,
                tag: 0,
                words: [1, 0, 0, 0],
            }
        }
    }

    fn pkg() -> BootstrapPackage {
        BootstrapPackage {
            aspace: 10,
            thread: 11,
            region: 12,
            session_notifications: [13, 14, 15, 16],
            process_server_ep: 17,
            pid: 5,
            optional: [None; 4],
        }
    }

    #[test]
    fn all_rejected_passes() {
        let mut k = MockKernel::rejects();
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), 0);
    }

    #[test]
    fn accepted_bad_call_is_a_failure() {
        let mut k = MockKernel::accepts();
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 1);
    }

    #[test]
    fn accepted_thread_create_kernel_pc_is_case_3() {
        // Kernel accepts THREAD_CREATE(kernel pc) at index 2; cases 0/1 still
        // reject → first non-rejected case is index 2.
        let mut k = MockKernel::rejects();
        k.statuses[2] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 3);
    }

    #[test]
    fn accepted_set_entry_kernel_pc_is_case_4() {
        // Kernel accepts SET_ENTRY(kernel pc) at index 5 (case 3) while all
        // earlier cases reject → failure at case index 3.
        let mut k = MockKernel::rejects();
        k.statuses[5] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 4);
    }

    #[test]
    fn accepted_set_tls_is_case_5() {
        // Kernel accepts SET_TLS(non-canonical) at index 8 (case 4).
        let mut k = MockKernel::rejects();
        k.statuses[8] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 5);
    }

    #[test]
    fn accepted_map_kernel_window_is_case_6() {
        // Kernel accepts MAP(kernel window) at index 9 (case 5).
        let mut k = MockKernel::rejects();
        k.statuses[9] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 6);
    }

    #[test]
    fn accepted_unmap_kernel_window_is_case_7() {
        // Kernel accepts UNMAP(kernel window) at index 10 (case 6).
        let mut k = MockKernel::rejects();
        k.statuses[10] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 7);
    }

    #[test]
    fn accepted_protect_kernel_window_is_case_8() {
        // Kernel accepts PROTECT(kernel window) at index 11 (case 7).
        let mut k = MockKernel::rejects();
        k.statuses[11] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 8);
    }

    #[test]
    fn accepted_map_null_is_case_9() {
        // Kernel accepts MAP(null) at index 12 (case 8).
        let mut k = MockKernel::rejects();
        k.statuses[12] = ipc::status::OK;
        let mut sys = Syscalls::new(&mut k);
        assert_eq!(run(&mut sys, &pkg()), FAIL_BASE | 9);
    }

    #[test]
    fn classify_encodes_the_case_index() {
        assert_eq!(classify(&[]), 0);
        assert_eq!(classify(&[true, true]), 0);
        assert_eq!(classify(&[true, false, true]), FAIL_BASE | 2);
        assert_eq!(classify(&[false, false]), FAIL_BASE | 1);
    }
}
