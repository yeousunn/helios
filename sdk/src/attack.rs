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
//! fault the machine). The two cases below are *harness self-tests* that hold
//! on the current kernel and prove the runner detects rejection correctly.

use crate::bootstrap::BootstrapPackage;
use crate::syscall::{RawSyscalls, Syscalls};
use ipc::{CapSlot, Message, Rights};

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
    let outcomes = [
        case_orphan_handle(sys),
        case_regs_write_non_frame_cap(sys, pkg),
        // S1  REGS_WRITE must not write the target's kernel stack.
        // S2  SET_ENTRY / THREAD_CREATE / NEW_THREAD must reject a bad PC/SP.
        // S3  SET_TLS must reject a non-canonical FS base.
        // S4  MAP / UNMAP / PROTECT must reject a kernel-window range.
        // S8  THREAD_CREATE / NEW_THREAD must not skip the GRANT check.
        // S9  UNMAP must reject an oversized page count.
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
/// not touch any register image. Case 1.
fn case_regs_write_non_frame_cap<R: RawSyscalls>(
    sys: &mut Syscalls<R>,
    pkg: &BootstrapPackage,
) -> bool {
    let mut m = Message::new(crate::methods::thread::REGS_WRITE);
    m.tag = m.tag.with_caps(1);
    let _ = m.set_descriptor(0, CapSlot::pack(pkg.aspace, Rights::READ));
    sys.invoke(pkg.thread, &m).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SysReply;

    /// Replays one status per raw syscall, in order. The two current cases
    /// each make exactly one invoke, so the replies are programed per case.
    struct MockKernel {
        statuses: [i32; 4],
        len: usize,
        i: usize,
    }

    impl MockKernel {
        /// A kernel that rejects each bad call with the error the case names.
        fn rejects() -> Self {
            MockKernel {
                statuses: [ipc::status::EBADCAP, ipc::status::EBADARG, 0, 0],
                len: 2,
                i: 0,
            }
        }

        /// A kernel that accepts every bad call (a security regression).
        fn accepts() -> Self {
            MockKernel {
                statuses: [ipc::status::OK; 4],
                len: 2,
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
            SysReply {
                status,
                tag: 0,
                words: [0; 4],
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
    fn classify_encodes_the_case_index() {
        assert_eq!(classify(&[]), 0);
        assert_eq!(classify(&[true, true]), 0);
        assert_eq!(classify(&[true, false, true]), FAIL_BASE | 2);
        assert_eq!(classify(&[false, false]), FAIL_BASE | 1);
    }
}
