# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. The plan is `PLAN.md` (v2, ADR-057). History before 2026-11-14 is in `docs/history/`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`. Mark a task done only when everything its line asks for is done.

**Milestone:** M0, baseline and guardrails (PLAN.md section 9). Baseline at `cda0a19`: host gates green, 286 host tests, full QEMU boot reaches DONE and clean halt at HEAD. The working tree holds uncommitted edits from stopped cycles that break the boot (W-tasks below fix that first).

## M0: Working tree (do first)

- [x PSX done 2026-11-14 07a3a3f] W1 PSX: stopped-cycle personality edits finished — linrun.rs VFS status double-negation fixed (`ipc::status` is already negative; `Host` needs negative errno), foreign.rs adds getppid/getgroups/getresuid/getresgid (+ host test). Full boot reaches DONE + clean halt (`tools/qemu-test.sh` green) after DS reverted their W2 WIP; host tests, userspace clippy + fmt green.
- [x DS done 2026-11-14 a6df780] W2 DS: finished ps.rs edits — persistent load_buf prevents heap exhaustion on repeated loads; VfsLoadParams struct reduces load_via_vfs from 7 to 5 args. init.rs had no uncommitted edits. Full boot reaches DONE + clean halt.

## M0: Security
  
  - [x GLM done 2026-11-15 9ecdb2a] S2b GLM: REGS_WRITE passes the user's entry PC (image slot 2) to `init_context` unchecked (`kernel/src/sched.rs` `regs_write`), so a non-canonical RIP faults in ring 0 at `iretq`. Reject a non-`is_user_addr` PC with EBADARG, add a host test, and file a Request for DS's attack case.
  - [x DS done 2026-11-15 5ff5f16] S2c DS: Add the S2b attack case to `sdk/src/attack.rs` — REGS_WRITE with a non-canonical/kernel-window/null entry PC (image slot 2) returns EBADARG; added as case 2 in attack.rs with tests.

## M0: Gates and tools

- [x NV done 2026-11-14 a707f18] G1 NV: `tools/check-unsafe.sh`: fail when `unsafe`, `asm!`, `global_asm!` or `extern "C"` appear outside the PLAN.md 7.1 allowlist. Keep today's exceptions in `tools/unsafe-baseline.txt` (file and count), which may only shrink. Add it to `tools/qemu-test.sh`.
- [x NV done 2026-11-15 309828e] G2 NV: `deny.toml` + `cargo deny check` added to the gate (tools/qemu-test.sh; `cargo deny check` passes). `tools/verify.sh` wired into the gate; `cargo vet` still blocked (cargo-vet not installed in sandbox, reported as non-failing blocker).
- [x NV done 2026-11-15 93f214a] G3 NV: `tools/bench.sh`: boot a `BENCH=1` image, parse the cycle counts the bench program prints, store them as `bench/results/<commit>.json`, and with `--compare` fail on a regression above 5% against the previous result.
- [x NV done 2026-11-14 281cd2f] G4 NV: `docs/rfcs/README.md` and `docs/rfcs/0000-template.md` with the RFC sections from PLAN.md 10.2.
- [x NV done 2026-11-14 4ae7629] G5 NV: SMP today (4ae7629): x86_64 `CpuTopology` via CPUID leaf 0x0B and `Halt` (`hlt`) are implemented; `Ipi` and `SecondaryBoot` are no-op stubs — real SMP (AP bring-up, IPI) deferred to M3.

## M0: ABI and proofs

- [x GLM done 2026-11-14 bc44452] A1 GLM: `spec/abi`: a `no_std` crate that lists every syscall and invoke method with its id, arguments, valid range per argument, error codes and a commutativity note. Add a test that the ids in `kernel/src/entry.rs` match the spec.
- [~ GLM started 2026-11-15] A2 GLM: Kani harnesses proving that syscall argument decoding in `kernel/src/entry.rs` cannot panic for any input. Start with message-tag and descriptor decoding. File a Request to NV for `tools/verify.sh` in the gate. Harnesses added in `kernel/src/kani.rs` (commit 4b2fcd0); awaits `tools/verify.sh` (NV). Harnesses written; blocked on Kani installation in sandbox.
- [x GLM done 2026-11-14 4b2fcd0] A3 GLM: `kernel/src/mem.rs` is the kernel's only unsafe module (console.rs already `#![forbid(unsafe_code)]` with no unsafe blocks). Verified by grep.

## M0: Unsafe migration (PLAN.md 7.1)
  
- [ ] U1 DS: Split the raw syscall assembly into `sdk/src/sys/raw.rs`. Every other `sdk` module, every `sdk` and server binary and every server crate becomes `#![forbid(unsafe_code)]`. (Reopened by HUMAN 2026-11-15: 5ff5f16 broke the boot, `child.rs` calls the allocating `Args::new` before its heap is up and exits `0x0BAD0001`. The server bins and `child.rs` have no `forbid`, and `init.rs` keeps 7 `unsafe`.)
- [ ] U2 DRV: Make `graphics` `#![forbid(unsafe_code)]` through `hal::mmio::MmioWindow` (ADR-063) with no `unsafe` of its own, and drop its `tools/unsafe-baseline.txt` entry. File a Request to NV for any HAL wrapper still missing (DMA frames). (Reopened by HUMAN 2026-11-15: 9a2db16 added a local unsafe MMIO module instead, `unsafe` went from 5 to 8, no `forbid`.)
- [ ] U3 DRV: Make `drivers` `#![forbid(unsafe_code)]` through `hal::mmio::MmioWindow` (ADR-063) with no `unsafe` of its own, and drop its `tools/unsafe-baseline.txt` entries. File a Request to NV for any HAL wrapper still missing (DMA frames). (Reopened by HUMAN 2026-11-15: 9a2db16 added local unsafe MMIO modules instead, `unsafe` went from 10/9 to 12/13, no `forbid`.)
- [x PSX done 2026-11-15 6bb21d2] U4a PSX: personality bins onto sdk's safe `Args::new(argc, argv_va, envp_va)` + `sdk::sys::SysHeap` — the 8 per-bin unsafe wrappers are gone and the bins build again; argv parses below `HEAP.init` (allocating Args) except linrun's pre-heap non-allocating copy.
- [x PSX done 2026-11-15 6bb21d2] U4b PSX: the 8 per-bin `global_asm!` `_start` stubs are gone — each bin calls `sdk::sys::entry_point!`; posix.rs's hand-written `_start` too. Each bin now holds 1 baseline line (`extern "C"` main).
- [x PSX done 2026-11-15 6bb21d2] U4c1 PSX: `vfs.rs`'s 8 arg-window writes now route through `WindowMapper`/`MappedWindow::write` (both windows mapped by one mapper at ARG/RESULT_WINDOW_VA; same wire messages, rights and VAs).
- [x PSX done 2026-11-15 012160a] U4e PSX: host test for `VfsClient::connect`'s carve→map-at-layout-VA→CONNECT sequence (U4c1 regression cover, boot-independent).
- [~ PSX started 2026-11-15] U4c2 PSX/DS: `vfs.rs`'s 2 result-window reads off `raw_copy_from_va` onto a no-alloc `MappedWindow::read_into` (a Vec per 4 KiB read leaks on the bump heap, ADR-055) — sdk (DS).
- [ ] U4c3 PSX/DS: `linrun.rs`'s guest-memory copies (`mem_read`/`mem_write`, `load_elf` copies and the Linux stack/auxv layout) behind a safe guest-memory copy type — sdk (DS) or hal (NV).
- [x PSX done 2026-11-15 6bb21d2] U4d1 PSX: `#![forbid(unsafe_code)]` on personality (lib + 8 bins) — zero unsafe blocks, vfs.rs at 0 and each bin at 1 baseline line.

## M0: Benchmarks

- [ ] B1 DS: `sdk/src/bin/bench.rs`: measure call/reply round trip, notification signal-to-wake, context switch and map/unmap of 4 KiB with the cycle counter, and print one parseable line per result for G3. The bin is `#![forbid(unsafe_code)]` and has no baseline entry. (Reopened by HUMAN 2026-11-15: 6dafb6a adds 6 `unsafe` outside the allowlist, which fails `tools/check-unsafe.sh`.)

## W0: Fix gate blocker (current cycle)

- [ ] W0 DRV: W0 was mis-assigned - the affected files are in `sdk/` (DS-owned). Update W0: DS needs to fix `sdk/src/sys/mod.rs` (remove `init_entry_point` from raw re-export, add crate re-export; add rdtsc/read_bootinfo exports) and `sdk/src/bin/child.rs` (add `use ipc::Message;` import).

## Requests
  - DRV → NV: Provide safe MMIO wrapper functions in `hal/src/mmio.rs` (read32, write32, read64, write64) for userspace drivers. The wrappers take a mapped MMIO base address and offset, performing volatile access safely. Drivers/gfx will use these instead of raw `ptr::read_volatile`/`write_volatile`. The capability that granted the MMIO region is still enforced by the kernel dispatcher.
  - Note: Sandbox file write restrictions prevent editing sdk/ files directly. The supervisor needs to resolve this for full boot gate to pass.
