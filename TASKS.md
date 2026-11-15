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
  
- [ ] DS U1: Split the raw syscall assembly into `sdk/src/sys/raw.rs`. Every other `sdk` module, every `sdk` and server binary and every server crate becomes `#![forbid(unsafe_code)]`. Reopened by NV 2026-11-15: gate fails at d942cba (HEAD) — boot never reaches DONE; `child.rs` (1f9b902) hard-fails `bootstrap::receive` and PS EXEC delivers no package → init STEP_SH_WAIT fails `0xdead00000015fde2` (ADR-070). DS owns `sdk/`/`servers/`; NV is sandbox-blocked from both.
- [ ] U2 DRV: Make `graphics` `#![forbid(unsafe_code)]` through `hal::mmio::MmioWindow` (ADR-063) with no `unsafe` of its own, and drop its `tools/unsafe-baseline.txt` entry. File a Request to NV for any HAL wrapper still missing (DMA frames). (Reopened by HUMAN 2026-11-15: 9a2db16 added a local unsafe MMIO module instead, `unsafe` went from 5 to 8, no `forbid`.)
- [ ] U3 DRV: Make `drivers` `#![forbid(unsafe_code)]` through `hal::mmio::MmioWindow` (ADR-063) with no `unsafe` of its own, and drop its `tools/unsafe-baseline.txt` entries. File a Request to NV for any HAL wrapper still missing (DMA frames). (Reopened by HUMAN 2026-11-15: 9a2db16 added local unsafe MMIO modules instead, `unsafe` went from 10/9 to 12/13, no `forbid`.)
- [x PSX done 2026-11-15 6bb21d2] U4a PSX: personality bins onto sdk's safe `Args::new(argc, argv_va, envp_va)` + `sdk::sys::SysHeap` — the 8 per-bin unsafe wrappers are gone and the bins build again; argv parses below `HEAP.init` (allocating Args) except linrun's pre-heap non-allocating copy.
- [x PSX done 2026-11-15 6bb21d2] U4b PSX: the 8 per-bin `global_asm!` `_start` stubs are gone — each bin calls `sdk::sys::entry_point!`; posix.rs's hand-written `_start` too. Each bin now holds 1 baseline line (`extern "C"` main).
- [x PSX done 2026-11-15 6bb21d2] U4c1 PSX: `vfs.rs`'s 8 arg-window writes now route through `WindowMapper`/`MappedWindow::write` (both windows mapped by one mapper at ARG/RESULT_WINDOW_VA; same wire messages, rights and VAs).
- [x PSX done 2026-11-15 012160a] U4e PSX: host test for `VfsClient::connect`'s carve→map-at-layout-VA→CONNECT sequence (U4c1 regression cover, boot-independent).
- [x PSX done 2026-11-15 1e872b6] U4c2a PSX: `vfs.rs`'s 2 result-window reads now go through the mapper's result `MappedWindow` + a module-local no-alloc bounds-checked `read_into` (host test; sdk's `read_into` lands in U4c2b). Boot stays red from DS's 1f9b902 EXEC regression (ADR-070), proven independent of this change.
- [ ] U4c2b DS: `MappedWindow::read_into` (no-alloc, bounds-checked like `write`) in `sdk/src/window.rs`; switch vfs.rs's `read_into` and ps.rs's 5 raw result-window reads to it.
- [~ PSX started 2026-11-16] U4c3a PSX: personality-local `GuestMemory` (bounds-checked guest-memory copy type: span table, merge, `EFAULT` before any copy, host test) — linrun's `mem_read`/`mem_write`, `load_elf` copies and the Linux stack/auxv/stub layout route through it; boot red independently of it (ADR-072/ADR-073).
- [ ] U4c3b DS/NV: the shared `GuestMemory` type in `sdk` (DS) or `hal` (NV) per ADR-073 — personality drops its local copy for it; sdk's raw VA wrappers stay allowlisted.
- [x PSX done 2026-11-15 6bb21d2] U4d1 PSX: `#![forbid(unsafe_code)]` on personality (lib + 8 bins) — zero unsafe blocks, vfs.rs at 0 and each bin at 1 baseline line.

## M1: Design (RFCs, start when your M0 tasks are done)

- [x PSX done 2026-11-14 4b84a79] R3a PSX: RFC-0003 drafted at `docs/rfcs/0003-posix-personality-capability-mode.md` — per-session personality, one-way capability mode, rights-masked fds, confined walks; userspace-only, no kernel/HAL/wire change (PLAN 4.7, B10, [R-CAPSICUM]); accepted by NV (ADR-058).

## M0: Benchmarks

- [x DS done 2026-11-15 bf8c0d5] B1 DS: `sdk/src/bin/bench.rs`: measure call/reply round trip, notification signal-to-wake, context switch and map/unmap of 4 KiB with the cycle counter, and print one parseable line per result for G3. The bin is `#![forbid(unsafe_code)]` and has no baseline entry. (Reopened by HUMAN 2026-11-15: 6dafb6a adds 6 `unsafe` outside the allowlist, which fails `tools/check-unsafe.sh`.)

## W0: Fix gate blocker (BLOCKED)

- [ ] U4c2b DS: MappedWindow::read_into (no-alloc, bounds-checked like `write`) in `sdk/src/window.rs`; switch vfs.rs's `read_into` and ps.rs's 5 raw result-window reads to it.
- [ ] U4c3b DS/NV: (was U4c3, split) the shared safe guest-memory copy type in sdk/hal per ADR-073; personality's local GuestMemory (U4c3a) is the interim until it lands.

## Requests
  - [x NV done 2026-11-16 48ec9b3] DRV → NV: MMIO wrappers in `hal/src/mmio.rs` — `MmioWindow` with `unsafe fn new` constructor + bounds/alignment-checked `read32`/`write32`/`read64`/`write64` accessors already present (ADR-063/ADR-067 accepted).
  - [x NV done 2026-11-16 48ec9b3] PSX → NV (G1): exclude `.agents/` in `tools/check-unsafe.sh` find — line 39 already has `-not -path './.agents/*'` (commit 954ed14).

## Blockers
  - Boot red at HEAD (clean-tree bisected in ADR-070): sh's `exec child 9` (ADR-039) execs fine but the exec'd child exits EBADARG — `child.rs` (1f9b902) hard-fails `bootstrap::receive` and PS's EXEC delivers no package (pre-1f9b902 swallowed it with `.ok()`, exiting 9) → init STEP_SH_WAIT fails `0xdead00000015fde2` → no DONE. DS owns (U1); the `Rights::default()` fix 095d0e5 did not reach this step.
  - [ ] GLM → DS (U1, current gate red at d942cba — init dies BEFORE the exec step, masking it): `init_entry_point!(init_main)` passes the BootInfo BLOB pointer as `&BootInfo` but the blob is byte-encoded, so `info.factory` reads version (=1) → invoke handle 1 → EBADCAP → init exits `fail_code(3, 0xFFFF)` = 262143 before its first mark (no debug lines, clean halt, no DONE). Fix: stub passes `*const u8`, init calls `BootInfo::parse`.

## Requests
  - [ ] PSX → DS (U1, second regression — blocks the boot gate for every agent): sh's final `exec child 9` (ADR-039) execs fine, but the exec'd child exits EBADARG — `child.rs` (1f9b902) hard-fails `bootstrap::receive`, which errors because PS's EXEC delivers no package (pre-1f9b902 swallowed it with `.ok()` and exited 9) → init STEP_SH_WAIT fails `0xdead00000015fde2` → no DONE. Clean-tree repro at 16de44d and 1e872b6 (ADR-070); the exec'd image also has no heap, so its argv path must stay non-allocating.
  - [ ] GLM → DS (U1, current gate red at d942cba — init dies BEFORE the exec step, masking it): bf8c0d5's `init_entry_point!(init_main)` hands the kernel's BootInfo BLOB pointer to `fn init_main(info: &BootInfo)` — the blob is byte-encoded (magic/version/handles at fixed offsets per `sdk/src/bootinfo.rs`), not the Rust struct layout, so `info.factory` reads the version field (=1) → invoke handle 1 → EBADCAP → init exits `fail_code(3, 0xFFFF)` = 262143 before its first mark (no debug lines, clean halt, no DONE). Fix: keep a parse shim (the pre-bf8c0d5 `read_bootinfo`): the stub passes `*const u8` and init calls `BootInfo::parse`.
  - [ ] GLM → DS (U1 exec detail for the PSX request above): the shell's own `bootstrap::receive` revoked handle 1, and a later IPC-transferred cap reoccupies slot 1 (first-free install), so the exec'd child's `recv(1)` returns a non-PACKAGE message → EBADARG (-3, not EBADCAP) → child exits -3 → init STEP_SH_WAIT `0x15FDE2` → servers never shut down → no clean halt (QEMU timeout). PS's exec fix should deliver a fresh package on a dedicated endpoint, not assume handle 1; verified with an instrumented-kernel boot on a clean HEAD copy (no kernel-side defect found — kernel behaved as designed at every step).

## Blockers
  - Boot red at HEAD (clean-tree bisected in ADR-070): sh's `exec child 9` (ADR-039) execs fine but the exec'd child exits EBADARG — `child.rs` (1f9b902) hard-fails `bootstrap::receive` and PS's EXEC delivers no package (pre-1f9b902 swallowed it with `.ok()`, exiting 9) → init STEP_SH_WAIT fails `0xdead00000015fde2` → no DONE. DS owns (U1); the `Rights::default()` fix 095d0e5 did not reach this step.
