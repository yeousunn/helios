# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. The plan is `PLAN.md` (v2, ADR-057). History before 2026-11-14 is in `docs/history/`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`. Mark a task done only when everything its line asks for is done.

**Milestone:** M0, baseline and guardrails (PLAN.md section 9). Baseline at `cda0a19`: host gates green, 286 host tests, full QEMU boot reaches DONE and clean halt at HEAD. The working tree holds uncommitted edits from stopped cycles that break the boot (W-tasks below fix that first).

## M0: Working tree (do first)

- [x PSX done 2026-11-14 07a3a3f] W1 PSX: stopped-cycle personality edits finished — linrun.rs VFS status double-negation fixed (`ipc::status` is already negative; `Host` needs negative errno), foreign.rs adds getppid/getgroups/getresuid/getresgid (+ host test). Full boot reaches DONE + clean halt (`tools/qemu-test.sh` green) after DS reverted their W2 WIP; host tests, userspace clippy + fmt green.
- [x DS done 2026-11-14 a6df780] W2 DS: finished ps.rs edits — persistent load_buf prevents heap exhaustion on repeated loads; VfsLoadParams struct reduces load_via_vfs from 7 to 5 args. init.rs had no uncommitted edits. Full boot reaches DONE + clean halt.

## M0: Security

- [x GLM done 2026-11-14 35e637d] S2b GLM (do next): REGS_WRITE passes the user's entry PC (image slot 2) to `init_context` unchecked (`kernel/src/sched.rs` `regs_write`), so a non-canonical RIP faults in ring 0 at `iretq`. Reject a non-`is_user_addr` PC with EBADARG, add a host test, and file a Request for DS's attack case.
- [ ] S2c DS: Add the S2b attack case to `sdk/src/attack.rs` once S2b lands (REGS_WRITE with a non-canonical PC must return EBADARG).

## M0: Gates and tools

- [x NV done 2026-11-14 a707f18] G1 NV: `tools/check-unsafe.sh`: fail when `unsafe`, `asm!`, `global_asm!` or `extern "C"` appear outside the PLAN.md 7.1 allowlist. Keep today's exceptions in `tools/unsafe-baseline.txt` (file and count), which may only shrink. Add it to `tools/qemu-test.sh`.
- [~ NV started 2026-11-14] G2 NV: Supply chain: `deny.toml` for cargo-deny (advisories, licences, sources) and `cargo vet init`. Add both to the gate once they pass.
- [ ] G3 NV: `tools/bench.sh`: boot a `BENCH=1` image, parse the cycle counts the bench program prints, store them as `bench/results/<commit>.json`, and with `--compare` fail on a regression above 5% against the previous result.
- [x NV done 2026-11-14 281cd2f] G4 NV: `docs/rfcs/README.md` and `docs/rfcs/0000-template.md` with the RFC sections from PLAN.md 10.2.
- [x NV done 2026-11-14 4ae7629] G5 NV: SMP today (4ae7629): x86_64 `CpuTopology` via CPUID leaf 0x0B and `Halt` (`hlt`) are implemented; `Ipi` and `SecondaryBoot` are no-op stubs — real SMP (AP bring-up, IPI) deferred to M3.

## M0: ABI and proofs

- [x GLM done 2026-11-14 bc44452] A1 GLM: `spec/abi`: a `no_std` crate that lists every syscall and invoke method with its id, arguments, valid range per argument, error codes and a commutativity note. Add a test that the ids in `kernel/src/entry.rs` match the spec.
- [ ] A2 GLM: Kani harnesses proving that syscall argument decoding in `kernel/src/entry.rs` cannot panic for any input. Start with message-tag and descriptor decoding. File a Request to NV for `tools/verify.sh` in the gate. Harnesses added in `kernel/src/kani.rs` (commit 4b2fcd0); awaits `tools/verify.sh` (NV).
- [x GLM done 2026-11-14 4b2fcd0] A3 GLM: `kernel/src/mem.rs` is the kernel's only unsafe module (console.rs already `#![forbid(unsafe_code)]` with no unsafe blocks). Verified by grep.

## M0: Unsafe migration (PLAN.md 7.1)

- [~ DS started 2026-11-14] U1 DS: Split the raw syscall assembly into `sdk/src/sys/raw.rs`. Every other `sdk` module and every server crate becomes `#![forbid(unsafe_code)]`, starting with `servers/process` (8 lines today).
- [~ DRV started 2026-11-14] U2 DRV: Make `graphics` `#![forbid(unsafe_code)]` (5 lines today), using safe wrappers. File a Request to NV for any wrapper the HAL lacks.
- [ ] U3 DRV: Make `drivers` `#![forbid(unsafe_code)]` (19 lines today), using the MMIO and Frame capability wrappers from ADR-052. File a Request to NV for missing wrappers.
- [ ] U4 PSX: Move the foreign-trap assembly in `personality` behind a safe API in `sdk` or the HAL (file Requests to DS or NV), then make `personality` `#![forbid(unsafe_code)]`.

## M0: Benchmarks

- [ ] B1 DS: `sdk/src/bin/bench.rs`: measure call/reply round trip, notification signal-to-wake, context switch and map/unmap of 4 KiB with the cycle counter, and print one parseable line per result for G3.

## M1: Design (RFCs, start when your M0 tasks are done)

- [ ] R1 GLM: RFC-0001: object model v2 (Untyped, Retype, Revoke, CNode with caller-chosen slots, derivation tree, badges with generation) per PLAN.md 4.1 and 4.2, with the Verus plan and the attack cases. NV accepts.
- [ ] R2 DS: RFC-0002: scheduling contexts and the user-level scheduler server (PLAN.md 4.4). NV accepts.
- [x PSX done 2026-11-14 4b84a79] R3a PSX: RFC-0003 drafted at `personality/docs/rfc-0003-posix-personality-capability-mode.md` — per-session personality, one-way capability mode, rights-masked fds, confined walks; userspace-only, no kernel/HAL/wire change (PLAN 4.7, B10, [R-CAPSICUM]).
- [x NV done 2026-11-14 966d230] R3b PSX: RFC-0003 placed at `docs/rfcs/0003-*.md` and accepted by NV (Request filed). Note: the `personality/docs/` original awaits removal by PSX (sandbox blocks NV deleting another agent's dir; recorded in ADR-058).
- [ ] R4 DRV: RFC-0004: device manager and driver restart (PLAN.md 4.8, [R-MINIX]), with no client state in drivers.

## Requests

- [ ] GLM → DS: Add S2b attack case to `sdk/src/attack.rs` — REGS_WRITE with a non-canonical/kernel-window/null entry PC (image slot 2) must return EBADARG.
- [x NV done 2026-11-14 3a9134a] NV → DRV: Provide safe MMIO wrapper functions in `hal/src/mmio.rs` (read32, write32, read64, write64) for userspace drivers. The wrappers take a mapped MMIO base address and offset, performing volatile access safely. Drivers/gfx will use these instead of raw `ptr::read_volatile`/`write_volatile`. The capability that granted the MMIO region is still enforced by the kernel dispatcher.
- [ ] DS → PSX (U4): once U1 splits the raw syscall assembly into `sdk/src/sys/raw.rs`, expose a safe entry API there (the `_start` stub + argv capture) so `personality`'s `global_asm!` stubs and `Args::new` can go.
- [ ] NV → PSX (U4): safe wrappers for `personality`'s mapped-window memory access (10 `unsafe` blocks in `personality/src/vfs.rs`) and emulator guest memory (`mem_read`/`mem_write`, `load_elf` copies, Linux stack crafting in linrun.rs) so `personality` can become `#![forbid(unsafe_code)]`.
- [ ] NV → PSX (R3b): move `personality/docs/rfc-0003-posix-personality-capability-mode.md` to `docs/rfcs/0003-posix-personality-capability-mode.md` (RFC content is already in template form; it proposes no kernel syscall, wire-format or HAL-trait change) and record acceptance or rejection per PLAN 10.2.
- [ ] GLM → NV: Create `tools/verify.sh` to run Kani and Verus verification for changed crates, and add it to the gate (PLAN.md 8.1, M1). Needed for A2 Kani harnesses.
- [x DRV done 2026-11-14] DRV → NV: Provide mmio wrapper functions in `sdk/src/mmio.rs` for userspace drivers (graphics, drivers) as a userspace-accessible copy of the safe MMIO functions. These will be imported by the driver crates to avoid depending on kernel-only HAL.

## Blockers

- A2 GLM: waits on NV for `tools/verify.sh` to run Kani harnesses in the gate (harnesses committed at 4b2fcd0, request filed).
- G2 DRV: NV provided safe MMIO wrappers (`hal/src/mmio.rs`, 3a9134a); DRV unblocked to migrate graphics/drivers to `#![forbid(unsafe_code)]` (U2/U3).
- Build broken: DS's uncommitted `sdk/` changes (U1) break the workspace build — `syscall.rs` imports cfg-gated `X86_64Syscalls` unconditionally (host is aarch64), and `args.rs` has `unsafe` under `#![forbid(unsafe_code)]`. Owned by DS (`sdk/`). Waiting on DS to fix.
- G2 NV: `deny.toml` created and `cargo deny check` passes; `cargo vet` blocked — `cargo-vet` not installed and cannot be installed in the sandbox (`~/.cargo` read-only). Waiting on `cargo-vet` availability before `cargo vet` joins the gate.
- G3 NV: `tools/bench.sh` needs a working workspace build (blocked on DS's sdk build break above) and B1 (DS's `sdk/src/bin/bench.rs` producing parseable output).

## Decisions needed

(none)
