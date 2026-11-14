# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. The plan is `PLAN.md` (v2, ADR-057). History before 2026-11-14 is in `docs/history/`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`. Mark a task done only when everything its line asks for is done.

**Milestone:** M0, baseline and guardrails (PLAN.md section 9). Baseline at `cda0a19`: host gates green, 286 host tests, full QEMU boot reaches DONE and clean halt at HEAD. The working tree holds uncommitted edits from stopped cycles that break the boot (W-tasks below fix that first).

## M0: Working tree (do first)

- [x PSX done 2026-11-14 07a3a3f] W1 PSX: stopped-cycle personality edits finished — linrun.rs VFS status double-negation fixed (`ipc::status` is already negative; `Host` needs negative errno), foreign.rs adds getppid/getgroups/getresuid/getresgid (+ host test). Full boot reaches DONE + clean halt (`tools/qemu-test.sh` green) after DS reverted their W2 WIP; host tests, userspace clippy + fmt green.
- [~ DS started 2026-11-14] W2 DS (do next): Finish or revert the uncommitted edits in `sdk/src/bin/init.rs` and `servers/process/src/bin/ps.rs`, and fix `load_via_vfs` taking 8 arguments (clippy). The full boot must reach DONE again.

## M0: Security

- [x GLM done 2026-11-14 35e637d] S2b GLM (do next): REGS_WRITE passes the user's entry PC (image slot 2) to `init_context` unchecked (`kernel/src/sched.rs` `regs_write`), so a non-canonical RIP faults in ring 0 at `iretq`. Reject a non-`is_user_addr` PC with EBADARG, add a host test, and file a Request for DS's attack case.
- [ ] S2c DS: Add the S2b attack case to `sdk/src/attack.rs` once S2b lands (REGS_WRITE with a non-canonical PC must return EBADARG).

## M0: Gates and tools

- [x NV done 2026-11-14 a707f18] G1 NV: `tools/check-unsafe.sh`: fail when `unsafe`, `asm!`, `global_asm!` or `extern "C"` appear outside the PLAN.md 7.1 allowlist. Keep today's exceptions in `tools/unsafe-baseline.txt` (file and count), which may only shrink. Add it to `tools/qemu-test.sh`.
- [ ] G2 NV: Supply chain: `deny.toml` for cargo-deny (advisories, licences, sources) and `cargo vet init`. Add both to the gate once they pass.
- [ ] G3 NV: `tools/bench.sh`: boot a `BENCH=1` image, parse the cycle counts the bench program prints, store them as `bench/results/<commit>.json`, and with `--compare` fail on a regression above 5% against the previous result.
- [x NV done 2026-11-14 281cd2f] G4 NV: `docs/rfcs/README.md` and `docs/rfcs/0000-template.md` with the RFC sections from PLAN.md 10.2.
- [x NV done 2026-11-14 4ae7629] G5 NV: SMP today (4ae7629): x86_64 `CpuTopology` via CPUID leaf 0x0B and `Halt` (`hlt`) are implemented; `Ipi` and `SecondaryBoot` are no-op stubs — real SMP (AP bring-up, IPI) deferred to M3.

## M0: ABI and proofs

- [x GLM done 2026-11-14 bc44452] A1 GLM: `spec/abi`: a `no_std` crate that lists every syscall and invoke method with its id, arguments, valid range per argument, error codes and a commutativity note. Add a test that the ids in `kernel/src/entry.rs` match the spec.
- [ ] A2 GLM: Kani harnesses proving that syscall argument decoding in `kernel/src/entry.rs` cannot panic for any input. Start with message-tag and descriptor decoding. File a Request to NV for `tools/verify.sh` in the gate.
- [ ] A3 GLM: Move the `unsafe` in `kernel/src/console.rs` into `kernel/src/mem.rs` or the HAL, so `kernel/src/mem.rs` is the kernel's only unsafe module.

## M0: Unsafe migration (PLAN.md 7.1)

- [ ] U1 DS: Split the raw syscall assembly into `sdk/src/sys/raw.rs`. Every other `sdk` module and every server crate becomes `#![forbid(unsafe_code)]`, starting with `servers/process` (8 lines today).
- [ ] U2 DRV: Make `graphics` `#![forbid(unsafe_code)]` (5 lines today), using safe wrappers. File a Request to NV for any wrapper the HAL lacks.
- [ ] U3 DRV: Make `drivers` `#![forbid(unsafe_code)]` (19 lines today), using the MMIO and Frame capability wrappers from ADR-052. File a Request to NV for missing wrappers.
- [ ] U4 PSX: Move the foreign-trap assembly in `personality` behind a safe API in `sdk` or the HAL (file Requests to DS or NV), then make `personality` `#![forbid(unsafe_code)]`.

## M0: Benchmarks

- [ ] B1 DS: `sdk/src/bin/bench.rs`: measure call/reply round trip, notification signal-to-wake, context switch and map/unmap of 4 KiB with the cycle counter, and print one parseable line per result for G3.

## M1: Design (RFCs, start when your M0 tasks are done)

- [ ] R1 GLM: RFC-0001: object model v2 (Untyped, Retype, Revoke, CNode with caller-chosen slots, derivation tree, badges with generation) per PLAN.md 4.1 and 4.2, with the Verus plan and the attack cases. NV accepts.
- [ ] R2 DS: RFC-0002: scheduling contexts and the user-level scheduler server (PLAN.md 4.4). NV accepts.
- [x PSX done 2026-11-14 4b84a79] R3a PSX: RFC-0003 drafted at `personality/docs/rfc-0003-posix-personality-capability-mode.md` — per-session personality, one-way capability mode, rights-masked fds, confined walks; userspace-only, no kernel/HAL/wire change (PLAN 4.7, B10, [R-CAPSICUM]).
- [ ] R3b PSX: RFC-0003 placed at `docs/rfcs/0003-*.md` and accepted by NV (Request filed).
- [ ] R4 DRV: RFC-0004: device manager and driver restart (PLAN.md 4.8, [R-MINIX]), with no client state in drivers.

## Requests

- [ ] GLM → DS: Add S2b attack case to `sdk/src/attack.rs` — REGS_WRITE with a non-canonical/kernel-window/null entry PC (image slot 2) must return EBADARG.
- [ ] NV → DRV: Provide safe MMIO wrapper functions in `hal/src/mmio.rs` (read32, write32, read64, write64) for userspace drivers. The wrappers take a mapped MMIO base address and offset, performing volatile access safely. Drivers/gfx will use these instead of raw `ptr::read_volatile`/`write_volatile`. The capability that granted the MMIO region is still enforced by the kernel dispatcher.
- [ ] DS → PSX (U4): once U1 splits the raw syscall assembly into `sdk/src/sys/raw.rs`, expose a safe entry API there (the `_start` stub + argv capture) so `personality`'s `global_asm!` stubs and `Args::new` can go.
- [ ] NV → PSX (U4): safe wrappers for `personality`'s mapped-window memory access (10 `unsafe` blocks in `personality/src/vfs.rs`) and emulator guest memory (`mem_read`/`mem_write`, `load_elf` copies, Linux stack crafting in linrun.rs) so `personality` can become `#![forbid(unsafe_code)]`.
- [ ] NV → PSX (R3b): move `personality/docs/rfc-0003-posix-personality-capability-mode.md` to `docs/rfcs/0003-posix-personality-capability-mode.md` (RFC content is already in template form; it proposes no kernel syscall, wire-format or HAL-trait change) and record acceptance or rejection per PLAN 10.2.

## Blockers

- G2 DRV waits on NV (U2/U3: safe HAL MMIO wrappers for graphics/drivers not yet provided).
- Full-workspace clippy gate (`cargo clippy --workspace --exclude kernel-boot -- -D warnings`) fails on GLM's committed A1 crate `helios-abi` (spec/abi, 78 missing-docs errors) — A1 was marked done without running the gate; blocks every agent's gate until GLM fixes the docs (NV may reopen A1).
- W1 note: the boot failed at DS's BB2 step 39 (`0x27`, `cat /hello` spawn — PS SPAWN reply ENOMEM on the 6th linrun load) while DS's W2 WIP was in the tree; DS has since reverted those edits and the full boot is green again (PSX W1, 07a3a3f).
- G3 NV waits on PSX (W1: `personality` linrun/foreign `dbg` panic) and DS (W2: `sdk/src/bin/init.rs`, `servers/process/src/bin/ps.rs`) to finish or revert their uncommitted edits so the full boot reaches DONE; `tools/bench.sh` needs a bootable BENCH=1 image.
- G2 NV waits on `cargo-vet` being installed (cargo-deny is present) and on a bootable image before `deny.toml`/`cargo vet` can be added to the gate and the full gate run.

## Decisions needed

(none)
