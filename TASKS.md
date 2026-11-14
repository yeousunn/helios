# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. The plan is `PLAN.md` (v2, ADR-057). History before 2026-11-14 is in `docs/history/`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`. Mark a task done only when everything its line asks for is done.

**Milestone:** M0, baseline and guardrails (PLAN.md section 9). Baseline at `cda0a19`: host gates green, 286 host tests, full QEMU boot reaches DONE and clean halt at HEAD. The working tree holds uncommitted edits from stopped cycles that break the boot (W-tasks below fix that first).

## M0: Working tree (do first)

- [ ] W1 PSX (do next): Finish or revert the uncommitted edits in `personality/src/bin/linrun.rs` and `personality/src/foreign.rs` (left by a stopped cycle, `dbg` indexed past its length). The full boot must reach DONE again.
- [ ] W2 DS (do next): Finish or revert the uncommitted edits in `sdk/src/bin/init.rs` and `servers/process/src/bin/ps.rs`, and fix `load_via_vfs` taking 8 arguments (clippy). The full boot must reach DONE again.

## M0: Security

- [~ GLM started 2026-11-14] S2b GLM (do next): REGS_WRITE passes the user's entry PC (image slot 2) to `init_context` unchecked (`kernel/src/sched.rs` `regs_write`), so a non-canonical RIP faults in ring 0 at `iretq`. Reject a non-`is_user_addr` PC with EBADARG, add a host test, and file a Request for DS's attack case.
- [ ] S2c DS: Add the S2b attack case to `sdk/src/attack.rs` once S2b lands (REGS_WRITE with a non-canonical PC must return EBADARG).

## M0: Gates and tools

- [~ NV started 2026-11-14] G1 NV: `tools/check-unsafe.sh`: fail when `unsafe`, `asm!`, `global_asm!` or `extern "C"` appear outside the PLAN.md 7.1 allowlist. Keep today's exceptions in `tools/unsafe-baseline.txt` (file and count), which may only shrink. Add it to `tools/qemu-test.sh`.
- [ ] G2 NV: Supply chain: `deny.toml` for cargo-deny (advisories, licences, sources) and `cargo vet init`. Add both to the gate once they pass.
- [ ] G3 NV: `tools/bench.sh`: boot a `BENCH=1` image, parse the cycle counts the bench program prints, store them as `bench/results/<commit>.json`, and with `--compare` fail on a regression above 5% against the previous result.
- [ ] G4 NV: `docs/rfcs/README.md` and `docs/rfcs/0000-template.md` with the RFC sections from PLAN.md 10.2.
- [ ] G5 NV: The SMP line marked done on 2026-11-14 (4ae7629) covers only topology and `hlt`. Record what exists in one line and leave real SMP to M3.

## M0: ABI and proofs

- [ ] A1 GLM: `spec/abi`: a `no_std` crate that lists every syscall and invoke method with its id, arguments, valid range per argument, error codes and a commutativity note. Add a test that the ids in `kernel/src/entry.rs` match the spec.
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
- [ ] R3 PSX: RFC-0003: POSIX personality in capability mode (PLAN.md 4.7, [R-CAPSICUM]), one personality instance per session.
- [ ] R4 DRV: RFC-0004: device manager and driver restart (PLAN.md 4.8, [R-MINIX]), with no client state in drivers.

## Requests

(none)

## Blockers

(none)

## Decisions needed

(none)
