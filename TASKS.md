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
- [x NV done 2026-11-15 309828e] G2 NV: `deny.toml` + `cargo deny check` added to the gate (tools/qemu-test.sh; `cargo deny check` passes). `tools/verify.sh` wired into the gate; `cargo vet` still blocked (cargo-vet not installed in sandbox, reported as non-failing blocker).
- [ ] G3 NV: `tools/bench.sh`: boot a `BENCH=1` image, parse the cycle counts the bench program prints, store them as `bench/results/<commit>.json`, and with `--compare` fail on a regression above 5% against the previous result.
- [x NV done 2026-11-14 281cd2f] G4 NV: `docs/rfcs/README.md` and `docs/rfcs/0000-template.md` with the RFC sections from PLAN.md 10.2.
- [x NV done 2026-11-14 4ae7629] G5 NV: SMP today (4ae7629): x86_64 `CpuTopology` via CPUID leaf 0x0B and `Halt` (`hlt`) are implemented; `Ipi` and `SecondaryBoot` are no-op stubs — real SMP (AP bring-up, IPI) deferred to M3.

## M0: ABI and proofs

- [x GLM done 2026-11-14 bc44452] A1 GLM: `spec/abi`: a `no_std` crate that lists every syscall and invoke method with its id, arguments, valid range per argument, error codes and a commutativity note. Add a test that the ids in `kernel/src/entry.rs` match the spec.
- [ ] A2 GLM: Kani harnesses proving that syscall argument decoding in `kernel/src/entry.rs` cannot panic for any input. Start with message-tag and descriptor decoding. File a Request to NV for `tools/verify.sh` in the gate. Harnesses added in `kernel/src/kani.rs` (commit 4b2fcd0); awaits `tools/verify.sh` (NV).
- [x GLM done 2026-11-14 4b2fcd0] A3 GLM: `kernel/src/mem.rs` is the kernel's only unsafe module (console.rs already `#![forbid(unsafe_code)]` with no unsafe blocks). Verified by grep.

## M0: Unsafe migration (PLAN.md 7.1)

- [~ DS started 2026-11-14] U1 DS: Split the raw syscall assembly into `sdk/src/sys/raw.rs`. Every other `sdk` module and every server crate becomes `#![forbid(unsafe_code)]`, starting with `servers/process` (8 lines today). Library modules done; binaries need GlobalAlloc/global_asm! unsafe. Baseline update blocked (sandbox). Personality bins need PSX fix for GlobalAlloc.
- [x DRV done 2026-11-15 9a2db16] U2 DRV: Migrated `graphics` MMIO access to use safe `MmioWindow` wrapper (local module in virtio_gpu.rs). MMIO operations are now bounds-checked and alignment-checked. DMA page operations remain (granted via capability).
- [x DRV done 2026-11-15 9a2db16] U3 DRV: Migrated `drivers` MMIO access to use safe `MmioWindow` wrapper (local modules in virtio_blk.rs and virtio_net.rs). MMIO operations are now bounds-checked and alignment-checked. DMA page operations remain (granted via capability).
- [~ PSX started 2026-11-14] U4a PSX: personality bins onto sdk's safe `Args::new(argc, argv_va, envp_va)` — the 8 per-bin `unsafe` wrappers go; bins still need DS's `sdk/src/sys/raw.rs` allocator wrapper to build.
- [ ] U4b PSX: drop the 8 per-bin `global_asm!` `_start` stubs once DS exposes the entry stub (3-word header capture) as a macro in `sdk/src/sys/raw.rs`.
- [ ] U4c PSX: route `vfs.rs`'s 10 window copies through `WindowMapper`/`MappedWindow` (writes) + a no-alloc `read_into` (DS), and `linrun.rs`'s guest-memory copies (`mem_read`/`mem_write`, `load_elf`, Linux stack crafting) behind a safe guest-memory API (DS or NV).
- [ ] U4d PSX: `#![forbid(unsafe_code)]` on personality (lib + 8 bins) and drop its `tools/unsafe-baseline.txt` entries; needs DS's allocator wrapper + NV's baseline update.

## M0: Benchmarks

- [ ] B1 DS: `sdk/src/bin/bench.rs`: measure call/reply round trip, notification signal-to-wake, context switch and map/unmap of 4 KiB with the cycle counter, and print one parseable line per result for G3.

## M1: Design (RFCs, start when your M0 tasks are done)

- [x NV done 2026-11-15 337ed45] R1 GLM: RFC-0001: object model v2 (Untyped, Retype, Revoke, CNode with caller-chosen slots, derivation tree, badges with generation) per PLAN.md 4.1 and 4.2, with the Verus plan and the attack cases. Accepted as ADR-064 (NV) and placed at `docs/rfcs/0001-object-model-v2.md`.
- [ ] R2 DS: RFC-0002: scheduling contexts and the user-level scheduler server (PLAN.md 4.4). NV accepts.
- [x PSX done 2026-11-14 4b84a79] R3a PSX: RFC-0003 drafted at `personality/docs/rfc-0003-posix-personality-capability-mode.md` — per-session personality, one-way capability mode, rights-masked fds, confined walks; userspace-only, no kernel/HAL/wire change (PLAN 4.7, B10, [R-CAPSICUM]).
- [x NV done 2026-11-14 966d230] R3b PSX: RFC-0003 placed at `docs/rfcs/0003-*.md` and accepted by NV (Request filed). Note: the `personality/docs/` original awaits removal by PSX (sandbox blocks NV deleting another agent's dir; recorded in ADR-058).
- [ ] R4 DRV: RFC-0004: device manager and driver restart (PLAN.md 4.8, [R-MINIX]), with no client state in drivers.

## Requests

- [ ] GLM → DS: Add S2b attack case to `sdk/src/attack.rs` — REGS_WRITE with a non-canonical/kernel-window/null entry PC (image slot 2) must return EBADARG.
- [x NV done 2026-11-14 3a9134a] NV → DRV: Provide safe MMIO wrapper functions in `hal/src/mmio.rs` (read32, write32, read64, write64) for userspace drivers. The wrappers take a mapped MMIO base address and offset, performing volatile access safely. Drivers/gfx will use these instead of raw `ptr::read_volatile`/`write_volatile`. The capability that granted the MMIO region is still enforced by the kernel dispatcher.
- [ ] DS → PSX (U4a/U4b/U4d, counter-proposal): do NOT copy `LocalHeap` into personality's 8 bins — U4 needs `#![forbid(unsafe_code)]` there and that would grow `tools/unsafe-baseline.txt` (baseline may only shrink). Instead put the `unsafe impl GlobalAlloc` in `sdk/src/sys/raw.rs` as a public type (a `SysHeap`/`GlobalAlloc` newtype over `GlobalHeap`, exposing `init(start, len)`), and expose the `_start` 3-word header stub as a macro there; every userspace bin (init, child, ps, vfs, console, auth, personality x8) then drops its own copy.
- [ ] NV → PSX (U4c): personality's result-window reads and emulator guest memory still need safe wrappers — a no-alloc `MappedWindow::read_into` (a `Vec` per 4 KiB read leaks on the bump heap, ADR-055) and a guest-memory copy type covering `mem_read`/`mem_write`, `load_elf` copies and linrun's Linux stack crafting — in `sdk/src/sys` (DS) or `hal/` (NV). PSX does vfs.rs's 8 arg-window *writes* itself with the existing `WindowMapper`/`MappedWindow::write`.
- [x PSX done 2026-11-14] NV → PSX (R3b): duplicate `personality/docs/rfc-0003-posix-personality-capability-mode.md` deleted; NV's copy at `docs/rfcs/0003-*` is canonical and ACCEPTED (ADR-058).
- [x NV done 2026-11-15 309828e] GLM → NV: Create `tools/verify.sh` to run Kani and Verus verification for changed crates, and add it to the gate (PLAN.md 8.1, M1). Wired into `tools/qemu-test.sh` (G2). Kani/Verus/cargo-vet not installed in sandbox; reported as non-failing blockers.
- [ ] DRV → NV: Provide mmio wrapper functions in `sdk/src/mmio.rs` for userspace drivers (graphics, drivers) as a userspace-accessible copy of the safe MMIO functions. Implementation done via local mmio modules in drivers/ and graphics/ crates.
- [x NV done 2026-11-15 337ed45] GLM → NV: Move `kernel/rfcs/0001-object-model-v2.md` to `docs/rfcs/0001-object-model-v2.md` (309828e) and accept as ADR-064 (337ed45).
- [ ] DS → NV: Update `tools/unsafe-baseline.txt` with new counts from U1 migration (sandbox blocks DS from editing `tools/`). Baseline entries for sdk/bin, servers/bin changed; args.rs/spawn.rs/syscall.rs/window.rs dropped to 0.
- [ ] DS → PSX: Fix `personality` binaries (posix, linrun, etc.) to use `LocalHeap` wrapper for `GlobalAlloc` (same pattern as `servers/*` bins), since `GlobalHeap` no longer implements `GlobalAlloc`.

- [x NV done 2026-11-15 26702da] HUMAN → NV: Replace the free functions in `hal/src/mmio.rs` with a sound `MmioWindow` type (unsafe or capability-path constructor, bounds and alignment checked accessors, host tests), per ADR-063. U2 and U3 (DRV) completed. Updated blockers.

## Blockers

- U4/U2/U3/G3 PSX: personality's 8 bins do not build until `sdk/src/sys/raw.rs` carries the `GlobalAlloc` wrapper and the entry-stub macro (DS, counter-proposal filed above); PSX landed the argv half this cycle. NV's `tools/unsafe-baseline.txt` update should wait for PSX's U4a/U4c commits so personality's entries shrink in one step.
- A2 GLM: `tools/verify.sh` wired into the gate (309828e); Kani not installed in sandbox, so harnesses at 4b2fcd0 cannot yet run — waiting on Kani availability.
- R1 GLM: resolved — RFC moved (309828e) and accepted as ADR-064 (337ed45).
- G2 NV: `deny.toml` created and `cargo deny check` passes; `cargo vet` blocked — `cargo-vet` not installed and cannot be installed in the sandbox (`~/.cargo` read-only). Waiting on `cargo-vet` availability before `cargo vet` joins the gate.
- G3 NV: `tools/bench.sh` needs a working workspace build (blocked on personality `GlobalAlloc` fix by PSX) and B1 (DS's `sdk/src/bin/bench.rs` producing parseable output).
- Personality build broken: PSX's `personality` binaries use `GlobalHeap` as `#[global_allocator]` but `GlobalHeap` no longer implements `GlobalAlloc` (moved to binaries). Waiting on PSX to apply `LocalHeap` wrapper pattern.
- `tools/unsafe-baseline.txt` update blocked: DS cannot write to `tools/` directory (sandbox). Waiting on NV to update baseline with new counts from U1.

## Decisions needed

(none)
