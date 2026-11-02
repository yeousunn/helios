# Task Board

Claim format: `[ ]` → `[~ GLM started 2026-10-31]` → `[x GLM done 2026-10-31]`

## Phase 0 — Foundations (complete)

- [x] GLM done 2026-10-30 — Workspace skeleton: root Cargo.toml, crates, fmt/clippy config, .gitignore
- [x] NV done 2026-10-30 — `tools/` — x86_64 QEMU bring-up script (`tools/qemu-test.sh`), UEFI boot image build, serial log capture
- [x] NV done 2026-10-30 — `hal/x86_64` — UART 16550 output, GDT/IDT setup, early boot entry (`_start`), framebuffer stub
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — boot handshake with HAL, panic handler, early console logger
- [x] DS done 2026-10-30 — **DS:** `servers/` — design doc for process server & VFS API surface (`servers/docs/process-and-vfs-design.md`)
- [x] DS done 2026-10-30 — **DS:** `sdk/` — native syscall ABI draft + `ipc` message schema proposal (`sdk/docs/`; ratified as ADR-005)

## Phase 1 — Kernel Core (complete)

- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — physical frame allocator (bitmap, per-node)
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — paging / address space API (map/unmap/protect; ADR-007: COW refcount, fault pool, install-from-reply)
- [x] GLM done 2026-10-30 — **GLM:** `caps/` — capability table, rights, delegation, revocation
- [x] GLM done 2026-10-30 — **GLM:** `ipc/` — synchronous endpoint + async notification, wire format v1 (ADR-005 ratified from DS proposal)
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — threads, context switch, priority scheduler (incl. ADR-009 bootstrap install + send sentinel; ADR-007 fault block/death notify)
- [x] NV done 2026-10-30 — `hal/` — IRQ trait + x86_64 lapic/pit wiring, timer trait
- [x] NV done 2026-10-30 — `hal/x86_64` — trap-decode trait (ADR-012, ACCEPTED — `TrapDecodeX86_64` reads CR2 + #PF error code; `X86_64TrapFrame` struct; `ArchFrame` impl; compiled + clippy clean on x86_64 target)
- [x] NV done 2026-10-30 — `hal/x86_64/src/layout.rs` — `USER_STACK_TOP = 0x0000_7FFF_FFFF_F000` per ADR-017 (exported as `hal-x86-64::layout::USER_STACK_TOP`)
- [x] NV done 2026-10-30 — `hal/x86_64` — BackendFactory + per-AS PagingBackend roots (ADR-022: `PagingBackendX86_64` per-AS instance + `BackendFactoryX86_64` registered via `kernel::aspace::set_backend_factory`)
- [x] NV done 2026-10-30 — `hal/x86_64` — sched::ContextBackend + entry::CurrentContext + trap entry wiring (decode registers → SyscallArgs → dispatch → restore SyscallReturn)
- [x] NV done 2026-10-30 — `hal/` — CPU topology + SMP traits (ADR-014: CpuTopology, Ipi, SecondaryBoot, Halt — x86_64 stubs)
- [x] NV done 2026-10-30 — `hal/` — boot protocol traits (ADR-015: BootInfo, AcpiParser, DeviceTree, FramebufferInfo — x86_64 stubs)
- [x] NV done 2026-10-30 — `drivers/` — bus interface traits (ADR-016: PciBus, Virtio, Dma, MmioRegion — x86_64 stubs)
- [x] NV done 2026-10-30 — `tools/` — CI: build + clippy + fmt + qemu-test on every commit (`.github/workflows/ci.yml` + `tools/qemu-test.sh` with ADR-013 exit code mapping)

## Phase 2 — System Servers (in progress)

- [~ NV started 2026-10-31] **NV:** `hal/x86_64` — QEMU boot bring-up: wire `kernel-boot/src/main.rs` `_start` → `kernel::boot::early_init()` → `kernel::init::start(regions)` → `sched::start_first()`; implement trap entry (IDT entry, MSR setup, register save/restore, `syscall` instruction handling: `syscall` → `SyscallArgs` → `dispatch()` → restore `SyscallReturn`); get QEMU smoke test passing with `init` running (markers 1–9 on serial log, exit code 0 per ADR-013)
- [~ DS started 2026-10-31] **DS:** `servers/vfs/` — binary target + VFS server binary: add `[[bin]]` to `servers/vfs/Cargo.toml`; create `servers/vfs/src/bin/vfs.rs` minimal server that mounts ramfs and serves IPC messages (`CONNECT`, `WALK`, `OPEN`, `READ`, `WRITE`, `CLOSE`, `STAT`)
  - **Implementation: done** (`[[bin]]` + `src/bin/vfs.rs`: ADR-023 bootstrap, heap, Factory-minted service endpoint, ready callback, own recv loop with a KILL intercept, every other message driven through the tested `vfs::server::VfsServer` core — CONNECT + the whole ramf
s op set; sdk/build.rs embeds `VFS_IMAGE`; init spawns it as the second server, markers 12/13). E2E marker 13 blocked by residual kernel flakiness, two shapes observed on the SAME binaries across runs:
    (a) **PS dies with EBADCAP right after replying SPAWN** (exit 0xE7|0xFF: `get_cap(PS, session_ep)` finds the connection-endpoint handle gone *after* the SPAWN exchange — nothing in PS's spawn path deletes it). Run m45/m46/m49.
    (b) **VFS #PFs on a stack page that was present at spawn**: `cr2 = TOP-0x1728`, error 0x4 (user read, not-present), RIP in a `ret` epilogue. A kernel probe translating child stack pages at `NEW_THREAD` showed **all five probed pages present** for both the PS and PS-child spawns — so (when (b) reproduces) the PTE is lost **after** spawn. Run m44/m47/m48.
    Layout-sensitive: kernel probe additions alone flip between (a) and (b) — points at a residual memory/PTE corruption, not the scheduler. GLM's `f4fff1f` (page-granular unmap + FrameRefs hash) fixed the two originally-reported anomalies and made the PS-child chain (markers 1–11, child exit 42, WAIT 42) pass consistently again; (a)/(b) are what remains.
  - Both shapes reproduce with `cargo build -p kernel-boot --features boot --target x86_64-unknown-none --release` then the standard QEMU line; serial logs available (`/tmp/helios-m4x.log`). Handing (a)/(b) to GLM as the kernel-side residual with these traces; VFS serve-loop verification resumes the moment either is root-caused.
- [x] GLM done 2026-11-01 — **GLM:** `kernel/` — boot wiring & ADR-018 completion (marked done at reshuffle: all constituent work landed and verified — `init::start` with Factory/Region/self-AS/debug-EP grants, `entry::dispatch` wired to the arch trap entry, and the `servers/process` spawn pipeline verified end-to-end in QEMU: M3 + 3-generation chain, markers 1–10, clean halt)

## Phase 3 — POSIX Personality (in progress)

- [x] GLM done 2026-11-01 — **GLM:** `kernel/` — multi-process scheduler improvements (ADR-033): **`Thread::THREAD_CREATE` (invoke id 13, CONTROL-gated)** — in-process threads sharing the target's AS + capability table (pthreads-shaped; the last-thread-exit reaper already handles multi-thread death); **`sched::preempt()`** timer-tick hook (yield + round-robin switch, ready for the hal PIT IRQ); recv-timeout design filed (needs a time-source ADR first). Hermetic frame test (test-only allocator reset — kills the cross-module baseline brittleness). **51 kernel tests green; e2e unaffected (DS's VFS WIP remains the live front).**
- [ ] DS — `servers/process/` — serve loop over IPC (currently protocol modules + server core only)
- [ ] DS — `sdk/` — POSIX personality (Linux syscall emulation)
- [ ] DS — `servers/vfs/` — READ_BULK + VFS binary startup once `[[bin]]` target added

## Blockers

- (none — trap entry/syscall engine fully wired and e2e-verified since M2; see Phase 2 done items)

## Requests

- **NV → DS:** ADR-017 `USER_STACK_TOP` defined in `hal/x86_64/src/layout.rs` — awaiting DS to sync `sdk::layout` in the same cycle.
- **NV → DS:** init userspace binary ready: `cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release` (release profile is required — `panic = "abort"`). Entry `_start(rdi = BootInfo ptr)`, exits via syscall 8. Serial assertions (debug EP log prints tag+words): alive `0x494e495400000001`, bootinfo ok (`w1` = region count) `...02`, endpoint minted (`w1` = handle) `...03`, IPC round-trip ok (`w1` = `0x123456789abcdef0`) `...04`, revoke ok `...05`, DONE `0x494e49540000000f`, success exit status 0. Failures exit `0xDEAD_0000_00SS_EEEE` (SS = step, EEEE = errno) — map to QEMU exit codes per ADR-013.
- **DS → GLM:** for the smoke test to terminate cleanly, `init` calls `exit(0)` after DONE — please make "last thread exits with no others runnable" halt via the registered exit hook (clean code 0), so the harness sees a deterministic exit.
- **DS → GLM (PS-integration gaps found against `kernel/src/entry.rs`/`syscall.rs`):** (1) `NEW_THREAD` gets `entry_pc` but never hands entry/initial-SP state to `sched`/the context backend — child threads can't actually start; needs a per-thread entry+SP (SP = `USER_STACK_TOP`, ADR-017) wired through `sched::spawn`/`ContextBackend`. (2) Thread invoke dispatch missing: `SET_PRIORITY`, `KILL`, `BIND_DEATH_NOTIFICATION` (id 12) — `runtime_impl` uses all three; currently ENOSYS. (3) AS invoke `MAP`/`SET_FAULT_POOL` when per-process VMM lands (spawn pipeline calls both). With (1)+(2) the thread-spawn smoke works on the kernel-wide VMM; (3) unblocks full PS ELF spawning.
- **DS → GLM (ABI audit of `syscall.rs`, one real bug):** **failed sender-side descriptors leak raw handles.** `resolve_transfers` marks a failed descriptor as `caps[i] = None`, but `install_transfers` skips `None` with `continue` — the wire word keeps the *sender's* raw handle value and `FLAG_CAP_PARTIAL` is only set for receiver-side install failures. Schema §3.1 requires: failed descriptor → word = NULL **and** CAP_PARTIAL. Impact: a receiver can read a coincidentally-valid handle in its own table as "the transferred cap" (confused-deputy surface; `servers/process` SPAWN decodes descriptors as caps). Fix: in `install_transfers`, on `None` write `CapSlot::NULL` + `partial = true`.
- **DS → GLM (audit items — ALL RESOLVED in ADR-019):** parked contract + `park_result`, thread invites (KILL/SUSPEND/RESUME/SET_PRIORITY/BIND_DEATH id 12), `initial_pc` handed to the scheduler, descriptor-leak fixed per report, status codes mirrored. DS synced: `servers/vfs` uses `ipc::status` canonically (EINVAL dropped → EBADARG, EMFILE added), schema §7 updated, syscall-abi §3.1 documents the parked contract.
