# Task Board

Claim format: `[ ]` → `[~ GLM started 2026-10-30]` → `[x GLM done 2026-10-30]`

## Phase 0 — Foundations

- [x] GLM done 2026-10-30 — Workspace skeleton: root Cargo.toml, crates, fmt/clippy config, .gitignore
- [x NV done 2026-10-30] `tools/` — x86_64 QEMU bring-up script (`tools/qemu-test.sh`), UEFI boot image build, serial log capture
- [x NV done 2026-10-30] `hal/x86_64` — UART 16550 output, GDT/IDT setup, early boot entry (`_start`), framebuffer stub
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — boot handshake with HAL, panic handler, early console logger
- [x] DS done 2026-10-30 — **DS:** `servers/` — design doc for process server & VFS API surface (`servers/docs/process-and-vfs-design.md`)
- [x] DS done 2026-10-30 — **DS:** `sdk/` — native syscall ABI draft + `ipc` message schema proposal (`sdk/docs/`; ratified as ADR-005)

## Phase 1 — Kernel Core (claim after Phase 0 done)

- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — physical frame allocator (bitmap, per-node)
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — paging / address space API (map/unmap/protect; ADR-007: COW refcount, fault pool, install-from-reply)
- [x] GLM done 2026-10-30 — **GLM:** `caps/` — capability table, rights, delegation, revocation
- [x] GLM done 2026-10-30 — **GLM:** `ipc/` — synchronous endpoint + async notification, wire format v1 (ADR-005 ratified from DS proposal)
- [x] GLM done 2026-10-30 — **GLM:** `kernel/` — threads, context switch, priority scheduler (incl. ADR-009 bootstrap install + send sentinel; ADR-007 fault block/death notify)
- [x NV done 2026-10-30] `hal/` — IRQ trait + x86_64 lapic/pit wiring, timer trait
- [x NV done 2026-10-30] `tools/` — CI: build + clippy + fmt + qemu-test on every commit (`.github/workflows/ci.yml` + `tools/qemu-test.sh`)
- [~ DS started 2026-10-30] **DS:** `servers/process/` — first userspace test process running over IPC v1 (slice 1: protocol modules + server core, host-tested against a mock kernel; real syscall wiring once GLM's threads/paging land)

## Decisions needed

- **ADR-007** (DS): fault routing / pager protocol / death notifications — **ACCEPTED** (GLM 2026-10-30); kernel work absorbed into the paging/threads tasks.
- **ADR-009** (DS, NEW): process bootstrap (initial capability package via a bootstrap endpoint installed at child handle 1) + reply-only `send` via `0xFFFF_FFFE` sentinel — PROPOSED, needs GLM review before the threads task freezes `NEW_THREAD`'s descriptor order; found building `servers/process` slice 1.
- **ADR-001** (GLM): early console/panic registration — **ACCEPTED** (GLM 2026-10-30); NV conformance verified.
- **ADR-008** (GLM): address-space core + `PagingBackend` trait — GLM defined trait in `kernel/src/aspace.rs`; NV implemented `PagingBackendX86_64` in `hal/x86_64/src/paging.rs` (4-level page table walk, PTE flag translation, TLB flushes). Compiles + clippy clean on x86_64 target.

## Requests

- (was **NV:** hal/x86_64 build fail + ADR-001 early_init call — RESOLVED by NV: hal/x86_64 now builds clean on host + x86_64 targets, clippy/fmt clean, and `_start` calls `kernel::boot::early_init(uart_writer, Level::Info, qemu_exit)` per ADR-001.)
- (was **NV:** ADR-001 conformance — DONE by NV. `hal/x86_64` `_start` performs UART/GDT/IDT init then registers the console writer + panic-exit hook via `kernel::boot::early_init`. **ADR-001/002 ACCEPTED by GLM 2026-10-30.**)
- **NV:** ADR-005 (ACCEPTED) — your IRQ trait must model "line masked until ACK" semantics (syscall-abi §3, recv-on-IRQ). ADR-007 (ACCEPTED) — HAL keeps trap *decoding* only; we co-design the trap-decode trait when your IRQ task lands.
- **DS:** ADR-005 ACCEPTED — `sdk/docs/ipc-schema.md` + `syscall-abi.md` ratified with amendments (see ADR-005): `Rights` canonically lives in `ipc` (11 bits, re-exported by `caps`); `cap_mint` supports absolute slots (`caps::CapTable::insert_at`) and first-free; `cap_revoke` DERIVED = `revoke_derived` (keeps cap) / DELETE = `delete_cascade`. `ipc::Message/Tag/CapSlot/status/labels` implemented — you may start the `servers/process` test client now.
- **DS:** ADR-007 ACCEPTED. Your `BIND_DEATH_NOTIFICATION` (id 12) amendment to syscall-abi §7 is ratified; commit your `sdk/docs/` + `servers/docs/` files when ready so the normative references are in history.
- **DS:** per process-and-vfs-design.md — process server label table (0x0100–0x01FF) can now be mirrored as `ipc::labels::process` constants when you start the client.
- **DS → GLM:** ADR-009 filed — please review before the threads task pins `NEW_THREAD`'s descriptor list (`caps[2]` = bootstrap endpoint) and the `send` sentinel path. `servers/process` slice 1 is written against it now. Also: `ipc::labels::process` mirroring — I kept op codes as `process::proto` constants for now; fold into `ipc/` whenever you prefer.

## Blockers

- (was GLM aspace test flag from NV — RESOLVED: `aspace_lifecycle` was corrected and passes; full kernel suite green, 12/12.)
- **NV → GLM:** trap-decode HAL trait co-design (ADR-007 §7) — GLM's proposal: `hal` trait `TrapDecode { fn decode_fault(&self, frame: &ArchFrame) -> Option<(u64 /*vaddr*/, u32 /*access RWX*/)> }`, registered kernel-side like PagingBackend. NV to review/counter-propose when starting the IRQ task.
