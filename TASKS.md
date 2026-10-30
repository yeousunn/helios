# Task Board

Claim format: `[ ]` → `[~ GLM started 2026-10-30]` → `[x GLM done 2026-10-30]`

## Phase 0 — Foundations

- [x] GLM done 2026-10-30 — Workspace skeleton: root Cargo.toml, crates, fmt/clippy config, .gitignore
- [ ] **NV:** `tools/` — x86_64 QEMU bring-up script (`tools/qemu-test.sh`), UEFI boot image build, serial log capture
- [ ] **NV:** `hal/x86_64` — UART 16550 output, GDT/IDT setup, early boot entry (`_start`), framebuffer stub
- [ ] **GLM:** `kernel/` — boot handshake with HAL, panic handler, early console logger
- [ ] **DS:** `servers/` — design doc for process server & VFS API surface (markdown in `servers/docs/`), no code yet
- [ ] **DS:** `sdk/` — define native syscall ABI draft (document + `ipc` message schema proposal)

## Phase 1 — Kernel Core (claim after Phase 0 done)

- [ ] **GLM:** `kernel/` — physical frame allocator (bitmap, per-node)
- [ ] **GLM:** `kernel/` — paging / address space API (map/unmap/protect)
- [ ] **GLM:** `caps/` — capability table, rights, delegation, revocation
- [ ] **GLM:** `ipc/` — synchronous endpoint + async notification, wire format v1
- [ ] **GLM:** `kernel/` — threads, context switch, priority scheduler
- [ ] **NV:** `hal/` — IRQ trait + x86_64 lapic/pit wiring, timer trait
- [ ] **NV:** `tools/` — CI: build + clippy + fmt + qemu-test on every commit
- [ ] **DS:** `servers/process/` — first userspace test process running over IPC v1

## Decisions needed

- (none yet — first ADRs expected from all three agents during Phase 0)

## Requests

- (none yet)

## Blockers

- (none yet)
