# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. History before 2026-11-12 is in `docs/history/TASKS-2026-10-30_to_2026-11-12.md`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`.

**Phase:** H (hardening, feature freeze, ADR-049). Baseline 2026-11-12 at `dcba3ce`: host gates green, 207 tests, full QEMU boot reaches DONE and clean halt, userspace clippy fails.

## Phase H — Security (S1 lands first, then in any order)

Every S-task needs a host unit test that fails before the fix (pattern: the entry tests in `kernel/src/entry.rs` using `MockCtx`, `FixedCtx`, `proc::install_cap`) and a case in the S11 attack test.

- [x GLM done 2026-11-13 f5d6717] S1 GLM — REGS_WRITE writes user words into the target's kernel stack (`kernel/src/entry.rs:591`, `kernel/src/mem.rs:69`, `kernel/src/sched.rs:690`). Word 3 is the ring-0 return address, and for a Blocked thread the syscall frame (RCX, R11) is exposed. Fix: keep a per-thread user register struct apart from the kstack, make REGS_READ/WRITE touch only that, and mask RFLAGS (IOPL=0, IF=1). Propose an ADR first (syscall contract change, NV accepts). ADR-050 PROPOSED; 3 host tests fail pre-fix/pass post-fix; boot reaches DONE with the S11 attack step exiting 0.
- [x GLM done 2026-11-13 203cf7a] S2 GLM — SET_ENTRY, THREAD_CREATE and NEW_THREAD accept any PC or stack pointer (`entry.rs:526`, `:626`, `:780`). Add one `is_user_addr()` helper (below `0x0000_8000_0000_0000`, not 0) and return EBADARG otherwise.
- [x GLM done 2026-11-13 e7028bd] S3 GLM (do next) — SET_TLS takes a non-canonical FS base, which faults in ring 0 at the next switch (`entry.rs:535`). Validate with `is_user_addr()` and return EBADARG. Until this lands, S3b's HAL check turns a bad base into a kernel panic, so any process can still halt the machine.
- [x NV done 2026-11-12 880983f] S3b NV — Assert a canonical user FS base in the HAL before `wrmsr` (`hal/x86_64/src/impl_x86_64.rs:1066`).
- [x GLM done 2026-11-13 1cd2a31] S4 GLM — MAP, UNMAP and PROTECT check only alignment, so a user can map over the shared kernel window PML4[511] (`kernel/src/aspace.rs:209`). Require the whole range in user space, with overflow-checked math, and reject VA 0.
- [x NV done 2026-11-13 7ac6f6e] S5 NV — `walk_create` ORs PTE_USER into upper-level entries and splits kernel huge pages (`hal/x86_64/src/paging.rs:279`). Refuse walks into PML4 slots 256–511 and never set USER on a shared kernel entry.
- [x NV done 2026-11-13 06d018b] S6 NV — SMEP, SMAP and UMIP are off (`kernel-boot/src/boot.S:119`). Write the CPUID-checked CR4 code as a HAL function and file a Request for GLM to call it from `kernel-boot`. SMAP waits for a user-copy helper: record that in an ADR.
- [x GLM done 2026-11-13 7165714] S6b — Call NV's CR4 hardening function from `kernel-boot` once S6 lands. Call wired in kernel_main (before any ring-3 code); boot reaches DONE. NOTE: boot log shows mask 0x0 — NV's probe checks wrong CPUID bits (see Request).
- [x NV done 2026-11-13 a865f5f] S7 NV — FMASK is `0x300`, so DF and AC reach the kernel (`hal/x86_64/src/syscall_entry.rs:46`). Clear IF, TF, DF, AC and NT (`0x47700`) and add `cld` to every interrupt and exception entry stub.
- [x GLM done 2026-11-14 ac1435c] S8 — NEW_THREAD copies caps[1] with full rights and no GRANT check, and adds SEND on caps[2] (`entry.rs:~801`, `~822`). Route both through the GRANT-checked, rights-intersecting transfer in `kernel/src/syscall.rs:112` and `:144`, and check the cap type.
- [x GLM done 2026-11-14 bb13bb8] S9 GLM — UNMAP with a huge page count loops with interrupts off (`aspace.rs:331`). Cap it at the region size and return EBADARG above that.
- [x NV done 2026-11-13 df460db] S10 NV — `map_page` panics when no page-table frame is free (`hal/x86_64/src/paging.rs:~388`). Return an error.
- [x GLM done 2026-11-14 ac5cf0e] S10b GLM — Audit every `unwrap()`/`expect()` reachable from `entry::dispatch` and turn each into an error code. Tests and boot code may keep theirs.
- [~ DS started 2026-11-13] S11 — An `attack` userspace program (pattern: `sdk/src/bin/child.rs`) makes every bad call from S1–S10 and expects an error back. init runs it as a new marker step. The boot must still reach DONE. Add each case as soon as its S-task lands. (S8/S9 landed 2026-11-14; adding their cases now.)
  - [x DS done 2026-11-13 803becd] S11.1 — harness: `sdk::attack` runner (generic, host-tested) + `child` argv "attack" mode + init markers 29/30 + 2 baseline cases; boot reaches DONE. Also fixed `sdk/build.rs` rerun-if-changed (fresh-build reproducibility).
  - [x DS done 2026-11-13 0bf07eb] S11.2 — cases for S2 (kernel-PC THREAD_CREATE, and SET_ENTRY via a suspended scratch thread that is killed after) and S3 (non-canonical SET_TLS); 5 cases total, boot reaches DONE + clean halt.
  - [x DS done 2026-11-13 b4c9bfd] S11.3 — cases for S4/S5 (MAP kernel-window, UNMAP kernel-window, PROTECT kernel-window, MAP null); 9 cases total, boot reaches DONE + clean halt. Pending: S8 GRANT-check and S9 oversized UNMAP (not landed); S6/S7 not observable from ring 3.

## Phase H — Engineering

- [x NV done 2026-11-13 90b345d] E1 NV — `tools/build-all.sh`: build every userspace image in dependency order, then `kernel-boot` release. Must honour `CARGO_TARGET_DIR` and the `*_IMAGE` variables.
- [x NV done 2026-11-13 ca0dc44] E2 NV — `tools/qemu-test.sh`: call E1, boot the release kernel, require the DONE marker and `clean halt`, work on macOS (use `gtimeout` if present), and honour `SERIAL_LOG` and `CARGO_TARGET_DIR`.
- [x NV done 2026-11-13 5766b07] E3 NV — CI (`.github/workflows/ci.yml`) runs E2, `cargo test` and the userspace clippy line. Pushing is for the human. Done when it runs locally through `tools/qemu-test.sh`.
- [x DS done 2026-11-13 9dda2e9] E4 DS — Make the userspace clippy line in AGENTS.md section 5 pass with `-D warnings` (fixed the 16 lints in `sdk` bins `init`/`child`, `personality` bins `sh`/`cat`/`wc`, `servers/process/src/bin/ps.rs`; boot still DONE + clean halt).
- [x NV done 2026-11-14 62e2826] E5 NV — Add the userspace clippy line to `tools/qemu-test.sh` once E4 lands; blocked on DS's E4 (userspace clippy not yet `-D warnings` clean).
- [ ] E6 DS — Source and build notes for every ELF in `personality/assets/` (one source file plus a reproducible build line each, and the musl MIT license noted), or a script that builds them.
- [ ] E7 DS — Remove the `.data` atomics workaround in `sdk/src/bin/init.rs:902` and its copy in ps. The real causes (kstack overflow, asm clobber) are fixed. The boot must still reach DONE.
- [x NV done 2026-11-13 66c3dcd] E8 NV — ADR-052: userspace drivers get MMIO/DMA through capabilities (MmioRegion + Frame caps; HAL traits stay kernel-internal; driver move waits for freeze lift).
- [x NV done 2026-11-13 603124d] E9 NV — README (honest status from PLAN.md 4a, build and boot steps), LICENSE-MIT, LICENSE-APACHE, `build/` and `graphify-out/` in `.gitignore`. Leave `repository` in Cargo.toml as is until the human names the URL.
- [x NV done 2026-11-13 fae3dab] E10 NV — PLAN.md section 5 says PLAN.md and TASKS.md live in `docs/`, but they are at the root. Fix the text in PLAN.md to match (do not move the files: the supervisor reads them at the root).
- [x NV done 2026-11-13 243bd24] E11 NV (do next) — The `hal/x86_64` tests never run: `impl_x86_64` is `#[cfg(target_arch = "x86_64")]` and the host is arm64, so `cargo test -p hal-x86-64` reports 0 tests (S3b's new tests included). Move pure, register-free logic (address checks, PTE math, PCI address building) into a module compiled on every host, and make the gate fail if the crate's test count is 0.

## Requests

- [x GLM done 2026-11-13 7165714] [Request] GLM — call `hal::enable_supervisor_protections()` from kernel-boot (CR4 SMEP/UMIP hardening, S6). Landed: call wired in kernel_main before any ring-3 code; see S6b note + the NV Request below for the probe-bug finding.
- [Resolved] NV — `enable_supervisor_protections` CPUID probe fixed (ea7bd59): SMEP=leaf7 EBX[7], SMAP=EBX[20] (deferred pending user-copy helper, ADR-051), UMIP=ECX[2]. CR4 bit constants correct. Boot now reports `CR4 supervisor protections enabled: 0x100800` (SMEP+UMIP), reaches the DONE marker and clean halt. (AGENTS.md `--features boot` clippy note references human-owned AGENTS.md; not agent-editable.)
- [x GLM done 2026-11-13 46cb60c] [Request] GLM — landed as `PagingBackend::map_page_checked` (fallible) with a default bridge to the infallible `map_page`, so mocks in entry.rs/init.rs needed no changes; all kernel install paths route through it, failures roll back PTEs/refs/records into `VmmError::MapFailed` (fault.rs kills the faulting thread). NV's S10 (df460db) overrides it in hal/x86_64.
- [Request] NV — E1 `tools/build-all.sh` image order is wrong for a fresh build: it builds `sdk init` before PS/VFS/CONSOLE/AUTH (init embeds those, so HAS_*_IMAGE=false → boot stops at init marker step 18), and builds `vfs` before the personality bins it embeds (no `/posix` → boot stops at step 16). Repro: fresh `cargo clean` (or empty `$CARGO_TARGET_DIR`) then `tools/qemu-test.sh`. Needed order: child, console, auth, personality --bins, vfs, ps, init, kernel-boot. (I fixed the related `sdk/build.rs` rerun-if-changed so the manual pipeline order is reproducible; build-all still needs this reorder.)
- [Resolved] NV — build-all.sh image order already fixed by E1 (7fd070f): order is now child, console, auth, personality --bins, vfs, ps, init, kernel-boot, matching the Request's needed order. No further NV action.
- [Request] NV — E4 landed (9dda2e9): the userspace clippy line is now `-D warnings` clean, so E5 (add it to `tools/qemu-test.sh`) is unblocked.

## Blockers

- [Resolved] NV — kernel-build blocker was stale: `cargo build -p kernel` and `cargo test -p hal-x86-64` both succeed on this host (5 host tests); E11 logic+tests (243bd24) and the qemu-test.sh guard (f2bf132) are committed. GLM's uncommitted `aspace.rs`/`fault.rs` refactor compiles cleanly and is GLM's to commit.
- [Resolved] NV — E5 (userspace clippy line in tools/qemu-test.sh) unblocked by DS's E4 (9dda2e9); clippy line added to tools/qemu-test.sh and full qemu-test.sh gate passes (DONE marker + clean halt).
- [Resolved] GLM — S8 test interference fixed by adding `frame::reset_for_test()` in entry test setup; all kernel tests pass.

## Decisions needed

(none)

## Phase 2 — System servers (after freeze lift; ADR-054)

- [~ NV started 2026-11-14] NV — virtio-blk as a userspace driver (after E8): drivers/ virtio_blk against MmioRegion + Frame caps per ADR-052; not wired into boot path yet; HAL traits stay kernel-internal.

## Phase 3 — POSIX personality + shell (after freeze lift; ADR-054)

- [ ] DS — busybox: port/build busybox against the POSIX personality; run under init (static musl binaries already run).
- [ ] DS — interactive login (ADR-048): login program, /etc/passwd in ramfs, console-in as stdin; init LOGIN=1 path spawns login instead of sh.

## Phase 4 — Graphics & desktop (after freeze lift; ADR-054)

- [ ] NV — virtio-gpu as a userspace driver (graphics/): virtio-gpu against MmioRegion + Frame caps per ADR-052; not wired into boot path yet.
