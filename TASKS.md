# Task Board

Rules: `AGENTS.md` sections 2, 3 and 7. History before 2026-11-12 is in `docs/history/TASKS-2026-10-30_to_2026-11-12.md`.

Claim format: `[ ]` then `[~ TAG started YYYY-MM-DD]` then `[x TAG done YYYY-MM-DD <hash>]`.

**Phase:** H (hardening, feature freeze, ADR-049). Baseline 2026-11-12 at `dcba3ce`: host gates green, 207 tests, full QEMU boot reaches DONE and clean halt, userspace clippy fails.

## Phase H — Security (S1 lands first, then in any order)

Every S-task needs a host unit test that fails before the fix (pattern: the entry tests in `kernel/src/entry.rs` using `MockCtx`, `FixedCtx`, `proc::install_cap`) and a case in the S11 attack test.

- [~ GLM started 2026-11-13] S1 GLM — REGS_WRITE writes user words into the target's kernel stack (`kernel/src/entry.rs:591`, `kernel/src/mem.rs:69`, `kernel/src/sched.rs:690`). Word 3 is the ring-0 return address, and for a Blocked thread the syscall frame (RCX, R11) is exposed. Fix: keep a per-thread user register struct apart from the kstack, make REGS_READ/WRITE touch only that, and mask RFLAGS (IOPL=0, IF=1). Propose an ADR first (syscall contract change, NV accepts).
- [ ] S2 GLM — SET_ENTRY, THREAD_CREATE and NEW_THREAD accept any PC or stack pointer (`entry.rs:526`, `:626`, `:780`). Add one `is_user_addr()` helper (below `0x0000_8000_0000_0000`, not 0) and return EBADARG otherwise.
- [ ] S3 GLM (do next) — SET_TLS takes a non-canonical FS base, which faults in ring 0 at the next switch (`entry.rs:535`). Validate with `is_user_addr()` and return EBADARG. Until this lands, S3b's HAL check turns a bad base into a kernel panic, so any process can still halt the machine.
- [x NV done 2026-11-12 880983f] S3b NV — Assert a canonical user FS base in the HAL before `wrmsr` (`hal/x86_64/src/impl_x86_64.rs:1066`).
- [ ] S4 GLM — MAP, UNMAP and PROTECT check only alignment, so a user can map over the shared kernel window PML4[511] (`kernel/src/aspace.rs:209`). Require the whole range in user space, with overflow-checked math, and reject VA 0.
- [x NV done 2026-11-13 7ac6f6e] S5 NV — `walk_create` ORs PTE_USER into upper-level entries and splits kernel huge pages (`hal/x86_64/src/paging.rs:279`). Refuse walks into PML4 slots 256–511 and never set USER on a shared kernel entry.
- [x NV done 2026-11-13 06d018b] S6 NV — SMEP, SMAP and UMIP are off (`kernel-boot/src/boot.S:119`). Write the CPUID-checked CR4 code as a HAL function and file a Request for GLM to call it from `kernel-boot`. SMAP waits for a user-copy helper: record that in an ADR.
- [ ] S6b GLM — Call NV's CR4 hardening function from `kernel-boot` once S6 lands.
- [x NV done 2026-11-13 a865f5f] S7 NV — FMASK is `0x300`, so DF and AC reach the kernel (`hal/x86_64/src/syscall_entry.rs:46`). Clear IF, TF, DF, AC and NT (`0x47700`) and add `cld` to every interrupt and exception entry stub.
- [ ] S8 GLM — NEW_THREAD copies caps[1] with full rights and no GRANT check, and adds SEND on caps[2] (`entry.rs:~801`, `~822`). Route both through the GRANT-checked, rights-intersecting transfer in `kernel/src/syscall.rs:112` and `:144`, and check the cap type.
- [ ] S9 GLM — UNMAP with a huge page count loops with interrupts off (`aspace.rs:331`). Cap it at the region size and return EBADARG above that.
- [~ NV started 2026-11-13] S10 NV — `map_page` panics when no page-table frame is free (`hal/x86_64/src/paging.rs:~388`). Return an error.
- [ ] S10b GLM — Audit every `unwrap()`/`expect()` reachable from `entry::dispatch` and turn each into an error code. Tests and boot code may keep theirs.
- [~ DS started 2026-11-13] S11 — An `attack` userspace program (pattern: `sdk/src/bin/child.rs`) makes every bad call from S1–S10 and expects an error back. init runs it as a new marker step. The boot must still reach DONE. Add each case as soon as its S-task lands.
  - [~ DS started 2026-11-13] S11.1 — harness: `sdk::attack` runner + `child` argv "attack" mode + init marker step + baseline self-test cases (S1–S10 cases appended as they land).

## Phase H — Engineering

- [x NV done 2026-11-13 90b345d] E1 NV — `tools/build-all.sh`: build every userspace image in dependency order, then `kernel-boot` release. Must honour `CARGO_TARGET_DIR` and the `*_IMAGE` variables.
- [x NV done 2026-11-13 ca0dc44] E2 NV — `tools/qemu-test.sh`: call E1, boot the release kernel, require the DONE marker and `clean halt`, work on macOS (use `gtimeout` if present), and honour `SERIAL_LOG` and `CARGO_TARGET_DIR`.
- [x NV done 2026-11-13 5766b07] E3 NV — CI (`.github/workflows/ci.yml`) runs E2, `cargo test` and the userspace clippy line. Pushing is for the human. Done when it runs locally through `tools/qemu-test.sh`.
- [ ] E4 DS — Make the userspace clippy line in AGENTS.md section 5 pass with `-D warnings` (errors today in `sdk` bins `init`/`child`, and in `servers/process/src/bin/ps.rs:974`).
- [ ] E5 NV — Add the userspace clippy line to `tools/qemu-test.sh` once E4 lands.
- [ ] E6 DS — Source and build notes for every ELF in `personality/assets/` (one source file plus a reproducible build line each, and the musl MIT license noted), or a script that builds them.
- [ ] E7 DS — Remove the `.data` atomics workaround in `sdk/src/bin/init.rs:902` and its copy in ps. The real causes (kstack overflow, asm clobber) are fixed. The boot must still reach DONE.
- [x NV done 2026-11-13 66c3dcd] E8 NV — ADR-052: userspace drivers get MMIO/DMA through capabilities (MmioRegion + Frame caps; HAL traits stay kernel-internal; driver move waits for freeze lift).
- [x NV done 2026-11-13 603124d] E9 NV — README (honest status from PLAN.md 4a, build and boot steps), LICENSE-MIT, LICENSE-APACHE, `build/` and `graphify-out/` in `.gitignore`. Leave `repository` in Cargo.toml as is until the human names the URL.
- [x NV done 2026-11-13 fae3dab] E10 NV — PLAN.md section 5 says PLAN.md and TASKS.md live in `docs/`, but they are at the root. Fix the text in PLAN.md to match (do not move the files: the supervisor reads them at the root).
- [x NV done 2026-11-13 243bd24] E11 NV (do next) — The `hal/x86_64` tests never run: `impl_x86_64` is `#[cfg(target_arch = "x86_64")]` and the host is arm64, so `cargo test -p hal-x86-64` reports 0 tests (S3b's new tests included). Move pure, register-free logic (address checks, PTE math, PCI address building) into a module compiled on every host, and make the gate fail if the crate's test count is 0.

## Requests

- [Request] GLM — call `hal::enable_supervisor_protections()` from kernel-boot (CR4 SMEP/UMIP hardening, S6). The HAL function is written (`hal/x86_64/src/impl_x86_64.rs`) and CPUID-enables SMEP + UMIP only; SMAP waits for a user-copy helper (ADR-051). Wiring the call into `kernel-boot` (boot.S or `kernel_main`) is GLM area.
- [Request] GLM — change `PagingBackend::map_page` (kernel/src/aspace.rs) to return `Result<(), VmmError>` (and update its mocks in entry.rs/init.rs + all callers) so S10 (hal/x86_64/src/paging.rs) can return an error instead of panicking when `walk_create` fails (no free page-table frame or S5 kernel-slot refusal). Unblocks NV's S10.

## Blockers

(none)

## Decisions needed

(none)
