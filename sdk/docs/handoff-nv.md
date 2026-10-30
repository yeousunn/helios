# Handoff: DS track → NV (user-directed, 2026-10-30)

The user directed that the DeepSeek track (Phase 1 "first userspace test
process" + the early Phase 2 server starts) transfers to **Nemotron (NV)**.
This document is the complete pickup kit: what exists, what remains, how to
build and verify. Per the coordination protocol this handoff was recorded in
`TASKS.md`; the usual directory boundary is lifted **for this track only** —
NV may now write `servers/` and `sdk/` (still no touching `kernel/`, `caps/`,
`ipc/`, and everything else outside NV's areas as usual).

## 1. What is complete (committed, all host-tested)

| piece | where | state |
|---|---|---|
| Process server core: codecs, CONNECT/SPAWN/WAIT/KILL, serving loop, reaper | `servers/process/src/` | 35 tests |
| VFS server core: codecs, ramfs, handle tables, serving loop | `servers/vfs/src/` | 29 tests |
| SDK runtime: syscalls (x86_64 asm + mock-tested), bootstrap recv/deliver, method tables, layout consts, window/bump-heap/ELF/loader modules | `sdk/src/` | 38 tests |
| init v2 (launcher): heap, embedded-PS ELF load, package delivery, ready handshake, death-notification reap | `sdk/src/bin/init.rs` | typechecks; runbook markers 1–9 |
| `ps` binary (first server process): package → heap → allocator smoke → service-ep mint → ready callback → exit | `servers/process/src/bin/ps.rs` | typechecks |
| Runbook with exact build commands + serial markers | `sdk/docs/bringup-smoke.md` | — |
| Ratified interfaces | `sdk/docs/{syscall-abi,ipc-schema}.md`, ADR-005/007/009/017/019/020/023 | all accepted |

All quality gates pass: `cargo test -p sdk -p process -p vfs` (102 tests),
clippy `-D warnings`, fmt.

## 2. What remains (in order)

1. **QEMU smoke (this is NV's existing work, not new):** context backend
   (`sched::ContextBackend`, per-thread SP from `hal` `USER_STACK_TOP`),
   trap/syscall entry marshaling into `kernel::entry::dispatch`, image
   pipeline staging (`x86_64-unknown-none` target provisioning is required —
   not installed on the DS host; the full init/ps code typechecks as x86_64
   ELF objects).
   Acceptance = the 9 markers in `sdk/docs/bringup-smoke.md` + clean exit 0
   (runbook §2), asserted by `tests/`/`tools/qemu-test.sh` (ADR-013 codes).
2. **PS serve loop** (post-smoke): CONNECT dispatch over the service endpoint,
   connection threads (PS can now create its own threads: it holds Factory +
   its self-AS cap per its package), publishing the service endpoint to init
   (a `ready` follow-up message is the natural v0 channel), then implement
   `EXEC`/`FORK`/`THREAD_CREATE` handlers (`servers/process/src/proto.rs` has
   the labels; `AddressSpace::FORK` is live per ADR-024).
3. **VFS binary** (mirror of `ps.rs`) + `READ_BULK` (needs a scratch
   map-into-self; `sdk::window`/`loader` show the pattern) + `now_ns` via the
   future timer service.
4. **Mock/test conventions to preserve:** trait-inversion runtime
   (`KernelOps`/`Transport`/`Windows` traits + mock impls in `test_support.rs`),
   hostile-message fuzz tests, golden-byte layout tests, `no_std + alloc`
   crate profile (ADR-020).

## 3. Build / verify cheatsheet

```text
# host tests (fast, no toolchain extras)
cargo test -p sdk -p process -p vfs
cargo clippy -p sdk -p process -p vfs --all-targets -- -D warnings

# target binaries (bare-metal profile; needs x86_64-unknown-none)
cargo build -p process --bin ps --features user --target x86_64-unknown-none --release
PS_IMAGE=target/x86_64-unknown-none/release/ps \
  cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release

# typecheck without the bare-metal target (works on this host):
cargo check -p sdk --bin init --features user --target x86_64-apple-darwin --release
cargo check -p process --bin ps --features user --target x86_64-apple-darwin --release
```

## 4. Design invariants to keep (ratified — changes need ADRs)

- All authority is capabilities; transfers enforce `GRANT` on the sender
  (the ADR-023 §5 rights adjustments were derived from this — don't regress).
- Wire format/status/labels come from `ipc/`; invoke method ids from
  `sdk::methods` (keep in sync with `kernel/src/entry.rs` dispatch).
- Window = one 4 KiB frame (page-granular `AS::MAP`); VA bases per server in
  `sdk::layout`; heap = bump over carved frames (ADR-020).
- Bootstrap package = `sdk::bootstrap` (header + ≤4-cap chunks, handle 1);
  PS protocol extensions ride the optional tail (`tail[0] = Factory`).
