# Bring-up runbook — first userspace process (Phase 1 smoke)

Single reference for the three sides of the first QEMU smoke (kernel / arch entry /
userspace), so the contracts meet in one place before wiring. Owners: GLM (kernel),
NV (arch entry + image pipeline + harness), DS (userspace binary + SDK).

## 1. Boot chain

```
hal/x86_64 _start
  → kernel::boot::early_init(writer, level, exit)            (ADR-001)
  → frame::init(usable regions)                              (ADR-003)
  → register backends: PagingBackend (NV), ContextBackend (NV),
    TrapDecode (NV, ADR-012), CurrentContext (NV)            (ADR-008/010)
  → kernel::init::start(regions) → InitLaunch { pid, thread, bootinfo }  (ADR-018)
  → arch maps init's image + first stack (stack base =
    USER_STACK_TOP − size), enters ELF entry in ring 3
      rdi = pointer to the BootInfo block (inside init's first stack page)
```

`USER_STACK_TOP = 0x0000_7FFF_FFFF_F000` is canonical in `hal/x86_64/src/layout.rs`
and mirrored in `sdk/src/layout.rs` — **verified identical**.

BootInfo block: writer `kernel::init::write_bootinfo` (ADR-018); parser
`sdk::bootinfo` with golden-bytes tests pinning the same byte map.

## 2. Userspace side (`sdk/bin/init`, feature `user`)

```text
cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release
```

- `--release` is required (root profile sets `panic = "abort"`).
- Entry: `_start(rdi = BootInfo ptr)`; terminates via syscall 8.
- Steps and debug-EP markers (kernel logs `tag + words`; assert on the marker in `w0`):

| step | `w0` | `w1` | meaning |
|---|---|---|---|
| 1 | `0x494e495400000001` | 0 | alive |
| 2 | `...0002` | region count | BootInfo parsed |
| 3 | `...0003` | endpoint handle | Factory `NEW_ENDPOINT` ok |
| 4 | `...0004` | `0x123456789abcdef0` | IPC v1 self round-trip ok |
| 5 | `...0005` | 0 | `cap_revoke(DELETE)` ok |
| 6 | `...0006` | heap KiB (1024) | heap mapped (`self_as` + Region, ADR-023) |
| 7 | `...0007` | child pid (or `0xFFFFFFFFFFFFFFFF` = no embedded image) | PS spawned: ELF loaded, package delivered |
| 8 | `...0008` | PS's service-endpoint handle | PS sent its ready callback over IPC (`READY_MAGIC` in `w0`) — proves the child ran its own code |
| 9 | `...0009` | death-notification tag | PS exited, reaped via NOTIFIED |
| DONE | `0x494e49540000000f` | 0 | all passed |
| fail | exit code `0xDEAD_0000_00SS_EEEE` (SS = step, EEEE = errno) | | |

Build with the process server embedded (pipeline, ADR-023):

```text
cargo build -p process --bin ps --features user --target x86_64-unknown-none --release
PS_IMAGE=target/x86_64-unknown-none/release/ps \
  cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release
```

ADR-023 kernel prerequisites (requested from GLM): BootInfo `self_as`@20 (`MAP|GRANT`),
init Region caps carry `GRANT`, `NEW_NOTIFICATION` installs `SIGNAL|RECV|GRANT`,
`NEW_THREAD`'s thread cap gains `GRANT` — all transfers enforce `GRANT` in
`resolve_transfers`, so launchers cannot pass zero-rights caps onward.

- Success exit status: 0 (init calls `exit(0)`; kernel should halt cleanly with the
  registered exit hook so the harness sees a deterministic QEMU exit — requested of GLM).
- Expected serial flow: five `userspace[debug]:` lines (steps 1–5), then the DONE line.

## 3. Syscall register contract (syscall-abi §2 ≙ `sdk/src/syscall.rs` asm)

| role | reg |
|---|---|
| number | `rax` |
| cap, tag, w0..w3 | `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` |
| return status | `rax` |
| return tag, w0..w3 | `rdx`, `rsi`, `rdi`, `r8`, `r9` |
| clobbered by `syscall` | `rcx`, `r11` |

- Parked `recv`/`reply_recv`: `dispatch` returns the `i32::MIN` parked sentinel — the
  arch entry must **not** return to userspace; switch away and re-enter via
  `entry::park_result` on resume (ADR-019 §1). The sentinel never reaches userspace.
- `invoke` returns new handles in `w0` (`install_ret`).

## 4. What the smoke exercises (init v1) — kernel checklist

- Factory `NEW_ENDPOINT` (handle in `w0`) — exists.
- `send` to own endpoint (mailbox store) + `recv` (message back, tag/words) — exists.
- `cap_revoke` DELETE — exists.
- `exit(0)` as the only live thread → clean halt via exit hook (ADR-002/013) — **open**.
- init v1 uses **none** of: `NEW_THREAD`, mappings, fault pools, notifications.

## 5. Next milestone after the smoke (init v2)

Init spawns a child thread via `Factory::NEW_THREAD` (ADR-017 packing; w0 = entry,
caps `[aspace, fault?, bootstrap?]`) and delivers an ADR-009 package over the
bootstrap endpoint, then the child pings init over its own endpoint and exits,
firing `BIND_DEATH_NOTIFICATION`. Requires from the arch/kernel side:
initial-PC wired through `ContextBackend` (ADR-019 §4, landed kernel-side) and a
per-thread SP policy on the shared v0 VMM.

## 6. Environment prerequisites

- `rustup target add x86_64-unknown-none` (not present on the DS host; download was
  blocked — pipeline/CI must provision it).
- QEMU (`tools/qemu-test.sh` handles accel selection); release profile `panic=abort`.
- Local de-risking already done: init (asm included) codegens to x86_64 ELF objects;
  `_start` is a defined `T` symbol.
