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
| 8 | `...0008` | heap KiB | PS sent its ready callback (`READY_MAGIC` in `w0`); its service endpoint arrives as capability descriptor 0 |
| 9 | `...0009` | connection id (1) | `CONNECT` round-trip over the service endpoint: init transfers session notif + arg/result frames (4 KiB each), PS maps both windows and replies with the connection endpoint (descriptor 0) |
| 10 | `...000a` | child pid | `SPAWN` over the connection: argv blob in the arg window (`(off<<32)\|len` in `w2`); PS loads its embedded child image, crafts the stack, replies with pid + out-caps |
| 11 | `...000b` | child exit status (42) | `WAIT`: PS parks on the child's death notification and reports the raw status (kernel payload: bit 0 = event, bits 32.. = status) |
| 7 | `...0007` | VFS pid | init spawned the **VFS first** (it serves program images) |
| 8 | `...0008` | VFS heap KiB | VFS ready callback (service endpoint as capability, SEND\|GRANT) |
| 9 | `...0009` | PS pid | init spawned the process server |
| 10 | `...000a` | PS heap KiB | PS ready callback |
| 11 | `...000b` | conn id | init `CONNECT` round-trip to PS |
| 12 | `...000c` | child pid | `SPAWN` carries the VFS service ep + the program path span; **PS loads the child ELF through the VFS** (`CONNECT`/`OPEN("/child")`/`READ` loop → heap → ELF load) |
| 13 | `...000d` | 42 | `WAIT`: child ran and exit-status propagated |
| 14 | `...000e` | bytes read (13) | init `CONNECT`s to the VFS, `OPEN("/hello")`, `READ`, byte-verifies `"helios-vfs-ok"` |
| 16 | `...0010` | posix pid | `SPAWN("/posix")` with the VFS cap: the demo runs the full personality runtime (bootstrap → heap → VFS client → open/read/write over IPC) |
| 17 | `...0011` | 77 (`0x4d`) | `WAIT` for the demo: it byte-verified `hello`, created+verified `posix-log`, exited 77 |
| 18 | `...0012` | console pid | console server spawned (holds the delegated debug endpoint) |
| 19 | `...0013` | service handle | console ready: its endpoint is later supplied to children as stdio |
| — | `tag=0x301` | text words | any `console::WRITE` line on the serial (e.g. the demo's `helios-posix-ok\n` at `w=[0x702d736f696c6568 0x0a6b6f2d7869736f ...]`) |
| 20 | `...0014` | sh pid | init spawns `/sh` (the scripted shell; vfs + stdout caps) |
| 21 | `...0015` | 0 | `WAIT` for the shell: full script — builtins, `/ls`, `/cat`, `/echo`, the pipeline `cat hello posix-log | wc` (token `bytes=28 lines=0`), then `exec child 9` (the shell process becomes the child; WAIT observes its real status 9) — printed `sh ok` |
| 22 | `...0016` | linrun pid | init spawns `/linrun` (caps: vfs, NULL, console, route-endpoint). `linrun` is a userspace **Linux-ABI emulator**: it loads an embedded static ELF, creates a THREAD_CREATE'd thread, `SET_FOREIGN`s it (its traps route raw to the emulator), and serves `open`/`read`/`write`/`mmap`/… back through the VFS/console |
| 23 | `...0017` | 0 | `WAIT` for `linrun`: the emulated thread ran the embedded binary to completion and exited |
| DONE | `0x494e49540000000f` | 0 | all passed (all servers reaped; clean halt) |

### musl (Linux-ABI) milestone

`linrun` runs a real static `zig cc -target x86_64-linux-musl -static` binary
end-to-end: musl startup (`arch_prctl(ARCH_SET_FS)` → `Thread::SET_TLS`;
`set_tid_address`), then `printf` (ioctl + `writev`), file I/O
(`open`/`openat`/`read`/`close` → the VFS client), `mmap`/`brk` (region
carve+map), and `exit_group`. Swap the embedded asset by editing `LIN_ELF` in
`personality/src/bin/linrun.rs` (`assets/{musl_all,musl_hello,musl_open,musl_mmap,musl_ls,musl_stat,musl_sig,musl_write,musl_noop}`):

```text
# musl_all (the default) — one run exercising the whole surface:
helios-musl: printf ok / read: helios-vfs-ok / mmap: ok / stat: size=13 / readdir: 11 entries / ALL OK
helios-musl-hello      # musl_hello — printf only
helios-open-ok:helios-vfs-ok   # musl_open  — open + read + write
helios-mmap:ok         # musl_mmap  — mmap(MAP_ANONYMOUS)
<entries>              # musl_ls    — opendir + readdir
size=13 mode=644       # musl_stat  — stat
<pre-raise line> then 143  # musl_sig — raise(SIGTERM)
```

The emulator's stdout is buffered and flushed after each foreign syscall reply;
foreign replies restore the full trap-time user GPR set (only `rax` = the Linux
result), and the emulated thread runs on a dedicated stack VA (the emulator's
own stack lives at `USER_STACK_TOP`).

### Pipeline console sequence (slice 14)

After the pre-pipeline commands the serial log shows, in order:

```
[pipe]  ok  L  R  | bytes=28 lines=0
 | sh ok
```

`[pipe]` = PS minted the pipe (ONE endpoint, rights-split caps); `L`/`R` = the
left (`cat`, stdout = write cap) and right (`wc`, stdin = read cap) children
spawned; the `wc` line is the consumer's output; `sh ok` is the shell's final
status check (pipeline statuses verified, plus the exec'd child's real exit).

### Redirection console sequence (slice 15)

```
echo >  note.txt | redirection works | cat > copy -> 0 | wc  <  hello  ->  0
bytes=13 lines=0 | sh ok
```

`echo > note.txt` = builtin write through the shell's VFS connection;
`redirection works` = `cat note.txt` reading it back; `cat > copy -> 0` =
external `cat hello` drained through a pipe into a file; `wc < hello -> 0` =
`hello` fed as the child's stdin (`bytes=13 lines=0`).

v0 conventions this smoke pins (all design §2.4/§2.6 provisional):

- **`SPAWN` packing:** `w1` = program `(off,len)` — ignored v0 (PS loads the image
  embedded via `CHILD_IMAGE`); `w2` = argv `(off << 32) | len`, blob read from the
  **arg window**; `w3` = env (unused). Reply `w0 = status, w1 = pid`; descriptor 0 =
  thread control (`CONTROL`), 1 = exit notification (`SIGNAL|RECV`).
- **Child stack convention:** at entry `sp = USER_STACK_TOP`; PS crafts the top
  page with `[sp-8] = argc`, `[sp-16] = argv[0] VA`; the entry stub captures both
  into registers **before any push**, then moves `sp` below the header. String
  bytes live at page offset 0x800 (parking them near the header got them
  clobbered by the child's own early stack frames).
- **`WAIT`** is blocking (parks the connection, design §2.6 note); it consumes the
  child's death-notification word built by the kernel on exit.
| fail | exit code `0xDEAD_0000_00SS_EEEE` (SS = step, EEEE = errno) | | |

Build with the process server embedded (pipeline, ADR-023):

```text
cargo build -p process --bin ps --features user --target x86_64-unknown-none --release
PS_IMAGE=target/x86_64-unknown-none/release/ps \
  cargo build -p sdk --bin init --features user --target x86_64-unknown-none --release
```

ADR-023 kernel prerequisites (all landed): BootInfo `self_as`@20 (`MAP|GRANT`),
init Region caps carry `GRANT`, `NEW_NOTIFICATION` installs `SIGNAL|RECV|GRANT`,
`NEW_THREAD`'s thread cap gains `GRANT` — all transfers enforce `GRANT` in
`resolve_transfers`, so launchers cannot pass zero-rights caps onward.

- On this workspace the build commands above can be simplified: `.cargo/config.toml`
  defaults `INIT_IMAGE`/`PS_IMAGE` to `target/x86_64-unknown-none/release/{init,ps}`
  (kernel-boot's build script embeds init; init's embeds ps).
- Success exit status: 0 (init calls `exit(0)`; the kernel's ADR-028/029 clean-halt
  path fires and QEMU exits with code 1, decoded to kernel code 0).
- Expected serial flow (M3, verified 2026-10-31): ten `userspace[debug]:` lines —
  steps 1–9 — then the DONE line, PS exit log, and `all threads exited — clean halt`.

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
