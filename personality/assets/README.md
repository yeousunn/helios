# `personality/assets` — emulated Linux-ABI test binaries

These are the static `x86_64-linux` ELF programs the `/linrun` emulator
(`personality/src/bin/linrun.rs`) runs. `linrun` loads one as a foreign thread,
flags it with `Thread::SET_FOREIGN`, and serves its raw Linux syscalls back
through the personality layer (ADR-044 / ADR-046). Swap the embedded one by
editing `static LIN_ELF` in `linrun.rs` (default: `musl_time`).

The binaries are **build outputs**, not source. Every one now has a source file
in `src/` and a pinned build line; `build.sh` rebuilds them all.

## Toolchain

* **zig 0.16.x** (`zig cc`, which bundles its own clang/LLD and musl). Pinned
  compiler identity in the committed `.comment`: `Homebrew clang version
  21.1.8` / `Linker: Homebrew LLD 21.1.8` (zig 0.16.0).
* All flags: `-target x86_64-linux-musl -static -Os -s` (plus `-nostdlib` for
  the two freestanding, libc-free programs).

A different zig/clang will build working binaries but not necessarily
byte-identical ones.

## Rebuild

```sh
personality/assets/build.sh              # build into a temp dir, report fidelity
personality/assets/build.sh --in-place   # regenerate the committed assets
personality/assets/build.sh /tmp/out     # build into /tmp/out
```

## musl license

The `musl_*` binaries statically link [musl libc](https://musl.libc.org),
which is **MIT-licensed** (© 2005-2020 Rich Felker et al.); zig ships a musl
build for `x86_64-linux-musl`. `lin_hello` and `lin_args` link no libc at all
(`-nostdlib`, raw `syscall` only).

## Inventory

| ELF | source | expected output | exercises |
|---|---|---|---|
| `lin_hello` | `src/lin_hello.s` | `helios-linux-abi` | freestanding raw `write`+`exit`; first foreign artifact |
| `lin_args` | `src/lin_args.s` | `argv[0]` (= `helios-linux-abi`) | crafted Linux startup stack (argc/argv) |
| `musl_noop` | `src/musl_noop.c` | (none) | musl startup + exit |
| `musl_write` | `src/musl_write.c` | `helios-musl-write` | bare `write`, no stdio |
| `musl_exit` | `src/musl_exit.c` | `helios-musl-write` | `_exit` (exit_group) |
| `musl_hello` | `src/musl_hello.c` | `helios-musl-hello` | musl `printf` → `ioctl`+`writev` |
| `musl_open` | `src/musl_open.c` | `helios-open-ok:helios-vfs-ok` | `open`/`read`/`close` over the VFS |
| `musl_mmap` | `src/musl_mmap.c` | `helios-mmap:ok` | `mmap(MAP_ANONYMOUS)` |
| `musl_ls` | `src/musl_ls.c` | entries, then `helios-ls-done:<n>` | `opendir`/`readdir` (getdents64) |
| `musl_stat` | `src/musl_stat.c` | `size=13 mode=644` | `stat`; hand-rolled integer formatting |
| `musl_sig` | `src/musl_sig.c` | `helios-before-raise` (exit 143) | `raise(SIGTERM)` self-delivery |
| `musl_cwd` | `src/musl_cwd.c` | `cwd:/` then `exe:/linrun` | `getcwd` + `readlink("/proc/self/exe")` |
| `musl_time` | `src/musl_time.c` | `mono: …` then `tls: fs=… ok` then `helios-musl-time: ALL OK` | `clock_gettime` (MONOTONIC/REALTIME), a real `nanosleep`, `arch_prctl(ARCH_GET_FS)`, plus `getcwd`/`readlink` |
| `musl_all` | `src/musl_all.c` | `helios-musl: printf ok` … `helios-musl: ALL OK` | printf + I/O + stat + readdir + mmap in one run |

## Fidelity

11 of the 13 rebuild **byte-for-byte identical** to the committed assets
(verified by `build.sh`). Two are behaviorally-equivalent reconstructions whose
exact originals were not retained, so they differ only cosmetically:

* `musl_stat` — same output (`size=<n> mode=<octal>\n`); the original's exact
  register allocation / frame layout for the hand-rolled itoa was not
  reproduced.
* `musl_all` — same strings, same control flow (its `main` compiles to the same
  instructions); the difference is a small amount of extra linked libc, not
  program behavior.

Both produce the outputs in the table above and exit the same way.

## busybox (Phase 3)

`busybox` is a minimal static `x86_64-linux-musl` busybox build used to run
unmodified Linux multi-call applets through the POSIX emulator (`linrun`, which
embeds it and dispatches on `argv[0]`). It is **not** one of the hand-written
demo programs above; it is third-party software fetched and built by
`busybox.build.sh` (pinned `busybox-1.36.1`, zig's bundled musl), with a small
applet set (echo, cat, ls, pwd, uname, id, head, wc, printf, seq, cut, env,
test, true/false, `[[`). `NUM_APPLETS` is 18; rebuild with:

```sh
personality/assets/busybox.build.sh            # writes ./busybox
```

**License:** busybox is **GPLv2** (© 2000-2024 Erik Andersen, Rob Landley,
Denys Vlasenko et al.; see busybox's `LICENSE`). It is a build output, like the
`musl_*` programs, and is statically linked against MIT-licensed musl libc.
