# Helios — A Portable Rust Microkernel

A capability-secure, multi-user microkernel written in Rust. The kernel provides only
address spaces, threads, IPC, capabilities, interrupts, and a scheduler. Everything else
(drivers, filesystems, networking, graphics) runs as userspace servers.

## Status (2026-11-12, Phase H hardening / feature freeze)

The project is in a hardening phase (ADR-049). No new features are being added while the
security holes S1–S11 and engineering gaps E1–E10 on TASKS.md are closed.

- **x86_64 only, single CPU**, cooperative scheduling with a PIT tick and no preemption.
- A clean release build boots in QEMU through init, VFS, process server, console, a
  scripted shell with a pipeline, a static musl program (printf, file I/O, mmap, stat,
  readdir), the auth server and `/login`, then halts cleanly.
- **207 host unit tests pass.** Host clippy and fmt are clean.
- **Not secure.** A user process can take control of the kernel (REGS_WRITE writes the
  kernel stack, MAP reaches the shared kernel window, no SMEP/SMAP). Do not run untrusted
  code on it. See security tasks S1–S10 on TASKS.md.
- Fixed limits: 16 processes, 16 address spaces, 64 threads, 64 kernel objects.

See `PLAN.md` for the full roadmap and `docs/DECISIONS.md` for design decisions (ADRs).

## Build & boot (full-system QEMU smoke)

From the repo root, with the nightly toolchain and `gtimeout` available:

```
T="--target x86_64-unknown-none --release --features user"
cargo build -p sdk --bin child $T \
 && cargo build -p console $T \
 && cargo build -p auth $T \
 && cargo build -p personality --bins $T \
 && cargo build -p vfs $T \
 && cargo build -p process $T \
 && cargo build -p sdk --bin init $T \
 && cargo build -p kernel-boot --target x86_64-unknown-none --release
```

Then boot (builds everything via `tools/build-all.sh` first if needed):

```
tools/qemu-test.sh
```

A good boot shows the `0x494e49540000000f` DONE marker and `all threads exited — clean halt`,
and QEMU exits with status 1. Serial output is written to `$SERIAL_LOG`
(default `.agents/serial-nv.log`).

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0.
See `LICENSE-MIT` and `LICENSE-APACHE`.

## Repository

The `repository` field in `Cargo.toml` is intentionally left as a placeholder until the
human owner names the canonical URL.
