# Helios

> **Experimental.** Helios is a research project. It is not secure enough to run untrusted code, its interfaces change without notice, and it should not be used for anything that matters. Most of the code is written by AI coding agents working unattended (see [How it is built](#how-it-is-built)).

Helios is a capability microkernel written in Rust. The kernel provides only address spaces, threads, IPC, capabilities, interrupts and scheduling. Drivers, filesystems, networking, the POSIX layer and everything else run as isolated userspace servers.

## What we are trying to achieve

One kernel, configured at build time, that runs on anything from a microcontroller with only a memory protection unit to a many-core NUMA server or an HPC compute node. It should be:

- **Multi-user and multi-threaded**, with each user's memory, CPU time and kernel objects isolated by capabilities.
- **Asynchronous by design**, with notifications, ports and capability-checked rings instead of a second, unchecked syscall surface.
- **Secure in every way the hardware allows**, from memory safety and capability confinement to timing-channel protection, measured boot and post-quantum image signing.
- **Portable** across x86_64, aarch64 and riscv64, then 32-bit microcontrollers, with CHERI as a research target.
- **Provable**, with the core objects checked in Verus, panic freedom checked with Kani, and protocols modelled in TLA+.

No existing system combines all of this. seL4 is verified but does not scale past a big lock. NrOS scales but is not verified. Tock and Hubris own the microcontroller end with a different resource model. `PLAN.md` describes how Helios tries to combine them, including ten research bets with success and kill criteria. `docs/research/BIBLIOGRAPHY.md` lists the papers each design choice rests on.

## Status (2026-11-14)

- x86_64 only, on one CPU, in QEMU. A release build boots through init, the VFS, the process server, the console, a scripted shell with a pipeline, static musl programs, a busybox applet, the auth server and `/login`, then halts cleanly.
- 286 host unit tests pass. fmt and clippy are clean for host and userspace crates.
- The security holes found in the 2026-11 review (S1 to S11) are fixed, with host tests and a QEMU attack suite. One more (REGS_WRITE entry PC, S2b) is being fixed now.
- `unsafe` is being confined to the HAL and a few allowlisted modules. A gate script fails any new `unsafe` outside the allowlist.
- Userspace virtio-blk, virtio-net and virtio-gpu drivers exist but are not wired into the boot yet.
- The aarch64 and riscv64 HAL crates have early trap, context and paging code. The system does not boot on them yet.
- Fixed limits remain: 16 processes, 16 address spaces, 64 threads, 64 kernel objects. Milestone M1 removes them.

## Checklist

The roadmap is milestone based. A milestone is done when its exit checks pass, not on a date. `TASKS.md` holds the live task board.

- [x] Phase H: security hardening (S1 to S11) and engineering gaps (E1 to E11)
- [ ] **M0. Baseline and guardrails** (in progress)
  - [x] Unsafe allowlist gate (`tools/check-unsafe.sh`)
  - [ ] REGS_WRITE entry PC validation (S2b) and its attack case
  - [ ] Supply-chain checks (cargo-deny, cargo-vet)
  - [ ] Benchmark suite with regression checks (IPC, context switch, map)
  - [ ] Machine-readable ABI specification (`spec/abi`)
  - [ ] Kani panic-freedom proofs for syscall decoding
  - [ ] `unsafe` removed from drivers, graphics, servers, the SDK and the POSIX personality
- [ ] **M1. Object model v2:** Untyped memory, Retype and Revoke, caller-chosen capability slots, Verus proofs of the capability table
- [ ] **M2. Time:** scheduling contexts, preemption, a user-level scheduler with a safe fallback
- [ ] **M3. Multicore:** per-core dispatch and node-replicated kernel state, no global lock
- [ ] **M4. Asynchrony:** ports and capability rings, with a TLA+ model checked first
- [ ] **M5. Multi-user:** login sessions as revocable capability trees, a trusted path, an audit log, driver restart
- [ ] **M6. Portability:** aarch64 and riscv64 at full parity, and a microcontroller profile
- [ ] **M7. Hardening:** CFI on every architecture, IOMMU-only DMA, security domains with timing-channel protection, fuzzing, measured boot
- [ ] **M8. Scale and HPC:** NUMA-aware memory, tiering, core grants, an HPC profile
- [ ] **M9. Desktop and compatibility:** real hardware drivers, a compositor, dynamic Linux binaries

## Build and boot

You need a Rust toolchain (rustup, stable) with the `x86_64-unknown-none` target, QEMU (`qemu-system-x86_64`) and, on macOS, GNU coreutils for `gtimeout`.

```
rustup target add x86_64-unknown-none
tools/qemu-test.sh
```

`tools/qemu-test.sh` builds every userspace image and the release kernel (through `tools/build-all.sh`), runs the unsafe check and the userspace clippy line, boots QEMU, and requires the `0x494e49540000000f` DONE marker and `clean halt` in the serial log. It honours `CARGO_TARGET_DIR`, `SERIAL_LOG` and the `*_IMAGE` variables.

Host tests:

```
cargo test --workspace --exclude kernel-boot
```

## How it is built

Helios is developed by AI coding agents running unattended in [opencode](https://opencode.ai), each on a free model endpoint hosted by NVIDIA. Each agent owns a set of directories, and a commit hook plus a sandbox enforce that ownership.

| Agent | Model | Owns |
|---|---|---|
| Coordinator | NVIDIA Nemotron 3.5 Super (`nemotron-3.5-super-vl-120b-a12b`) | HAL, tools, benchmarks, tests, CI, docs |
| Kernel | NVIDIA Nemotron 3 Ultra (`nemotron-3-ultra-550b-a55b`), standing in for Z.ai GLM 5.3 Flash | kernel, boot, capabilities, IPC, ABI spec |
| Userspace | NVIDIA Nemotron 3 Ultra (`nemotron-3-ultra-550b-a55b`), replacing DeepSeek V4.1 Flash, which was too slow | system servers, SDK |
| Drivers | Poolside Laguna XS 2.1 (`laguna-xs-2.1`) | drivers, graphics |
| POSIX | StepFun Step 5 Preview (`step-5-preview`) | POSIX/Linux personality |

The agents never talk to each other directly. They coordinate through:
- `TASKS.md`, the task board
- `docs/DECISIONS.md`, an append-only decision log
- design proposals (RFCs) in `docs/rfcs/`
- git history

A supervisor in `tools/agents/` runs each agent in fresh cycles inside a macOS sandbox. After every cycle it audits the new commits, and it stops every agent on an ownership violation, a history rewrite or an edit to old decisions.

**Other tools:**
- Rust, Cargo, rustfmt and clippy
- QEMU
- `tmux` and `caffeinate` to keep the agents running
- Planned for the proof and supply-chain work: Verus, Kani, Flux, TLA+, cargo-deny and cargo-vet

## Repository layout

```
kernel/        microkernel core (no_std)
kernel-boot/   boot glue and the kernel binary
hal/           hardware abstraction: traits plus x86_64, aarch64, riscv64 backends
caps/  ipc/    capability types and the IPC wire format
servers/       process, VFS, console, auth, net servers
sdk/           userspace runtime, init, attack and test programs
personality/   POSIX/Linux syscall emulation and test programs
drivers/       userspace virtio drivers
graphics/      virtio-gpu driver, framebuffer, compositor and widget primitives
tools/         build, boot, gate scripts and the agent supervisor
docs/          decision log, research bibliography, history
PLAN.md        architecture and roadmap
TASKS.md       task board
```

## License

Dual-licensed under the MIT License or the Apache License, Version 2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
