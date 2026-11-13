# Helios — A Portable Rust Microkernel

**Working title:** Helios
**Language:** Rust (no_std kernel, std userspace)
**Targets:** x86_64, aarch64, riscv64 (extensible to others via HAL)
**Goal:** A capability-secure, multi-user, microkernel OS that runs on desktop and mobile hardware, and can run most existing Linux / Windows / macOS applications through userspace compatibility personalities.

---

## 1. Design Philosophy

1. **Minimality in the kernel.** The kernel provides only: address spaces, threads, IPC, capabilities, interrupts, and a scheduler. Everything else — drivers, filesystems, network stack, graphics — runs as userspace servers.
2. **Capabilities everywhere.** Every resource (memory, ports, files, devices, IPC endpoints) is an unforgeable capability. No ambient authority. This is the foundation of multi-user security and sandboxing.
3. **Portability through a thin HAL.** Architecture-specific code lives in one crate per arch behind a stable `hal` trait surface. The kernel never touches registers directly.
4. **Safety-first Rust.** `#![no_std]`, `#![forbid(unsafe_code)]` in all kernel crates except `kernel-hal-*` and tiny `unsafe` islands in core memory management, each justified with `// SAFETY:` comments and Miri/Kani-checked where possible.
5. **Compatibility as a first-class personality.** Linux/Win32/macOS apps run in userspace "personality servers" (seccomp-style trampolines + syscall translation), NOT in the kernel. The kernel only needs one syscall: message-passing.

## 2. Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│ Userspace                                                     │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────┐  │
│  │ POSIX      │ │ Win32      │ │ macOS      │ │ Native    │  │
│  │ personality│ │ personality│ │ personality│ │ apps      │  │
│  │ (Linux     │ │ (WINE-like)│ │ (Darling-  │ │ (Helios   │  │
│  │  syscall   │ │            │ │  like)     │ │  SDK)     │  │
│  │  emulation)│ │            │ │            │ │           │  │
│  └─────┬──────┘ └─────┬──────┘ └─────┬──────┘ └────┬──────┘  │
│        │              │              │             │         │
│  ┌─────┴──────────────┴──────────────┴─────────────┴──────┐  │
│  │ System servers: VFS | netstack | GPU/comp | audio |    │  │
│  │ device manager | auth/login | package manager          │  │
│  └────────────────────────┬───────────────────────────────┘  │
├──────────────────────────── IPC ─────────────────────────────┤
│ Kernel:                                                       │
│  • Capabilities & capability table      • IPC (sync + async)  │
│  • Address spaces / paging              • Threads & scheduler │
│  • Interrupt routing                    • Basic timers        │
├──────────────────────────────────────────────────────────────┤
│ HAL (per-arch): uart | gic/lapic | pagetable | plic | SBI |   │
│ UEFI | device tree | ACPI                                     │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 Kernel Primitives (the entire kernel API)

| Primitive | Description |
|---|---|
| `AddressSpace` | Create/destroy/modify virtual address spaces, map frames |
| `Thread` | Create threads in an address space, register state |
| `Endpoint` | Typed IPC channel; send/receive/recv with capability transfer |
| `Notification` | Lightweight async signal (futex-like) |
| `Capability` | Token granting a right on an object; delegable, revocable, maskable |
| `IRQ` | Register userspace handler for a hardware interrupt line |
| `Frame` | Physical memory grant |

Everything else (syscalls like `open`, `fork`, `socket`) is implemented by userspace servers speaking this primitive protocol.

### 2.2 Security Model

- **Capability-based access control (primary).** Processes inherit capabilities from their launcher; the login/auth server mints user-scoped capabilities. Kernel-enforced; unforgeable; revocable via "revoke + echo" (seL4-style).
- **Multi-user:** UID/GID-like labels; auth server owns password/key material (never in kernel); each user gets isolated capability namespace. User switching = capability re-minting, not kernel state changes.
- **Mandatory isolation:** every app runs sandboxed by default (no ambient filesystem/network caps). File dialogs, network prompts = capability grants from user via system UI.
- **Hardening path:** formal verification ambitions for the IPC/capability core (Kani proofs, then seL4-style proof where feasible). Fuzz every kernel entrypoint (ipc fuzzing harness in CI).

### 2.3 Scheduling

- Priority-aware multi-queue scheduler, tickless, deadline hints for UI/audio threads.
- Bandwidth reservation per capability (a misbehaving app cannot starve the system) — needed for mobile power/responsiveness goals.
- Big.LITTLE aware placement on aarch64 via platform descriptor.

### 2.4 Memory

- Physical frame allocator per-NUMA-node (start: simple free-list).
- Slab/byte allocators over `alloc` with a kernel-crate `GlobalAlloc` impl; page-granular user mappings.
- Copy-on-write fork (userland semantics live in the process server, kernel provides COW map primitive).
- demand paging + page-cache ownership lives in VFS server, kernel swaps in pages on fault via pager protocol.

### 2.5 IPC

- Fast path: registered shared-memory ring + doorbell notification (zero-copy for bulk data).
- Control path: synchronous capability-passing call (send → receive reply), ~100ns target on modern x86_64.
- Async message queues for servers; capability transfer is atomic with message send (prevents TOCTOU on grants).

## 3. Compatibility Strategy (honest scoping)

Binary compatibility with all three ecosystems is a multi-year effort. Phased honestly:

| Phase | Deliverable | Notes |
|---|---|---|
| 1 | **POSIX personality** | Linux syscalls emulated by a personality server + glibc/musl loader; run unmodified static musl binaries first |
| 2 | Linux ELF dynamic linking | ld.so interception, /proc, futexes, epoll emulation |
| 3 | GUI | Wayland compositor runs as system server; XWayland for X11 apps |
| 4 | **Win32 personality** | WINE-style: PE loader + win32 API implemented over Helios servers; DirectX→Vulkan |
| 5 | **macOS personality** | Darling-style: Mach-O loader, Mach ports over IPC, CoreFoundation subset |

The kernel itself needs **zero** changes for each personality — this is the payoff of the microkernel design. Plan assumes phases 1–3 for a "usable desktop OS" milestone; 4–5 are long-tail community efforts.

## 4. Roadmap

Milestones, in order. No dates: a phase is done when its exit check passes, not when a week ends.

- **Phase H — Hardening (active, feature freeze, ADR-049):** close the security holes S1–S11 and the engineering gaps E1–E10 on `TASKS.md`. Exit: the freeze-lift conditions in ADR-049.
- **Phase 0 — Foundations:** workspace, CI, QEMU boot, serial logging, arch bring-up on x86_64. *Mostly done. CI has never run on a remote (E3).*
- **Phase 1 — Kernel core:** frame allocator, paging, threads + scheduler, IPC v1, capability table, IRQ delivery. Boot a userspace test process. *Done for one CPU without preemption.*
- **Phase 2 — System servers:** process server (fork/exec semantics), VFS + ramfs + virtio-blk ext-ish fs, PCI + virtio drivers, user/auth server, netstack (smoltcp in userspace). *Process server, ramfs VFS, console and auth done. virtio-blk, disk filesystem and netstack open.*
- **Phase 3 — POSIX personality + shell:** run busybox; port musl; interactive multi-user shell; login. *Static musl binaries run. Busybox and interactive login open.*
- **Phase 4 — Graphics & desktop:** virtio-gpu → real drivers, compositor, toolkit, mobile bring-up (aarch64 phone/tablet SBCs: Pi, Pixel 3a postmarketOS-class). *Not started.*
- **Phase 5 — Portability & polish:** aarch64 and riscv64 ports, SMP, preemption, power management, verified core. *Not started. The aarch64 and riscv64 HAL crates are empty stubs.*
- **Phase 6 — Compatibility long-tail:** Win32, macOS personalities. *Not started.*

## 4a. Current status (2026-11-12)

- x86_64 only, single CPU, cooperative scheduling with a PIT tick and no preemption.
- A clean release build boots in QEMU through init, VFS, process server, console, a scripted shell with a pipeline, a static musl program (printf, file I/O, mmap, stat, readdir), the auth server and `/login`, then halts cleanly.
- 207 host unit tests pass. Host clippy and fmt are clean. Userspace binaries do not pass clippy yet (E4).
- **Not secure.** A user process can take control of the kernel (REGS_WRITE, MAP into the kernel window, no SMEP/SMAP). See S1–S10. Do not run untrusted code on it.
- Fixed limits: 16 processes, 16 address spaces, 64 threads, 64 kernel objects.

## 5. Repository Layout (Cargo workspace)

```
micro-kernel-rs/
├── kernel/            # the microkernel core (no_std)         [GLM]
├── hal/               # HAL trait definitions (no_std)       [Nemotron]
│   ├── x86_64/  ├── aarch64/  └── riscv64/                   [Nemotron]
├── caps/              # capability types & tables (no_std)   [GLM]
├── ipc/               # IPC wire format & transport (no_std) [GLM]
├── servers/           # userspace system servers (std)       [DeepSeek]
│   ├── process/ ├── vfs/ ├── auth/ ├── net/ └── device/
├── personality/       # POSIX/Win32/macOS compat layers      [DeepSeek]
├── sdk/               # Helios native app SDK + rust std port[DeepSeek]
├── drivers/           # userspace drivers (std)              [Nemotron]
├── graphics/          # compositor & GPU stack               [Nemotron]
├── tools/             # build, mkimage, QEMU scripts, CI     [Nemotron]
├── docs/              # DECISIONS.md
└── tests/             # integration tests (QEMU harness)     [shared]
```

## 6. Engineering Rules

1. Every crate: `cargo clippy -- -D warnings` clean; `cargo fmt` enforced in CI. *Enforced for host crates. Userspace binaries: not yet enforced (E4, E5).*
2. Kernel-entry fuzzing: any byte arriving over IPC must never panic the kernel (harness in `tests/`). *Not yet enforced. The S11 attack test is the first step.*
3. No `unsafe` without a `// SAFETY:` comment + entry in `docs/DECISIONS.md`. *SAFETY comments enforced by clippy. DECISIONS entries: not yet enforced.*
4. Every PR boots in QEMU before merge (`tools/qemu-test.sh`). *Not yet enforced: the script does not boot the full system (E1, E2).*
5. Benchmarks for IPC fast path and context switch tracked per commit (criterion). *Not yet enforced.*
6. All design changes go through `docs/DECISIONS.md` (append-only ADRs). *Enforced.*
