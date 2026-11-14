# Helios: architecture and roadmap (v2)

**Language:** Rust. The kernel is `no_std`. Userspace starts `no_std + alloc` and gains a `std` port later.
**Targets:** x86_64, aarch64 and riscv64 first, then 32-bit microcontrollers (Armv7-M, Armv8-M, RV32 with PMP), then CHERI as a research target.
**Sources:** every claim about prior work cites `docs/research/BIBLIOGRAPHY.md` by ID, for example `[R-NROS]`.

This plan replaces the 2026-10-30 plan. ADR-057 records the change. The old plan's history stays in git and in `docs/history/`.

---

## 1. Vision

Helios is a capability microkernel that one code base can configure for any machine, from a microcontroller with only an MPU to a many-core NUMA server or an HPC compute node. It is multi-user and multi-threaded, asynchronous by design, and built so its security properties can be proved, not just tested.

Prior systems each solved part of this:
- seL4 proved a capability kernel correct but does not scale past a big lock and excludes timing channels [R-SEL4].
- NrOS scaled a sequential kernel across NUMA nodes but is not verified [R-NROS].
- Atmosphere proved a Rust kernel correct in Verus, again under one lock [R-ATMOSPHERE].
- Tock and Hubris own the microcontroller end, with a different resource model from seL4 [R-TOCK] [R-HUBRIS].
- Asterinas showed a Rust kernel can confine `unsafe` to a small framework [R-ASTERINAS].

Nobody has put these together. Helios aims to be the first kernel that is verified, scalable, secure against timing channels where hardware allows, and the same kernel at every scale. Section 3 lists the new ideas this needs. Each one is a bet with a test and a kill criterion.

### 1.1 Measurable goals

These are targets, not claims. Each milestone in section 9 says which ones it moves.

| Goal | Target | How it is measured |
|---|---|---|
| Safety | `unsafe` only in the allowlisted crates (section 7.1). Every other crate is `#![forbid(unsafe_code)]`. | CI check over the workspace |
| Panic freedom | No panic reachable from any syscall entry | Kani harnesses per entry point, plus fuzzing |
| Proof | Capability table, Untyped/Retype/Revoke, IPC state machine and page tables proved in Verus | Verus runs in CI, with time and line counts reported |
| IPC | Call/reply round trip within 1.25x of seL4 on the same hardware (Atmosphere is at 1.03x) | `bench/ipc` against a published seL4 number on the same CPU |
| Scaling | Commuting operations (for example map and unmap on disjoint ranges by different processes) scale near-linearly to the cores available | `bench/scale` on QEMU `-smp` 8, 16 and 64, then real hardware |
| Isolation | One user cannot read, write or exhaust another user's objects or time | `attack` suite, multi-user cases |
| Range | The same kernel source boots on an MPU-only microcontroller and on a 64-core NUMA machine | Profile builds in CI |

### 1.2 Non-goals

- Drivers, filesystems, networking or POSIX inside the kernel.
- Dynamic information-flow labels inside the kernel. A userspace label server handles them [R-HISTAR] [R-FLUME].
- Transparent persistence of all memory, as in EROS [R-EROS]. Persistence belongs to a storage server.
- A big kernel lock on multicore.
- A kernel that interprets rich async operation chains, as io_uring does [R-IOURING].

---

## 2. Design principles

Every design decision must follow these. An RFC that breaks one says so and justifies it.

1. **A sequential core, replicated for scale.** Kernel state transitions are written as sequential Rust state machines. On multicore, node replication wraps them [R-NROS]: one replica per NUMA node, kept consistent through an operation log, with separate logs for operations that commute. A microcontroller build uses one replica. This keeps the proof sequential and the scaling real.
2. **Everything is a capability, including time, cores and energy.** Memory, threads, endpoints, interrupts, address spaces, scheduling time [R-MCS], CPU cores [R-SHENANGO], energy budgets and security domains are all kernel objects reached only through capabilities. There is no ambient authority.
3. **The principal pays for kernel state.** All kernel memory comes from Untyped memory the caller owns [R-SEL4]. On a microcontroller, the same rule takes the form of grants or build-time allocation [R-TOCK] [R-HUBRIS]. No user can exhaust a shared kernel heap, because there is none.
4. **`unsafe` lives in one framework.** Hardware access goes through safe wrappers in the HAL [R-ASTERINAS]. Everything else is safe Rust. Each `unsafe` block has a written safety contract that Kani checks [R-KANI].
5. **A finite, verifiable ABI.** Every syscall does bounded work, takes explicit slot arguments instead of letting the kernel pick, validates every argument against a stated range, and states which operations commute [R-HYPERKERNEL] [R-COMMUTER].
6. **Async without a second attack surface.** The kernel provides notifications, signal waits and rings [R-SEL4-NTFN] [R-ZIRCON]. Ring entries name capabilities and pass through the same rights checks as synchronous calls. The kernel moves messages and never interprets operations [R-IOURING].
7. **Policy lives in userspace.** Scheduling policy [R-GHOST], memory tiering [R-TPP], energy policy [R-EAS], device management and naming are servers. The kernel provides mechanisms with a safe default and a watchdog fallback [R-SCHEDEXT].
8. **Servers hold no state on behalf of their clients.** Clients keep their own session state, so any server can be restarted [R-THESEUS] [R-MINIX]. Endpoint badges carry a generation number so clients see a restart [R-HUBRIS].
9. **One kernel, many profiles.** Scale is a build-time configuration, never a fork (section 5).
10. **Hardware is not trusted by default.** DMA goes through an IOMMU domain object. In a confidential VM, every host input is hostile [R-TDX-GUEST] [R-HECKLER]. Branch predictors and caches are not a security boundary, so every domain crossing gets an explicit barrier [R-BPI] [R-VMSCAPE].

---

## 3. Research bets

These are the parts that go beyond the state of the art. Each bet has a hypothesis, a prototype, a success metric and a kill criterion. A bet that hits its kill criterion is written up in an ADR and dropped, and the fallback ships instead. Every bet is first written as an RFC (section 10).

### B1. Verified scaling
- **Hypothesis:** a capability kernel whose core is a sequential state machine proved in Verus, then wrapped in node replication, keeps its proof and scales across NUMA nodes.
- **Basis:** [R-NROS] [R-ATMOSPHERE] [R-CORTENMM] [R-RCU-PROOF]. Every verified kernel today is single-core or big-lock.
- **Prototype:** the CSpace (capability tables and derivation tree) as a Verus-verified sequential structure, replicated with NR. Prove linearizability of the replicated wrapper separately, or adopt a verified NR implementation if one exists.
- **Success:** the CSpace proof still passes after replication, and `bench/scale` shows capability operations on disjoint CNodes scaling to 8 cores within 80% of linear (target).
- **Kill:** if the replicated wrapper cannot be proved within 6 person-months, ship NR as trusted code with Kani checks and keep the sequential proof.

### B2. Capability rings with the same security as synchronous calls
- **Hypothesis:** an async ring interface can give FlexSC-class batching [R-FLEXSC] with no new attack surface, if each entry is a capability invocation checked by the synchronous code path and the kernel never interprets operations.
- **Basis:** [R-FLEXSC] [R-IOURING] [R-SEL4-NTFN] [R-ZIRCON] [R-TLA-AWS].
- **Prototype:** rings built from Untyped memory, a notification as the doorbell, and a TLA+ model of submission, completion, cancellation and revocation with no lost wakeups and bounded queues. Then a Verus refinement of the kernel side.
- **Success:** the TLA+ model checks. The ring path and the synchronous path share one rights-check function, enforced by a test. Ring throughput beats per-call IPC by a measured factor on `bench/ring`.
- **Kill:** if the ring cannot reuse the synchronous checks, ship notifications plus shared memory only.

### B3. The security domain as a kernel object
- **Hypothesis:** one capability that owns a set of cores (never sharing a physical core across domains), cache colours, a kernel image clone, interrupt lines and a scheduling budget can give time protection on top of spatial isolation [R-TIMEPROT] [R-CORESCHED].
- **Basis:** [R-TIMEPROT] [R-MCS] [R-CORESCHED] [R-SPECTRE] [R-GHOSTRACE] [R-BPI].
- **Prototype:** domain switch with flush and pad behind a HAL trait. Cache colouring on RISC-V and x86 in QEMU first, then real hardware. Each endpoint gets a "speculation barrier class" that says which predictor and cache state an IPC through it scrubs.
- **Success:** a covert-channel test (prime and probe across domains) shows the channel closes on hardware that has the needed flush instructions. Every architecture has a published table of the channels that remain open.
- **Kill:** none. The fallback is the documented channel table plus core-granular scheduling.

### B4. One resource model from microcontroller to NUMA
- **Hypothesis:** Untyped memory, Tock grants and Hubris build-time allocation are three backends of one accounting abstraction, so the same capability semantics hold at every scale.
- **Basis:** [R-SEL4] [R-TOCK] [R-HUBRIS] [R-CHERIOT].
- **Prototype:** an `AddressSpace` trait with an MMU page-table backend and an MPU/PMP region backend. A `ResourceSource` abstraction with static, grant and Untyped backends. NUMA node and memory tier as attributes of Untyped.
- **Success:** the same kernel crate builds for an MPU target and for x86_64. The attack suite's isolation cases pass on both.
- **Kill:** if the MPU backend needs a separate kernel core, keep a shared ABI and capability crate and accept two cores.

### B5. Cores and energy as capabilities
- **Hypothesis:** scheduling contexts can carry an energy budget measured from hardware counters, and cores can be granted as capabilities and reassigned at microsecond scale by a user-level arbiter, with a portable preempt-to-user primitive.
- **Basis:** [R-MCS] [R-EAS] [R-SHENANGO] [R-CALADAN] [R-SKYLOFT].
- **Success:** a budget test shows an energy-capped context throttled to its budget. A core arbiter reallocates cores at a measured interval.
- **Kill:** if hardware energy counters are too coarse on a platform, energy budgets become advisory there.

### B6. An auditable authority log
- **Hypothesis:** a tamper-evident log of every mint, derive and revoke, anchored in measured boot, lets a multi-user system answer "who could access object X at time t".
- **Basis:** [R-SEL4-IF] [R-DICE] [R-TPM]. No capability system specifies this.
- **Success:** the audit server can replay the log and reconstruct the derivation tree at any recorded point. Tampering breaks a hash chain check.
- **Kill:** if logging costs more than a set budget on the IPC fast path, log only authority changes, not uses.

### B7. Proven live update for servers
- **Hypothesis:** a server can be replaced live if it declares a state-transfer function, and Verus checks that the transfer preserves the client-visible specification.
- **Basis:** [R-THESEUS] [R-MINIX] [R-VERUS].
- **Success:** a server (the VFS first) is replaced under load with no client-visible error.
- **Kill:** fall back to restart with client-held session state (principle 8).

### B8. A commutativity-checked ABI
- **Hypothesis:** generating conflict-freedom tests from a machine-readable ABI spec catches scalability bugs before they ship and can assign operations to CNR logs automatically.
- **Basis:** [R-COMMUTER] [R-NROS].
- **Success:** `spec/abi` generates tests that run in CI, and the CNR log assignment is derived from the same spec.

### B9. DMA inside the proof boundary
- **Hypothesis:** the IOMMU page table can be proved with the same flat Verus proof as CPU page tables, so DMA is no longer a trusted assumption.
- **Basis:** [R-ATMOSPHERE] [R-CORTENMM]. seL4 assumes DMA is off or trusted [R-SEL4].
- **Success:** the IOSpace object is verified and is the only way to grant DMA.

### B10. An isolation proof for the POSIX personality
- **Hypothesis:** the Linux ABI server does not need a functional proof. It needs a proof that it can never exceed the capabilities it holds, which follows from the kernel's authority-confinement property.
- **Basis:** [R-SEL4-IF] [R-CAPSICUM] [R-HYPERKERNEL].
- **Success:** a written proof sketch that links the personality's capability set to the kernel's confinement theorem, plus attack tests that try to exceed it.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Applications: native Helios apps, Linux binaries via the POSIX       │
│ personality (Capsicum-style capability mode)                         │
├─────────────────────────────────────────────────────────────────────┤
│ Personality servers: POSIX/Linux ABI (one per user session)          │
├─────────────────────────────────────────────────────────────────────┤
│ System servers:                                                      │
│  auth+sessions │ label (IFC) │ audit │ reincarnation │ constructor   │
│  sched policy │ memory/tier │ energy │ core arbiter │ device manager │
│  VFS + storage │ netstack │ console (trusted path) │ compositor      │
├─────────────────────────────────────────────────────────────────────┤
│ Userspace drivers: MMIO, IRQ and DMA through capabilities, restartable│
├══════════════════════════ capability boundary ═══════════════════════┤
│ Kernel (safe Rust over HAL wrappers, sequential core, NR-replicated):│
│  Untyped/Retype/Revoke │ CNode + derivation tree │ Endpoint, Reply   │
│  Notification, Port, Ring │ Thread │ SchedContext │ Domain           │
│  VSpace (MMU or MPU) │ IOSpace (IOMMU) │ IRQ/MSI handler │ CoreGrant │
├─────────────────────────────────────────────────────────────────────┤
│ HAL (the only unsafe framework): paging, MPU/PMP, traps, context,    │
│ timers, IPI, interrupt controllers, IOMMU, CFI, flush-and-pad, cache │
│ colouring, energy counters, platform description                     │
├─────────────────────────────────────────────────────────────────────┤
│ Boot: measured (DICE, TPM where present), signed images, DT + ACPI   │
│ reduced to one platform description                                  │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.1 Kernel object model (v2)

| Object | Purpose | Basis |
|---|---|---|
| Untyped | Raw memory with a size, an alignment, a NUMA node and a tier. The only source of kernel memory. | [R-SEL4] [R-INGENS] |
| CNode | A table of capability slots. Callers name the destination slot (principle 5). | [R-SEL4] [R-COMMUTER] |
| Derivation tree | Parent and child links for revocation, sharded per replica. | [R-SEL4] [R-NROS] |
| Endpoint | Synchronous call/reply rendezvous with capability transfer. Badges carry (principal, session, generation). | [R-SEL4] [R-HUBRIS] |
| Reply | One-shot reply capability (exists today, ADR-047). | ADR-047 |
| Notification | A word of signal bits. Doorbell for rings, IRQ delivery, block/unblock events. | [R-SEL4-NTFN] |
| Port | Packet queue for one-shot, cancellable, keyed waits on many objects. | [R-ZIRCON] |
| Ring | Submission and completion queues in Untyped memory. Entries are capability invocations. | [R-FLEXSC] (bet B2) |
| Thread | Register state, a VSpace, a CSpace root, a fault endpoint and a bound scheduling context. | existing |
| SchedContext | Budget, period, energy budget and core affinity. Donated across IPC. | [R-MCS] (bet B5) |
| Domain | Cores, cache colours, kernel clone, IRQ set, barrier class. | [R-TIMEPROT] (bet B3) |
| VSpace | Address space, with an MMU or MPU/PMP backend. Transactional mapping interface. | [R-CORTENMM] (bet B4) |
| IOSpace | IOMMU domain for a device. The only way to grant DMA. | [R-ARRAKIS] (bet B9) |
| IRQ handler | An interrupt line or MSI, delivered to a notification. | [R-RISCV-AIA] |
| CoreGrant | Exclusive use of a core for a period, revocable. | [R-SHENANGO] (bet B5) |

Each object type has, before code is written:
- an RFC with the object's state machine
- a Verus specification
- the validation range for every argument
- a commutativity statement

### 4.2 Capabilities, revocation and badges

- Capabilities follow the seL4 model: rights masks, badges and derivation from Untyped [R-SEL4]. Transfer through IPC can only drop rights, never add them (S8 already enforces this for NEW_THREAD).
- Revocation walks the derivation tree. The walk is bounded per call. A large revoke is resumable, so no single syscall does unbounded work (principle 5).
- Badges encode (principal, session, generation). A restarted server gets a new generation, and clients detect it [R-HUBRIS].
- Integrity and authority confinement are written as Verus specifications from M1 onward [R-SEL4-IF].

### 4.3 IPC and asynchrony

- **Synchronous call/reply** stays the control path. The fast path is measured on every commit (`bench/ipc`).
- **Notifications** are the only kernel signalling primitive. Interrupts, ring doorbells and scheduler events all arrive as notification bits [R-SEL4-NTFN].
- **Ports** let one thread wait on many objects with one-shot, cancellable, keyed waits [R-ZIRCON].
- **Rings** carry bulk and batched work (bet B2). The kernel copies or transfers entries between rings and endpoints and checks each entry's capability with the synchronous path's code. It never runs operation semantics.
- **Zero-copy buffers** move ownership between Rust servers in the style of RedLeaf's exchange heap [R-REDLEAF], mapped through VSpace transactions.

### 4.4 Scheduling and time

- Every runnable thread runs on a scheduling context with a budget and a period [R-MCS]. Passive servers run on the caller's context.
- The kernel dispatcher is per core and simple. The policy runs in a user-level scheduler server [R-GHOST], with EEVDF as the default best-effort policy inside each budget [R-EEVDF].
- A watchdog reverts to the default policy if the policy server stalls [R-SCHEDEXT].
- Core grants and a core arbiter give microsecond-scale reallocation for latency-critical work [R-SHENANGO] [R-CALADAN]. Preemption reaches userspace through a HAL primitive: user interrupts where the CPU has them, IPIs and notifications elsewhere [R-SKYLOFT].
- Mixed-criticality mode switches happen at user level [R-MIXEDCRIT]. The microcontroller profile keeps every kernel path bounded so worst-case execution time can be analysed.

### 4.5 Memory

- Physical memory exists only as Untyped, tagged with NUMA node and tier. Contiguous 2 MiB and 1 GiB Untyped is a managed resource [R-INGENS].
- The VSpace object uses a transactional, VMA-free page-table interface [R-CORTENMM]. Page-table pages come from ordered pools [R-ASAP]. Page tables are replicated per NUMA node where it pays off [R-MITOSIS].
- TLB shootdowns reach only the cores that have run the VSpace [R-RADIXVM].
- A userspace memory server owns demand paging, copy-on-write policy, tiering (DRAM, CXL, persistent memory) and promotion and demotion. The kernel provides access-bit sampling and remap primitives [R-TPP] [R-MEMTIS] [R-PMEM].

### 4.6 Multicore and NUMA

- Per-core kernel state for the dispatcher, the current thread and pending IPIs.
- CSpace, VSpace metadata and scheduler bookkeeping are sequential structures wrapped in NR, with CNR logs for commuting operations [R-NROS] (bets B1 and B8).
- Message-passing between kernel instances, in the multikernel style, only across non-coherent or different-ISA boundaries [R-MULTIKERNEL] [R-POPCORN].
- Accelerators are reached through queue capabilities with scheduling contexts [R-PTASK].

### 4.7 Multi-user security

- **Authentication:** the auth server holds credential material, and the kernel never does [R-HISTAR]. A secure attention sequence goes from the console server straight to the auth server, which is the trusted path [R-EROS-TWS].
- **Sessions:** a login creates a CNode subtree, minted from the user's Untyped quota, with badges carrying (uid, session, epoch). Logout revokes the subtree [R-SEL4].
- **Launching programs:** untrusted programs start through a constructor, which checks that the new process holds no capability that leaks outward [R-EROS-CONF].
- **Resource isolation:** each user owns its Untyped, so memory quotas are enforced by construction. Each user owns scheduling contexts, so CPU quotas are too [R-MCS].
- **Information flow:** the kernel enforces static partitions with noninterference as the proof target [R-SEL4-IF]. A userspace label server mediates declassification [R-HISTAR] [R-FLUME].
- **Audit:** an append-only, hash-chained log of authority changes (bet B6).
- **POSIX programs:** they run in a per-session personality server in capability mode. Each file descriptor maps to a rights-masked capability [R-CAPSICUM].

### 4.8 Drivers and devices

- Every driver is a userspace process holding MMIO, IRQ and IOSpace capabilities (ADR-052).
- The reincarnation server restarts a failed driver [R-MINIX]. Drivers keep no client state (principle 8).
- A device manager reads the platform description and hands out device capabilities. ACPI's AML interpreter lives in a userspace server, never in the kernel [R-ARM-ACPI].
- Kernel bypass is a capability: a virtual function plus an IOSpace [R-ARRAKIS] [R-DEMIKERNEL].

### 4.9 HAL and boot

- The HAL is the unsafe framework (principle 4). It exposes safe traits:
  - `Paging` (MMU), `MemoryProtection` (MPU and PMP), `Trap`, `Context`, `Timer`, `Ipi`
  - `InterruptController` (APIC, GIC, PLIC, AIA), `Iommu`
  - `Cfi` (CET, PAC and BTI, Zicfiss and Zicfilp), `FlushAndPad`, `CacheColour`
  - `EnergyCounters`, `PlatformDescription`
- Every hardware hardening feature is on by default when the CPU supports it: SMEP, SMAP, UMIP, LASS, kernel IBT, PAC, BTI, RISC-V CFI and ePMP. On CPUs that need it, kernel and user use split page tables [R-KAISER] [R-LASS] [R-CET] [R-RISCV-CFI] [R-EPMP].
- Boot is measured with DICE layering on every profile, extended into a TPM where one exists [R-DICE] [R-TPM]. Boot images are signed with LMS. Runtime attestation uses ML-DSA [R-LMS] [R-MLDSA].
- The boot stage turns device tree and ACPI into one platform description. The kernel sees only typed capabilities [R-DT].

---

## 5. Profiles: one kernel at every scale

A profile is a Cargo feature set plus a build-time system description, in the style of Hubris's application file [R-HUBRIS]. CI builds every profile.

| Profile | Hardware | Memory protection | Resource model | Scheduling | Notes |
|---|---|---|---|---|---|
| `micro` | Armv7-M, Armv8-M, RV32 with PMP | MPU/PMP regions | Static, fixed at build time. No runtime Retype. | Fixed priorities plus MCS budgets | One NR replica. Bounded paths for WCET analysis. |
| `micro-cheri` | CHERIoT | Hardware capabilities | Static or grants | As `micro` | Research target [R-CHERIOT] |
| `embedded` | Small Arm or RISC-V with an MMU | MMU | Untyped | MCS | |
| `desktop` / `mobile` | x86_64, aarch64 laptops, phones, SBCs | MMU, SMAP-class features | Untyped | MCS + EEVDF + energy | Trusted path, compositor |
| `server` | Many-core NUMA x86_64, aarch64, riscv64 | MMU, IOMMU | Untyped per NUMA node and tier | MCS, core arbiter | NR replicas per node, Mitosis |
| `hpc` | Compute nodes | MMU, 1 GiB pages | Static scheduling contexts, no demand paging | Tickless compute cores | Syscalls offloaded to service cores [R-MCKERNEL] [R-MOS] |
| `cc-guest` | TDX, SEV-SNP, CCA | MMU + hardware memory encryption | Untyped | MCS | Host is hostile. Interrupt vector allowlist [R-HECKLER]. |

### 5.1 Architecture tiers

- **Tier 1 (every gate, every commit):** x86_64, aarch64, riscv64 on QEMU `virt`/`q35`.
- **Tier 2 (built every commit, booted nightly):** Armv8-M and RV32 microcontroller targets in QEMU, and at least one real board per Tier 1 architecture once available.
- **Tier 3 (research):** CHERI (Morello or CHERI-RISC-V), confidential-VM guests.

---

## 6. Security model

### 6.1 Threat model

**The attacker can:**
- run arbitrary code in any number of user processes
- act as one or more logged-in users
- control any userspace driver or server except the trusted base below
- send any byte sequence to any syscall or IPC endpoint
- mount microarchitectural timing attacks from userspace
- in `cc-guest`, control the host

**The trusted base is:**
- the kernel and the HAL
- the boot chain and the signing keys
- in the security sense: the auth server, the console server's trusted-path code and the constructor

### 6.2 Properties Helios aims to provide, with the evidence for each

| Property | Mechanism | Evidence |
|---|---|---|
| Memory safety of kernel code | Safe Rust outside the HAL framework | CI unsafe allowlist, Kani on HAL contracts |
| Kernel never panics or hangs from user input | Bounded ABI, checked arithmetic, no `unwrap` on syscall paths | Kani panic-freedom harnesses, fuzzing [R-SYZKALLER] |
| Spatial isolation between processes and users | Capabilities, VSpace, IOSpace | Verus proofs (M1, M7), attack suite |
| Authority confinement | Derivation tree, rights-only-drop transfer | Verus specification, proof target [R-SEL4-IF] |
| Temporal isolation (CPU) | Scheduling contexts | Budget tests, MCS proofs as a target |
| Timing-channel isolation | Domains: colouring, flush-and-pad, core-granular scheduling | Channel tests and a per-architecture table of open channels [R-TIMEPROT] |
| Speculation safety at boundaries | Barrier classes on endpoints and domain switches | Per-architecture tests against published attack classes [R-INSPECTRE] [R-BPI] [R-VMSCAPE] |
| DMA safety | IOSpace only | Verus proof target (bet B9) |
| Boot integrity | DICE, TPM, LMS-signed images | Reproducible build, SBOM |
| Supply chain | cargo-vet, cargo-deny, cargo-audit, pinned toolchain | CI gate [R-CARGO-VET] [R-CARGO-DENY] [R-CARGO-AUDIT] |

### 6.3 What Helios does not claim

- It does not claim to stop physical attacks, beyond what measured boot and memory encryption give.
- It does not claim to close timing channels on hardware that lacks complete flush primitives. The per-architecture channel table says which channels remain.
- MTE and PAC are bug detectors and defence in depth, not boundaries [R-TIKTAG] [R-PACMAN].

---

## 7. Safety and verification strategy

### 7.1 The `unsafe` rule

- `unsafe` code and inline assembly are allowed only in:
  - `hal/*`
  - `kernel-boot`
  - one module in `kernel` for raw memory access (`kernel/src/mem.rs`)
  - the raw syscall module in `sdk` (`sdk/src/sys/raw.rs` once split out)
- Every other crate root has `#![forbid(unsafe_code)]`. Today `drivers`, `graphics`, `servers/process`, `personality` and the rest of `sdk` contain `unsafe` (counted on 2026-11-14). Each gets a migration task to move it behind a safe wrapper in an allowed crate.
- Every `unsafe` block has a `// SAFETY:` comment (already enforced by clippy). Every `unsafe fn` has a written contract and a Kani harness.
- Non-Rust code is limited to the boot and trap stubs in `hal/*` and `kernel-boot`. The C and assembly test programs and busybox in `personality/assets` are foreign test inputs, not Helios code.

### 7.2 Proof and checking tiers

| Tier | Tool | Scope | When |
|---|---|---|---|
| 1 | Verus [R-VERUS] | Capability table and derivation tree, Untyped/Retype/Revoke, IPC state machine, VSpace and IOSpace page tables, ring protocol | From M1, grows each milestone |
| 2 | Flux [R-FLUX] | Index bounds, MPU and PMP region math, badge packing | From M1 |
| 3 | Kani [R-KANI] | Panic freedom of every syscall entry, contracts of every `unsafe fn` | From M0 |
| 4 | TLA+ [R-TLA-AWS] | Revocation across replicas, ring protocol, NR log protocol, live update | Before each protocol is coded |
| 5 | Testing | Host unit tests, QEMU attack suite, syzkaller-style fuzzing, differential tests of the POSIX personality against Linux [R-SYZKALLER] | Always |

The proof-to-code ratio, verification time and trusted line count are reported in CI on every commit, so progress is visible. Atmosphere reports 3.32:1 and about one minute of verification [R-ATMOSPHERE], which is the reference point.

---

## 8. Engineering standards

### 8.1 The gate (every task, every agent)

```
cargo fmt --check
cargo clippy --workspace --exclude kernel-boot -- -D warnings
cargo clippy -p kernel-boot --target x86_64-unknown-none -- -D warnings
cargo clippy (userspace line, AGENTS.md section 5) -- -D warnings
cargo test --workspace --exclude kernel-boot
tools/qemu-test.sh                 # full boot, attack suite, DONE + clean halt
tools/check-unsafe.sh              # unsafe and asm only in allowed crates (M0)
cargo deny check && cargo vet      # supply chain (M0)
tools/verify.sh                    # Verus + Kani for changed crates (M1)
tools/bench.sh --compare           # IPC, context switch, map, scale: fails on regression beyond 5% (M0)
```

A milestone adds its checks to this gate. Once a check is in the gate it never leaves.

### 8.2 Benchmarks

`bench/` holds the suite. Results are stored per commit, so a regression shows up in the commit that caused it.
- `ipc`: call/reply round trip, one-way send, notification signal-to-wake.
- `ctx`: context switch, same and different address space.
- `map`: map and unmap 4 KiB, 2 MiB and 1 GiB.
- `ring`: batched submissions per second against per-call IPC.
- `scale`: capability and map operations on disjoint resources, 1 to N cores.
- `boot`: time to init on each profile.

### 8.3 Design records

- **RFC** (`docs/rfcs/NNNN-title.md`) for anything new: a kernel object, an ABI change, a research bet or a new server. The template is in section 10.
- **ADR** (`docs/DECISIONS.md`, append-only) records each accepted decision and links its RFC.
- An ABI change needs:
  - the validation range for each argument
  - a commutativity statement
  - the Verus specification change
  - the attack-suite cases

---

## 9. Roadmap

Milestones are ordered. A milestone is done when every exit check passes and every task it names is marked done with a commit hash. No dates.

### M0. Baseline and guardrails
- Close the remaining Phase H items (S2b REGS_WRITE entry PC, reopened SMP claim).
- Add `tools/check-unsafe.sh`, cargo-deny, cargo-vet, the `bench/` suite and the commit-by-commit benchmark record.
- Write `spec/abi`: a machine-readable description of every syscall, its arguments, ranges, errors and commutativity.
- Kani harnesses for panic freedom of today's syscall entries.
- **Exit:** the M0 checks are in the gate, `spec/abi` covers every current syscall, and benchmarks are recorded for HEAD.

### M1. Object model v2 and the finite ABI
- Untyped, Retype and Revoke as the only kernel allocator. This removes today's fixed limits (16 processes, 64 objects).
- CNode with caller-chosen slots, the derivation tree, and badges with generation numbers.
- Verus specifications and proofs for the CSpace and Untyped. Flux on index math.
- TLA+ model of revocation.
- **Exit:** all kernel objects come from Untyped, the Verus proofs pass in CI, and the attack suite covers Retype and Revoke abuse.

### M2. Time
- Scheduling contexts with budget and period, preemption, and donation over IPC.
- A user-level scheduler server with an EEVDF default and a watchdog fallback.
- **Exit:** a CPU hog cannot starve a thread with its own budget (test). The policy server can be killed and the system keeps running on the default policy.

### M3. Multicore
- Per-core dispatch, IPIs and shootdown tracking.
- NR wrapper for CSpace and VSpace metadata, with CNR logs derived from `spec/abi` (bets B1 and B8).
- **Exit:** boots on QEMU `-smp` 8 with no global kernel lock, and `bench/scale` meets the B1 target.

### M4. Asynchrony
- Ports and rings (bet B2), with the TLA+ model checked first.
- **Exit:** the model checks, the ring path shares the synchronous rights check (test), and `bench/ring` is recorded.

### M5. Multi-user and system services
- Session subtrees, logout revocation, constructor, reincarnation server, audit log (bet B6), trusted path.
- POSIX personality in capability mode.
- **Exit:**
  - Two concurrent users cannot reach each other's objects, memory or time (attack suite).
  - Logout revokes everything the session held.
  - A killed driver restarts and its clients recover.

### M6. Portability
- aarch64 and riscv64 brought to Tier 1, booting the same userspace and passing the same suite.
- The `micro` profile on an MPU target with the MPU backend (bet B4). Platform description from device tree and ACPI.
- **Exit:** the attack suite passes on all three Tier 1 architectures, and an MPU target runs two isolated tasks with the isolation cases passing.

### M7. Hardening
- HAL `Cfi` trait across x86, Arm and RISC-V, LASS, and SMAP with a user-copy helper.
- Barrier classes on domain crossings.
- IOSpace and verified DMA (bet B9).
- The security domain object (bet B3) with a published channel table.
- Nightly syzkaller-style fuzzing, measured boot and signed images.
- **Exit:** the channel table is published for each Tier 1 architecture, and fuzzing runs nightly with no kernel panic over a set CPU-hour budget.

### M8. Scale and HPC
- NUMA-tagged Untyped, Mitosis replicas, the memory server with tiering, core grants and the arbiter (bet B5), and the `hpc` profile.
- **Exit:** `bench/scale` on 64 cores (QEMU, then real hardware) and an HPC profile boot with tickless compute cores.

### M9. Desktop, mobile and compatibility
- Real-hardware drivers, the compositor and toolkit on the trusted path, busybox and a dynamic Linux ELF loader in the personality, then the long-tail personalities.
- Proven live update for the VFS (bet B7).

Bet B10 (the personality isolation proof) runs alongside M5 and M7.

---

## 10. How the agents work under this plan

### 10.1 Ownership

| Agent | Tag | Owns | Main milestones |
|---|---|---|---|
| Nemotron (coordinator) | `[NV]` | `hal/`, `tools/`, `bench/`, `tests/`, `.github/`, `docs/`, root files | HAL traits, gates, benchmarks, M6 and M7 HAL work |
| GLM slot | `[GLM]` | `kernel/`, `kernel-boot/`, `caps/`, `ipc/`, `spec/` | Object model, proofs, ABI spec, M1 to M4 |
| DeepSeek | `[DS]` | `servers/`, `sdk/` | Scheduler, memory, auth, audit, reincarnation and constructor servers |
| Drivers | `[DRV]` | `drivers/`, `graphics/` | Driver migration to safe wrappers, IOSpace users, device manager |
| POSIX | `[PSX]` | `personality/` | Capability-mode personality, Linux ABI coverage, differential tests |

### 10.2 The research loop

Every new object, ABI change or research bet goes through these steps:
1. **Read.** Find the relevant entries in `docs/research/BIBLIOGRAPHY.md`. Add any new source you rely on, following the entry format and opening the source yourself.
2. **Write an RFC** (`docs/rfcs/NNNN-title.md`) with these sections:
   - Problem
   - Research basis (bibliography IDs)
   - Design
   - ABI: arguments, validation ranges, errors and commutativity
   - Verification plan
   - Benchmark and success metric
   - Kill criterion
   - Alternatives considered
3. **Get acceptance.** NV accepts an RFC that changes the ABI, a HAL trait or a milestone. An RFC that touches only the owner's own area may be self-accepted. An accepted RFC becomes an ADR.
4. **Specify before coding:** the Verus spec, TLA+ model or Kani harness comes first, in the same task or the task before.
5. **Build behind a feature flag** until the exit test passes.
6. **Measure** with `bench/`, and record the result in the ADR.

### 10.3 Board discipline

- A task is done only when everything its line asks for is done, with the hash of the commit that did it. Partial work is split into numbered sub-tasks.
- A milestone or phase gate ADR lists every task with its hash.

---

## 11. Migration from the current code

| Today | v2 |
|---|---|
| Capability table with parent links and cascade revoke (ADR-004) | Becomes the CNode and derivation tree, with caller-chosen slots |
| Fixed object limits (16 processes, 64 objects) | Removed by Untyped and Retype (M1) |
| Single global frame allocator (ADR-003) | Becomes the root Untyped handed to init |
| Cooperative scheduler with priorities (ADR-010) | Becomes the per-core dispatcher with scheduling contexts (M2) |
| PIT tick, no preemption (ADR-042) | Becomes timer-driven budget enforcement (M2) |
| Deadlines on RECV (ADR-041) | Kept, expressed through notifications and ports |
| Bulk transport deferred (ADR-006) | Becomes rings (M4) |
| Userspace drivers with MMIO and DMA capabilities (ADR-052) | Kept. DMA moves to IOSpace (M7). |
| Phase 2 to 5 board items added on 2026-11-14 | Re-sorted into M0 to M9. Items marked done without meeting their line are reopened. |

---

## 12. Risks

| Risk | Effect | Mitigation |
|---|---|---|
| Proof effort outruns the agents | Proofs lag code | Proof tiers (7.2). Kani and Flux first, Verus on the core only, and the proof ratio is visible in CI. |
| Verus cannot express the NR wrapper | Bet B1 fails | Kill criterion: trusted NR with Kani checks |
| Agents mark work done that is not | False progress | Coordinator review, whole-line rule, gate ADRs list hashes |
| Shared working tree causes build clashes | Lost cycles | Next step: one git worktree per agent |
| Free model endpoints change or vanish | Agents stop | Per-agent model file, swap without a commit |
| Hardware for real-device tiers is missing | M6 to M8 stay in QEMU | Owner decides target boards (section 13) |

## 13. Decisions for the owner

1. Which real boards to buy for Tier 2 (for example one Armv8-M MCU board, one RISC-V board with an MMU, one aarch64 SBC).
2. Whether to publish the repository and where, so CI can run on a remote.
3. Who holds the boot-image signing key, and whether an HSM is available for LMS signer state.
