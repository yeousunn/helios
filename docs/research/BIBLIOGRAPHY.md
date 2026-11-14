# Helios research bibliography

Every design proposal (RFC) and ADR that rests on prior work cites entries here by ID, for example `[R-NROS]`. Numbers below are quoted from the source named in the entry. An entry marked **UNVERIFIED** could not be checked against a primary source when it was added, so confirm it before relying on it.

To add an entry: give the full citation, a URL you opened, the core idea, the measured result as the source states it, the limitation, and what Helios takes from it. Keep each entry short.

---

## A. Kernel architecture and Rust operating systems

**[R-SEL4]** Klein et al. "seL4: Formal Verification of an OS Kernel." SOSP 2009. https://www.sigops.org/s/conferences/sosp/2009/papers/klein-sosp09.pdf. Also: Klein et al. "Comprehensive Formal Verification of an OS Microkernel." ACM TOCS 32(1), 2014. https://sel4.systems/Research/pdfs/comprehensive-formal-verification-os-microkernel.pdf
- Idea: an L4 kernel with a machine-checked refinement proof from abstract spec to C. All kernel memory is user-managed through Untyped capabilities, `Retype` and `Revoke`, which form the capability derivation tree (CDT).
- Result: 8,700 lines of C plus 600 of assembly, about 200,000 lines of proof and about 20 person-years (2009 paper).
- Limit: the SMP kernel uses a big lock and is "not meant to scale to many cores". Assembly, boot, TLB and cache code are assumed correct. There are no timing-channel guarantees (FAQ: https://sel4.systems/About/FAQ.html).
- Helios takes: Untyped, Retype and Revoke as the only kernel memory allocator, and badged endpoints. Helios avoids a big lock and a single whole-kernel Isabelle proof.

**[R-SEL4-IF]** Sewell et al. "seL4 Enforces Integrity." ITP 2011. https://trustworthy.systems/publications/nicta_full_text/4709.pdf. Murray et al. "seL4: from General Purpose to a Proof of Information Flow Enforcement." IEEE S&P 2013. https://trustworthy.systems/publications/nicta_full_text/6464.pdf
- Result: noninterference is proved for the real C code, about 51 person-months for the information-flow proof.
- Limit: it needs a static partitioned configuration, and timing channels are out of scope.
- Helios takes: integrity and authority confinement written as executable specifications from the start.

**[R-MCS]** Lyons, McLeod, Almatary, Heiser. "Scheduling-Context Capabilities." EuroSys 2018. https://trustworthy.systems/publications/full_text/Lyons_MAH_18.pdf
- Idea: time is a capability. A scheduling context carries budget and period, and passive servers run on the caller's context.
- Helios takes: scheduling contexts from the first SMP milestone, not retrofitted.

**[R-ZIRCON]** Fuchsia Zircon documentation: handles https://fuchsia.dev/fuchsia-src/concepts/kernel/handles, ports https://fuchsia.dev/fuchsia-src/reference/kernel_objects/port, async waits https://fuchsia.dev/reference/syscalls/object_wait_async, VMOs https://fuchsia.dev/fuchsia-src/reference/kernel_objects/vm_object
- Idea: rights attenuation on handle duplication, objects expose signal bits, and one-shot cancellable waits deliver packets to a port.
- Limit: not verified, large object set, no published measurements.
- Helios takes: the signal and port model for async waiting, without the large object set.

**[R-ASTERINAS]** Peng et al. "Asterinas: A Linux ABI-Compatible, Rust-Based Framekernel OS with a Small and Sound TCB." USENIX ATC 2025. https://www.usenix.org/conference/atc25/presentation/peng-yuke
- Idea: only the OSTD framework may use `unsafe`. Every service is safe Rust over OSTD's safe wrappers for page tables, DMA, MMIO and IOMMU.
- Result: over 210 Linux syscalls with a TCB of 14.0% of the code base, against 43.8% for Tock, 62.4% for Theseus and 66.1% for RedLeaf.
- Limit: one address space and no hardware isolation between services. Soundness rests on testing (KernMiri) and partial Verus work.
- Helios takes: the one-unsafe-crate discipline. Helios keeps hardware isolation between processes.

**[R-VOSTD]** Asterinas team. "Towards Practical Formal Verification for a General-Purpose OS in Rust." 2025. https://asterinas.github.io/2025/02/13/towards-practical-formal-verification-for-a-general-purpose-os-in-rust.html
- Result: Verus verification of OSTD page management covered 11 of 14 targets and found a race that freed a page-table node early.

**[R-CORTENMM]** Zhang et al. "CortenMM: Efficient Memory Management with Strong Correctness Guarantees." SOSP 2025. https://zhou-diyu.github.io/files/cortenmm-sosp25.pdf
- Idea: no VMA layer. Page tables are managed directly through a transactional interface with scalable locking, and the concurrent core is verified in Verus.
- Result: 1.2x to 26x faster than Linux on real applications, proof-to-code ratio 5.2:1, about 8 person-months.
- Helios takes: the transactional page-table interface for the VSpace object.

**[R-THESEUS]** Boos, Liyanage, Ijaz, Zhong. "Theseus: an Experiment in Operating System Structure and State Management." OSDI 2020. https://www.usenix.org/conference/osdi20/presentation/boos
- Idea: small cells with no "state spill" (no component holds state on behalf of another), so cells can be replaced live.
- Result: median downtime of 385 µs for a live swap. Recovered 69% of manifested faults out of 800,000 injected.
- Helios takes: the no-state-spill rule for every server, so servers can restart.

**[R-REDLEAF]** Narayanan et al. "RedLeaf: Isolation and Communication in a Safe Operating System." OSDI 2020. https://www.usenix.org/conference/osdi20/presentation/narayanan-vikram
- Idea: language-based domains with an exchangeable heap that transfers ownership for zero-copy calls, and clean domain restart.
- Helios takes: ownership-transferring shared buffers as the model for zero-copy IPC between Rust servers.

**[R-TOCK]** Levy et al. "Multiprogramming a 64 kB Computer Safely and Efficiently." SOSP 2017. https://www.amitlevy.com/papers/tock-sosp2017.pdf
- Idea: Rust capsules isolated by types, processes isolated by the MPU, and "grants" that charge kernel state to the process that caused it.
- Result: kernel uses 8.4 kB SRAM plus a 4 kB stack and 87 kB flash.
- Helios takes: grants as the MPU-profile form of "a principal pays for kernel state on its behalf".

**[R-TICKTOCK]** Rindisbacher et al. "TickTock: Verified Isolation in a Production Embedded OS." SOSP 2025. https://cseweb.ucsd.edu/~dstefan/pubs/rindisbacher:2025:ticktock.pdf
- Result: Flux verifies process isolation on ARMv7-M and three RV32 platforms and found isolation bugs in Tock's MPU and interrupt code. Exact counts are UNVERIFIED.
- Helios takes: MPU and PMP region math must be verified, not just tested.

**[R-HUBRIS]** Oxide Computer. Hubris reference. https://hubris.oxide.computer/reference/
- Idea: all tasks fixed at build time, synchronous IPC with leases, a supervisor task restarts faulted tasks, generation numbers in task IDs.
- Helios takes: the static build profile and generation numbers in endpoint badges.

**[R-REDOX]** Redox kernel. https://github.com/redox-os/kernel
- Helios takes: the rule that no panic is reachable in kernel space, checked mechanically.

**[R-MINIX]** Herder, Bos, Gras, Homburg, Tanenbaum. "Fault Isolation for Device Drivers." DSN 2009. https://www.cs.vu.nl/~herbertb/papers/minix3_dsn09.pdf
- Result: 3,400,000 faults injected into 4 Ethernet drivers crashed the OS zero times.
- Helios takes: a reincarnation server that restarts failed drivers and servers.

**[R-COMPOSITE]** Gadepalli, Gifford, Baier, Kelly, Parmer. "Temporal Capabilities: Access Control for Time." RTSS 2017. https://faculty.cs.gwu.edu/gparmer/publications/rtss17tcaps.pdf
- Helios takes: time delegated alongside a service request, so a restarted driver cannot starve others.

**[R-RFL]** Li et al. "An Empirical Study of Rust-for-Linux." USENIX ATC 2024. https://www.usenix.org/conference/atc24/presentation/li-hongyu. Li et al. "Rust for Linux: Understanding the Security Impact of Rust in the Linux Kernel." 2024 (ACSAC per URL, UNVERIFIED in the PDF). https://mars-research.github.io/doc/2024-acsac-rfl.pdf
- Result: of 240 driver CVEs, 82 are removed by Rust automatically, 113 need specific idioms and 45 are unaffected.
- Helios takes: safe-by-construction driver APIs, typestate protocol modelling, checked arithmetic.

## B. Verification

**[R-ATMOSPHERE]** Chen, Li, Zhang, Narayanan, Burtsev. "Atmosphere: Practical Verified Kernels with Rust and Verus." SOSP 2025. https://mars-research.github.io/doc/2025-sosp-atmo.pdf
- Idea: an L4-like kernel proved functionally correct in Verus, using a flat ownership design for page tables.
- Result: 6K lines of code, proof-to-code 3.32:1, under 2.5 person-years, full verification in about 1 minute on 8 threads. Call/reply IPC 1,058 cycles against seL4's 1,026.
- Limit: big-lock SMP. About 3,000 lines of trusted Rust and assembly.
- Helios takes: Verus as the main proof tool and the flat page-table proof style.

**[R-VERUS]** Lattuada et al. "Verus: A Practical Foundation for Systems Verification." SOSP 2024. https://www.microsoft.com/en-us/research/publication/verus-a-practical-foundation-for-systems-verification/. OOPSLA 2023 paper: https://arxiv.org/pdf/2303.05491
- Result: 3x to 61x faster verification than prior tools in its case studies.

**[R-KANI]** Kani Rust model checker. https://model-checking.github.io/kani/. Paper: Delmas et al. "Kani: A Model Checker for Rust." https://arxiv.org/abs/2607.01504
- Helios takes: bounded proofs of panic freedom and of the safety contracts of every `unsafe` function.

**[R-FLUX]** Lehmann, Geller, Vazou, Jhala. "Flux: Liquid Types for Rust." PLDI 2023. https://arxiv.org/abs/2207.04034
- Helios takes: cheap refinement types for index bounds and region arithmetic across crates.

**[R-PRUSTI]** Prusti project. https://github.com/viperproject/prusti-dev. Self-described prototype. Not a primary tool for Helios.

**[R-RUSTBELT]** Jung, Jourdan, Krebbers, Dreyer. "RustBelt." POPL 2018. https://plv.mpi-sws.org/rustbelt/popl18/
- Helios takes: the rule that each unsafe abstraction must justify itself as a safe extension.

**[R-HYPERKERNEL]** Nelson et al. "Hyperkernel: Push-Button Verification of an OS Kernel." SOSP 2017. https://par.nsf.gov/servlets/purl/10049039
- Idea: a finite interface with bounded work per call, verified with Z3.
- Helios takes: design the syscall ABI to be finite and bounded before implementing it, with explicit slot arguments.

**[R-CERTIKOS]** Gu et al. "CertiKOS." OSDI 2016. https://www.usenix.org/conference/osdi16/technical-sessions/presentation/gu
- Helios takes: layered refinement, so concurrency proofs can be added layer by layer.

**[R-KOMODO]** Ferraiuolo, Baumann, Hawblitzel, Parno. "Komodo." SOSP 2017. https://css.csail.mit.edu/6.858/2022/readings/komodo.pdf

**[R-TLA-AWS]** Newcombe et al. "Use of Formal Methods at Amazon Web Services." 2014. https://lamport.azurewebsites.net/tla/formal-methods-amazon.pdf
- Helios takes: TLA+ models for IPC, revocation and the ring protocol before they are coded.

**[R-RCU-PROOF]** Tassarotti, Dreyer, Vafeiadis. "Verifying Read-Copy-Update in a Logic for Weak Memory." PLDI 2015. https://people.mpi-sws.org/~dreyer/papers/rcu/paper.pdf

## C. Scalability, NUMA and memory

**[R-MULTIKERNEL]** Baumann et al. "The Multikernel." SOSP 2009. https://www.sigops.org/s/conferences/sosp/2009/papers/baumann-sosp09.pdf
- Helios takes: message passing between kernel instances only where hardware is not cache-coherent or the ISA differs.

**[R-NR]** Calciu, Sen, Balakrishnan, Aguilera. "Black-box Concurrent Data Structures for NUMA Architectures." ASPLOS 2017. UNVERIFIED (paper not opened). Mechanism taken from [R-NROS].

**[R-NROS]** Bhardwaj et al. "NrOS: Effective Replication and Sharing in an Operating System." OSDI 2021. https://www.usenix.org/system/files/osdi21-bhardwaj.pdf
- Idea: a sequential kernel replicated per NUMA node and kept consistent through operation logs. Concurrent NR (CNR) gives commuting operations separate logs.
- Result: scales to 96 cores and "nearly always dominates Linux at scale".
- Limit: mutation-heavy subsystems contend on a single log. Replicas cost memory.
- Helios takes: the core is a sequential state machine wrapped in NR or CNR, so it stays verifiable and scales.

**[R-RADIXVM]** Clements, Kaashoek, Zeldovich. "RadixVM." EuroSys 2013. https://pdos.csail.mit.edu/papers/radixvm:eurosys13.pdf
- Helios takes: track which cores used a mapping so TLB shootdowns reach only those cores.

**[R-COMMUTER]** Clements et al. "The Scalable Commutativity Rule." SOSP 2013. https://pdos.csail.mit.edu/papers/commutativity:sosp13.pdf
- Result: of 13,664 generated tests across 18 POSIX calls, Linux was conflict-free for 68% and sv6 for 99%.
- Helios takes: every syscall ADR states which operations commute.

**[R-MITOSIS]** Achermann et al. "Mitosis." ASPLOS 2020. https://arxiv.org/pdf/1910.05398
- Result: up to 1.34x on multi-socket workloads and 3.24x after migration.
- Helios takes: per-node page-table replicas.

**[R-INGENS]** Kwon et al. "Ingens." OSDI 2016. https://www.usenix.org/conference/osdi16/technical-sessions/presentation/kwon
- Helios takes: physical contiguity as a managed resource (2 MiB and 1 GiB aligned Untyped).

**[R-MOSAIC]** Gosakan et al. "Mosaic Pages." ASPLOS 2023. https://par.nsf.gov/servlets/purl/10504744. Needs new hardware. Keep frame placement pluggable.

**[R-ASAP]** Margaritov et al. "Prefetched Address Translation." MICRO 2019. https://infoscience.epfl.ch/record/276507
- Helios takes: page-table pages allocated from ordered pools.

**[R-TPP]** Maruf et al. "TPP: Transparent Page Placement for CXL-Enabled Tiered Memory." https://arxiv.org/pdf/2206.02878 (venue UNVERIFIED). **[R-POND]** Li et al. "Pond." https://arxiv.org/pdf/2203.00241 (venue UNVERIFIED). **[R-MEMTIS]** Lee et al. "Memtis." SOSP 2023. https://cosmoss-jigu.github.io/pages/pubs/memtis-lee-sosp23.pdf
- Helios takes: each memory tier is its own Untyped pool. Promotion and demotion policy lives in a userspace memory server.

**[R-PMEM]** Yang et al. "An Empirical Guide to the Behavior and Use of Scalable Persistent Memory." FAST 2020. https://www.usenix.org/conference/fast20/presentation/yang
- Helios takes: no persistence semantics in the kernel.

## D. Asynchrony and scheduling

**[R-FLEXSC]** Soares, Stumm. "FlexSC: Flexible System Call Scheduling with Exception-Less System Calls." OSDI 2010. https://www.usenix.org/legacy/events/osdi10/tech/full_papers/Soares.pdf
- Result: Apache up to 116%, MySQL up to 40%, BIND up to 105%.
- Helios takes: shared submission and completion rings for bulk work, synchronous IPC for short calls.

**[R-IOURING]** Axboe. "Efficient IO with io_uring." 2019. https://kernel.dk/io_uring.pdf. Koczka. "Learnings from kCTF VRP's 42 Linux kernel exploits submissions." Google, 2023. https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html
- Result: 60% of kCTF submissions exploited io_uring, and Google disabled it on ChromeOS and production servers.
- Helios takes: the ring shape only. Every entry names a capability, the kernel never interprets operations, and the ring uses the same rights checks as the synchronous path.

**[R-SEL4-NTFN]** seL4 notifications. https://docs.sel4.systems/Tutorials/notifications.html
- Helios takes: the notification as the doorbell under every ring and the IRQ delivery object.

**[R-SCHEDACT]** Anderson et al. "Scheduler Activations." ACM TOCS 10(1), 1992. https://homes.cs.washington.edu/~tom/pubs/sched_act.pdf
- Helios takes: block and unblock events delivered as notifications to user-level schedulers, without upcall stacks.

**[R-ARRAKIS]** Peter et al. "Arrakis." OSDI 2014. https://www.usenix.org/conference/osdi14/technical-sessions/presentation/peter. **[R-IX]** Belay et al. "IX." OSDI 2014. https://www.usenix.org/conference/osdi14/technical-sessions/presentation/belay. **[R-DEMIKERNEL]** Zhang et al. "The Demikernel Datapath OS Architecture." SOSP 2021. https://www.microsoft.com/en-us/research/publication/the-demikernel-datapath-os-architecture-for-microsecond-scale-datacenter-systems/
- Helios takes: a device virtual function plus an IOMMU domain is a capability-shaped kernel bypass.

**[R-EEVDF]** Linux EEVDF scheduler docs. https://docs.kernel.org/scheduler/sched-eevdf.html
- Helios takes: EEVDF as the default best-effort policy inside a scheduling-context budget.

**[R-SCHEDEXT]** Linux sched_ext docs. https://docs.kernel.org/scheduler/sched-ext.html
- Helios takes: a watchdog that reverts to the default policy if a pluggable policy stalls.

**[R-GHOST]** Humphries et al. "ghOSt." SOSP 2021. https://storage.googleapis.com/gweb-research2023-media/pubtools/6413.pdf
- Result: within 5% of Shinjuku, and a Google Search policy under 1,000 lines often cut latency by 40 to 50%.
- Helios takes: a kernel dispatcher driven by a user-level policy server.

**[R-SHENANGO]** Ousterhout et al. NSDI 2019. https://www.usenix.org/conference/nsdi19/presentation/ousterhout. **[R-CALADAN]** Fried et al. OSDI 2020. https://www.usenix.org/conference/osdi20/presentation/fried. **[R-SHINJUKU]** Kaffes et al. NSDI 2019. https://www.usenix.org/conference/nsdi19/presentation/kaffes. **[R-SKYLOFT]** Jia et al. SOSP 2024. https://madsys.cs.tsinghua.edu.cn/publication/skyloft-a-general-high-efficient-scheduling-framework-in-user-space/SOSP24-Jia.pdf
- Helios takes: cores as capabilities that a user-level arbiter reassigns at microsecond scale, and a portable preempt-to-user primitive.

**[R-MIXEDCRIT]** Burns, Davis. "Mixed Criticality Systems: A Review." 13th ed., 2022. https://www-users.york.ac.uk/~ab38/review.pdf

**[R-EAS]** Linux Energy Aware Scheduling. https://docs.kernel.org/scheduler/sched-energy.html

## E. HPC, heterogeneity and portability

**[R-KITTEN]** Lange et al. "Palacios and Kitten." IPDPS 2010. https://www.osti.gov/servlets/purl/1142272. **[R-MOS]** Wisniewski et al. "mOS." ROSS 2014, slides only: https://events.cels.anl.gov/ross/2014/slides/ross2014-wisniewski.pdf. **[R-MCKERNEL]** Gerofi et al. "IHK/McKernel." IPDPS 2016. https://bgerofi.github.io/papers/bgerofi-ipdps16.pdf. **[R-CATAMOUNT]** Vaughan, Van Dyke, Kelly. CUG 2008. https://www.osti.gov/servlets/purl/1145825
- Helios takes: an HPC profile with tickless compute cores, static scheduling contexts, 1 GiB pages and syscalls offloaded to service cores, in one kernel.

**[R-POPCORN]** Barbalace et al. "Breaking the Boundaries in Heterogeneous-ISA Datacenters." ASPLOS 2017. Slides: https://www.systor.org/2017/slides/Breaking_the_Boundaries.pdf (paper UNVERIFIED-OPENED)

**[R-PTASK]** Rossbach et al. "PTask." SOSP 2011. https://www.cs.utexas.edu/users/witchel/pubs/sosp11rossbach-ptask.pdf
- Helios takes: accelerator queues as capabilities with scheduling contexts.

**[R-ZEPHYR-USER]** Zephyr user mode. https://docs.zephyrproject.org/latest/kernel/usermode/overview.html

**[R-RISCV-PRIV]** RISC-V Privileged Architecture 20240411. https://github.com/riscv/riscv-isa-manual/releases/download/20240411/priv-isa-asciidoc.pdf. **[R-RISCV-AIA]** https://github.com/riscv/riscv-aia

**[R-DT]** Devicetree specification. https://www.devicetree.org/specifications/. **[R-ARM-ACPI]** https://docs.kernel.org/arch/arm64/arm-acpi.html
- Helios takes: device tree and ACPI turned into one platform description at boot. AML interpretation in userspace.

## F. Security

**[R-KEYKOS]** Hardy. "The KeyKOS Architecture." OSR 1985. https://pdos.csail.mit.edu/6.828/2009/readings/keykos-osr.pdf. **[R-EROS]** Shapiro, Smith, Farber. "EROS: a fast capability system." SOSP 1999. https://www.cs.yale.edu/flint/cs428/doc/eros.pdf. **[R-EROS-CONF]** Shapiro, Weber. "Verifying the EROS Confinement Mechanism." IEEE S&P 2000. https://www.cs.yale.edu/flint/cs428/doc/eros-verify.pdf
- Helios takes: the constructor pattern for launching untrusted programs. Helios avoids transparent persistence.

**[R-CAPSICUM]** Watson, Anderson, Laurie, Kennaway. "Capsicum." USENIX Security 2010. https://www.usenix.org/legacy/event/sec10/tech/full_papers/Watson.pdf
- Helios takes: capability mode and rights-limited descriptors in the POSIX personality.

**[R-CHERI]** Watson et al. "CHERI ISA Version 9." UCAM-CL-TR-987, 2023. https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-987.pdf. **[R-CORNUCOPIA2]** Filardo et al. "Cornucopia Reloaded." ASPLOS 2024. https://microsoft.com/en-us/research/?p=1010307
- Helios takes: a HAL that does not assume a pointer is a plain integer, so a CHERI target is possible.

**[R-CHERIOT]** Amar et al. "CHERIoT: Complete Memory Safety for Embedded Devices." MICRO 2023. https://cheriot.org/papers/2023-micro-cheriot-uarch.pdf
- Helios takes: a microcontroller profile where Helios capabilities are hardware sealed capabilities.

**[R-HISTAR]** Zeldovich et al. "Making Information Flow Explicit in HiStar." OSDI 2006. https://www.usenix.org/legacy/event/osdi06/tech/full_papers/zeldovich/zeldovich.pdf. **[R-FLUME]** Krohn et al. SOSP 2007. https://pdos.csail.mit.edu/papers/flume-sosp07.pdf. **[R-ASBESTOS]** Efstathopoulos et al. SOSP 2005. https://pdos.csail.mit.edu/papers/asbestos-sosp05.pdf. **[R-LAMINAR]** Roy et al. PLDI 2009. https://www.cs.utexas.edu/~witchel/pubs/roy09pldi.pdf
- Result: Flume ran MoinMoin 30 to 40% slower with a 2% code change.
- Helios takes: no dynamic labels in the kernel. Static kernel partitions plus a userspace label server that holds declassification rights.

**[R-SPECTRE]** Kocher et al. https://spectreattack.com/spectre.pdf. **[R-MELTDOWN]** Lipp et al. https://meltdownattack.com/meltdown.pdf. **[R-KAISER]** Gruss et al. "KASLR is Dead: Long Live KASLR." ESSoS 2017. https://gruss.cc/files/kaiser.pdf

**[R-TIMEPROT]** Ge, Yarom, Chothia, Heiser. "Time Protection: The Missing OS Abstraction." EuroSys 2019. https://trustworthy.systems/publications/full_text/Ge_YCH_19.pdf. Heiser, Klein, Murray. "Can We Prove Time Protection?" HotOS 2019. https://arxiv.org/pdf/1901.08338. Sison. 2026 extended abstract. https://trustworthy.systems/publications/papers/Sison_26.pdf
- Idea: cache colouring, a kernel clone per partition, flushing on-core state at domain switch, padding switch time, partitioned interrupts.
- Result: IPC slowdown of 13 to 15% on Cortex-A9, "negligible" on x86. The proof is unfinished and needs a hardware contract (`fence.t` on CVA6).
- Helios takes: the security domain as a kernel object owning colours, a kernel clone, cores and interrupts.

**[R-CORESCHED]** Linux core scheduling. https://docs.kernel.org/admin-guide/hw-vuln/core-scheduling.html
- Helios takes: a physical core is the smallest unit of a security domain.

**[R-DOWNFALL]** Moghimi. USENIX Security 2023. https://www.usenix.org/system/files/usenixsecurity23-moghimi.pdf. **[R-INCEPTION]** Trujillo, Wikner, Razavi. USENIX Security 2023. https://www.usenix.org/system/files/usenixsecurity23-trujillo.pdf. **[R-GHOSTRACE]** Ragab et al. USENIX Security 2024. https://www.usenix.org/system/files/usenixsecurity24-ragab.pdf. **[R-INSPECTRE]** Wiebing et al. USENIX Security 2024. https://www.usenix.org/system/files/usenixsecurity24-wiebing.pdf. **[R-BPI]** Rüegge, Wikner, Razavi. USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/ruegge. **[R-VMSCAPE]** https://www.kernel.org/doc/Documentation/admin-guide/hw-vuln/vmscape.rst
- Helios takes: every domain crossing gets an explicit predictor barrier, including IPC between servers and the return to a userspace VMM.

**[R-MTE]** https://docs.kernel.org/arch/arm64/memory-tagging-extension.html. **[R-TIKTAG]** Kim et al. https://arxiv.org/pdf/2406.08719
- Helios takes: MTE as a bug detector, not a boundary.

**[R-PAC]** https://docs.kernel.org/arch/arm64/pointer-authentication.html. **[R-PACMAN]** Ravichandran et al. https://pacmanattack.com/paper.pdf (venue UNVERIFIED)

**[R-CET]** https://docs.kernel.org/arch/x86/shstk.html. **[R-LASS]** https://lkml.iu.edu/2510.3/07674.html

**[R-RISCV-CFI]** https://github.com/riscv/riscv-cfi. **[R-EPMP]** https://github.com/riscv/riscv-tee/blob/main/Smepmp/Smepmp.pdf

**[R-TDX]** https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html and Cheng et al. https://arxiv.org/pdf/2303.15540. **[R-SNP]** AMD SEV-SNP whitepaper (mirror): https://www.sas.com/content/dam/SAS/documents/marketing-whitepapers-ebooks/third-party-whitepapers/en/amd-sev-snp-strengthening-vm-isolation-with-integrity-protection-and-more.pdf. **[R-CCA]** Li et al. OSDI 2022. https://www.usenix.org/system/files/osdi22-li.pdf. **[R-KEYSTONE]** https://arxiv.org/pdf/1907.10119. **[R-COVE]** https://arxiv.org/pdf/2304.06167. **[R-TDX-GUEST]** Intel guest hardening. https://intel.github.io/ccc-linux-guest-hardening-docs/security-spec.html
- **[R-HECKLER]** Schlüter et al. USENIX Security 2024. https://www.usenix.org/system/files/usenixsecurity24-schluter.pdf. **[R-CACHEWARP]** Zhang et al. USENIX Security 2024. https://www.usenix.org/system/files/usenixsecurity24-zhang-ruiyi.pdf
- Helios takes: treat every host input as hostile in a confidential guest, and allowlist interrupt vectors per domain.

**[R-TPM]** https://trustedcomputinggroup.org/resource/tpm-library-specification/. **[R-DICE]** https://trustedcomputinggroup.org/work-groups/dice-architectures/. **[R-CALIPTRA]** https://github.com/chipsalliance/Caliptra

**[R-REPRO]** https://reproducible-builds.org/. **[R-SPDX]** https://spdx.dev/. **[R-CYCLONEDX]** https://cyclonedx.org/. **[R-CARGO-VET]** https://mozilla.github.io/cargo-vet/. **[R-CARGO-AUDIT]** https://rustsec.org/. **[R-CARGO-DENY]** https://embarkstudios.github.io/cargo-deny/

**[R-MLDSA]** FIPS 204. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf. **[R-SLHDSA]** FIPS 205. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf. **[R-LMS]** SP 800-208. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
- Helios takes: LMS for boot image signatures (signer state kept in an HSM, never rolled back) and ML-DSA for runtime attestation.

**[R-EROS-TWS]** Shapiro et al. "Design of the EROS Trusted Window System." USENIX Security 2004. https://www.usenix.org/legacy/event/sec04/tech/full_papers/shapiro/shapiro.pdf
- Helios takes: a secure attention sequence that only the console server can see and that always reaches the auth server.

**[R-SYZKALLER]** https://github.com/google/syzkaller. **[R-KERNELGPT]** Yang, Zhao, Zhang. "KernelGPT." https://arxiv.org/pdf/2401.00563
- Helios takes: a syzkaller description of the Helios ABI and coverage-guided fuzzing in CI.
