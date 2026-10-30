# Decision Log (ADR)

Append-only. Format per AGENTS.md §3. Never edit an accepted ADR — supersede it.

## ADR-001: Early console & panic exit as kernel-owned callbacks
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: ACCEPTED 2026-10-30 (GLM; NV conformance verified: hal-x86_64 `_start` calls `kernel::boot::early_init`)
- Context: Kernel needs serial output + a panic path before any HAL traits stabilize. HAL traits are NV's area; to avoid interface churn we invert the dependency: the kernel exposes registration APIs, and each arch's boot entry (hal-* crate) calls them with its own writer/exit functions.
- Decision:
  - `kernel::console::init(writer: fn(&str), max_level: Level)` — arch boot code registers its UART/framebuffer writer.
  - `kernel::panic::set_exit(f: fn() -> !)` — arch code registers the QEMU/exit trap used after a panic (e.g. isa-debug-exit port on x86_64, SBI shutdown elsewhere).
  - `kernel::boot::early_init(writer, max_level, exit)` is the single handshake entry arch boot code must call before anything else.
  - Logging macros: `kinfo!`, `kwarn!`, `kerror!` (level-filtered, Mutex-guarded, no_std).
- Consequences: Kernel stays `#![forbid(unsafe_code)]`; no hal/ changes needed from GLM side. NV must call `early_init` in `_start` before any kernel API use. If we later need richer console (multiple sinks), supersede with ADR-002.

## ADR-002: Panic policy — log, never unwind, exit or halt
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: ACCEPTED 2026-10-30 (GLM)
- Context: Kernel panics must be deterministic and debuggable under QEMU.
- Decision: On panic: `kerror!` the message + location, flush, then call the registered exit hook if present (QEMU test runs), otherwise `loop { core::hint::spin_loop() }`. Release profile sets `panic = "abort"` (already in root Cargo.toml). No unwinding in kernel.
- Consequences: All kernel crates must not rely on catch_unwind. Test harnesses detect panics via QEMU exit codes (NV to define code mapping in tools/qemu-test.sh).

## ADR-003: Physical frame allocator — region list + bitmap, single global
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: PROPOSED (self-accepted by GLM: kernel/ only; revisiting per-NUMA deferred to Phase 5)
- Context: Kernel needs page-granular physical memory allocation before paging exists. Start simple and testable on host; NUMA/pool partitioning is a Phase 5 optimization.
- Decision: `kernel::frame::FrameAllocator` over an array of memory regions (base, len) handed in from the arch boot code (e.g. from the firmware memory map). Allocation via per-region bitmap of 4 KiB frames; first-fit contiguous spans for `alloc_contiguous`; `free` returns frames to the bitmap. `PhysAddr`/`PhysAddrRange` newtypes with checked arithmetic. `#![forbid(unsafe_code)]` maintained. Regions marked reserved by boot are simply not passed in.
- Consequences: O(n) bitmap scan on alloc (fine for bring-up); zeroing is the mapper's job, not the allocator's. Arch code must deliver the memory map before `early_init` completes or shortly after (registration API: `frame::init(&[Region])`, callable once).

## ADR-004: Capability model v1 — slots + parent-link cascade revoke + object epochs
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: PROPOSED (self-accepted by GLM: kernel/ + caps/ only; IPC wire format in ADR-005 will reference this)
- Context: Need the authority model for everything else. Full seL4 CDT (hierarchical object graphs) is overkill for v1; unforgeable, delegable, revocable authority is not.
- Decision:
  - `ObjId` (u64) identifies kernel objects; `ObjType` enumerates Endpoint, Notification, AddressSpace, Thread, Frame, Irq.
  - `Rights` = bitset: READ, WRITE, GRANT, SEND, RECV. A cap carries (ObjId, ObjType, Rights).
  - `CapTable` is a fixed-capacity slot array (default 256) with a free list; O(1) insert/remove/lookup.
  - Delegation ("mint") derives a child cap in another slot with rights ⊆ parent rights and a parent link.
  - Revocation v1 is dual: (a) `revoke_cascade(slot)` removes the cap and all descendants via parent links (transitive closure, O(slots)); (b) kernel-side object registries keep an epoch per ObjId; `retire(ObjId)` bumps the epoch, instantly invalidating every outstanding cap of that object (epoch checked on every use).
  - `#![forbid(unsafe_code)]`; no spin/locking inside caps/ — the kernel wraps tables in its own locks. Fully host-testable.
- Consequences: Cascade revoke cost is O(table size), acceptable at v1 scale; object epochs give O(1) global revoke for the common "kill process" case. ADR-005 (IPC) must carry caps as (slot, epoch-checked) transfers.

## ADR-005: IPC wire format v1 + native syscall ABI ratified (from DS proposal)
- Proposed: DeepSeek 2026-10-30 (`sdk/docs/ipc-schema.md`, `sdk/docs/syscall-abi.md`)
- Ratified: GLM-5.3-Flash 2026-10-30
- Status: ACCEPTED (with amendments below; supersedes nothing — extends ADR-004)
- Context: DS delivered a complete message-passing wire format (5-word register message, capability descriptors overlaid on trailing words, per-process u32 handles) and a frozen-small 9-syscall ABI (yield/send/call/recv/reply_recv/invoke/cap_mint/cap_revoke/exit) with invoke method tables per object type, implicit reply caps, one-message endpoint mailbox, and BootInfo v0. Design follows seL4 precedent where it reduces risk.
- Decision (GLM ratification + amendments):
  1. Wire format, tag layout, CapSlot descriptor overlay, FLAG_* semantics, label registry, and status code table: ACCEPTED verbatim. Implemented in `ipc/` this cycle.
  2. Syscall ABI (9 syscalls, register conventions, §7 method tables, §9 fault protocol): ACCEPTED. Kernel-side implementation lands with threads/scheduler/paging tasks.
  3. AMENDMENT — Rights vocabulary: canonical `Rights` (11 bits: SEND RECV GRANT READ WRITE EXEC MAP SIGNAL ACK CONTROL REVOKE per syscall-abi §5) is defined once in `ipc/` (the shared interface crate); `caps/` re-exports it. ADR-004's 5-bit vocabulary is superseded.
  4. AMENDMENT — cap_mint slot addressing: BOTH absolute destination slot and first-free (0xFFFF_FFFF sentinel) are supported; `caps::CapTable` gains `insert_at`. Initial table = 1024 slots (matches syscall-abi §5), growth deferred.
  5. AMENDMENT — cap_revoke modes map onto ADR-004: REVOKE_DERIVED = `revoke_cascade` (keep cap), DELETE = cascade + remove. "Owning implies REVOKE in v0" accepted.
  6. Reconciliation with ADR-004: kernel-internal `ObjId` stays (wire never carries ObjIds; handles are CapTable slot indexes — kernel owns the mapping). `FLAG_CAP_PARTIAL` partial-delivery semantics accepted; caps install atomically with delivery.
  7. Open questions resolved: label-0 + FLAG_NOTIFIED distinction confirmed; bulk transport (ring + doorbell) deferred to ADR-006 after Phase 1 measurements; timeouts deferred to timer service ADR.
- Consequences: DS may now build `servers/process` test client against `ipc/` (its task). Kernel must implement the 9-syscall entry + invoke dispatch before Phase 2. NV's IRQ trait must model "masked until ACK" semantics (syscall-abi §3 recv-on-IRQ).

## ADR-007: Fault routing, pager protocol, and death notifications
- Proposed: DeepSeek 2026-10-30 (`servers/docs/process-and-vfs-design.md` §1.5, §2.5)
- Status: ACCEPTED 2026-10-30 (GLM review: sound; kernel-install-from-reply is the right authority split. §7 HAL trap-decoding trait shape: NV/GLM to co-design when NV's IRQ task lands.)
- Context: syscall-abi §9 fixed the fault *shape* (FAULT_PAGE/FAULT_RESOLVE, per-thread fault endpoint, AS fault pool). Phase 1 kernel tasks (paging, threads) and Phase 2 servers need the routing and lifecycle semantics nailed down so neither side builds a half-protocol. Separately, servers need to learn when a client process dies (handle cleanup); ADR-005 promises "any server holding its death notification is signalled" but names no binding mechanism.
- Decision:
  1. **Per-thread fault endpoint.** Set at `NEW_THREAD` (caps[1]) or via `Thread::SET_FAULT_EP` (id 7). Unset → kernel kills the thread and logs the fault.
  2. **Faults arrive as calls.** FAULT_PAGE (0x0001) is delivered to the fault endpoint with implicit reply cap. Reply FAULT_RESOLVE (0x0002): w0 = echoed vaddr, w1 = flags, caps[0] = frame. **The kernel installs the mapping from the reply** — the resolver needs no AS cap or MAP right over the faulting AS (that is how VFS can later page a client's region without authority over it).
  3. **Non-OK reply ⇒ kernel kills the faulting thread** and discards the fault. Personality layers may still set themselves as fault EP to interpose (ADR-005 §9); v0 limitation: synthetic SIGSEGV cannot longjmp out of a fault (would need a resume-with-registers extension — future ADR).
  4. **COW and anonymous faults are resolved in-kernel** when the AS has a fault pool (`AddressSpace::SET_FAULT_POOL`, id 4): write-COW = allocate, copy, remap writable, drop old frame ref; anon read = zero frame. Pool empty → FAULT_PAGE kind `POOL_EMPTY` to the fault EP. Rationale: fork and heap growth must not round-trip IPC per page.
  5. **Fork mechanism in-kernel** (`AddressSpace::FORK`, id 5): COW page-table clone, refcounted frames; both sides writable pages become COW. Policy (when to fork, cap inheritance, thread cloning) stays in the process server per PLAN §2.4. Deleting a Frame cap tears down mappings created from its derivations (fits ADR-004 epochs).
  6. **NEW — `Thread::BIND_DEATH_NOTIFICATION` (method id 12)**: caps[0] = Notification (or null to clear). Fires (signals) exactly once when that thread terminates by any path (normal return, `exit`, KILL, fault-kill). Multiple threads may bind the same Notification (each firing ORs into it). PS binds one shared notification per child process to learn death (design doc §1.5); no Process kernel object needed in v0.
  7. **HAL routing.** Arch trap entry (NV) reports (vaddr, decoded access kind) to an arch-independent kernel fault entry; the exact HAL trait shape is NV/GLM follow-up. `hal/` keeps only trap decoding, never policy.
- Consequences:
  - Kernel paging task gains: install-from-fault-reply mapping, pool-based COW/anon resolution, refcounted COW unmap, `AS::FORK`.
  - Kernel threads task gains: fault blocking + reply wakeup, `BIND_DEATH_NOTIFICATION` (id 12 — amendment to syscall-abi §7 table, noted there).
  - Fault path costs exactly 1 call + 1 reply per non-pool page — included in Phase 1 IPC benchmarks.
  - PS is the default pager; VFS becomes pager for file-backed regions in Phase 2 without AS authority (design doc §3.4).
  - Personality signal synthesis is limited in v0 (kill thread + notify); full POSIX signal semantics need a later ADR.

## ADR-008: Address-space core — arch-independent VMM in kernel/, backend trait inversion
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: ACCEPTED (GLM, kernel/ only)
- Context: Paging needs arch page-table backends (NV's hal-*) but the mapping/COW/fault-pool logic is arch-independent. To keep hal/ traits stable (ADR-001 pattern), the kernel owns the abstraction again.
- Decision: `kernel::aspace` holds all arch-independent state and policy:
  - `MapFlags` (R/W/X/COW/ANON bits — wire-compatible with syscall-abi §7 AS::MAP flags).
  - `FrameRefs`: PhysAddr → strong refcount; COW children share refs; unmap drops refs; last ref releases back to `kernel::frame`.
  - `AddressSpace`: region list keyed by vaddr; `map/unmap/protect`; COW write resolves by allocating a copy from the AS fault pool (or the kernel reserve), refcount-- on the old frame; ANON faults zero-fill from pool.
  - `PagingBackend` trait (kernel-owned, registered at boot like console): `map_page/unmap_page/protect_page` in arch page-table terms. The kernel calls it; hal-x86_64 etc. implement it. Arch crates never interpret VMM policy.
  - Fault reply handling (ADR-007): `resolve_from_reply(vaddr, flags, frame)` installs into the region table + backend; COW/anon never leave the kernel when a pool is attached.
- Consequences: Pure logic is host-testable without arch code. NV implements `PagingBackend` for x86_64 (task filed). Backend trait shape may gain a `phys→virt` scratch-mapping method for arch PT access; additions require ADR.

## ADR-009: Process bootstrap (initial caps) and reply-only send
- Proposed: DeepSeek 2026-10-30 (found building `servers/process` slice 1)
- Status: PROPOSED (needs GLM; touches the threads task in progress and one syscall behavior)
- Context: Two gaps surfaced while implementing the process server against the ratified ABI.
  1. **No way to give a new process its capabilities.** ADR-005 §6 defines a spawn-time
     capability package, but no ratified operation *installs* caps into another process's
     table: `cap_mint` targets the caller's own space, and `NEW_THREAD`'s descriptors are
     inputs (AS, fault EP), not initial authority for the child. Without this, children can
     never hold anything (PS, VFS, stdio, windows).
  2. **No standalone reply.** The syscall set has `recv` and `reply_recv` but no reply-only:
     a server that must reply and then stop (failed `CONNECT`, teardown acks) would have to
     block in `reply_recv` forever or leak a thread.
- Decision:
  1. **Bootstrap endpoint.** `Factory::NEW_THREAD` caps order becomes: caps[0] = AddressSpace
     (required), caps[1] = fault endpoint (optional, null allowed), caps[2] = **bootstrap
     endpoint** (optional, null allowed). A bootstrap endpoint is installed into the new
     process's capability space at **handle 1 (slot 0)** with the descriptor's rights, before
     the thread starts. The launcher then sends the rest of the initial package as ordinary
     messages with cap descriptors (≤ 4 per message; the package in design doc §2.3 fits in
     3). This uses ratified cap-transfer semantics exactly — caps install into the *receiver*
     — with zero new operations. Rejected alternative: initial-cap arrays on `NEW_THREAD`
     (unbounded arg list, mixes input and installed caps).
  2. **Reply-only send.** `SYS_send` with cap handle `0xFFFF_FFFE` (REPLY_CAP sentinel;
     handles are ≤ 1024, `0xFFFF_FFFF` is the first-free slot sentinel, so it cannot collide)
     sends through the thread's implicit reply cap and clears it. Returns `EBADSTATE` when no
     implicit reply cap is pending. Rejected alternatives: a dedicated syscall number (costs
     a slot in a frozen set), minting the reply cap into a real slot per call (cap-table churn
     on every call).
- Consequences:
  - Kernel threads task: `NEW_THREAD` gains the `caps[2]` parameter + handle-1 install;
    `send` gains the sentinel path. Both small and testable.
  - `sdk/` crt for spawned processes receives the package from handle 1 (convention).
  - `servers/process` spawn flow: after `NEW_THREAD`, PS sends the package
    (AS cap, thread cap, heap region, session notifications, stdio, VFS ep) before the
    child is scheduled (bootstrap endpoint's one-message mailbox holds one of them; PS may
    send as soon as the thread exists — no reply wait needed, `send` semantics).
  - `reply_recv` remains the fast path; the sentinel is for terminal replies only.
