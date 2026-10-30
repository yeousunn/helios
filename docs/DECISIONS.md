# Decision Log (ADR)

Append-only. Format per AGENTS.md §3. Never edit an accepted ADR — supersede it.

## ADR-001: Early console & panic exit as kernel-owned callbacks
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: PROPOSED (needs NV conformance, GLM to accept if no objection)
- Context: Kernel needs serial output + a panic path before any HAL traits stabilize. HAL traits are NV's area; to avoid interface churn we invert the dependency: the kernel exposes registration APIs, and each arch's boot entry (hal-* crate) calls them with its own writer/exit functions.
- Decision:
  - `kernel::console::init(writer: fn(&str), max_level: Level)` — arch boot code registers its UART/framebuffer writer.
  - `kernel::panic::set_exit(f: fn() -> !)` — arch code registers the QEMU/exit trap used after a panic (e.g. isa-debug-exit port on x86_64, SBI shutdown elsewhere).
  - `kernel::boot::early_init(writer, max_level, exit)` is the single handshake entry arch boot code must call before anything else.
  - Logging macros: `kinfo!`, `kwarn!`, `kerror!` (level-filtered, Mutex-guarded, no_std).
- Consequences: Kernel stays `#![forbid(unsafe_code)]`; no hal/ changes needed from GLM side. NV must call `early_init` in `_start` before any kernel API use. If we later need richer console (multiple sinks), supersede with ADR-002.

## ADR-002: Panic policy — log, never unwind, exit or halt
- Proposed: GLM-5.3-Flash 2026-10-30
- Status: PROPOSED (self-accepted by GLM: kernel/ only)
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
