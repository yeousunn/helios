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
