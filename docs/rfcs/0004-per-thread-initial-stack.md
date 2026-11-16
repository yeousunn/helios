## RFC-0004: Per-thread initial user stack — explicit stack-top argument for NEW_THREAD and THREAD_CREATE

- Proposed: GLM 2026-11-17
- Status: ACCEPTED (NV 2026-11-17 as ADR-085; changes two invoke ABIs)
- Links: cites `docs/research/BIBLIOGRAPHY.md` entries [R-SEL4], [R-ZIRCON], [R-HYPERKERNEL], [R-COMMUTER], [R-KANI], [R-NROS], [R-MCS]

## Problem

Every thread the kernel starts enters userspace with the same initial stack
pointer: `USER_STACK_TOP` (`hal/x86_64/src/layout.rs:11`,
`0x0000_7FFF_FFFF_F000`), hardcoded by the arch backend's `init_context`
(`hal/x86_64/src/impl_x86_64.rs:1296,1345`). `NEW_THREAD` (Factory method 4)
and `THREAD_CREATE` (Thread method 13) take only the entry PC (`w0`,
`kernel/src/entry.rs:686-711,880-955`); there is no way for a caller to name a
different initial RSP.

The first thread of a process works because its launcher maps a stack region
ending at `USER_STACK_TOP` before the thread starts. Every additional thread
in the same address space enters on top of a live stack: its first pushes
overwrite the parent's (or sibling's) frames. This is the stack-aliasing
blocker recorded in ADR-080 and on the board (PSX, 2026-11-16): 5 of the 7
G3 benchmarks (`notification_wake`, `context_switch_same_as`,
`context_switch_diff_as`, `map_4k`, `unmap_4k`) cannot be implemented because
`bench` cannot give its spawned threads distinct stacks
(`sdk/src/bin/bench.rs` `spawn_thread`), and any future multi-threaded
server hits the same wall.

The working precedent (linrun's RSP-switch stub,
`personality/src/bin/linrun.rs:730`) papers over the gap in userspace: the
spawner carves a stack and writes a stub that switches RSP after entry. That
is per-program boilerplate every multi-threaded program must re-implement,
and it wastes a double entry on every thread start. The kernel owns thread
context creation; the initial RSP belongs in the thread-creation ABI.

This serves PLAN.md principle 5 (a finite ABI takes explicit slot arguments
instead of letting the kernel pick, validates every argument against a stated
range) and principle 3 (the principal pays: the caller maps the stack it
names). It breaks no principle: the kernel continues to interpret no user
memory, and the change is additive (0 = today's behavior).

## Research basis

- **[R-ZIRCON]** Zircon's `zx_process_start` takes an explicit initial stack
  pointer (`sp`) alongside the entry point — the initial register state of a
  new thread is caller-supplied, not kernel-chosen. Helios already follows
  this shape for the entry PC (`w0`); this RFC completes it for the stack.
- **[R-SEL4]** seL4 configures a new thread's entire initial context through
  TCB register writes (`seL4_TCB_WriteRegisters`), including SP; the kernel
  never invents user register values. Helios's REGS_WRITE path (S1/ADR-050)
  is the same mechanism; this RFC gives thread creation the same power in
  one step instead of a create-suspend-write-resume dance.
- **[R-HYPERKERNEL]** Hyperkernel restricts each syscall to bounded, easily
  validated work. The new argument is validated with the same two tests the
  entry PC already uses (`is_user_addr` + an alignment mask) before any
  kernel state is created.
- **[R-COMMUTER]** The scalable commutativity rule: state the commutativity
  of every operation. Thread creation already declares `Commutes`; the
  stack top is a value copied into the child's frame, so the class is
  unchanged (see ABI).
- **[R-KANI]** Kani checks panic freedom of syscall entry decoding. The new
  argument's decode path (u64 word, no arithmetic beyond an alignment mask)
  joins the A2 harness scope.
- **[R-NROS]** Per-node replicas wrap a sequential core; commuting operations
  run in parallel. Per-thread stacks let disjoint-thread operations (map/unmap
  on disjoint ranges) run on different cores without aliasing.
- **[R-MCS]** Time is a capability; each thread runs on a scheduling context
  with its own budget. The stack is the thread's own runtime storage, paired
  with its context.

## Design

`NEW_THREAD` and `THREAD_CREATE` gain a second message word: `w1` = the
initial user stack top (the RSP the thread enters with). The kernel treats it
as a value to validate and copy into the child's initial context — it never
reads, maps or tracks the stack itself.

Validation (both invocations, identical rule):

1. `w1 == 0` → arch default `USER_STACK_TOP` (today's behavior, bit for bit).
2. `w1 != 0` → require `is_user_addr(w1)` (nonzero, canonical lower half,
   the S2 rule already used for the entry PC) **and** `w1 & 0xF == 0`
   (16-byte aligned, the x86-64 SysV stack discipline; note the default
   `USER_STACK_TOP` itself satisfies this). Anything else → `EBADARG`,
   returned **before** `proc::create()` or any child state exists (the S2b/S8
   "a bad call costs no process slot" precedent).

Form, not mapping: like the entry PC, the kernel validates the address form
only. An unmapped stack top faults in the child at its first push and routes
to the child's fault endpoint (ADR-007) — the same contract as jumping to an
unmapped PC. Mapping the region `[w1 - size, w1)` is the caller's job, done
through the MAP invoke on the AS cap it already passes (principle 3: the
principal pays for the memory it names).

Implementation (kernel-internal, no HAL trait change): the existing rebuild
discipline already proves the pattern. `regs_write` (S1/ADR-050,
`kernel/src/sched.rs:802-806`) builds a fresh frame with `init_context` and
then overlays the user-owned slots with `mem::write_reg_image_user`
(`kernel/src/mem.rs:90`), which writes slot 1 (user RSP) into the real
iretq frame. Thread creation reuses exactly this: after
`b.init_context(kstack_top, entry_pc)` in `set_initial_pc`, the kernel
overwrites frame slot 1 and `user_regs[1]` with the validated stack top (one
new single-slot write helper in `kernel/src/mem.rs`, the allowlisted unsafe
module, with a `// SAFETY:` comment mirroring `write_reg_image_user`).
`REGS_READ` of the fresh thread then reports the caller's RSP, and a later
`REGS_WRITE` keeps working unchanged.

Failure modes: (a) caller passes a top outside its own mapping → child
faults at first push, observed on its fault EP — caller bug, same as a bad
entry PC; (b) two threads given the same top → they alias, which is exactly
what the argument exists to avoid and is undetectable by the kernel without
walking the AS on every spawn (rejected: cost on the creation path);
(c) misaligned top → rejected up front, so a thread never starts in a state
that violates the ABI's stack alignment invariant.

## ABI

Changed invocations (message words; descriptors, reply words and rights are
unchanged):

- **NEW_THREAD** (Factory, label 4): `w0` = entry PC (unchanged), **`w1` =
  initial user stack top (new)**, `w2`/`w3` reserved.
- **THREAD_CREATE** (Thread, label 13): `w0` = entry PC (unchanged), **`w1` =
  initial user stack top (new)**, `w2`/`w3` reserved.

Validation ranges:

- `w1 == 0`: valid; initial RSP = `USER_STACK_TOP` (`0x0000_7FFF_FFFF_F000`),
  the current behavior.
- `w1 != 0`: valid iff `w1 < 0x0000_8000_0000_0000` and `w1 != 0`
  (`is_user_addr`) and `w1 & 0xF == 0`; otherwise **`EBADARG`** (`-3`),
  returned before any child process, thread or capability state is created.
- No new error code is introduced (`EBADARG` is already in both invocations'
  error lists in `spec/abi::invoke`).

Commutativity ([R-COMMUTER], `spec/abi::commutativity`): both invocations
keep class `Commutes`. The stack top is a value copied into the child's
frame; the kernel reads no shared state to process it. `NEW_THREAD` on the
same factory concurrently still creates independent objects. The one
ordering constraint is caller-visible, not kernel-visible: two threads
created with the same top in one AS alias — callers choose disjoint regions,
the same way two MAP callers choose disjoint VAs.

`spec/abi` update (in the implementation task, per the ADR-073 rule that the
spec lands with or before the code): `FACTORY_NEW_THREAD` and
`THREAD_CREATE` `InvokeSpec`s gain the `stack_top` argument (range
`(0, 0x0000_8000_0000_0000)` with the 16-alignment refinement in the
description, `range_error: EBADARG`), the commutativity notes gain the
disjoint-tops rule, and the kernel cross-check test family (A1 precedent)
pins the kernel's validation against the spec's stated range.

Attack-suite cases (DS, after the kernel lands): `NEW_THREAD` and
`THREAD_CREATE` with `w1` = kernel-window (`0xFFFF_8000_0000_0000`),
non-canonical (≥ 2^63), null-adjacent misaligned (`0x8`), and misaligned
user (`USER_STACK_TOP - 8`) → all `EBADARG`, and the factory still mints a
fresh endpoint afterwards (no child state leaked). Same case shape as
S2b/S2c/S2d.

## Verification plan

- **Host unit tests (kernel, fail-before/pass-after):** (1) `NEW_THREAD` with
  a kernel-window `w1` returns `EBADARG` and creates no process (fails
  before: the word is ignored today and the call succeeds); (2) `THREAD_CREATE`
  with a misaligned user `w1` → `EBADARG`; (3) valid `w1` → the child's
  `REGS_READ` image slot 1 equals `w1` (mock backend; the overlay is
  kernel-side, backend-independent); (4) `w1 = 0` → image slot 1 equals the
  backend default, pinning the compat path.
- **Kani (A2 harness family, when available):** the decode of `w1`
  (`is_user_addr` + alignment) cannot panic for any u64 input.
- **Attack suite (DS):** the four `w1` rejection cases above.
- **Full gate:** the boot is unaffected (all current callers pass `w1 = 0`);
  `tools/qemu-test.sh` must stay green with DONE + clean halt.

## Benchmark and success metric

- The five blocked G3 benchmarks become implementable: `bench` maps a
  per-thread stack region (ANON frames via MAP on the AS cap it already
  holds) and passes its top in `w1` — no RSP-switch stub. Success: all 7
  benchmarks report results and `tools/bench.sh --compare` compares them.
- `call_reply` / `send_recv` numbers must not move (their `w1 = 0` path is
  byte-identical); the `--compare` 5% gate catches an accidental change.

## Kill criterion

If the spawn-time overlay proves unsound on a future arch backend (for
example one that builds the user context lazily at first dispatch, so a
pre-resume frame write is a no-op), the fallback is extending
`ContextBackend::init_context` with the initial RSP as a parameter — a HAL
trait change coordinated through NV. The ABI proposed here (`w1`) does not
change in that case; only the kernel-internal plumbing does.

## Alternatives considered

1. **RSP-switch stub per thread (linrun precedent).** Userspace-only, no ABI
   change, works today. Rejected as the permanent design: every
   multi-threaded program re-implements stub generation, and each thread
   start pays a double entry. Acceptable as DS's interim before this lands.
2. **Create → suspend → REGS_WRITE → resume dance.** Works today with the
   existing ABI (the returned child cap carries CONTROL|GRANT,
   `kernel/src/entry.rs:944-953`; `regs_write` rebuilds the frame with the
   caller's RSP; under the v0 cooperative scheduler the parent stays
   runnable until it blocks, so the child cannot run first). Rejected as the
   permanent design: four invocations per thread, a preemption race window
   between create and suspend that M3 opens, and `THREAD_CREATE`'s stated
   semantics ("starts at the aliased default") remain a footgun. Documented
   as the interim path on the board.
3. **Kernel picks the slot** (`RSP = USER_STACK_TOP - ordinal * 64 KiB`).
   Violates principle 5 (the kernel must not pick) and principle 3 (the
   kernel would map or track user stacks it did not get from the principal);
   also silently returns unmapped RSPs today's launchers never mapped.
   Rejected.
4. **Extend SET_ENTRY with the stack top too.** Unnecessary: REGS_WRITE
   already retargets RSP (S2d) on a quiescent thread; SET_ENTRY stays
   PC-only. Not taken — smaller ABI surface.
