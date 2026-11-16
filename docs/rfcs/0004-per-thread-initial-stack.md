## RFC-0004: Per-thread initial user stack for NEW_THREAD/THREAD_CREATE

- Proposed: NV 2026-11-17
- Status: PROPOSED
- Links: PLAN.md section 2 principle 5 (finite verifiable ABI), PLAN.md M3 (multicore), PLAN.md bet B1 (verified scaling); cites [R-SEL4], [R-NROS], [R-COMMUTER], [R-MCS], [R-SKYLOFT]

### Problem

Today `NEW_THREAD` (FACTORY invoke label 4) and `THREAD_CREATE` (Thread invoke label 13) take only `w0 = entry_pc`. The kernel stages the child's initial user stack at the arch constant `USER_STACK_TOP` (hal/x86_64/src/layout.rs:31) for every thread in the same address space. All threads in one AS therefore share one stack and alias each other's frames. This is sound for the v0 cooperative scheduler but blocks M3 scaling and bet B1's `bench/scale`: commuting map/unmap operations on disjoint ranges cannot run on separate threads because the threads clobber one another's stacks. It also blocks B1's remaining 5 benchmarks (notification_wake, context_switch_same_as, context_switch_diff_as, map_4k, unmap_4k), which need per-thread stacks.

This serves principle 5 (finite, explicit ABI: every argument is named and range-checked) and principle 2 (the stack is per-thread state the principal pays for through its own Untyped, not an implicit kernel global).

### Research basis

- **[R-SEL4]** Capabilities as the only authority; every object is created and managed by its owner. The initial stack is memory the caller owns, so it should be an explicit capability argument, not an arch constant.
- **[R-NROS]** Per-node replicas wrap a sequential core; commuting operations run in parallel. Per-thread stacks let disjoint-thread operations (map/unmap on disjoint ranges) run on different cores without aliasing.
- **[R-COMMUTER]** Every operation declares its commutativity. NEW_THREAD/THREAD_CREATE on disjoint cap slots commute; per-thread stacks are a per-thread resource, so they do not introduce cross-thread conflicts.
- **[R-MCS]** Time is a capability; each thread runs on a scheduling context with its own budget. The stack is the thread's own runtime storage, paired with its context.
- **[R-SKYLOFT]** Preemption reaches userspace through a HAL primitive; a preempted thread must resume on its own stack, never a shared one.

### Design

`NEW_THREAD` and `THREAD_CREATE` gain a second argument `w1 = initial_stack_top`:

- `w1 = 0` (default): the kernel uses the arch default `USER_STACK_TOP` for the thread's initial user stack. Preserves v0 behavior.
- `w1 != 0`: must be a canonical user address (`is_user_addr(w1)`) and 16-byte aligned. The kernel uses `w1` as the child's initial user stack pointer (`rsp` at entry). If out of range or misaligned, the invoke returns `EBADARG` before any child state (thread cap, stack allocation, register frame) is created.

Validation happens before any mutation: `is_user_addr(w1)` and `(w1 & 0xF) == 0` are checked first; on failure, `EBADARG` and no side effects. The stack memory itself must already be mapped in the target address space (the caller is responsible; a stack that is not mapped faults on first use, which is the caller's error, not a kernel hole).

The thread cap returned carries `CONTROL | GRANT` as before. `THREAD_SET_ENTRY` (label 14) is unchanged; it sets the entry PC only, not the stack.

### ABI

Changed invoke methods:

| Label | Name | New arg | Range | Error | Commutativity |
|---|---|---|---|---|---|
| FACTORY invoke 4 | NEW_THREAD | `w1 = initial_stack_top` | 0 = arch default; else canonical user addr, 16-byte aligned | `EBADARG` if `!is_user_addr(w1)` or `w1 & 0xF != 0` | `Commutes` (dest CapSlot; per-thread stack, no shared state) |
| Thread invoke 13 | THREAD_CREATE | `w1 = initial_stack_top` | 0 = arch default; else canonical user addr, 16-byte aligned | `EBADARG` if `!is_user_addr(w1)` or `w1 & 0xF != 0` | `Commutes` (dest CapSlot; per-thread stack, no shared state) |

Validation ranges are stated per argument above; every violation returns the stated error, nothing else. `spec/abi` (A1) `InvokeSpec` entries for `FACTORY_NEW_THREAD` and `THREAD_CREATE` gain the `w1` argument with the same `range_error: EBADARG`; `spec/abi/src/commutativity.rs` entries keep `Commutativity::Commutes` with `ResourceExtractor::CapSlot`. No syscall number, error code, or wire-format change beyond the added argument word.

Commutativity note: NEW_THREAD/THREAD_CREATE create independent thread state (cap slot, register frame, stack pointer). Two creates on disjoint destination slots commute even in the same address space, because each thread's initial stack pointer is distinct. Only operations on the same destination slot conflict.

### Verification plan

| Component | Tool | Scope |
|---|---|---|
| w1 argument decoding | Kani | Panic-freedom of `is_user_addr(w1) && (w1 & 0xF) == 0` for all u64 inputs; no side effects on failure. |
| Validation range | Flux | Index/bounds: `w1` is either 0 or a valid user address; alignment check is exact. |
| spec/abi cross-check | Test | `spec/abi` host test asserts the `w1` InvokeArg matches the kernel's entry.rs decoding. |
| Attack suite | Testing | `w1` = kernel address → EBADARG; `w1` = misaligned user addr → EBADARG; `w1` = 0 → arch default (OK); `w1` = valid user addr → OK, thread starts at w1 rsp. |

### Benchmark and success metric

- `bench/scale`: map/unmap on disjoint ranges by different threads in one AS, 1→8 cores on QEMU `-smp`, within 80% of linear (bet B1 target). Previously blocked by stack aliasing; unblocked by per-thread `w1`.
- B1's remaining 5 benchmarks (notification_wake, context_switch_same_as, context_switch_diff_as, map_4k, unmap_4k) become implementable with per-thread stacks.

### Kill criterion

If per-thread stacks cannot be validated without a kernel-side mapping check (i.e., the kernel must walk the VSpace to confirm `w1` is mapped before accepting it, adding unbounded work to the ABI), fall back to `w1 = 0` arch-default only and require userspace to switch stacks explicitly via an RSP-switch stub (linrun precedent). The commutativity and ABI structure are unchanged; only the default differs.

### Alternatives considered

1. **Always arch default (status quo)** — rejected: stack aliasing blocks per-core scaling and B1's 5 benchmarks.
2. **Kernel-validated mapped stack** — rejected: requires a VSpace walk (potentially unbounded page-table traversal), violating principle 5 (bounded ABI). The caller is responsible for mapping; unmapped stack faults on first use.
3. **Separate SET_STACK invoke** — rejected: adds a syscall for what is naturally a creation argument; two-step creation races (create then set stack) leave a window where the thread runs on the wrong stack.
4. **Stack cap argument (cap slot instead of VA)** — rejected: would require a new Stack object type (M1+ scope); a raw VA is simpler and the caller already owns the memory.

---

This RFC proposes an ABI change to NEW_THREAD and THREAD_CREATE. NV acceptance is required (changes syscall arguments, PLAN.md principle 5).
