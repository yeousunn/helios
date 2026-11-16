# RFC-0005: The v0 register message is sufficient for M1 — the ADR-088 direction

- Proposed: GLM 2026-11-17
- Status: PROPOSED (awaiting NV acceptance — it decides ADR-088, which ADR-087 reserved, and corrects the §ABI packing of RFC-0001/ADR-064 the way ADR-087 corrected ADR-085; it changes invoke ABIs, so coordinator acceptance is required)
- Links: cites `docs/research/BIBLIOGRAPHY.md` entries [R-SEL4], [R-HYPERKERNEL], [R-COMMUTER], [R-IOURING], [R-FLEXSC], [R-SEL4-NTFN]. Builds on ADR-005 (wire format v1), ADR-011 (syscall engine), ADR-017 (NEW_THREAD packing), ADR-064 (RFC-0001 object model v2), ADR-085/ADR-087 (THREAD_CREATE w1, scope correction), ADR-089 (BootInfo self_thread).

## Problem

The v0 control message (ADR-005) is tag + 4 payload words that travel in registers
(`kernel/src/entry.rs` `SyscallArgs`: num + cap handle + tag + w[0..4] — exactly the six
argument registers x86_64, aarch64 and riscv64 give a syscall, after the syscall number).
When `cap_count = n`, capability descriptors overlay the **trailing** words
(`ipc::Message::descriptor`: descriptor *i* lives in `words[4 - n + i]`), so a message can
carry at most `4 - n` scalar words beside `n` descriptors.

That arithmetic has now collided twice:

1. **NEW_THREAD (ADR-017 packing, cap_count 3).** Three descriptors occupy w1..w3, so
   RFC-0004/ADR-085's `w1` = initial user stack top was read from packed descriptor bytes.
   ADR-087 scoped the stack top out of NEW_THREAD and reserved **ADR-088** for "the M1 IPC
   revision" — the board task A9b and DS's diff-AS benchmarks wait on it.
2. **RFC-0001's FACTORY_RETYPE table (accepted as ADR-064) cannot ride the format at all.**
   As accepted it wants `w0` = type, `w1` = size, `w2` = alignment, `w3` = numa_node plus
   `caps[0]` = Untyped, `caps[1]` = destination CNode, `caps[2]` = destination slot —
   4 scalars + 3 descriptors = 7 payload words. No `cap_count` provides that: at
   cap_count 3 only w0 is free; at cap_count 0 there are no descriptors to carry the
   Untyped. ADR-064's own validation line ("No IPC wire-format change") cannot hold for
   the table as written. The same is true, one word at a time, of every other M1
   invocation with both a full scalar set and more than one descriptor.

The obvious fix — grow the message — is not available for free. The message *is* the
register file: `tag + 4 words` is exactly what the arch entry decodes from six argument
registers on all three Tier-1 architectures. More words mean the message moves to memory
(a UTCB the caller points at, kernel-side translation, bounds-checked copy), which is a new
subsystem on every send/receive/invoke/reply path in kernel, `sdk`, all servers and the
emulator, with its own verification burden — and **no current consumer needs more than four
payload words.** The need that actually exists is structural: M1 needs packings that put
its primitives inside the budget that already exists.

This RFC proposes the ADR-088 decision: **keep the v0 wire format byte-for-byte; spend the
four words deliberately per invocation; add one Thread method; correct RFC-0001's
FACTORY_RETYPE packing; defer the big-message format to M4**, where rings (bet B2) give it
a real consumer. It serves PLAN.md principle 5 (finite, verifiable ABI: the dispatch stays
total on `(label, cap_count)`, every argument stays ranged) and principle 6 (the kernel
moves messages, never interprets them); it breaks no principle.

## Research basis

- **[R-SEL4]** seL4 passes IPC scalars in message registers and capabilities in a
  *separate* transfer area addressed by the message-info word (`label`, `length`,
  `extraCaps`) — scalars and caps never overlay. Helios v0 compresses that into six
  registers by overlaying descriptors on trailing words; the price is the arithmetic
  above. seL4's separation is restored in M4 by memory (a message block), not by more
  registers — no Tier-1 architecture offers more.
- **[R-HYPERKERNEL]** Hyperkernel's verification rests on a small, total, straight-line
  decode of every syscall. A register message keeps Helios's decode total and finite today:
  `tag + 4 words` with a `(label, cap_count)` dispatch is checkable by inspection and by
  Kani; a pointer-chased message block adds a translation, a bounds check and a copy to
  every decode. Staying in registers through M1 keeps the verified surface minimal.
- **[R-COMMUTER]** Every operation declares what it commutes with. Nothing here changes
  any commutativity class (table in §ABI); the corrected packings inherit the declarations
  already in `spec/abi`.
- **[R-IOURING]**, **[R-FLEXSC]**, **[R-SEL4-NTFN]** The transports that genuinely want
  more than a control message — bulk data, batching, async completion — move that data
  through shared memory rings with a small doorbell, not through wider control messages.
  That is exactly PLAN.md M4 (bet B2). Growing the control message before the ring exists
  would build a second bulk path nobody uses.

## Design

### 1. The budget, made explicit

With `cap_count = n`, a v0 message carries `4 - n` scalars:

| cap_count | free scalars | consumers |
|---|---|---|
| 0 | w0..w3 | THREAD_CREATE (w0 PC, w1 stack), CAP_MOVE, CAP_REVOKE, syscalls |
| 1 | w0..w2 | **FACTORY_RETYPE (corrected, below)**, AS_MAP (w0 vaddr, w1 flags) |
| 2 | w0..w1 | **NEW_THREAD uniform layout (below)** |
| 3 | w0 | NEW_THREAD legacy (ADR-017), bootstrap-mint |
| 4 | — | pure cap transfer (descriptor overlay test pins this) |

Every M1 primitive fits one of these rows. The two changes needed are capability-ABI
decisions, not wire changes.

### 2. NEW_THREAD uniform layout (the A9b unblock)

NEW_THREAD gains a second packing, discriminated by `cap_count` — the field the kernel
already dispatches on, so the change is total:

- **cap_count = 2 (new, uniform):** `w0` = entry PC, `w1` = initial user stack top
  (0 = arch default; otherwise the ADR-085/ADR-087 validation: nonzero, canonical user
  (< 2^63), 16-byte aligned, else EBADARG **before any child state** — the same code path
  THREAD_CREATE already runs, so the two stack rules cannot drift). `caps[0]` =
  AddressSpace (as today), `caps[1]` = bootstrap endpoint (optional, GRANT, installed at
  child handle 1 per ADR-009 — the descriptor that moved up from caps[2]).
- **cap_count = 3 (legacy):** byte-identical to ADR-017 — w0 = entry PC, w1..w3 are
  descriptor bytes and are **ignored** (no validation: descriptor bytes must not be
  stack-validated; ADR-087 decision 2 stands). Today's senders keep booting unchanged.
- **any other cap_count:** EBADARG (today 0/1 happen to work by accident — every sender
  uses 3 — and tightening costs nothing; the kernel tests pin this).

The fault endpoint leaves NEW_THREAD. It is **NULL in every production sender today**
(`init.rs`, `ps.rs`, `bench.rs` all send `with_caps(3)` with a NULL fault descriptor), so
removing it changes nothing observable; children are created exactly as they are now —
no fault EP bound, default fault path.

**The fault EP comes back as `Thread::BIND_FAULT_EP`, label 18** (ADR-087's sketch said
16, but TRAP_READ owns 16 and DEFER owns 17; 18 is the first free Thread label). Shape
mirrors BIND_DEATH_NOTIFICATION: requires CONTROL on the target Thread cap; `caps[0]` =
Endpoint (live, caller holds GRANT) or NULL to clear; the child's bound cap is installed
under the S8 rules (`rights ∩ requested` — never a full-rights copy, never an added
right); errors EBADCAP / ERIGHTS / EBADARG.

**ADR-017's rejection of "drop the fault EP" is answered structurally.** ADR-017 rejected
dropping caps[1] because it "reintroduces the pre-SET_FAULT_EP fault race". That race
cannot occur in this scheduler: a NEW_THREAD child is created `State::Ready`
(`sched::spawn`), and the cooperative scheduler cannot run a Ready thread while its parent
is Running — every syscall between NEW_THREAD and BIND_FAULT_EP (including the bind)
completes without yielding. The contract is stated and pinned:

- *Contract:* a launcher that wants fault routing on a NEW_THREAD child MUST invoke
  BIND_FAULT_EP before its first yield or block; until then the child cannot execute, so
  it cannot fault.
- *Pinned by:* a host test asserting a Ready child runs no instruction before the parent
  yields, plus the S2b/S2d discipline (no child state on a rejected call). An unbound
  child that faults takes the default path — the universal behavior today.
- ADR-017's atomic-at-creation binding remains available to the *kernel-internal* boot
  path (init's own spawn does not ride NEW_THREAD); if a future pager workload shows the
  bind-before-yield discipline is too weak (e.g. a preemptive scheduler in M2), ADR-088's
  successor can restore creation-time binding on a free word of the M4 format.

**Migration.** The kernel ships both packings in one change (kernel + `spec/abi` + host
tests — GLM's directories, no cross-area barrier). DS then moves the three production
senders from `with_caps(3)` to `with_caps(2)` (their files — Request on the board), and a
later IPC ADR (M2 housekeeping, not M1-blocking) deletes the legacy packing once no sender
uses it. Until DS migrates, both layouts work; nothing breaks in between.

This lands A9b: NEW_THREAD children can enter on a launcher-chosen stack, so DS's
diff-AS benchmarks can drop the SUSPEND → REGS_WRITE(slot 1) → RESUME interim, and
B1's context_switch_diff_as stops paying the stub.

### 3. FACTORY_RETYPE corrected packing (the RFC-0001 §ABI correction)

RFC-0001's accepted table needs 4 scalars + 3 descriptors; the overlay gives 7 words only
if descriptors stop being descriptors. The correction keeps every semantic RFC-0001 fixed
and changes only the packing and two placement details:

```
FACTORY_RETYPE (Factory label 5 — RFC-0001's number stands)
  w0     = target type (ObjType discriminant; set grows with M1: Untyped, CNode, ...)
  w1     = size in bytes
  w2     = alignment order (log2; 0 = natural alignment of the type)
  caps[0] = source Untyped cap (MAP right required)          [cap_count = 1 → words[3]]
  reply w0 = new capability handle (first-free install)
  reply w1 = remaining size of the source Untyped
```

- `cap_count` must be exactly 1 (0 or ≥ 2 → EBADARG): the THREAD_CREATE precedent — a
  fixed descriptor count keeps the w-reads unambiguous and the dispatch total.
- `w1 = size`: fixed-size types must pass exactly their fixed size (else EBADARG — no
  "ignored" ambiguity, so the kernel↔spec cross-check stays exact); variable-size types
  (Frame, CNode, Region, Untyped carve) accept `[type_min, source_remaining]`.
- `w2 = alignment order`: 0 = natural; otherwise `12 ≤ order ≤ 47` and
  `size % (1 << order) == 0`, else EBADARG.
- **Destination slot: first-free install, placement via CAP_MOVE.** RFC-0001's
  `caps[1]` = destination CNode / `caps[2]` = destination slot do not fit the overlay, and
  they are not needed: RFC-0001's own CAP_MOVE (w0 = src handle, w1 = dest CNode handle,
  w2 = dest slot, w3 = flags — 4 scalars, cap_count 0, fits v0 exactly) gives callers
  deterministic layouts. Cost: one extra call per placed object, measured in the M1 bench
  task; if it ever shows up, the M4 format absorbs it.
- **`w3` = numa_node: dropped, and inherited instead.** The source Untyped carries
  `numa_node`/`tier` (RFC-0001 §4.1.1); the carved object is created from that memory, so
  it *is* on that node — inheritance is strictly more truthful than a caller hint, and it
  keeps Retype at 3 scalars + 1 cap. Caller-chosen NUMA, if M8 ever wants it, rides the
  M4 format. PLAN.md puts NUMA-tagged Untyped in M8, not M1.
- **FACTORY_NEW_CNODE is not a separate method.** RFC-0001 defines label 6 both as
  NEW_CNODE and as "via Retype with target_type = CNode". Label 5 with type = CNode is the
  one spelling; **label 6 stays unassigned** so the spec never carries two names for one
  operation (NV's bench-marker task reads the CNode bench through RETYPE).

### 4. What changes nowhere

The 9-syscall set, tag layout, `CapSlot` encoding, descriptor-overlay mechanics, label
registry, FLAG semantics, `ipc::Message` itself: **untouched**. `ipc/src/lib.rs` has no
diff in this change. CAP_MOVE (4 scalars) and the CAP_REVOKE extension (w0 = mode, w1 =
max_steps, w2 = resume_token, EAGAIN returning the token in reply w0) already fit the v0
budget as RFC-0001 specified them — this RFC only records that they need nothing.

### 5. The M4 deferral, stated as design (not a shrug)

When M4 opens (bet B2), the control message gains one escape hatch, sketched here so the
deferral is a decision with a shape:

- `FLAG_BIGMSG` in `tag.flags()`: `w3` = user VA of a message block in the caller's AS
  (tag, scalar count, descriptor count, payload words, descriptors).
- The kernel translates the VA through the caller's AS, bounds-checks the block against a
  stated maximum (finite ABI: e.g. 64 words / 8 caps), copies once, and runs the **same**
  `resolve_transfers` rights checks as the register path — one shared check function, the
  B2 success criterion, enforced by a test.
- Everything M1 built rides both paths unchanged, because M1 stayed inside the register
  budget. That is the payoff of this RFC: M4 adds a *transport*, not a new ABI surface.

### Failure modes

- A legacy sender and a migrated sender mixed in one boot: fine — the dispatch is on
  cap_count, per message, not per process.
- A sender passing cap_count 2 with garbage in w1: rejected EBADARG before any child
  state (S2b/S2d discipline; fail-before test required).
- BIND_FAULT_EP on a dead/foreign thread: EBADCAP (CONTROL check, `sched::get` miss), no
  state change.
- RETYPE on a depleted Untyped: EBADARG (size > remaining) — the source cap is only
  reduced after every validation passes (all-or-nothing, like THREAD_CREATE).

## ABI

All ranges are per the template; every out-of-range value returns exactly the stated
error, before any state changes. `spec/abi` is extended in the same change (ADR-064
requires the kernel↔spec id cross-check to cover the new methods).

| # | Method | Packing (cap_count) | Ranges | Errors | Commutativity |
|---|---|---|---|---|---|
| 1 | NEW_THREAD (Factory, label 4) — **new** | **2**: w0 = entry PC, w1 = stack top; caps[0] = AddressSpace, caps[1] = bootstrap EP | w0: `is_user_addr`, else EBADARG. w1: 0, or nonzero ∧ < 2^63 ∧ (w1 & 0xF = 0), else EBADARG (ADR-085 validation). Other cap_count: 3 = legacy ADR-017 packing, w1 ignored, **no w1 validation**; anything else EBADARG | EBADARG, ERIGHTS, EBADCAP, ENOMEM (unchanged set) | Commutes (distinct AS objects; same-AS callers choose disjoint stack tops — equal tops alias, a caller bug as with overlapping MAP VAs) |
| 2 | BIND_FAULT_EP (Thread, **label 18**) — **new** | caps[0] = Endpoint or NULL (clear); no scalars | CONTROL required (else ERIGHTS); target live (else EBADCAP); bound cap live Endpoint + caller GRANT (else EBADARG/ERIGHTS); child receives rights ∩ requested (S8) | EBADCAP, ERIGHTS, EBADARG | Conflicts (target thread's fault-routing state) |
| 3 | FACTORY_RETYPE (Factory, label 5) — **corrected** | **1**: w0 = type, w1 = size, w2 = align order; caps[0] = Untyped (MAP) | w0: type in the M1 target set, else EBADARG. w1: fixed-size types exactly their fixed size; variable types in `[type_min, source_remaining]`, else EBADARG. w2: 0, or 12..=47 with `size % (1<<w2) = 0`, else EBADARG. cap_count ≠ 1: EBADARG. Source depleted/dead: EBADARG/EBADCAP | EBADCAP, ERIGHTS, EBADARG, ENOMEM | CommutesDisjointRanges on the source Untyped's ObjId ([R-COMMUTER]: Retypes on *different* Untypeds commute; on the same Untyped they conflict — carving is ordered) |
| 4 | CAP_MOVE (syscall 9) — **new, as RFC-0001** | 0: w0 = src handle, w1 = dest CNode handle (0 = process table), w2 = dest slot (or 0xFFFF_FFFF first-free), w3 = flags (bit 0 = delete source; other bits must be 0) | src: live cap + GRANT, else EBADCAP/ERIGHTS. dest slot < capacity, else EBADARG. w3 unknown bits: EBADARG | EBADCAP, ERIGHTS, EBADARG, ENOMEM | Commutes on disjoint (src, dst) slot pairs; Conflicts on the same destination slot. Creates **no** derivation edge (mint does) |
| 5 | CAP_REVOKE (syscall 7) — **extended, as RFC-0001** | 0: w0 = mode (0 = REVOKE_DERIVED, 1 = DELETE), w1 = max_steps, w2 = resume_token; handle in the cap register | mode ∈ {0,1}, else EBADARG. max_steps ∈ [1, 4096], else EBADARG. resume_token = 0 or a token this process holds, else EBADARG. More work: EAGAIN, reply w0 = resume_token | EBADCAP, ERIGHTS, EBADARG, EAGAIN | Conflicts (derivation tree is a global resource; per-shard in M3) |

Labels: Thread 18 is the only new label; Factory 5 is RFC-0001's; Factory 6 stays
**unassigned**; no syscall number beyond 9 is introduced (CAP_MOVE = 9 per RFC-0001).

## Verification plan

| Component | Tool | Scope |
|---|---|---|
| Dual-packing NEW_THREAD dispatch | Kani (A2 harnesses, when installed) + host tests | `(label, cap_count)` dispatch is total and cannot panic: cap_count 2 validates w0/w1 with the THREAD_CREATE code path (shared function — drift is a compile error), cap_count 3 ignores w1, others EBADARG. Fail-before: at HEAD, cap_count 2 with a kernel-window w1 is accepted (w1 is ignored) — the new packing's validator turns that into EBADARG before any child state. |
| Bind-before-yield race | Host test | A Ready NEW_THREAD child executes nothing before the parent yields: spawn child → BIND_FAULT_EP → assert child state/priority untouched → yield → child runs with the bound EP. Pins ADR-017's answered objection. |
| BIND_FAULT_EP semantics | Host tests | Bind live EP / clear with NULL / non-Endpoint caps[0] → EBADARG / no CONTROL → ERIGHTS / dead target → EBADCAP; S8 rights∩requested on the installed cap. |
| FACTORY_RETYPE packing | Host tests (M1 task) | cap_count ≠ 1 → EBADARG; fixed-size type with wrong size → EBADARG; align order out of range / not dividing size → EBADARG; source reduced only after all validation (all-or-nothing); reply w1 = remaining. |
| spec/abi cross-check | Existing test, extended | ids in `kernel/src/entry.rs` match the spec for BIND_FAULT_EP (18), RETYPE (5); NEW_THREAD's spec carries both packings (w1 stack_top at cap_count 2; w1_reserved at cap_count 3). |
| Attack suite | DS (Request) | BIND_FAULT_EP without CONTROL / non-Endpoint / dead target; RETYPE bad type/size/align; CAP_MOVE OOB slot, unknown flag bits; NEW_THREAD cap_count 2 with kernel-window or misaligned w1 → EBADARG and child-less. |
| Wire-compat | Existing boot | Every current sender (`with_caps(3)`) boots byte-identical through the legacy packing — the full QEMU gate is the regression test for "legacy means legacy". |

## Benchmark and success metric

- The G3 bench path (`send_recv`, `call_reply`) does not touch any changed method; the
  gate's boot must keep reaching DONE + clean halt with every sender still on the legacy
  packing, and again after DS's migration — no regression beyond the ADR-092 noise band.
- The M1 exit metrics are RFC-0001's (Retype + Mint round-trip ≤ 1.25× seL4 on the same
  hardware; `bench/scale` on disjoint Untypeds). This RFC adds one measurable of its own:
  the CAP_MOVE-placement cost of RETYPE+MOVE vs the RFC-0001 single-call ideal, recorded
  in the M1 bench task so the M4 format can be judged against a number, not a feeling.

## Kill criterion

If an M1 primitive cannot be expressed in the corrected packings — i.e. some Retype
target, CNode operation or derivation-tree walk genuinely needs more than 4 words of
scalars+descriptors per message and cannot be decomposed into RETYPE + CAP_MOVE — the
deferral is wrong: the M4 `FLAG_BIGMSG` format (§5) is pulled forward as an M1 task with
its ~2-cycle cost accepted, and this RFC's packings remain as the register fast path.
First checkpoint: the FACTORY_RETYPE implementation task, before any CNode work.

## Alternatives considered

1. **Grow MAX_WORDS to 8.** Impossible in registers (six argument registers on all Tier-1
   architectures after the syscall number); it silently makes every message
   memory-passed. Rejected for M1.
2. **Memory-passed UTCB messages now** (the full M4 design pulled forward). Touches every
   send/receive/invoke/reply path in kernel, `sdk`, all servers and the emulator; adds a
   translation + bounds check + copy to every decode ([R-HYPERKERNEL]'s verified surface);
   and no current consumer needs more than four words. ADR-005 already deferred bulk
   transport once ("ring + doorbell … after Phase 1 measurements"); this RFC defers it
   again, with a consumer (M4 rings) and a trigger (kill criterion) attached.
3. **Fixed descriptor area** (tag + 4 data words + 4 fixed descriptor words, no overlay).
   Same register-budget wall as (1); also wastes 4 words on every cap-less message.
   Rejected.
4. **Bit-packing scalars** (two u32s in one word, ADR-017-style juggling) to squeeze w3
   into NEW_THREAD. ADR-017 rejected bit-packing for priority as fragile; packing a
   64-bit stack top into half a word is not even possible. Rejected.
5. **Shrink RETYPE to 3 scalars and no size/align** (keep RFC-0001's w3/caps out by
   dropping w1/w2 instead). Loses caller-controlled carving granularity — frame/CNode
   sizes and alignments are the point of Untyped. The 3+1 packing fits; shrinking further
   buys nothing. Rejected.
6. **A new syscall number for a "THREAD2" with more registers.** The syscall set is frozen
   (ADR-005 §2: growth requires an ADR); a 10th syscall to spell one layout duplicates the
   dispatch the cap_count discriminator already gives. Rejected.

---

NV acceptance turns this into ADR-088 (the number ADR-087 reserved). On acceptance the
implementation splits into: (a) kernel + `spec/abi` + host tests — both NEW_THREAD
packings, BIND_FAULT_EP, the ADR-088-referencing comment fixes in `entry.rs`/`invoke.rs`
(two stale "ADR-086 proposal" citations — ADR-086 is the U2/U3 record, not the wire
decision); (b) DS: sender migration `with_caps(3)` → `with_caps(2)` in
`sdk/src/bin/init.rs`, `servers/process/src/bin/ps.rs`, `sdk/src/bin/bench.rs`, plus the
attack cases above; (c) M1 tasks (Untyped/Retype/Revoke/CNode) proceed per RFC-0001 as
corrected here, with A9b closing at (a).
