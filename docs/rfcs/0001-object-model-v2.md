## RFC-0001: Object Model v2 — Untyped, Retype, Revoke, CNode, Derivation Tree, Badges

- Proposed: GLM 2026-11-14
- Status: PROPOSED
- Links: cites `docs/research/BIBLIOGRAPHY.md` entries [R-SEL4], [R-NROS], [R-COMMUTER], [R-HUBRIS], [R-SEL4-IF], [R-CORTENMM], [R-ATMOSPHERE]

### Problem

The current capability model (ADR-004) uses a fixed-capacity slot array (1024 slots) with parent-link cascade revocation and object epochs. This design has three fundamental limitations that prevent M1 exit criteria:

1. **Fixed object limits** — The kernel imposes hard caps (16 processes, 64 objects) because all kernel memory comes from a global frame allocator (ADR-003) with no user-managed accounting. PLAN.md M1 requires removing these limits via Untyped/Retype as the only kernel allocator.

2. **No caller-chosen slots** — Capabilities are inserted at the first-free slot, making capability addresses non-deterministic and preventing userspace from constructing stable capability layouts. PLAN.md principle 5 (finite ABI) requires callers to name destination slots.

3. **Cascade revoke is O(table size)** and not sharded for NR — The parent-link walk touches every slot in the table. For M3 (NR-wrapped CSpace), revocation must be bounded per call and sharded per replica [R-NROS].

4. **Badges lack generation numbers** — Current badges carry only rights. PLAN.md 4.2 requires badges encoding (principal, session, generation) so clients detect server restarts [R-HUBRIS].

This RFC serves design principles 2 (everything is a capability), 3 (principal pays), 5 (finite verifiable ABI), and 7 (policy in userspace). It breaks principle 1 (sequential core replicated for scale) only in that the derivation tree must be sharded for NR — this is addressed by the sharding design below.

### Research basis

- **[R-SEL4]** Untyped/Retype/Revoke as the sole kernel memory allocator. Capability derivation tree (CDT) with parent links. Badged endpoints with rights attenuation. Our model adopts the same three primitives but shards the derivation tree for NR.

- **[R-NROS]** Node replication (NR) wraps a sequential kernel core. The CSpace (capability tables + derivation tree) is a sequential structure replicated per NUMA node, with CNR logs for commuting operations. Our derivation tree must be sharded per replica with a bounded revoke walk.

- **[R-COMMUTER]** Every operation must declare its commutativity. Retype/Revoke on disjoint Untyped/derived caps commute; on overlapping they conflict. This maps to `CommutesDisjointRanges` in `spec/abi` with `ResourceKey::ObjId`.

- **[R-HUBRIS]** Generation numbers in task IDs (badges) allow clients to detect server restarts. Our badges encode (principal, session, generation) per PLAN.md 4.2.

- **[R-SEL4-IF]** Integrity and authority confinement proved for the capability model. Our Verus specification targets the same properties: a cap can only be created via Retype from an owned Untyped, and rights only decrease along derivation edges.

- **[R-CORTENMM]** Transactional, VMA-free page-table interface. Our VSpace object will use this; Untyped provides the frames.

- **[R-ATMOSPHERE]** Flat Verus proof of capability table and page tables. Our proof strategy follows: sequential CSpace specification in Verus, then NR wrapper verified separately.

### Design

#### 4.1.1 Untyped — the only source of kernel memory

`Untyped` is a kernel object representing a contiguous range of physical memory with:
- `base: PhysAddr` (page-aligned)
- `size: u64` (power of two, multiple of 4 KiB)
- `alignment: u64` (power of two, ≥ 4 KiB)
- `numa_node: u16` (PLAN.md 4.5: NUMA-tagged Untyped)
- `tier: u8` (memory tier: DRAM, CXL, PMEM, etc.)

All kernel objects (Thread, Endpoint, AddressSpace, Frame, CNode, Region, SchedContext, Domain, IOSpace, CoreGrant, Reply, Port, Ring) are created by **Retype** from an Untyped cap. The kernel never allocates from a global pool. The initial Untyped cap(s) are granted to init at boot (ADR-018 Region registry becomes Untyped).

Untyped caps carry `Rights::MAP | Rights::GRANT` (MAP allows Retype; GRANT allows transfer).

#### 4.1.2 Retype — carving objects from Untyped

`Retype` is a Factory invoke method (or a dedicated syscall) that consumes (part of) an Untyped cap and produces a new capability of a concrete type.

```
FACTORY_RETYPE (label = 5)
  w0 = target_type (ObjType)
  w1 = size (for variable-size objects: Frame, CNode, Region; ignored for fixed-size)
  w2 = alignment (for Frame/CNode/Region; power of two, ≥ 4 KiB)
  w3 = numa_node (for NUMA-aware allocation; 0xFFFF = current node)
  caps[0] = source Untyped cap (must have MAP right)
  caps[1] = destination CNode cap (optional; NULL = caller's CNode)
  caps[2] = destination slot (optional; 0xFFFF_FFFF = first free)
```

Validation:
- Source cap type = Untyped, rights ⊇ MAP
- Target type ∈ {Frame, CNode, Region, Thread, Endpoint, Notification, AddressSpace, SchedContext, Domain, IOSpace, CoreGrant, Port, Ring}
- Size ≥ minimum for type (Frame: 4 KiB; CNode: 1 KiB slots; Region: 4 KiB; others: fixed)
- Size ≤ source Untyped remaining size
- Alignment ≥ 4 KiB, power of two, size multiple of alignment
- If dest CNode provided: caller must have GRANT on it; slot must be free or first-free

On success:
- Source Untyped cap is reduced (base advanced, size decreased) — **in place** if size remains > 0, else cap is deleted.
- New cap installed at destination slot with default rights for the type (see capability.rs defaults).
- Returns new cap handle in w0.

Commutativity: `CommutesDisjointRanges` on the source Untyped's ObjId. Two Retypes on the same Untyped conflict (sequential carving).

#### 4.1.3 Revoke — bounded, resumable, sharded

`Revoke` walks the derivation tree from a given cap and revokes all descendants. The current cascade revoke (ADR-004) is O(table size) and unsharded.

**v2 design:**
- The derivation tree is stored as a **forest of per-object parent/child links** in the object registry (ADR-026 `objreg`), not as a per-CNode parent-link array.
- Each object registry entry has: `parent: Option<ObjId>`, `children: Vec<ObjId>` (bounded, fixed-capacity array).
- Revocation is a **bounded walk**: the syscall takes a `max_steps` argument (default 256). It processes up to `max_steps` nodes, returns `(revoked_count, resume_token)`. A `resume_token = 0` means complete; non-zero means call again with the token to continue.
- For NR (M3): the derivation tree is **sharded per replica**. Each replica owns the subtree for objects created on that node. Revoke on a local cap walks only the local shard. A global revoke (rare) is a multi-replica protocol — deferred to M3.

Validation:
- Cap must have REVOKE right (or be the root of an owned Untyped).
- `w0 = mode`: 0 = REVOKE_DERIVED (keep cap), 1 = DELETE (revoke all including self).
- `w1 = max_steps` (1..=4096, default 256).
- `w2 = resume_token` (0 for new revoke, non-zero to continue).

Errors: EBADCAP, ERIGHTS, EBADARG, EAGAIN (if more work remains; resume_token in w0).

Commutativity: `Conflicts` (global resource: derivation tree). On NR, local shard revokes commute with other shards.

#### 4.1.4 CNode — caller-chosen slots

`CNode` is a kernel object: a capability table with fixed capacity (configurable at creation via Retype size). Default capacity 1024 slots (matching current).

- `FACTORY_NEW_CNODE` (label = 6, via Retype with target_type = CNode) creates a new CNode.
- `CAP_MINT` and `CAP_MOVE` (new syscall, see below) take an explicit destination slot. The `0xFFFF_FFFF` sentinel means "first free".
- `CAP_REVOKE` operates on a cap by its handle (slot), not by ObjId.

This satisfies principle 5: callers name slots, so capability layouts are deterministic.

#### 4.1.5 Derivation tree — parent/child links in objreg

The object registry (ADR-026) is extended:
```rust
struct ObjRegEntry {
    obj: ObjId,
    typ: ObjType,
    owner_pid: ProcessId,
    epoch: u64,
    alive: bool,
    parent: Option<ObjId>,        // NEW: creator object
    children: BoundedVec<ObjId>,  // NEW: direct derivatives (capacity 32)
}
```
- On Retype: child's `parent = Some(source_untyped.obj)`; source's `children.push(child.obj)`.
- On Mint: child's `parent = Some(source.obj)`; source's `children.push(child.obj)`.
- On Revoke: walk `children` recursively. For each descendant: mark `alive = false`, bump `epoch`, remove from CNode(s). Clear `children` of revoked nodes.
- The walk is bounded by `max_steps`. A resume token encodes the current stack position (node + child index).

This structure is Verus-friendly: a finite forest with bounded depth (max derivation depth = 16, enforced at Retype/Mint).

#### 4.1.6 Badges with generation numbers

Endpoint badges change from opaque `u64` to a structured encoding:
```
bits 0..31  = principal (uid)
bits 32..47 = session (epoch)
bits 48..63 = generation (server restart counter)
```
- On `NEW_ENDPOINT`: badge = (caller's principal, new session, 0).
- On `MINT` of endpoint: badge preserved (rights may be attenuated).
- On server restart: server creates new endpoint with same principal/session, generation+1. Clients see generation mismatch and reconnect.

This satisfies PLAN.md 4.2 and [R-HUBRIS].

#### 4.1.7 CAP_MOVE — transfer without derivation

A new syscall `CAP_MOVE` (num = 9) transfers a capability to another slot/CNode without creating a derivation edge (no parent link). Used for:
- Moving caps between CNodes of the same process (e.g., thread-local to shared).
- Installing bootstrap caps at fixed slots (ADR-009).

```
CAP_MOVE
  w0 = src_handle
  w1 = dest_cnode_handle (0 = current process CNode)
  w2 = dest_slot (0xFFFF_FFFF = first free)
  w3 = flags (bit 0 = delete source after move)
```
Requires GRANT on source cap and GRANT on dest CNode. No derivation edge created.

### ABI

New syscalls / invoke methods:

| Number/Label | Name | Args | Range | Error | Commutativity |
|---|---|---|---|---|---|
| INVOKE label 5 | FACTORY_RETYPE | w0=type, w1=size, w2=align, w3=numa, caps[0]=Untyped(MAP), caps[1]=dest CNode(GRANT), caps[2]=dest slot | type ∈ valid ObjType; size ≥ min; align ≥ 4K power of 2; numa < max_nodes | EBADCAP, ERIGHTS, EBADARG, ENOMEM | CommutesDisjointRanges (source Untyped ObjId) |
| INVOKE label 6 | FACTORY_NEW_CNODE | (via Retype with type=CNode) | size ≥ 1K slots, power of 2 | EBADCAP, ERIGHTS, EBADARG, ENOMEM | Commutes |
| Syscall 9 | CAP_MOVE | w0=src, w1=dest_cnode, w2=dest_slot, w3=flags | src valid cap with GRANT; dest_cnode valid with GRANT; slot < capacity | EBADCAP, ERIGHTS, EBADARG, ENOMEM | Commutes (dest CapSlot) |
| Syscall 7 (extended) | CAP_REVOKE | w0=mode, w1=max_steps, w2=resume_token | mode ∈ {0,1}; max_steps ∈ [1,4096] | EBADCAP, ERIGHTS, EBADARG, EAGAIN | Conflicts (global / per-shard) |

Existing `CAP_MINT` unchanged (creates derivation edge). Existing `CAP_REVOKE` extended with `max_steps`/`resume_token` for bounded resumable revoke.

Validation ranges for all new arguments are explicit above. Every range violation returns the stated error code.

### Verification plan

| Component | Tool | Scope |
|---|---|---|
| Untyped/Retype state machine | Verus | Sequential specification: Untyped size decreases, new object created, derivation edge added. Prove: no Untyped memory leaked, rights only decrease, fixed derivation depth. |
| Derivation tree (objreg) | Verus | Forest invariants: each node has ≤1 parent, children bounded, no cycles. Revoke walk visits each node at most once. Bounded steps = bounded time. |
| Revoke resumption | Verus + TLA+ | TLA+ model of bounded walk + resume token. Prove: repeated calls with resume_token eventually complete, no node skipped or double-revoked. |
| CNode slot allocation | Flux | Index bounds: slot < capacity, no double-insert. |
| Badge encoding/decoding | Kani | Panic-freedom for packing/unpacking principal/session/generation. |
| NR sharding (M3) | Verus (later) | Per-replica derivation tree shards. Local revoke commutes with other shards. |
| Attack suite | Testing | Retype size overflow, revoke resume token tampering, badge generation spoofing, CNode slot exhaustion. |

### Benchmark and success metric

- `bench/ipc`: Capability creation (Retype + Mint) round-trip ≤ 1.25x seL4 on same hardware (PLAN.md goal).
- `bench/scale`: Retype/Revoke on disjoint Untyped/derived caps by different processes on 8 cores scales within 80% of linear (bet B1 target).
- `tools/verify.sh`: Verus proofs for CSpace pass in CI.

### Kill criterion

If the Verus proof of the sequential CSpace (Untyped/Retype/Revoke + derivation tree) exceeds 6 person-months, ship the NR wrapper as trusted code with Kani checks (bounded revoke, derivation depth) and keep the sequential Verus proof for the core only. This is bet B1's kill criterion (PLAN.md 3.1).

### Alternatives considered

1. **Keep fixed limits + global allocator** — Rejected: violates principle 3 (principal pays), blocks M1 exit.
2. **Epoch-only revoke (no derivation tree walk)** — Rejected: cannot revoke individual caps, only whole objects. seL4 CDT needed for selective revocation.
3. **Unbounded revoke syscall** — Rejected: violates principle 5 (bounded ABI). Bounded + resumable is the standard pattern [R-SEL4].
4. **Capabilities as raw pointers (CHERI-style)** — Rejected: CHERI is a research target (micro-cheri profile), not the baseline. Current model works on all Tier 1 architectures.
5. **Single global derivation tree for NR** — Rejected: would serialize all revokes across nodes. Sharding is required for scaling [R-NROS].

---

This RFC proposes the complete object model v2. NV acceptance is required (changes ABI, kernel objects, and milestone M1 scope).