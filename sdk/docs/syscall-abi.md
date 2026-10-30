# Helios Native Syscall ABI — Draft v0.1

- Status: RATIFIED as ADR-005 by GLM (2026-10-30) with amendments listed there
  (11-bit rights in `ipc/`, 1024-cap tables, first-free or absolute mint slots).
  Amendments proposed since: `Thread::BIND_DEATH_NOTIFICATION` (id 12, ADR-007).
  Authored by DeepSeek (DS), 2026-10-30.
- Applies to: native applications, system servers, personality layers. This is a
  register-level spec; the SDK may expose Rust wrappers, but any language can target it.
- Companion docs: `sdk/docs/ipc-schema.md` (message bytes),
  `servers/docs/process-and-vfs-design.md` (server protocols built on this).

## 1. Invariants

1. The object API is message passing. There is no `open`, no `mmap`, no `socket`
   syscall. Servers are built from `call` / `reply_recv`.
2. Kernel object *control* (threads, address spaces, frames, IRQs) is `invoke`:
   method dispatch on a capability, using the same message shape as `send`.
3. All authority is a capability. Handles are indices into a **per-process**
   capability table; a handle value is meaningless in another process.
4. Capability transfer rides messages (wire format v1), never a separate syscall.
5. The syscall set is intentionally frozen-small (9 entries). Growth happens in
   server protocols; burning a syscall number requires an ADR.

## 2. Register conventions

Every syscall takes `(cap, tag, w0..w3)` — the same shape as the message in
`sdk/docs/ipc-schema.md` §3. One logical layout, three architectures.

### x86_64 (`syscall` instruction; `rcx` and `r11` are clobbered by it)

| role | register |
|---|---|
| arg0 — destination cap handle | `rdi` |
| arg1 — tag | `rsi` |
| arg2..arg5 — w0..w3 | `rdx`, `r10`, `r8`, `r9` |
| syscall number | `rax` |
| return — status (0 or negative errno) | `rax` |
| return — tag | `rdx` |
| return — w0..w3 | `rsi`, `rdi`, `r8`, `r9` |

### aarch64 (`svc #0`)

| role | register |
|---|---|
| args — cap, tag, w0..w3 | `x0`..`x5` |
| syscall number | `x8` |
| return — status; tag; w0..w3 | `x0`; `x1`; `x2`..`x5` |

### riscv64 (`ecall`)

| role | register |
|---|---|
| args — cap, tag, w0..w3 | `a0`..`a5` |
| syscall number | `a7` |
| return — status; tag; w0..w3 | `a0`; `a1`; `a2`..`a5` |

Return tag/words registers are only meaningful when status is OK. `yield`,
`send`, `exit` return only a status. Floating point registers are never touched.

## 3. Syscalls

| # | name | semantics |
|---|---|---|
| 0 | `yield` | voluntarily deschedule the calling thread; no arguments beyond the number. Returns OK. |
| 1 | `send` | Dispatch on destination cap type — Endpoint: enqueue the message. Notification: atomically OR `w0` into the notification word; never blocks; other words ignored. IRQ: `EBADARG`. Blocking unless `FLAG_NONBLOCK`; returns when the message is accepted (delivered to a waiting receiver or stored in the endpoint's one-message mailbox), not when received. **Special cap handle `0xFFFF_FFFE` (REPLY_CAP): send through the thread's implicit reply cap and clear it — the reply-only escape hatch for terminal replies (ADR-009); `EBADSTATE` if none is pending.** |
| 2 | `call` | `send` **and** atomically wait for the reply. The kernel mints a temporary *reply capability* for the callee, delivered as the callee's implicit reply cap. Returns the reply's tag and words. |
| 3 | `recv` | Block on the destination cap (dispatch on cap type) — Endpoint: next message; sets the thread's implicit reply cap **iff** the message was produced by `call`. Notification: return pending mask in `w0` (immediately if nonzero, else block until signalled); tag label 0x0003 (NOTIFY), mask cleared on return. IRQ: block until the IRQ count increments; tag label 0x0004 (IRQ), `w0` = irq vector; the hardware line stays masked until `invoke(ACK)` (see §7). |
| 4 | `reply_recv` | Send a reply through the thread's implicit reply cap (from the last `recv`/`reply_recv`), then `recv` on the destination cap. The server fast path: one syscall per request/reply cycle. Returns `EBADSTATE` if no implicit reply cap is pending. |
| 5 | `invoke` | Method call on a kernel object capability. `tag.label` is the method id (§7). Same shape as the wire message, including capability descriptors. Synchronous; returns tag+words exactly like `recv`. |
| 6 | `cap_mint` | Derive a capability locally: `w0` = destination slot in own space (or `0xFFFF_FFFF` = first free), `w1` = requested rights mask, which must be a subset of the source's rights. On success the first return word = installed handle; the new cap records its parent for `cap_revoke`. (GRANT is only required to *transfer* a cap inside a message, not to mint a local child.) |
| 7 | `cap_revoke` | `w0` = mode — 0 = `REVOKE_DERIVED`: delete all capabilities derived from this cap (transitively), keep it; 1 = `DELETE`: also delete this cap. Deleting a Frame cap tears down every mapping created from any of its derivations (kernel tracks per-mapping origin). |
| 8 | `exit` | Terminate the calling thread; `w0` = status. The process dies when its last thread exits; all its capabilities are revoked, its resources are released, and any server holding its death notification is signalled. |

Everything else — file I/O, networking, time, GUI, process management — is a
server protocol.

### 3.1 Blocking and wakeups

- Endpoints have a one-message mailbox: at most one undelivered message sits in
  the kernel; further senders block in FIFO order until the receiver drains it.
  The exact queue structures are kernel-internal; the observable semantics above
  are the ABI.
- A thread blocked in `recv` may be woken by a *bound notification* (see
  `Thread::BIND_NOTIFICATION`): `recv` returns with `FLAG_NOTIFIED` set, `label 0`,
  `w0` = pending mask. The thread is not required to be blocked on the
  notification's own endpoint — this is the server "select" primitive.
- No timeouts in v0: a timer service (later) signals notifications; a client can
  use `reply_recv`/`recv` with a notification bound and treat timeout as cancel.
- Parked-syscall contract (ADR-019, GLM): a `recv`/`reply_recv` that parks returns a
  kernel-internal sentinel from `dispatch` (`i32::MIN`); the arch entry must switch
  contexts instead of returning to userspace, and re-enter through `park_result`
  on resume. Userspace only ever observes real results: the delivered message, or
  `OK + FLAG_NOTIFIED` with `w0` = consumed notification mask when a bound
  notification woke the park. The sentinel never reaches user space — SDK wrappers
  treat any non-OK status as an error, and `i32::MIN` appearing there would be a
  kernel bug.

## 4. Endpoint / call protocol recap

```
client: call(svc, req) ──────────────┐
server: recv(svc) → (implicit reply) │  request delivered
server: reply_recv(svc, reply) ──────┘  reply delivered to client's blocked call
```

- A reply targets the *specific blocked caller*, not the endpoint mailbox; it
  bypasses the one-message slot.
- If the caller died before the reply, the reply is discarded and `reply_recv`
  continues normally (the server observes the death via its death notification).
- `send` (not `call`) to a serving endpoint is allowed (fire-and-forget), but the
  receiver then has no implicit reply cap.

## 5. Capability handles and rights

- Handle = `u32` index, `0` = null. Per-process table, initially 1024 slots
  (growth policy open, §10). Handles are not capabilities: the kernel owns the
  mapping.
- Rights are a `u32` bitmask (`Rights` in `ipc/`). Vocabulary:

| bit | right | applies to | meaning |
|---|---|---|---|
| 0 | SEND | Endpoint | may send/call |
| 1 | RECV | Endpoint, Notification, IRQ | may receive/wait |
| 2 | GRANT | any | may be transferred in a message |
| 3 | READ | Frame | may be mapped readable |
| 4 | WRITE | Frame | may be mapped writable |
| 5 | EXEC | Frame | may be mapped executable |
| 6 | MAP | AddressSpace | may add/remove mappings |
| 7 | SIGNAL | Notification | may signal |
| 8 | ACK | IRQ | may acknowledge |
| 9 | CONTROL | Thread | kill, suspend, priority, regs, fault handler |
| 10 | REVOKE | any | may `cap_revoke` derived caps (owning implies it in v0; see ADR-004) |

Minting may only narrow rights. Mapping permission is checked as
`frame_rights ⊇ requested_mapping_flags` at `AddressSpace::MAP` time.

## 6. Spawn-time capability package

Every process is launched by the process server and starts with exactly these
capabilities (no ambient authority):

| capability | rights | purpose |
|---|---|---|
| self AddressSpace | MAP, GRANT | manage own mappings (mmap, stacks) |
| self Thread(s) | CONTROL | set TLS, priority; exit |
| heap Region | — (carve) | physical frames for heap/stacks |
| stdio endpoints x3 | SEND (in) / RECV (out) | console or pipes |
| VFS service endpoint | SEND, GRANT | talk to the filesystem |
| initial directory handle | (server-side) | cwd; the root of its namespace view |
| fault endpoint (held by launcher) | — | page fault resolution |

The init task (first userspace task, §8) is the only process with a Factory cap
and full Region caps.

## 7. Invoke method tables

Method ids are per object type; `invoke` returns `ENOSYS` for unknown ids.

### Factory (boot-granted only)

| id | method | args |
|---|---|---|
| 1 | NEW_ENDPOINT | returns new handle in w0 |
| 2 | NEW_NOTIFICATION | returns new handle in w0 |
| 3 | NEW_ADDRESS_SPACE | returns new handle in w0 |
| 4 | NEW_THREAD | w0 = entry PC, w1 = stack top, w2 = priority; caps[0] = AddressSpace (GRANT), caps[1] = fault endpoint (optional), caps[2] = bootstrap endpoint (optional) — a bootstrap endpoint is installed into the new process at handle 1 before it starts (ADR-009); returns thread handle in w0 |

### Region (physical memory grant; boot carves these for init, the process server carves for children)

| id | method | args |
|---|---|---|
| 1 | CARVE | w0 = size in bytes (power of two pages), w1 = alignment; returns Frame cap handle in w0 |

### Thread

| id | method | args |
|---|---|---|
| 1 | EXIT | w0 = status (same effect as syscall `exit` for this thread) |
| 2 | KILL | terminate immediately (no unwinding); CONTROL right required |
| 3 | SUSPEND | stop at next kernel entry |
| 4 | RESUME | |
| 5 | SET_PRIORITY | w0 = priority |
| 6 | SET_AFFINITY | w0 = CPU mask |
| 7 | SET_FAULT_EP | caps[0] = Endpoint or null to clear; page faults of this thread route here (§9) |
| 8 | BIND_NOTIFICATION | caps[0] = Notification or null; if the thread is blocked in `recv`, a signal wakes it with FLAG_NOTIFIED |
| 9 | REGS_READ | caps[0] = Frame; kernel writes the arch-defined register image (v0: x86_64 = rip, rsp, rflags, rax..r15, fsbase, gsbase; aarch64/riscv64 layouts follow their HAL) into the frame |
| 10 | REGS_WRITE | caps[0] = Frame; kernel loads the register image; used by fork and debuggers |
| 11 | SET_TLS | w0 = FS base (x86_64) / TPIDR_EL0 (aarch64) / tp (riscv64) |
| 12 | BIND_DEATH_NOTIFICATION | caps[0] = Notification (or null); fires exactly once when this thread terminates by any path — proposal, ADR-007 |

### AddressSpace

| id | method | args |
|---|---|---|
| 1 | MAP | w0 = vaddr, w1 = flags (bit0 R, bit1 W, bit2 X, bit3 COW, bit4 ANON-zero-fill); caps[0] = Frame to map (ANON ignores caps[0]) |
| 2 | UNMAP | w0 = vaddr, w1 = length in pages |
| 3 | PROTECT | w0 = vaddr, w1 = length in pages, w2 = flags (R/W/X) |
| 4 | SET_FAULT_POOL | caps[0] = Region; the kernel resolves COW-write and ANON faults for this AS directly from this pool (see ADR-002). Pool exhausted → FAULT_PAGE with kind POOL_EMPTY to the fault endpoint. Null clears the pool. |
| 5 | FORK | COW page-table clone of this AS (mechanism in the kernel): returns the new AddressSpace cap handle in w0; source AS keeps its mappings, both sides become COW for writable pages. Frames are refcounted. |
| 6 | DESTROY | tear down all mappings; frames' refcounts drop (automatic when the last cap to the AS is deleted) |

### Notification

| id | method | args |
|---|---|---|
| 1 | SIGNAL | w0 = mask to OR (equivalent to `send`) |
| 2 | CLEAR | w0 = mask to clear without receiving (race-free for shutdown paths) |

### IRQ

| id | method | args |
|---|---|---|
| 1 | ACK | re-arm the line; called after handling |

IRQ line caps are minted by the device manager (which holds boot-granted IRQ
provisioning authority) and gifted to driver processes with RECV+ACK rights.

### Endpoint and Frame

No methods in v0. Frame mappings are created through `AddressSpace::MAP`; the
frame cap's rights gate the flags. Endpoint behavior is entirely the syscall
semantics in §3.

## 8. Boot and init

- The kernel starts one userspace task (`init`) with a `BootInfo` struct written
  into its first stack page; the address is passed in the first argument register
  (`rdi` / `x0` / `a0`).
- `BootInfo` v0: `{ magic: u32, version: u32, debug_ep: u32, factory: u32,
  region_count: u32, regions: [ {handle: u32, base: u64, len: u64}; N ] }`.
  Debug endpoint = serial console (HAL-backed), for early logging from userspace.
- Init's job: start the process server (Factory + a large Region), the VFS
  (region for ramfs), the device manager (IRQ provisioning + its own regions),
  and the auth server; then relinquish its Factory and idle. This sequence is
  fixed by convention in Phase 0/1 and becomes the documented boot contract.
- Framebuffer/ACPI/multiboot details are HAL-facing and owned by NV; this ABI
  deliberately does not bake them in beyond the debug endpoint.

## 9. Fault handling (summary; full protocol in ADR-002)

- Per-thread fault endpoint (set via `Thread::SET_FAULT_EP`; `NEW_THREAD` can set
  it up front). No fault endpoint → the kernel kills the thread.
- The kernel sends FAULT_PAGE (label 0x0001) to the fault endpoint as a *call*:
  `w0` = kind (NOT_PRESENT, WRITE_COW, PERM, POOL_EMPTY), `w1` = vaddr,
  `w2` = access (R/W/X bits — bit0 read, bit1 write, bit2 exec).
- The resolver replies FAULT_RESOLVE (label 0x0002) via `reply_recv`:
  `w0` = echoed vaddr, `w1` = mapping flags, caps[0] = frame (wire example in
  `ipc-schema.md` §8.3). Status ≠ OK → the kernel kills the faulting thread and
  discards the fault.
- COW and anonymous faults never reach userspace when a fault pool is attached —
  the kernel resolves them directly (this is what keeps fork cheap).

## 10. Open questions

- Timeouts/cancellation: deferred to a timer service; the reply-cap model already
  supports "reply later"; cancel semantics (ECANCELED on rendezvous) need an ADR.
- Capability-space growth and `cap_mint` slot addressing (absolute vs
  first-free) — resolve with GLM alongside ADR-004.
- `REGS_READ/WRITE` image layouts per arch — NV/GLM to confirm in HAL terms.
- SMP: no thread migration syscall yet; `SET_AFFINITY` is a hint in v0.
- Debug/diagnostic endpoint needs a capability story (`debug_ep` from BootInfo is
  a special case; a proper story belongs to the device manager phase).
- seL4 precedent was followed where it saves design risk (register messages,
  implicit reply cap, cap derivation trees); deliberate departures: per-process
  (shared) cap table, one-message endpoint mailbox, kernel-side COW pool.
