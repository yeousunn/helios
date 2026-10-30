# Process Server and VFS — API Surface Design (Phase 0)

- Status: draft delivered by DeepSeek (DS), 2026-10-30. Phase 0 task: design doc, no code.
- Built on: ADR-004 (capability model), ADR-005/`sdk/docs/syscall-abi.md` (syscall ABI),
  `sdk/docs/ipc-schema.md` (wire format v1). Label constants referenced here live in
  `ipc::labels` (`process::BASE = 0x0100`, `vfs::BASE = 0x0200`).
- Kernel implications are collected in proposed **ADR-007** (fault routing, pager
  protocol, death notifications); Phase-2-only deltas are listed in §6 Open questions.
- Scope: the message-level API surface of `servers/process` and `servers/vfs`. POSIX
  semantics (signals, fds, process groups) stay in the personality layer.

## 1. Common server conventions

1. **One service endpoint.** Every server is reachable through exactly one capability
   to its service endpoint. Holding the cap is necessary; it grants nothing by itself
   (no ambient filesystem/network view — that comes from handles, §1.4).
2. **Per-client connection.** State is bucketed per connection:
   - `CONNECT` handshake on the service endpoint: client sends its session
     notification and the two window frames; the server allocates a client record,
     mints a fresh **connection endpoint**, and returns its cap in the reply.
   - All later operations go to the connection endpoint, served by a dedicated
     **connection thread** (`recv`/`reply_recv` on that endpoint). The endpoint *is*
     the connection identity — no client-supplied id is trusted.
   - Rationale: endpoint-per-connection needs zero kernel features (a sender-badge
     mechanism would be an ADR-005 amendment); cost is one endpoint object + one
     server thread per connection, acceptable at v0 scale (see §6).
3. **Argument/result windows.** Two frames are transferred at connect (arg =
   server reads, result = server writes). **v0: one 4 KiB frame per window** —
   `AddressSpace::MAP` is page-granular (ADR-021); larger windows land with
   multi-page maps. The server maps each window lazily at a server-specific VA
   base (`sdk::layout::{PS,VFS}_WINDOW_VA_BASE`, distinct per server so the
   kernel-wide v0 VMM never collides; `sdk::window::WindowMapper` encapsulates
   the mapping + safe byte access). Strings and small structs travel in the
   windows; register words carry `(offset, len)` pairs packed as `u32(u32)`.
   Client-side, a per-connection lock serializes window use (SDK responsibility);
   server-side, the connection thread serializes it naturally.
4. **Handles.** Servers mint server-private `u64` handles
   (`{generation: u16, kind: u8, index: u48}`) bound to a client record. A handle from
   another connection is rejected by the `(client, handle)` check — unforgeable
   without kernel caps. Handles are *not* transferable to other connections in v0
   (see §6, open question).
5. **Death notifications.** A process needs servers to learn of its death (handle
   cleanup, locks, sessions). v0 pattern (mechanism in ADR-007):
   - PS binds one **death notification `N_dead`** per process (via
     `Thread::BIND_DEATH_NOTIFICATION`) to every thread it creates for that process;
     the first thread exit signals it and the PS reaper for that process reacts.
   - At spawn, PS mints a small pool of **session notifications** (v0: 4) into the
     child; the child grants one per server connection at `CONNECT`.
   - Each server connection thread binds its session notification
     (`Thread::BIND_NOTIFICATION`), so its blocking `recv` wakes with `FLAG_NOTIFIED`
     when the client dies, and it tears the connection down.
   - On `N_dead`, the reaper signals *all* of the child's session notifications
     (blindly — an unused one just accumulates a bit) plus the parent's `WAIT`
     notification. No per-connection bookkeeping in PS.
6. **Reply shape.** Replies start `w0 = status` (`ipc::status` codes). Servers never
   invent codes; the POSIX personality translates to errno at its boundary.
7. **Server loop.** `recv(svc)` once, then `reply_recv(svc, ...)` per request
   (syscall-abi §4). Heavy operations (ELF loading, disk I/O) run on worker threads;
   the loop stays responsive.
8. **Crate profile: `no_std + alloc`** (ADR-020). There is no `std` port yet, so
   server crates avoid `std::` (collections/strings come from `alloc`); the server
   binary supplies a global allocator over carved frames, and each blocking WAIT
   parks only its own connection thread (v0, §2.6).

## 2. Process server (`servers/process`)

### 2.1 Responsibilities

- **spawn**: ELF load, address space construction, thread creation, capability minting
- **fork/exec**: process duplication (policy) and image replacement
- **exit/wait**: lifecycle, zombie status, death notification routing (§1.5)
- **pager**: default resolver for file-backed demand faults and pool-exhausted faults
  of its children (ADR-007)
- **thread management**: create/join, priority hints, fault-endpoint assignment
- **Not responsible for**: POSIX signals/groups/sessions (personality layer), scheduling
  policy (hints only), memory policy beyond the spawn pool.

### 2.2 Capabilities the process server holds

| capability | source | use |
|---|---|---|
| service endpoint | init (boot contract) | clients reach it |
| Factory | init | mints endpoints, notifications, ASes, threads for children and itself; system servers PS spawns receive their own Factory caps, regular processes never do |
| Region (large) | init | carves frames: ELF images, stacks, heap pools, fault pools |
| VFS service endpoint + root handle | init | ELF loading, path resolution at spawn |
| per-child: AS cap, thread caps, `N_dead` | created at spawn | fault-pool setup, kill, reaping |

### 2.3 Spawn-time capability package (child's initial caps)

No ambient authority; this table is the child's entire world. Mirrors syscall-abi §6,
concretized:

| capability | rights | purpose |
|---|---|---|
| self AddressSpace | `MAP|GRANT` | mmap/brk via personality; grant to pager for MAP_FILE (Phase 2) |
| self main Thread | `CONTROL` | TLS, priority, exit |
| heap Region | — (CARVE only) | frames for heap/stack growth |
| stdio endpoints x3 | in: `RECV`; out: `SEND` | console or pipes (caller-supplied) |
| VFS service endpoint | `SEND|GRANT` | filesystem access |
| session notifications (4) | `SIGNAL|RECV|GRANT` | grant one per server connection (§1.5) |
| PS service endpoint | `SEND|GRANT` | its own `CONNECT` for thread/IPC services (windows are granted then, not at spawn) |
| fault endpoint (held by PS) | — | demand paging, COW fallback |

The `SPAWN` call's capability descriptors install caller-supplied stdio and VFS caps;
slots the caller omits are filled by PS defaults (`/dev/null` endpoints, PS's own VFS
endpoint minted with `SEND|GRANT` downgrade). The child's AS **fault pool** is set from
a PS region at spawn (`AddressSpace::SET_FAULT_POOL`) so COW/anon faults never cross
IPC (ADR-007).

### 2.4 Spawn sequence

```
caller                PS                      VFS                 kernel
  | call SPAWN ------> |                       |                    |
  |                    | WALK/OPEN (window) -> |                    |
  |                    | <- file handle        |                    |
  |                    | READ_BULK (frames) -> |                    |
  |                    | <- ELF bytes          |                    |
  |                    | NEW AS + map segments (invokes) ----------> |
  |                    | SET_FAULT_POOL (region) -----------------> |
  |                    | build stack + argv/env from windows        |
  |                    | NEW THREAD (entry, fault_ep) ------------->|
  |                    | mint child caps (mint/message) ----------> |
  |                    | bind N_dead to child threads ------------->|
  | <- SPAWN reply ---- |                       |                    |
```

1. Caller (shell/personality) sends `SPAWN` with argv/env in the arg window, cwd path,
   up to 4 cap descriptors (vfs_ep, stdin, stdout, stderr).
2. PS resolves the program through its VFS connection; reads it into frames it maps
   into the new AS. (v0: eager load; Phase 2+: lazy segments via the pager protocol.)
3. PS creates AS, maps segments, sets fault pool, builds stack/auxv from windows.
4. PS creates main thread with `fault_ep` + a bootstrap endpoint set; binds `N_dead`;
   then sends the §2.3 package over the bootstrap endpoint (ADR-009): first a header
   (label 0x0102, `w0` = number of caps that follow), then messages of ≤ 4 cap
   descriptors each. The child's crt drains until the header count is satisfied, so the
   full package is installed before it proceeds. PS's sends block on the one-message
   mailbox while the child drains — expect the child to be scheduled during spawn.
5. Reply: `w0 = status`, `w1 = pid`; out-caps: `thread_control` (parent may kill),
   `exit_notif` (signalled by PS's reaper when the child dies).
6. PS registers the process in its table (pid → AS/threads/N_dead/session notifs).

### 2.5 Pager role (details in ADR-007)

- File-backed faults: FAULT_PAGE arrives on PS's pager thread (one per child, also the
  reaper for that child); PS reads the file range into a frame via its VFS handles and
  replies FAULT_RESOLVE with the frame. Kernel installs the mapping; the resolver does
  not need an AS cap for this (kernel applies the reply mapping). Frame stays cached by
  PS per mapping (v0: one frame per 4 KiB fault, no readahead).
- COW/anon: kernel resolves from the fault pool; PS only sees `POOL_EMPTY` and responds
  by attaching a fresh region (or killing the child on ENOMEM).
- A POSIX personality may later set itself as the fault endpoint of app threads
  (`Thread::SET_FAULT_EP`) to synthesize SIGSEGV/SIGBUS before PS's fallback.

### 2.6 Process protocol (labels `0x01xx`)

| label | name | words (w0..w3) | caps in | reply |
|---|---|---|---|---|
| 0x0101 | CONNECT | w0 = version, w1 = arg window size, w2 = result window size, w3 = flags | session notification, arg frame (`READ`), result frame (`WRITE|MAP`) | w0 = status, w1 = connection id; out: connection endpoint |
| 0x0102 | PACKAGE | w0 = number of caps that follow, w1 = flags (PS → child at bootstrap only; ADR-009) | package caps over following messages | none |
| 0x0110 | SPAWN | w0 = flags, w1 = `(program off,len)`, w2 = `(argv off,len)`, w3 = `(env off,len)` | up to 4: vfs_ep, stdin, stdout, stderr (order fixed, nulls allowed) | w0 = status, w1 = pid; out: thread_control, exit_notif |
| 0x0111 | WAIT | w0 = pid, w1 = flags (NONBLOCK) | — | w0 = status (of the wait), w1 = child's exit status; pending-call semantics: blocks until death unless NONBLOCK |
| 0x0112 | KILL | w0 = pid, w1 = raw status | — | w0 = status |
| 0x0113 | EXEC | w0 = `(argv off,len)`, w1 = `(env off,len)`, w2 = `(program off,len)`, w3 = flags | — | (on success: never returns — image replaced; on failure: w0 = status) |
| 0x0114 | FORK | w0 = flags | self AS (`MAP|GRANT` from caller) | w0 = status, w1 = pid; out: thread_control, exit_notif |
| 0x0115 | THREAD_CREATE | w0 = stack top, w1 = entry PC, w2 = priority | — | w0 = status, w1 = tid; out: thread_control |
| 0x0116 | THREAD_EXIT | w0 = status | — | (worker threads; process exit uses syscall `exit`) |
| 0x0117 | GETPID | — | — | w0 = status, w1 = pid |

Notes:
- **Blocking `WAIT` parks the connection** in v0: the reply capability for a deferred
  reply cannot be saved across requests (no SaveCaller-style op in the ABI), so the
  serving context stays parked until the reaper answers. A client that wants to wait
  and keep working concurrently uses a second connection; the SDK does this
  transparently. A reply-cap-save op is a candidate for a future ABI ADR (§6).
- `EXEC` and `FORK` apply to the **calling process** (POSIX semantics): PS holds or is
  granted the caller's AS/thread caps; EXEC builds a new AS and swaps the caller's
  threads onto it, then destroys the old one. v0 simplification: EXEC kills all
  non-calling threads (POSIX-conformant enough for single-threaded programs).
- `FORK` uses the kernel `AddressSpace::FORK` COW clone; PS re-binds `N_dead` for the
  child's threads and re-registers everything else from its own bookkeeping.
- Zombies: exit status is retained until `WAIT` or until the reaper decides the parent
  died (PS tracks parent links; reassignment semantics belong to the personality).

## 3. VFS server (`servers/vfs`)

### 3.1 Namespace model

- Tree of nodes: directories, files (v0: symlinks are personality-level). VFS owns a
  **mount table**: mount-point handle → root node of a mounted filesystem service.
  v0: one in-process ramfs mounted at `/`. Later: external FS servers (ext2 over
  virtio-blk) mount by capability.
- **Capability-rooted access**: a client can only name nodes reachable from handles it
  was granted. There is no global path lookup. The POSIX personality holds the user's
  root handle and resolves `/etc/passwd` against it; escaping the root is impossible
  without a handle above it.
- v0 posture: single-user development image; VFS does not enforce uid/gid — isolation
  comes from which roots are granted (auth server leases per-user roots in Phase 3).
  Multi-user enforcement is a Phase 3 task with its own ADR.
- `..` walks upward in the VFS tree; v0 note: a connection's *effective root* is
  recorded at CONNECT and `..` clamps at it (creds story in §6).

### 3.2 Handles and connections

- `CONNECT` as in §1.2. Session notifications per §1.5; on death the client record,
  its handles, and its pending-delete files are released.
- Handle kinds: `DIR` (walk/list), `FILE` (read/write). Open flags: `READ`, `WRITE`,
  `APPEND`, `TRUNC`, `CREATE` (v0 set; POSIX translation in the personality).

### 3.3 Operations (labels `0x02xx`)

All name arguments are `(offset, len)` pairs into the argument window; results mostly
land in the result window. `STAT` returns a packed stat: `w1 = kind(8)|mode(24)|pad`,
`w2 = size`, `w3 = mtime_ns`.

| label | name | words (w0..w3) | reply |
|---|---|---|---|
| 0x0201 | CONNECT | w0 = version(16)\|flags(16) — same generic handshake as PS | session notification, arg frame (`READ`), result frame (`WRITE\|MAP`) | w0 = status, w1 = connection id, **w2 = root directory handle** (VFS extension: the connection's whole visible tree); out: connection endpoint |
| 0x0210 | WALK | w0 = dir handle, w1 = `(name off,len)`, w2 = flags | w0 = status, w1 = new handle, w2..w3 = stat |
| 0x0211 | OPEN | w0 = dir handle, w1 = `(name off,len)`, w2 = flags | w0 = status, w1 = file handle, w2..w3 = stat |
| 0x0212 | READ | w0 = file handle, w1 = offset, w2 = len, w3 = result-window off | w0 = status, w1 = bytes read |
| 0x0213 | READ_BULK | w0 = file handle, w1 = offset, w2 = len | caps[0] = destination frame (`WRITE|MAP`); w1 = bytes read |
| 0x0214 | WRITE | w0 = file handle, w1 = offset, w2 = `(arg window off,len)` | w0 = status, w1 = bytes written |
| 0x0215 | CLOSE | w0 = handle | w0 = status |
| 0x0216 | FSYNC | w0 = handle | w0 = status |
| 0x0217 | STAT | w0 = handle (or dir handle with w1 = name), w2 = 0 by handle / 1 by dir+name | w0 = status, w1 = packed kind(8)\|mode(24), w2 = size, w3 = mtime_ns |
| 0x0218 | READDIR | w0 = dir handle, w1 = cookie | w0 = status, w1 = next cookie (0 = end), w2 = `(name off,len)`, w3 = kind |
| 0x0219 | CREATE | w0 = dir handle, w1 = `(name off,len)`, w2 = mode | w0 = status, w1 = file handle |
| 0x021A | MKDIR | w0 = dir handle, w1 = `(name off,len)`, w2 = mode | w0 = status, w1 = dir handle |
| 0x021B | UNLINK | w0 = dir handle, w1 = `(name off,len)` | w0 = status (open files: pending-delete, data freed on last CLOSE) |
| 0x021C | RENAME | w0 = src dir, w1 = `(src name)`, w2 = dst dir, w3 = `(dst name)` | w0 = status |
| 0x021D | TRUNCATE | w0 = file handle, w1 = new size | w0 = status |
| 0x021E | DUP | w0 = file handle | w0 = status, w1 = new handle (server-side refcount) |

`READ_BULK` exists because the 64 KiB window is the wrong shape for ELF loading and
future mmap population (sdk schema §8.2 shows the wire example). Smaller reads use the
window to avoid a frame transfer per call. **v0 status:** `READ_BULK` returns `ENOSYS`
in `servers/vfs` slice 1 — the server must first be able to map the transferred frame
into its own address space (runtime `map_into_self`); PS ELF loading uses chunked
window reads until that lands.

**Stat words:** WALK/OPEN/CREATE/MKDIR replies carry `w2 = kind(8)|mode(24)`,
`w3 = size`; only STAT carries the full triple including mtime. Status codes come from
the shared table (`sdk/docs/ipc-schema.md` §7): the VFS set ENOENT/EEXIST/ENOTEMPTY/
ENOTDIR/EISDIR/EINVAL/EACCES (-15..-21) was appended there while building
`servers/vfs`; `ipc::status` mirrors it (requested from GLM).

### 3.4 Page cache and pager role (Phase 2 interface, sketched)

- v0: ramfs is the cache; reads are served from memory.
- File-backed `mmap`: the client (personality) grants the AS cap and VFS becomes the
  pager for the region (it owns the cache frames). Fault → VFS reads the cache/disk →
  `FAULT_RESOLVE` with a cached frame mapped `READ` (COW for writable maps: kernel
  handles the write-COW via the AS fault pool). Frame reuse across mappings is the
  actual page-cache point; the exact eviction/writeback protocol needs its own ADR
  when mmap lands (Phase 2/3).
- Block backend: external FS servers implement the node protocol of §3.3 behind a
  mount; the block driver interface (`BLOCK_READ/WRITE(frame, lba, count)`) is NV's
  virtio-blk surface and will be specified when that driver lands.

## 4. Bootstrap sequence (who starts whom)

1. Kernel starts `init` with BootInfo (syscall-abi §8): debug endpoint, Factory,
   memory Regions.
2. `init` carves a large Region and spawns the **process server** with Factory + a
   large Region. PS is the sole object manufacturer for regular processes; the
   system servers it spawns receive their own Factory caps for connection endpoints.
3. PS spawns, in order: **device manager** (holds IRQ provisioning authority and
   driver regions), **VFS** (region for ramfs), **auth** (later: credentials + per-user
   capability leasing), **net** (later).
4. PS provisions VFS with a root directory authority at boot (v0: VFS starts with the
   full ramfs tree; root handles are minted to init/PS which pass user roots along).
5. Login (Phase 3): auth verifies the user, then asks PS for a shell spawn with the
   user's root handle; from then on every capability the session has was explicitly
   granted. User switching = re-minting session caps, no kernel state.

## 5. Non-goals (v0)

- Multi-user enforcement inside VFS (Phase 3 ADR; VFS gains per-connection creds).
- POSIX information leaks like `/proc` (personality synthesizes).
- Network/device handles for regular processes (separate server docs).
- Cross-connection handle transfer / `SCM_RIGHTS` (see §6).
- mmap and page-cache eviction detail (Phase 2/3 ADR).

## 6. Open questions (need ADRs before the phases that use them)

1. **Namespace credentials at CONNECT** (§3.1): recommended v0 rule is
   "the connection's effective root is recorded from the granting authority" — i.e.
   VFS mints per-connection roots only to holders of root tokens that PS/auth created
   from dir handles. Precise token mechanism lands with the multi-user ADR (Phase 3);
   dev image stays permissive.
2. **Handle transfer across connections** (`SCM_RIGHTS`, fd inheritance): v0 avoids it
   (POSIX personality keeps fds in its own process). If personality servers go
   out-of-process, this needs a VFS gift protocol + ADR.
3. **Session notification pool size** (currently 4): if clients legitimately exceed it,
   either grow the pool or add `Factory::NEW_NOTIFICATION` rights for regular
   processes. Decide with Phase 2 measurements.
4. **PS reaper thread-per-process** cost: fine for Phase 1/2; revisit with ADR if
   process counts grow (a wait-any primitive would collapse it).
5. **`STAT` reply packing** (wire words left after status): acceptable because STAT
   reply has no other payload; if the stat struct grows, move it to the result window.
6. **Connection identity: endpoint-per-connection (v0) vs sender badges** (seL4-style:
   one thread serves many connections; requires an ADR-005 amendment to carry the
   sender capability along with a message). Decide with Phase 2 measurements; the
   protocol above is badge-compatible (same ops, shared endpoint).
7. **Deferred replies / SaveCaller**: a reply capability cannot currently be saved
   into an explicit slot, so a deferred reply (blocking WAIT, async I/O completion)
   parks its whole connection thread. A `recv` option or Thread op to *save* the
   implicit reply cap into a slot (seL4 `CNode_SaveCaller`-style) would let one
   connection thread juggle many outstanding requests. Needs an ADR with GLM when
   VFS async I/O lands (Phase 2).
