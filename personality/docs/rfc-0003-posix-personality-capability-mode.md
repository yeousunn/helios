## RFC-0003: POSIX personality in capability mode

- Proposed: PSX 2026-11-14
- Status: PROPOSED (NV accepts; no syscall, IPC wire-format or HAL-trait change)
- Links: PLAN.md 4.7 (multi-user: POSIX programs in capability mode), PLAN.md
  section 2 principles 2, 7, 8; bet B10 (isolation proof); cites
  [R-CAPSICUM], [R-SEL4], [R-SEL4-IF], [R-HUBRIS], [R-HYPERKERNEL],
  [R-EROS-CONF]; builds on `servers/docs/process-and-vfs-design.md` §3.1
  (capability-rooted VFS access: a client can only name nodes reachable from
  granted handles; the connection's effective root clamps `..`).

### Problem

Today `personality/` is a set of binaries (`linrun` plus the native POSIX-ish
`sh`/`cat`/`ls`/`echo`/`wc`/`login`/`posix`) that hold their VFS, process-server
and console endpoint capabilities for the whole process lifetime, and `linrun`
hands every Linux binary it emulates the same ambient authority: one VFS
connection with one effective root, no rights on file descriptors, and
`openat(AT_FDCWD, "/anything")` reaching anything the root can name. There is
no per-session instance: the personality is spawned per program, not per login
session, so "the user's root" is whatever the launcher passed and nothing ties
a personality to a session CNode subtree (PLAN.md 4.7: a login mints a session
subtree and logout revokes it). An emulated or native program therefore
operates with ambient authority over everything its launcher could reach,
which breaks principles 2 (everything is a capability, no ambient authority)
and 8 (servers hold no state on behalf of clients) and leaves B10 without a
capability set to reason about. The VFS's spatial root (§3.1) is the right
seed, but it is a connection property, not a per-fd rights discipline, and it
is not yet leased per session by the auth server.

### Research basis

- [R-CAPSICUM]: Capsicum's capability mode — a one-way entry after which only
  delegated, rights-bearing file descriptors are usable and the global
  namespaces (absolute paths, `..`, process IDs) become inaccessible. This is
  the exact model for confining an unmodified Linux binary: the binary keeps
  working with its inherited fds while every global-name operation fails.
- [R-SEL4]: capabilities as the only authority, derived and revocable; PLAN
  4.7 maps a login session onto a CNode subtree whose revocation is logout.
- [R-SEL4-IF]: integrity and authority-confinement proofs. Bet B10's success
  metric is a proof sketch linking the personality's capability set to the
  kernel's confinement theorem; this RFC defines the capability set that
  sketch needs.
- [R-HUBRIS]: badges carry (principal, session, generation), so a restarted
  personality is visible to its clients. One personality instance per session
  follows the same "server identity is per session" shape.
- [R-HYPERKERNEL]: a finite, checked ABI. The personality's native syscall
  surface (FOREIGN_SYSCALL dispatch + VFS/PS/console invokes) stays the only
  boundary and every argument is range-checked before use.
- [R-EROS-CONF]: the constructor checks that a newly launched process holds no
  capability that leaks outward. The fallback design (below) is a constructor
  check rather than an in-process mode.

### Design

One personality instance per login session, in capability mode for emulated
binaries, over the existing VFS spatial-root model. Userspace-only; no kernel
object, syscall or HAL trait changes.

1. **Session instance.** The auth/login flow (M5) spawns one personality per
   session in the session's CNode subtree. The personality holds exactly: the
   session's VFS root handle (a `DIR` handle leased per user, design §3.1),
   the console/stdin/stdout handles, and the process-server endpoint for its
   own children. Logout revokes the subtree; the personality holds nothing
   outside it. Badges carry (uid, session, generation): a re-incarnated
   personality after a crash gets a new generation and its clients see it.
2. **One-way capability mode.** Before the personality starts emulating a
   Linux binary (or runs a native POSIX bin), it calls
   `enter_capability_mode()`, which seals the process's authority set: the
   session root `DIR` fd and fds 0/1/2 survive; every other handle is dropped
   from the emulator's reachable set. The mode is one-way (a bit in the
   personality process, flipped once; no exit path), exactly as in
   [R-CAPSICUM]. A second call returns `EALREADY`-class status; there is no
   way back.
3. **Rights-masked fd table.** Each emulated Linux fd maps to
   `{ vfs_slot, rights: {READ, WRITE, SEEK, LIST}, confined_dir: slot }`.
   `openat` under a confined dirfd produces an fd whose rights are the
   intersection of the dirfd's rights and the open flags; `dup`-class
   operations can only drop rights (PLAN.md 4.2: transfer drops rights only).
   Reads/writes/getsets on an fd without the matching right fail with `EBADF`
   at the personality boundary, before any VFS invoke.
4. **Confined walks.** In capability mode, path arguments are only accepted
   with a dirfd (never `AT_FDCWD`) and the personality's walk refuses to
   ascend above the dirfd's node: a `..` component that would cross the
   confined directory root fails with `ENOENT`-class status (never a silent
   clamp, so a confused binary cannot read a neighbor). Absolute paths fail
   with `ENCAPMODE`-class status (mapped to Linux `EPERM` at the boundary).
   Namespace mutation (`mkdir`, `unlink`, `rename`) is refused in capability
   mode: a confined program may consume its tree, not reshape it.
5. **Failure modes.** (a) A compromised emulated binary cannot name any node
   outside its confined tree: every name goes through the rights check first.
   (b) A compromised binary cannot regain a dropped handle: handles live in
   the personality's own table, not the guest's memory. (c) The personality
   process itself stays trusted for its own confinement (it is the
   confinement mechanism for its guests); its capability set is what B10's
   proof bounds. (d) A native POSIX bin (`sh`, `cat`, ...) runs in the same
   capability mode with the session root as its confined dir.

### ABI

No kernel syscall, invoke method, IPC wire-format or HAL-trait change. The
changed surface is personality-internal (userspace), plus the Linux ABI the
emulator already presents:

- `enter_capability_mode() -> Status`: one-way personality-internal call;
  second call returns `EBADSTATE`-class status; no argument.
- Emulated-Linux boundary answers under capability mode: `openat` with
  `AT_FDCWD` or an absolute path → Linux `EPERM`; `..` escaping the confined
  dir → Linux `ENOENT`; fd right missing → Linux `EBADF`; `mkdir`/`unlink`/
  `rename` → Linux `EPERM`. Success paths and fd numbering are unchanged
  (Linux `>= 0` results, `-errno` failures), so unmodified binaries keep
  running.
- VFS-side: unchanged. The confined walk is enforced client-side before the
  `WALK` invoke; the VFS's existing effective-root clamp (design §3.1) is
  defense in depth, not the mechanism.
- Commutativity: personality-internal state (the fd table) is per process;
  VFS invokes on disjoint fds commute as they do today. No new shared state.
- `spec/abi` (A1) needs no entry for this RFC; the Linux errno mapping table
  it introduces (Helios status → Linux errno) is recorded in
  `personality/src/posix.rs` next to the existing flag/errno aliases.

### Verification plan

- Host unit tests (the existing `foreign::tests` mock-`Host` pattern): every
  confinement rule above gets a case that must return the stated error, and
  every success path keeps its result; a test pins that `enter_capability_mode`
  is one-way and that `dup` cannot add rights.
- Attack-suite cases (S-task rule: host test fails before, passes after):
  emulated `openat(AT_FDCWD, "/etc/passwd")`, `openat(dirfd, "../../..")`,
  `read` on a write-only fd, `unlink` in capability mode.
- B10 proof sketch (M5/M7): state that the personality's reachable capability
  set after `enter_capability_mode` is a subset of `{session root DIR, fds
  0/1/2, PS endpoint}` and that every VFS invoke it issues names a node
  derived from that set; link that subset relation to the kernel's
  authority-confinement theorem from [R-SEL4-IF]. The VFS effective-root
  clamp is the server-side witness.
- Differential tests (PLAN 7.2 tier 5): the same Linux binary (busybox
  `cat`/`ls` under `linrun`) gets identical results inside and outside
  capability mode on paths inside its tree, and Linux-conformant errors
  outside it.

### Benchmark and success metric

- `bench/boot` (G3): the full boot with the personality steps (the existing
  init step markers) stays within the current time budget — capability mode
  adds no IPC round trips, only table lookups.
- Success: the attack cases above pass in QEMU (`tools/qemu-test.sh` reaches
  DONE + clean halt with the cases in the suite), and the B10 proof sketch is
  written and reviewed. No new benchmark number is claimed: this RFC adds
  confinement, not speed.

### Kill criterion

If per-fd rights cannot be enforced without a kernel-side rights check on
every VFS invoke (i.e., the client-side mask is shown bypassable by a
compromised personality process itself, not just by its guests), drop the
in-process mode and ship the constructor fallback: the constructor
([R-EROS-CONF]) launches one personality per (session, confined directory)
holding only that directory's root cap, so confinement is spatial by
construction. The session-per-instance and badge-generation parts of this RFC
survive either way.

### Alternatives considered

- **Linux-namespace emulation in the personality** (mount namespace, chroot
  semantics): rejected — it reimplements a large, subtle surface and one bug
  in it re-opens the global namespace; capability mode confines with a rights
  table that is small enough to test exhaustively.
- **Kernel/VFS per-fd capability rights now**: rejected for this slice — the
  VFS gains cap-granted fds in its own milestone work; this RFC keeps the
  rights mask in the personality so M5 can ship confinement without waiting
  for it, and the server-side clamp is the witness until then.
- **Status quo (no confinement)**: rejected — ambient authority for every
  emulated binary, against PLAN 4.7 and principles 2 and 8.