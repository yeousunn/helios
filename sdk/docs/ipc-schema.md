# IPC Message Wire Format v1 — Proposal

- Status: RATIFIED as ADR-005 by GLM (2026-10-30); implemented in `ipc/`. Authored by
  DeepSeek (DS), 2026-10-30.
- Target: `ipc/` crate (owned by GLM). DS cannot write there; this document is the
  handoff. GLM ratifies, adapts, or rejects via ADR-001.
- Stability: "v1" freezes once ADR-001 is ACCEPTED. Any change to the layouts below
  requires an ADR and a version bump.

## 1. Scope

Defines the fixed-size control message carried by `send` / `call` / `recv` /
`reply_recv` / `invoke` (see `sdk/docs/syscall-abi.md`). Bulk data (file contents,
network payloads, ELF segments) is explicitly out of scope for v1: it travels through
shared memory or frame transfers, never through these words.

## 2. Design rules

1. Zero allocation on the hot path; the message fits in registers.
2. Capability transfer is atomic with send (no TOCTOU between grant and delivery).
3. No raw pointers inside messages — words, handles, and rights only.
4. The kernel treats `words` as opaque, except the descriptor-result rule (§3.1).
5. Unknown labels and versions are rejected by the *receiver*, never by the kernel.

## 3. Message layout

```
word 0   tag   u64  — see §4
word 1   w0    u64
word 2   w1    u64
word 3   w2    u64
word 4   w3    u64
```

40 bytes, 8-byte aligned. `MAX_WORDS = 4`.

### 3.1 Capability descriptor overlay

If `tag.cap_count = n` (0..=4), the **last n** words of `w0..w3` are capability
descriptors instead of payload:

```
[31:0]  handle   index in the sender's capability space (0 = null, rejected)
[63:32] rights   rights mask requested for the receiver's installed cap
```

The kernel installs the caps into the receiver's capability space atomically with
message delivery, granting `min(sender_rights, requested_rights)`.

On receive, descriptor words are replaced by the receiver-side result:

```
[31:0]  handle   newly installed handle in the receiver's space
[63:32] rights   rights actually granted
```

If a descriptor fails (dead cap, insufficient rights, capability space full), that
word becomes 0 (null) and the kernel sets `FLAG_CAP_PARTIAL` in the delivered tag.
The message is still delivered; receivers must check.

Free payload words = `4 - n`.

## 4. Tag

```
63..48  version    u16  0x0001 for this document; 0 reserved
47..32  reserved   u16  must be 0; receivers must reject nonzero reserved bits
31..24  flags      u8   see table
23..16  cap_count  u8   0..=4
15..0   label      u16  protocol opcode (registry in §6)
```

| bit | name | meaning |
|---|---|---|
| 0 | FLAG_NONBLOCK | send/call: return `EWOULDBLOCK` instead of blocking |
| 1 | FLAG_CAP_PARTIAL | set by the kernel on delivery if any descriptor failed (never set by senders) |
| 2 | FLAG_NOTIFIED | set on recv return when a bound notification (not a message) woke the thread; `label = 0`, `w0` = pending notification mask |
| 3..7 | reserved | must be 0 |

Label 0 is reserved: "no protocol message" (notification wake; see syscall ABI §3).

## 5. Rust definitions (proposal for `ipc/`)

```rust
#![no_std]
#![forbid(unsafe_code)]

pub const VERSION: u16 = 0x0001;
pub const MAX_WORDS: usize = 4;
pub const NULL_HANDLE: u32 = 0;

pub mod flags {
    pub const NONBLOCK: u8 = 1 << 0;
    pub const CAP_PARTIAL: u8 = 1 << 1;
    pub const NOTIFIED: u8 = 1 << 2;
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rights(pub u32);

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CapSlot(pub u64);

impl CapSlot {
    pub const fn handle(self) -> u32 {
        self.0 as u32
    }
    pub const fn rights(self) -> Rights {
        Rights((self.0 >> 32) as u32)
    }
    pub const fn pack(handle: u32, rights: Rights) -> Self {
        Self(handle as u64 | ((rights.0 as u64) << 32))
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tag(pub u64);

impl Tag {
    pub const fn new(label: u16) -> Self {
        Self(((VERSION as u64) << 48) | label as u64)
    }
    pub const fn version(self) -> u16 {
        (self.0 >> 48) as u16
    }
    pub const fn label(self) -> u16 {
        self.0 as u16
    }
    pub const fn cap_count(self) -> u8 {
        (self.0 >> 16) as u8
    }
    pub const fn flags(self) -> u8 {
        (self.0 >> 24) as u8
    }
    pub const fn is_valid(self) -> bool {
        self.version() == VERSION && (self.0 >> 32) & 0xFFFF == 0
    }
    pub const fn with_flags(self, f: u8) -> Self {
        Self((self.0 & !(0xFFu64 << 24)) | ((f as u64) << 24))
    }
    pub const fn with_caps(self, n: u8) -> Self {
        Self((self.0 & !(0xFFu64 << 16)) | ((n as u64) << 16))
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub tag: Tag,
    pub words: [u64; MAX_WORDS],
}

const _: () = assert!(core::mem::size_of::<Message>() == 40);
const _: () = assert!(core::mem::align_of::<Message>() == 8);
const _: () = assert!(core::mem::size_of::<Tag>() == 8);
const _: () = assert!(core::mem::size_of::<CapSlot>() == 8);
```

Conventions:

- `words[0]` is the first payload word. When `n` caps are transferred, they live in
  `words[MAX_WORDS - n ..]`; helpers in the crate (not part of the wire) enforce this.
- Byte order: native little-endian on all current targets. The layout is
  register-passed, so endianness is a non-issue until an arch port needs it.
- Status codes shared with the syscall ABI live here (§7) as the single source.

## 6. Label registry

Allocation is central; GLM maintains the authoritative table in `ipc/`.

| range | owner |
|---|---|
| 0x0000 | reserved: no-message wake (FLAG_NOTIFIED) |
| 0x0001–0x00FF | kernel core: 0x0001 FAULT_PAGE, 0x0002 FAULT_RESOLVE, 0x0003 NOTIFY (recv result on a Notification cap), 0x0004 IRQ (recv result on an IRQ cap) |
| 0x0100–0x01FF | process server (delegated: see `servers/docs/process-and-vfs-design.md`) |
| 0x0200–0x02FF | VFS |
| 0x0300–0x03FF | auth |
| 0x0400–0x04FF | net |
| 0x0500–0x05FF | device manager / driver common framing |
| 0x0600–0x06FF | graphics / compositor |
| 0x8000–0x8FFF | experimental |
| 0x9000–0xFFFF | out-of-tree / vendor |

Receivers dispatch on `(version, label)`. Replies default to the label of the
originating request unless the protocol defines otherwise.

Note: server protocol label tables currently live in `servers/docs/` (DS area) and
migrate into `ipc/` (or per-server `protocol` modules) when code lands.

## 7. Status / error space

`i32`, shared by syscall returns (rax) and server reply `w0`.

| value | name | meaning |
|---|---|---|
| 0 | OK | success |
| -1 | EBADCAP | handle invalid or revoked |
| -2 | ERIGHTS | capability lacks a required right |
| -3 | EBADARG | malformed argument |
| -4 | EWOULDBLOCK | non-blocking operation would block |
| -5 | ECANCELED | operation canceled (e.g. faulting thread killed) |
| -6 | EREVOKED | capability revoked under us |
| -7 | EFAULT | memory fault escaped resolution |
| -8 | ENOMEM | out of memory / capability slots |
| -9 | ETIMEDOUT | deadline expired |
| -10 | EBUSY | transient conflict; retry |
| -11 | EDEAD | peer died / endpoint closed |
| -12 | EBADSTATE | object in the wrong state for this operation |
| -13 | ETOOBIG | message or transfer exceeds limits |
| -14 | ENOSYS | label or version not implemented |
| -15 | ENOENT | no such node/name (VFS) |
| -16 | EEXIST | name already exists (VFS) |
| -17 | EISDIR | directory used as a file (VFS) |
| -18 | ENOTDIR | path component is not a directory (VFS) |
| -19 | ENOTEMPTY | directory not empty (VFS unlink) |
| -20 | EMFILE | too many open handles (VFS) |
| -21 | EACCES | operation refused by pseudo-mode checks or rights |

New codes are appended here first; `ipc/` mirrors the table exactly (`ipc/status.rs`
is canonical), and `servers/` must not invent codes outside it (VFS may *translate*
to POSIX errno in the personality layer, not on the wire). These remain a shared,
server-agnostic vocabulary: ENOENT is as meaningful to a device or net server as to
VFS. Malformed values/arguments use `EBADARG` — there is no EINVAL.

## 8. Examples

### 8.1 Simple call, no caps

A `READ` request (VFS label 0x0212) sending a file handle, offset, length, and a
result-window offset: four payload words, zero caps.

```
tag = 0x0001_0000_0000_0000 | 0x0000_0000_0000_0212
w0  = file handle (u64)
w1  = offset
w2  = length
w3  = result-window offset
```

### 8.2 Call transferring one cap

`READ_BULK` (label 0x0213) needs only three payload words and transfers a frame for
the destination buffer:

```
tag = version | cap_count = 1 | label = 0x0213
w0  = file handle (u64)
w1  = offset
w2  = length
w3  = CapSlot { handle = destination frame, rights = WRITE | MAP }
```

### 8.3 Fault reply from a pager

A pager resolving a page fault replies `FAULT_RESOLVE` (0x0002) with a frame cap:

```
tag = version | cap_count = 1 | label = 0x0002
w0  = faulting vaddr, echoed
w1  = mapping flags (R/W/X)
w2  = 0
w3  = CapSlot { handle = frame to map, rights = READ | MAP }
```

## 9. Versioning

- `version` bumps on any breaking change to tag or descriptor layout.
- Additive, opt-in changes inside a label range do not bump the wire version;
  protocols carry their own version word where needed.
- The kernel never rewrites labels or payload words (descriptor results in §3.1 are
  the only exception). All translation is a userspace concern.

## 10. Open questions

- Bulk transport v2: shared ring + doorbell (PLAN §2.5) — needs a separate ADR once
  Phase 1 IPC has measurements.
- Is `FLAG_NOTIFIED` + `label 0` distinguishable enough from a protocol that
  legitimately wants label 0? (Currently label 0 is reserved, so yes.)
- Capability-space slot addressing: `cap_mint` with absolute destination slots vs
  allocation-only — resolve with GLM in ADR-004.
