//! Invoke method specifications per object type

use crate::capability::{ObjType, Rights};
use crate::commutativity::Commutativity;
use crate::error::ErrorCode;

/// Invoke method argument specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeArg {
    /// Argument name
    pub name: &'static str,
    /// Valid range: (min, max) inclusive
    pub range: (u64, u64),
    /// Error code when out of range
    pub range_error: ErrorCode,
    /// Description
    pub description: &'static str,
}

/// Complete invoke method specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvokeSpec {
    /// Object type this method belongs to
    pub obj_type: ObjType,
    /// Method label (tag.label())
    pub label: u16,
    /// Method name
    pub name: &'static str,
    /// Required rights on the capability
    pub required_rights: Rights,
    /// Arguments (w0..w3 + descriptors)
    pub args: &'static [InvokeArg],
    /// Descriptor requirements: (index, expected_obj_type, required_rights)
    pub descriptors: &'static [(&'static str, ObjType, Rights)],
    /// Possible error codes
    pub errors: &'static [ErrorCode],
    /// Commutativity
    pub commutativity: Commutativity,
    /// Description
    pub description: &'static str,
}

// ============================================================================
// Factory methods (ObjType::Factory)
// ============================================================================

/// FACTORY_NEW_ENDPOINT invoke specification
pub const FACTORY_NEW_ENDPOINT: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Factory,
    label: 1,
    name: "NEW_ENDPOINT",
    required_rights: Rights::GRANT,
    args: &[],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::ENOMEM, ErrorCode::ERIGHTS],
    commutativity: Commutativity::Commutes,
    description: "Create a new endpoint. Returns capability with SEND|RECV|GRANT rights.",
};

/// FACTORY_NEW_NOTIFICATION invoke specification
pub const FACTORY_NEW_NOTIFICATION: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Factory,
    label: 2,
    name: "NEW_NOTIFICATION",
    required_rights: Rights::GRANT,
    args: &[],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::ENOMEM, ErrorCode::ERIGHTS],
    commutativity: Commutativity::Commutes,
    description: "Create a new notification. Returns capability with SIGNAL|RECV|GRANT rights.",
};

/// FACTORY_NEW_ADDRESS_SPACE invoke specification
pub const FACTORY_NEW_ADDRESS_SPACE: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Factory,
    label: 3,
    name: "NEW_ADDRESS_SPACE",
    required_rights: Rights::GRANT,
    args: &[],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::ENOMEM, ErrorCode::ERIGHTS],
    commutativity: Commutativity::Commutes,
    description: "Create a new address space. Returns capability with MAP|GRANT rights.",
};

/// FACTORY_NEW_THREAD invoke specification
///
/// ADR-088 (RFC-0005): the packing is discriminated by cap_count, so the
/// (label, cap_count) dispatch stays total. cap_count 2 = uniform layout
/// (w1 = initial user stack top, caps[1] = bootstrap EP, no fault EP);
/// cap_count 3 = legacy ADR-017 (w1..w3 are descriptor bytes, never
/// stack-validated). Any other cap_count → EBADARG.
pub const FACTORY_NEW_THREAD: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Factory,
    label: 4,
    name: "NEW_THREAD",
    required_rights: Rights::GRANT,
    args: &[
        InvokeArg {
            name: "entry_pc",
            range: (1, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Entry point PC (must be canonical user address, validated by is_user_addr)",
        },
        InvokeArg {
            name: "stack_top",
            range: (0, 0x0000_8000_0000_0000 - 1),
            range_error: ErrorCode::EBADARG,
            description: "Initial user stack top at cap_count 2 (ADR-088 uniform packing). 0 = arch default USER_STACK_TOP (0x0000_7FFF_FFFF_F000). Nonzero: canonical user address (nonzero, < 0x8000_0000_0000_0000) AND 16-byte aligned — the same rule THREAD_CREATE w1 runs, so the two cannot drift. Validated before any child state exists.",
        },
        InvokeArg {
            name: "w1_reserved",
            range: (0, u64::MAX),
            range_error: ErrorCode::OK,
            description: "RESERVED at cap_count 3 (legacy ADR-017 packing, kept until the M2 housekeeping ADR deletes it): trailing-descriptor overlay puts descriptor 0 (the AS cap) in words[1], so w1 carries descriptor bytes, not a stack value — the kernel ignores it there and must not stack-validate descriptor bytes (ADR-087 rule). Custom stacks for legacy senders go through THREAD_CREATE w1.",
        },
    ],
    descriptors: &[
        ("caps[0]", ObjType::AddressSpace, Rights::MAP), // required (both packings)
        ("caps[1]", ObjType::Endpoint, Rights::GRANT), // cap_count 2: bootstrap EP; cap_count 3: fault EP
        ("caps[2]", ObjType::Endpoint, Rights::GRANT), // cap_count 3 only: bootstrap endpoint
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
        ErrorCode::EREVOKED,
    ],
    commutativity: Commutativity::Commutes,
    description: "Create a new thread in a new process. w0 = entry PC (both packings). cap_count 2 (ADR-088 uniform): w1 = initial user stack top (0 = arch default, ADR-085 validation), caps[0] = AddressSpace, caps[1] = bootstrap endpoint (installed at child handle 1), no fault EP (bind one later with Thread::BIND_FAULT_EP before the first yield — the child cannot run before the parent yields). cap_count 3 (legacy ADR-017): w1..w3 are descriptor bytes (ignored, no validation), caps[0] = AddressSpace, caps[1] = fault endpoint (optional), caps[2] = bootstrap endpoint (optional, installed at child handle 1). Any other cap_count: EBADARG. caps transfer under S8 (rights ∩ requested). Returns thread cap with CONTROL|GRANT.",
};

/// FACTORY_RETYPE invoke specification
///
/// ADR-088 (RFC-0005 §3, correcting RFC-0001/ADR-064's table): retype
/// carves a new object out of a source Untyped. cap_count must be exactly
/// 1 — caps[0] is the source Untyped (MAP right required) and rides
/// words[3] under the trailing-descriptor overlay — with w0 = target
/// type, w1 = size, w2 = alignment order. RFC-0001's w3 = numa_node is
/// dropped (the carved object inherits the source's node/tier) and
/// destination placement goes through CAP_MOVE (first-free install here).
/// Kernel support lands with M1 (Untyped/Retype/Revoke); until then
/// INVOKE on a Factory cap with label 5 answers ENOSYS (the AS_FORK/
/// AS_DESTROY precedent). Factory label 6 stays unassigned — NEW_CNODE
/// is RETYPE with target type CNode, never a second name for it.
pub const FACTORY_RETYPE: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Factory,
    label: 5,
    name: "RETYPE",
    required_rights: Rights::GRANT,
    args: &[
        InvokeArg {
            name: "target_type",
            range: (1, 63),
            range_error: ErrorCode::EBADARG,
            description: "Target object type (ObjType discriminant). Must be in the M1 retype target set — Endpoint, Notification, AddressSpace, Thread, Frame, CNode, Region, SchedContext, Domain, IOSpace, CoreGrant, Port, Ring (RFC-0001 §4.1.2) — a set test, not a range check: 0 (None), 8 (Untyped — a source, never a target), 14 (Reply), 15 (Factory), 6 (Irq) and every other discriminant outside the set are EBADARG.",
        },
        InvokeArg {
            name: "size",
            range: (1, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Carve size in bytes. Fixed-size types must pass exactly their fixed size (no ignore-ambiguity — the kernel↔spec cross-check stays exact); variable-size types (Frame, CNode, Region) accept [type_min, source remaining] (Frame/Region ≥ 4 KiB; CNode capacity ≥ 1 KiB of slots). Type minimums are kernel constants (M1); size 0 is never valid.",
        },
        InvokeArg {
            name: "align_order",
            range: (0, 47),
            range_error: ErrorCode::EBADARG,
            description: "Alignment order (log2). 0 = the type's natural alignment; otherwise 12 ≤ order ≤ 47 (4 KiB .. 128 TiB) AND size % (1 << order) == 0. 1..=11 and > 47 are EBADARG (RFC-0005 §3).",
        },
    ],
    descriptors: &[("caps[0]", ObjType::Untyped, Rights::MAP)],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
        ErrorCode::ENOSYS,
    ],
    commutativity: Commutativity::CommutesDisjointRanges,
    description: "Retype: carve a new object from a source Untyped (caps[0], MAP required; cap_count exactly 1, else EBADARG — the THREAD_CREATE precedent, keeping the w-reads unambiguous). w0 = target type (M1 target set), w1 = size, w2 = alignment order (0 = natural, else 12..=47 dividing size). All-or-nothing: the source is reduced only after every validation passes (depleted source = EBADARG; dead/foreign source = EBADCAP). Reply w0 = new cap handle (first-free install; deterministic placement via CAP_MOVE), reply w1 = remaining source size. NUMA node/tier inherited from the source (RFC-0001's w3 dropped). Kernel support lands with M1 — until then ENOSYS (AS_FORK/AS_DESTROY precedent). Retypes on different Untypeds commute; on the same Untyped they conflict (carving is ordered).",
};

// ============================================================================
// Thread methods (ObjType::Thread)
// ============================================================================

/// THREAD_EXIT invoke specification
pub const THREAD_EXIT: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 1,
    name: "EXIT",
    required_rights: Rights::CONTROL,
    args: &[InvokeArg {
        name: "status",
        range: (0, u32::MAX as u64),
        range_error: ErrorCode::EBADARG,
        description: "Exit status (i32)",
    }],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Exit the target thread with the given status.",
};

/// THREAD_KILL invoke specification
pub const THREAD_KILL: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 2,
    name: "KILL",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Kill the target thread (exit status -1).",
};

/// THREAD_SUSPEND invoke specification
pub const THREAD_SUSPEND: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 3,
    name: "SUSPEND",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Suspend the target thread.",
};

/// THREAD_RESUME invoke specification
pub const THREAD_RESUME: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 4,
    name: "RESUME",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Resume a suspended thread.",
};

/// THREAD_SET_PRIORITY invoke specification
pub const THREAD_SET_PRIORITY: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 5,
    name: "SET_PRIORITY",
    required_rights: Rights::CONTROL,
    args: &[InvokeArg {
        name: "priority",
        range: (1, 255),
        range_error: ErrorCode::EBADARG,
        description: "New priority (1..=255, higher = more urgent)",
    }],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Set the target thread's scheduling priority.",
};

/// THREAD_SET_TLS invoke specification
pub const THREAD_SET_TLS: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 11,
    name: "SET_TLS",
    required_rights: Rights::CONTROL,
    args: &[InvokeArg {
        name: "fs_base",
        range: (0, u64::MAX),
        range_error: ErrorCode::EBADARG,
        description: "FS base address (must be canonical user address or 0 to clear)",
    }],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Set the target thread's TLS base (FS register on x86_64). 0 clears it.",
};

/// THREAD_BIND_DEATH_NOTIFICATION invoke specification
pub const THREAD_BIND_DEATH_NOTIFICATION: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 12,
    name: "BIND_DEATH_NOTIFICATION",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[
        ("caps[0]", ObjType::Notification, Rights::SIGNAL), // optional, NULL to clear
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::EBADSTATE, ErrorCode::EREVOKED],
    commutativity: Commutativity::Commutes,
    description: "Bind a notification to be signalled when the thread exits. caps[0] = Notification or NULL to clear.",
};

/// THREAD_CREATE invoke specification
pub const THREAD_CREATE: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 13,
    name: "THREAD_CREATE",
    required_rights: Rights::CONTROL,
    args: &[
        InvokeArg {
            name: "entry_pc",
            range: (1, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Entry point PC (must be canonical user address)",
        },
        InvokeArg {
            name: "stack_top",
            range: (0, 0x0000_8000_0000_0000 - 1),
            range_error: ErrorCode::EBADARG,
            description: "Initial user stack top (RFC-0004/ADR-085). 0 = arch default USER_STACK_TOP (0x0000_7FFF_FFFF_F000). Nonzero: canonical user address (nonzero, < 0x8000_0000_0000_0000) AND 16-byte aligned; the caller maps [top - size, top) in the target process's AS. Form only — an unmapped top faults in the child at first push (fault EP, ADR-007).",
        },
    ],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::ENOMEM, ErrorCode::EBADSTATE],
    commutativity: Commutativity::Commutes,
    description: "Create a new thread in the same process as the target (shares AS and cap table). w0 = entry PC, w1 = initial user stack top (0 = arch default, RFC-0004/ADR-085). Returns thread cap with CONTROL|GRANT.",
};

/// THREAD_SET_ENTRY invoke specification
pub const THREAD_SET_ENTRY: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 14,
    name: "SET_ENTRY",
    required_rights: Rights::CONTROL,
    args: &[InvokeArg {
        name: "entry_pc",
        range: (1, u64::MAX),
        range_error: ErrorCode::EBADARG,
        description: "New entry PC (must be canonical user address)",
    }],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description: "Rewrite a SUSPENDED thread's entry PC and rebuild its initial kernel context.",
};

/// THREAD_SET_FOREIGN invoke specification
pub const THREAD_SET_FOREIGN: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 15,
    name: "SET_FOREIGN",
    required_rights: Rights::CONTROL,
    args: &[InvokeArg {
        name: "endpoint_handle",
        range: (0, u32::MAX as u64),
        range_error: ErrorCode::EBADCAP,
        description: "Caller's cap handle for the route endpoint (0 = clear foreign routing)",
    }],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description:
        "Flag the thread for foreign syscall routing. w0 = endpoint handle in caller's cap table.",
};

/// THREAD_TRAP_READ invoke specification
pub const THREAD_TRAP_READ: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 16,
    name: "TRAP_READ",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADSTATE,
    ],
    commutativity: Commutativity::Commutes,
    description:
        "Read the routed syscall frame from a foreign-parked thread. Returns [tag, w0, w1, w2].",
};

/// THREAD_DEFER invoke specification
pub const THREAD_DEFER: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 17,
    name: "DEFER",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::EBADSTATE],
    commutativity: Commutativity::Commutes,
    description: "Mint a one-shot Reply cap from the thread's implicit reply slot (self only). Returns handle.",
};

/// THREAD_BIND_FAULT_EP invoke specification
///
/// ADR-088 (RFC-0005 §2): the fault endpoint leaves NEW_THREAD's uniform
/// cap_count-2 packing (it was NULL in every production sender) and comes
/// back as this post-creation bind. Label 18: TRAP_READ owns 16, DEFER
/// owns 17. ADR-017's fault-race objection is answered structurally: a
/// NEW_THREAD child is created Ready and the cooperative scheduler cannot
/// run it while the parent is Running, so a launcher that wants fault
/// routing MUST invoke BIND_FAULT_EP before its first yield or block.
pub const THREAD_BIND_FAULT_EP: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 18,
    name: "BIND_FAULT_EP",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[
        ("caps[0]", ObjType::Endpoint, Rights::GRANT), // optional, NULL to clear
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG],
    commutativity: Commutativity::Conflicts,
    description: "Bind or clear the target thread's fault endpoint (ADR-088). caps[0] = Endpoint or NULL to clear. CONTROL required (else ERIGHTS); target must be live (else EBADCAP); the caller's cap must be a live Endpoint carrying GRANT (else EBADARG/ERIGHTS); the target's process receives rights ∩ requested (S8 — never a full-rights copy, never an added right). Errors: EBADCAP, ERIGHTS, EBADARG.",
};

/// THREAD_REGS_READ invoke specification
pub const THREAD_REGS_READ: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 9,
    name: "REGS_READ",
    required_rights: Rights::CONTROL,
    args: &[],
    descriptors: &[
        ("caps[0]", ObjType::Frame, Rights::READ), // validating frame
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::EBADSTATE, ErrorCode::EREVOKED],
    commutativity: Commutativity::Commutes,
    description: "Read the target thread's user register image. caps[0] = Frame cap (validating access). Returns [rax, rdi, rsi, rdx].",
};

/// THREAD_REGS_WRITE invoke specification
pub const THREAD_REGS_WRITE: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Thread,
    label: 10,
    name: "REGS_WRITE",
    required_rights: Rights::CONTROL,
    args: &[
        InvokeArg {
            name: "image",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "10 qwords of register image (w0..w3 = first 4, rest implicit). Slot 1 (user RSP) and slot 2 (entry PC) must be canonical non-null user addresses (< 0x8000_0000_0000_0000); EBADARG otherwise. Slot 3 (RFLAGS) is masked, never an error.",
        },
    ],
    descriptors: &[
        ("caps[0]", ObjType::Frame, Rights::WRITE), // validating frame
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::EBADSTATE, ErrorCode::EREVOKED],
    commutativity: Commutativity::Commutes,
    description: "Write the target thread's user register image. caps[0] = Frame cap (validating access). Image slot 1 (user RSP, S2d) and slot 2 (entry PC, S2b) must be canonical user addresses — either faulting value would reach iretq from ring 0.",
};

// ============================================================================
// AddressSpace methods (ObjType::AddressSpace)
// ============================================================================

/// AS_MAP invoke specification
pub const AS_MAP: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 1,
    name: "MAP",
    required_rights: Rights::MAP,
    args: &[
        InvokeArg {
            name: "vaddr",
            range: (0x1000, 0x0000_7FFF_FFFF_E000),
            range_error: ErrorCode::EBADARG,
            description: "Virtual address (page-aligned, canonical user range, not VA 0)",
        },
        InvokeArg {
            name: "flags",
            range: (1, 0b1_1111),
            range_error: ErrorCode::EBADARG,
            description: "MapFlags: bits 0..2 = R|W|X, bit 4 = ANON (non-zero required)",
        },
    ],
    descriptors: &[
        ("caps[0]", ObjType::Frame, Rights::READ.union(Rights::WRITE).union(Rights::EXEC)), // required unless ANON
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
        ErrorCode::EEXIST,
    ],
    commutativity: Commutativity::CommutesDisjointRanges,
    description: "Map a frame into the address space. If ANON flag is set and no fault pool attached, resolves eagerly with a zeroed frame. Frame cap rights must cover requested MapFlags (READ->R, WRITE->W, EXEC->X).",
};

/// AS_UNMAP invoke specification
pub const AS_UNMAP: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 2,
    name: "UNMAP",
    required_rights: Rights::MAP,
    args: &[
        InvokeArg {
            name: "vaddr",
            range: (0x1000, 0x0000_7FFF_FFFF_E000),
            range_error: ErrorCode::EBADARG,
            description: "Virtual address (page-aligned)",
        },
        InvokeArg {
            name: "pages",
            range: (1, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Number of pages to unmap",
        },
    ],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
    ],
    commutativity: Commutativity::CommutesDisjointRanges,
    description: "Unmap a range of pages from the address space.",
};

/// AS_PROTECT invoke specification
pub const AS_PROTECT: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 3,
    name: "PROTECT",
    required_rights: Rights::MAP,
    args: &[
        InvokeArg {
            name: "vaddr",
            range: (0x1000, 0x0000_7FFF_FFFF_E000),
            range_error: ErrorCode::EBADARG,
            description: "Virtual address (page-aligned)",
        },
        InvokeArg {
            name: "flags",
            range: (0, 0b111),
            range_error: ErrorCode::EBADARG,
            description: "New MapFlags (R|W|X)",
        },
    ],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
    ],
    commutativity: Commutativity::CommutesDisjointRanges,
    description: "Change protection flags on a mapped page.",
};

/// AS_SET_FAULT_POOL invoke specification
pub const AS_SET_FAULT_POOL: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 4,
    name: "SET_FAULT_POOL",
    required_rights: Rights::MAP,
    args: &[],
    descriptors: &[
        ("caps[0]", ObjType::Region, Rights(0)), // Region to dedicate as fault pool
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::ENOMEM],
    commutativity: Commutativity::Conflicts,
    description: "Dedicate a Region's remaining space as the address space's fault pool for lazy ANON/COW resolution.",
};

/// AS_FORK invoke specification
pub const AS_FORK: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 5,
    name: "FORK",
    required_rights: Rights::MAP,
    args: &[],
    descriptors: &[],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::ENOMEM, ErrorCode::ENOSYS],
    commutativity: Commutativity::Conflicts,
    description: "Fork the address space (COW clone). Returns child AS cap with MAP|GRANT. Requires backend copy_page support.",
};

/// AS_DESTROY invoke specification
pub const AS_DESTROY: InvokeSpec = InvokeSpec {
    obj_type: ObjType::AddressSpace,
    label: 6,
    name: "DESTROY",
    required_rights: Rights::MAP,
    args: &[],
    descriptors: &[],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
    ],
    commutativity: Commutativity::Conflicts,
    description: "Destroy the address space, dropping all mappings and frame references.",
};

// ============================================================================
// Reply methods (ObjType::Reply)
// ============================================================================

/// REPLY_SEND invoke specification
pub const REPLY_SEND: InvokeSpec = InvokeSpec {
    obj_type: ObjType::Reply,
    label: 1,
    name: "SEND",
    required_rights: Rights::SEND,
    args: &[
        InvokeArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Reply message tag",
        },
        InvokeArg {
            name: "w0",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 0",
        },
        InvokeArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 1",
        },
        InvokeArg {
            name: "w2",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 2",
        },
        InvokeArg {
            name: "w3",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 3",
        },
    ],
    descriptors: &[
        ("caps[0..3]", ObjType::Any, Rights::GRANT), // optional capability transfer
    ],
    errors: &[ErrorCode::OK, ErrorCode::EBADCAP, ErrorCode::ERIGHTS, ErrorCode::EBADARG, ErrorCode::EBADSTATE],
    commutativity: Commutativity::Commutes,
    description: "Deliver the deferred reply to the parked caller (ObjId = caller TID) and retire the Reply cap (one-shot).",
};

// ============================================================================
// All invoke specs and lookup table
// ============================================================================

/// All invoke method specifications
pub const ALL_SPECS: &[InvokeSpec] = &[
    FACTORY_NEW_ENDPOINT,
    FACTORY_NEW_NOTIFICATION,
    FACTORY_NEW_ADDRESS_SPACE,
    FACTORY_NEW_THREAD,
    FACTORY_RETYPE,
    THREAD_EXIT,
    THREAD_KILL,
    THREAD_SUSPEND,
    THREAD_RESUME,
    THREAD_SET_PRIORITY,
    THREAD_SET_TLS,
    THREAD_BIND_DEATH_NOTIFICATION,
    THREAD_CREATE,
    THREAD_SET_ENTRY,
    THREAD_SET_FOREIGN,
    THREAD_TRAP_READ,
    THREAD_DEFER,
    THREAD_BIND_FAULT_EP,
    THREAD_REGS_READ,
    THREAD_REGS_WRITE,
    AS_MAP,
    AS_UNMAP,
    AS_PROTECT,
    AS_SET_FAULT_POOL,
    AS_FORK,
    AS_DESTROY,
    REPLY_SEND,
];

/// Lookup table by (object_type, label)
pub const SPEC_BY_TYPE_AND_LABEL: &[((ObjType, u16), &InvokeSpec)] = &[
    (
        (ObjType::Factory, FACTORY_NEW_ENDPOINT.label),
        &FACTORY_NEW_ENDPOINT,
    ),
    (
        (ObjType::Factory, FACTORY_NEW_NOTIFICATION.label),
        &FACTORY_NEW_NOTIFICATION,
    ),
    (
        (ObjType::Factory, FACTORY_NEW_ADDRESS_SPACE.label),
        &FACTORY_NEW_ADDRESS_SPACE,
    ),
    (
        (ObjType::Factory, FACTORY_NEW_THREAD.label),
        &FACTORY_NEW_THREAD,
    ),
    ((ObjType::Factory, FACTORY_RETYPE.label), &FACTORY_RETYPE),
    ((ObjType::Thread, THREAD_EXIT.label), &THREAD_EXIT),
    ((ObjType::Thread, THREAD_KILL.label), &THREAD_KILL),
    ((ObjType::Thread, THREAD_SUSPEND.label), &THREAD_SUSPEND),
    ((ObjType::Thread, THREAD_RESUME.label), &THREAD_RESUME),
    (
        (ObjType::Thread, THREAD_SET_PRIORITY.label),
        &THREAD_SET_PRIORITY,
    ),
    ((ObjType::Thread, THREAD_SET_TLS.label), &THREAD_SET_TLS),
    (
        (ObjType::Thread, THREAD_BIND_DEATH_NOTIFICATION.label),
        &THREAD_BIND_DEATH_NOTIFICATION,
    ),
    ((ObjType::Thread, THREAD_CREATE.label), &THREAD_CREATE),
    ((ObjType::Thread, THREAD_SET_ENTRY.label), &THREAD_SET_ENTRY),
    (
        (ObjType::Thread, THREAD_SET_FOREIGN.label),
        &THREAD_SET_FOREIGN,
    ),
    ((ObjType::Thread, THREAD_TRAP_READ.label), &THREAD_TRAP_READ),
    ((ObjType::Thread, THREAD_DEFER.label), &THREAD_DEFER),
    (
        (ObjType::Thread, THREAD_BIND_FAULT_EP.label),
        &THREAD_BIND_FAULT_EP,
    ),
    ((ObjType::Thread, THREAD_REGS_READ.label), &THREAD_REGS_READ),
    (
        (ObjType::Thread, THREAD_REGS_WRITE.label),
        &THREAD_REGS_WRITE,
    ),
    ((ObjType::AddressSpace, AS_MAP.label), &AS_MAP),
    ((ObjType::AddressSpace, AS_UNMAP.label), &AS_UNMAP),
    ((ObjType::AddressSpace, AS_PROTECT.label), &AS_PROTECT),
    (
        (ObjType::AddressSpace, AS_SET_FAULT_POOL.label),
        &AS_SET_FAULT_POOL,
    ),
    ((ObjType::AddressSpace, AS_FORK.label), &AS_FORK),
    ((ObjType::AddressSpace, AS_DESTROY.label), &AS_DESTROY),
    ((ObjType::Reply, REPLY_SEND.label), &REPLY_SEND),
];
