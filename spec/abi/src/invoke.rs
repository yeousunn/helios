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
            name: "w1_reserved",
            range: (0, u64::MAX),
            range_error: ErrorCode::OK,
            description: "RESERVED (ignored by the kernel). RFC-0004/ADR-085 assigned w1 = initial stack top, but at cap_count 3 — the layout every production sender uses — trailing-descriptor overlay puts descriptor 0 (the AS cap) in words[1], so w1 carries descriptor bytes, not a stack value. The kernel therefore reads no stack from NEW_THREAD until the wire format grows (ADR-086 proposal); custom stacks go through THREAD_CREATE w1.",
        },
    ],
    descriptors: &[
        ("caps[0]", ObjType::AddressSpace, Rights::MAP), // required
        ("caps[1]", ObjType::Endpoint, Rights::GRANT),    // optional fault endpoint
        ("caps[2]", ObjType::Endpoint, Rights::GRANT),    // optional bootstrap endpoint
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
    description: "Create a new thread in a new process. w0 = entry PC; w1 is descriptor-overlay territory at cap_count 3 (the kernel ignores it — ADR-086). caps[0] = AddressSpace (required, MAP right). caps[1] = fault endpoint (optional, GRANT). caps[2] = bootstrap endpoint (optional, GRANT, installed at child handle 1). Returns thread cap with CONTROL|GRANT.",
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
