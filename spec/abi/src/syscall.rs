//! Syscall definitions and specifications

use crate::capability::Rights;
use crate::commutativity::Commutativity;
use crate::error::ErrorCode;

/// Maximum number of capability descriptors in a message
pub const MAX_DESCRIPTORS: usize = 4;

/// Maximum message payload words (w0..w3)
pub const MAX_PAYLOAD_WORDS: usize = 4;

/// A single syscall argument specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallArg {
    /// Argument name (for documentation)
    pub name: &'static str,
    /// Valid range: (min, max) inclusive. Use (0, u64::MAX) for unconstrained.
    pub range: (u64, u64),
    /// Error code returned when the argument is out of range
    pub range_error: ErrorCode,
    /// Description of the argument's purpose
    pub description: &'static str,
}

/// Complete syscall specification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallSpec {
    /// Syscall number (rax / x8 / a7)
    pub num: u64,
    /// Syscall name
    pub name: &'static str,
    /// Arguments (cap handle, tag, w0..w3)
    pub args: &'static [SyscallArg],
    /// Possible error codes this syscall can return
    pub errors: &'static [ErrorCode],
    /// Commutativity classification
    pub commutativity: Commutativity,
    /// Brief description
    pub description: &'static str,
}

/// The YIELD syscall (0): yield the CPU
pub const YIELD_SPEC: SyscallSpec = SyscallSpec {
    num: 0,
    name: "YIELD",
    args: &[
        SyscallArg {
            name: "cap",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0 (no capability used)",
        },
        SyscallArg {
            name: "tag",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0 (no message tag)",
        },
        SyscallArg {
            name: "w0",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w1",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w2",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w3",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
    ],
    errors: &[ErrorCode::OK],
    commutativity: Commutativity::Commutes,
    description: "Yield the CPU to another thread of the same or higher priority",
};

/// The SEND syscall (1): send a message to an endpoint
pub const SEND_SPEC: SyscallSpec = SyscallSpec {
    num: 1,
    name: "SEND",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle of the destination endpoint (handle = slot + 1)",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Message tag (label + flags + descriptor count)",
        },
        SyscallArg {
            name: "w0",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 0",
        },
        SyscallArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 1",
        },
        SyscallArg {
            name: "w2",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 2",
        },
        SyscallArg {
            name: "w3",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 3",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EWOULDBLOCK,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
    ],
    commutativity: Commutativity::Commutes,
    description: "Send a message to an endpoint. Blocks if the endpoint mailbox is full unless FLAG_NONBLOCK is set.",
};

/// The CALL syscall (2): synchronous call/reply to an endpoint
pub const CALL_SPEC: SyscallSpec = SyscallSpec {
    num: 2,
    name: "CALL",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle of the destination endpoint",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Message tag (label + flags + descriptor count)",
        },
        SyscallArg {
            name: "w0",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 0",
        },
        SyscallArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 1",
        },
        SyscallArg {
            name: "w2",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 2",
        },
        SyscallArg {
            name: "w3",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Message payload word 3",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EWOULDBLOCK,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
    ],
    commutativity: Commutativity::Commutes,
    description: "Synchronous call to an endpoint. Blocks until a reply is received. Creates an implicit reply capability.",
};

/// The RECV syscall (3): receive a message from an endpoint
pub const RECV_SPEC: SyscallSpec = SyscallSpec {
    num: 3,
    name: "RECV",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle of the source endpoint",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Ignored on receive (kernel fills in the received tag)",
        },
        SyscallArg {
            name: "w0",
            range: (0, 1),
            range_error: ErrorCode::EBADARG,
            description: "Blocking flag: 1 = block until message arrives, 0 = return EWOULDBLOCK",
        },
        SyscallArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Deadline in nanoseconds (0 = no deadline)",
        },
        SyscallArg {
            name: "w2",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w3",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EWOULDBLOCK,
        ErrorCode::EBADARG,
        ErrorCode::ETIMEDOUT,
    ],
    commutativity: Commutativity::Commutes,
    description:
        "Receive a message from an endpoint. Can block or return immediately with EWOULDBLOCK.",
};

/// The REPLY_RECV syscall (4): reply to a call and wait for the next message
pub const REPLY_RECV_SPEC: SyscallSpec = SyscallSpec {
    num: 4,
    name: "REPLY_RECV",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle of the endpoint to receive from",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Reply message tag",
        },
        SyscallArg {
            name: "w0",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 0",
        },
        SyscallArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 1",
        },
        SyscallArg {
            name: "w2",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 2",
        },
        SyscallArg {
            name: "w3",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Reply payload word 3",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EWOULDBLOCK,
        ErrorCode::EBADARG,
        ErrorCode::ETIMEDOUT,
    ],
    commutativity: Commutativity::Commutes,
    description: "Reply to the pending call (consuming the implicit reply cap) and atomically wait for the next message on the same endpoint.",
};

/// The INVOKE syscall (5): invoke a method on a kernel object
pub const INVOKE_SPEC: SyscallSpec = SyscallSpec {
    num: 5,
    name: "INVOKE",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle of the target object",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Invoke tag: label = method ID, flags, descriptor count",
        },
        SyscallArg {
            name: "w0",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Method argument 0",
        },
        SyscallArg {
            name: "w1",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Method argument 1",
        },
        SyscallArg {
            name: "w2",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Method argument 2",
        },
        SyscallArg {
            name: "w3",
            range: (0, u64::MAX),
            range_error: ErrorCode::EBADARG,
            description: "Method argument 3",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOSYS,
        ErrorCode::ENOMEM,
        ErrorCode::EBADSTATE,
        ErrorCode::EREVOKED,
    ],
    commutativity: Commutativity::DependsOnMethod,
    description: "Invoke a method on a kernel object (Factory, Thread, AddressSpace, Reply, etc.). Method is encoded in tag.label(). Commutativity depends on the specific method.",
};

/// The CAP_MINT syscall (6): mint a derived capability
pub const CAP_MINT_SPEC: SyscallSpec = SyscallSpec {
    num: 6,
    name: "CAP_MINT",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Source capability handle (must have GRANT right)",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Descriptor count in flags (0 or 1 for dest slot)",
        },
        SyscallArg {
            name: "w0",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Destination slot (0 = first free, 0xFFFF_FFFF = first free sentinel)",
        },
        SyscallArg {
            name: "w1",
            range: (0, Rights::ALL.0 as u64),
            range_error: ErrorCode::ERIGHTS,
            description: "Rights mask for the new capability (must be subset of source rights)",
        },
        SyscallArg {
            name: "w2",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w3",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
    ],
    commutativity: Commutativity::Commutes,
    description: "Create a derived capability from an existing one with reduced rights. The destination slot can be specified or auto-assigned.",
};

/// The CAP_REVOKE syscall (7): revoke a capability and its derivatives
pub const CAP_REVOKE_SPEC: SyscallSpec = SyscallSpec {
    num: 7,
    name: "CAP_REVOKE",
    args: &[
        SyscallArg {
            name: "cap",
            range: (1, u32::MAX as u64),
            range_error: ErrorCode::EBADCAP,
            description: "Capability handle to revoke",
        },
        SyscallArg {
            name: "tag",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Ignored",
        },
        SyscallArg {
            name: "w0",
            range: (0, 1),
            range_error: ErrorCode::EBADARG,
            description: "Revoke mode: 0 = REVOKE_DERIVED (keep cap, revoke children), 1 = DELETE (revoke all including self)",
        },
        SyscallArg {
            name: "w1",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w2",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w3",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
    ],
    errors: &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::EBADARG,
    ],
    commutativity: Commutativity::Conflicts,
    description: "Revoke a capability and all capabilities derived from it. Mode 0 keeps the cap, mode 1 deletes it too.",
};

/// The EXIT syscall (8): exit the current thread
pub const EXIT_SPEC: SyscallSpec = SyscallSpec {
    num: 8,
    name: "EXIT",
    args: &[
        SyscallArg {
            name: "cap",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0 (no capability used)",
        },
        SyscallArg {
            name: "tag",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w0",
            range: (0, u32::MAX as u64),
            range_error: ErrorCode::EBADARG,
            description: "Exit status (i32, sign-extended)",
        },
        SyscallArg {
            name: "w1",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w2",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
        SyscallArg {
            name: "w3",
            range: (0, 0),
            range_error: ErrorCode::EBADARG,
            description: "Must be 0",
        },
    ],
    errors: &[ErrorCode::OK],
    commutativity: Commutativity::Commutes,
    description: "Exit the current thread with the given status. If this was the last thread, the system halts cleanly.",
};

/// All syscall specifications, indexed by number
pub const ALL_SPECS: &[SyscallSpec] = &[
    YIELD_SPEC,
    SEND_SPEC,
    CALL_SPEC,
    RECV_SPEC,
    REPLY_RECV_SPEC,
    INVOKE_SPEC,
    CAP_MINT_SPEC,
    CAP_REVOKE_SPEC,
    EXIT_SPEC,
];

/// Lookup table by syscall number (built at compile time)
pub const SPEC_BY_NUM: &[(u64, SyscallSpec)] = &[
    (YIELD_SPEC.num, YIELD_SPEC),
    (SEND_SPEC.num, SEND_SPEC),
    (CALL_SPEC.num, CALL_SPEC),
    (RECV_SPEC.num, RECV_SPEC),
    (REPLY_RECV_SPEC.num, REPLY_RECV_SPEC),
    (INVOKE_SPEC.num, INVOKE_SPEC),
    (CAP_MINT_SPEC.num, CAP_MINT_SPEC),
    (CAP_REVOKE_SPEC.num, CAP_REVOKE_SPEC),
    (EXIT_SPEC.num, EXIT_SPEC),
];

/// Get the number of defined syscalls
pub const fn syscall_count() -> usize {
    ALL_SPECS.len()
}
