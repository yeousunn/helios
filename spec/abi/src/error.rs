//! Error code definitions and specifications

use core::fmt;

/// Kernel error codes (must match ipc::status)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(i32)]
pub enum ErrorCode {
    /// Success
    OK = 0,
    /// Invalid capability handle
    EBADCAP = -1,
    /// Insufficient rights on capability
    ERIGHTS = -2,
    /// Invalid argument
    EBADARG = -3,
    /// Out of memory / kernel resources
    ENOMEM = -4,
    /// Would block (non-blocking operation)
    EWOULDBLOCK = -5,
    /// Timeout expired
    ETIMEDOUT = -6,
    /// System call not implemented
    ENOSYS = -7,
    /// Invalid state for operation
    EBADSTATE = -8,
    /// Object was revoked
    EREVOKED = -9,
    /// Object already exists
    EEXIST = -10,
    /// No such process/thread
    ESRCH = -11,
    /// Permission denied
    EPERM = -12,
    /// I/O error
    EIO = -13,
    /// Interrupted
    EINTR = -14,
}

impl ErrorCode {
    /// All defined error codes
    pub const ALL: &[ErrorCode] = &[
        ErrorCode::OK,
        ErrorCode::EBADCAP,
        ErrorCode::ERIGHTS,
        ErrorCode::EBADARG,
        ErrorCode::ENOMEM,
        ErrorCode::EWOULDBLOCK,
        ErrorCode::ETIMEDOUT,
        ErrorCode::ENOSYS,
        ErrorCode::EBADSTATE,
        ErrorCode::EREVOKED,
        ErrorCode::EEXIST,
        ErrorCode::ESRCH,
        ErrorCode::EPERM,
        ErrorCode::EIO,
        ErrorCode::EINTR,
    ];

    /// Get the numeric value
    pub fn value(self) -> i32 {
        self as i32
    }

    /// Check if this is a success code
    pub fn is_ok(self) -> bool {
        self == ErrorCode::OK
    }

    /// Check if this is an error code
    pub fn is_err(self) -> bool {
        self != ErrorCode::OK
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({})", self, self.value())
    }
}

/// Error specification with context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorSpec {
    /// The error code
    pub code: ErrorCode,
    /// When this error is returned
    pub condition: &'static str,
    /// Additional context
    pub context: &'static str,
}

/// Common error specifications for syscalls
pub mod common {
    use super::{ErrorCode, ErrorSpec};

    /// EBADCAP: capability handle is invalid (0, out of range, or not a capability)
    pub const EBADCAP_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EBADCAP,
        condition: "capability handle is 0, exceeds table size, or slot is empty",
        context:
            "The handle must be a valid capability in the caller's cap table (handle = slot + 1)",
    };

    /// ERIGHTS: capability exists but lacks required rights
    pub const ERIGHTS_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::ERIGHTS,
        condition: "capability lacks one or more required rights for the operation",
        context: "Required rights are specified per syscall/invoke method. Rights can only be reduced, never added, during transfer.",
    };

    /// EBADARG: argument value is outside valid range
    pub const EBADARG_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EBADARG,
        condition: "one or more syscall/invoke arguments are outside their valid range",
        context: "Each argument has a documented valid range. This includes: non-canonical addresses, VA 0, unaligned addresses, zero flags where non-zero required, etc.",
    };

    /// ENOMEM: kernel resource exhausted (frames, cap slots, object table entries)
    pub const ENOMEM_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::ENOMEM,
        condition: "kernel cannot allocate required resource (frame, cap slot, object entry)",
        context: "All kernel memory comes from Untyped. If the caller's Untyped quota is exhausted, operations fail with ENOMEM.",
    };

    /// EWOULDBLOCK: non-blocking operation would need to block
    pub const EWOULDBLOCK_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EWOULDBLOCK,
        condition: "FLAG_NONBLOCK set and operation cannot complete immediately",
        context: "For SEND: endpoint mailbox full. For RECV: no message available. For REPLY_RECV: no message after reply.",
    };

    /// ETIMEDOUT: deadline expired
    pub const ETIMEDOUT_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::ETIMEDOUT,
        condition: "operation did not complete before the specified deadline",
        context: "Deadline is specified in nanoseconds since boot. 0 = no deadline.",
    };

    /// ENOSYS: syscall/invoke method not implemented
    pub const ENOSYS_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::ENOSYS,
        condition: "syscall number or invoke method label is not recognized",
        context: "The set of syscalls is frozen (ADR-005). New methods require an ADR.",
    };

    /// EBADSTATE: object is in wrong state for operation
    pub const EBADSTATE_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EBADSTATE,
        condition: "target object exists but is in an invalid state for the requested operation",
        context: "Examples: REGS_WRITE on a running thread, DEFER on another thread, SET_ENTRY on non-SUSPENDED thread.",
    };

    /// EREVOKED: capability was revoked
    pub const EREVOKED_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EREVOKED,
        condition: "the capability's object has been retired (epoch bumped or alive=false)",
        context: "Object retirement happens on process exit or explicit revoke. Transfers of dead-object caps fail at install time.",
    };

    /// EEXIST: object already exists
    pub const EEXIST_SPEC: ErrorSpec = ErrorSpec {
        code: ErrorCode::EEXIST,
        condition: "operation would create a duplicate object where uniqueness is required",
        context: "Currently used by AS::MAP when the virtual address range is already mapped.",
    };
}
