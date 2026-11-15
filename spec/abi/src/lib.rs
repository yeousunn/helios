//! Helios Kernel ABI Specification (spec/abi)
//!
//! This crate provides a machine-readable description of the Helios kernel ABI:
//! - Syscall numbers, arguments, valid ranges, error codes
//! - Invoke method tables per object type
//! - Capability rights and object types
//! - Commutativity annotations for scaling
//!
//! The kernel's `entry.rs` syscall numbers and invoke dispatch must match this spec.
//! A test in `kernel/src/entry.rs` verifies the correspondence.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capability;
pub mod commutativity;
pub mod entry;
pub mod error;
pub mod invoke;
pub mod syscall;

pub use capability::{ObjType, Rights};
pub use commutativity::{Commutativity, CommutativitySpec, ResourceExtractor, ResourceKey};
pub use entry::{
    BOOTINFO_MAGIC, BOOTINFO_MAX_LEN, BOOTINFO_VERSION_V0, BOOTINFO_VERSION_V1, MAX_REGIONS,
};
pub use error::{ErrorCode, ErrorSpec};
pub use invoke::InvokeSpec;
/// Re-export commonly used types
pub use syscall::{syscall_count, SyscallArg, SyscallSpec};

/// Current ABI version
pub const ABI_VERSION: u32 = 1;

/// Validate that a syscall number is known
pub fn is_valid_syscall(num: u64) -> bool {
    syscall::SPEC_BY_NUM.iter().any(|(n, _)| *n == num)
}

/// Validate that an invoke method is known for an object type
pub fn is_valid_invoke(obj_type: ObjType, label: u16) -> bool {
    invoke::SPEC_BY_TYPE_AND_LABEL
        .iter()
        .any(|((ot, l), _)| *ot == obj_type && *l == label)
}

/// Get the syscall specification by number
pub fn syscall_spec(num: u64) -> Option<&'static SyscallSpec> {
    syscall::SPEC_BY_NUM
        .iter()
        .find(|(n, _)| *n == num)
        .map(|(_, s)| s)
}

/// Get the invoke method specification by object type and label
pub fn invoke_spec(obj_type: ObjType, label: u16) -> Option<&'static InvokeSpec> {
    invoke::SPEC_BY_TYPE_AND_LABEL
        .iter()
        .find(|((ot, l), _)| *ot == obj_type && *l == label)
        .map(|(_, s)| *s)
}
