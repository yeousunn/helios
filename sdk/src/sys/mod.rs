//! System-specific raw implementations.
//!
//! Only `raw.rs` (the x86_64 syscall assembly and unsafe primitives) is
//! allowed `unsafe` in this crate (PLAN.md §7.1). All other modules in
//! `sdk` are `#![forbid(unsafe_code)]`.

pub mod raw;

pub use crate::entry_point;
pub use crate::init_entry_point;
pub use crate::server_entry_point;
pub use raw::{
    raw_copy_from_va, raw_copy_from_va_to_u64x3, raw_copy_to_va, raw_cstr_from_va,
    raw_ptr_array_from_va, rdtsc, read_bootinfo, SysHeap, X86_64Syscalls,
};
