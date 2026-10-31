//! x86_64 memory layout constants (ADR-017).
//!
//! `USER_STACK_TOP` is the arch ABI constant for the initial thread stack
//! top. It is the single source of truth shared with `sdk::layout` (userspace
//! side) — both must be kept identical.

#![allow(dead_code)]

/// Initial user thread stack top (x86_64: 47-bit canonical user address space
/// top, page-aligned). Matches `sdk::layout::USER_STACK_TOP`.
pub const USER_STACK_TOP: usize = 0x0000_7FFF_FFFF_F000;

/// Default thread stack size (1 MiB).
pub const DEFAULT_STACK_SIZE: usize = 1 << 20;

/// Default thread priority (ADR-010: u8, higher = more urgent, default 100).
pub const DEFAULT_THREAD_PRIORITY: u8 = 100;
