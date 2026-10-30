//! Arch/ABI layout constants shared by launchers and processes.
//!
//! Per ADR-017, `NEW_THREAD` does not take a stack pointer: the initial stack
//! pointer is fixed by the architecture ABI. Launchers map the first stack at
//! `USER_STACK_TOP - stack_size`; threads start with SP = `USER_STACK_TOP`.

/// Top of the initial user stack (x86_64; canonical low half, page-aligned).
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

/// Priority every thread starts with (ADR-017 §3, scheduler default per
/// ADR-010; higher = more urgent). Launchers re-prioritize via
/// `Thread::SET_PRIORITY` when they want something else.
pub const DEFAULT_THREAD_PRIORITY: u8 = 100;
