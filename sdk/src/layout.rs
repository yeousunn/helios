//! Arch/ABI layout constants shared by launchers and processes.
//!
//! Per ADR-017, `NEW_THREAD` does not take a stack pointer: the initial stack
//! pointer is fixed by the architecture ABI. Launchers map the first stack at
//! `USER_STACK_TOP - stack_size`; threads start with SP = `USER_STACK_TOP`.
#![forbid(unsafe_code)]

/// Top of the initial user stack (x86_64; canonical low half, page-aligned).
pub const USER_STACK_TOP: u64 = 0x0000_7FFF_FFFF_F000;

/// Priority every thread starts with (ADR-017 §3, scheduler default per
/// ADR-010; higher = more urgent). Launchers re-prioritize via
/// `Thread::SET_PRIORITY` when they want something else.
pub const DEFAULT_THREAD_PRIORITY: u8 = 100;

/// VA bases for server connection windows (design doc §1.3; v0 constants).
/// Distinct per server so the kernel-wide v0 VMM never collides; a window is
/// one 4 KiB frame, mapped on first access. Subject to the per-process VMM
/// layout ADR later.
pub const PS_WINDOW_VA_BASE: u64 = 0x0000_4000_0000_0000;
pub const VFS_WINDOW_VA_BASE: u64 = 0x0000_4001_0000_0000;

/// VA bases for server heaps (`sdk::heap::RegionSource`; v0 fixed-size heaps).
pub const PS_HEAP_VA_BASE: u64 = 0x0000_4000_1000_0000;
pub const VFS_HEAP_VA_BASE: u64 = 0x0000_4001_1000_0000;

/// v0 heap size per server: 1 MiB (16 × 64 KiB chunks, mapped at startup).
pub const HEAP_CHUNK: u64 = 64 * 1024;
pub const HEAP_CHUNKS: u64 = 16;

/// init (launcher) VA reservations: its own heap, loader scratch mappings,
/// and the CONNECT arg window (client side writes request data there).
pub const INIT_HEAP_VA_BASE: u64 = 0x0000_3F00_1000_0000;
pub const INIT_SCRATCH_VA_BASE: u64 = 0x0000_3F00_2000_0000;
pub const INIT_WINDOW_VA_BASE: u64 = 0x0000_3F00_3000_0000;

/// PS (process server) loader scratch: transient self-mappings while crafting
/// frames for children (ELF segments, the argv-carrying stack top page).
pub const PS_SCRATCH_VA_BASE: u64 = 0x0000_4000_2000_0000;

/// Initial stack for spawned processes: 64 KiB of ANON pages below
/// `USER_STACK_TOP`.
pub const CHILD_STACK_PAGES: u64 = 16;
