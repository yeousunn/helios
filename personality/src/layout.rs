//! VA layout for personality-hosted processes.
//!
//! Every spawned process gets a fresh address space; these bases only have to
//! avoid the image (0x7E000000+), the user stack (`USER_STACK_TOP` down), and
//! the SDK's other reserved areas for the same process (`sdk::layout`).
//! Kept in the upper user range, page-aligned, and 2 MiB apart so mapping
//! table splits never collide.

/// Heap mapping base (`RegionSource` chunks grow upward from here).
pub const HEAP_VA_BASE: u64 = 0x0000_5F00_0000_0000;
/// VFS connection arg window (4 KiB, design §1.3).
pub const ARG_WINDOW_VA: u64 = 0x0000_5F00_1000_0000;
/// VFS connection result window (4 KiB).
pub const RESULT_WINDOW_VA: u64 = 0x0000_5F00_1000_1000;
