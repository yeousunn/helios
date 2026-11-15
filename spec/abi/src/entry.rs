//! The userspace entry contract (normative, ADR-073).
//!
//! Three entry forms exist. Each is pinned here with its constants so the
//! kernel side and the userspace side cannot drift silently: the bf8c0d5
//! boot regression (ADR-072) was exactly such a drift — userspace
//! reinterpreted the kernel's byte block as a Rust struct and never parsed
//! it. Every entry-path change updates this module first; implementations
//! take their constants from here.
//!
//! 1. **Launcher/init entry.** The kernel starts the first userspace thread
//!    with `rdi` = a `*const u8` pointer to the BootInfo **byte block**
//!    written by `kernel::init::write_bootinfo` (little-endian, layout
//!    below). Userspace MUST run that pointer through a bounds-checked
//!    parser (sdk: `BootInfo::parse`, at most [`BOOTINFO_MAX_LEN`] bytes)
//!    and MUST NOT reinterpret it as the Rust `BootInfo` struct: that
//!    struct's layout is unspecified and does not match the byte block.
//! 2. **Server entry.** A thread spawned with FACTORY_NEW_THREAD starts at
//!    its image entry with no register arguments. Its ADR-009 bootstrap
//!    package arrives on the endpoint the spawner passed in caps[2]
//!    (installed at the child's handle 1 per the NEW_THREAD invoke spec).
//! 3. **EXEC entry.** A thread re-targeted by PROCESS_SET_ENTRY keeps its
//!    thread identity and registers; the launcher crafts a 3-word stack
//!    header read as `[rsp - 8]` = argc, `[rsp - 16]` = argv*,
//!    `[rsp - 24]` = envp* (byte addresses, little-endian).
//!
//! # BootInfo byte block (little-endian)
//!
//! ```text
//! o  0: u32 magic = "HELI" ([BOOTINFO_MAGIC])
//! o  4: u32 version ([BOOTINFO_VERSION_V0] or [BOOTINFO_VERSION_V1])
//! o  8: u32 debug endpoint handle
//! o 12: u32 factory handle
//! o 16: u32 region_count
//! o 20: u32 self_as handle (0 = none; v0.1+, ADR-023)
//! o 24: u32 console_in handle (0 = none; v1 only, ADR-043)
//! o 28: u32 reserved (0)
//! o 32: region_count × { u32 handle; u32 reserved; u64 base; u64 len }
//! ```
//!
//! v0 readers (24-byte header, regions at 24) are rejected by the version
//! check on the userspace side; the kernel only writes v1.

/// BootInfo magic: "HELI", little-endian.
pub const BOOTINFO_MAGIC: u32 = 0x4845_4C49;
/// BootInfo v0: 24-byte header, regions start at offset 24.
pub const BOOTINFO_VERSION_V0: u32 = 0;
/// BootInfo v1 (ADR-043): console_in added, 32-byte header, regions at 32.
pub const BOOTINFO_VERSION_V1: u32 = 1;
/// Offset of the magic u32.
pub const OFF_MAGIC: usize = 0;
/// Offset of the version u32.
pub const OFF_VERSION: usize = 4;
/// Offset of the debug endpoint handle u32.
pub const OFF_DEBUG_EP: usize = 8;
/// Offset of the factory handle u32.
pub const OFF_FACTORY: usize = 12;
/// Offset of the region_count u32.
pub const OFF_REGION_COUNT: usize = 16;
/// Offset of the self_as handle u32 (0 = none).
pub const OFF_SELF_AS: usize = 20;
/// Offset of the console_in handle u32 (v1 only; 0 = none).
pub const OFF_CONSOLE_IN: usize = 24;
/// Offset of the reserved u32 (v1 only; always 0).
pub const OFF_RESERVED: usize = 28;
/// Header length in bytes of a v0 block (regions start here).
pub const HEADER_LEN_V0: usize = 24;
/// Header length in bytes of a v1 block (regions start here).
pub const HEADER_LEN_V1: usize = 32;
/// Maximum BootInfo regions the kernel grants; more are truncated.
pub const MAX_REGIONS: usize = 8;
/// One region record: u32 handle, u32 reserved, u64 base, u64 len.
pub const REGION_LEN: usize = 24;
/// Upper bound a parser may read: v1 header plus all regions.
pub const BOOTINFO_MAX_LEN: usize = HEADER_LEN_V1 + MAX_REGIONS * REGION_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden v1 block: one region. Every offset constant must land its
    /// field, and the region records must start at `HEADER_LEN_V1`.
    #[test]
    fn v1_layout_constants_match_a_written_block() {
        let debug_ep: u32 = 7;
        let factory: u32 = 9;
        let self_as: u32 = 3;
        let console_in: u32 = 11;
        let (handle, base, len): (u32, u64, u64) = (5, 0x1000_0000, 0x4000_0000);

        let mut block = [0u8; BOOTINFO_MAX_LEN];
        let mut put = |off: usize, v: u64, n: usize| {
            for i in 0..n {
                block[off + i] = ((v >> (i * 8)) & 0xFF) as u8;
            }
        };
        put(OFF_MAGIC, BOOTINFO_MAGIC as u64, 4);
        put(OFF_VERSION, BOOTINFO_VERSION_V1 as u64, 4);
        put(OFF_DEBUG_EP, debug_ep as u64, 4);
        put(OFF_FACTORY, factory as u64, 4);
        put(OFF_REGION_COUNT, 1, 4);
        put(OFF_SELF_AS, self_as as u64, 4);
        put(OFF_CONSOLE_IN, console_in as u64, 4);
        put(OFF_RESERVED, 0, 4);
        put(HEADER_LEN_V1, handle as u64, 4);
        put(HEADER_LEN_V1 + 8, base, 8);
        put(HEADER_LEN_V1 + 16, len, 8);

        let rd32 = |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().unwrap());
        let rd64 = |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().unwrap());
        assert_eq!(rd32(OFF_MAGIC), BOOTINFO_MAGIC);
        assert_eq!(rd32(OFF_VERSION), BOOTINFO_VERSION_V1);
        assert_eq!(rd32(OFF_DEBUG_EP), debug_ep);
        assert_eq!(rd32(OFF_FACTORY), factory);
        assert_eq!(rd32(OFF_REGION_COUNT), 1);
        assert_eq!(rd32(OFF_SELF_AS), self_as);
        assert_eq!(rd32(OFF_CONSOLE_IN), console_in);
        assert_eq!(rd32(OFF_RESERVED), 0);
        assert_eq!(rd32(HEADER_LEN_V1), handle);
        assert_eq!(rd64(HEADER_LEN_V1 + 8), base);
        assert_eq!(rd64(HEADER_LEN_V1 + 16), len);
    }

    /// Layout arithmetic: a v0 header is 24 bytes, a v1 header 32, a region
    /// record 24, and the parser bound covers header plus all regions.
    #[test]
    fn length_constants_are_consistent() {
        assert_eq!(HEADER_LEN_V0, OFF_CONSOLE_IN);
        assert_eq!(HEADER_LEN_V1, OFF_RESERVED + 4);
        assert_eq!(REGION_LEN, 4 + 4 + 8 + 8);
        assert_eq!(BOOTINFO_MAX_LEN, HEADER_LEN_V1 + MAX_REGIONS * REGION_LEN);
        assert!(HEADER_LEN_V0 < HEADER_LEN_V1);
        // A v0 region start (24) would collide with the v1 console_in word:
        // that is exactly why v0 and v1 blocks cannot share a parser path
        // without the version check.
    }
}
