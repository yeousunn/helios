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
//!    The package's optional tail is ordered
//!    `[vfs, stdin, stdout, stderr, factory]` = tail[0..=4] (constants
//!    [`PACKAGE_TAIL_*`] below); absent slots are NULL descriptors.
//!    PROCESS_SPAWN's positional input caps (vfs, stdin, stdout, stderr)
//!    map one-to-one onto tail[0..=3] and the spawner's Factory always
//!    rides at tail[4] (contract shipped by 61568a9; pinned here per the
//!    ADR-073 rule that every entry-path change updates this module first).
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
//! o 28: u32 self_thread handle (0 = none; ADR-089; formerly reserved)
//! o 32: region_count × { u32 handle; u32 reserved; u64 base; u64 len }
//! o 32 + region_count·24: u32 untyped_count; u32 reserved; then
//!                         untyped_count × { u32 handle; u32 reserved;
//!                         u64 base; u64 len }   (M1a2, root Untyped)
//! ```
//!
//! v0 readers (24-byte header, regions at 24) are rejected by the version
//! check on the userspace side; the kernel only writes v1.
//!
//! The root-Untyped section (M1a2, RFC-0001 §4.1.1) is an append-only
//! extension of the v1 block, exactly like the region records it follows:
//! the v1 header words were exhausted (o20/24/28 are all assigned), and a
//! version bump would reject every committed v1 parser (ENOSYS) and break
//! the shared boot until every reader migrated — the ADR-089 lesson ran the
//! other way. Readers that stop after the region records are unaffected
//! (trailing bytes are ignored); readers that want the handles compute the
//! section offset from the declared region_count via
//! [`off_untyped_section`].

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
/// Offset of the self_thread handle u32 (ADR-089; 0 = none). The launcher's
/// own Thread cap, so it can invoke THREAD_CREATE on itself (same-AS sibling
/// threads with RFC-0004/ADR-085 stack tops). Occupies the word reserved
/// since ADR-043; readers predating ADR-089 treat it as reserved.
pub const OFF_SELF_THREAD: usize = 28;
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
/// Maximum root Untyped handles the kernel grants; more are truncated.
pub const MAX_UNTYPED: usize = MAX_REGIONS;
/// One root-Untyped record: u32 handle, u32 reserved, u64 base, u64 len —
/// the same record shape as a region record.
pub const UNTYPED_RECORD_LEN: usize = REGION_LEN;
/// Root-Untyped section header: u32 untyped_count + u32 reserved.
pub const UNTYPED_SECTION_HEADER: usize = 8;
/// Upper bound a parser may read when it also wants the root-Untyped
/// section: the v1 block plus the section header plus all records.
pub const BOOTINFO_MAX_LEN_V2: usize =
    BOOTINFO_MAX_LEN + UNTYPED_SECTION_HEADER + MAX_UNTYPED * UNTYPED_RECORD_LEN;

/// Offset of the root-Untyped section in a block that declares
/// `region_count` region records: immediately after those records.
/// The returned offset plus [`UNTYPED_SECTION_HEADER`] is 8-aligned, so
/// the records' u64 fields need no padding at any region_count.
pub const fn off_untyped_section(region_count: usize) -> usize {
    HEADER_LEN_V1 + region_count * REGION_LEN
}

/// ADR-009 bootstrap package: fixed prefix caps
/// (aspace, thread, region, 4 session notifications, ps service endpoint).
pub const PACKAGE_FIXED_CAPS: usize = 8;
/// Tail slot 0: the VFS service endpoint the SPAWN caller supplied (or, for
/// directly launched servers, the launcher's extra cap — the console's
/// kernel debug endpoint).
pub const PACKAGE_TAIL_VFS: usize = 0;
/// Tail slot 1: stdin (stream endpoint; NULL = none).
pub const PACKAGE_TAIL_STDIN: usize = 1;
/// Tail slot 2: stdout (console endpoint; NULL = none).
pub const PACKAGE_TAIL_STDOUT: usize = 2;
/// Tail slot 3: stderr / the ADR-048 auth endpoint for `/login` (NULL = none).
pub const PACKAGE_TAIL_STDERR: usize = 3;
/// Tail slot 4: the spawner's FACTORY capability (`Rights::ALL`) — every
/// spawned process can spawn further processes (attack mode, shells).
pub const PACKAGE_TAIL_FACTORY: usize = 4;
/// Tail slots a receiver materializes; [5..8) are reserved and absent.
pub const PACKAGE_OPTIONAL_SLOTS: usize = 8;
/// Upper bound on total package caps (fixed + tail) a deliverer may send:
/// `deliver` fails ETOOBIG and a receiver fails EBADARG outside this range.
pub const PACKAGE_MAX_CAPS: usize = 16;

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
        let self_thread: u32 = 13;
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
        put(OFF_SELF_THREAD, self_thread as u64, 4);
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
        assert_eq!(
            rd32(OFF_SELF_THREAD),
            self_thread,
            "self_thread at o28 (ADR-089)"
        );
        assert_eq!(rd32(HEADER_LEN_V1), handle);
        assert_eq!(rd64(HEADER_LEN_V1 + 8), base);
        assert_eq!(rd64(HEADER_LEN_V1 + 16), len);
    }

    /// Layout arithmetic: a v0 header is 24 bytes, a v1 header 32, a region
    /// record 24, and the parser bound covers header plus all regions.
    #[test]
    fn length_constants_are_consistent() {
        assert_eq!(HEADER_LEN_V0, OFF_CONSOLE_IN);
        assert_eq!(HEADER_LEN_V1, OFF_SELF_THREAD + 4);
        assert_eq!(REGION_LEN, 4 + 4 + 8 + 8);
        assert_eq!(BOOTINFO_MAX_LEN, HEADER_LEN_V1 + MAX_REGIONS * REGION_LEN);
        assert!(HEADER_LEN_V0 < HEADER_LEN_V1);
        // A v0 region start (24) would collide with the v1 console_in word:
        // that is exactly why v0 and v1 blocks cannot share a parser path
        // without the version check.
    }

    /// M1a2: the root-Untyped section sits immediately after the region
    /// records, carries its own count, and reuses the region record shape.
    #[test]
    fn root_untyped_section_layout_matches_a_written_block() {
        let region_count = 2usize;
        let untypeds: [(u32, u64, u64); 2] = [
            (21, 0x100_0000, 0xF00_0000),
            (22, 0x1_0000_0000, 0x4000_0000),
        ];
        let untyped_count = untypeds.len();

        let mut block = [0u8; BOOTINFO_MAX_LEN_V2];
        let mut put = |off: usize, v: u64, n: usize| {
            for i in 0..n {
                block[off + i] = ((v >> (i * 8)) & 0xFF) as u8;
            }
        };
        put(OFF_MAGIC, BOOTINFO_MAGIC as u64, 4);
        put(OFF_VERSION, BOOTINFO_VERSION_V1 as u64, 4);
        put(OFF_REGION_COUNT, region_count as u64, 4);
        let sec = off_untyped_section(region_count);
        put(sec, untyped_count as u64, 4);
        for (i, &(handle, base, len)) in untypeds.iter().enumerate() {
            let off = sec + UNTYPED_SECTION_HEADER + i * UNTYPED_RECORD_LEN;
            put(off, handle as u64, 4);
            put(off + 8, base, 8);
            put(off + 16, len, 8);
        }

        let rd32 = |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().unwrap());
        let rd64 = |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().unwrap());
        assert_eq!(rd32(sec), untyped_count as u32);
        // The section offset after the declared regions; the u64 fields are
        // 8-aligned for every region_count (24-record + 8-byte header).
        assert_eq!(sec, HEADER_LEN_V1 + region_count * REGION_LEN);
        assert_eq!((sec + UNTYPED_SECTION_HEADER) % 8, 0);
        assert_eq!(rd64(sec + UNTYPED_SECTION_HEADER + 8), 0x100_0000);
        let rec1 = sec + UNTYPED_SECTION_HEADER + UNTYPED_RECORD_LEN;
        assert_eq!(rd32(rec1), 22);
        assert_eq!(rd64(rec1 + 16), 0x4000_0000);
    }

    /// M1a2 arithmetic: the section bound extends (never shrinks) the v1
    /// parser bound, the record shape matches the regions', and the bound
    /// covers count + header + a full MAX_UNTYPED record set.
    #[test]
    fn root_untyped_constants_are_consistent() {
        assert_eq!(UNTYPED_RECORD_LEN, REGION_LEN, "same record shape");
        assert_eq!(UNTYPED_RECORD_LEN, 4 + 4 + 8 + 8);
        assert!(BOOTINFO_MAX_LEN_V2 > BOOTINFO_MAX_LEN);
        assert_eq!(
            BOOTINFO_MAX_LEN_V2,
            BOOTINFO_MAX_LEN + UNTYPED_SECTION_HEADER + MAX_UNTYPED * UNTYPED_RECORD_LEN
        );
        // Section offset is monotone in region_count and lands right after
        // the last region record.
        for n in 0..=MAX_REGIONS {
            assert_eq!(off_untyped_section(n), HEADER_LEN_V1 + n * REGION_LEN);
            if n > 0 {
                assert!(off_untyped_section(n) > off_untyped_section(n - 1));
            }
        }
        // A maximal block never exceeds the extended bound.
        assert!(
            off_untyped_section(MAX_REGIONS)
                + UNTYPED_SECTION_HEADER
                + MAX_UNTYPED * UNTYPED_RECORD_LEN
                <= BOOTINFO_MAX_LEN_V2
        );
    }

    /// ADR-009 package arithmetic: the 8-cap fixed prefix, five defined tail
    /// slots in the shipped order (vfs, stdin, stdout, stderr, factory), the
    /// reserved remainder of the 8 materialized tail slots, and the 16-cap
    /// package ceiling.
    #[test]
    fn package_tail_constants_are_consistent() {
        // Fixed prefix: aspace + thread + region + 4 sessions + ps ep.
        assert_eq!(PACKAGE_FIXED_CAPS, 3 + 4 + 1);
        // Tail order is dense from 0 and the factory is last.
        let order = [
            PACKAGE_TAIL_VFS,
            PACKAGE_TAIL_STDIN,
            PACKAGE_TAIL_STDOUT,
            PACKAGE_TAIL_STDERR,
            PACKAGE_TAIL_FACTORY,
        ];
        for (i, slot) in order.iter().enumerate() {
            assert_eq!(*slot, i, "tail slot {i} drifted");
        }
        // Reserved tail slots exist above the factory.
        assert!(PACKAGE_TAIL_FACTORY + 1 < PACKAGE_OPTIONAL_SLOTS);
        // Package ceiling covers fixed prefix plus all tail slots.
        assert_eq!(
            PACKAGE_MAX_CAPS,
            PACKAGE_FIXED_CAPS + PACKAGE_OPTIONAL_SLOTS
        );
    }

    /// PROCESS_SPAWN's positional input caps (design §2.6: vfs, stdin,
    /// stdout, stderr at descriptors 0..=3) land on the same tail slots, and
    /// the spawner's Factory rides at tail[4] — the mapping the process
    /// server (writer) and the personality (readers) must agree on.
    #[test]
    fn spawn_descriptors_map_onto_tail_slots() {
        let spawn_order = [
            PACKAGE_TAIL_VFS,
            PACKAGE_TAIL_STDIN,
            PACKAGE_TAIL_STDOUT,
            PACKAGE_TAIL_STDERR,
        ];
        for (descriptor, slot) in spawn_order.iter().enumerate() {
            assert_eq!(
                *slot, descriptor,
                "spawn descriptor {descriptor} left the tail order"
            );
        }
        assert_eq!(PACKAGE_TAIL_FACTORY, PACKAGE_TAIL_STDERR + 1);
    }
}
