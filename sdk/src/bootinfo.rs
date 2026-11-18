//! BootInfo v0 parser (syscall-abi §8, ADR-018): the block the kernel writes
//! into init's first stack page. The layout is pinned from both sides — the
//! kernel writer (`kernel::init::write_bootinfo`) has its own layout test and
//! this parser has a golden-bytes test mirroring the same byte map:
//!
//! ```text
//! o  0: u32 magic = "HELI"
//! o  4: u32 version = 0
//! o  8: u32 debug_ep handle
//! o 12: u32 factory handle
//! o 16: u32 region_count
//! o 20: u32 self_as handle (v0.1, ADR-023; formerly reserved — 0 = none)
//! o 24: region_count × { u32 handle; u32 reserved; u64 base; u64 len }   (v0)
//! ```
//! v1 (ADR-043, interactive-shell prerequisites; GLM kernel side 2026-11-06):
//! o 24: u32 console_in handle (0 = none) - GRANT-carrying recv cap
//! o 28: u32 reserved
//! o 32: region_count * { u32 handle; u32 reserved; u64 base; u64 len }
//! ```
//! ```
//! v1.1 (ADR-089): self_thread handle at o28 (formerly reserved), regions still at o32
//! o 28: u32 self_thread handle (0 = none) - launcher own Thread cap for THREAD_CREATE
//! o 32: region_count * { u32 handle; u32 reserved; u64 base; u64 len }
//!
//! v2 (M1a2, future): root_untyped handle(s) added per RFC-0001/ADR-064.
//! Exact layout TBD per GLM's M1a2 implementation.
//! ```
#![forbid(unsafe_code)]

use ipc::status;

/// "HELI" little-endian.
pub const MAGIC: u32 = 0x4845_4C49;
pub const VERSION_V0: u32 = 0;
pub const VERSION_V1: u32 = 1;
pub const MAX_REGIONS: usize = 8;
/// Header size in bytes: 24 for v0, 32 for v1 (console_in + reserved
/// added — ADR-043; regions start at o32).
pub const HEADER_LEN_V0: usize = 24;
/// Header size in bytes for v1: 32 (console_in + self_thread at o28;
/// regions start at o32).
pub const HEADER_LEN_V1: usize = 32;
/// Backward-compat alias (v1 header).
pub const HEADER_LEN: usize = HEADER_LEN_V1;
/// One region record in bytes.
pub const REGION_LEN: usize = 24;
/// Bytes a parser may read at most (header + all regions).
pub const MAX_LEN: usize = HEADER_LEN + MAX_REGIONS * REGION_LEN;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootRegion {
    pub handle: u32,
    pub base: u64,
    pub len: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BootInfo {
    pub debug_ep: u32,
    pub factory: u32,
    /// Capability to the caller's own address space (ADR-023; v0 images that
    /// predate the grant read as `None`).
    pub self_as: Option<u32>,
    /// Console-in endpoint handle (ADR-043; recv + GRANT — delegable as
    /// stdin). `None` for v0 images and for kernels without console input.
    pub console_in: Option<u32>,
    /// Launcher's own Thread cap handle (ADR-089; 0 = none). Allows the
    /// launcher to invoke THREAD_CREATE on itself for same-AS sibling threads.
    pub self_thread: Option<u32>,
    /// Root Untyped capability handle (M1a2, RFC-0001/ADR-064).
    /// `None` until kernel provides it (GLM M1a2).
    pub root_untyped: Option<u32>,
    pub regions: [Option<BootRegion>; MAX_REGIONS],
    pub region_count: u32,
}

fn rd32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().expect("bounds checked"))
}

fn rd64(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().expect("bounds checked"))
}

impl BootInfo {
    /// Parse a byte block. Requires at least the full declared length to be
    /// present; trailing bytes are ignored.
    pub fn parse(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() < HEADER_LEN_V0 {
            return Err(status::EBADARG);
        }
        if rd32(bytes, 0) != MAGIC {
            return Err(status::EBADARG);
        }
        let version = rd32(bytes, 4);
        // v0 (24-byte header) and v1 (32-byte header, console_in + self_thread — ADR-043/ADR-089).
        let v1 = match version {
            VERSION_V0 => false,
            VERSION_V1 => true,
            _ => return Err(status::ENOSYS),
        };
        let header_len = if v1 { HEADER_LEN_V1 } else { HEADER_LEN_V0 };
        let region_count = rd32(bytes, 16);
        if region_count as usize > MAX_REGIONS {
            return Err(status::EBADARG);
        }
        let need = header_len + region_count as usize * REGION_LEN;
        if bytes.len() < need {
            return Err(status::EBADARG);
        }
        let mut regions = [None; MAX_REGIONS];
        for (i, slot) in regions.iter_mut().enumerate().take(region_count as usize) {
            let off = header_len + i * REGION_LEN;
            *slot = Some(BootRegion {
                handle: rd32(bytes, off),
                base: rd64(bytes, off + 8),
                len: rd64(bytes, off + 16),
            });
        }
        let self_as = rd32(bytes, 20);
        let console_in = if v1 {
            (rd32(bytes, 24) != 0).then_some(rd32(bytes, 24))
        } else {
            None
        };
        let self_thread = if v1 {
            let val = rd32(bytes, 28);
            (val != 0).then_some(val)
        } else {
            None
        };
        Ok(Self {
            debug_ep: rd32(bytes, 8),
            factory: rd32(bytes, 12),
            self_as: (self_as != 0).then_some(self_as),
            console_in,
            self_thread,
            root_untyped: None,
            regions,
            region_count,
        })
    }

    /// Iterate the granted regions in order.
    pub fn region(&self, i: usize) -> Option<BootRegion> {
        self.regions.get(i).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Mirror of the kernel writer (ADR-018/ADR-089), built by hand so either
    /// side drifting from the documented layout breaks exactly one test.
    fn encode(info: &BootInfo) -> Vec<u8> {
        // v1 mirror of the kernel writer (ADR-043 + ADR-089): self_thread at o28.
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION_V1.to_le_bytes());
        out.extend_from_slice(&info.debug_ep.to_le_bytes());
        out.extend_from_slice(&info.factory.to_le_bytes());
        out.extend_from_slice(&info.region_count.to_le_bytes());
        out.extend_from_slice(&info.self_as.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&info.console_in.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&info.self_thread.unwrap_or(0).to_le_bytes());
        for r in info.regions.iter().flatten() {
            out.extend_from_slice(&r.handle.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&r.base.to_le_bytes());
            out.extend_from_slice(&r.len.to_le_bytes());
        }
        out
    }

    fn sample() -> BootInfo {
        let mut regions = [None; MAX_REGIONS];
        regions[0] = Some(BootRegion {
            handle: 4,
            base: 0x10_0000,
            len: 0x40_0000,
        });
        regions[1] = Some(BootRegion {
            handle: 5,
            base: 0x60_0000,
            len: 0x20_0000,
        });
        BootInfo {
            debug_ep: 2,
            factory: 3,
            self_as: Some(9),
            console_in: Some(7),
            self_thread: Some(13),
            root_untyped: None,
            regions,
            region_count: 2,
        }
    }

    /// A v0 image (24-byte header, no console_in) still parses; console_in
    /// reads as `None` (back-compat for pre-ADR-043 kernels).
    #[test]
    fn parses_v0_without_console_in() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION_V0.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&9u32.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0x10_0000u64.to_le_bytes());
        out.extend_from_slice(&0x40_0000u64.to_le_bytes());
        let parsed = BootInfo::parse(&out).unwrap();
        assert_eq!(parsed.debug_ep, 2);
        assert_eq!(parsed.self_as, Some(9));
        assert_eq!(parsed.console_in, None);
        assert_eq!(parsed.region(0).unwrap().base, 0x10_0000);
    }

    #[test]
    fn roundtrip_matches_documented_layout() {
        let info = sample();
        let bytes = encode(&info);
        assert_eq!(bytes.len(), HEADER_LEN + 2 * REGION_LEN);
        let parsed = BootInfo::parse(&bytes).unwrap();
        assert_eq!(parsed, info);
        assert_eq!(parsed.region(0).unwrap().base, 0x10_0000);
        assert_eq!(parsed.region(1).unwrap().handle, 5);
        assert_eq!(parsed.region(2), None);
    }

    #[test]
    fn field_offsets_are_pinned() {
        let bytes = encode(&sample());
        assert_eq!(rd32(&bytes, 0), MAGIC);
        assert_eq!(rd32(&bytes, 4), VERSION_V1);
        assert_eq!(rd32(&bytes, 8), 2, "debug_ep at o8");
        assert_eq!(rd32(&bytes, 12), 3, "factory at o12");
        assert_eq!(rd32(&bytes, 20), 9, "self_as at o20 (ADR-023)");
        assert_eq!(rd32(&bytes, 24), 7, "console_in at o24 (ADR-043)");
        assert_eq!(rd32(&bytes, 28), 13, "self_thread at o28 (ADR-089)");
        assert_eq!(rd32(&bytes, 32), 4, "first region handle at o32");
        assert_eq!(rd64(&bytes, 40), 0x10_0000, "first region base at o40");
        assert_eq!(rd64(&bytes, 48), 0x40_0000, "first region len at o48");
    }

    #[test]
    fn zero_self_as_reads_as_none_for_v0_images() {
        let mut info = sample();
        info.self_as = None;
        let parsed = BootInfo::parse(&encode(&info)).unwrap();
        assert_eq!(parsed.self_as, None);
        assert_eq!(parsed, info);
    }

    #[test]
    fn zero_self_thread_reads_as_none() {
        let mut info = sample();
        info.self_thread = None;
        let parsed = BootInfo::parse(&encode(&info)).unwrap();
        assert_eq!(parsed.self_thread, None);
        assert_eq!(parsed, info);
    }

    #[test]
    fn v0_image_reads_self_thread_as_none() {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION_V0.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&9u32.to_le_bytes());
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0x10_0000u64.to_le_bytes());
        out.extend_from_slice(&0x40_0000u64.to_le_bytes());
        let parsed = BootInfo::parse(&out).unwrap();
        assert_eq!(parsed.self_thread, None);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert_eq!(BootInfo::parse(&[]), Err(status::EBADARG));
        assert_eq!(BootInfo::parse(&[0u8; 23]), Err(status::EBADARG));

        let mut wrong_magic = encode(&sample());
        wrong_magic[0] ^= 0xFF;
        assert_eq!(BootInfo::parse(&wrong_magic), Err(status::EBADARG));

        let mut wrong_version = encode(&sample());
        wrong_version[4] = 99;
        assert_eq!(BootInfo::parse(&wrong_version), Err(status::ENOSYS));

        let mut too_many = encode(&sample());
        too_many[16] = (MAX_REGIONS + 1) as u8;
        assert_eq!(BootInfo::parse(&too_many), Err(status::EBADARG));

        let mut truncated = encode(&sample());
        truncated.truncate(HEADER_LEN + 1);
        assert_eq!(
            BootInfo::parse(&truncated),
            Err(status::EBADARG),
            "region_count promises more bytes than present"
        );
    }
}
