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
//! o 20: u32 reserved
//! o 24: region_count × { u32 handle; u32 reserved; u64 base; u64 len }
//! ```

use ipc::status;

/// "HELI" little-endian.
pub const MAGIC: u32 = 0x4845_4C49;
pub const VERSION: u32 = 0;
pub const MAX_REGIONS: usize = 8;
/// Header size in bytes.
pub const HEADER_LEN: usize = 24;
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
        if bytes.len() < HEADER_LEN {
            return Err(status::EBADARG);
        }
        if rd32(bytes, 0) != MAGIC {
            return Err(status::EBADARG);
        }
        let version = rd32(bytes, 4);
        if version != VERSION {
            return Err(status::ENOSYS);
        }
        let region_count = rd32(bytes, 16);
        if region_count as usize > MAX_REGIONS {
            return Err(status::EBADARG);
        }
        let need = HEADER_LEN + region_count as usize * REGION_LEN;
        if bytes.len() < need {
            return Err(status::EBADARG);
        }
        let mut regions = [None; MAX_REGIONS];
        for (i, slot) in regions.iter_mut().enumerate().take(region_count as usize) {
            let off = HEADER_LEN + i * REGION_LEN;
            *slot = Some(BootRegion {
                handle: rd32(bytes, off),
                base: rd64(bytes, off + 8),
                len: rd64(bytes, off + 16),
            });
        }
        Ok(Self {
            debug_ep: rd32(bytes, 8),
            factory: rd32(bytes, 12),
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

    /// Mirror of the kernel writer (ADR-018), built by hand so either side
    /// drifting from the documented layout breaks exactly one test.
    fn encode(info: &BootInfo) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&info.debug_ep.to_le_bytes());
        out.extend_from_slice(&info.factory.to_le_bytes());
        out.extend_from_slice(&info.region_count.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
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
            regions,
            region_count: 2,
        }
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
        assert_eq!(rd32(&bytes, 8), 2, "debug_ep at o8");
        assert_eq!(rd32(&bytes, 12), 3, "factory at o12");
        assert_eq!(rd32(&bytes, 24), 4, "first region handle at o24");
        assert_eq!(rd64(&bytes, 32), 0x10_0000, "first region base at o32");
        assert_eq!(rd64(&bytes, 40), 0x40_0000, "first region len at o40");
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        assert_eq!(BootInfo::parse(&[]), Err(status::EBADARG));
        assert_eq!(BootInfo::parse(&[0u8; 23]), Err(status::EBADARG));

        let mut wrong_magic = encode(&sample());
        wrong_magic[0] ^= 0xFF;
        assert_eq!(BootInfo::parse(&wrong_magic), Err(status::EBADARG));

        let mut wrong_version = encode(&sample());
        wrong_version[4] = 1;
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
