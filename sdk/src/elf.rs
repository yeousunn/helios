//! Minimal ELF64 loader (v0): the bytes for the first spawned processes come
//! from images embedded in their launcher's binary, so this parses exactly
//! that: little-endian x86_64 `ET_EXEC` with `PT_LOAD` segments.
//!
//! Pure logic, fully host-testable; the frame carving/mapping that consumes
//! [`ElfImage`] lives in the launcher (process server / init) via
//! `AS::MAP` (ADR-021/022).
#![forbid(unsafe_code)]

use ipc::status;

pub const EI_NIDENT: usize = 16;
pub const EHDR_LEN: usize = 64;
pub const PHDR_LEN: usize = 56;
pub const MAX_SEGMENTS: usize = 8;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// One loadable segment, mapped into a [`MapFlags`](crate::window)-style flag
/// set (bit0 R, bit1 W, bit2 X — the servers' `MapFlags` bit layout).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ElfSegment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    /// Bit0 R, bit1 W, bit2 X.
    pub flags: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ElfImage {
    pub entry: u64,
    pub segments: [Option<ElfSegment>; MAX_SEGMENTS],
    pub segment_count: usize,
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().expect("bounds"))
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("bounds"))
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("bounds"))
}

impl ElfImage {
    pub fn parse(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() < EHDR_LEN {
            return Err(status::EBADARG);
        }
        if bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
            return Err(status::EBADARG);
        }
        if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
            return Err(status::EBADARG); // 64-bit, little-endian, v1
        }
        if rd16(bytes, 16) != ET_EXEC {
            return Err(status::EBADARG); // v0: fixed-address images only
        }
        if rd16(bytes, 18) != EM_X86_64 {
            return Err(status::EBADARG);
        }
        let entry = rd64(bytes, 24);
        let phoff = rd64(bytes, 32) as usize;
        let phentsize = rd16(bytes, 54) as usize;
        let phnum = rd16(bytes, 56) as usize;
        if phentsize != PHDR_LEN || phnum == 0 {
            return Err(status::EBADARG);
        }
        let ph_end = phoff.checked_add(phnum * PHDR_LEN).ok_or(status::EBADARG)?;
        if ph_end > bytes.len() {
            return Err(status::EBADARG);
        }

        let mut image = Self {
            entry,
            segments: [None; MAX_SEGMENTS],
            segment_count: 0,
        };
        for i in 0..phnum {
            let ph = phoff + i * PHDR_LEN;
            if rd32(bytes, ph) != PT_LOAD {
                continue;
            }
            let p_flags = rd32(bytes, ph + 4);
            let offset = rd64(bytes, ph + 8);
            let vaddr = rd64(bytes, ph + 16);
            let filesz = rd64(bytes, ph + 32);
            let memsz = rd64(bytes, ph + 40);
            if memsz < filesz || memsz == 0 {
                return Err(status::EBADARG);
            }
            if offset
                .checked_add(filesz)
                .is_none_or(|e| e > bytes.len() as u64)
            {
                return Err(status::EBADARG);
            }
            if vaddr.checked_add(memsz).is_none() {
                return Err(status::EBADARG);
            }
            if image.segment_count == MAX_SEGMENTS {
                return Err(status::ETOOBIG);
            }
            // ELF PF_* (X=1, W=2, R=4) → MapFlags bits (R=1, W=2, X=4).
            let flags = ((p_flags & PF_R) >> 2) | (p_flags & PF_W) | ((p_flags & PF_X) << 2);
            image.segments[image.segment_count] = Some(ElfSegment {
                vaddr,
                offset,
                filesz,
                memsz,
                flags,
            });
            image.segment_count += 1;
        }
        if image.segment_count == 0 {
            return Err(status::EBADARG);
        }
        Ok(image)
    }

    /// Iterate the parsed segments in order.
    pub fn segment(&self, i: usize) -> Option<ElfSegment> {
        self.segments.get(i).copied().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Build a synthetic ET_EXEC ELF64 with the given PT_LOAD segments.
    fn build(segments: &[(u32, u64, u64, u64, u64)], entry: u64) -> Vec<u8> {
        let phnum = segments.len() as u16;
        let phoff = EHDR_LEN as u64;
        let mut total = EHDR_LEN + segments.len() * PHDR_LEN + 64;
        for &(_, offset, _, filesz, _) in segments {
            total = total.max((offset + filesz) as usize);
        }
        let mut b = vec![0u8; total];
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = 2; // 64-bit
        b[5] = 1; // LE
        b[6] = 1; // version
        b[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        b[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&phoff.to_le_bytes());
        b[52..54].copy_from_slice(&(EHDR_LEN as u16).to_le_bytes());
        b[54..56].copy_from_slice(&(PHDR_LEN as u16).to_le_bytes());
        b[56..58].copy_from_slice(&phnum.to_le_bytes());
        for (i, &(flags, offset, vaddr, filesz, memsz)) in segments.iter().enumerate() {
            let ph = EHDR_LEN + i * PHDR_LEN;
            b[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
            b[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
            b[ph + 8..ph + 16].copy_from_slice(&offset.to_le_bytes());
            b[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
            b[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
            b[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_typical_text_and_data_segments() {
        // text at 0x401000 (R|X), data at 0x402000 (R|W).
        let img = build(
            &[
                (PF_R | PF_X, 0, 0x401000, 0x100, 0x100),
                (PF_R | PF_W, 0, 0x402000, 0x40, 0x80),
            ],
            0x401000,
        );
        let elf = ElfImage::parse(&img).unwrap();
        assert_eq!(elf.entry, 0x401000);
        assert_eq!(elf.segment_count, 2);

        let t = elf.segment(0).unwrap();
        assert_eq!(
            (t.vaddr, t.offset, t.filesz, t.memsz),
            (0x401000, 0, 0x100, 0x100)
        );
        assert_eq!(t.flags, 0b101, "R|X");
        let d = elf.segment(1).unwrap();
        assert_eq!(d.flags, 0b011, "R|W");
        assert_eq!(d.memsz, 0x80, "bss counted");
        assert_eq!(elf.segment(2), None);
    }

    #[test]
    fn non_load_program_headers_are_skipped() {
        let mut img = build(&[(PF_R | PF_X, 0, 0x1000, 16, 16)], 0x1000);
        // Second phdr: PT_NOTE (4) — ignored.
        let ph = EHDR_LEN + PHDR_LEN;
        img[ph..ph + 4].copy_from_slice(&4u32.to_le_bytes());
        img[56..58].copy_from_slice(&2u16.to_le_bytes());
        let elf = ElfImage::parse(&img).unwrap();
        assert_eq!(elf.segment_count, 1);
    }

    #[test]
    fn rejects_bad_headers() {
        let good = build(&[(PF_R, 0, 0x1000, 16, 16)], 0x1000);
        assert_eq!(
            ElfImage::parse(&good[..32]),
            Err(status::EBADARG),
            "too short"
        );

        let mut bad_magic = good.clone();
        bad_magic[1] = b'X';
        assert_eq!(ElfImage::parse(&bad_magic), Err(status::EBADARG));

        let mut bad_class = good.clone();
        bad_class[4] = 1;
        assert_eq!(ElfImage::parse(&bad_class), Err(status::EBADARG), "32-bit");

        let mut bad_type = good.clone();
        bad_type[16] = 3;
        assert_eq!(
            ElfImage::parse(&bad_type),
            Err(status::EBADARG),
            "ET_DYN not v0"
        );

        let mut bad_machine = good.clone();
        bad_machine[18] = 0x28; // aarch64
        assert_eq!(ElfImage::parse(&bad_machine), Err(status::EBADARG));

        let mut bad_phoff = good.clone();
        bad_phoff[32..40].copy_from_slice(&0xFFFFu64.to_le_bytes());
        assert_eq!(ElfImage::parse(&bad_phoff), Err(status::EBADARG));
    }

    #[test]
    fn rejects_bad_segments() {
        // filesz beyond the image (truncate the buffer after building it).
        let mut oob = build(&[(PF_R, 0x100, 0x1000, 0x200, 0x200)], 0x1000);
        oob.truncate(EHDR_LEN + PHDR_LEN);
        assert_eq!(ElfImage::parse(&oob), Err(status::EBADARG));

        // memsz < filesz.
        let shrink = build(&[(PF_R, 0, 0x1000, 0x100, 0x40)], 0x1000);
        assert_eq!(ElfImage::parse(&shrink), Err(status::EBADARG));

        // No loadable segments.
        let none = build(&[], 0x1000);
        assert_eq!(ElfImage::parse(&none), Err(status::EBADARG));

        // Too many segments.
        let segs = [(PF_R, 0u64, 0x1000u64, 16u64, 16u64); MAX_SEGMENTS + 1];
        let many = build(&segs, 0x1000);
        assert_eq!(ElfImage::parse(&many), Err(status::ETOOBIG));
    }
}
