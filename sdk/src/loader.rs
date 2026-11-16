//! Embedded-image loader (ADR-023): maps an ELF image into a child address
//! space from bytes living in the launcher's own image.
//!
//! Split for testability:
//! - [`plan`] — pure: turns an [`ElfImage`] into an ordered [`LoadOp`] list
//!   (page splitting, bss remainder, scratch copies). Host-tested.
//! - [`execute`] — thin: runs the ops against the ratified invokes
//!   (`Region::CARVE`, `AS::MAP` frame/ANON, `AS::UNMAP`) and copies bytes
//!   through scratch [`MappedWindow`]s. Invoke shapes are mock-tested; only
//!   the byte copies touch real memory.
//!
//! v0 constraints: `ET_EXEC`, 4 KiB pages, and segments obeying the ELF ABI's
//! `p_vaddr ≡ p_offset (mod PAGE)` congruence (linkers guarantee this; the
//! loader page-splits segments, so unaligned segment vaddrs are fine).
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use ipc::{status, CapSlot, Message};

use crate::elf::{ElfImage, ElfSegment};
use crate::methods;
use crate::syscall::{Handle, RawSyscalls, Status, Syscalls};
use crate::window::MappedWindow;

pub const PAGE: u64 = 4096;
/// Scratch mapping flags: R | W.
const SCRATCH_FLAGS: u32 = 0b011;
/// `MapFlags::ANON` (bit 4).
const FLAG_ANON: u32 = 1 << 4;

/// Which address space a mapping op targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AsChoice {
    Child,
    SelfScratch,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadOp {
    /// Carve one page from the launcher's Region (result: a frame handle).
    CarvePage,
    /// Map the most recently carved frame.
    MapFrame {
        target: AsChoice,
        vaddr: u64,
        flags: u32,
    },
    /// Copy `len` bytes from `src_off` in the image into the scratch page at
    /// `scratch_vaddr + offset`. `offset` mirrors the segment's intra-page
    /// VADDR offset on its first page (`vaddr % PAGE`); always 0 afterwards.
    Copy {
        scratch_vaddr: u64,
        offset: u32,
        src_off: u64,
        len: u32,
    },
    /// Zero `len` bytes at `offset` in the scratch page (partial-page tail).
    ZeroFill {
        scratch_vaddr: u64,
        offset: u32,
        len: u32,
    },
    /// Unmap the scratch page from the launcher's AS.
    UnmapScratch { vaddr: u64 },
    /// Zero-fill `pages` pages in the child AS (bss / stack).
    AnonMap { vaddr: u64, pages: u64, flags: u32 },
}

/// Build the op list for `image`, mapping into a child AS and using scratch
/// VAs from `scratch_base` upward.
pub fn plan(image: &ElfImage, scratch_base: u64) -> Result<Vec<LoadOp>, Status> {
    let mut ops = Vec::new();
    let mut scratch = scratch_base;
    for i in 0..image.segment_count {
        let seg = image.segment(i).ok_or(status::EBADARG)?;
        plan_segment(&seg, &mut scratch, &mut ops)?;
    }
    if ops.is_empty() {
        return Err(status::EBADARG);
    }
    Ok(ops)
}

/// Plan one PT_LOAD segment, page-splitting like a real loader. Segment
/// vaddrs are not required to be page-aligned; the ELF ABI only requires
/// `vaddr ≡ offset (mod PAGE)` so aligned pages can be backed by file bytes.
fn plan_segment(seg: &ElfSegment, scratch: &mut u64, ops: &mut Vec<LoadOp>) -> Result<(), Status> {
    if (seg.vaddr & (PAGE - 1)) != (seg.offset & (PAGE - 1)) {
        return Err(status::EBADARG);
    }
    let first_page = seg.vaddr & !(PAGE - 1);
    let intra = seg.vaddr - first_page;
    let file_pages = if seg.filesz == 0 {
        0
    } else {
        (intra + seg.filesz).div_ceil(PAGE)
    };
    let total_pages = (intra + seg.memsz).div_ceil(PAGE);

    let mut copied = 0u64;
    let mut page = 0u64;
    while page < total_pages {
        if page >= file_pages {
            ops.push(LoadOp::AnonMap {
                vaddr: first_page + page * PAGE,
                pages: total_pages - page,
                flags: seg.flags,
            });
            break;
        }
        let page_vaddr = first_page + page * PAGE;
        let copy_start = if page == 0 { intra } else { 0 };
        let want = (PAGE - copy_start).min(seg.filesz - copied);

        ops.push(LoadOp::CarvePage);
        ops.push(LoadOp::MapFrame {
            target: AsChoice::Child,
            vaddr: page_vaddr,
            flags: seg.flags,
        });
        ops.push(LoadOp::MapFrame {
            target: AsChoice::SelfScratch,
            vaddr: *scratch,
            flags: SCRATCH_FLAGS,
        });
        if copy_start > 0 {
            // Bytes before the segment start in its first page (only when the
            // link script left the page partly unused) must be zero.
            ops.push(LoadOp::ZeroFill {
                scratch_vaddr: *scratch,
                offset: 0,
                len: copy_start as u32,
            });
        }
        if want > 0 {
            ops.push(LoadOp::Copy {
                scratch_vaddr: *scratch,
                offset: copy_start as u32,
                src_off: seg.offset + copied,
                len: want as u32,
            });
            copied += want;
        }
        let used = copy_start + want;
        if used < PAGE {
            ops.push(LoadOp::ZeroFill {
                scratch_vaddr: *scratch,
                offset: used as u32,
                len: (PAGE - used) as u32,
            });
        }
        ops.push(LoadOp::UnmapScratch { vaddr: *scratch });
        *scratch += PAGE;
        page += 1;
    }
    Ok(())
}

fn invoke_map(
    sys: &mut impl Invoke,
    as_cap: Handle,
    vaddr: u64,
    flags: u32,
    frame: Option<Handle>,
) -> Result<(), Status> {
    let mut m = Message::new(methods::aspace::MAP);
    m.words[0] = vaddr;
    m.words[1] = flags as u64;
    if let Some(frame) = frame {
        m.tag = m.tag.with_caps(1);
        let mut rights = ipc::Rights::default();
        if flags & methods::map_flags::R != 0 {
            rights = rights.union(ipc::Rights::READ);
        }
        if flags & methods::map_flags::W != 0 {
            rights = rights.union(ipc::Rights::WRITE);
        }
        if flags & methods::map_flags::X != 0 {
            rights = rights.union(ipc::Rights::EXEC);
        }
        if rights.is_empty() {
            rights = ipc::Rights::READ;
        }
        let _ = m.set_descriptor(0, CapSlot::pack(frame, rights));
    }
    sys.invoke(as_cap, &m)?;
    Ok(())
}

/// Map `pages` zero-fill (ANON) pages into `as_cap` starting at `vaddr` —
/// used by the loader for bss remainders and by launchers for initial stacks.
pub fn map_anon(
    sys: &mut impl Invoke,
    as_cap: Handle,
    vaddr: u64,
    pages: u64,
    flags: u32,
) -> Result<(), Status> {
    for p in 0..pages {
        invoke_map(sys, as_cap, vaddr + p * PAGE, flags | FLAG_ANON, None)?;
    }
    Ok(())
}

/// The invoke surface the executor needs (implemented for `Syscalls`, mocked
/// in tests).
pub trait Invoke {
    fn invoke(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status>;
}

impl<R: RawSyscalls> Invoke for Syscalls<'_, R> {
    fn invoke(&mut self, cap: Handle, msg: &Message) -> Result<Message, Status> {
        Syscalls::invoke(self, cap, msg)
    }
}

/// Writes bytes into a just-mapped scratch page. The real sink goes through
/// [`MappedWindow`]; host tests use a recording sink (they cannot touch
/// fabricated VAs).
pub trait ScratchWriter {
    fn write(&mut self, scratch_va: u64, offset: u32, data: &[u8]) -> Result<(), Status>;
}

/// The production sink: a raw memory copy into our own mapped scratch page.
pub struct MemoryWriter;

impl ScratchWriter for MemoryWriter {
    fn write(&mut self, scratch_va: u64, offset: u32, data: &[u8]) -> Result<(), Status> {
        MappedWindow { va: scratch_va }.write(offset, data)
    }
}

/// Run the planned ops. `child_as` = target AS cap; `region` = frame source;
/// `self_as` = the launcher's own AS cap (scratch mappings); `image` = the
/// embedded ELF bytes the plan's `src_off`s refer to; `writer` = the scratch
/// byte sink ([`MemoryWriter`] in production).
pub fn execute(
    sys: &mut impl Invoke,
    writer: &mut impl ScratchWriter,
    ops: &[LoadOp],
    child_as: Handle,
    region: Handle,
    self_as: Handle,
    image: &[u8],
) -> Result<(), Status> {
    let mut frame: Handle = 0;
    for op in ops {
        match *op {
            LoadOp::CarvePage => {
                let mut m = Message::new(methods::region::CARVE);
                m.words[0] = PAGE;
                m.words[1] = PAGE;
                let reply = sys.invoke(region, &m)?;
                frame = reply.words[0] as Handle;
                if frame == 0 {
                    return Err(status::ENOMEM);
                }
            }
            LoadOp::MapFrame {
                target,
                vaddr,
                flags,
            } => {
                let as_cap = match target {
                    AsChoice::Child => child_as,
                    AsChoice::SelfScratch => self_as,
                };
                invoke_map(sys, as_cap, vaddr, flags, Some(frame))?;
            }
            LoadOp::Copy {
                scratch_vaddr,
                offset,
                src_off,
                len,
            } => {
                let start = src_off as usize;
                let end = start.checked_add(len as usize).ok_or(status::EBADARG)?;
                let src = image.get(start..end).ok_or(status::EBADARG)?;
                if offset as usize + src.len() > PAGE as usize {
                    return Err(status::EBADARG);
                }
                writer.write(scratch_vaddr, offset, src)?;
            }
            LoadOp::ZeroFill {
                scratch_vaddr,
                offset,
                len,
            } => {
                let zeros = [0u8; PAGE as usize];
                let len = len as usize;
                if offset as usize + len > PAGE as usize {
                    return Err(status::EBADARG);
                }
                writer.write(scratch_vaddr, offset, &zeros[..len])?;
            }
            LoadOp::UnmapScratch { vaddr } => {
                let mut m = Message::new(methods::aspace::UNMAP);
                m.words[0] = vaddr;
                sys.invoke(self_as, &m)?;
            }
            LoadOp::AnonMap {
                vaddr,
                pages,
                flags,
            } => {
                map_anon(sys, child_as, vaddr, pages, flags)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfImage;
    use crate::syscall::{number, SysReply};
    use std::vec;
    use std::vec::Vec;

    /// Build a synthetic ELF the way the elf tests do (kept local).
    fn build_elf(segments: &[(u32, u64, u64, u64, u64)], entry: u64) -> Vec<u8> {
        const EHDR: usize = 64;
        const PHDR: usize = 56;
        let mut total = EHDR + segments.len() * PHDR + 64;
        for &(_, offset, _, filesz, _) in segments {
            total = total.max((offset + filesz) as usize);
        }
        let mut b = vec![0u8; total];
        b[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes());
        b[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes());
        b[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for (i, &(flags, offset, vaddr, filesz, memsz)) in segments.iter().enumerate() {
            let ph = EHDR + i * PHDR;
            b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            b[ph + 4..ph + 8].copy_from_slice(&flags.to_le_bytes());
            b[ph + 8..ph + 16].copy_from_slice(&offset.to_le_bytes());
            b[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
            b[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
            b[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        }
        b
    }

    #[test]
    fn plan_splits_pages_and_zero_fills_partial_tail() {
        // 0x1800 filesz (1.5 pages), 0x2000 memsz (2 pages): 2 file pages +
        // partial-page tail zero-fill, no bss remainder.
        let img = build_elf(&[(5, 0, 0x10_0000, 0x1800, 0x2000)], 0x10_0000);
        let elf = ElfImage::parse(&img).unwrap();
        let ops = plan(&elf, 0x7000).unwrap();

        assert_eq!(ops[0], LoadOp::CarvePage);
        assert_eq!(
            ops[1],
            LoadOp::MapFrame {
                target: AsChoice::Child,
                vaddr: 0x10_0000,
                flags: 5
            }
        );
        assert_eq!(
            ops[2],
            LoadOp::MapFrame {
                target: AsChoice::SelfScratch,
                vaddr: 0x7000,
                flags: SCRATCH_FLAGS
            }
        );
        assert_eq!(
            ops[3],
            LoadOp::Copy {
                scratch_vaddr: 0x7000,
                offset: 0,
                src_off: 0,
                len: 4096
            }
        );
        // Page 2 begins at +4096 with 0x800 bytes copied and 0x800 zeroed.
        let page2 = ops
            .iter()
            .position(|op| {
                matches!(
                    op,
                    LoadOp::MapFrame {
                        target: AsChoice::Child,
                        vaddr: 0x10_1000,
                        ..
                    }
                )
            })
            .unwrap();
        assert_eq!(
            ops[page2 + 2],
            LoadOp::Copy {
                scratch_vaddr: 0x8000,
                offset: 0,
                src_off: 0x1000,
                len: 0x800
            }
        );
        assert_eq!(
            ops[page2 + 3],
            LoadOp::ZeroFill {
                scratch_vaddr: 0x8000,
                offset: 0x800,
                len: 0x800
            }
        );

        let unmaps = ops
            .iter()
            .filter(|op| matches!(op, LoadOp::UnmapScratch { .. }))
            .count();
        assert_eq!(unmaps, 2, "one scratch unmap per file page");
        assert!(!ops.iter().any(|op| matches!(op, LoadOp::AnonMap { .. })));
    }

    #[test]
    fn plan_anon_maps_bss_remainder() {
        // 0x400 filesz, 0x2400 memsz → 1 file page + 2 anon pages (R|W).
        let img = build_elf(&[(6, 0, 0x20_0000, 0x400, 0x2400)], 0x20_0000);
        let elf = ElfImage::parse(&img).unwrap();
        let ops = plan(&elf, 0x9000).unwrap();
        assert_eq!(
            ops.last(),
            Some(&LoadOp::AnonMap {
                vaddr: 0x20_1000,
                pages: 2,
                flags: 3
            })
        );
    }

    #[test]
    fn plan_rejects_incongruent_segment() {
        // vaddr 0x10_0800 with file offset 0 violates vaddr ≡ offset (mod 4096).
        let img = build_elf(&[(5, 0, 0x10_0800, 0x100, 0x100)], 0x10_0800);
        let elf = ElfImage::parse(&img).unwrap();
        assert_eq!(plan(&elf, 0x7000), Err(status::EBADARG));
    }

    #[test]
    fn plan_handles_congruent_unaligned_segments() {
        // Typical rust-lld layout: vaddr 0x201540, offset 0x540.
        let img = build_elf(&[(5, 0x540, 0x201_540, 0x116f, 0x1200)], 0x201_540);
        let elf = ElfImage::parse(&img).unwrap();
        let ops = plan(&elf, 0x7000).unwrap();

        // First page maps at 0x201000; zero-fill before the segment start,
        // then copy the leading chunk from file offset 0x540.
        assert_eq!(
            ops[0..3],
            [
                LoadOp::CarvePage,
                LoadOp::MapFrame {
                    target: AsChoice::Child,
                    vaddr: 0x201_000,
                    flags: 5
                },
                LoadOp::MapFrame {
                    target: AsChoice::SelfScratch,
                    vaddr: 0x7000,
                    flags: SCRATCH_FLAGS
                },
            ]
        );
        assert!(ops.contains(&LoadOp::ZeroFill {
            scratch_vaddr: 0x7000,
            offset: 0,
            len: 0x540
        }));
        // First page of a segment with intra-page offset 0x540: the bytes
        // land at scratch offset 0x540 (regression: used to copy at 0).
        assert!(ops.contains(&LoadOp::Copy {
            scratch_vaddr: 0x7000,
            offset: 0x540,
            src_off: 0x540,
            len: 0x1000 - 0x540
        }));
        // The segment's bytes are contiguous in the image: page 1 copies from
        // file offset 0x1000 (= 0x540 + 0xAC0 copied on page 0), 0x6AF bytes,
        // and zero-fills the rest of the page.
        assert!(ops.iter().any(|op| matches!(
            op,
            LoadOp::Copy {
                offset: 0,
                src_off: 0x1000,
                len: 0x6AF,
                scratch_vaddr: 0x8000
            }
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            LoadOp::ZeroFill {
                scratch_vaddr: 0x8000,
                offset: 0x6AF,
                len: 0x951
            }
        )));
    }

    #[test]
    fn execute_emits_the_expected_invoke_sequence() {
        #[derive(Default)]
        struct MockRaw {
            calls: Vec<(u32, [u64; 6])>,
            next_frame: u32,
        }
        impl RawSyscalls for MockRaw {
            fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
                self.calls.push((number, args));
                self.next_frame += 1;
                SysReply {
                    status: status::OK,
                    words: [self.next_frame as u64, 0, 0, 0],
                    ..Default::default()
                }
            }
        }

        // A tiny image: one full page, plus 1 anon page.
        let img = build_elf(&[(5, 0, 0x10_0000, 0x1000, 0x2000)], 0x10_0000);
        let elf = ElfImage::parse(&img).unwrap();
        let ops = plan(&elf, 0x7000).unwrap();

        #[derive(Default)]
        struct RecordingWriter {
            writes: Vec<(u64, u32, usize)>,
        }
        impl ScratchWriter for RecordingWriter {
            fn write(&mut self, scratch_va: u64, offset: u32, data: &[u8]) -> Result<(), Status> {
                self.writes.push((scratch_va, offset, data.len()));
                Ok(())
            }
        }

        let mut writer = RecordingWriter::default();
        let mut raw = MockRaw::default();
        {
            let mut sys = Syscalls::new(&mut raw);
            execute(&mut sys, &mut writer, &ops, 3, 4, 9, &img).unwrap();
        }
        assert_eq!(
            writer.writes,
            vec![(0x7000, 0, 0x1000)],
            "one full-page copy"
        );

        let kinds: Vec<(u32, u16)> = raw
            .calls
            .iter()
            .map(|(num, args)| (*num, *args.get(1).unwrap_or(&0) as u16))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (number::INVOKE, methods::region::CARVE),
                (number::INVOKE, methods::aspace::MAP), // child
                (number::INVOKE, methods::aspace::MAP), // self scratch
                (number::INVOKE, methods::aspace::UNMAP),
                (number::INVOKE, methods::aspace::MAP), // anon page
            ]
        );
        // Child map flags preserved; anon page carries ANON.
        let child_map = &raw.calls[1];
        assert_eq!(child_map.1[0], 3, "child AS cap");
        assert_eq!(child_map.1[2], 0x10_0000, "vaddr");
        assert_eq!(child_map.1[3], 5, "segment flags");
        let anon_map = raw.calls.last().unwrap();
        assert_eq!(anon_map.1[2], 0x10_1000, "bss vaddr");
        assert_eq!(anon_map.1[3], 5 | FLAG_ANON as u64);
        assert_eq!(anon_map.1[4], 0, "no frame descriptor for ANON");
        // Scratch map uses R|W on the launcher AS.
        let scratch_map = &raw.calls[2];
        assert_eq!(scratch_map.1[0], 9, "self AS cap");
        assert_eq!(scratch_map.1[3], SCRATCH_FLAGS as u64);
        assert_eq!(scratch_map.1[5] as u32, 1, "carved frame descriptor");
    }
}
