//! IPC wire format v1 (ADR-005, ratified from `sdk/docs/ipc-schema.md`).
//!
//! The message is 40 bytes / 5 words so it travels in registers. Capability
//! transfer is atomic with send. This crate is the single source of truth for
//! the wire `Rights` vocabulary, label registry, and status codes.
#![no_std]
#![forbid(unsafe_code)]

pub mod flags;
pub mod labels;
pub mod status;

pub const VERSION: u16 = 0x0001;
pub const MAX_WORDS: usize = 4;
pub const NULL_HANDLE: u32 = 0;

/// Sentinel for `cap_mint`: install at the first free slot.
pub const FIRST_FREE_SLOT: u32 = 0xFFFF_FFFF;

/// Canonical capability rights vocabulary (syscall-abi §5, ADR-005).
///
/// Bit order is frozen wire format. `caps/` re-exports this type.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rights(pub u32);

impl Rights {
    pub const SEND: Rights = Rights(1 << 0);
    pub const RECV: Rights = Rights(1 << 1);
    pub const GRANT: Rights = Rights(1 << 2);
    pub const READ: Rights = Rights(1 << 3);
    pub const WRITE: Rights = Rights(1 << 4);
    pub const EXEC: Rights = Rights(1 << 5);
    pub const MAP: Rights = Rights(1 << 6);
    pub const SIGNAL: Rights = Rights(1 << 7);
    pub const ACK: Rights = Rights(1 << 8);
    pub const CONTROL: Rights = Rights(1 << 9);
    pub const REVOKE: Rights = Rights(1 << 10);

    /// Every right (freshly-minted kernel authority only).
    pub const ALL: Rights = Rights(0b111_1111_1111);

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    /// Rights present in both sets (masking on delegation).
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }

    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// One capability descriptor / result word: handle in the low 32 bits,
/// requested-or-granted rights in the high 32 (schema §3.1).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapSlot(pub u64);

impl CapSlot {
    pub const NULL: CapSlot = CapSlot(0);

    pub const fn handle(self) -> u32 {
        self.0 as u32
    }

    pub const fn rights(self) -> Rights {
        Rights((self.0 >> 32) as u32)
    }

    pub const fn pack(handle: u32, rights: Rights) -> Self {
        Self(handle as u64 | ((rights.0 as u64) << 32))
    }
}

/// Message tag (schema §4): version, reserved, flags, cap_count, label.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Tag(pub u64);

impl Tag {
    pub const fn new(label: u16) -> Self {
        Self(((VERSION as u64) << 48) | label as u64)
    }

    pub const fn version(self) -> u16 {
        (self.0 >> 48) as u16
    }

    pub const fn reserved(self) -> u16 {
        ((self.0 >> 32) & 0xFFFF) as u16
    }

    pub const fn flags(self) -> u8 {
        (self.0 >> 24) as u8
    }

    pub const fn cap_count(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn label(self) -> u16 {
        self.0 as u16
    }

    pub const fn is_valid(self) -> bool {
        self.version() == VERSION && self.reserved() == 0
    }

    pub const fn with_flags(self, f: u8) -> Self {
        Self((self.0 & !(0xFFu64 << 24)) | ((f as u64) << 24))
    }

    pub const fn with_caps(self, n: u8) -> Self {
        Self((self.0 & !(0xFFu64 << 16)) | ((n as u64) << 16))
    }
}

/// The v1 control message: tag + 4 payload words. When `cap_count = n`, the
/// last `n` words of `words` are `CapSlot` descriptors.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Message {
    pub tag: Tag,
    pub words: [u64; MAX_WORDS],
}

impl Message {
    pub const fn new(label: u16) -> Self {
        Message {
            tag: Tag::new(label),
            words: [0; MAX_WORDS],
        }
    }

    /// The `i`-th capability descriptor (counting from the first transferred
    /// cap), or `None` if out of range. Descriptors overlay the *trailing*
    /// words: with `cap_count = n`, descriptor 0 is `words[MAX_WORDS - n]`.
    pub fn descriptor(&self, i: usize) -> Option<CapSlot> {
        let n = self.tag.cap_count() as usize;
        if i >= n || n > MAX_WORDS {
            return None;
        }
        Some(CapSlot(self.words[MAX_WORDS - n + i]))
    }

    /// Overwrite the `i`-th capability descriptor.
    pub fn set_descriptor(&mut self, i: usize, slot: CapSlot) -> Option<()> {
        let n = self.tag.cap_count() as usize;
        if i >= n || n > MAX_WORDS {
            return None;
        }
        self.words[MAX_WORDS - n + i] = slot.0;
        Some(())
    }

    /// Number of capability descriptors this message carries.
    pub fn cap_count(&self) -> usize {
        (self.tag.cap_count() as usize).min(MAX_WORDS)
    }
}

const _: () = assert!(core::mem::size_of::<Message>() == 40);
const _: () = assert!(core::mem::align_of::<Message>() == 8);
const _: () = assert!(core::mem::size_of::<Tag>() == 8);
const _: () = assert!(core::mem::size_of::<CapSlot>() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_roundtrip_and_validation() {
        let t = Tag::new(0x0212);
        assert_eq!(t.label(), 0x0212);
        assert_eq!(t.version(), VERSION);
        assert_eq!(t.cap_count(), 0);
        assert!(t.is_valid());

        let t2 = t.with_caps(2).with_flags(flags::NONBLOCK);
        assert_eq!(t2.cap_count(), 2);
        assert_eq!(t2.flags(), flags::NONBLOCK);
        assert_eq!(t2.label(), 0x0212);
        assert!(t2.is_valid());

        // Corrupted reserved bits / wrong version must fail validation.
        let bad = Tag((t2.0 & !(0xFFFFu64 << 48)) | (0x0002u64 << 48));
        assert!(!bad.is_valid());
        let bad2 = Tag(t2.0 | (1u64 << 40));
        assert!(!bad2.is_valid());
    }

    #[test]
    fn capslot_packing() {
        let cs = CapSlot::pack(7, Rights::SEND.union(Rights::GRANT));
        assert_eq!(cs.handle(), 7);
        assert_eq!(cs.rights(), Rights::SEND.union(Rights::GRANT));
        assert_eq!(CapSlot::NULL.handle(), NULL_HANDLE);
        assert!(CapSlot::NULL.rights().is_empty());
    }

    #[test]
    fn descriptor_overlay_uses_trailing_words() {
        let mut m = Message::new(labels::kernel::FAULT_RESOLVE);
        m.tag = m.tag.with_caps(1);
        m.words[0] = 0x0000_7FFF_F000; // faulting vaddr
        m.words[1] = 0b011; // R|W mapping flags
        m.words[2] = 0;
        m.set_descriptor(0, CapSlot::pack(3, Rights::READ.union(Rights::MAP)))
            .unwrap();

        assert_eq!(m.cap_count(), 1);
        assert_eq!(m.descriptor(0).unwrap().handle(), 3);
        // Descriptor landed in the last word, payload words untouched.
        assert_eq!(m.words[3], m.descriptor(0).unwrap().0);
        assert_eq!(m.words[0], 0x0000_7FFF_F000);
    }

    #[test]
    fn four_caps_fill_all_words() {
        let mut m = Message::new(0x8001);
        m.tag = m.tag.with_caps(4);
        for i in 0..4 {
            m.set_descriptor(i, CapSlot::pack(i as u32 + 1, Rights::SEND))
                .unwrap();
        }
        assert_eq!(m.cap_count(), 4);
        assert_eq!(m.descriptor(0).unwrap().handle(), 1);
        assert_eq!(m.descriptor(3).unwrap().handle(), 4);
        assert!(m.descriptor(4).is_none());
        assert!(m.set_descriptor(4, CapSlot::NULL).is_none());
    }

    #[test]
    fn cap_count_over_max_is_clamped() {
        let mut m = Message::new(1);
        m.tag = m.tag.with_caps(9); // nonsense — kernel rejects, crate clamps
        assert_eq!(m.cap_count(), MAX_WORDS);
        assert!(m.descriptor(0).is_none());
    }

    #[test]
    fn layout_assertions() {
        assert_eq!(core::mem::size_of::<Message>(), 40);
        assert_eq!(core::mem::align_of::<Message>(), 8);
    }
}
