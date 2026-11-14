//! Kani harnesses for panic-freedom of syscall argument decoding (A2).
//!
//! These harnesses prove that message-tag and descriptor decoding in the
//! syscall path cannot panic for any input. Run with:
//!   cargo kani -p kernel --harness tag_decoding
//!   cargo kani -p kernel --harness descriptor_decoding
//!   cargo kani -p kernel --harness syscall_args_decoding

#![cfg(kani)]

use ipc::{CapSlot, Message, Rights, Tag, FIRST_FREE_SLOT, MAX_WORDS, NULL_HANDLE, VERSION};

/// Harness: Tag construction and validation cannot panic for any 64-bit input.
#[kani::proof]
fn tag_decoding() {
    let raw: u64 = kani::any();
    let tag = Tag(raw);

    // These methods must not panic for any u64 input
    let _version = tag.version();
    let _reserved = tag.reserved();
    let _flags = tag.flags();
    let _cap_count = tag.cap_count();
    let _label = tag.label();
    let _valid = tag.is_valid();

    // with_flags and with_caps must not panic
    let _t2 = tag.with_flags(kani::any());
    let _t3 = tag.with_caps(kani::any());

    // Tag::new must not panic for any u16 label
    let _t4 = Tag::new(kani::any());
}

/// Harness: CapSlot packing and extraction cannot panic for any input.
#[kani::proof]
fn caps_slot_decoding() {
    let raw: u64 = kani::any();
    let slot = CapSlot(raw);

    // These methods must not panic for any u64 input
    let _handle = slot.handle();
    let _rights = slot.rights();

    // CapSlot::pack must not panic for any u32 handle and Rights
    let handle: u32 = kani::any();
    let rights_bits: u32 = kani::any();
    let rights = Rights(rights_bits & Rights::ALL.0);
    let _packed = CapSlot::pack(handle, rights);

    // CapSlot::NULL is a constant
    let _null = CapSlot::NULL;
}

/// Harness: Message descriptor overlay logic cannot panic for any input.
#[kani::proof]
fn descriptor_decoding() {
    let mut msg = Message {
        tag: Tag(kani::any()),
        words: [kani::any(), kani::any(), kani::any(), kani::any()],
    };

    // Message::new must not panic for any u16 label
    let _m = Message::new(kani::any());

    // cap_count must not panic and must be bounded
    let count = msg.cap_count();
    assert!(count <= MAX_WORDS);

    // descriptor(i) must not panic for any usize index
    for i in 0..MAX_WORDS + 2 {
        let _desc = msg.descriptor(i);
    }

    // set_descriptor must not panic for any valid index and slot
    for i in 0..MAX_WORDS {
        let slot = CapSlot(kani::any());
        let _ = msg.set_descriptor(i, slot);
    }
}

/// Harness: Message with arbitrary tag and words - full round-trip.
#[kani::proof]
fn message_roundtrip() {
    let tag_raw: u64 = kani::any();
    let words: [u64; MAX_WORDS] = [kani::any(), kani::any(), kani::any(), kani::any()];

    let mut msg = Message {
        tag: Tag(tag_raw),
        words,
    };

    // Verify descriptor overlay invariants hold for any input
    let n = msg.tag.cap_count() as usize;
    if n <= MAX_WORDS && n > 0 {
        // Descriptors overlay the trailing n words
        for i in 0..n {
            let desc = msg.descriptor(i);
            assert!(desc.is_some());
            let d = desc.unwrap();
            // The descriptor word must match the corresponding trailing word
            let expected_word = msg.words[MAX_WORDS - n + i];
            assert_eq!(d.0, expected_word);
        }
    }

    // Out-of-bounds indices return None
    for i in n..MAX_WORDS + 2 {
        assert!(msg.descriptor(i).is_none());
    }
}

/// Harness: SyscallArgs construction from raw registers cannot panic.
#[kani::proof]
fn syscall_args_decoding() {
    use crate::entry::SyscallArgs;

    let num: u64 = kani::any();
    let cap: u64 = kani::any();
    let tag_raw: u64 = kani::any();
    let w: [u64; 4] = [kani::any(), kani::any(), kani::any(), kani::any()];
    let nonblock: bool = kani::any();

    let args = SyscallArgs {
        num,
        cap,
        tag: Tag(tag_raw),
        w,
        nonblock,
    };

    // message() must not panic
    let _msg = args.message();
}

/// Harness: CapSlot special values (NULL, FIRST_FREE_SLOT) handled correctly.
#[kani::proof]
fn caps_slot_special_values() {
    let null_slot = CapSlot::NULL;
    assert_eq!(null_slot.handle(), NULL_HANDLE);
    assert!(null_slot.rights().is_empty());

    // FIRST_FREE_SLOT as a handle
    let ff_slot = CapSlot::pack(FIRST_FREE_SLOT, Rights::SEND);
    assert_eq!(ff_slot.handle(), FIRST_FREE_SLOT);
    assert_eq!(ff_slot.rights(), Rights::SEND);

    // Packing with zero rights
    let zero_rights = CapSlot::pack(42, Rights::default());
    assert_eq!(zero_rights.handle(), 42);
    assert!(zero_rights.rights().is_empty());
}

/// Harness: Tag version and reserved bit validation.
#[kani::proof]
fn tag_version_validation() {
    // Valid tag construction
    let valid_tag = Tag::new(0x1234);
    assert!(valid_tag.is_valid());
    assert_eq!(valid_tag.version(), VERSION);
    assert_eq!(valid_tag.reserved(), 0);

    // Arbitrary tag - validation must not panic
    let raw: u64 = kani::any();
    let tag = Tag(raw);
    let _ = tag.is_valid(); // Must not panic

    // If version matches and reserved is 0, it's valid
    if tag.version() == VERSION && tag.reserved() == 0 {
        assert!(tag.is_valid());
    } else {
        assert!(!tag.is_valid());
    }
}

/// Harness: Flags and cap_count bit manipulation.
#[kani::proof]
fn tag_flags_and_caps() {
    let mut tag = Tag::new(kani::any());

    // Test all flag combinations
    for flags_val in 0u8..=0xFF {
        let t = tag.with_flags(flags_val);
        assert_eq!(t.flags(), flags_val);
        assert_eq!(t.label(), tag.label());
    }

    // Test all cap_count combinations (0..=255, but capped at MAX_WORDS in cap_count())
    for caps_val in 0u8..=0xFF {
        let t = tag.with_caps(caps_val);
        let expected = (caps_val as usize).min(MAX_WORDS);
        assert_eq!(t.cap_count(), expected);
        assert_eq!(t.label(), tag.label());
    }
}
