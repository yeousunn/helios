//! Window frame mapping and byte access (design doc §1.3; ADR-021).
//!
//! v0: a window is exactly **one 4 KiB frame** — the kernel's `AddressSpace::MAP`
//! is page-granular. Servers lazily map window frames into their own address
//! space at server-specific VA bases ([`crate::layout`]) on first access and
//! cache the mapping.
//!
//! Safety model: [`WindowMapper`] is the only producer of [`MappedWindow`],
//! and it performs the `AS::MAP` invoke before handing one out. The byte
//! access methods use safe wrappers from `crate::sys` for raw pointer access.
#![forbid(unsafe_code)]

use alloc::vec;
use alloc::vec::Vec;

use ipc::{status, CapSlot, Message};

use crate::methods;
use crate::sys::{raw_copy_from_va, raw_copy_to_va};
use crate::syscall::{Handle, RawSyscalls, Status, Syscalls};

/// v0 window size: one frame / one page.
pub const WINDOW_SIZE: u32 = 4096;

/// Mapping flags for a server-read (argument) window: `MapFlags::R`.
pub const FLAG_READ: u32 = 1 << 0;
/// Mapping flags for a server-write (result) window: `MapFlags::W`.
pub const FLAG_WRITE: u32 = 1 << 1;

/// A live window mapping in the current address space. Constructible by
/// [`WindowMapper`] — and by SDK-internal code that has just performed the
/// mapping invoke itself (the loader's scratch copies); the field is
/// `pub(crate)` so external crates cannot fabricate one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MappedWindow {
    pub(crate) va: u64,
}

impl MappedWindow {
    pub fn va(&self) -> u64 {
        self.va
    }

    /// Read `len` bytes at `offset` inside the window.
    pub fn read(&self, offset: u32, len: u32) -> Result<Vec<u8>, Status> {
        if offset + len > WINDOW_SIZE {
            return Err(status::ETOOBIG);
        }
        let mut buf = vec![0u8; len as usize];
        // SAFETY: The window VA is valid and mapped (guaranteed by WindowMapper).
        // The bounds check keeps the access inside the frame.
        raw_copy_from_va(self.va + offset as u64, &mut buf);
        Ok(buf)
    }

    /// Write `data` at `offset` inside the window.
    pub fn write(&self, offset: u32, data: &[u8]) -> Result<(), Status> {
        if offset + data.len() as u32 > WINDOW_SIZE {
            return Err(status::ETOOBIG);
        }
        // SAFETY: The window VA is valid and mapped with WRITE flag (guaranteed by WindowMapper).
        // The bounds check keeps the copy inside the frame.
        raw_copy_to_va(self.va + offset as u64, data);
        Ok(())
    }
}

/// Lazily maps window frames at consecutive VAs starting at `va_base`.
pub struct WindowMapper {
    as_cap: Handle,
    next_va: u64,
    limit: u64,
    entries: Vec<(Handle, u64)>,
}

impl WindowMapper {
    /// `as_cap` must carry the MAP right (the spawn-package self-AS cap does);
    /// `max_windows * 4 KiB` of VA space is reserved from `va_base`.
    pub fn new(as_cap: Handle, va_base: u64, max_windows: usize) -> Self {
        let span = max_windows as u64 * WINDOW_SIZE as u64;
        Self {
            as_cap,
            next_va: va_base,
            limit: va_base + span,
            entries: Vec::new(),
        }
    }

    /// Return the window for `frame`, mapping it first if needed.
    pub fn window_of<R: RawSyscalls>(
        &mut self,
        sys: &mut Syscalls<R>,
        frame: Handle,
        flags: u32,
    ) -> Result<MappedWindow, Status> {
        if let Some(&(_, va)) = self.entries.iter().find(|(h, _)| *h == frame) {
            return Ok(MappedWindow { va });
        }
        if self.next_va + WINDOW_SIZE as u64 > self.limit {
            return Err(status::ENOMEM);
        }
        let va = self.next_va;

        // AS::MAP (syscall-abi §7, ADR-021): w0 = vaddr, w1 = flags,
        // caps[0] = frame (the kernel checks the frame cap's READ/WRITE/EXEC
        // bits against the flags).
        let mut m = Message::new(methods::aspace::MAP);
        m.tag = m.tag.with_caps(1);
        m.words[0] = va;
        m.words[1] = flags as u64;
        let _ = m.set_descriptor(0, CapSlot::pack(frame, ipc::Rights::READ));
        sys.invoke(self.as_cap, &m)?;

        self.entries.push((frame, va));
        self.next_va += WINDOW_SIZE as u64;
        Ok(MappedWindow { va })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::{number, SysReply};
    use std::vec;
    use std::vec::Vec as StdVec;

    #[derive(Default)]
    struct MockRaw {
        calls: StdVec<(u32, [u64; 6])>,
        fail: bool,
    }

    impl RawSyscalls for MockRaw {
        fn raw(&mut self, number: u32, args: [u64; 6]) -> SysReply {
            self.calls.push((number, args));
            SysReply {
                status: if self.fail {
                    status::ENOMEM
                } else {
                    status::OK
                },
                ..Default::default()
            }
        }
    }

    const BASE: u64 = 0x0000_4000_0000_0000;

    #[test]
    fn first_access_maps_and_later_access_caches() {
        let mut raw = MockRaw::default();
        let va;
        let va2;
        {
            let mut sys = Syscalls::new(&mut raw);
            let mut mapper = WindowMapper::new(5, BASE, 8);
            va = mapper.window_of(&mut sys, 21, FLAG_READ).unwrap().va();
            assert_eq!(va, BASE);
            let same = mapper.window_of(&mut sys, 21, FLAG_READ).unwrap();
            assert_eq!(same.va(), BASE, "cached");
            va2 = mapper.window_of(&mut sys, 22, FLAG_WRITE).unwrap().va();
        }
        assert_eq!(raw.calls.len(), 2, "one invoke for 21, one for 22");
        let (num, args) = raw.calls[0];
        assert_eq!(num, number::INVOKE);
        assert_eq!(args[0], 5, "invoke on the AS cap");
        assert_eq!(args[1] as u16, methods::aspace::MAP);
        assert_eq!(args[2], BASE, "w0 = vaddr");
        assert_eq!(args[3], FLAG_READ as u64, "w1 = flags");
        assert_eq!(args[5] as u32, 21, "caps[0] = frame handle");
        assert_eq!(va2, BASE + WINDOW_SIZE as u64);
    }

    #[test]
    fn exhaustion_returns_enomem_without_invoking() {
        let mut raw = MockRaw::default();
        {
            let mut sys = Syscalls::new(&mut raw);
            let mut mapper = WindowMapper::new(5, BASE, 1);
            mapper.window_of(&mut sys, 1, FLAG_READ).unwrap();
            assert_eq!(
                mapper.window_of(&mut sys, 2, FLAG_READ).err(),
                Some(status::ENOMEM)
            );
        }
        assert_eq!(raw.calls.len(), 1, "no invoke past the reserved span");
    }

    #[test]
    fn invoke_failure_is_propagated_and_not_cached() {
        let mut raw = MockRaw {
            fail: true,
            ..Default::default()
        };
        let mut mapper = WindowMapper::new(5, BASE, 4);
        {
            let mut sys = Syscalls::new(&mut raw);
            assert_eq!(
                mapper.window_of(&mut sys, 7, FLAG_READ).err(),
                Some(status::ENOMEM)
            );
        }
        raw.fail = false;
        {
            let mut sys = Syscalls::new(&mut raw);
            assert_eq!(mapper.window_of(&mut sys, 7, FLAG_READ).unwrap().va(), BASE);
        }
    }

    #[test]
    fn bounds_checks_reject_overlong_spans_before_touching_memory() {
        let w = MappedWindow { va: BASE };
        assert_eq!(w.read(WINDOW_SIZE, 1).err(), Some(status::ETOOBIG));
        assert_eq!(
            w.write(WINDOW_SIZE - 1, &[0u8; 2]).err(),
            Some(status::ETOOBIG)
        );
    }

    #[test]
    fn byte_access_roundtrip_over_a_real_buffer() {
        let mut buf = vec![0u8; WINDOW_SIZE as usize];
        let w = MappedWindow {
            va: buf.as_mut_ptr() as u64,
        };
        w.write(8, b"hello").unwrap();
        assert_eq!(w.read(8, 5).unwrap().as_slice(), b"hello");
        assert_eq!(w.read(0, 8).unwrap(), vec![0u8; 8]);
        assert_eq!(&buf[8..13], b"hello");
    }
}
