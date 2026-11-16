//! Shared bounds-checked guest memory copy type (U4c3b).
//!
//! This type provides a safe way to access guest memory ranges by recording
//! all mapped guest address ranges and validating every access against them
//! before any copy is performed. This prevents wild guest pointers from
//! reaching host memory outside the guest's mappings.
//!
//! The personality layer (linrun) uses this for Linux-ABI emulation where
//! the emulator and emulated image share an address space (v0 model).

use crate::sys::{raw_copy_from_va, raw_copy_to_va};

/// Error returned when a guest access is out of bounds.
pub const EFAULT: i64 = -14;
/// Error returned when the span table is full.
pub const ENOMEM: i64 = -12;

/// Maximum number of guest memory spans that can be tracked.
/// The emulator's guest ranges collapse to one span per region because
/// `add` merges touching ranges, so a small table is plenty.
pub const MAX_SPANS: usize = 24;

/// One mapped guest range: `[base, base + len)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuestSpan {
    pub base: u64,
    pub len: u64,
}

impl GuestSpan {
    /// The range's end (`base + len`), saturating.
    pub fn end(self) -> u64 {
        self.base.saturating_add(self.len)
    }

    /// Does `[va, va + len)` lie inside this range?
    pub fn covers(self, va: u64, len: usize) -> bool {
        match va.checked_add(len as u64) {
            Some(end) => va >= self.base && end <= self.end(),
            None => false,
        }
    }
}

/// Bounds-checked guest memory: the only way the emulator touches guest
/// addresses. `add` records a mapping; `read`/`write` reject anything
/// outside the recorded ranges with `EFAULT` before any copy.
#[derive(Clone, Debug)]
pub struct GuestMemory {
    spans: [GuestSpan; MAX_SPANS],
    len: usize,
}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestMemory {
    /// An empty guest memory: no address is accessible until a range is
    /// recorded with `add`.
    pub const fn new() -> Self {
        Self {
            spans: [GuestSpan { base: 0, len: 0 }; MAX_SPANS],
            len: 0,
        }
    }

    /// The recorded ranges, in base order.
    pub fn spans(&self) -> &[GuestSpan] {
        &self.spans[..self.len]
    }

    /// Record `[base, base + len)` as mapped guest memory, merging it with any
    /// range it touches. Returns `ENOMEM` when the span table is full or the
    /// range overflows.
    pub fn add(&mut self, base: u64, len: u64) -> Result<(), i64> {
        if len == 0 {
            return Ok(());
        }
        if base.checked_add(len).is_none() {
            return Err(ENOMEM);
        }
        if self.len >= MAX_SPANS {
            return Err(ENOMEM);
        }
        let mut pos = self.len;
        while pos > 0 && self.spans[pos - 1].base > base {
            self.spans[pos] = self.spans[pos - 1];
            pos -= 1;
        }
        self.spans[pos] = GuestSpan { base, len };
        self.len += 1;
        self.merge();
        Ok(())
    }

    /// Collapse touching or overlapping neighbours (the list is base-sorted).
    fn merge(&mut self) {
        let mut w = 0usize;
        for r in 1..self.len {
            let prev = self.spans[w];
            let next = self.spans[r];
            if next.base <= prev.end() {
                let merged = GuestSpan {
                    base: prev.base,
                    len: next.end().max(prev.end()) - prev.base,
                };
                self.spans[w] = merged;
            } else {
                w += 1;
                self.spans[w] = next;
            }
        }
        self.len = w + 1;
    }

    /// Is `[va, va + len)` inside one recorded range?
    pub fn contains(&self, va: u64, len: usize) -> bool {
        self.spans[..self.len].iter().any(|s| s.covers(va, len))
    }

    /// Read `buf.len()` bytes from guest address `va`. Rejects an address (or
    /// length) outside the recorded ranges with `EFAULT` before any copy.
    pub fn read(&self, va: u64, buf: &mut [u8]) -> Result<usize, i64> {
        if !self.contains(va, buf.len()) {
            return Err(EFAULT);
        }
        raw_copy_from_va(va, buf);
        Ok(buf.len())
    }

    /// Write `data` to guest address `va`, with the same bounds check.
    pub fn write(&self, va: u64, data: &[u8]) -> Result<usize, i64> {
        if !self.contains(va, data.len()) {
            return Err(EFAULT);
        }
        raw_copy_to_va(va, data);
        Ok(data.len())
    }

    /// Read one little-endian `u64` from guest memory.
    pub fn read_u64(&self, va: u64) -> Result<u64, i64> {
        let mut b = [0u8; 8];
        self.read(va, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Write one `u64` to guest memory (little-endian).
    pub fn write_u64(&self, va: u64, v: u64) -> Result<(), i64> {
        self.write(va, &v.to_le_bytes()).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x0000_4000_0000_0000;

    fn record(buf: &mut [u8; 4096]) -> GuestMemory {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5A;
        }
        let mut g = GuestMemory::new();
        g.add(buf.as_ptr() as u64, 4096).expect("add");
        g
    }

    #[test]
    fn read_write_roundtrip_inside_a_recorded_range() {
        let mut buf = [0u8; 4096];
        let g = record(&mut buf);
        let base = buf.as_ptr() as u64;
        assert_eq!(g.write(base + 8, b"hello"), Ok(5));
        assert_eq!(&buf[8..13], b"hello");
        let mut out = [0u8; 5];
        assert_eq!(g.read(base + 8, &mut out), Ok(5));
        assert_eq!(&out, b"hello");
        assert_eq!(g.write_u64(base + 64, 0x0123_4567_89ab_cdef), Ok(()));
        assert_eq!(g.read_u64(base + 64), Ok(0x0123_4567_89ab_cdef));
        assert_eq!(&buf[64..72], &0x0123_4567_89ab_cdefu64.to_le_bytes());
        assert_eq!(g.read(base + 4095, &mut out[..1]), Ok(1));
        assert_eq!(g.write(base + 4095, &[0u8]), Ok(1));
    }

    #[test]
    fn out_of_range_access_is_rejected_before_touching_memory() {
        let mut buf = [0u8; 4096];
        let g = record(&mut buf);
        let base = buf.as_ptr() as u64;
        let mut dst = [0xAAu8; 8];
        assert_eq!(g.read(base + 4089, &mut dst), Err(EFAULT));
        assert_eq!(dst, [0xAAu8; 8], "destination untouched");
        assert_eq!(g.read(base, &mut [0u8; 4097]), Err(EFAULT));
        assert_eq!(g.write(base + 4096, b"x"), Err(EFAULT));
        assert_eq!(g.write(0x1000, b"x"), Err(EFAULT));
        assert_eq!(g.read(0x7fff_ffff_f000, &mut dst), Err(EFAULT));
        assert_eq!(dst, [0xAAu8; 8]);
        assert_eq!(g.read_u64(base + 4089), Err(EFAULT));
        assert_eq!(g.write_u64(base + 4096, 1), Err(EFAULT));
        assert_eq!(g.read(u64::MAX - 4, &mut [0u8; 8]), Err(EFAULT));
    }

    #[test]
    fn unknown_addresses_are_inaccessible_until_added() {
        let g = GuestMemory::new();
        assert!(!g.contains(BASE, 8));
        let mut dst = [0u8; 8];
        assert_eq!(g.read(BASE, &mut dst), Err(EFAULT));
        assert_eq!(g.write(BASE, b"x"), Err(EFAULT));
        assert!(g.spans().is_empty());
    }

    #[test]
    fn add_merges_touching_and_overlapping_ranges() {
        let mut g = GuestMemory::new();
        g.add(BASE, 0x1000).unwrap();
        g.add(BASE + 0x1000, 0x1000).unwrap();
        assert_eq!(g.spans().len(), 1, "adjacent ranges merge");
        g.add(BASE + 0x800, 0x800).unwrap();
        assert_eq!(
            g.spans(),
            &[GuestSpan {
                base: BASE,
                len: 0x2000
            }]
        );
        g.add(BASE - 0x1000, 0x1000).unwrap();
        assert_eq!(
            g.spans(),
            &[GuestSpan {
                base: BASE - 0x1000,
                len: 0x3000
            }]
        );
        g.add(BASE + 0x3000, 0x1000).unwrap();
        assert_eq!(
            g.spans(),
            &[
                GuestSpan {
                    base: BASE - 0x1000,
                    len: 0x3000
                },
                GuestSpan {
                    base: BASE + 0x3000,
                    len: 0x1000
                },
            ]
        );
        assert!(g.contains(BASE - 0x1000, 0x3000), "the merged union");
        assert!(g.contains(BASE + 0x1FF8, 8), "the union's last 8 bytes");
        assert!(g.contains(BASE + 0x3000, 0x1000), "the separate range");
        assert!(g.contains(BASE + 0x3FF8, 8), "the separate last 8 bytes");
        assert!(!g.contains(BASE + 0x1FF9, 8), "straddles the union end");
        assert!(!g.contains(BASE + 0x2000, 1), "the gap itself");
        assert!(!g.contains(BASE - 0x1001, 1));
    }

    #[test]
    fn full_span_table_reports_enomem() {
        let mut g = GuestMemory::new();
        let mut va = 0x1000_0000u64;
        for _ in 0..MAX_SPANS {
            g.add(va, 0x1000).expect("span fits");
            va += 0x2000;
        }
        assert_eq!(g.add(va, 0x1000), Err(ENOMEM));
        assert_eq!(g.spans().len(), MAX_SPANS);
    }

    #[test]
    fn zero_length_access_needs_a_containing_range() {
        let mut buf = [0u8; 4096];
        let g = record(&mut buf);
        let base = buf.as_ptr() as u64;
        assert_eq!(g.read(base + 4096, &mut []), Ok(0));
        assert_eq!(g.read(base + 4095, &mut []), Ok(0));
        assert_eq!(g.write(base + 4096, &[]), Ok(0));
        assert_eq!(g.write(base + 4095, &[]), Ok(0));
        assert_eq!(g.read(base + 4097, &mut []), Err(EFAULT));
    }
}
