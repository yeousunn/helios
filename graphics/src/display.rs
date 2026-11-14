//! A host-testable framebuffer/scanout primitive — the Phase 4 compositor
//! base (follow-up to the virtio-gpu driver, ADR-052 capability model).
//!
//! A `Framebuffer` owns a pixel buffer (width × height) in a documented
//! pixel format. It is deliberately pure safe Rust with bounds-checked
//! pixel access: no MMIO, no raw pointers, no `unsafe`. A real display
//! server (virtio-gpu-backed or otherwise) presents its scanout memory as
//! a `Framebuffer` view; compositors draw into it and the driver flushes.
//!
//! `#![no_std]`, `alloc` only. Host unit tests exercise bounds checking,
//! format strides, fill, and pixel read/write round-trips.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

/// A pixel format describing how pixels are laid out in the framebuffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PixelFormat {
    /// 8-bit grayscale, one byte per pixel.
    #[default]
    Gray8,
    /// 24-bit RGB, three bytes per pixel in R, G, B order.
    Rgb888,
    /// 32-bit RGBA, four bytes per pixel in R, G, B, A order.
    Rgba8888,
}

impl PixelFormat {
    /// Bytes per pixel for this format.
    pub const fn bytes_per_pixel(self) -> usize {
        match self {
            PixelFormat::Gray8 => 1,
            PixelFormat::Rgb888 => 3,
            PixelFormat::Rgba8888 => 4,
        }
    }
}

/// A single pixel, stored in a canonical R, G, B, A form.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pixel {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Pixel {
    /// Opaque RGB pixel.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 0xFF }
    }

    /// Opaque grayscale pixel.
    pub const fn gray(v: u8) -> Self {
        Self {
            r: v,
            g: v,
            b: v,
            a: 0xFF,
        }
    }

    /// Transparent black.
    pub const fn transparent() -> Self {
        Self {
            r: 0,
            g: 0,
            b: 0,
            a: 0,
        }
    }
}

/// A mutable framebuffer scanout: `width × height` pixels in `format`.
///
/// Pixel `(x, y)` lives at byte offset `(y * stride + x) * bpp` where
/// `stride == width` (tightly packed, no row padding). All access is
/// bounds-checked; out-of-range coordinates are silently ignored (write)
/// or return `None` (read), so a compositor never panics on a bad rect.
pub struct Framebuffer {
    width: u32,
    height: u32,
    format: PixelFormat,
    buf: Vec<u8>,
}

impl Framebuffer {
    /// Create a tight-packed `width × height` framebuffer in `format`,
    /// filled with transparent black.
    pub fn new(width: u32, height: u32, format: PixelFormat) -> Self {
        let bpp = format.bytes_per_pixel();
        Self {
            width,
            height,
            format,
            buf: vec![0; (width as usize) * (height as usize) * bpp],
        }
    }

    /// Framebuffer width in pixels.
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Framebuffer height in pixels.
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// The pixel format in use.
    pub const fn format(&self) -> PixelFormat {
        self.format
    }

    /// Bytes per pixel for the configured format.
    pub const fn bytes_per_pixel(&self) -> usize {
        self.format.bytes_per_pixel()
    }

    /// Stride in bytes (tightly packed: `width * bpp`).
    pub const fn stride_bytes(&self) -> usize {
        (self.width as usize) * self.format.bytes_per_pixel()
    }

    /// Total buffer size in bytes.
    pub const fn byte_len(&self) -> usize {
        self.buf.len()
    }

    /// Byte offset of pixel `(x, y)`, or `None` if out of range.
    fn offset(&self, x: u32, y: u32) -> Option<usize> {
        let bpp = self.format.bytes_per_pixel();
        if x >= self.width || y >= self.height {
            return None;
        }
        Some((y as usize) * (self.width as usize) * bpp + (x as usize) * bpp)
    }

    /// Read pixel `(x, y)`. Returns `None` when out of range.
    pub fn pixel(&self, x: u32, y: u32) -> Option<Pixel> {
        let off = self.offset(x, y)?;
        Some(match self.format {
            PixelFormat::Gray8 => {
                let v = self.buf[off];
                Pixel::gray(v)
            }
            PixelFormat::Rgb888 => Pixel::rgb(self.buf[off], self.buf[off + 1], self.buf[off + 2]),
            PixelFormat::Rgba8888 => Pixel {
                r: self.buf[off],
                g: self.buf[off + 1],
                b: self.buf[off + 2],
                a: self.buf[off + 3],
            },
        })
    }

    /// Write pixel `(x, y)`. No-op when out of range.
    pub fn write_pixel(&mut self, x: u32, y: u32, p: Pixel) {
        let Some(off) = self.offset(x, y) else {
            return;
        };
        match self.format {
            PixelFormat::Gray8 => {
                self.buf[off] = p.r;
            }
            PixelFormat::Rgb888 => {
                self.buf[off] = p.r;
                self.buf[off + 1] = p.g;
                self.buf[off + 2] = p.b;
            }
            PixelFormat::Rgba8888 => {
                self.buf[off] = p.r;
                self.buf[off + 1] = p.g;
                self.buf[off + 2] = p.b;
                self.buf[off + 3] = p.a;
            }
        }
    }

    /// Fill the entire framebuffer with `p`.
    pub fn fill(&mut self, p: Pixel) {
        let bpp = self.format.bytes_per_pixel();
        let width = self.width as usize;
        let height = self.height as usize;
        match self.format {
            PixelFormat::Gray8 => {
                for byte in self.buf.iter_mut() {
                    *byte = p.r;
                }
            }
            PixelFormat::Rgb888 => {
                for row in 0..height {
                    let base = row * width * bpp;
                    for col in 0..width {
                        let off = base + col * bpp;
                        self.buf[off] = p.r;
                        self.buf[off + 1] = p.g;
                        self.buf[off + 2] = p.b;
                    }
                }
            }
            PixelFormat::Rgba8888 => {
                for row in 0..height {
                    let base = row * width * bpp;
                    for col in 0..width {
                        let off = base + col * bpp;
                        self.buf[off] = p.r;
                        self.buf[off + 1] = p.g;
                        self.buf[off + 2] = p.b;
                        self.buf[off + 3] = p.a;
                    }
                }
            }
        }
    }

    /// Borrow the raw byte slice (tightly packed, row-major).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for Framebuffer {
    fn default() -> Self {
        Self::new(0, 0, PixelFormat::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_per_pixel() {
        assert_eq!(PixelFormat::Gray8.bytes_per_pixel(), 1);
        assert_eq!(PixelFormat::Rgb888.bytes_per_pixel(), 3);
        assert_eq!(PixelFormat::Rgba8888.bytes_per_pixel(), 4);
    }

    #[test]
    fn new_dims_and_stride() {
        let fb = Framebuffer::new(4, 3, PixelFormat::Rgba8888);
        assert_eq!(fb.width(), 4);
        assert_eq!(fb.height(), 3);
        assert_eq!(fb.stride_bytes(), 16);
        assert_eq!(fb.byte_len(), 48);
        assert_eq!(fb.as_bytes().len(), 48);
    }

    #[test]
    fn pixel_read_write_round_trip() {
        let mut fb = Framebuffer::new(2, 2, PixelFormat::Rgba8888);
        fb.write_pixel(0, 0, Pixel::rgb(10, 20, 30));
        fb.write_pixel(1, 1, Pixel::rgb(255, 0, 128));
        assert_eq!(fb.pixel(0, 0), Some(Pixel::rgb(10, 20, 30)));
        assert_eq!(fb.pixel(1, 1), Some(Pixel::rgb(255, 0, 128)));
        // Unwritten pixels are transparent black.
        assert_eq!(fb.pixel(0, 1), Some(Pixel::transparent()));
    }

    #[test]
    fn out_of_range_is_silent() {
        let mut fb = Framebuffer::new(2, 2, PixelFormat::Rgb888);
        // Writes past the edge are no-ops (no panic).
        fb.write_pixel(2, 0, Pixel::rgb(1, 2, 3));
        fb.write_pixel(0, 2, Pixel::rgb(1, 2, 3));
        fb.write_pixel(99, 99, Pixel::rgb(1, 2, 3));
        assert_eq!(fb.pixel(2, 0), None);
        assert_eq!(fb.pixel(0, 2), None);
        assert_eq!(fb.pixel(99, 99), None);
        // In-range pixels are untouched (Rgb888 has no alpha -> opaque black).
        assert_eq!(fb.pixel(0, 0), Some(Pixel::rgb(0, 0, 0)));
    }

    #[test]
    fn fill_rgba_and_gray8() {
        let mut fb = Framebuffer::new(3, 2, PixelFormat::Rgba8888);
        fb.fill(Pixel::rgb(1, 2, 3));
        for y in 0..2 {
            for x in 0..3 {
                assert_eq!(fb.pixel(x, y), Some(Pixel::rgb(1, 2, 3)));
            }
        }

        let mut g = Framebuffer::new(2, 2, PixelFormat::Gray8);
        g.fill(Pixel::gray(7));
        assert_eq!(g.pixel(0, 0), Some(Pixel::gray(7)));
        assert_eq!(g.pixel(1, 1), Some(Pixel::gray(7)));
        assert_eq!(g.byte_len(), 4);
    }

    #[test]
    fn default_is_empty() {
        let fb = Framebuffer::default();
        assert_eq!(fb.width(), 0);
        assert_eq!(fb.height(), 0);
        assert_eq!(fb.byte_len(), 0);
    }
}
