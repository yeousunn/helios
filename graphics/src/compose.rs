//! Source-over alpha compositing over `graphics::display::Framebuffer`.
//!
//! The first building block of the Phase 4 compositor: blend one framebuffer
//! (a surface / layer) onto another at an integer offset using straight-alpha
//! source-over (Porter-Duff). Only the overlapping region is touched; out-of
//! range source pixels are skipped and the destination is left unchanged
//! outside the overlap. Pure safe Rust, no `unsafe`, no MMIO, host-testable.

use crate::display::{Framebuffer, Pixel};

/// Blend `src` onto `dst` at destination offset `(dx, dy)` using source-over
/// alpha compositing.
///
/// Straight-alpha source-over:
///   out = src * (src.a / 255) + dst * ((255 - src.a) / 255)
///   out.a = src.a + dst.a * ((255 - src.a) / 255)
///
/// Fully opaque source (`a == 255`) overwrites; fully transparent source
/// (`a == 0`) is a no-op. Pixels of `src` that fall outside `dst`'s bounds
/// are skipped; `dst` outside the overlap is untouched.
pub fn compose(src: &Framebuffer, dst: &mut Framebuffer, dx: i32, dy: i32) {
    let sw = src.width() as i32;
    let sh = src.height() as i32;
    let dw = dst.width() as i32;
    let dh = dst.height() as i32;

    // Overlap region in source coordinates.
    let sx0 = 0i32.max(-dx);
    let sy0 = 0i32.max(-dy);
    let sx1 = sw.min(dw - dx);
    let sy1 = sh.min(dh - dy);
    if sx1 <= sx0 || sy1 <= sy0 {
        return;
    }

    for sy in sy0..sy1 {
        let dy = dy + sy;
        for sx in sx0..sx1 {
            let px = match src.pixel(sx as u32, sy as u32) {
                Some(p) => p,
                None => continue,
            };
            let Some(cur) = dst.pixel((dx + sx) as u32, dy as u32) else {
                continue;
            };
            dst.write_pixel((dx + sx) as u32, dy as u32, blend(px, cur));
        }
    }
}

/// Source-over blend of straight-alpha `src` over `dst`.
fn blend(src: Pixel, dst: Pixel) -> Pixel {
    let sa = src.a as u32;
    let inv = 255u32 - sa;
    let mul = |s: u32, d: u32| ((s * sa + d * inv) / 255) as u8;
    let a = (sa + dst.a as u32 * inv / 255) as u8;
    Pixel {
        r: mul(src.r as u32, dst.r as u32),
        g: mul(src.g as u32, dst.g as u32),
        b: mul(src.b as u32, dst.b as u32),
        a,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::display::PixelFormat;

    fn fb() -> Framebuffer {
        Framebuffer::new(4, 4, PixelFormat::Rgba8888)
    }

    #[test]
    fn transparent_src_is_noop() {
        let mut dst = fb();
        dst.fill(Pixel::rgb(10, 20, 30));
        let src = Framebuffer::new(2, 2, PixelFormat::Rgba8888);
        compose(&src, &mut dst, 0, 0);
        for y in 0..4 {
            for x in 0..4 {
                assert_eq!(dst.pixel(x, y), Some(Pixel::rgb(10, 20, 30)));
            }
        }
    }

    #[test]
    fn opaque_src_overwrites() {
        let mut dst = fb();
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut src = Framebuffer::new(2, 2, PixelFormat::Rgba8888);
        src.fill(Pixel::rgb(255, 128, 64));
        compose(&src, &mut dst, 1, 1);
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(0, 0, 0)));
        assert_eq!(dst.pixel(1, 1), Some(Pixel::rgb(255, 128, 64)));
        assert_eq!(dst.pixel(2, 1), Some(Pixel::rgb(255, 128, 64)));
        assert_eq!(dst.pixel(3, 3), Some(Pixel::rgb(0, 0, 0)));
    }

    #[test]
    fn alpha_blend_midpoint() {
        let mut dst = fb();
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut src = Framebuffer::new(1, 1, PixelFormat::Rgba8888);
        src.write_pixel(
            0,
            0,
            Pixel {
                r: 255,
                g: 0,
                b: 0,
                a: 128,
            },
        );
        compose(&src, &mut dst, 0, 0);
        // 128/255 of 255 ~ 128 on red; opaque dst makes result fully opaque.
        assert_eq!(
            dst.pixel(0, 0),
            Some(Pixel {
                r: 128,
                g: 0,
                b: 0,
                a: 255
            })
        );
    }

    #[test]
    fn partial_overlap() {
        let mut dst = fb();
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut src = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        src.fill(Pixel::rgb(255, 0, 0));
        // Place src so only its bottom-right 2x2 quadrant overlaps dst at (2,2).
        compose(&src, &mut dst, 2, 2);
        assert_eq!(dst.pixel(1, 1), Some(Pixel::rgb(0, 0, 0)));
        assert_eq!(dst.pixel(2, 2), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(dst.pixel(3, 3), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(dst.pixel(4, 4), None);
    }

    #[test]
    fn dst_outside_overlap_untouched() {
        let mut dst = fb();
        dst.fill(Pixel::rgb(7, 7, 7));
        let mut src = Framebuffer::new(1, 1, PixelFormat::Rgba8888);
        src.write_pixel(0, 0, Pixel::rgb(255, 0, 0));
        compose(&src, &mut dst, 0, 0);
        assert_eq!(dst.pixel(1, 0), Some(Pixel::rgb(7, 7, 7)));
        assert_eq!(dst.pixel(0, 1), Some(Pixel::rgb(7, 7, 7)));
        assert_eq!(dst.pixel(3, 3), Some(Pixel::rgb(7, 7, 7)));
    }
}
