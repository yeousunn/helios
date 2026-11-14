//! Widget primitives for the Phase 4 graphics toolkit.
//!
//! A `Widget` paints itself into a `Framebuffer` at its bounds. Pure safe
//! Rust, no `unsafe`, no MMIO, host-testable. A widget owns its geometry
//! and appearance; layout and child management come in a later slice.

use crate::display::{Framebuffer, Pixel};

/// A rectangle in pixel space: origin `(x, y)`, size `w × h`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    /// Right edge (exclusive).
    pub fn right(&self) -> i32 {
        self.x + self.w as i32
    }

    /// Bottom edge (exclusive).
    pub fn bottom(&self) -> i32 {
        self.y + self.h as i32
    }

    /// Whether pixel `(px, py)` lies inside this rect.
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.right() && py >= self.y && py < self.bottom()
    }

    /// The overlap of `self` and `other`, or `None` if they do not overlap.
    pub fn intersect(self, other: Rect) -> Option<Rect> {
        let x0 = self.x.max(other.x);
        let y0 = self.y.max(other.y);
        let x1 = self.right().min(other.right());
        let y1 = self.bottom().min(other.bottom());
        if x1 <= x0 || y1 <= y0 {
            return None;
        }
        Some(Rect::new(x0, y0, (x1 - x0) as u32, (y1 - y0) as u32))
    }
}

/// A widget that paints itself into a `Framebuffer`.
pub trait Widget {
    /// The widget's bounds in pixel space (may be partially off-screen).
    fn bounds(&self) -> Rect;
    /// Paint the visible portion of the widget onto `fb`.
    fn draw(&self, fb: &mut Framebuffer);
}

/// A filled rectangle of a single color, clipped to the framebuffer.
pub struct FillRect {
    pub rect: Rect,
    pub color: Pixel,
}

impl FillRect {
    pub fn new(rect: Rect, color: Pixel) -> Self {
        Self { rect, color }
    }
}

impl Widget for FillRect {
    fn bounds(&self) -> Rect {
        self.rect
    }

    fn draw(&self, fb: &mut Framebuffer) {
        let clip = Rect::new(0, 0, fb.width(), fb.height());
        let Some(vis) = self.rect.intersect(clip) else {
            return;
        };
        for y in vis.y..vis.bottom() {
            for x in vis.x..vis.right() {
                fb.write_pixel(x as u32, y as u32, self.color);
            }
        }
    }
}

/// A rectangle outline (frame) of a single color and thickness, clipped to
/// the framebuffer.
pub struct FrameRect {
    pub rect: Rect,
    pub color: Pixel,
    pub thickness: u32,
}

impl FrameRect {
    pub fn new(rect: Rect, color: Pixel) -> Self {
        Self {
            rect,
            color,
            thickness: 1,
        }
    }

    pub fn with_thickness(mut self, thickness: u32) -> Self {
        self.thickness = thickness;
        self
    }
}

impl Widget for FrameRect {
    fn bounds(&self) -> Rect {
        self.rect
    }

    fn draw(&self, fb: &mut Framebuffer) {
        let clip = Rect::new(0, 0, fb.width(), fb.height());
        let Some(vis) = self.rect.intersect(clip) else {
            return;
        };
        let t = self.thickness as i32;
        for x in vis.x..vis.right() {
            for ty in 0..t {
                let y = vis.y + ty;
                if y < vis.bottom() {
                    fb.write_pixel(x as u32, y as u32, self.color);
                }
            }
        }
        for x in vis.x..vis.right() {
            for ty in 0..t {
                let y = vis.bottom() - 1 - ty;
                if y >= vis.y {
                    fb.write_pixel(x as u32, y as u32, self.color);
                }
            }
        }
        for y in vis.y..vis.bottom() {
            for tx in 0..t {
                let x = vis.x + tx;
                if x < vis.right() {
                    fb.write_pixel(x as u32, y as u32, self.color);
                }
            }
        }
        for y in vis.y..vis.bottom() {
            for tx in 0..t {
                let x = vis.right() - 1 - tx;
                if x >= vis.x {
                    fb.write_pixel(x as u32, y as u32, self.color);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::PixelFormat;

    fn new_fb() -> Framebuffer {
        Framebuffer::new(4, 4, PixelFormat::Rgba8888)
    }

    #[test]
    fn rect_contains_and_edges() {
        let r = Rect::new(1, 1, 2, 2);
        assert_eq!(r.right(), 3);
        assert_eq!(r.bottom(), 3);
        assert!(r.contains(1, 1));
        assert!(r.contains(2, 2));
        assert!(!r.contains(0, 1));
        assert!(!r.contains(3, 3));
    }

    #[test]
    fn rect_intersect() {
        let a = Rect::new(0, 0, 4, 4);
        let b = Rect::new(2, 2, 4, 4);
        let i = a.intersect(b).unwrap();
        assert_eq!(i, Rect::new(2, 2, 2, 2));
        assert!(a.intersect(Rect::new(5, 5, 1, 1)).is_none());
    }

    #[test]
    fn fill_rect_draws_and_clips() {
        let mut fb = new_fb();
        FillRect::new(Rect::new(1, 1, 2, 2), Pixel::rgb(255, 0, 0)).draw(&mut fb);
        assert_eq!(fb.pixel(1, 1), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(fb.pixel(2, 2), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(fb.pixel(0, 0), Some(Pixel::transparent()));
        let mut fb2 = new_fb();
        FillRect::new(Rect::new(2, 2, 4, 4), Pixel::rgb(0, 255, 0)).draw(&mut fb2);
        assert_eq!(fb2.pixel(2, 2), Some(Pixel::rgb(0, 255, 0)));
        assert_eq!(fb2.pixel(3, 3), Some(Pixel::rgb(0, 255, 0)));
        assert_eq!(fb2.pixel(4, 4), None);
        assert_eq!(fb2.pixel(1, 1), Some(Pixel::transparent()));
        let mut fb3 = new_fb();
        FillRect::new(Rect::new(10, 10, 2, 2), Pixel::rgb(1, 2, 3)).draw(&mut fb3);
        assert_eq!(fb3.pixel(0, 0), Some(Pixel::transparent()));
    }

    #[test]
    fn frame_rect_draws_border() {
        let mut fb = new_fb();
        FrameRect::new(Rect::new(0, 0, 4, 4), Pixel::rgb(0, 0, 255)).draw(&mut fb);
        assert_eq!(fb.pixel(0, 0), Some(Pixel::rgb(0, 0, 255)));
        assert_eq!(fb.pixel(3, 0), Some(Pixel::rgb(0, 0, 255)));
        assert_eq!(fb.pixel(0, 3), Some(Pixel::rgb(0, 0, 255)));
        assert_eq!(fb.pixel(3, 3), Some(Pixel::rgb(0, 0, 255)));
        assert_eq!(fb.pixel(1, 1), Some(Pixel::transparent()));
    }

    #[test]
    fn widget_trait_object() {
        let mut fb = new_fb();
        let w: &dyn Widget = &FillRect::new(Rect::new(0, 0, 2, 2), Pixel::rgb(255, 255, 0));
        w.draw(&mut fb);
        assert_eq!(fb.pixel(0, 0), Some(Pixel::rgb(255, 255, 0)));
        assert_eq!(w.bounds(), Rect::new(0, 0, 2, 2));
    }
}
