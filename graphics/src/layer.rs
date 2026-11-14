//! Layer/surface abstraction over `Framebuffer` for the Phase 4 compositor.
//!
//! A `Layer` pairs a `Framebuffer` surface with a destination offset and a
//! z-order. A `Compositor` owns a stack of layers and paints them back-to-front
//! (low z first) onto a target framebuffer using source-over alpha
//! compositing (`crate::compose::compose`). Pure safe Rust, no `unsafe`, no
//! MMIO, host-testable.

use crate::compose::compose;
use crate::display::Framebuffer;

/// A single compositing layer: a surface plus where it lands on the output.
///
/// `z` orders layers during composite: lower z is painted first, so higher-z
/// layers appear on top. A hidden layer is skipped entirely.
pub struct Layer {
    surface: Framebuffer,
    x: i32,
    y: i32,
    z: u32,
    visible: bool,
}

impl Layer {
    /// Wrap `surface` at offset `(0, 0)`, z-order `0`, visible.
    pub fn new(surface: Framebuffer) -> Self {
        Self {
            surface,
            x: 0,
            y: 0,
            z: 0,
            visible: true,
        }
    }

    /// Paint at destination offset `(x, y)` (may be negative).
    pub fn position(mut self, x: i32, y: i32) -> Self {
        self.x = x;
        self.y = y;
        self
    }

    /// Set the z-order (painted back-to-front; higher z on top).
    pub fn z_order(mut self, z: u32) -> Self {
        self.z = z;
        self
    }

    /// Make the layer visible.
    pub fn show(mut self) -> Self {
        self.visible = true;
        self
    }

    /// Hide the layer (skipped during composite).
    pub fn hide(mut self) -> Self {
        self.visible = false;
        self
    }

    /// Set the destination offset.
    pub fn set_position(&mut self, x: i32, y: i32) {
        self.x = x;
        self.y = y;
    }

    /// Set the z-order.
    pub fn set_z_order(&mut self, z: u32) {
        self.z = z;
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Borrow the layer's surface.
    pub fn surface(&self) -> &Framebuffer {
        &self.surface
    }

    /// Mutably borrow the layer's surface (draw into it directly).
    pub fn surface_mut(&mut self) -> &mut Framebuffer {
        &mut self.surface
    }

    /// Destination X offset.
    pub fn x(&self) -> i32 {
        self.x
    }

    /// Destination Y offset.
    pub fn y(&self) -> i32 {
        self.y
    }

    /// Z-order.
    pub fn z(&self) -> u32 {
        self.z
    }

    /// Whether the layer is visible.
    pub fn visible(&self) -> bool {
        self.visible
    }
}

/// The compositor: paints visible layers back-to-front (low z first) onto a
/// target framebuffer using source-over alpha compositing.
pub struct Compositor {
    layers: Vec<Layer>,
}

impl Compositor {
    /// Empty compositor.
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Add a layer to the stack. Composite order is by z-order, not insertion
    /// order; layers with equal z keep insertion order (stable sort).
    pub fn add_layer(&mut self, layer: Layer) {
        self.layers.push(layer);
    }

    /// Number of layers in the stack.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Paint all visible layers back-to-front onto `dst`. Each layer's surface
    /// is blended at its destination offset; out-of-range source pixels are
    /// skipped by `compose`. Hidden layers are not painted.
    pub fn composite(&self, dst: &mut Framebuffer) {
        let mut ordered: Vec<&Layer> = self.layers.iter().collect();
        ordered.sort_by_key(|l| l.z());
        for layer in ordered {
            if !layer.visible() {
                continue;
            }
            compose(layer.surface(), dst, layer.x(), layer.y());
        }
    }
}

impl Default for Compositor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::{Pixel, PixelFormat};

    fn red_opaque(w: u32, h: u32) -> Framebuffer {
        let mut fb = Framebuffer::new(w, h, PixelFormat::Rgba8888);
        fb.fill(Pixel::rgb(255, 0, 0));
        fb
    }

    fn blue_opaque(w: u32, h: u32) -> Framebuffer {
        let mut fb = Framebuffer::new(w, h, PixelFormat::Rgba8888);
        fb.fill(Pixel::rgb(0, 0, 255));
        fb
    }

    #[test]
    fn empty_composite_is_noop() {
        let mut dst = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        dst.fill(Pixel::rgb(10, 20, 30));
        let mut c = Compositor::new();
        c.composite(&mut dst);
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(10, 20, 30)));
    }

    #[test]
    fn lower_z_painted_first_higher_z_on_top() {
        let mut dst = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut c = Compositor::new();
        c.add_layer(Layer::new(red_opaque(4, 4)).z_order(10)); // bottom
        c.add_layer(Layer::new(blue_opaque(2, 2)).z_order(20)); // top-left
        c.composite(&mut dst);
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(0, 0, 255))); // blue on top
        assert_eq!(dst.pixel(3, 3), Some(Pixel::rgb(255, 0, 0))); // red shows through
    }

    #[test]
    fn hidden_layer_is_skipped() {
        let mut dst = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut c = Compositor::new();
        c.add_layer(Layer::new(red_opaque(4, 4)).z_order(10).hide());
        c.composite(&mut dst);
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(0, 0, 0)));
    }

    #[test]
    fn equal_z_keeps_insertion_order() {
        let mut dst = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut c = Compositor::new();
        c.add_layer(Layer::new(red_opaque(2, 2)).position(0, 0).z_order(5));
        c.add_layer(Layer::new(blue_opaque(2, 2)).position(0, 0).z_order(5));
        c.composite(&mut dst);
        // Second-added (blue) painted last, on top.
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(0, 0, 255)));
    }

    #[test]
    fn negative_offset_layer_stays_in_bounds() {
        let mut dst = Framebuffer::new(4, 4, PixelFormat::Rgba8888);
        dst.fill(Pixel::rgb(0, 0, 0));
        let mut c = Compositor::new();
        c.add_layer(Layer::new(red_opaque(4, 4)).position(-2, -2));
        c.composite(&mut dst);
        // src pixels (2,2)..(4,4) overlap dst at (0,0)..(2,2).
        assert_eq!(dst.pixel(0, 0), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(dst.pixel(1, 1), Some(Pixel::rgb(255, 0, 0)));
        assert_eq!(dst.pixel(2, 2), Some(Pixel::rgb(0, 0, 0)));
        assert_eq!(dst.pixel(3, 3), Some(Pixel::rgb(0, 0, 0)));
    }
}
