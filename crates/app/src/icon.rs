//! The icon, drawn in code — no image file that can be missing or go stale.
//!
//! A sheet with a dog-ear and three lines, plus a dot at the bottom right for the state. Two
//! styles, because the platforms expect different things:
//!
//! * [`IconStyle::Template`] (macOS): black with coverage only. As a template image
//!   (`with_icon_as_template`) macOS colours it itself to match light and dark mode (ADR-D07).
//!   There is no colour there; the state therefore sits in the **shape**: a full dot (notice), a
//!   ring (offline), a dot with a punched-out "!" (warning).
//! * [`IconStyle::Colour`] (Windows): a blue sheet, white lines — readable on a light and on a
//!   dark taskbar. The dot is coloured as well, the shape stays the same, so that the state is
//!   recognisable without colour vision too.
//!
//! **Sharp:** horizontal and vertical edges lie on whole pixels (rounded to the grid); only
//! diagonals and circles are smoothed over 4×4 subsamples. An edge falling on half a pixel would
//! be a grey haze instead of a line at a display size of 16 px.

use serde::{Deserialize, Serialize};

use crate::display::Status;

/// Pixel size of the icon in the menu bar.
///
/// tray-icon fixes the height of the `NSImage` at 18 pt; 36 px is exactly one pixel per device
/// pixel on a Retina screen. 64 px would be scaled down to 36 and lose the edges.
#[cfg(target_os = "macos")]
pub const SIZE_TRAY: u32 = 36;
/// Pixel size of the icon in the notification area (16 px at 100 %, 32 px at 200 % scaling).
#[cfg(not(target_os = "macos"))]
pub const SIZE_TRAY: u32 = 32;

/// Pixel size of the window icon (title bar and taskbar on Windows).
pub const SIZE_WINDOW: u32 = 64;

/// The style of the tray icon on this platform.
pub const STYLE_TRAY: IconStyle =
    if cfg!(target_os = "macos") { IconStyle::Template } else { IconStyle::Colour };

/// How the icon is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconStyle {
    /// Black with coverage; macOS colours it.
    Template,
    /// Coloured, for the notification area on Windows.
    Colour,
}

/// The dot on the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IconState {
    /// No dot.
    Normal,
    /// A full dot: the user has to do something (sign in, wait for approval).
    Notice,
    /// A ring: the server is not reachable.
    Offline,
    /// A dot with a "!": security warning.
    Warning,
}

impl IconState {
    /// The dot for a session state.
    pub const fn from_status(status: Status) -> Self {
        match status {
            Status::SignedIn => Self::Normal,
            Status::NotSignedIn | Status::LoginRequired | Status::AwaitingApproval => Self::Notice,
            Status::Offline => Self::Offline,
            Status::SecurityWarning => Self::Warning,
        }
    }
}

/// A finished image: RGBA, 8 bits per channel, not premultiplied, row by row from the top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `width * height * 4` bytes.
    pub rgba: Vec<u8>,
}

type Colour = [f32; 4];

const BLACK: Colour = [0.0, 0.0, 0.0, 1.0];
const WHITE: Colour = [1.0, 1.0, 1.0, 1.0];
const BLUE: Colour = [0.122, 0.373, 0.839, 1.0];
const LIGHT_BLUE: Colour = [0.553, 0.706, 0.961, 1.0];
const AMBER: Colour = [0.949, 0.616, 0.043, 1.0];
const GREY: Colour = [0.42, 0.447, 0.502, 1.0];
const RED: Colour = [0.851, 0.188, 0.145, 1.0];

/// Draws the icon in `size × size` pixels.
pub fn draw(size: u32, style: IconStyle, state: IconState) -> Image {
    let g = Geometry::for_size(size);
    let mut l = Canvas::new(size);
    match style {
        IconStyle::Template => {
            l.fill(|x, y| g.in_leaf(x, y, 0.0) && !g.in_leaf(x, y, g.stroke), BLACK);
            l.fill(|x, y| g.in_leaf(x, y, 0.0) && g.in_dog_ear_stroke(x, y), BLACK);
            l.fill(|x, y| g.in_row(x, y), BLACK);
        }
        IconStyle::Colour => {
            l.fill(|x, y| g.in_leaf(x, y, 0.0), BLUE);
            l.fill(|x, y| g.in_leaf(x, y, 0.0) && g.in_dog_ear(x, y), LIGHT_BLUE);
            l.fill(|x, y| g.in_row(x, y), WHITE);
        }
    }
    let coloured = style == IconStyle::Colour;
    let dot = g.dot;
    match state {
        IconState::Normal => {}
        IconState::Notice => {
            l.erase_pixels(|x, y| dot.spacing(x, y) <= dot.gap);
            l.fill(|x, y| dot.spacing(x, y) <= dot.radius, if coloured { AMBER } else { BLACK });
        }
        IconState::Offline => {
            l.erase_pixels(|x, y| dot.spacing(x, y) <= dot.gap);
            l.fill(
                |x, y| {
                    let d = dot.spacing(x, y);
                    d <= dot.radius && d >= dot.radius - dot.ring
                },
                if coloured { GREY } else { BLACK },
            );
        }
        IconState::Warning => {
            l.erase_pixels(|x, y| dot.spacing(x, y) <= dot.gap);
            l.fill(|x, y| dot.spacing(x, y) <= dot.radius, if coloured { RED } else { BLACK });
            if coloured {
                l.fill(|x, y| dot.in_exclamation_mark(x, y), WHITE);
            } else {
                l.erase_pixels(|x, y| dot.in_exclamation_mark(x, y));
            }
        }
    }
    l.in_image()
}

/// The measurements, all in pixels; the sheet's edges rounded to whole pixels.
struct Geometry {
    x0: f32,
    x1: f32,
    y0: f32,
    y1: f32,
    /// Edge length of the dog-ear.
    corner: f32,
    /// Stroke width of the outline.
    stroke: f32,
    /// The three lines: (left, top, right, bottom).
    rows: [(f32, f32, f32, f32); 3],
    dot: Dot,
}

#[derive(Clone, Copy)]
struct Dot {
    mx: f32,
    my: f32,
    radius: f32,
    /// Radius of the punched-out gap around the dot.
    gap: f32,
    /// Thickness of the ring (offline).
    ring: f32,
}

impl Geometry {
    fn for_size(size: u32) -> Self {
        let s = size as f32;
        // Designed on a 16-unit grid; `r` rounds to whole pixels.
        let r = |sixteenths: f32| (sixteenths * s / 16.0).round();
        let stroke = (s * 1.5 / 16.0).round().max(1.0);
        let thickness = (s / 16.0).round().max(1.0);
        let row = |left: f32, top: f32, right: f32| {
            let o = r(top);
            (r(left), o, r(right), o + thickness)
        };
        Self {
            x0: r(3.0),
            x1: r(13.0),
            y0: r(1.0),
            y1: r(15.0),
            corner: r(4.0),
            stroke,
            rows: [row(5.5, 7.0, 10.5), row(5.5, 9.5, 10.5), row(5.5, 12.0, 8.5)],
            dot: Dot {
                mx: s * 0.75,
                my: s * 0.75,
                radius: s * 0.22,
                gap: s * 0.30,
                ring: (s * 0.075).max(1.5),
            },
        }
    }

    /// Inside the sheet, inset by `inset`; the diagonal of the dog-ear included.
    fn in_leaf(&self, x: f32, y: f32, inset: f32) -> bool {
        x >= self.x0 + inset
            && x <= self.x1 - inset
            && y >= self.y0 + inset
            && y <= self.y1 - inset
            // The diagonal from (x1 - corner, y0) to (x1, y0 + corner) is the line
            // x - y = x1 - corner - y0; inside is everything below it, offset by inset·√2.
            && x - y <= self.x1 - self.corner - self.y0 - inset * std::f32::consts::SQRT_2
    }

    /// The triangle of the dog-ear (clipped to the sheet).
    fn in_dog_ear(&self, x: f32, y: f32) -> bool {
        x >= self.x1 - self.corner && y <= self.y0 + self.corner
    }

    /// The two fold edges of the dog-ear, as strokes.
    fn in_dog_ear_stroke(&self, x: f32, y: f32) -> bool {
        let left = self.x1 - self.corner;
        let bottom = self.y0 + self.corner;
        let vertical = x >= left && x <= left + self.stroke && y <= bottom + self.stroke;
        let horizontal = y >= bottom && y <= bottom + self.stroke && x >= left;
        vertical || horizontal
    }

    fn in_row(&self, x: f32, y: f32) -> bool {
        self.rows.iter().any(|&(l, o, r, u)| x >= l && x < r && y >= o && y < u)
    }
}

impl Dot {
    fn spacing(&self, x: f32, y: f32) -> f32 {
        ((x - self.mx).powi(2) + (y - self.my).powi(2)).sqrt()
    }

    /// The "!" in the warning dot: a bar with a dot under it.
    fn in_exclamation_mark(&self, x: f32, y: f32) -> bool {
        let half = (self.radius * 0.16).max(0.75);
        let bar = (x - self.mx).abs() <= half
            && y >= self.my - self.radius * 0.62
            && y <= self.my + self.radius * 0.18;
        let speck = ((x - self.mx).powi(2) + (y - (self.my + self.radius * 0.5)).powi(2)).sqrt()
            <= half * 1.15;
        bar || speck
    }
}

/// A canvas with premultiplied colours, so that "over" and "erase" are simple.
struct Canvas {
    size: u32,
    pixel: Vec<Colour>,
}

/// Subsamples per axis for the anti-aliasing.
const SUPERSAMPLING: u32 = 4;

impl Canvas {
    fn new(size: u32) -> Self {
        Self { size, pixel: vec![[0.0; 4]; (size * size) as usize] }
    }

    /// The share of a pixel's subsamples that lie inside the shape.
    fn coverage(x: u32, y: u32, form: &impl Fn(f32, f32) -> bool) -> f32 {
        let mut hits = 0_u32;
        for i in 0..SUPERSAMPLING {
            for j in 0..SUPERSAMPLING {
                let px = x as f32 + (i as f32 + 0.5) / SUPERSAMPLING as f32;
                let py = y as f32 + (j as f32 + 0.5) / SUPERSAMPLING as f32;
                if form(px, py) {
                    hits += 1;
                }
            }
        }
        hits as f32 / (SUPERSAMPLING * SUPERSAMPLING) as f32
    }

    /// Paints `colour` over everything that lies inside the shape.
    fn fill(&mut self, form: impl Fn(f32, f32) -> bool, colour: Colour) {
        for y in 0..self.size {
            for x in 0..self.size {
                let a = Self::coverage(x, y, &form) * colour[3];
                if a == 0.0 {
                    continue;
                }
                let p = &mut self.pixel[(y * self.size + x) as usize];
                for k in 0..3 {
                    p[k] = colour[k] * a + p[k] * (1.0 - a);
                }
                p[3] = a + p[3] * (1.0 - a);
            }
        }
    }

    /// Makes transparent whatever lies inside the shape.
    fn erase_pixels(&mut self, form: impl Fn(f32, f32) -> bool) {
        for y in 0..self.size {
            for x in 0..self.size {
                let k = Self::coverage(x, y, &form);
                if k == 0.0 {
                    continue;
                }
                let p = &mut self.pixel[(y * self.size + x) as usize];
                for channel in p.iter_mut() {
                    *channel *= 1.0 - k;
                }
            }
        }
    }

    fn in_image(self) -> Image {
        let mut rgba = Vec::with_capacity(self.pixel.len() * 4);
        let byte = |value: f32| (value.clamp(0.0, 1.0) * 255.0).round() as u8;
        for p in &self.pixel {
            let a = p[3];
            if a <= 0.0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            rgba.extend_from_slice(&[byte(p[0] / a), byte(p[1] / a), byte(p[2] / a), byte(a)]);
        }
        Image { width: self.size, height: self.size, rgba }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [IconState; 4] =
        [IconState::Normal, IconState::Notice, IconState::Offline, IconState::Warning];

    fn pixel(b: &Image, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * b.width + x) * 4) as usize;
        [b.rgba[i], b.rgba[i + 1], b.rgba[i + 2], b.rgba[i + 3]]
    }

    fn dot_centre(b: &Image) -> (u32, u32) {
        let m = (b.width as f32 * 0.75) as u32;
        (m, m)
    }

    #[test]
    fn every_icon_has_the_size_it_should() {
        for size in [SIZE_TRAY, 32, 36, SIZE_WINDOW] {
            for style in [IconStyle::Template, IconStyle::Colour] {
                for state in ALL {
                    let b = draw(size, style, state);
                    assert_eq!((b.width, b.height), (size, size));
                    assert_eq!(b.rgba.len(), (size * size * 4) as usize);
                }
            }
        }
    }

    #[test]
    fn the_template_icon_is_black_with_coverage_only() {
        for state in ALL {
            let b = draw(36, IconStyle::Template, state);
            assert!(
                b.rgba.as_chunks::<4>().0.iter().all(|p| p[3] == 0 || p[..3] == [0, 0, 0]),
                "{state:?}"
            );
            assert!(
                b.rgba.as_chunks::<4>().0.iter().any(|p| p[3] == 255),
                "{state:?}: drawn empty"
            );
        }
    }

    #[test]
    fn the_sheet_edges_are_sharp() {
        // In colour the sheet is filled: nothing to the left of the edge, full coverage on it.
        for size in [32, 64] {
            let b = draw(size, IconStyle::Colour, IconState::Normal);
            let g = Geometry::for_size(size);
            let (x0, middle) = (g.x0 as u32, size / 2);
            assert_eq!(pixel(&b, x0 - 1, middle)[3], 0, "{size}px");
            assert_eq!(pixel(&b, x0, middle)[3], 255, "{size}px");
        }
    }

    #[test]
    fn the_notice_dot_appears_only_in_the_notice_state() {
        let normal = draw(32, IconStyle::Colour, IconState::Normal);
        let hint = draw(32, IconStyle::Colour, IconState::Notice);
        let (x, y) = dot_centre(&hint);
        assert_eq!(pixel(&hint, x, y), [242, 157, 11, 255], "an amber dot");
        assert_ne!(pixel(&normal, x, y), pixel(&hint, x, y));
        let template = draw(36, IconStyle::Template, IconState::Notice);
        let (x, y) = dot_centre(&template);
        assert_eq!(pixel(&template, x, y)[3], 255);
    }

    #[test]
    fn offline_is_a_ring_and_not_a_full_dot() {
        let b = draw(36, IconStyle::Template, IconState::Offline);
        let (x, y) = dot_centre(&b);
        assert_eq!(pixel(&b, x, y)[3], 0, "the middle of the ring is clear");
        let g = Geometry::for_size(36);
        let on_the_ring = (g.dot.mx + g.dot.radius - g.dot.ring / 2.0) as u32;
        assert!(pixel(&b, on_the_ring, y)[3] > 128, "the ring itself is drawn");
    }

    #[test]
    fn the_warning_has_a_punched_out_exclamation_mark() {
        let b = draw(36, IconStyle::Template, IconState::Warning);
        let g = Geometry::for_size(36);
        let p = g.dot;
        let bar = (p.mx as u32, (p.my - p.radius * 0.3) as u32);
        assert_eq!(pixel(&b, bar.0, bar.1)[3], 0, "in the bar of the \"!\" there is nothing");
        let edge = ((p.mx + p.radius * 0.7) as u32, p.my as u32);
        assert_eq!(pixel(&b, edge.0, edge.1)[3], 255, "next to the \"!\" the dot is full");
    }

    #[test]
    fn a_gap_to_the_sheet_stays_around_the_dot() {
        // Without a gap the dot would merge with the sheet into a blob at 16 px.
        let b = draw(32, IconStyle::Colour, IconState::Notice);
        let g = Geometry::for_size(32);
        let p = g.dot;
        let in_the_gap = ((p.mx - (p.radius + p.gap) / 2.0) as u32, p.my as u32);
        assert_eq!(pixel(&b, in_the_gap.0, in_the_gap.1)[3], 0);
    }

    #[test]
    fn every_status_has_its_dot() {
        assert_eq!(IconState::from_status(Status::SignedIn), IconState::Normal);
        assert_eq!(IconState::from_status(Status::AwaitingApproval), IconState::Notice);
        assert_eq!(IconState::from_status(Status::Offline), IconState::Offline);
        assert_eq!(IconState::from_status(Status::SecurityWarning), IconState::Warning);
    }
}
