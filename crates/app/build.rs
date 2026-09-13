//! The icon files the two operating systems want, drawn by the same code that draws the tray icon.
//!
//! WHY A BUILD SCRIPT AND NOT TWO FILES IN THE REPOSITORY: `src/icon.rs` says it in its first line
//! — "no image file that can be missing or go stale". A checked-in `.ico` and `.icns` would be
//! exactly that: two binaries nobody can read in a review, that no test holds against the drawing,
//! and that stay as they are when the drawing changes. Here they arise from the drawing itself, on
//! every build, and there is nothing left to keep in step.
//!
//! WHAT ARISES WHERE, and why each lies where it lies:
//!
//! * `OUT_DIR/elasticdms.ico` — 16, 32, 48 and 256 px. `winresource` compiles it into a resource
//!   and links it into `elasticdms.exe`: that is the icon Explorer shows on the file, the taskbar
//!   on the running program and Alt+Tab in the switcher.
//! * `<the directory of the program>/elasticdms.ico` — the same file beside `elasticdms.exe`,
//!   because `packaging/windows/elasticdms.wxs` reads it as `$(var.BinDir)\elasticdms.ico` for
//!   `ARPPRODUCTICON`, the icon of the row in "Programs and Features". `wix build` needs a real
//!   file at a path somebody can write down, and `OUT_DIR` carries a hash in its name that changes
//!   with the crate's metadata — nobody can write that down.
//! * `<the directory of the program>/elasticdms.iconset/` — the ten PNGs macOS wants.
//!   `scripts/macos-bundle.sh` makes `elasticdms.icns` out of them with `iconutil` when it
//!   assembles the bundle. Writing the container here instead would be a second guess at a format
//!   that nobody in this repository has ever had the system read back; `iconutil` is on every Mac,
//!   checks the names and sizes, and writes what Finder reads.
//!
//! THE DIRECTORY OF THE PROGRAM IS DERIVED FROM `OUT_DIR`, and that is the one unofficial step
//! here: cargo tells a build script where its own scratch directory lies, never where the linker
//! puts the program. `OUT_DIR` is `…/<profile>/build/<crate>-<hash>/out`, and three levels up lies
//! the directory the program lands in. [`beside_the_program`] checks that shape and stops with a
//! sentence if it ever changes, instead of scattering icons into a directory nobody looks in.
//!
//! WHAT WAS MEASURED, on the development Mac, 2026-09-13: `cargo xwin check -p elasticdms
//! --target x86_64-pc-windows-msvc` writes a `resource.res` that holds four `RT_ICON`s (16, 32, 48
//! as DIB, 256 as PNG) and one `RT_GROUP_ICON` with name id 1 — the lowest id, which is the one
//! Explorer takes as the application icon. The `.icns` that `iconutil` makes out of the iconset
//! carries all ten sizes (`ic04` … `ic14`).
//!
//! WHAT IS NOT PROVEN: no Windows has seen any of this. The resource is compiled here but never
//! linked into an `.exe` here, and nobody has watched Explorer draw it.

// A build script speaks to cargo over its standard output; `cargo::rerun-if-changed` and
// `cargo::warning` are that protocol and not console output. The workspace forbids `print_stdout`
// for the crates whose output a user reads — this is not one of them.
#![allow(clippy::print_stdout)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Stands in for `crate::display::Status`, which `src/icon.rs` reads for
/// [`icon::IconState::from_status`].
///
/// The drawing is included here as a module (`#[path]` below), and a module carries its `use`
/// lines with it. The real [`Status`](display::Status) hangs off the user interface — over
/// `edms_core`, `edms_i18n` and the whole log — and none of that has any business in a build
/// script that draws a sheet with three lines.
///
/// THE PRICE, named: this is a second copy of a list of states. It cannot go wrong quietly. A
/// variant that is renamed, added or removed in `src/display.rs` makes the `match` in
/// `IconState::from_status` non-exhaustive or name something that is not there — and this file
/// then fails to compile, before anything is built.
mod display {
    /// The states of the session, as far as the icon has to know them.
    ///
    /// `dead_code`: nothing here ever builds a `Status`. The variants exist so that the `match` in
    /// the included drawing resolves — that is the whole point of this stand-in.
    #[allow(dead_code)]
    #[derive(Clone, Copy)]
    pub enum Status {
        /// Nobody is signed in.
        NotSignedIn,
        /// Registered, not yet approved.
        AwaitingApproval,
        /// Signed in and connected.
        SignedIn,
        /// The session has expired.
        LoginRequired,
        /// The server is not reachable.
        Offline,
        /// A signature or key problem.
        SecurityWarning,
    }
}

// `dead_code`: the build script uses `draw`, and of the states only `Normal`. Everything else in
// that file belongs to the running application — the tray sizes, the three other states, the
// exclamation mark. Without this the whole file would have to be cut in two to keep
// `-D warnings` green, and the drawing would then live in two places.
#[allow(dead_code)]
#[path = "src/icon.rs"]
mod icon;

use icon::{IconState, IconStyle, Image, draw};

/// The sizes in the `.ico`.
///
/// 16 for the title bar and the details view, 32 for the desktop and the taskbar at 100 %, 48 for
/// Explorer's "medium icons" AND for the row in Programs and Features, 256 for the large views and
/// for the tile the installer extracts. Whoever leaves 48 out gets a 32 blown up to 48 there,
/// which is the blurred icon one sees in half of all MSIs.
const ICO_SIZES: [u32; 4] = [16, 32, 48, 256];

/// The ten images of an `.iconset`, grouped by the pixel size they share.
///
/// A name says how large the icon is in POINTS, the suffix at how many pixels per point. A 16 pt
/// icon on a Retina screen and a 32 pt icon on an old one are therefore the same 32 pixels — but
/// both names have to be there, or `iconutil` leaves the corresponding size out of the container
/// and macOS scales a neighbour.
const ICONSET: [(u32, &[&str]); 7] = [
    (16, &["icon_16x16.png"]),
    (32, &["icon_16x16@2x.png", "icon_32x32.png"]),
    (64, &["icon_32x32@2x.png"]),
    (128, &["icon_128x128.png"]),
    (256, &["icon_128x128@2x.png", "icon_256x256.png"]),
    (512, &["icon_256x256@2x.png", "icon_512x512.png"]),
    (1024, &["icon_512x512@2x.png"]),
];

/// The style of every file this script writes: [`IconStyle::Colour`].
///
/// NOT `Template`, although this is macOS as well: a template image is one that the system colours
/// itself, and it does that only where it is USED as one — `with_icon_as_template` in the menu bar.
/// Finder, the Dock, the installer and "Programs and Features" colour nothing; there a template
/// would be a black sheet on a black dog-ear.
const STYLE: IconStyle = IconStyle::Colour;

/// The state of every file this script writes: [`IconState::Normal`], no dot.
///
/// The dot is the state of the SESSION, and a file on the disk has no session. It belongs on the
/// tray icon, which the running application draws afresh on every change.
const STATE: IconState = IconState::Normal;

fn main() -> Result<(), Box<dyn Error>> {
    // Without these two lines the icons would be redrawn on every build (a second on the 1024 px
    // image alone), and with only the first one a change to this file would not take effect.
    println!("cargo::rerun-if-changed=src/icon.rs");
    println!("cargo::rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    // The target's operating system, not this machine's: whoever builds for Windows on a Mac
    // (`cargo xwin`) needs the `.ico`, and nothing else.
    match std::env::var("CARGO_CFG_TARGET_OS")?.as_str() {
        "windows" => windows_icon(&out_dir)?,
        "macos" => macos_iconset(&out_dir)?,
        // Linux has neither a bundle nor a resource section; there is nothing to write there, and
        // an error would stop a `cargo check` that has nothing to do with icons.
        _ => {}
    }
    Ok(())
}

/// Writes the `.ico` and embeds it in the program.
fn windows_icon(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    let file = out_dir.join("elasticdms.ico");
    fs::write(&file, ico()?)?;

    // The second copy, for `wix build`. It lies beside the program because that is the one
    // directory the packaging script already knows by name (`$BinDirectory` in
    // scripts/windows-package.ps1, `$(var.BinDir)` in elasticdms.wxs).
    fs::copy(&file, beside_the_program(out_dir)?.join("elasticdms.ico"))?;

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(file.to_str().ok_or("the path of the .ico is not valid UTF-8")?);
    match resource.compile() {
        Ok(()) => Ok(()),
        // On Windows the resource compiler comes with the Windows SDK, and the program that goes
        // out to customers is built there (.github/workflows/release.yml, job "Windows .msi"). A
        // failure there is a program without an icon and has to stop the build.
        Err(reason) if cfg!(windows) => Err(Box::new(reason)),
        // Cross-compiling from a Mac or from Linux, `winresource` calls `llvm-rc`, and no Rust
        // toolchain brings that. MEASURED on the development Mac: under `make windows`
        // (cargo xwin check) it IS there — cargo-xwin puts an llvm-rc in front of the build
        // script, and the resource compiles, group icon and all. With a bare PATH it is not, and
        // then this is a warning and not an error: the Windows layer has to stay checkable on a
        // machine with no LLVM, and the .exe that would be missing its icon is one nobody
        // delivers. The .ico itself is written either way, so the MSI keeps its icon.
        Err(reason) => {
            println!(
                "cargo::warning=The icon was not compiled into elasticdms.exe: {reason}. On a \
                 non-Windows machine winresource needs llvm-rc (brew install llvm). The packages \
                 from .github/workflows are built on Windows and are not affected."
            );
            Ok(())
        }
    }
}

/// Writes the ten PNGs of the `.iconset`; `scripts/macos-bundle.sh` makes the `.icns` from them.
fn macos_iconset(out_dir: &Path) -> Result<(), Box<dyn Error>> {
    let folder = beside_the_program(out_dir)?.join("elasticdms.iconset");
    fs::create_dir_all(&folder)?;
    for (size, names) in ICONSET {
        let image = draw(size, STYLE, STATE);
        for name in names {
            write_png(&folder.join(name), &image)?;
        }
    }
    Ok(())
}

/// The directory the linker puts `elasticdms.exe` (or `elasticdms`) into.
///
/// `OUT_DIR` is `<target directory>/[<triple>/]<profile>/build/<crate>-<hash>/out`, and the
/// program lands three levels above it. Cargo gives a build script no other way to learn that
/// directory, and both packaging scripts need one file from it.
///
/// The shape is checked rather than assumed. If cargo ever lays its scratch directories out
/// differently, this stops with a sentence — instead of writing an icon into a directory nobody
/// reads, which the packaging would only notice as a missing file much later.
fn beside_the_program(out_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let build = out_dir.parent().and_then(Path::parent);
    let profile = build.and_then(Path::parent);
    let shape_is_right = out_dir.file_name().is_some_and(|name| name == "out")
        && build.and_then(Path::file_name).is_some_and(|name| name == "build");
    match profile {
        Some(directory) if shape_is_right => Ok(directory.to_path_buf()),
        _ => Err(format!(
            "OUT_DIR is “{}”; expected was “…/<profile>/build/<crate>-<hash>/out”. The icon is \
             written beside the program, and where that lies can only be read off OUT_DIR.",
            out_dir.display()
        )
        .into()),
    }
}

/// Packs the drawings into an `.ico`.
///
/// The format is a table of contents and a heap of images, each one either a DIB or a whole PNG
/// file. Which of the two is chosen per size stands at [`dib`] and [`png`].
fn ico() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut images = Vec::new();
    for size in ICO_SIZES {
        let drawing = draw(size, STYLE, STATE);
        images.push(if size >= 256 { png(&drawing)? } else { dib(&drawing) });
    }

    let mut out = Vec::new();
    out.extend_from_slice(&0_u16.to_le_bytes()); // reserved, always 0
    out.extend_from_slice(&1_u16.to_le_bytes()); // 1 = icon (2 would be a mouse pointer)
    out.extend_from_slice(&(ICO_SIZES.len() as u16).to_le_bytes());

    // Every entry is 16 bytes; the images follow after the whole table.
    let mut offset = 6 + 16 * ICO_SIZES.len();
    for (size, image) in ICO_SIZES.iter().zip(&images) {
        // Width and height are ONE byte each, and 256 does not fit into one: 0 means 256. An
        // entry that wrote 255 here would be an icon of the wrong size, not an error.
        let edge = if *size >= 256 { 0 } else { *size as u8 };
        out.push(edge);
        out.push(edge);
        out.push(0); // colours in the palette; 0 = no palette
        out.push(0); // reserved
        out.extend_from_slice(&1_u16.to_le_bytes()); // colour planes
        out.extend_from_slice(&32_u16.to_le_bytes()); // bits per pixel
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += image.len();
    }
    for image in images {
        out.extend_from_slice(&image);
    }
    Ok(out)
}

/// One image of the `.ico` as a DIB — the shape the format was built around.
///
/// WHY NOT PNG FOR THESE SIZES TOO: a PNG inside an `.ico` is read from Windows Vista on, and it
/// is the usual choice for 256 px, where a DIB would be a quarter of a megabyte. Below that every
/// icon editor writes a DIB, and that is the shape no reader anywhere has to be assumed about.
///
/// MEASURED once, with a foreign reader (Pillow 11.1.0) rather than with this code: the 32 px DIB
/// out of the finished `.ico` decodes pixel for pixel to the same image as the 32 px PNG of the
/// `.iconset`. That is what catches the two mistakes this function invites — rows the wrong way up
/// and red and blue swapped — because both would survive a round trip through my own code.
/// NOT MEASURED: no Windows has read the file.
///
/// Two peculiarities of the format, both of which produce a wrong picture rather than an error:
/// the height in the header counts the image TWICE (colours and mask lie one above the other), and
/// the rows run from the bottom up.
fn dib(image: &Image) -> Vec<u8> {
    let (width, height) = (image.width, image.height);
    // The mask is one bit per pixel, and every row is padded to four bytes.
    let mask_row = width.div_ceil(32) as usize * 4;

    let mut out =
        Vec::with_capacity(40 + (width * height * 4) as usize + mask_row * height as usize);
    out.extend_from_slice(&40_u32.to_le_bytes()); // size of this header
    out.extend_from_slice(&(width as i32).to_le_bytes());
    out.extend_from_slice(&((height * 2) as i32).to_le_bytes()); // colours AND mask
    out.extend_from_slice(&1_u16.to_le_bytes()); // colour planes
    out.extend_from_slice(&32_u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&0_u32.to_le_bytes()); // BI_RGB, uncompressed
    out.extend_from_slice(&0_u32.to_le_bytes()); // size of the image; 0 is allowed for BI_RGB
    for _ in 0..4 {
        // resolution in pixels per metre and the two palette counts — none of them mean anything
        // for a 32-bit icon.
        out.extend_from_slice(&0_u32.to_le_bytes());
    }

    // The colours, bottom row first, blue before green before red.
    for y in (0..height).rev() {
        for x in 0..width {
            let at = ((y * width + x) * 4) as usize;
            let pixel = &image.rgba[at..at + 4];
            out.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
        }
    }

    // The mask from the days before there was an alpha channel: a set bit means "let the
    // background through". Windows reads the alpha channel of a 32-bit icon, but the mask is part
    // of the format and is what some older paths in the shell fall back on.
    for y in (0..height).rev() {
        let mut row = vec![0_u8; mask_row];
        for x in 0..width {
            let alpha = image.rgba[((y * width + x) * 4 + 3) as usize];
            if alpha == 0 {
                row[(x / 8) as usize] |= 0x80 >> (x % 8);
            }
        }
        out.extend_from_slice(&row);
    }
    out
}

/// One drawing as PNG bytes.
fn png(image: &Image) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, image.width, image.height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(&image.rgba)?;
    writer.finish()?;
    Ok(out)
}

/// One drawing as a PNG file.
fn write_png(path: &Path, image: &Image) -> Result<(), Box<dyn Error>> {
    fs::write(path, png(image)?)?;
    Ok(())
}
