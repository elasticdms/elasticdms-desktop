//! Links the program `elasticdms-fileprovider` as an extension executable.
//!
//! A .appex is an ordinary Mach-O executable (`MH_EXECUTE`) whose entry point is not `main` but
//! Foundation's `_NSExtensionMain` — for the product type `app-extension` Xcode sets exactly
//! `LD_ENTRY_POINT = _NSExtensionMain` and `APPLICATION_EXTENSION_API_ONLY`
//! (DarwinProductTypes.xcspec, ADR-D05). Both stand here, and **only for this one program**: the
//! same switches given through `RUSTFLAGS` also hit the build scripts of every dependency, which
//! then abort during the build with "An XPC Service cannot be run directly." (measured).
//!
//! The target is read from `CARGO_CFG_TARGET_OS`, not from `cfg!`: the build script runs on the
//! build machine, and `cargo xwin check` for Windows must not get a Mach-O switch.
//!
//! **Measured, so that nobody goes looking for it:** `-application_extension` does *not* set
//! `APP_EXTENSION_SAFE` in the Mach-O header of the finished program (`otool -hv`, macOS 26.6).
//! That is not a bug and nothing to fix — Apple's own `PhotosFileProvider.appex` does not carry
//! the flag either, and PlugInKit does not look for it. The switch acts at link time, not in the
//! header; the proof of what actually matters is what `scripts/macos-bundle.sh check` does on the
//! entry point.

#![allow(
    clippy::print_stdout,
    reason = "Cargo reads the directives of a build script from its standard output."
)]

/// Name of the program in Cargo.toml; the switch applies only to this one.
const PROGRAM: &str = "elasticdms-fileprovider";

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        println!("cargo::rustc-link-arg-bin={PROGRAM}=-Wl,-e,_NSExtensionMain");
        println!("cargo::rustc-link-arg-bin={PROGRAM}=-Wl,-application_extension");
    }
}
