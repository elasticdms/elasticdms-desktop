//! The program of the extension:
//! `elasticdms.app/Contents/PlugIns/elasticdms-fileprovider.appex/Contents/MacOS/elasticdms-fileprovider`.
//!
//! There is almost nothing here, and that is deliberate. The principal class `EdmsFileProvider`
//! lives in the library so that `cargo test` can test it in the same process, and it registers
//! itself when the program is loaded (`__mod_init_func`, see `extension.rs`).
//!
//! The entry point is not `main` but Foundation's `_NSExtensionMain` (build.rs) — as with every
//! extension built by Xcode. That means: **`main` never runs in production**, and neither does
//! Rust's runtime preparation (`lang_start`). Nothing in the extension relies on it; the channel
//! to the app sets `SO_NOSIGPIPE` itself anyway (std on Apple). `main` is the fallback should the
//! program ever be linked without the switch: it then calls `NSExtensionMain` itself, with the
//! same arguments.

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{CString, c_char, c_int};
    use std::os::unix::ffi::OsStringExt;

    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        /// Foundation's entry point for extension executables (exported in Foundation.tbd,
        /// declared in no public header).
        fn NSExtensionMain(argc: c_int, argv: *const *const c_char) -> c_int;
    }

    /// Makes sure the registration has happened and hands over to Foundation; returns only at
    /// the very end.
    pub(super) fn start() -> i32 {
        edms_fileprovider::extension::place_registration_safe();
        let arguments: Vec<CString> =
            std::env::args_os().filter_map(|a| CString::new(a.into_vec()).ok()).collect();
        let mut pointers: Vec<*const c_char> = arguments.iter().map(|a| a.as_ptr()).collect();
        pointers.push(std::ptr::null());
        let count = c_int::try_from(arguments.len()).unwrap_or(c_int::MAX);
        // SAFETY: argv is a null-terminated array of valid C strings that live until
        // NSExtensionMain returns; argc counts the entries without the terminator.
        unsafe { NSExtensionMain(count, pointers.as_ptr()) }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(mac::start());
}

#[cfg(not(target_os = "macos"))]
fn main() {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "elasticdms-fileprovider is the File Provider extension for macOS and runs only there."
    );
    std::process::exit(1);
}
