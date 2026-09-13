//! The principal class is registered before any Rust code touches it.
//!
//! PlugInKit resolves `NSExtensionPrincipalClass` through the Objective-C runtime **before** Rust
//! code runs; with the entry point `_NSExtensionMain` Rust's `main` never runs at all. objc2,
//! however, registers a class only on the first `ClassType::class()` — without the constructor in
//! `__mod_init_func` the system would not find the class (measured, ADR-D05).
//!
//! This test is the program in miniature: a test binary of its own that only **links** the library
//! (`extern crate … as _`) and names none of its functions — exactly like the .appex executable.
//! If `objc_getClass` finds the class, the constructor registered it at load time, and it survived
//! being linked as an rlib. That is why there is exactly one test here: a second one could call
//! `class()` before this one looks.
//!
//! The checks come in the order in which the system asks: first the class exists, then it carries
//! both protocols, then it answers every mandatory message. A missing method would otherwise only
//! show up in Finder — as an empty folder without an error message, because
//! `doesNotRecognizeSelector:` terminates the extension's process, and the system takes that for a
//! temporary crash and retries endlessly (NSFileProviderReplicatedExtension.h, "Error cases").

#![cfg(target_os = "macos")]

extern crate edms_fileprovider as _;

use objc2::runtime::{AnyClass, AnyProtocol};
use objc2::sel;

#[test]
fn the_principal_class_is_registered_at_load_time_without_rust_touching_it() {
    let class = AnyClass::get(c"EdmsFileProvider")
        .expect("objc_getClass(\"EdmsFileProvider\") is nil: the constructor did not run");
    let replicated =
        AnyProtocol::get(c"NSFileProviderReplicatedExtension").expect("protocol known");
    let enumerating = AnyProtocol::get(c"NSFileProviderEnumerating").expect("protocol known");
    assert!(class.conforms_to(replicated));
    assert!(class.conforms_to(enumerating));

    // Every message the system sends that must not go unanswered: the mandatory methods of
    // NSFileProviderReplicatedExtension together with the one from NSFileProviderEnumerating.
    let required = [
        sel!(initWithDomain:),
        sel!(invalidate),
        sel!(itemForIdentifier:request:completionHandler:),
        sel!(fetchContentsForItemWithIdentifier:version:request:completionHandler:),
        sel!(createItemBasedOnTemplate:fields:contents:options:request:completionHandler:),
        sel!(modifyItem:baseVersion:changedFields:contents:options:request:completionHandler:),
        sel!(deleteItemWithIdentifier:baseVersion:options:request:completionHandler:),
        sel!(enumeratorForContainerItemIdentifier:request:error:),
    ];
    for message in required {
        assert!(class.responds_to(message), "{message}");
    }
}
