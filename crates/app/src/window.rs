//! The window with the usage log — a web view with an embedded page.
//!
//! **On demand, not kept in reserve** (ADR-D07): the window is created on a click on "Open
//! elasticdms" (`menu.open`) and destroyed when it is closed; the app carries on in the icon. A
//! merely hidden window would be the worse choice on macOS — a hidden web view gets no updates
//! there any more, and "open" would then show a frozen list.
//!
//! **The page is embedded and stays that way.** Everything lies in the binary (`include_str!`),
//! the policy in the page's head permits nothing except its own style and its own script (each
//! with this start's nonce), and [`navigation_allowed`] refuses every navigation that is not the
//! first. That is not caution on suspicion: document titles from the archive stand in this list.
//! If the page were allowed to load anything, a title like `<img src=https://foreign/…>` would be
//! a channel carrying case file (Akte) names out of a GoBD archive — out of exactly the window
//! that was built for transparency.
//!
//! **One catalogue, not two.** The page carries key paths (`data-text="window.list.title"`) and
//! no sentences; [`page`] puts the whole catalogue in as JSON, and the script fills the page from
//! it. Otherwise there would be a German HTML file next to a German TOML file, and the second one
//! would be translated while the first stayed behind.
//!
//! **Two directions, both typed** ([`crate::message`]): the page sends
//! `window.ipc.postMessage(JSON)`, the app answers with `evaluate_script("window.receive(…)")`.
//! The IPC call does not run into the control flow immediately but goes back into the event loop
//! through the [`EventLoopProxy`]: otherwise a click on the page would run into the middle of
//! another call and would need a second lock.

use std::hash::{BuildHasher, Hasher, RandomState};

use edms_i18n::Catalog;
use tao::dpi::LogicalSize;
use tao::event_loop::{EventLoopProxy, EventLoopWindowTarget};
use tao::window::{Window as TaoWindow, WindowBuilder, WindowId};
use wry::{WebView, WebViewBuilder};

use crate::icon::{self, IconState, IconStyle, SIZE_WINDOW};
use crate::message::{MessageError, Notice};

/// The title of the window.
pub const TITLE: &str = "elasticdms";

const WIDTH: f64 = 840.0;
const HEIGHT: f64 = 640.0;
const MIN_WIDTH: f64 = 460.0;
const MIN_HEIGHT: f64 = 360.0;

const TEMPLATE: &str = include_str!("view/view.html");
const STYLE: &str = include_str!("view/view.css");
const SCRIPT: &str = include_str!("view/view.js");

/// The set-up wizard's page for switching the extension on — **macOS, and nowhere else**.
///
/// ADR-D13 §10: behind a `cfg`, not behind a runtime `if`. On Windows this markup is not in the
/// binary; the document then carries no element with `data-page="extension"`, the step list
/// view.js reads out of the document cannot contain it, and the wizard's Back and Next — which
/// are indices into that list — have no index that reaches it. A page that exists but never
/// shows is a page a wrong index can reach.
#[cfg(target_os = "macos")]
const EXTENSION: &str = include_str!("view/extension.html");
/// Nothing, on every platform whose folder needs no switching on.
#[cfg(not(target_os = "macos"))]
const EXTENSION: &str = "";

/// Where the mirror lies — **Windows, and nowhere else**, for the same reason and the mirror
/// image of it: outside the Windows branch `platform.rs` reads `let _ = mirror_path;`, so the
/// field would be a question whose answer is thrown away (ADR-D13, measurement 5).
#[cfg(target_os = "windows")]
const MIRROR: &str = include_str!("view/mirror.html");
/// Nothing, where the root is named by the operating system.
#[cfg(not(target_os = "windows"))]
const MIRROR: &str = "";

/// The window could not be built or could not be supplied.
///
/// Diagnostic only: none of these three reaches a user as a sentence. Without a window the app
/// stays usable at the icon, and the reason belongs in the log (`event_loop::show_window`).
#[derive(Debug, thiserror::Error)]
pub enum WindowError {
    /// The operating system did not hand out a window.
    #[error("the window could not be opened: {0}")]
    Window(#[from] tao::error::OsError),
    /// The web view could not be set up (on Windows WebView2 is usually missing).
    #[error(
        "the web view could not be set up: {0}. On Windows elasticdms needs Microsoft's WebView2 \
         runtime"
    )]
    Webview(#[from] wry::Error),
    /// A message could not be delivered.
    #[error("the message to the window could not be delivered: {0}")]
    Notice(#[from] MessageError),
}

/// An open window together with its web view.
pub struct Window {
    window: TaoWindow,
    view: WebView,
    /// Only once the page has reported `ready` does `window.receive` exist.
    ready: bool,
    /// What came up before the ready message. Without this queue the first state would be lost
    /// if the source wakes while the page is still loading — the window would then stand empty.
    queue: Vec<Notice>,
}

impl Window {
    /// Opens the window. `proxy` carries the page's messages into the event loop.
    pub fn open<E: From<PageCall> + 'static>(
        target: &EventLoopWindowTarget<E>,
        proxy: EventLoopProxy<E>,
        catalogue: &Catalog,
    ) -> Result<Self, WindowError> {
        let image = icon::draw(SIZE_WINDOW, IconStyle::Colour, IconState::Normal);
        let window = WindowBuilder::new()
            .with_title(TITLE)
            .with_inner_size(LogicalSize::new(WIDTH, HEIGHT))
            .with_min_inner_size(LogicalSize::new(MIN_WIDTH, MIN_HEIGHT))
            // A window icon that failed is no reason not to show the window.
            .with_window_icon(
                tao::window::Icon::from_rgba(image.rgba, image.width, image.height).ok(),
            )
            .build(target)?;

        let view = WebViewBuilder::new()
            .with_html(page(&nonce(), catalogue))
            .with_ipc_handler(move |request| {
                // If the channel swallows the message, the loop has ended — and then there is
                // nobody left who could answer it either.
                let _ = proxy.send_event(E::from(PageCall(request.into_body())));
            })
            .with_navigation_handler(navigation_allowed)
            // No "inspect" context menu in the shipped build; the page is not a workbench but a
            // display.
            .with_devtools(cfg!(debug_assertions))
            .build(&window)?;

        // Position and size into the diagnostic log: they are the only place where a screenshot
        // (and a bug report "the window is half off screen") can work out where the window is,
        // without anybody having to question the user interface.
        let situation = window.outer_position().map(|p| p.to_logical::<f64>(window.scale_factor()));
        let size = window.outer_size().to_logical::<f64>(window.scale_factor());
        tracing::debug!(
            x = situation.as_ref().map(|p| p.x).unwrap_or(f64::NAN),
            y = situation.as_ref().map(|p| p.y).unwrap_or(f64::NAN),
            width = size.width,
            height = size.height,
            scale = window.scale_factor(),
            "window opened."
        );
        Ok(Self { window, view, ready: false, queue: Vec::new() })
    }

    /// The identifier of the window — the event loop tells foreign windows apart by it.
    pub fn identifier(&self) -> WindowId {
        self.window.id()
    }

    /// Brings the window to the front (a second start, a click on the icon, the "open" menu
    /// entry).
    pub fn to_the_front(&self) {
        self.window.set_visible(true);
        self.window.set_minimized(false);
        self.window.set_focus();
    }

    /// The page has reported in; from now on `window.receive` exists.
    pub fn is_ready(&mut self) -> Result<(), WindowError> {
        self.ready = true;
        for notice in std::mem::take(&mut self.queue) {
            self.send(&notice)?;
        }
        Ok(())
    }

    /// Sends a message to the page — or keeps it until the page is ready.
    pub fn send(&mut self, notice: &Notice) -> Result<(), WindowError> {
        if !self.ready {
            self.queue.push(notice.clone());
            return Ok(());
        }
        self.view.evaluate_script(&notice.as_script()?)?;
        Ok(())
    }
}

/// The application's menu — **macOS only, and only so that Cmd+V has somewhere to land**.
///
/// On macOS the keyboard equivalents of the editing commands do not belong to the text field but
/// to the application's main menu: a key-down is offered to `[NSApp mainMenu]` for key-equivalent
/// processing on its way through `NSApplication.sendEvent:`, and nothing else in AppKit turns
/// Cmd+V into `paste:`.
/// Until this function existed there was no main menu at all, and the wizard's address fields
/// could only be typed into — which is how an address arrives from an administrator's mail, and
/// not how anybody wants to enter it.
///
/// **MEASURED on 2026-09-14** in the running app (`--demo --window`, the wizard on its server
/// page, the field focused, the web view the window's first responder, the window key, an address
/// on the pasteboard): `NSApp.mainMenu` was nil; a Cmd+V key-down handed to
/// `NSApplication.sendEvent:` left the field empty; `sendAction:paste: to:nil from:nil` returned
/// true and filled it with the pasteboard's text. The web view was never the difficulty — there
/// was nobody to send it `paste:`.
///
/// **Why an Edit entry and nothing else.** elasticdms is an accessory of the menu bar
/// (`ActivationPolicy::Accessory`, ADR-D07), and Apple's own `NSRunningApplication.h` says of that
/// policy: "The application does not appear in the Dock and does not have a menu bar". This menu
/// is therefore never drawn. It is a dispatch table, not a surface — which is also why its words
/// carry no catalogue key: nobody reads them. What stands in it is what a text field needs and
/// nothing further. No "Quit" in particular: quitting belongs to the entry on the icon, which
/// stops the source before the loop exits (`event_loop::menu_command`), and `terminate:` would go
/// round that.
///
/// The entries are `muda`'s predefined ones. They carry AppKit's own selectors and none of our
/// identifiers, so they fire no `MenuEvent` — the handler the icon's menu installed
/// (`event_loop::start`) keeps every event it had.
///
/// **Nothing of this on Windows, and behind a `cfg` rather than an `if` for that reason.** There
/// the editing keys are WebView2's own business and not an application menu's, and elasticdms
/// never takes them away from it: `AreBrowserAcceleratorKeysEnabled` is only touched by `wry` when
/// `with_browser_accelerator_keys(false)` was asked for (wry 0.57, `webview2/mod.rs:649`), and
/// `Window::open` does not ask. What was **not** measured is the step after that — that WebView2
/// then really does paste on Ctrl+V. This house has no Windows machine; the Windows target is
/// compile-checked (`cargo xwin check`) and nothing more. The `cfg` is what makes that
/// unmeasured step safe: no line of this reaches a Windows build, so it cannot break what works
/// there today.
///
/// The menu has to be **held**: `muda` takes its bookkeeping for this menu down on drop, and the
/// caller therefore keeps it for as long as the app runs.
///
/// # Errors
///
/// [`tray_icon::menu::Error`] when the entries cannot be appended. Not a reason to stop: without
/// this menu the app is what it was yesterday.
#[cfg(target_os = "macos")]
pub fn edit_menu() -> Result<tray_icon::menu::Menu, tray_icon::menu::Error> {
    use tray_icon::menu::{Menu, PredefinedMenuItem, Submenu};

    let edit = Submenu::new("Edit", true);
    edit.append_items(&[
        &PredefinedMenuItem::undo(None),
        &PredefinedMenuItem::redo(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::cut(None),
        &PredefinedMenuItem::copy(None),
        &PredefinedMenuItem::paste(None),
        &PredefinedMenuItem::select_all(None),
    ])?;
    let menu = Menu::new();
    menu.append(&edit)?;
    menu.init_for_nsapp();
    Ok(menu)
}

/// What the page sent — raw text; it is parsed in [`crate::message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCall(pub String);

/// Puts nonce, style, script, the two platform parts, language and catalogue into the page.
///
/// Seven placeholders, no templating engine: the page is one file, and the variable parts are
/// this start's nonce, the language of this run, and the two pieces that only one platform has.
///
/// The order matters twice. The catalogue goes in **last**: a sentence in it may contain
/// `{{STYLE}}` or any other placeholder — an archive is full of texts nobody vetted — and a
/// replacement running after it would substitute inside a sentence the user wrote. Whatever the
/// catalogue brings is therefore never looked at again. And no piece put in here may itself carry
/// a placeholder: its own replacement has already run when it arrives, and the placeholder would
/// stay standing in the page. `no_part_of_the_page_carries_a_placeholder_of_its_own` holds that.
pub fn page(nonce: &str, catalogue: &Catalog) -> String {
    TEMPLATE
        .replace("{{STYLE}}", STYLE)
        .replace("{{SCRIPT}}", SCRIPT)
        .replace("{{MIRROR}}", MIRROR)
        .replace("{{EXTENSION}}", EXTENSION)
        .replace("{{NONCE}}", nonce)
        .replace("{{LANGUAGE}}", catalogue.language().tag())
        .replace("{{CATALOG}}", &catalogue.as_json())
}

/// The System Settings pane on which the user switches the extension on.
///
/// **Measured on macOS 26.6 (build 25G72), 2026-09-13.** `open "x-apple.systempreferences:…"`
/// with this identifier starts
/// `/System/Library/ExtensionKit/Extensions/LoginItems.appex/Contents/MacOS/LoginItems` with
/// `serviceName = com.apple.LoginItems-Settings.extension` in its launch arguments — that is the
/// pane, and it really was selected. The pane's own `Info.plist` names
/// `allowsXAppleSystemPreferencesURLScheme = true` and carries the older identifier
/// `com.apple.ExtensionsPreferences` as `url_alias`, which was measured to open the same pane;
/// the newer one is used here because it is the pane's own.
///
/// **What a success does not say:** `open` returns 0 for an identifier that exists nowhere
/// (measured with `com.apple.NoSuchPane.extension` — System Settings comes up on whatever pane it
/// was last on, and no pane extension starts). The exit code is therefore no evidence that the
/// user is looking at the right list, which is why the page keeps the written way there as well.
///
/// **Not proven:** that any parameter jumps to the section the elasticdms entry is in. No
/// settings pane on this machine carries the string "File Provider" at all (searched over every
/// `/System/Library/ExtensionKit/Extensions/*/Contents/Resources/Localizable.loctable`, 241 of
/// them), and the pane's binary yields no extension-point string either. The catalogue sentence
/// therefore names the pane and the "Extensions" section — both measured, in both languages, out
/// of that pane's `Localizable.loctable` — and no heading below them.
#[cfg(target_os = "macos")]
pub const EXTENSION_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.LoginItems-Settings.extension";

/// Opens [`EXTENSION_SETTINGS`] — through the operating system, never in the web view.
///
/// The same way the sign-in page takes (`event_loop::open_login_page`): this page navigates
/// nowhere, and a pane of System Settings is not something a web view could show anyway.
///
/// # Errors
///
/// [`DisplayError::Open`] when the operating system refuses to open it at all.
#[cfg(target_os = "macos")]
pub fn open_extension_settings() -> Result<(), crate::display::DisplayError> {
    open::that_detached(EXTENSION_SETTINGS).map_err(|e| crate::display::DisplayError::Open {
        target: EXTENSION_SETTINGS.to_owned(),
        reason: e.to_string(),
    })
}

/// May the web view navigate there?
///
/// Only to the embedded page itself. It is loaded as text (`NavigateToString` on Windows,
/// `loadHTMLString` on macOS); both report `about:blank` as the address. Everything else — an
/// `https://` link, a `data:` page, a file — is to be refused, because the page shows case file
/// (Akte) names, and a jump outwards would take them along (ADR-D07: "navigates nowhere").
///
/// A link the user *really* should open (the sign-in page) does not go through the web view but
/// through the operating system — see `event_loop::check_login_address`.
pub fn navigation_allowed(address: String) -> bool {
    let allowed = address.is_empty() || address == "about:blank" || address == "about:srcdoc";
    if !allowed {
        tracing::warn!(%address, "the web view wanted to navigate; refused.");
    }
    allowed
}

/// 128 bits for the content policy's nonce, out of two freshly keyed SipHash runs from the
/// standard library.
///
/// Not cryptographic — and it does not have to be here: the page loads nothing, and whoever wanted
/// to guess the nonce would first have to get script into the page. The nonce is the second lock
/// behind "no markup out of data" (view.js), not the first.
fn nonce() -> String {
    (0_u8..2)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u8(i);
            h.write_u128(std::process::id() as u128);
            format!("{:016x}", h.finish())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use edms_core::log::LogKind;
    use edms_i18n::{KEYS, Language, key};

    use super::*;

    /// The page in one language. Which one does not matter for most of the properties below —
    /// where it does, the test names it.
    fn german() -> &'static Catalog {
        Catalog::of(Language::De)
    }

    /// Every kind from the core. That none is missing is enforced by [`_is_complete`] at compile time.
    const KINDS: [LogKind; 15] = [
        LogKind::Opened,
        LogKind::OpenFailed,
        LogKind::NewVersion,
        LogKind::SpaceReclaimed,
        LogKind::AccessRevoked,
        LogKind::ErasedByOrder,
        LogKind::IngestAccepted,
        LogKind::IngestFailed,
        LogKind::DeviceRegistered,
        LogKind::SignedIn,
        LogKind::SignedOut,
        LogKind::LoginRequired,
        LogKind::ConnectionLost,
        LogKind::ConnectionRestored,
        LogKind::SecurityWarning,
    ];

    /// Never called. Its purpose is the exhaustive match: a new log kind in the core turns this
    /// file red instead of landing silently in the user interface without a glyph.
    const fn _is_complete(kind: LogKind) -> usize {
        match kind {
            LogKind::Opened => 0,
            LogKind::OpenFailed => 1,
            LogKind::NewVersion => 2,
            LogKind::SpaceReclaimed => 3,
            LogKind::AccessRevoked => 4,
            LogKind::ErasedByOrder => 5,
            LogKind::IngestAccepted => 6,
            LogKind::IngestFailed => 7,
            LogKind::DeviceRegistered => 8,
            LogKind::SignedIn => 9,
            LogKind::SignedOut => 10,
            LogKind::LoginRequired => 11,
            LogKind::ConnectionLost => 12,
            LogKind::ConnectionRestored => 13,
            LogKind::SecurityWarning => 14,
        }
    }

    #[test]
    fn the_page_carries_style_script_and_nonce_and_no_placeholder_any_more() {
        let html = page("abc123", german());
        assert!(!html.contains("{{"), "a placeholder stayed behind");
        // Three times as an attribute (style, catalogue, script), twice in the policy as
        // 'nonce-…'. The catalogue has a block of its own so that the script can read it before
        // its first line runs.
        assert_eq!(html.matches("nonce=\"abc123\"").count(), 3, "style, catalogue and script");
        assert_eq!(html.matches("'nonce-abc123'").count(), 2, "style-src and script-src");
        assert!(html.contains("window.receive"), "the script is missing");
        assert!(html.contains("prefers-color-scheme"), "the style is missing");
    }

    #[test]
    fn every_log_kind_has_a_glyph() {
        for kind in KINDS {
            let wire = serde_json::to_string(&kind).unwrap();
            let name = wire.trim_matches('"');
            assert!(SCRIPT.contains(&format!("{name}:")), "view.js names no glyph for {name}");
        }
    }

    #[test]
    fn the_script_draws_no_name_on_an_erasure_row_and_never_out_of_markup() {
        // The second lock behind the core's type: even if a name did arrive, the page does not
        // draw it on an erasure row.
        assert!(
            SCRIPT.contains(r#"row.kind !== "ERASED_BY_ORDER""#),
            "the lock against a name on the erasure row is missing from view.js"
        );
        for markup in [".innerHTML", ".outerHTML", "insertAdjacentHTML", "document.write"] {
            assert!(
                !SCRIPT.contains(markup),
                "{markup} puts archive data in as markup — only textContent is allowed"
            );
        }
    }

    /// The two platform parts as **files**, on every platform.
    ///
    /// [`EXTENSION`] and [`MIRROR`] are empty on the platform that does not carry them, and a
    /// check over an empty string checks nothing: on this machine nobody would ever look at
    /// `view/mirror.html`, and on a Windows machine nobody at `view/extension.html`. Read here so
    /// that both are measured wherever the tests run — what may **not** be read on both platforms
    /// is the finished page, and `page` is not built from these.
    const EXTENSION_SOURCE: &str = include_str!("view/extension.html");
    const MIRROR_SOURCE: &str = include_str!("view/mirror.html");

    /// Every part the page is put together from — the shared ones and the two that only one
    /// platform carries. What is checked on "the page's own parts" has to be checked on these
    /// as well, or the check has a hole exactly where the newest markup is.
    const PARTS: [&str; 5] = [TEMPLATE, STYLE, SCRIPT, EXTENSION_SOURCE, MIRROR_SOURCE];

    /// The parts that are put **into** the template. The template itself carries the markers and
    /// is therefore not among them.
    const PUT_IN: [&str; 4] = [STYLE, SCRIPT, EXTENSION_SOURCE, MIRROR_SOURCE];

    /// One function of the page's script, from its `function` line to the brace that closes it.
    ///
    /// The file is written with the whole page one level inside its own IIFE, so a function's
    /// closing brace is the only thing that ever stands alone in a line of two spaces. Reading a
    /// single function and not the whole file is what makes the two tests below say something: a
    /// guard that moved out of the function it guards is a guard that is gone.
    ///
    /// Line by line, and not over the file as one string: `str::lines` is the one reading that
    /// says the same thing wherever the tests run. `.gitattributes` pins LF for every checkout,
    /// and a search for `"\n  }\n"` would have been a test that depends on that pin holding —
    /// which is the kind of Mac-only assertion this repository has already paid for once.
    fn function_of(name: &str) -> String {
        let opening = format!("  function {name}(");
        let mut body = String::new();
        for line in SCRIPT.lines().skip_while(|line| !line.starts_with(&opening)) {
            body.push_str(line);
            body.push('\n');
            if line == "  }" {
                return body;
            }
        }
        panic!("view.js carries no function {name} that is closed at its own indentation");
    }

    #[test]
    fn the_one_address_is_handed_over_only_from_the_page_it_stands_on() {
        // The defect this stands for shipped on 2026-09-14 and was found by hand, in a browser:
        // `typed` collects the fields of the whole wizard, the first "Next" is pressed on the
        // overview page, and the one field that can stand there **filled** without anybody having
        // typed in it is the address (`setup::DEVELOPMENT_BASE`). One click on "Step 1 of 7"
        // stored elasticdms's own development server as the address of that workstation, two
        // pages before the field had been shown.
        //
        // **What this test is.** Nothing in this workspace executes a line of view.js — there is
        // no JavaScript engine among the dependencies and no browser in CI — and that is why the
        // defect got through a green suite. This reads the source of the one function and insists
        // the guard is inside it: it bites when somebody deletes the guard, which is how the
        // defect arose, and it cannot tell whether the guard is right. That was measured by hand,
        // and the measurement stands beside the code in view.js.
        // The condition that opens the block in which the one answer becomes the three, and not
        // the function as a whole: a page check standing unused two lines above the block is the
        // same defect with a variable in front of it.
        let typed = function_of("typed");
        let lines: Vec<&str> = typed.lines().collect();
        let collapse = lines
            .iter()
            .position(|line| line.contains("for (const name of ADDRESSES)"))
            .expect("`typed` answers the three addresses with the one");
        let guard = lines[..collapse]
            .iter()
            .rposition(|line| line.trim_start().starts_with("if ("))
            .expect("and it does so under a condition");
        assert!(
            lines[guard].contains("isOnPage(base)"),
            "`typed` hands the one address over without asking which page the user is on:\n{}",
            lines[guard]
        );
        // And that the judgement itself is one: a helper that answers `true` would be worse than
        // none, because the line above would go on reading like a guard.
        let judging = function_of("isOnPage");
        assert!(
            judging.contains("steps[at]") && judging.contains(".page"),
            "the page is no longer judged by the step the user is standing on:\n{judging}"
        );
    }

    #[test]
    fn the_development_sentence_is_read_from_the_field_and_not_from_the_offer() {
        // The second half of the same day, and the same kind of proof. The sentence used to be
        // tied to `suggestedBase` — the offer the app makes only while no channel carries an
        // address — and compared byte for byte. Both halves switched it off in the ordinary case:
        // the address was stored on the first Next, so nothing was offered any more, and the
        // stored spelling (without the trailing slash) did not match the offered one.
        let showing = function_of("showSuggestion");
        assert!(
            showing.contains("setup.developmentBase") && showing.contains("sameAddress("),
            "the sentence no longer reads the field it is about:\n{showing}"
        );
        assert!(
            !showing.contains("suggestedBase"),
            "the sentence is tied to the offer again, and goes out with it:\n{showing}"
        );
    }

    #[test]
    fn no_part_of_the_page_carries_a_placeholder_of_its_own() {
        // `page` substitutes each placeholder once and in order. A part that itself contained
        // `{{EXTENSION}}` would arrive after that replacement had run, and the marker would stay
        // standing in the finished page — visible to the user, and nothing would have filled it.
        for part in PUT_IN {
            assert!(!part.contains("{{"), "a part of the page carries a placeholder of its own");
        }
    }

    #[test]
    fn the_encoding_stands_in_the_first_kilobyte_of_the_page() {
        // A browser reads the encoding out of the first 1024 bytes and otherwise falls back to
        // the machine's default. MEASURED on 2026-09-13: with the header comment in front of
        // `<head>`, the German page came up as "Ã–ffnen Sie die Systemeinstellungen" — every
        // umlaut two wrong characters, in every sentence of the catalogue.
        for language in Language::ALL {
            let html = page("n", Catalog::of(language));
            let place = html.find("charset=\"utf-8\"").expect("the page names its encoding");
            assert!(place < 1024, "{language}: the encoding stands only at byte {place}");
        }
    }

    #[test]
    fn every_comment_of_every_part_is_opened_once_and_closed_once() {
        // A comment that carries an end marker in its own prose ends there, and everything after
        // it stands in the window as a sentence for the user. MEASURED on 2026-09-13: the header
        // of this file explained the danger, spelled the marker out while doing so, and put half
        // its own text on the screen. An unequal count is exactly that mistake.
        for part in PARTS {
            assert_eq!(
                part.matches("<!--").count(),
                part.matches("-->").count(),
                "a part of the page opens and closes a different number of comments"
            );
        }
    }

    #[test]
    fn no_comment_of_the_template_names_a_marker() {
        // The replacement runs over the comments too. A part put in inside one of them would end
        // that comment at its own `-->` and spill its markup into the document — MEASURED on
        // 2026-09-13: the wizard's extension page stood above the window's header, and the rest
        // of the comment stood there as a sentence for the user to read.
        let mut rest = TEMPLATE;
        while let Some(start) = rest.find("<!--") {
            let after = &rest[start + 4..];
            let end = after.find("-->").expect("every comment is closed");
            assert!(
                !after[..end].contains("{{"),
                "a comment of the page names a marker; the replacement would run into it"
            );
            rest = &after[end + 3..];
        }
    }

    #[test]
    fn the_wizard_carries_every_step_the_decision_names() {
        // ADR-D13 §5. The steps this build has are the sections in the document — view.js reads
        // them from there — so this is the list the wizard can ever show.
        let html = page("n", german());
        for step in ["welcome", "server", "workstation", "code", "signin", "done"] {
            assert!(html.contains(&format!("data-page=\"{step}\"")), "the {step} page is missing");
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn only_macos_carries_the_extension_page_and_windows_carries_the_folder_s_place() {
        // ADR-D13 §10, the half of it this machine can measure: here the extension page is in
        // the document and the field for the folder's place is not. The Windows half stands in
        // the test below, and the Windows build runs it.
        let html = page("n", german());
        assert!(html.contains(r#"data-page="extension""#), "the extension page is missing");
        assert!(
            !html.contains(r#"data-field="mirrorPath""#),
            "the field for the folder's place has no meaning here (measurement 5) and must not \
             stand in the page"
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn no_index_of_the_wizard_reaches_the_extension_page_here() {
        // The structural half of ADR-D13 §10: not "the page is never shown" but "the page is not
        // there". Back and Next are indices into the sections the document carries.
        let html = page("n", german());
        assert!(EXTENSION.is_empty(), "the extension markup is compiled in on this platform");
        assert!(!html.contains(r#"data-page="extension""#), "the extension page is in the page");
        // The identifier `setup-extension-open` DOES stand in the page here, and that is not a
        // leak: view.css and view.js are one file each for every platform, so the style and the
        // `onClickIfThere` binding travel everywhere. Neither can do anything without the button.
        // What carries the promise is the pair above — no markup, and no index that reaches it —
        // together with `event_loop`, where the request opens nothing off macOS and says in the
        // log that it should never have arrived. Asserting on the raw string instead tested the
        // build of the stylesheet, and it failed on Windows for a reason that was not the rule.
        assert!(
            !html.contains(r#"id="setup-extension-open""#),
            "the button to System Settings is in the page"
        );
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_carries_the_field_for_the_folder_s_place() {
        let html = page("n", german());
        assert!(html.contains(r#"data-field="mirrorPath""#), "the folder's place is missing");
    }

    #[test]
    fn both_platform_parts_are_a_page_of_the_wizard_and_a_field_of_it() {
        // Read from the files and not from the built page, so that the part this platform does
        // not carry is measured all the same — otherwise the first anyone hears of a broken
        // `view/mirror.html` is a Windows build.
        assert!(EXTENSION_SOURCE.contains(r#"data-page="extension""#));
        assert!(EXTENSION_SOURCE.contains(r#"data-step="setup.extension.step""#));
        assert!(MIRROR_SOURCE.contains(r#"data-field="mirrorPath""#));
        // Both carry key paths and no sentence, like every other part.
        for part in [EXTENSION_SOURCE, MIRROR_SOURCE] {
            assert!(part.contains("data-text=\"setup."), "a part carries no catalogue key");
        }
    }

    #[test]
    fn the_page_knows_the_same_length_limit_as_the_protocol() {
        // Two numbers, one rule. If the page let more through than `Request::read` takes, the
        // message would be discarded on the other side and the click would do nothing at all.
        assert!(
            SCRIPT.contains(&format!("MAX_VALUE = {}", crate::message::MAX_VALUE)),
            "view.js holds to a different length than message::MAX_VALUE"
        );
        // That seven values of that length also fit in one request is the protocol's own rule and
        // is asserted where the two numbers stand (`message.rs`, at compile time). It used to
        // stand here as `MAX_VALUE * 7 < MAX_LENGTH / 2`, which multiplies characters and
        // compares them against a byte budget — true for ASCII and for nothing else.
    }

    /// The walk through the wizard at the level the page walks it — every message in the order
    /// view.js sends and receives it.
    ///
    /// It is not the window: nobody can click in a `wry` web view from a test. What it does hold
    /// is everything between the click and the source — that a set-up arrives at all, that the
    /// values the page hands over reach the source, that a value for a fixed field does not, and
    /// that the extension answers on its own channel.
    #[test]
    fn the_page_s_way_through_the_set_up_arrives_at_the_source() {
        use std::path::Path;

        use crate::demo::{DemoSource, DemoState};
        use crate::display::{DisplaySource, ExtensionState, Fixed, SetupValues};
        use crate::message::Request;

        let source =
            DemoSource::new(crate::demo::now(), DemoState::SignedOut, Path::new("/tmp"), german())
                .unwrap();

        // "Set-up" in the window.
        assert_eq!(Request::read(r#"{"kind":"openSetup"}"#).unwrap(), Request::OpenSetup);
        let view = source.setup().expect("the demo knows its set-up");
        assert!(view.api_base.is_open() && view.auth_base.is_open());
        assert_eq!(view.app_base.fixed, Fixed::Operator, "the demo's one fixed value");

        // Next from the pages with fields: everything that was offered, and the value that was
        // not offered alongside it — the page cannot enforce §1, the source can.
        let typed = SetupValues {
            api_base: Some("https://api.elasticdms.example".into()),
            auth_base: Some("https://anmeldung.elasticdms.example".into()),
            app_base: Some("https://attacker.example".into()),
            device_name: Some("Werkstatt 4".into()),
            ..SetupValues::default()
        };
        source.apply_setup(&typed).unwrap();
        let after = source.setup().unwrap();
        assert_eq!(after.api_base.value, "https://api.elasticdms.example");
        assert_eq!(after.device_name.value, "Werkstatt 4");
        assert_eq!(
            after.app_base.value, "https://archiv.example",
            "a value for a fixed field must not get through"
        );

        // The extension page, asking every two seconds until macOS says yes.
        assert_eq!(source.extension_state(), ExtensionState::Off);
        let mut state = ExtensionState::Off;
        for _ in 0..10 {
            state = source.extension_state();
        }
        assert_eq!(state, ExtensionState::On, "the demo never switches itself on");

        // And the last page.
        source.complete_setup().unwrap();
    }

    #[test]
    fn a_fixed_value_is_marked_as_fixed_and_an_open_one_is_not() {
        use crate::display::{Fixed, SetupField};
        assert!(SetupField::open("https://archive.example").is_open());
        assert!(!SetupField::fixed("https://archive.example", Fixed::Operator).is_open());
    }

    #[test]
    fn the_page_names_no_foreign_origin() {
        // Checked on the page's **own** parts, not on the rendered whole: a sentence of the
        // catalogue may name an address (`error.login_address` explains which schemes are
        // allowed), and a word inside a JSON string is not an origin — it is never a `src`, never
        // a `href`, and the policy forbids loading anything anyway. What matters is that markup
        // and script name nothing that could be fetched.
        //
        // The only permitted hit is the SVG namespace — an identifier, not an address:
        // `createElementNS` fetches nothing.
        let namespace = "http://www.w3.org/2000/svg";
        for part in PARTS {
            assert_eq!(
                part.matches("http://").count(),
                part.matches(namespace).count(),
                "a foreign http:// stands in the page"
            );
            assert_eq!(
                part.matches("https://").count(),
                0,
                "a foreign https:// stands in the page"
            );
        }
        // And the catalogue really does arrive as a JSON string and not as markup.
        let html = page("n", german());
        assert!(!german().as_json().contains('<'), "a sentence could close a tag");
        assert!(html.contains("window.__edmsCatalog = {"), "the catalogue is not in the page");
    }

    #[test]
    fn the_page_says_that_it_is_only_a_local_view_in_every_language() {
        // ADR-D07: "it says what it is." Without this sentence the list could be taken for the
        // authoritative access log — and the server keeps that one. The page carries the key; the
        // sentence has to arrive with the catalogue.
        for language in Language::ALL {
            let catalogue = Catalog::of(language);
            let html = page("n", catalogue);
            assert!(
                html.contains(r#"data-text="window.list.local_note""#),
                "{language}: the element that carries the sentence is missing"
            );
            let sentence = catalogue.text(key::WINDOW_LIST_LOCAL_NOTE);
            assert!(html.contains(sentence), "{language}: the sentence is not in the catalogue");
        }
    }

    #[test]
    fn the_page_carries_the_whole_catalogue_and_no_sentence_of_its_own() {
        // Two catalogues would be one too many: the HTML would stay German while the TOML was
        // translated, and nobody would see it until a customer did.
        for language in Language::ALL {
            let html = page("n", Catalog::of(language));
            for entry in KEYS {
                assert!(
                    html.contains(&format!("\"{}\":", entry.path())),
                    "{language}: `{entry}` did not reach the page"
                );
            }
        }
        for part in PARTS {
            assert!(
                !part.contains("Ordner"),
                "a German sentence stands in the page itself instead of in the catalogue"
            );
        }
    }

    #[test]
    fn the_language_of_the_catalogue_stands_in_the_html_element() {
        // Without `lang` a screen reader reads German sentences with English phonemes, and the
        // web view hyphenates by the wrong rules.
        for language in Language::ALL {
            let html = page("n", Catalog::of(language));
            assert!(html.contains(&format!("<html lang=\"{}\">", language.tag())), "{language}");
        }
    }

    #[test]
    fn a_sentence_of_the_catalogue_cannot_close_the_script_block_or_be_substituted_into() {
        // The catalogue goes in last and is never looked at again — otherwise a sentence
        // containing `{{STYLE}}` would pull the whole stylesheet into a text.
        for language in Language::ALL {
            let html = page("n", Catalog::of(language));
            assert!(!html.contains("</script>x"), "{language}");
        }
        // The JSON escapes `<`, so a sentence can carry neither `</script>` nor markup.
        assert!(!german().as_json().contains('<'));
    }

    #[test]
    fn the_policy_forbids_every_foreign_source() {
        let html = page("n", german());
        assert!(
            html.contains("default-src 'none'"),
            "without default-src 'none' everything is open"
        );
        for forbidden in ["connect-src 'none'", "img-src 'none'"] {
            assert!(html.contains(forbidden), "{forbidden} is missing from the policy");
        }
        // `frame-ancestors` is in the policy and is **inert there**: the content-security-policy
        // specification lists it — with `report-uri` and `sandbox` — among the directives a
        // browser ignores when the policy is delivered in a `meta` element. It stands in the page
        // as a statement of intent and for the day the policy moves to a header; what actually
        // keeps this page out of a frame is the web view, which loads one document and
        // `navigation_allowed` refuses every other. Asserting it beside the two above would read
        // as a guarantee the delivery cannot hold.
        assert!(html.contains("frame-ancestors 'none'"), "the statement of intent is gone");
        assert!(!html.contains("'unsafe-inline'"), "unsafe-inline would cancel the nonce out");
    }

    #[test]
    fn only_the_embedded_page_may_be_loaded() {
        assert!(navigation_allowed("about:blank".into()));
        assert!(navigation_allowed(String::new()));
        for foreign in [
            "https://elasticdms.example/",
            "http://127.0.0.1:8480/v1/dokumente",
            "file:///etc/passwd",
            "data:text/html,<script>1</script>",
            "javascript:alert(1)",
        ] {
            assert!(!navigation_allowed(foreign.into()), "\"{foreign}\" should have been refused");
        }
    }

    /// Writes the set-up wizard as files that can be walked through — the tool behind the
    /// walk-through, not a check (hence `ignore`):
    /// `cargo test -p elasticdms -- --ignored write_setup_preview --nocapture`.
    ///
    /// It takes the same route as the window — `window::page`, the same `Notice`s, the same
    /// `Notice::as_script` — so that what is walked through is the page the app shows and not a
    /// drawing of it. Four devices, because they are four different wizards:
    ///
    /// * `unmanaged` — nobody has told this workstation its addresses, and they were given apart
    ///   (`--demo`'s own shape): the three fields, one of them an operator's.
    /// * `first-run` — the device of `--demo=first-run`: the one address field, prefilled with
    ///   `setup::DEVELOPMENT_BASE`, and the sentence underneath saying what that address is. This
    ///   one was missing until 2026-09-14, and with it the two defects that were then found in
    ///   this page by hand.
    /// * `managed` — the operator set all three addresses and the name: the server and workstation
    ///   pages are not steps at all, and their values stand as facts on the first page (§3).
    /// * `extension-on` — the same unmanaged device with the extension already switched on: the
    ///   step for it is not in the list.
    ///
    /// The language is this run's, so `EDMS_LANG=en` writes the English pages.
    #[test]
    #[ignore = "only writes the wizard for a walk-through"]
    fn write_setup_preview() {
        use std::path::Path;

        use crate::demo::{DemoSource, DemoState};
        use crate::display::{DisplaySource, ExtensionState, Fixed, SetupField};
        use crate::menu::{FileManager, menu_state};
        use crate::message::StateView;

        let catalogue = crate::locale::catalogue();
        let device = |state| {
            DemoSource::new(crate::demo::now(), state, Path::new("/tmp"), catalogue).unwrap()
        };
        let source = device(DemoState::SignedOut);
        let state = source.state();
        let menu = menu_state(&state, FileManager::Finder, catalogue);
        let header = Notice::State { state: Box::new(StateView::from(&state, &menu, catalogue)) };

        let unmanaged = source.setup().unwrap();
        let first_run = device(DemoState::FirstRun).setup().unwrap();
        let mut managed = unmanaged.clone();
        managed.api_base = SetupField::fixed("https://api.elasticdms.example", Fixed::Operator);
        managed.auth_base =
            SetupField::fixed("https://anmeldung.elasticdms.example", Fixed::Operator);
        managed.device_name = SetupField::fixed("Werkstatt 4", Fixed::Enrolled);
        managed.language = SetupField::fixed(catalogue.language().tag(), Fixed::Operator);
        managed.enrolled = true;
        let mut switched_on = unmanaged.clone();
        switched_on.extension = ExtensionState::On;

        for (name, view) in [
            ("unmanaged", unmanaged),
            ("first-run", first_run),
            ("managed", managed),
            ("extension-on", switched_on),
        ] {
            let nonce = "preview00000abcd";
            let notice = Notice::Setup { setup: Box::new(view) };
            // The app's half of the round trip, in eight lines. "Next" hands the values over and
            // waits for the answer before it moves on (view.js: the refusal used to arrive while
            // the user was already one page further, about a field they could no longer see), so
            // a preview with nothing behind `window.ipc` would stop on the first page that has a
            // field. This answers the way `event_loop::page_call` answers — the same notice, and
            // asynchronously, because that is the half that matters.
            let answer = format!(
                "window.__edmsAnswer = () => {{ {} }};\n\
                 window.ipc = {{ postMessage: (raw) => {{\n  \
                   const sent = JSON.parse(raw);\n  \
                   if (sent.kind === \"applySetup\" || sent.kind === \"openSetup\") \
                     {{ setTimeout(window.__edmsAnswer, 0); }}\n\
                 }} }};",
                notice.as_script().unwrap()
            );
            let to_set = format!(
                "<script nonce=\"{nonce}\">\n{}\n{}\n{}\n</script>\n</body>",
                header.as_script().unwrap(),
                notice.as_script().unwrap(),
                answer
            );
            let html = page(nonce, catalogue).replace("</body>", &to_set);
            let path = std::env::temp_dir()
                .join(format!("elasticdms-setup-{name}-{}.html", catalogue.language()));
            std::fs::write(&path, html).unwrap();
            println!("SETUP {}", path.display());
        }
    }

    #[test]
    fn two_nonces_are_different_and_thirty_two_hex_digits_long() {
        let (a, b) = (nonce(), nonce());
        assert_ne!(a, b);
        assert!(a.len() == 32 && a.bytes().all(|z| z.is_ascii_hexdigit()), "{a}");
    }
}
