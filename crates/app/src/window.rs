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

/// What the page sent — raw text; it is parsed in [`crate::message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCall(pub String);

/// Puts nonce, style, script, language and catalogue into the page.
///
/// Five placeholders, no templating engine: the page is one file, and the variable parts are this
/// start's nonce and the language of this run.
///
/// The order matters. The catalogue goes in **last**: a sentence in it may contain `{{STYLE}}` or
/// any other placeholder — an archive is full of texts nobody vetted — and a replacement running
/// after it would substitute inside a sentence the user wrote. Whatever the catalogue brings is
/// therefore never looked at again.
pub fn page(nonce: &str, catalogue: &Catalog) -> String {
    TEMPLATE
        .replace("{{STYLE}}", STYLE)
        .replace("{{SCRIPT}}", SCRIPT)
        .replace("{{NONCE}}", nonce)
        .replace("{{LANGUAGE}}", catalogue.language().tag())
        .replace("{{CATALOG}}", &catalogue.as_json())
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
        for part in [TEMPLATE, STYLE, SCRIPT] {
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
        assert!(
            !TEMPLATE.contains("Ordner") && !SCRIPT.contains("Ordner"),
            "a German sentence stands in the page itself instead of in the catalogue"
        );
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
        for forbidden in ["connect-src 'none'", "img-src 'none'", "frame-ancestors 'none'"] {
            assert!(html.contains(forbidden), "{forbidden} is missing from the policy");
        }
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

    #[test]
    fn two_nonces_are_different_and_thirty_two_hex_digits_long() {
        let (a, b) = (nonce(), nonce());
        assert_ne!(a, b);
        assert!(a.len() == 32 && a.bytes().all(|z| z.is_ascii_hexdigit()), "{a}");
    }
}
