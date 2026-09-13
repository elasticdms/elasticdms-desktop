//! Every sentence the user reads — in German and in English, chosen from the operating system's
//! locale.
//!
//! Three decisions carry this crate:
//!
//! 1. **A key is a value, not a string.** [`Key`] can only be built here, from the list in
//!    [`KEYS`]. A call site cannot mistype a key, and a key that is in no catalogue — or in one
//!    catalogue too many — makes `tests/catalogs.rs` red. A missing sentence is therefore a test
//!    failure before the release and never a surprise in a window.
//! 2. **The catalogues are in the binary.** `include_str!`, not a file next to the program: a
//!    shipped client whose texts can be edited from outside is a client whose sentences nobody can
//!    vouch for, and on macOS the File Provider extension runs in a sandbox that would not reach
//!    the file anyway.
//! 3. **A fallback is loud.** English stands in for a locale the client does not speak — but
//!    [`Language::resolve`] says so in the diagnostic log, once per process. Silence here would
//!    mean: a German workstation shows English sentences and nobody can tell whether that is the
//!    locale, the packaging or a bug.
//!
//! ## The way through the crate
//!
//! ```ignore
//! let language = Language::from_environment()                 // EDMS_LANG wins
//!     .unwrap_or_else(|| Language::resolve(system_languages)); // otherwise the OS
//! let catalogue = Catalog::of(language);
//! catalogue.text(key::MENU_OPEN);
//! catalogue.format(key::STATUS_SIGNED_IN_AS, &[("account", "Erika Mustermann")]);
//! ```
//!
//! **The operating system is asked elsewhere.** `AppleLanguages` and `GetUserDefaultUILanguage`
//! are platform API, and platform API lives in the platform crates (architecture rules R4 and R5):
//! `edms_fileprovider::locale` on macOS, `edms_cfapi::locale` on Windows. This crate takes the
//! list of language tags they return and nothing else — that keeps it testable without an
//! operating system, like everything below the app.
//!
//! ## Placeholders
//!
//! Named, never positional: `{account}`, `{count}`. A positional `{0}` cannot be translated —
//! whoever swaps two of them in one language gets a sentence that is wrong in exactly that
//! language, and no test sees it. [`Catalog::format`] leaves an unfilled placeholder standing and
//! reports it in the log; `tests/catalogs.rs` makes sure every locale uses the same placeholders
//! for the same key.

#![forbid(unsafe_code)]

mod reader;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Once, OnceLock};

pub use crate::reader::ReaderError;

/// The environment variable that overrides the operating system's choice.
pub const VAR_LANGUAGE: &str = "EDMS_LANG";

/// The language the client falls back to when it understands no other.
pub const FALLBACK: Language = Language::En;

/// A language the folder client speaks.
///
/// Two, and the list is closed: a third would need a third catalogue, and a catalogue that does
/// not exist is exactly what this crate refuses to paper over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Language {
    /// German.
    De,
    /// English.
    En,
}

impl Language {
    /// Every language, in the order of the catalogues.
    pub const ALL: [Self; 2] = [Self::De, Self::En];

    /// The primary language subtag (BCP 47), e.g. `de`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::De => "de",
            Self::En => "en",
        }
    }

    /// The language for one tag: `de`, `de-AT`, `de_DE` and `DE` all yield [`Self::De`].
    ///
    /// Only the primary subtag counts. A client that distinguished `de-AT` from `de-DE` would
    /// need two Austrian catalogues to keep the promise, and it has one German one.
    pub fn from_tag(tag: &str) -> Option<Self> {
        let primary = tag.split(['-', '_']).next().unwrap_or_default().to_ascii_lowercase();
        Self::ALL.into_iter().find(|language| language.tag() == primary)
    }

    /// The language from [`VAR_LANGUAGE`], if it is set and understood.
    ///
    /// A value that is set but not understood is **not** silently passed over: it stands in the
    /// log with the list of what would have been understood. Whoever writes `EDMS_LANG=fr` is to
    /// read why the window nevertheless comes up in German.
    pub fn from_environment() -> Option<Self> {
        Self::from_value(std::env::var(VAR_LANGUAGE).ok().as_deref())
    }

    /// The testable core of [`Self::from_environment`] — no test sets an environment variable,
    /// because that belongs to the whole process.
    pub fn from_value(value: Option<&str>) -> Option<Self> {
        let raw = value?.trim().to_owned();
        if raw.is_empty() {
            return None;
        }
        match Self::from_tag(&raw) {
            Some(language) => Some(language),
            None => {
                let known: Vec<&str> = Self::ALL.iter().map(|l| l.tag()).collect();
                tracing::warn!(
                    value = raw,
                    known = known.join(", "),
                    "{VAR_LANGUAGE} names a language the folder client does not speak; \
                     the operating system's choice holds."
                );
                None
            }
        }
    }

    /// The first understood language out of the operating system's list; [`FALLBACK`] when none
    /// is understood.
    ///
    /// The fallback is reported **once per process** at `info` level: it is not an error (a Dutch
    /// workstation gets English, and that is right), but it is a fact somebody looking at an
    /// English window wants to find in the log.
    pub fn resolve<'a>(offered: impl IntoIterator<Item = &'a str>) -> Self {
        let offered: Vec<&str> = offered.into_iter().collect();
        if let Some(language) = offered.iter().find_map(|tag| Self::from_tag(tag)) {
            return language;
        }
        static REPORTED: Once = Once::new();
        REPORTED.call_once(|| {
            tracing::info!(
                offered = offered.join(", "),
                fallback = FALLBACK.tag(),
                "the operating system names no language the folder client speaks; \
                 the user interface is in the fallback language."
            );
        });
        FALLBACK
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// A key of the catalogue.
///
/// Can be built only in this crate, and only from [`KEYS`]. That is the whole point: a sentence
/// the user interface asks for either stands in every catalogue, or the test is red.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(&'static str);

impl Key {
    /// The dotted path, e.g. `menu.open`.
    pub const fn path(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

macro_rules! catalogue_keys {
    ($($name:ident = $path:literal;)*) => {
        /// Every key of the catalogue as a constant.
        pub mod key {
            use super::Key;
            $(
                #[doc = concat!("`", $path, "`")]
                pub const $name: Key = Key($path);
            )*
        }
        /// Every key, in the order in which they are declared — the list the catalogue tests
        /// compare both catalogues against.
        pub const KEYS: &[Key] = &[$(key::$name),*];
    };
}

catalogue_keys! {
    // ── The user interface's own locale ──────────────────────────────────────────────────────
    LOCALE_TAG = "locale.tag";

    // ── The menu on the icon ─────────────────────────────────────────────────────────────────
    MENU_OPEN = "menu.open";
    MENU_FOLDER_EXPLORER = "menu.folder.explorer";
    MENU_FOLDER_FINDER = "menu.folder.finder";
    MENU_FOLDER_PLAIN = "menu.folder.plain";
    MENU_BASKETS = "menu.baskets";
    MENU_SIGN_IN = "menu.sign_in";
    MENU_SIGN_OUT = "menu.sign_out";
    MENU_SIGNING_IN = "menu.signing_in";
    MENU_QUIT = "menu.quit";
    MENU_TOOLTIP = "menu.tooltip";

    // ── The state, in the menu and in the window ─────────────────────────────────────────────
    STATUS_SIGNED_IN = "status.signed_in";
    STATUS_SIGNED_IN_AS = "status.signed_in_as";
    STATUS_NOT_SIGNED_IN = "status.not_signed_in";
    STATUS_LOGIN_REQUIRED = "status.login_required";
    STATUS_OFFLINE = "status.offline";
    STATUS_AWAITING_APPROVAL = "status.awaiting_approval";
    STATUS_SECURITY_WARNING = "status.security_warning";
    STATUS_SIGNING_IN = "status.signing_in";
    STATUS_WITH_HINT = "status.with_hint";

    // ── The usage log's row labels (edms_core::log::LogKind) ─────────────────────────────────
    LOG_OPENED = "log.opened";
    LOG_OPEN_FAILED = "log.open_failed";
    LOG_NEW_VERSION = "log.new_version";
    LOG_SPACE_RECLAIMED = "log.space_reclaimed";
    LOG_ACCESS_REVOKED = "log.access_revoked";
    LOG_ERASED_BY_ORDER = "log.erased_by_order";
    LOG_INGEST_ACCEPTED = "log.ingest_accepted";
    LOG_INGEST_FAILED = "log.ingest_failed";
    LOG_DEVICE_REGISTERED = "log.device_registered";
    LOG_SIGNED_IN = "log.signed_in";
    LOG_SIGNED_OUT = "log.signed_out";
    LOG_LOGIN_REQUIRED = "log.login_required";
    LOG_CONNECTION_LOST = "log.connection_lost";
    LOG_CONNECTION_RESTORED = "log.connection_restored";
    LOG_SECURITY_WARNING = "log.security_warning";
    LOG_REDACTED = "log.redacted";

    // ── A delivery command that was carried out (edms_engine::CommandKind) ───────────────────
    COMMAND_DEHYDRATE = "command.dehydrate";
    COMMAND_RECONCILE = "command.reconcile";
    COMMAND_SIGN_OUT = "command.sign_out";
    COMMAND_REFRESH_KEYS = "command.refresh_keys";

    // ── The window ───────────────────────────────────────────────────────────────────────────
    WINDOW_LOADING = "window.loading";
    WINDOW_TITLE_WITH_ACCOUNT = "window.title_with_account";
    WINDOW_BUTTON_SIGN_IN = "window.button.sign_in";
    WINDOW_BUTTON_FOLDER = "window.button.folder";
    WINDOW_BUTTON_BASKETS = "window.button.baskets";
    WINDOW_BUTTON_SETUP = "window.button.setup";
    WINDOW_LOGIN_TITLE = "window.login.title";
    WINDOW_LOGIN_TEXT = "window.login.text";
    WINDOW_LOGIN_ADDRESS = "window.login.address";
    WINDOW_LOGIN_ANCHOR = "window.login.anchor";
    WINDOW_LOGIN_ANCHOR_MISSING = "window.login.anchor_missing";
    WINDOW_LOGIN_BUTTON = "window.login.button";
    WINDOW_LIST_TITLE = "window.list.title";
    WINDOW_LIST_LOCAL_NOTE = "window.list.local_note";
    WINDOW_LIST_EMPTY = "window.list.empty";
    WINDOW_LIST_LOAD_OLDER = "window.list.load_older";
    WINDOW_LIST_REDACTED_TITLE = "window.list.redacted_title";
    WINDOW_FOLDER_MISSING = "window.folder_missing";
    WINDOW_BASKETS_MISSING = "window.baskets_missing";

    // ── The set-up wizard (ADR-D13) ──────────────────────────────────────────────────────────
    //
    // Unconditional, on both platforms, although two of its pages exist on one platform only
    // (ADR-D13 §10): `no_catalogue_carries_a_key_the_program_does_not_ask_for` measures the two
    // TOML files against this list, so a `cfg` here would make the Windows build of the test
    // suite red the day somebody ran it — while a page behind a `cfg` costs the catalogue
    // nothing.
    SETUP_TITLE = "setup.title";
    SETUP_STEP = "setup.step";
    SETUP_BACK = "setup.back";
    SETUP_NEXT = "setup.next";
    SETUP_FINISH = "setup.finish";
    SETUP_NOT_AVAILABLE = "setup.not_available";

    // Why a value stands there as a line of text and not as a field (ADR-D13 §3: a disabled
    // field is a field that failed). None of these four names the variable — that is `doctor`'s
    // job, in English, outside the catalogue.
    SETUP_FIXED_OPERATOR = "setup.fixed.operator";
    SETUP_FIXED_ENROLLED = "setup.fixed.enrolled";
    SETUP_FIXED_MIRROR = "setup.fixed.mirror";
    SETUP_FIXED_VARIABLE = "setup.fixed.variable";
    SETUP_FACTS_TITLE = "setup.facts.title";

    SETUP_WELCOME_STEP = "setup.welcome.step";
    SETUP_WELCOME_TITLE = "setup.welcome.title";
    SETUP_WELCOME_TEXT = "setup.welcome.text";
    SETUP_WELCOME_RECORDED = "setup.welcome.recorded";
    SETUP_WELCOME_LANGUAGE = "setup.welcome.language";
    SETUP_WELCOME_LANGUAGE_HINT = "setup.welcome.language_hint";
    // The languages name themselves, and therefore read the same in both catalogues (see
    // `SAME_ON_PURPOSE` in tests/catalogs.rs): whoever lands in a window they cannot read has to
    // be able to find their own language in the list all the same.
    SETUP_LANGUAGE_DE = "setup.language.de";
    SETUP_LANGUAGE_EN = "setup.language.en";
    SETUP_WELCOME_COUNTERPART = "setup.welcome.counterpart";

    SETUP_SERVER_STEP = "setup.server.step";
    SETUP_SERVER_TITLE = "setup.server.title";
    SETUP_SERVER_TEXT = "setup.server.text";
    SETUP_SERVER_API = "setup.server.api";
    SETUP_SERVER_API_HINT = "setup.server.api_hint";
    SETUP_SERVER_AUTH = "setup.server.auth";
    SETUP_SERVER_AUTH_HINT = "setup.server.auth_hint";
    SETUP_SERVER_APP = "setup.server.app";
    SETUP_SERVER_APP_HINT = "setup.server.app_hint";

    SETUP_WORKSTATION_STEP = "setup.workstation.step";
    SETUP_WORKSTATION_TITLE = "setup.workstation.title";
    SETUP_WORKSTATION_TEXT = "setup.workstation.text";
    // The same page with the folder's place on it — Windows, where `window::MIRROR` puts that
    // field in. The page picks by what the document carries, not by a platform name.
    SETUP_WORKSTATION_TEXT_WITH_MIRROR = "setup.workstation.text_with_mirror";
    SETUP_WORKSTATION_DEVICE = "setup.workstation.device";
    SETUP_WORKSTATION_DEVICE_HINT = "setup.workstation.device_hint";
    SETUP_WORKSTATION_MIRROR = "setup.workstation.mirror";
    SETUP_WORKSTATION_MIRROR_HINT = "setup.workstation.mirror_hint";
    SETUP_WORKSTATION_PLACES = "setup.workstation.places";
    SETUP_WORKSTATION_PLACES_HINT = "setup.workstation.places_hint";
    SETUP_WORKSTATION_DATA = "setup.workstation.data";
    SETUP_WORKSTATION_STAGING = "setup.workstation.staging";
    SETUP_WORKSTATION_HOLDING = "setup.workstation.holding";

    SETUP_CODE_STEP = "setup.code.step";
    SETUP_CODE_TITLE = "setup.code.title";
    SETUP_CODE_TEXT = "setup.code.text";
    SETUP_CODE_LABEL = "setup.code.label";
    SETUP_CODE_HINT = "setup.code.hint";

    SETUP_SIGNIN_STEP = "setup.signin.step";
    SETUP_SIGNIN_TITLE = "setup.signin.title";
    SETUP_SIGNIN_TEXT = "setup.signin.text";
    SETUP_SIGNIN_WAITING = "setup.signin.waiting";
    SETUP_SIGNIN_SIGNED_IN = "setup.signin.signed_in";
    SETUP_SIGNIN_SKIP = "setup.signin.skip";

    SETUP_EXTENSION_STEP = "setup.extension.step";
    SETUP_EXTENSION_TITLE = "setup.extension.title";
    SETUP_EXTENSION_TEXT = "setup.extension.text";
    SETUP_EXTENSION_PATH = "setup.extension.path";
    SETUP_EXTENSION_BUTTON = "setup.extension.button";
    SETUP_EXTENSION_AGAIN = "setup.extension.again";
    SETUP_EXTENSION_ASKING = "setup.extension.asking";
    SETUP_EXTENSION_OFF = "setup.extension.off";
    SETUP_EXTENSION_ON = "setup.extension.on";
    SETUP_EXTENSION_SKIP = "setup.extension.skip";

    SETUP_DONE_STEP = "setup.done.step";
    SETUP_DONE_TITLE = "setup.done.title";
    SETUP_DONE_TEXT = "setup.done.text";
    SETUP_DONE_FOLDER = "setup.done.folder";
    SETUP_DONE_REOPEN = "setup.done.reopen";

    // What is wrong with a typed value. The shape only, and never a red border on its own
    // (ADR-D13 §8: the check is the one `edms_net` makes, the network is not asked).
    SETUP_WRONG_EMPTY = "setup.wrong.empty";
    SETUP_WRONG_SCHEME = "setup.wrong.scheme";
    SETUP_WRONG_HOST = "setup.wrong.host";
    SETUP_WRONG_PLAINTEXT = "setup.wrong.plaintext";
    SETUP_WRONG_USERINFO = "setup.wrong.userinfo";
    SETUP_WRONG_QUERY = "setup.wrong.query";
    SETUP_WRONG_TOO_LONG = "setup.wrong.too_long";
    SETUP_WRONG_PATH_ABSOLUTE = "setup.wrong.path_absolute";
    SETUP_WRONG_PATH_TAKEN = "setup.wrong.path_taken";
    SETUP_WRONG_CODE = "setup.wrong.code";

    // What the store's own door says when it refuses a value the page let through
    // (`setup::SettingRefused::user_key`). The page checks the shape; these are the answers only
    // the app can give, and they reach the user through the wizard's own message line.
    SETUP_WRONG_ADDRESS = "setup.wrong.address";
    SETUP_WRONG_NOT_YOURS = "setup.wrong.not_yours";
    SETUP_WRONG_PATH_HOLDS = "setup.wrong.path_holds";
    SETUP_WRONG_PATH_NOT_EMPTY = "setup.wrong.path_not_empty";
    SETUP_WRONG_CONTROL = "setup.wrong.control";
    SETUP_WRONG_LANGUAGE = "setup.wrong.language";
    SETUP_WRONG_NOT_STORED = "setup.wrong.not_stored";

    // ── The mirror: what stands in Explorer and in Finder ────────────────────────────────────
    MIRROR_BASKETS = "mirror.baskets";
    MIRROR_ARCHIVES = "mirror.archives";
    MIRROR_SEARCHES = "mirror.searches";
    MIRROR_README_NAME = "mirror.readme.name";
    MIRROR_README_BODY = "mirror.readme.body";
    MIRROR_TRUNCATED_NAME = "mirror.truncated.name";
    MIRROR_TRUNCATED_BODY = "mirror.truncated.body";

    // ── Sentences the engine and the app say to the user ─────────────────────────────────────
    NOTICE_SIGNING_OUT = "notice.signing_out";
    NOTICE_STOPPING = "notice.stopping";
    NOTICE_AWAITING_APPROVAL = "notice.awaiting_approval";
    NOTICE_ENROLLMENT_CODE_MISSING = "notice.enrollment_code_missing";
    NOTICE_SETUP_NEEDED = "notice.setup_needed";
    NOTICE_SETUP_RESTART = "notice.setup_restart";
    NOTICE_SESSION_ENDED = "notice.session_ended";
    NOTICE_DEVICE_CODE_EXPIRED = "notice.device_code_expired";
    NOTICE_LOGIN_REJECTED = "notice.login_rejected";
    NOTICE_STEP_UP_REQUIRED = "notice.step_up_required";
    NOTICE_SERVER_REFUSED = "notice.server_refused";
    NOTICE_SIGNED_IN_AS = "notice.signed_in_as";
    NOTICE_DEVICE_REGISTERED = "notice.device_registered";
    NOTICE_DEVICE_REGISTERED_AGAIN = "notice.device_registered_again";
    NOTICE_BASKET_PROGRESS_ONE = "notice.basket_progress.one";
    NOTICE_BASKET_PROGRESS_MANY = "notice.basket_progress.many";
    NOTICE_ERASED_BY_ORDER_ONE = "notice.erased_by_order.one";
    NOTICE_ERASED_BY_ORDER_MANY = "notice.erased_by_order.many";
    NOTICE_ACCESS_REVOKED_ONE = "notice.access_revoked.one";
    NOTICE_ACCESS_REVOKED_MANY = "notice.access_revoked.many";
    NOTICE_SPACE_RECLAIMED_ONE = "notice.space_reclaimed.one";
    NOTICE_SPACE_RECLAIMED_MANY = "notice.space_reclaimed.many";
    NOTICE_NO_FOLDER_ON_THIS_PLATFORM = "notice.no_folder_on_this_platform";
    NOTICE_NO_FOLDER_WITHOUT_BUNDLE = "notice.no_folder_without_bundle";
    NOTICE_MIRROR_PATH_NOT_UNICODE = "notice.mirror_path_not_unicode";
    NOTICE_DELIVERY_SIGNATURE = "notice.delivery_signature";
    NOTICE_KEY_SET_UNREADABLE = "notice.key_set_unreadable";
    NOTICE_SERVER_KEYS_REJECTED = "notice.server_keys_rejected";

    // ── What the app refuses, and why ────────────────────────────────────────────────────────
    ERROR_FOLDER_NOT_PROVISIONED = "error.folder_not_provisioned";
    ERROR_BASKETS_NOT_PROVISIONED = "error.baskets_not_provisioned";
    ERROR_OPEN_FAILED = "error.open_failed";
    ERROR_LOG_UNREADABLE = "error.log_unreadable";
    ERROR_LOGIN_ADDRESS = "error.login_address";
    ERROR_ALREADY_SIGNED_IN = "error.already_signed_in";
    ERROR_SIGN_IN_RUNNING = "error.sign_in_running";
    ERROR_NOBODY_SIGNED_IN = "error.nobody_signed_in";
    ERROR_AWAITING_APPROVAL_SIGN_IN = "error.awaiting_approval_sign_in";
    ERROR_OFFLINE_SIGN_IN = "error.offline_sign_in";
    ERROR_SIGN_OUT_NOT_STARTED = "error.sign_out_not_started";
    ERROR_NO_SIGN_IN_RUNNING = "error.no_sign_in_running";
    ERROR_ROW_NUMBER = "error.row_number";
    ERROR_FOLDER_NOT_AVAILABLE = "error.folder_not_available";
    ERROR_FOLDER_CHANNEL = "error.folder_channel";
    ERROR_FOLDER_SECRET = "error.folder_secret";

    // ── What the engine refuses, and why ─────────────────────────────────────────────────────
    ERROR_ENGINE_CONFIGURATION = "error.engine.configuration";
    ERROR_ENGINE_VAULT = "error.engine.vault";
    ERROR_ENGINE_STORE = "error.engine.store";
    ERROR_ENGINE_CRYPTO = "error.engine.crypto";
    ERROR_ENGINE_DIRECTORY = "error.engine.directory";
    ERROR_ENGINE_RUNTIME = "error.engine.runtime";
    ERROR_ENGINE_STOPPED = "error.engine.stopped";
    ERROR_ENGINE_NOT_SIGNED_IN = "error.engine.not_signed_in";
    ERROR_ENGINE_ENROLLMENT_CODE_MISSING = "error.engine.enrollment_code_missing";
    ERROR_ENGINE_REFUSED = "error.engine.refused";
    ERROR_ENGINE_SESSION_EXPIRED = "error.engine.session_expired";
    ERROR_ENGINE_NO_NETWORK = "error.engine.no_network";
    ERROR_ENGINE_SECURITY = "error.engine.security";
    ERROR_ENGINE_NO_FILE_SYSTEM = "error.engine.no_file_system";
    ERROR_ENGINE_INTERNAL = "error.engine.internal";

    // ── What Explorer and Finder show when the source cannot deliver ─────────────────────────
    ERROR_SOURCE_NOT_SIGNED_IN = "error.source.not_signed_in";
    ERROR_SOURCE_NO_NETWORK = "error.source.no_network";
    ERROR_SOURCE_NOT_FOUND = "error.source.not_found";
    ERROR_SOURCE_NO_ACCESS = "error.source.no_access";
    ERROR_SOURCE_INTEGRITY = "error.source.integrity";
    ERROR_SOURCE_INCOMPLETE = "error.source.incomplete";
    ERROR_SOURCE_ANCHOR_EXPIRED = "error.source.anchor_expired";
    ERROR_SOURCE_CANCELLED = "error.source.cancelled";
    ERROR_SOURCE_SINK = "error.source.sink";
    ERROR_SOURCE_SERVER = "error.source.server";
    ERROR_SOURCE_INTERNAL = "error.source.internal";

    // ── What the platform layer could not carry out ──────────────────────────────────────────
    ERROR_PLATFORM_NOT_READY = "error.platform.not_ready";
    ERROR_PLATFORM_NOT_FOUND = "error.platform.not_found";
    ERROR_PLATFORM_IN_USE = "error.platform.in_use";
    ERROR_PLATFORM_OPERATING_SYSTEM = "error.platform.operating_system";
    ERROR_PLATFORM_NOT_SUPPORTED = "error.platform.not_supported";

    // ── The macOS File Provider extension ────────────────────────────────────────────────────
    ERROR_PROVIDER_APP_NOT_REACHABLE = "error.provider.app_not_reachable";
    ERROR_PROVIDER_FOREIGN_IDENTIFIER = "error.provider.foreign_identifier";
    ERROR_PROVIDER_NO_TRASH = "error.provider.no_trash";
    ERROR_PROVIDER_NO_FILE = "error.provider.no_file";
    ERROR_PROVIDER_READ_ONLY = "error.provider.read_only";
    ERROR_PROVIDER_DELETE_REJECTED = "error.provider.delete_rejected";
    ERROR_PROVIDER_PAGE_EXPIRED = "error.provider.page_expired";
    ERROR_PROVIDER_STAGING = "error.provider.staging";
    ERROR_PROVIDER_FILE = "error.provider.file";
    ERROR_PROVIDER_CANCELLED = "error.provider.cancelled";

    // ── The sample data of `--demo` ──────────────────────────────────────────────────────────
    DEMO_ACCOUNT = "demo.account";
    DEMO_BASKET = "demo.basket";
    DEMO_CASE_SULZER = "demo.case.sulzer";
    DEMO_CASE_ENGINEERING = "demo.case.engineering";
    DEMO_CASE_SAFETY = "demo.case.safety";
    DEMO_CASE_NORTHPORT = "demo.case.northport";
    DEMO_CASE_PURCHASING = "demo.case.purchasing";
    DEMO_CASE_PERSONNEL = "demo.case.personnel";
    DEMO_CASE_QUALITY = "demo.case.quality";
    DEMO_CASE_FLEET = "demo.case.fleet";
    DEMO_SEARCH_INVOICES = "demo.search.invoices";
    DEMO_SEARCH_OFFERS = "demo.search.offers";
    DEMO_SEARCH_RECEIPTS = "demo.search.receipts";
    DEMO_LOADED = "demo.loaded";
    DEMO_LOADED_2_4 = "demo.loaded_2_4";
    DEMO_LOADED_1_1 = "demo.loaded_1_1";
    DEMO_LOADED_480 = "demo.loaded_480";
    DEMO_INGEST_WITH_BROWSER = "demo.ingest_with_browser";
    DEMO_INGEST_PLAIN = "demo.ingest_plain";
    DEMO_NEW_VERSION = "demo.new_version";
    DEMO_CONNECTION_RESTORED = "demo.connection_restored";
    DEMO_CONNECTION_LOST = "demo.connection_lost";
    DEMO_SPACE_RECLAIMED_STALE = "demo.space_reclaimed_stale";
    DEMO_SPACE_RECLAIMED_ASKED = "demo.space_reclaimed_asked";
    DEMO_NO_ACCESS = "demo.no_access";
    DEMO_ACCESS_REVOKED = "demo.access_revoked";
    DEMO_SECURITY_WARNING = "demo.security_warning";
    DEMO_INGEST_FAILED = "demo.ingest_failed";
    DEMO_SESSION_EXPIRED = "demo.session_expired";
    DEMO_DEVICE_APPROVED = "demo.device_approved";
    DEMO_SIGN_IN_NOT_STARTED = "demo.sign_in_not_started";
    DEMO_MIRROR_CLEARED = "demo.mirror_cleared";
}

const CATALOG_DE: &str = include_str!("../catalog/de.toml");
const CATALOG_EN: &str = include_str!("../catalog/en.toml");

/// The source text of a catalogue — the tests read it, nobody else has to.
pub const fn source(language: Language) -> &'static str {
    match language {
        Language::De => CATALOG_DE,
        Language::En => CATALOG_EN,
    }
}

/// Every sentence of one language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    language: Language,
    entry: BTreeMap<String, String>,
}

impl Catalog {
    /// The catalogue of a language — read once per process, then held.
    ///
    /// A catalogue that does not read is **not** an empty one: English stands in, and the fault
    /// stands in the log at `error` level. `tests/catalogs.rs` makes sure this way is never
    /// walked in a shipped build.
    pub fn of(language: Language) -> &'static Self {
        static HELD: [OnceLock<Catalog>; 2] = [OnceLock::new(), OnceLock::new()];
        let place = match language {
            Language::De => 0,
            Language::En => 1,
        };
        HELD[place].get_or_init(|| match Self::read(language) {
            Ok(catalogue) => catalogue,
            Err(error) => {
                tracing::error!(
                    language = language.tag(),
                    %error,
                    "the built-in text catalogue does not read; the user interface falls back to \
                     the key names."
                );
                Self { language, entry: BTreeMap::new() }
            }
        })
    }

    /// Reads the built-in catalogue of a language.
    ///
    /// # Errors
    ///
    /// [`ReaderError`] with the line number when the catalogue is outside the accepted subset.
    pub fn read(language: Language) -> Result<Self, ReaderError> {
        Ok(Self { language, entry: crate::reader::read(source(language))? })
    }

    /// Which language this catalogue speaks.
    pub const fn language(&self) -> Language {
        self.language
    }

    /// The sentence for a key.
    ///
    /// A key that is not in the catalogue cannot occur in a tested build (`tests/catalogs.rs`
    /// compares [`KEYS`] with every catalogue). If it does occur all the same, the path stands
    /// there instead of the sentence — visible in the window and loud in the log, never an empty
    /// place that looks like a working user interface.
    pub fn text(&self, key: Key) -> &str {
        match self.entry.get(key.path()) {
            Some(text) => text,
            None => {
                tracing::error!(
                    key = key.path(),
                    language = self.language.tag(),
                    "the text catalogue has no sentence for this key."
                );
                key.path()
            }
        }
    }

    /// The sentence for a key, with its placeholders filled in.
    ///
    /// An unfilled placeholder stays standing (`{account}` is then visible) and is reported: half
    /// a sentence is a defect, and one that can be seen gets fixed.
    pub fn format(&self, key: Key, arguments: &[(&str, &str)]) -> String {
        let text = self.text(key);
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        let mut open = Vec::new();
        while let Some(start) = rest.find('{') {
            out.push_str(&rest[..start]);
            let after = &rest[start + 1..];
            let Some(end) = after.find('}') else {
                out.push_str(&rest[start..]);
                rest = "";
                break;
            };
            let name = &after[..end];
            match arguments.iter().find(|(n, _)| *n == name) {
                Some((_, value)) => out.push_str(value),
                None => {
                    open.push(name.to_owned());
                    out.push('{');
                    out.push_str(name);
                    out.push('}');
                }
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        if !open.is_empty() {
            tracing::error!(
                key = key.path(),
                language = self.language.tag(),
                open = open.join(", "),
                "a sentence of the text catalogue was rendered with an unfilled placeholder."
            );
        }
        out
    }

    /// Every key with its sentence, sorted — what the catalogue tests compare.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entry.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The whole catalogue as a JSON object, for the window's web view.
    ///
    /// The page must not carry any sentence of its own (ADR-D07: the user interface is one
    /// catalogue, not two). It therefore receives all of it and looks up by the same dotted paths
    /// the Rust side uses.
    ///
    /// The text is written for a `<script>` block: every `<` goes out as `<`, so that a
    /// sentence can never close the block, and U+2028/U+2029 are escaped, because in JavaScript
    /// before ES2019 they are line terminators inside a string.
    pub fn as_json(&self) -> String {
        let mut out = String::from("{");
        for (place, (key, text)) in self.entry.iter().enumerate() {
            if place > 0 {
                out.push(',');
            }
            write_json_string(&mut out, key);
            out.push(':');
            write_json_string(&mut out, text);
        }
        out.push('}');
        out
    }
}

/// One JSON string, escaped so that it survives both JSON and a `<script>` block.
fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_region_does_not_make_a_second_language() {
        for tag in ["de", "de-AT", "de_DE", "DE", "de-CH-1901"] {
            assert_eq!(Language::from_tag(tag), Some(Language::De), "{tag}");
        }
        for tag in ["en", "en-GB", "en_US", "EN"] {
            assert_eq!(Language::from_tag(tag), Some(Language::En), "{tag}");
        }
        for tag in ["fr", "nl-BE", "", "x"] {
            assert_eq!(Language::from_tag(tag), None, "{tag}");
        }
    }

    #[test]
    fn the_first_understood_tag_of_the_system_wins() {
        assert_eq!(Language::resolve(["fr-FR", "de-AT", "en-GB"]), Language::De);
        assert_eq!(Language::resolve(["en-US", "de-DE"]), Language::En);
    }

    #[test]
    fn a_system_that_offers_nothing_understood_gets_the_fallback() {
        assert_eq!(Language::resolve(["fr-FR", "nl-NL"]), FALLBACK);
        assert_eq!(Language::resolve(std::iter::empty()), FALLBACK);
    }

    #[test]
    fn an_unset_or_unreadable_override_does_not_decide() {
        assert_eq!(Language::from_value(None), None);
        assert_eq!(Language::from_value(Some("   ")), None);
        assert_eq!(Language::from_value(Some("fr")), None);
        assert_eq!(Language::from_value(Some(" de-AT ")), Some(Language::De));
    }

    #[test]
    fn both_catalogues_read() {
        for language in Language::ALL {
            let catalogue = Catalog::read(language).unwrap_or_else(|e| panic!("{language}: {e}"));
            assert_eq!(catalogue.language(), language);
            assert!(catalogue.entries().count() >= KEYS.len(), "{language}");
        }
    }

    #[test]
    fn a_placeholder_is_filled_by_name() {
        let catalogue = Catalog::of(Language::En);
        let line = catalogue.format(key::STATUS_SIGNED_IN_AS, &[("account", "Erika Mustermann")]);
        assert!(line.contains("Erika Mustermann"), "{line}");
        assert!(!line.contains('{'), "{line}");
    }

    #[test]
    fn an_unfilled_placeholder_stays_visible_instead_of_disappearing() {
        // Half a sentence that reads smoothly is worse than one that shows its gap: the second
        // gets reported, the first does not.
        let catalogue = Catalog::of(Language::En);
        let line = catalogue.format(key::STATUS_SIGNED_IN_AS, &[]);
        assert!(line.contains("{account}"), "{line}");
    }

    #[test]
    fn a_surplus_argument_changes_nothing() {
        let catalogue = Catalog::of(Language::De);
        let plain = catalogue.text(key::MENU_QUIT);
        assert_eq!(catalogue.format(key::MENU_QUIT, &[("account", "x")]), plain);
    }

    #[test]
    fn the_json_for_the_web_view_closes_no_script_block() {
        for language in Language::ALL {
            let json = Catalog::of(language).as_json();
            assert!(json.starts_with('{') && json.ends_with('}'), "{language}");
            assert!(!json.contains('<'), "{language}: a `<` would be able to close the block");
            assert!(json.contains("\"menu.open\":"), "{language}");
        }
    }
}
