//! What the menu on the icon shows — as a pure function of the [`DisplayState`].
//!
//! The menu itself (tray-icon) cannot be built and cannot be tested without an event loop. That is
//! why every decision it makes stands here: which status line, which entries are active, whether
//! "sign in …" or "sign out", which dot on the icon. `tray.rs` only puts it into practice.
//!
//! Every text comes out of the catalogue ([`edms_i18n`]) and none out of a string literal. The
//! catalogue is handed **in**, not fetched: that way the tests can check the same menu in both
//! languages without setting an environment variable for the whole process.

use edms_i18n::{Catalog, key};

use crate::display::{DisplayState, Status};
use crate::icon::IconState;

/// Identifier of the (never clickable) status entry.
pub const IDENTIFIER_STATUS: &str = "status";

/// The platform's file manager — it appears in the menu text (brief: "open the folder in
/// Explorer" on Windows, "… in Finder" on macOS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileManager {
    /// Windows.
    Explorer,
    /// macOS.
    Finder,
    /// Everything else (only for builds outside the target platforms).
    Other,
}

impl FileManager {
    /// This machine's file manager.
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Finder
        } else if cfg!(windows) {
            Self::Explorer
        } else {
            Self::Other
        }
    }
}

/// What the menu's single account entry does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    /// Start the device flow.
    SignIn,
    /// Sign out and clear the mirror.
    SignOut,
    /// A sign-in is already running: show the window with the code, do not start a second flow.
    CodeShow,
    /// Nothing is possible (the device is waiting for approval); the entry is greyed out.
    No,
}

/// The menu's commands, with their identifier as a [`tray_icon::menu::MenuId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuCommand {
    /// Open elasticdms (`menu.open`).
    Open,
    /// Open the folder in Explorer or Finder (`menu.folder.*`).
    Folder,
    /// Open the mail baskets in the mirror (`menu.baskets`).
    Baskets,
    /// Sign in, sign out, or show the code of a sign-in in progress (`menu.sign_in` and its
    /// neighbours).
    Account,
    /// Quit (`menu.quit`).
    Stop,
}

impl MenuCommand {
    const ALL: [Self; 5] = [Self::Open, Self::Folder, Self::Baskets, Self::Account, Self::Stop];

    /// The identifier in the menu.
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Folder => "folder",
            Self::Baskets => "baskets",
            Self::Account => "account",
            Self::Stop => "quit",
        }
    }

    /// The command for an identifier; `None` for the status entry and anything foreign.
    pub fn from_identifier(identifier: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.identifier() == identifier)
    }
}

/// Everything menu and icon show for one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuState {
    /// The greyed-out first line, e.g. "Signed in as Erika Mustermann".
    pub status_line: String,
    /// "Open folder in File Explorer" or "… in Finder".
    pub folder_text: &'static str,
    /// Whether the folder is set up.
    pub folder_active: bool,
    /// Whether the mail baskets can be opened.
    pub baskets_active: bool,
    /// Text of the account entry.
    pub account_text: &'static str,
    /// What the account entry does; on [`AccountAction::No`] it is greyed out.
    pub account_action: AccountAction,
    /// The dot on the icon.
    pub icon: IconState,
    /// The tooltip when hovering over the icon.
    pub tooltip: String,
}

/// The state in words, **without** the account name.
///
/// That is what the window header needs: there the name already stands large above it, and "Erika
/// Mustermann" over "Signed in as Erika Mustermann" would say the same thing twice. In the menu
/// there is no such heading, which is why [`status_line`] names the account there.
pub fn status_short(display: &DisplayState, catalogue: &Catalog) -> String {
    if let Some(code) = &display.login_code {
        return catalogue.format(key::STATUS_SIGNING_IN, &[("code", &code.user_code)]);
    }
    catalogue
        .text(match display.status {
            Status::SignedIn => key::STATUS_SIGNED_IN,
            Status::NotSignedIn => key::STATUS_NOT_SIGNED_IN,
            Status::LoginRequired => key::STATUS_LOGIN_REQUIRED,
            Status::Offline => key::STATUS_OFFLINE,
            Status::AwaitingApproval => key::STATUS_AWAITING_APPROVAL,
            Status::SecurityWarning => key::STATUS_SECURITY_WARNING,
        })
        .to_owned()
}

/// The status line of the menu: the same statement as [`status_short`], only with the account
/// name added.
///
/// The guarantee that never lets the two drift apart: the long line always starts with the short
/// one. Tested in `both_status_forms_say_the_same_thing` — otherwise something different would
/// stand in the menu from what stands in the window, and the user would not know which one
/// holds.
pub fn status_line(display: &DisplayState, catalogue: &Catalog) -> String {
    let state = match (&display.login_code, display.status, &display.account) {
        (None, Status::SignedIn, Some(account)) => {
            catalogue.format(key::STATUS_SIGNED_IN_AS, &[("account", account)])
        }
        _ => status_short(display, catalogue),
    };
    // The hint comes **after** the state, never in its place: otherwise one failed action would
    // mean the line no longer says whether anybody is signed in. The guarantee "the long line
    // starts with the short one" is preserved, because it is only appended to.
    match &display.hint {
        Some(hint) if !hint.is_empty() => {
            catalogue.format(key::STATUS_WITH_HINT, &[("state", &state), ("hint", hint)])
        }
        _ => state,
    }
}

/// What the account entry does in this state.
pub fn account_action(display: &DisplayState) -> AccountAction {
    if display.login_code.is_some() {
        return AccountAction::CodeShow;
    }
    match display.status {
        // Without approval the server refuses every sign-in (geraete-auth, token endpoint:
        // `403 device-pending-approval`); an active entry would be a button that only fails.
        Status::AwaitingApproval => AccountAction::No,
        Status::NotSignedIn | Status::LoginRequired => AccountAction::SignIn,
        Status::SignedIn => AccountAction::SignOut,
        // Offline, or with a warning, it depends on whether anybody was signed in at all.
        Status::Offline | Status::SecurityWarning if display.account.is_some() => {
            AccountAction::SignOut
        }
        Status::Offline | Status::SecurityWarning => AccountAction::SignIn,
    }
}

/// The whole menu state.
pub fn menu_state(
    display: &DisplayState,
    file_manager: FileManager,
    catalogue: &'static Catalog,
) -> MenuState {
    let status_line = status_line(display, catalogue);
    let account_action = account_action(display);
    MenuState {
        tooltip: catalogue.format(key::MENU_TOOLTIP, &[("status", &status_line)]),
        status_line,
        folder_text: catalogue.text(match file_manager {
            FileManager::Explorer => key::MENU_FOLDER_EXPLORER,
            FileManager::Finder => key::MENU_FOLDER_FINDER,
            FileManager::Other => key::MENU_FOLDER_PLAIN,
        }),
        folder_active: display.folder.is_some(),
        baskets_active: display.baskets.is_some(),
        account_text: catalogue.text(match account_action {
            AccountAction::SignOut => key::MENU_SIGN_OUT,
            AccountAction::CodeShow => key::MENU_SIGNING_IN,
            AccountAction::SignIn | AccountAction::No => key::MENU_SIGN_IN,
        }),
        account_action,
        icon: IconState::from_status(display.status),
    }
}

/// Text for a menu entry: `&` doubled.
///
/// On Windows a single `&` makes the following letter a keyboard mnemonic and disappears; "Müller
/// & Söhne" would become "Müller  Söhne". muda takes `&&` on both platforms as one `&` (on macOS
/// through `strip_mnemonic`).
pub fn for_menu(text: &str) -> String {
    text.replace('&', "&&")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use edms_i18n::Language;

    use super::*;
    use crate::display::LoginCode;

    /// The German catalogue — the menu's texts were written against it, and the tests read like
    /// the menu the user sees. `the_menu_speaks_every_language` checks the other one.
    fn german() -> &'static Catalog {
        Catalog::of(Language::De)
    }

    fn display(status: Status, account: Option<&str>) -> DisplayState {
        DisplayState {
            account: account.map(str::to_owned),
            status,
            folder: Some(PathBuf::from("/o")),
            baskets: Some(PathBuf::from("/o/Briefkörbe")),
            login_code: None,
            hint: None,
        }
    }

    fn code() -> LoginCode {
        LoginCode {
            user_code: "WQPX-7TRM".into(),
            address: "https://anmeldung.example/geraet".into(),
            address_complete: None,
            anchor: Some("K7-M4".into()),
        }
    }

    #[test]
    fn signed_in_shows_the_account_and_offers_signing_out() {
        let m = menu_state(
            &display(Status::SignedIn, Some("Erika Mustermann")),
            FileManager::Finder,
            german(),
        );
        assert_eq!(m.status_line, "Angemeldet als Erika Mustermann");
        assert_eq!((m.account_text, m.account_action), ("Abmelden", AccountAction::SignOut));
        assert_eq!(m.icon, IconState::Normal);
        assert_eq!(m.tooltip, "elasticdms – Angemeldet als Erika Mustermann");
    }

    #[test]
    fn both_status_forms_say_the_same_thing() {
        // The window header shows the short form, the menu the long one. They must never
        // contradict each other; the guarantee is: the long one starts with the short one.
        for status in [
            Status::SignedIn,
            Status::NotSignedIn,
            Status::LoginRequired,
            Status::Offline,
            Status::AwaitingApproval,
            Status::SecurityWarning,
        ] {
            for account in [None, Some("Erika Mustermann")] {
                for login_code in [None, Some(code())] {
                    let mut s = display(status, account);
                    s.login_code = login_code;
                    let (long, short) = (status_line(&s, german()), status_short(&s, german()));
                    assert!(long.starts_with(&short), "\"{long}\" does not start with \"{short}\"");
                    assert!(!short.contains("Erika"), "the short form names the account: {short}");
                }
            }
        }
        let signed_in = display(Status::SignedIn, Some("Erika Mustermann"));
        assert_eq!(status_line(&signed_in, german()), "Angemeldet als Erika Mustermann");
        assert_eq!(status_short(&signed_in, german()), "Angemeldet");
    }

    #[test]
    fn every_status_has_the_status_line_it_should() {
        let expected = [
            (Status::NotSignedIn, "Nicht angemeldet"),
            (Status::LoginRequired, "Anmeldung erforderlich"),
            (Status::Offline, "Offline"),
            (Status::AwaitingApproval, "Gerät wartet auf Freigabe"),
        ];
        for (status, row) in expected {
            assert_eq!(status_line(&display(status, Some("E. M.")), german()), row, "{status:?}");
        }
    }

    #[test]
    fn not_signed_in_and_expired_offer_signing_in_with_a_notice_dot() {
        for status in [Status::NotSignedIn, Status::LoginRequired] {
            let m = menu_state(&display(status, None), FileManager::Explorer, german());
            assert_eq!((m.account_text, m.account_action), ("Anmelden …", AccountAction::SignIn));
            assert_eq!(m.icon, IconState::Notice, "{status:?}");
        }
    }

    #[test]
    fn without_approval_signing_in_is_greyed_out() {
        let m = menu_state(&display(Status::AwaitingApproval, None), FileManager::Finder, german());
        assert_eq!((m.account_text, m.account_action), ("Anmelden …", AccountAction::No));
    }

    #[test]
    fn a_sign_in_in_progress_shows_the_code_instead_of_starting_a_second_flow() {
        let mut s = display(Status::NotSignedIn, None);
        s.login_code = Some(code());
        let m = menu_state(&s, FileManager::Finder, german());
        assert_eq!(m.status_line, "Anmeldung läuft – Code WQPX-7TRM");
        assert_eq!(
            (m.account_text, m.account_action),
            ("Anmeldung läuft …", AccountAction::CodeShow)
        );
    }

    #[test]
    fn offline_with_an_account_offers_signing_out_without_one_signing_in() {
        let with =
            menu_state(&display(Status::Offline, Some("E. M.")), FileManager::Finder, german());
        assert_eq!(with.account_action, AccountAction::SignOut);
        assert_eq!(with.icon, IconState::Offline);
        let without = menu_state(&display(Status::Offline, None), FileManager::Finder, german());
        assert_eq!(without.account_action, AccountAction::SignIn);
    }

    #[test]
    fn a_security_warning_sets_the_warning_dot() {
        let m = menu_state(
            &display(Status::SecurityWarning, Some("E. M.")),
            FileManager::Finder,
            german(),
        );
        assert_eq!(m.icon, IconState::Warning);
        assert!(m.status_line.starts_with("Sicherheitswarnung"));
    }

    #[test]
    fn without_folders_being_set_up_their_entries_are_greyed_out() {
        let mut s = display(Status::NotSignedIn, None);
        s.folder = None;
        s.baskets = None;
        let m = menu_state(&s, FileManager::Explorer, german());
        assert!(!m.folder_active && !m.baskets_active);
    }

    #[test]
    fn the_file_manager_stands_in_the_folder_entry() {
        let s = display(Status::SignedIn, Some("E. M."));
        assert_eq!(
            menu_state(&s, FileManager::Explorer, german()).folder_text,
            "Ordner im Explorer öffnen"
        );
        assert_eq!(
            menu_state(&s, FileManager::Finder, german()).folder_text,
            "Ordner im Finder öffnen"
        );
    }

    #[test]
    fn the_menu_speaks_every_language_and_not_a_word_of_another() {
        // The point of the whole exercise: the same state, two catalogues, and no German left in
        // the English menu.
        let state = display(Status::SignedIn, Some("Erika Mustermann"));
        let english = menu_state(&state, FileManager::Finder, Catalog::of(Language::En));
        assert_eq!(english.status_line, "Signed in as Erika Mustermann");
        assert_eq!(english.account_text, "Sign out");
        assert_eq!(english.folder_text, "Open folder in Finder");
        assert_eq!(english.tooltip, "elasticdms – Signed in as Erika Mustermann");

        // And in every language a whole sentence, never a key path and never a gap.
        for language in Language::ALL {
            let catalogue = Catalog::of(language);
            let m = menu_state(&state, FileManager::Explorer, catalogue);
            for text in [&m.status_line, &m.tooltip, &m.folder_text.to_owned()] {
                assert!(!text.is_empty(), "{language}");
                assert!(!text.contains('{'), "{language}: {text}");
                assert!(!text.starts_with("menu."), "{language}: {text}");
            }
        }
    }

    #[test]
    fn every_menu_identifier_leads_back_to_its_command() {
        for b in MenuCommand::ALL {
            assert_eq!(MenuCommand::from_identifier(b.identifier()), Some(b));
        }
        assert_eq!(MenuCommand::from_identifier(IDENTIFIER_STATUS), None);
        assert_eq!(MenuCommand::from_identifier("foreign"), None);
    }

    #[test]
    fn an_ampersand_in_the_account_name_stays_in_the_menu() {
        assert_eq!(for_menu("Angemeldet als Müller & Söhne"), "Angemeldet als Müller && Söhne");
    }
}
