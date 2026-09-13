//! The icon in the taskbar or menu bar, together with its menu.
//!
//! Only the implementation stands here; **what** the menu shows is decided by [`crate::menu`] as a
//! pure function of the display state. The reason for the split: a menu can neither be built nor
//! queried without a running event loop — but the decisions have to be testable. This file may
//! therefore decide nothing that `menu.rs` has not decided already.
//!
//! The layout follows the brief (ADR-D07, requirements):
//!
//! ```text
//! Signed in as Erika Mustermann     (greyed out, never clickable)
//! ─────────────────────────────
//! Open elasticdms
//! Open folder in Finder             (on Windows: "… in File Explorer")
//! Open mailbaskets
//! ─────────────────────────────
//! Sign out                          (or "Sign in …", depending on the state)
//! ─────────────────────────────
//! Quit
//! ```
//!
//! Every one of these lines comes out of the text catalogue; the layout above is the English one.
//!
//! Platform differences, both of them deliberate:
//!
//! * **macOS:** a template icon (`with_icon_as_template`), so that the menu bar colours it for
//!   light and dark itself. A left click opens the menu — that is what every program does there.
//! * **Windows:** a coloured icon; **a left click opens the window**, the menu comes on a right
//!   click. That too is the habit of the platform (OneDrive, Teams); a left click that unfolded a
//!   menu there would strike the user as being in the wrong place.

use edms_i18n::{Catalog, key};
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use crate::icon::{self, IconState, Image, SIZE_TRAY, STYLE_TRAY};
use crate::menu::{AccountAction, IDENTIFIER_STATUS, MenuCommand, MenuState, for_menu};

/// The icon could not be created or could not be changed.
///
/// Diagnostic only: this error ends the start, and the sentence goes to the error output where an
/// administrator reads it (`main::run`).
#[derive(Debug, thiserror::Error)]
pub enum TrayError {
    /// The operating system did not accept the icon.
    #[error(
        "the icon in the taskbar or menu bar could not be created: {0}. Without the icon \
         elasticdms would have no controls at all, so the start is aborted"
    )]
    Icon(#[from] tray_icon::Error),
    /// The drawn image does not match what the system expects.
    #[error("the drawn icon was not accepted: {0}")]
    Image(#[from] tray_icon::BadIcon),
    /// The menu could not be assembled.
    #[error("the menu on the icon could not be assembled: {0}")]
    Menu(#[from] tray_icon::menu::Error),
}

/// The icon with its menu.
///
/// It holds on to the entries: `muda` does not hand an entry back once it has been appended, and
/// without the handles neither a label nor "greyed out" could be changed later — the menu would
/// have to be rebuilt on every change and would close under the user's hand while doing so.
pub struct Tray {
    icon: TrayIcon,
    status: MenuItem,
    folder: MenuItem,
    baskets: MenuItem,
    account: MenuItem,
    /// The state last shown — whatever has not changed is not touched.
    shown: MenuState,
    /// Only held: for as long as the menu lives, it lives on its icon.
    _menu: Menu,
}

impl Tray {
    /// Creates icon and menu. Has to happen on the event loop's thread.
    pub fn new(display: &MenuState, catalogue: &Catalog) -> Result<Self, TrayError> {
        let status =
            MenuItem::with_id(IDENTIFIER_STATUS, for_menu(&display.status_line), false, None);
        let open = entry(MenuCommand::Open, catalogue.text(key::MENU_OPEN), true);
        let folder = entry(MenuCommand::Folder, display.folder_text, display.folder_active);
        let baskets =
            entry(MenuCommand::Baskets, catalogue.text(key::MENU_BASKETS), display.baskets_active);
        let account = entry(MenuCommand::Account, display.account_text, account_active(display));
        let stop = entry(MenuCommand::Stop, catalogue.text(key::MENU_QUIT), true);

        let menu = Menu::new();
        menu.append_items(&[
            &status,
            &PredefinedMenuItem::separator(),
            &open,
            &folder,
            &baskets,
            &PredefinedMenuItem::separator(),
            &account,
            &PredefinedMenuItem::separator(),
            &stop,
        ])?;

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_tooltip(&display.tooltip)
            .with_icon(image(display.icon)?)
            .with_icon_as_template(STYLE_TRAY == icon::IconStyle::Template)
            // See the module header: on Windows the left click belongs to the window.
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .with_menu_on_right_click(true)
            .build()?;

        Ok(Self { icon, status, folder, baskets, account, shown: display.clone(), _menu: menu })
    }

    /// Enters a new state.
    ///
    /// Only the differences: another `set_icon` with the same image makes the icon flicker
    /// visibly on Windows, and a `set_text` while the menu stands open pulls the entry out from
    /// under the user's pointer.
    pub fn update(&mut self, display: &MenuState) -> Result<(), TrayError> {
        if *display == self.shown {
            return Ok(());
        }
        if display.status_line != self.shown.status_line {
            self.status.set_text(for_menu(&display.status_line));
        }
        if display.folder_text != self.shown.folder_text {
            self.folder.set_text(display.folder_text);
        }
        if display.folder_active != self.shown.folder_active {
            self.folder.set_enabled(display.folder_active);
        }
        if display.baskets_active != self.shown.baskets_active {
            self.baskets.set_enabled(display.baskets_active);
        }
        if display.account_text != self.shown.account_text {
            self.account.set_text(display.account_text);
        }
        if account_active(display) != account_active(&self.shown) {
            self.account.set_enabled(account_active(display));
        }
        if display.tooltip != self.shown.tooltip {
            self.icon.set_tooltip(Some(&display.tooltip))?;
        }
        if display.icon != self.shown.icon {
            self.icon.set_icon(Some(image(display.icon)?))?;
        }
        self.shown = display.clone();
        Ok(())
    }

    /// What the account entry currently does — the event loop asks here on a click, so that
    /// "sign in" and "sign out" are not decided in two places.
    pub fn account_action(&self) -> AccountAction {
        self.shown.account_action
    }
}

/// A menu entry with the identifier of its command.
fn entry(command: MenuCommand, text: &str, active: bool) -> MenuItem {
    MenuItem::with_id(command.identifier(), for_menu(text), active, None)
}

/// The account entry is greyed out only when there really is nothing to do.
fn account_active(display: &MenuState) -> bool {
    display.account_action != AccountAction::No
}

/// Draws the tray icon and hands it over in the form `tray-icon` expects.
fn image(state: IconState) -> Result<Icon, tray_icon::BadIcon> {
    let Image { width, height, rgba } = icon::draw(SIZE_TRAY, STYLE_TRAY, state);
    Icon::from_rgba(rgba, width, height)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::display::{DisplayState, Status};
    use crate::menu::{FileManager, menu_state};

    fn display(status: Status, account: Option<&str>) -> MenuState {
        menu_state(
            &DisplayState {
                account: account.map(str::to_owned),
                status,
                folder: Some(PathBuf::from("/o")),
                baskets: Some(PathBuf::from("/o/Briefkörbe")),
                login_code: None,
                hint: None,
            },
            FileManager::current(),
            Catalog::of(edms_i18n::Language::De),
        )
    }

    #[test]
    fn only_the_account_entry_without_a_possible_action_is_greyed_out() {
        assert!(account_active(&display(Status::SignedIn, Some("E. M."))));
        assert!(account_active(&display(Status::NotSignedIn, None)));
        assert!(!account_active(&display(Status::AwaitingApproval, None)));
    }

    #[test]
    fn every_state_yields_an_icon_in_the_size_of_the_tray() {
        // `Icon::from_rgba` rejects an image whose bytes do not match width and height; this test
        // is the proof that icon.rs and tray-icon agree.
        for state in [IconState::Normal, IconState::Notice, IconState::Offline, IconState::Warning]
        {
            assert!(image(state).is_ok(), "{state:?}");
        }
        let signed = icon::draw(SIZE_TRAY, STYLE_TRAY, IconState::Normal);
        assert_eq!((signed.width, signed.height), (SIZE_TRAY, SIZE_TRAY));
    }

    #[test]
    fn the_menu_carries_every_identifier_the_loop_expects() {
        // The identifiers are the whole contract between menu and event loop; a typo here would
        // mean a menu entry that silently does nothing.
        for command in [
            MenuCommand::Open,
            MenuCommand::Folder,
            MenuCommand::Baskets,
            MenuCommand::Account,
            MenuCommand::Stop,
        ] {
            assert_eq!(MenuCommand::from_identifier(command.identifier()), Some(command));
        }
        assert_eq!(
            MenuCommand::from_identifier(IDENTIFIER_STATUS),
            None,
            "the status line is not a command"
        );
    }
}
