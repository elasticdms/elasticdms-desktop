//! The event loop: the one thread that owns icon, menu and window.
//!
//! The loop belongs to the program, not to the window (ADR-D07). It carries on when no window is
//! open and builds a new one on request — which is why the icon survives the window being closed,
//! and why "open elasticdms" still reacts after hours without a window.
//!
//! Four sources of events come together here, all through the same route ([`EventLoopProxy`]), so
//! that nothing works on the state alongside:
//!
//! * the **menu** on the icon (`muda`), the **icon** itself (a left click on Windows),
//! * the **page** in the window (`window.ipc.postMessage`),
//! * the **source** ([`DisplaySource::observe`]) — it wakes from any thread at all when state or
//!   log have changed,
//! * a **second start** of the same app ([`crate::single_instance`]).
//!
//! **A wake reloads the list instead of extending it.** That is not convenience: when a document is
//! erased on order, older rows lose their name too (`edms_core::log`). Only a replacement gets the
//! name back out of an already open window; a mere append would leave it standing at the top.

use std::convert::Infallible;
use std::sync::Arc;

use edms_core::log::LogEntry;
use edms_i18n::{Catalog, key};
use tao::event::{Event as TaoEvent, StartCause, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy, EventLoopWindowTarget};
use tray_icon::menu::{MenuEvent, MenuId};
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};

use crate::display::{DisplayError, DisplaySource, DisplayState};
use crate::menu::{AccountAction, FileManager, MenuCommand, MenuState, menu_state};
use crate::message::{Mode, Notice, Request, Row, StateView};
use crate::single_instance::{Guard, InstanceError};
use crate::tray::{Tray, TrayError};
use crate::window::{PageCall, Window};

/// This many rows one page of the list fetches. Enough to fill the screen when the window opens,
/// few enough that the first picture does not wait on the whole database.
pub const PAGE: usize = 25;

/// Everything that comes into the loop.
///
/// `Debug` is written out by hand below: one variant carries a built engine, and neither it nor
/// the abort beside it belongs in a line that only says which event arrived.
pub enum Event {
    /// A menu entry was clicked.
    Menu(MenuId),
    /// Something happened on the icon itself (on Windows: a left click opens the window).
    Icon(Box<TrayIconEvent>),
    /// The page in the window sent something.
    Page(PageCall),
    /// The source reports: state or log have changed.
    Wake,
    /// A second start asks for the window.
    WindowShow,
    /// The engine a finished set-up made possible is up — or did not come up.
    ///
    /// It is built on a thread of its own: `EngineView::start` opens the keychain (which may put
    /// a system dialog in front of the user), connects the platform layer and starts the sign-in.
    /// On the user-interface thread that would be a frozen window, and on macOS an app the system
    /// marks as "not responding".
    Engine(Box<Result<crate::wiring::EngineView, crate::wiring::StartupAbort>>),
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Menu(id) => f.debug_tuple("Menu").field(id).finish(),
            Self::Icon(event) => f.debug_tuple("Icon").field(event).finish(),
            Self::Page(call) => f.debug_tuple("Page").field(call).finish(),
            Self::Wake => f.write_str("Wake"),
            Self::WindowShow => f.write_str("WindowShow"),
            // Not the view and not the abort: the abort names addresses, the view names the
            // state, and neither belongs in a line that only says which event arrived.
            Self::Engine(built) => f.debug_tuple("Engine").field(&built.is_ok()).finish(),
        }
    }
}

impl From<PageCall> for Event {
    fn from(call: PageCall) -> Self {
        Self::Page(call)
    }
}

/// Starting the user interface failed — without an icon there is no way to operate it, so no going on.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The icon could not be created.
    #[error(transparent)]
    Tray(#[from] TrayError),
    /// The back channel for a second start could not be set up.
    #[error(transparent)]
    Instance(#[from] InstanceError),
}

/// Starts icon, menu and event loop. Never returns: `Stop` exits the process.
///
/// `guard` holds the single-instance lock; it has to live for as long as the app runs, and is
/// therefore handed into the loop.
///
/// `waiting_for_setup` says that `source` is the one of a workstation that has not been told
/// where its server is (`crate::awaiting`). Only such a run builds an engine when the wizard
/// reaches its last page; every other one already has its engine, and the values the wizard
/// stores reach it at the next start the ordinary way.
pub fn start(
    source: Arc<dyn DisplaySource>,
    window_on_start: bool,
    guard: Option<Guard>,
    catalogue: &'static Catalog,
    waiting_for_setup: bool,
) -> Result<Infallible, StartupError> {
    // Only macOS needs the `mut`: `set_activation_policy` takes the loop mutably. Without this
    // exception the Windows build would report an unnecessary `mut` — and `-D warnings` would turn
    // that into an error there.
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut, reason = "only macOS changes the loop"))]
    let mut event_loop = EventLoopBuilder::<Event>::with_user_event().build();
    // macOS: no dock icon, no application menu — elasticdms is an accessory of the menu bar
    // (ADR-D07). Has to happen before the first window.
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }

    let messenger = event_loop.create_proxy();
    // muda and tray-icon report from callbacks of their own; without this forwarding the loop
    // would never see them and the window would only react on the next mouse movement.
    MenuEvent::set_event_handler(Some({
        let messenger = messenger.clone();
        move |e: MenuEvent| {
            let _ = messenger.send_event(Event::Menu(e.id));
        }
    }));
    TrayIconEvent::set_event_handler(Some({
        let messenger = messenger.clone();
        move |e: TrayIconEvent| {
            let _ = messenger.send_event(Event::Icon(Box::new(e)));
        }
    }));
    source.observe(Box::new({
        let messenger = messenger.clone();
        move || {
            let _ = messenger.send_event(Event::Wake);
        }
    }));
    if let Some(guard) = &guard {
        let messenger = messenger.clone();
        guard.listen(Box::new(move || messenger.send_event(Event::WindowShow).is_ok()))?;
    }

    let file_manager = FileManager::current();
    let tray = Tray::new(&menu_state(&source.state(), file_manager, catalogue), catalogue)?;
    let mut control = Control {
        source,
        messenger,
        tray,
        window: None,
        file_manager,
        catalogue,
        loaded: PAGE,
        show_on_start: window_on_start,
        open_setup: true,
        awaiting: waiting_for_setup,
        _guard: guard,
    };

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;
        control.handle(event, target, control_flow);
    })
}

/// The state of the loop. Everything here belongs to one thread; none of it is shared.
struct Control {
    source: Arc<dyn DisplaySource>,
    messenger: EventLoopProxy<Event>,
    tray: Tray,
    window: Option<Window>,
    file_manager: FileManager,
    /// Every sentence of this run, in the language of this workstation (`crate::locale`).
    catalogue: &'static Catalog,
    /// How many rows the open window shows — a wake fetches that many again.
    loaded: usize,
    /// `--window`: open the window right on the first pass.
    show_on_start: bool,
    /// Whether the set-up has still to open by itself in this run (ADR-D13 §11, points 2 and 3).
    ///
    /// Once per run and not once per window: a device that is waiting for its approval, or whose
    /// user closed the window halfway through, is not to be met by the wizard again at every
    /// click on "Open elasticdms" — "a wizard that reopened at every login would nag the one
    /// person who can do least about it" (`DisplaySource::complete_setup`).
    open_setup: bool,
    /// Whether the source is `crate::awaiting::AwaitingSetup` — a workstation nobody has told
    /// where its server is (ADR-D13 §11, point 1).
    ///
    /// A `bool` and not a downcast: what the loop needs to know is not which type stands there
    /// but whether a finished set-up is allowed to build an engine. It goes `false` the moment
    /// one is being built, so a second "Done" cannot start a second engine against the same store
    /// and the same keychain.
    awaiting: bool,
    /// Only held: for as long as it lives, this instance is the only one.
    _guard: Option<Guard>,
}

impl Control {
    fn handle(
        &mut self,
        event: TaoEvent<'_, Event>,
        target: &EventLoopWindowTarget<Event>,
        control_flow: &mut ControlFlow,
    ) {
        match event {
            TaoEvent::NewEvents(StartCause::Init) if self.show_on_start => {
                self.show_on_start = false;
                self.show_window(target);
            }
            TaoEvent::UserEvent(Event::Menu(identifier)) => {
                self.menu_command(&identifier, target, control_flow);
            }
            TaoEvent::UserEvent(Event::Icon(e)) => self.icon_click(&e, target),
            TaoEvent::UserEvent(Event::Page(call)) => self.page_call(&call),
            TaoEvent::UserEvent(Event::Wake) => self.adopt_state(),
            TaoEvent::UserEvent(Event::WindowShow) => self.show_window(target),
            TaoEvent::UserEvent(Event::Engine(built)) => self.take_over(*built),
            // Closing does not end the app, it only releases the window (ADR-D07).
            TaoEvent::WindowEvent { window_id, event: WindowEvent::CloseRequested, .. }
                if self.window.as_ref().is_some_and(|f| f.identifier() == window_id) =>
            {
                tracing::debug!("window closed; elasticdms carries on in the icon.");
                self.window = None;
                self.loaded = PAGE;
            }
            _ => {}
        }
    }

    /// The source's state, read once, for menu and window header at the same time.
    fn state(&self) -> (DisplayState, MenuState) {
        let state = self.source.state();
        let menu = menu_state(&state, self.file_manager, self.catalogue);
        (state, menu)
    }

    fn menu_command(
        &mut self,
        identifier: &MenuId,
        target: &EventLoopWindowTarget<Event>,
        control_flow: &mut ControlFlow,
    ) {
        let Some(command) = MenuCommand::from_identifier(identifier.as_ref()) else {
            // The status line deliberately has no identifier; anything else would be a bug.
            tracing::debug!(
                identifier = identifier.as_ref(),
                "a menu entry without a command was clicked."
            );
            return;
        };
        match command {
            MenuCommand::Open => self.show_window(target),
            MenuCommand::Folder => self.report(self.source.open_folder(), Some(target)),
            MenuCommand::Baskets => self.report(self.source.open_baskets(), Some(target)),
            MenuCommand::Account => match self.tray.account_action() {
                AccountAction::SignIn => self.report(self.source.sign_in(), Some(target)),
                AccountAction::SignOut => self.report(self.source.sign_out(), Some(target)),
                // "Signing in …" starts no second flow but shows the code.
                AccountAction::CodeShow => self.show_window(target),
                AccountAction::No => {}
            },
            MenuCommand::Stop => {
                tracing::debug!("\"Quit\" in the menu: elasticdms ends.");
                // `ControlFlow::Exit` exits the process without calling a single `Drop`. What the
                // source holds in the background (runtime, channel to the extension, rendezvous
                // file) therefore has to be cleared **here**.
                self.source.stop();
                *control_flow = ControlFlow::Exit;
            }
        }
    }

    /// On Windows a left click on the icon opens the window (like OneDrive); on macOS the same
    /// click belongs to the menu, and `tray-icon` shows it itself.
    fn icon_click(&mut self, event: &TrayIconEvent, target: &EventLoopWindowTarget<Event>) {
        let left_click = matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
        );
        if left_click && !cfg!(target_os = "macos") {
            self.show_window(target);
        }
    }

    fn page_call(&mut self, call: &PageCall) {
        let request = match Request::read(&call.0) {
            Ok(a) => a,
            // The page is embedded and knows only this catalogue; whatever else arrives is not
            // carried out, but it is not kept quiet about either.
            Err(e) => {
                tracing::warn!(%e, "message from the user interface discarded.");
                return;
            }
        };
        match request {
            Request::Ready { language, time_zone } => {
                tracing::debug!(?language, ?time_zone, "the user interface is ready.");
                let Some(window) = &mut self.window else { return };
                if let Err(e) = window.is_ready() {
                    tracing::warn!(%e, "the queued messages did not reach the user interface.");
                }
                // Fresh again after the queue: it can be empty (the page can reload itself), and
                // an empty window would be the worse surprise.
                self.loaded = PAGE;
                self.adopt_state();
            }
            Request::LoadOlder { before_id } => {
                let notice =
                    row_notice(&*self.source, Some(before_id), PAGE, Mode::Append, self.catalogue);
                match notice {
                    Ok(m) => {
                        self.loaded = self.loaded.saturating_add(PAGE);
                        self.send(&m);
                    }
                    Err(e) => self.report(Err(e), None),
                }
            }
            Request::SignIn => self.report(self.source.sign_in(), None),
            Request::OpenFolder => self.report(self.source.open_folder(), None),
            Request::OpenBaskets => self.report(self.source.open_baskets(), None),
            Request::OpenLoginPage => self.report(self.open_login_page(), None),
            Request::OpenSetup => self.show_setup(),
            Request::ApplySetup { values } => match self.source.apply_setup(&values) {
                // Afresh afterwards, and only then: what the source made of the values is what
                // the wizard has to show — a field the enrolment has just closed is a field
                // nobody may go on typing in.
                Ok(()) => self.show_setup(),
                Err(e) => self.report(Err(e), None),
            },
            Request::CompleteSetup => {
                let marked = self.source.complete_setup();
                let reached = marked.is_ok();
                self.report(marked, None);
                if reached {
                    self.build_engine_if_waiting();
                }
            }
            Request::CheckExtension => {
                let state = self.source.extension_state();
                self.send(&Notice::SetupExtension { state });
            }
            Request::OpenExtensionSettings => {
                #[cfg(target_os = "macos")]
                self.report(crate::window::open_extension_settings(), None);
                // Nowhere else is there a pane to open, and nowhere else does the page carry the
                // button that would ask for one. If the request arrives all the same, something
                // is wrong with this program — and that belongs in the log.
                #[cfg(not(target_os = "macos"))]
                tracing::warn!(
                    "the user interface asked for the extension settings; this platform has none."
                );
            }
        }
    }

    /// The set-up opens by itself on a device that has not been walked through to the end
    /// (ADR-D13 §11, points 2 and 3) — once per run, at the first window.
    ///
    /// What decides is the source's own answer and nothing else: `SetupReason::ByHand` means
    /// `setup.completed` stands, `First` that it never did, `Counterpart` that a start found this
    /// device pointed at another server and gave the mark up
    /// (`setup::note_counterpart_changed`). A source that knows no set-up at all
    /// (`setup()` -> `None`) opens nothing, and says nothing about it either: a sentence would be
    /// a complaint about a click nobody made.
    fn open_setup_if_it_is_owed(&mut self) {
        if !self.open_setup {
            return;
        }
        self.open_setup = false;
        let Some(setup) = self.source.setup() else { return };
        if setup.reason == crate::display::SetupReason::ByHand {
            return;
        }
        tracing::info!(reason = ?setup.reason, "the set-up opens by itself.");
        self.send(&Notice::Setup { setup: Box::new(setup) });
    }

    /// The last page of the set-up was reached on a workstation that had no engine — build one.
    ///
    /// Only from [`crate::awaiting::AwaitingSetup`]: a running engine does not get a second one,
    /// and the values the wizard just stored reach it at the next start the ordinary way. The
    /// building runs on a thread of its own and comes back as [`Event::Engine`]; see that variant
    /// for why it must not run here.
    ///
    /// A set-up that still leaves something mandatory open changes nothing: the source stays what
    /// it is, and the page said what is missing under the field it belongs to.
    fn build_engine_if_waiting(&mut self) {
        if !self.awaiting {
            return;
        }
        let resolution = crate::setup::resolve();
        let configuration = match resolution.configuration() {
            Ok(configuration) => configuration,
            Err(error) => {
                tracing::info!(%error, "the set-up was finished, and something is still missing.");
                return;
            }
        };
        // From here on this source is on its way out; a second "Done" must not start a second
        // engine against the same store and the same keychain.
        self.awaiting = false;
        let messenger = self.messenger.clone();
        let started =
            std::thread::Builder::new().name("edms-take-over".to_owned()).spawn(move || {
                let built = crate::wiring::EngineView::start(configuration);
                let _ = messenger.send_event(Event::Engine(Box::new(built)));
            });
        if let Err(error) = started {
            tracing::error!(%error, "the engine could not be built after the set-up.");
            self.awaiting = true;
            self.report(
                Err(DisplayError::NotPossible(
                    self.catalogue.text(key::NOTICE_SETUP_RESTART).to_owned(),
                )),
                None,
            );
        }
    }

    /// The built engine takes the waiting source's place — or it did not come up, and the user is
    /// told in one sentence.
    ///
    /// The waiting source is dropped here and not before: while the engine is being built, the
    /// wizard has to go on working, because the build may fail and the user is still standing in
    /// it. For a moment the two hold a connection to the same `state.sqlite` each; the file is in
    /// WAL mode for exactly that (`edms_store`, module header).
    /// [`crate::awaiting::AwaitingSetup::stop`] closes the old one by hand, because `tao` exits
    /// the process without running a single `Drop`.
    ///
    /// `[GAP → PROPOSAL]` The window, the menu and the tray keep the language they were built
    /// with. If the wizard's own language field was changed on the way here, the engine's hints
    /// arrive in the new language while the window around them is still in the old one, until the
    /// next start — `window::page` puts the catalogue into the document once, at window creation,
    /// and there is no reload path. The chooser says so in its own sentence
    /// (`setup.welcome.language_hint`); closing it properly means a window that can be rebuilt.
    fn take_over(&mut self, built: Result<crate::wiring::EngineView, crate::wiring::StartupAbort>) {
        match built {
            Ok(view) => {
                tracing::info!("the set-up is finished; the engine takes over.");
                self.source.stop();
                self.source = Arc::new(view);
                let messenger = self.messenger.clone();
                self.source.observe(Box::new(move || {
                    let _ = messenger.send_event(Event::Wake);
                }));
                self.loaded = PAGE;
                self.adopt_state();
            }
            Err(abort) => {
                // The window stays, and so does the wizard: whatever went wrong here is something
                // the values can be changed for. Ending the process would leave the person who
                // just typed three addresses with nothing at all.
                tracing::error!(%abort, "the engine did not come up after the set-up.");
                self.awaiting = true;
                self.report(
                    Err(DisplayError::NotPossible(
                        self.catalogue.text(key::NOTICE_SETUP_RESTART).to_owned(),
                    )),
                    None,
                );
            }
        }
    }

    /// Sends the set-up to the page, or says that there is none to send.
    fn show_setup(&mut self) {
        match self.source.setup() {
            Some(setup) => self.send(&Notice::Setup { setup: Box::new(setup) }),
            None => self.report(Err(DisplayError::SetupNotAvailable), None),
        }
    }

    /// Reads state and list afresh and enters both into icon, menu and window.
    fn adopt_state(&mut self) {
        let (state, menu) = self.state();
        if let Err(e) = self.tray.update(&menu) {
            tracing::warn!(%e, "the icon could not be updated.");
        }
        if self.window.is_none() {
            return;
        }
        self.send(&Notice::State {
            state: Box::new(StateView::from(&state, &menu, self.catalogue)),
        });
        // Replace, not append — see the module header.
        match row_notice(&*self.source, None, self.loaded.max(PAGE), Mode::Replace, self.catalogue)
        {
            Ok(m) => self.send(&m),
            Err(e) => self.report(Err(e), None),
        }
    }

    fn show_window(&mut self, target: &EventLoopWindowTarget<Event>) {
        if let Some(window) = &self.window {
            window.to_the_front();
            return;
        }
        match Window::open(target, self.messenger.clone(), self.catalogue) {
            Ok(window) => {
                window.to_the_front();
                self.window = Some(window);
                self.loaded = PAGE;
                // Fill it already: until the page reports `ready`, it waits in its queue.
                self.adopt_state();
                self.open_setup_if_it_is_owed();
            }
            // Without a window the icon stays usable; a silent click would be the worse thing.
            Err(e) => tracing::error!(%e, "the window could not be opened."),
        }
    }

    /// Opens the sign-in page in the user's browser — not in the web view.
    fn open_login_page(&self) -> Result<(), DisplayError> {
        let code = self.source.state().login_code.ok_or_else(|| {
            DisplayError::NotPossible(self.catalogue.text(key::ERROR_NO_SIGN_IN_RUNNING).to_owned())
        })?;
        // `verification_uri_complete` already carries the code (RFC 8628 §3.3.1); the user then
        // does not have to type it. The four-character anchor stays in the window all the same and
        // wants to be compared (geraete-auth, Device Authorization).
        let address = code.address_complete.unwrap_or(code.address);
        check_login_address(&address)?;
        open::that_detached(&address)
            .map_err(|e| DisplayError::Open { target: address, reason: e.to_string() })
    }

    fn send(&mut self, notice: &Notice) {
        let Some(window) = &mut self.window else { return };
        if let Err(e) = window.send(notice) {
            tracing::warn!(%e, "the message did not reach the user interface.");
        }
    }

    /// A failed action is shown, not swallowed: in the window as a whole sentence, in the
    /// diagnostic log in any case.
    ///
    /// If the action comes from the **menu**, often no window is open at all — one is then opened
    /// just to show the answer. A "sign out" that the server refuses and that silently does nothing
    /// on the icon would otherwise be indistinguishable from a successful sign-out. `target` is
    /// there for exactly that; from the page (`None`) the window already stands, because that is
    /// where the click came from.
    fn report(
        &mut self,
        result: Result<(), DisplayError>,
        target: Option<&EventLoopWindowTarget<Event>>,
    ) {
        let Err(error) = result else { return };
        tracing::warn!(%error, "an action of the user interface was not carried out.");
        if let (None, Some(target)) = (&self.window, target) {
            self.show_window(target);
        }
        // Until the page reports `ready`, the sentence waits in its queue (`window::Window`).
        self.send(&Notice::Error { text: error.user_text(self.catalogue) });
    }
}

/// One page of the list, ready for the web view.
///
/// It fetches one row more than asked for: only that way can "there are older ones" be answered
/// without asking the source a second time. A read error stays an error — an empty list would mean
/// "nothing has happened" in the user interface, and that would be the plausible untruth this
/// house forbids.
pub fn row_notice(
    source: &dyn DisplaySource,
    before_id: Option<i64>,
    count: usize,
    mode: Mode,
    catalogue: &Catalog,
) -> Result<Notice, DisplayError> {
    let mut entries: Vec<(i64, LogEntry)> = source.log(before_id, count.saturating_add(1))?;
    let more = entries.len() > count;
    entries.truncate(count);
    let rows: Vec<Row> =
        entries.iter().map(|(id, entry)| Row::from_entry(*id, entry, catalogue)).collect();
    Ok(Notice::Rows { rows, mode, more })
}

/// May this address be opened in the browser?
///
/// Only `https://` — and `http://` solely against the loopback address, because the mock server
/// listens there (README, "configuration"). The address comes from the authorization server; a
/// `file://` or a `javascript:` from there would be an attack, and `open::that_detached` would pass
/// it on to the operating system unchecked.
pub fn check_login_address(address: &str) -> Result<(), DisplayError> {
    let allowed = match address.split_once("://") {
        Some(("https", rest)) => !rest.is_empty(),
        Some(("http", rest)) => is_loopback(rest),
        _ => false,
    };
    if allowed { Ok(()) } else { Err(DisplayError::LoginAddress(address.to_owned())) }
}

/// Whether exactly the loopback address stands behind `http://`.
///
/// Two traps, both cleared away here, because `open::that_detached` passes the address on to the
/// operating system unchecked:
///
/// * **A prefix is not a host:** `127.0.0.1.foreign.example` does start that way but leads
///   outwards. That is why the host name is compared as a whole, never with `starts_with`.
/// * **Credentials stand in front of the host:** in `http://localhost:8481@foreign.example/`,
///   `localhost:8481` is the userinfo part and `foreign.example` is the host. An `@` in the host
///   part is therefore already grounds to stop — nothing is taken apart here that a browser would
///   take apart differently.
fn is_loopback(rest: &str) -> bool {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.contains('@') {
        return false;
    }
    let without_port = host.rsplit_once(':').map_or(host, |(w, _)| w);
    matches!(without_port, "127.0.0.1" | "localhost" | "[::1]")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use edms_core::log::LogKind;
    use edms_core::time::Timestamp;

    use super::*;
    use crate::demo::{DemoSource, DemoState};

    const NOW: Timestamp = Timestamp::from_unix_millis(1_788_334_692_118);

    /// The German catalogue: the demo's texts read in it the way the user sees them, and the
    /// language does not matter for the properties checked here. `the_list_speaks_the_language of
    /// the catalogue` checks the other one.
    fn german() -> &'static Catalog {
        Catalog::of(edms_i18n::Language::De)
    }

    fn source(state: DemoState) -> DemoSource {
        DemoSource::new(NOW, state, Path::new("/does/not/exist"), german()).unwrap()
    }

    fn rows(notice: &Notice) -> &[Row] {
        match notice {
            Notice::Rows { rows, .. } => rows,
            other => panic!("not a rows notice: {other:?}"),
        }
    }

    #[test]
    fn the_first_page_is_full_and_reports_that_there_are_older_ones() {
        let m =
            row_notice(&source(DemoState::SignedIn), None, PAGE, Mode::Replace, german()).unwrap();
        assert_eq!(rows(&m).len(), PAGE);
        assert!(matches!(m, Notice::Rows { more: true, mode: Mode::Replace, .. }));
    }

    #[test]
    fn paging_ends_with_more_false_and_shows_every_row_exactly_once() {
        let q = source(DemoState::SignedIn);
        let all = q.log(None, usize::MAX).unwrap().len();
        let mut seen: Vec<i64> = Vec::new();
        let mut before = None;
        loop {
            let m = row_notice(&q, before, PAGE, Mode::Append, german()).unwrap();
            seen.extend(rows(&m).iter().map(|z| z.id));
            let Notice::Rows { more, .. } = m else { unreachable!() };
            if !more {
                break;
            }
            before = seen.last().copied();
        }
        assert_eq!(seen.len(), all);
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all, "a row arrived twice");
        assert!(seen.windows(2).all(|p| p[0] > p[1]), "newest first");
    }

    #[test]
    fn an_erasure_row_carries_no_name_in_the_wire_form() {
        // The core permits no subject on an erasure row; here it is checked that none of it gets
        // into the JSON message to the web view either.
        let m = row_notice(&source(DemoState::SignedIn), None, usize::MAX, Mode::Replace, german())
            .unwrap();
        let value = serde_json::to_value(&m).unwrap();
        let list = value["rows"].as_array().unwrap();
        let erased: Vec<_> = list.iter().filter(|z| z["kind"] == "ERASED_BY_ORDER").collect();
        assert_eq!(erased.len(), 1, "the sample data carries exactly one erasure row");
        for z in erased {
            assert_eq!(z["name"], serde_json::Value::Null, "an erasure row carried a name: {z}");
            assert_eq!(z["location"], serde_json::Value::Null);
            assert_eq!(z["document"], serde_json::Value::Null);
            assert_eq!(z["detail"], serde_json::Value::Null);
            assert_eq!(z["label"], "Auf Anordnung entfernt");
        }
    }

    #[test]
    fn a_row_redacted_afterwards_arrives_without_its_name() {
        let m = row_notice(&source(DemoState::SignedIn), None, usize::MAX, Mode::Replace, german())
            .unwrap();
        let redacted: Vec<&Row> = rows(&m).iter().filter(|z| z.redacted).collect();
        assert_eq!(redacted.len(), 1);
        for z in redacted {
            // Not the stored marker: the page gets the sentence, in the user's language.
            assert_eq!(
                z.name.as_deref(),
                Some(german().text(edms_i18n::key::LOG_REDACTED)),
                "the store's marker reached the window"
            );
            assert_ne!(z.name.as_deref(), Some(edms_core::log::REDACTED));
            assert!(z.location.is_none() && z.document.is_none() && z.detail.is_none());
        }
    }

    #[test]
    fn every_row_carries_label_and_severity_from_the_core() {
        let m = row_notice(&source(DemoState::SignedIn), None, usize::MAX, Mode::Replace, german())
            .unwrap();
        for z in rows(&m) {
            assert_eq!(z.label, z.kind.label(german()), "{:?}", z.kind);
            assert_eq!(z.severity, z.kind.severity(), "{:?}", z.kind);
        }
        assert!(rows(&m).iter().any(|z| z.kind == LogKind::SecurityWarning));
    }

    #[test]
    fn after_signing_out_no_document_name_stands_in_the_list_any_more() {
        // Requirement 4: the view is bound to the user. Signing out clears it.
        let q = source(DemoState::SignedIn);
        q.sign_out().unwrap();
        let m = row_notice(&q, None, usize::MAX, Mode::Replace, german()).unwrap();
        assert!(rows(&m).iter().all(|z| z.name.is_none()), "a name survived the sign-out");
    }

    #[test]
    fn a_read_error_becomes_an_error_and_not_an_empty_list() {
        struct Broken;
        impl DisplaySource for Broken {
            fn state(&self) -> DisplayState {
                unreachable!("this test asks only for the log")
            }
            fn log(
                &self,
                _before_id: Option<i64>,
                _count: usize,
            ) -> Result<Vec<(i64, LogEntry)>, DisplayError> {
                Err(DisplayError::Log("the database is locked".to_owned()))
            }
            fn sign_in(&self) -> Result<(), DisplayError> {
                Ok(())
            }
            fn sign_out(&self) -> Result<(), DisplayError> {
                Ok(())
            }
            fn open_folder(&self) -> Result<(), DisplayError> {
                Ok(())
            }
            fn open_baskets(&self) -> Result<(), DisplayError> {
                Ok(())
            }
            fn observe(&self, _waker: crate::display::Waker) {}
        }
        let f = row_notice(&Broken, None, PAGE, Mode::Replace, german()).unwrap_err();
        assert!(matches!(f, DisplayError::Log(_)), "{f}");
    }

    #[test]
    fn only_https_and_the_loopback_address_are_opened() {
        for good in [
            "https://anmeldung.example/geraet",
            "https://anmeldung.example/geraet?user_code=WQPX-7TRM",
            "http://127.0.0.1:8481/geraet",
            "http://localhost:8481/geraet",
            "http://[::1]:8481/geraet",
        ] {
            assert!(check_login_address(good).is_ok(), "\"{good}\" should have been allowed");
        }
        for bad in [
            "http://anmeldung.example/geraet",
            "http://127.0.0.1@fremd.example/geraet",
            // `localhost:8481` is the userinfo part here; the host is fremd.example.
            "http://localhost:8481@fremd.example/geraet",
            "http://127.0.0.1.fremd.example/geraet",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "anmeldung.example/geraet",
            "https://",
            "",
        ] {
            let f = check_login_address(bad).unwrap_err();
            assert!(matches!(f, DisplayError::LoginAddress(_)), "\"{bad}\": {f}");
        }
    }

    /// Writes the page with sample data as a file — the template for `docs/images/`.
    ///
    /// It checks nothing, hence `ignore`: the test is the tool with which the picture in the
    /// documentation folder is regenerated when the page changes
    /// (`cargo test -p elasticdms -- --ignored write_preview --nocapture`). It takes the same route
    /// as the window: `window::page`, the same messages, the same demo source — a picture that
    /// showed something different from the app would be worse than none.
    ///
    /// The language is this run's (`crate::locale`), so that `EDMS_LANG=en` writes the English
    /// page and `EDMS_LANG=de` the German one — one picture per language, out of one tool.
    #[test]
    #[ignore = "only writes the preview for docs/images"]
    fn write_preview() {
        use crate::menu::menu_state;
        let catalogue = crate::locale::catalogue();
        let q =
            DemoSource::new(crate::demo::now(), DemoState::SignedIn, Path::new("/tmp"), catalogue)
                .unwrap();
        let state = q.state();
        let menu = menu_state(&state, FileManager::Finder, catalogue);
        let header = Notice::State { state: Box::new(StateView::from(&state, &menu, catalogue)) };
        let list = row_notice(&q, None, PAGE, Mode::Replace, catalogue).unwrap();
        let nonce = "preview00000abcd";
        let page = crate::window::page(nonce, catalogue);
        let to_set = format!(
            "<script nonce=\"{nonce}\">\n{}\n{}\n</script>\n</body>",
            header.as_script().unwrap(),
            list.as_script().unwrap()
        );
        let page = page.replace("</body>", &to_set);
        let path =
            std::env::temp_dir().join(format!("elasticdms-preview-{}.html", catalogue.language()));
        std::fs::write(&path, page).unwrap();
        println!("PREVIEW {} ({})", path.display(), catalogue.language());
        println!("MENU {}", menu.status_line);
        println!("FOLDER {}", menu.folder_text);
        println!("ACCOUNT_ENTRY {}", menu.account_text);
    }

    #[test]
    fn the_list_speaks_the_language_of_the_catalogue() {
        // The same rows, two catalogues: the labels follow, the file names do not (they are
        // archive content and belong to the document, not to the user interface).
        let q = source(DemoState::SignedIn);
        let english = Catalog::of(edms_i18n::Language::En);
        let german_rows = row_notice(&q, None, PAGE, Mode::Replace, german()).unwrap();
        let english_rows = row_notice(&q, None, PAGE, Mode::Replace, english).unwrap();
        let opened_de = rows(&german_rows).iter().find(|z| z.kind == LogKind::Opened).unwrap();
        let opened_en = rows(&english_rows).iter().find(|z| z.kind == LogKind::Opened).unwrap();
        assert_eq!(opened_de.label, "Geöffnet");
        assert_eq!(opened_en.label, "Opened");
        assert_eq!(opened_de.name, opened_en.name, "a file name is not translated");
    }

    #[test]
    fn a_page_call_becomes_an_event_of_the_loop() {
        let call = PageCall(r#"{"kind":"signIn"}"#.to_owned());
        assert!(matches!(Event::from(call), Event::Page(_)));
    }
}
