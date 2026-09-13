//! Where the app takes its settings from — the one order of precedence, and the only door that
//! writes one.
//!
//! [`edms_engine::EngineConfiguration`] knows nine `EDMS_*` variables and makes **all** of them
//! mandatory: the engine must not invent a default, because it does not know the layout of this
//! machine. The app does — it asks `directories` for the data and home directory, and since
//! ADR-D13 it also asks the `setting` table what this client was told through its own surface.
//!
//! ## The order, and it has no exception list
//!
//! ```text
//! EDMS_* in this process's environment  ->  the setting table  ->  the computed default
//! ```
//!
//! **To set it is to fix it.** A value an administrator has set is a value the administrator has
//! decided; the set-up shows it and does not offer it. A value they have not set is the user's, all
//! the way down to the default. The reason is the distribution channel: the client goes to managed
//! devices over Intune and GPO, and a user who could repoint `EDMS_API_BASE` could aim a client
//! holding a signed-in session, a device key and a mirror of a GoBD archive at a server of someone
//! else's choosing (ADR-D13, "The question that decides the shape").
//!
//! There is therefore exactly one reader — [`read`], reached through [`resolve`] — and exactly one
//! writer, [`set_value`]. A page of the set-up can be bypassed; a setter cannot, which is why the
//! checks live here and not there.
//!
//! ## Two stages, because the settings lie at the end of one of the values
//!
//! ```text
//! stage 1 (no store):   the data path        — environment or computed default
//!                       open the store
//! stage 2 (with store): everything else      — environment -> setting -> default
//! ```
//!
//! A setting that said where the settings live could not live among them; `EDMS_DATA_PATH` is
//! therefore shown by the set-up and never offered, and the same holds for the scratch area and
//! the holding directory, each for its own reason ([`edms_engine::config::Value`]).
//!
//! If the store cannot be opened at all, nothing here fails: the resolution then knows no stored
//! value, and the start aborts a moment later with the store's own sentence on the error output —
//! exactly as it did before this module read a store.
//!
//! ## Who calls the writing half
//!
//! ADR-D13 splits the set-up in two: the plumbing (here) and its face (`window.rs`, `view/`, the
//! `Request` variants of `message.rs`). The two halves are joined in `wiring::EngineView`, which
//! implements `DisplaySource`'s four set-up methods over [`resolve_over`], [`set_value`],
//! [`mark_completed`] and [`forget_counterpart_changed`]. Until that happened the writing half
//! carried eight `#[allow(dead_code)]` and this paragraph said so; they went with the joining,
//! and `-D warnings` is what keeps them gone.
//!
//! ## What it deliberately does not do
//!
//! It reaches no server. Neither outcome would be a verdict on the typed text: a server that
//! answers proves nothing about *which* tenant it is, and one that does not answer is far more
//! often a VPN that is not up. The checked answer comes one step later, from the enrolment
//! (ADR-D13 §8).

use std::path::{Path, PathBuf};

use edms_i18n::{FALLBACK, Language};

use edms_engine::EngineConfiguration;
use edms_engine::config::{
    ConfigurationError, Origin, SETTING_COMPLETED, SETTING_COUNTERPART_API_BASE,
    SETTING_COUNTERPART_APP_BASE, SETTING_COUNTERPART_AUTH_BASE, SETTING_COUNTERPART_CHANGED,
    VAR_ENROLLMENT_CODE, Value, YES, check_paths,
};
use edms_engine::session::SETTING_ENROLLED;
use edms_store::{Store, StoreError};

/// Name of the mirror folder in the home directory.
pub const FOLDER_NAME: &str = "elasticdms";

/// Directory name of the holding directory in the data directory.
///
/// Files that were dropped into a mail basket lie here after the ingest until the server has
/// confirmed it (namespace v2 §5, ADR-D08 point 5). Never a name the user reads: nobody is meant
/// to look for a folder here — the drop target is the basket inside the mirror.
///
/// English, like every other name in this directory since 2026-09-13 (see [`DATABASE_NAME`]).
pub const HOLDING_NAME: &str = "holding";

/// File name of the local state in the data directory.
///
/// English since 2026-09-13, and with it [`STAGING_NAME`]. Both stood German (`zustand.sqlite`,
/// `zwischenablage`) on one argument: a rename would need a migration, because an installed client
/// has a database under the old name. MEASURED on this machine on 2026-09-13 before the rename: no
/// `/Applications/elasticdms.app`, no launch agent, no `pkgutil` receipt, no File Provider
/// container. There **is** a data directory under the old identity, and it holds more than the
/// leftovers of `make demo`: a signed-in database and, in the keychain beside it, a device key.
/// It is left where it is and removed by hand — ADR-D10, "What the rename costs on the one machine
/// where it costs anything", says why no code goes looking for it. Nowhere else is there anything,
/// per the owner the same day: nothing published, nothing installed at a customer. With nothing to
/// migrate, the owner's decision of 2026-09-12 ("everything developers touch is English") reaches
/// these two like everything else (ADR-D10 and its correction of 2026-09-13).
pub const DATABASE_NAME: &str = "state.sqlite";

/// Directory name of the staging area in the data directory. See [`DATABASE_NAME`] on the name.
pub const STAGING_NAME: &str = "staging";

/// The device name when the machine offers none.
pub const DEVICE_NAME_FALLBACK: &str = "elasticdms workstation";

/// One value as the resolution found it: what holds, and which channel it came through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    text: String,
    origin: Origin,
}

impl Resolved {
    /// The value, trimmed — and for an address as [`edms_net::connection::check`] returned it.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Which channel it came through.
    pub const fn origin(&self) -> Origin {
        self.origin
    }

    /// Whether the environment decided it, and the set-up therefore shows it instead of offering
    /// it (ADR-D13 §3).
    pub const fn is_fixed(&self) -> bool {
        self.origin.is_fixed()
    }
}

/// Every value of this workstation, and where each of them came from.
///
/// Built by [`resolve`] and by nothing else. Whoever needs a configuration asks
/// [`Self::configuration`]; whoever needs to know what to show asks [`Self::of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    found: [Option<Resolved>; Value::COUNT],
    /// Never stored, never reported: a one-time secret from the console (ADR-D13 §6).
    enrollment_code: Option<String>,
    completed: bool,
    counterpart: Counterpart,
    counterpart_changed: Option<String>,
}

impl Resolution {
    /// The value, or `None` when no channel carries one.
    pub fn of(&self, which: Value) -> Option<&Resolved> {
        self.found[which.index()].as_ref()
    }

    /// The text of the value; `None` when none stands.
    pub fn text(&self, which: Value) -> Option<&str> {
        self.of(which).map(Resolved::text)
    }

    /// Whether the environment fixes this value — the set-up shows it and offers no field.
    pub fn is_fixed(&self, which: Value) -> bool {
        self.of(which).is_some_and(Resolved::is_fixed)
    }

    /// The language of this run, resolved through the same order as everything else.
    ///
    /// **This is the only answer.** `main.rs` builds the catalogue from it and hands that one
    /// catalogue to `event_loop::start`, so window, menu and tray read the same language the
    /// engine writes its hints in and the mirror names its folders in
    /// (`edms_core::namespace::name_baskets`). `crate::locale` is still asked — it is what this
    /// machine and this environment say, and it is the default the order falls through to — but
    /// it is not asked a second time after this.
    pub fn language(&self) -> Language {
        self.text(Value::Language).and_then(Language::from_tag).unwrap_or(FALLBACK)
    }

    /// Whether an enrolment code came with the environment. The code itself leaves this module
    /// only inside a configuration.
    pub fn has_enrollment_code(&self) -> bool {
        self.enrollment_code.is_some()
    }

    /// Whether this device has been walked to the last page of the set-up ([`SETTING_COMPLETED`]).
    pub const fn completed(&self) -> bool {
        self.completed
    }

    /// What the comparison against the enrolled counterpart found (ADR-D13 §4).
    pub const fn counterpart(&self) -> &Counterpart {
        &self.counterpart
    }

    /// The address this device was pointed away from, until the page that says so has been shown.
    pub fn counterpart_changed(&self) -> Option<&str> {
        self.counterpart_changed.as_deref()
    }

    /// Every value for which no channel carries anything — what the set-up has to ask for.
    ///
    /// The language is never among them: it always has one, because a window that will not come up
    /// over a locale would be worse than a window in the fallback language (`edms_i18n`).
    pub fn missing(&self) -> Vec<Value> {
        Value::ALL
            .into_iter()
            .filter(|which| *which != Value::Language)
            .filter(|which| self.text(*which).is_none_or(str::is_empty))
            .collect()
    }

    /// The finished configuration.
    ///
    /// # Errors
    ///
    /// The first value no channel carries, named together with its purpose — the same sentence
    /// this module wrote before it read anything but the environment. A value the environment sets
    /// to nothing at all is [`ConfigurationError::Empty`]: setting a variable is the act of taking
    /// the choice away, and nothing is not a value.
    pub fn configuration(&self) -> Result<EngineConfiguration, ConfigurationError> {
        let text = |which: Value| -> Result<String, ConfigurationError> {
            let (variable, purpose) = (which.variable(), which.purpose());
            match self.of(which) {
                None => Err(ConfigurationError::Missing { variable, purpose }),
                Some(found) if found.text.is_empty() => {
                    Err(ConfigurationError::Empty { variable, purpose })
                }
                Some(found) => Ok(found.text.clone()),
            }
        };
        let configuration = EngineConfiguration {
            api_base: text(Value::ApiBase)?,
            auth_base: text(Value::AuthBase)?,
            app_base: text(Value::AppBase)?,
            data_path: PathBuf::from(text(Value::DataPath)?),
            staging: PathBuf::from(text(Value::Staging)?),
            mirror_path: PathBuf::from(text(Value::MirrorPath)?),
            holding: PathBuf::from(text(Value::Holding)?),
            device_name: text(Value::DeviceName)?,
            enrollment_code: self.enrollment_code.clone(),
            language: self.language(),
        };
        configuration.check()?;
        Ok(configuration)
    }
}

/// Reads every value of this workstation, through the one order and in two stages.
pub fn resolve() -> Resolution {
    let lookup = |name: &str| std::env::var(name).ok();
    let store = open_settings_with(&lookup);
    read(&lookup, &reader(store.as_ref()), crate::locale::language())
}

/// The same reading, over a store somebody else already holds open.
///
/// `wiring::EngineView` keeps one for the set-up's sake: every render of the wizard and every
/// "Next" resolves afresh, and opening a database file per click on the user-interface thread
/// would be a file operation where the trait promises an immediate answer
/// (`DisplaySource`, module header).
pub fn resolve_over(store: &Store) -> Resolution {
    read(&|name: &str| std::env::var(name).ok(), &reader(Some(store)), crate::locale::language())
}

/// The `setting` table as the resolution reads it.
///
/// A row that cannot be read is a value nobody gave, never an abort: the start then says what is
/// missing instead of what the database did.
fn reader(store: Option<&Store>) -> impl Fn(&str) -> Option<String> + '_ {
    move |key: &str| match store.map(|open| open.setting(key)) {
        None => None,
        Some(Ok(value)) => value,
        Some(Err(error)) => {
            tracing::warn!(%error, key, "a stored setting could not be read.");
            None
        }
    }
}

/// The testable core of [`resolve`]: the same work, only with arbitrary lookup functions.
///
/// No test sets environment variables — those belong to the whole process, and two tests running
/// alongside each other would pull the values out from under one another. `pub(crate)` for that
/// reason alone: `doctor` has to be able to show a report of a workstation that does not exist.
pub(crate) fn read(
    lookup: &dyn Fn(&str) -> Option<String>,
    stored: &dyn Fn(&str) -> Option<String>,
    system_language: Language,
) -> Resolution {
    let found: [Option<Resolved>; Value::COUNT] = std::array::from_fn(|index| {
        resolve_one(Value::ALL[index], lookup, stored, system_language)
    });
    // `None` when one of the three is missing: a device that has no address at all has not been
    // pointed anywhere, and comparing a stored counterpart against an empty string would report a
    // re-point to a workstation that is merely waiting to be asked.
    let now = addresses(
        found[Value::ApiBase.index()].as_ref().map(|v| v.text.clone()),
        found[Value::AuthBase.index()].as_ref().map(|v| v.text.clone()),
        found[Value::AppBase.index()].as_ref().map(|v| v.text.clone()),
    );
    Resolution {
        found,
        // Empty means not set here, and unlike everywhere else it does not abort the start: the
        // MSI carries the code as a public property, and a property nobody filled in arrives as
        // an empty string.
        enrollment_code: trimmed(lookup(VAR_ENROLLMENT_CODE)),
        completed: stored(SETTING_COMPLETED).as_deref() == Some(YES),
        counterpart: compare(
            stored(SETTING_ENROLLED).as_deref() == Some(YES),
            addresses(
                stored(SETTING_COUNTERPART_API_BASE),
                stored(SETTING_COUNTERPART_AUTH_BASE),
                stored(SETTING_COUNTERPART_APP_BASE),
            ),
            now.as_ref(),
        ),
        counterpart_changed: trimmed(stored(SETTING_COUNTERPART_CHANGED)),
    }
}

/// The one place a value is chosen — environment, then setting, then default.
fn resolve_one(
    which: Value,
    lookup: &dyn Fn(&str) -> Option<String>,
    stored: &dyn Fn(&str) -> Option<String>,
    system_language: Language,
) -> Option<Resolved> {
    // The language is the one value whose environment channel may fall through, and the decision
    // is not made here: `edms_i18n` settled that an `EDMS_LANG` nobody understands falls back
    // loudly instead of aborting, because a program that will not come up over a locale is worse
    // than one in the wrong language. Everywhere else a variable that is set decides — even when
    // it is set to nothing, and then the start says so (`Resolution::configuration`).
    if which == Value::Language {
        if let Some(language) = Language::from_value(lookup(which.variable()).as_deref()) {
            return Some(Resolved { text: language.tag().to_owned(), origin: Origin::Environment });
        }
    } else if let Some(raw) = lookup(which.variable()) {
        return Some(Resolved { text: as_written(which, raw.trim()), origin: Origin::Environment });
    }

    if let Some(key) = which.setting_key()
        && let Some(text) = trimmed(stored(key))
    {
        match check_alone(which, &text) {
            Ok(checked) => return Some(Resolved { text: checked, origin: Origin::Setting }),
            // Passed over, not fatal: this client wrote the value itself, and if it no longer
            // holds — because the check grew stricter, as it did for userinfo in an authority
            // (ADR-D13 §8) — then falling back to the default sends the user to the set-up, which
            // is the place that can ask again. A value out of the environment is never passed over
            // this way: there, to set it is to fix it, and an unusable one aborts the start.
            Err(refused) => tracing::warn!(
                %refused,
                key,
                "a stored value does not hold any more and was passed over."
            ),
        }
    }

    default_for(which, lookup, system_language)
        .map(|text| Resolved { text, origin: Origin::Default })
}

/// One address as [`edms_net::connection::check`] writes it — **on the environment channel too**.
///
/// The two channels used to write the same server two ways: a stored address came back from
/// `check` without its trailing slash (that is what [`set_value`] returns), one out of the
/// environment came back exactly as an administrator had typed it. The counterpart seal compares
/// those strings byte for byte ([`compare`]), so `EDMS_API_BASE=https://api.acme/` next to a
/// device sealed against `https://api.acme` read as a re-point: revoke, clear the mirror, drop
/// `device.enrolled` — for a cosmetic edit to a GPO value, on every device at once. One function
/// on both channels is the whole repair.
///
/// A value `check` refuses stays as it was typed. The start then aborts a moment later where it
/// always did — `Connection::new` runs the same check — and with the same sentence; passing an
/// unusable environment value over would be the one thing this module's order forbids ("to set it
/// is to fix it").
fn as_written(which: Value, text: &str) -> String {
    match which {
        Value::ApiBase | Value::AuthBase | Value::AppBase => {
            check_alone(which, text).unwrap_or_else(|_| text.to_owned())
        }
        Value::DataPath
        | Value::Staging
        | Value::Holding
        | Value::MirrorPath
        | Value::DeviceName
        | Value::Language => text.to_owned(),
    }
}

/// What this machine computes for itself when nobody has said anything.
fn default_for(
    which: Value,
    lookup: &dyn Fn(&str) -> Option<String>,
    system_language: Language,
) -> Option<String> {
    match which {
        // No default, and that is the whole point: an invented host would mean a wrongly set-up
        // workstation that speaks to the wrong tenant while everything "works".
        Value::ApiBase | Value::AuthBase | Value::AppBase => None,
        Value::DataPath => as_text(&data_directory()?.join(DATABASE_NAME)),
        Value::Staging => as_text(&data_directory()?.join(STAGING_NAME)),
        // Not in the home directory: the holding directory is our spool, not a place the user
        // files into (namespace v2 §5). The drop target is a mail basket inside the mirror.
        Value::Holding => as_text(&data_directory()?.join(HOLDING_NAME)),
        Value::MirrorPath => as_text(&home_directory()?.join(FOLDER_NAME)),
        Value::DeviceName => Some(device_name(lookup)),
        Value::Language => Some(system_language.tag().to_owned()),
    }
}

/// Why a value a human being typed is not stored.
///
/// Read by whoever built the page that offered it, and — where a sentence of it reaches the user —
/// through the catalogue and not from here: these are English like every other diagnostic in this
/// house.
#[derive(Debug, thiserror::Error)]
pub enum SettingRefused {
    /// The environment carries this value, and that is the end of the matter.
    #[error(
        "the variable `{variable}` is set in this process's environment; a value set there is the \
         one this device uses, and a stored one beside it would be a second answer to one question"
    )]
    Fixed {
        /// The variable that decided.
        variable: &'static str,
    },
    /// The value is shown by the set-up and never offered.
    #[error("`{variable}` is not offered by the set-up: {reason}")]
    NotOffered {
        /// The variable that can still set it.
        variable: &'static str,
        /// Why nobody may type it here.
        reason: &'static str,
    },
    /// The value was spent: something has already been done with it.
    #[error("`{variable}` cannot be changed any more: {reason}")]
    Spent {
        /// The variable the value belongs to.
        variable: &'static str,
        /// What has already happened with it.
        reason: &'static str,
    },
    /// Nothing was typed.
    #[error("a value for `{variable}` is empty; it names {purpose}")]
    Empty {
        /// The variable the value belongs to.
        variable: &'static str,
        /// What the value stands for.
        purpose: &'static str,
    },
    /// The address is not one.
    #[error(transparent)]
    Address(#[from] edms_net::ConnectionError),
    /// Two of the three directories would be the same place.
    #[error(transparent)]
    Path(#[from] ConfigurationError),
    /// The root of the mirror would lie **above** one of the three places the installation owns.
    ///
    /// [`check_paths`] compares the three for equality and nothing else, and equality is not the
    /// dangerous shape. A root that merely *contains* the local state — `…\folderclient\data`
    /// holds `state.sqlite`, `staging` and `holding` — passes every later check, and at a
    /// sign-out `Mirror::clear_everything` deletes **every child** of the root: the holding
    /// directory with the ingests the server has not confirmed yet included, the one thing
    /// `uninstall::clear_state` goes to lengths to keep.
    #[error(
        "`{path}` lies above `{inner}`, which is what `{variable}` names; a sign-out clears every \
         child of the mirror's root, and that one would go with it"
    )]
    Contains {
        /// The root that was typed.
        path: String,
        /// The place it would hold.
        inner: String,
        /// The variable that names the place it would hold.
        variable: &'static str,
    },
    /// The root of the mirror is a directory that already holds something of somebody else's.
    ///
    /// The same reason: at a sign-out every child of the root goes. A user who types
    /// `C:\Users\erika\Documents` here is naming a folder whose contents the next sign-out
    /// deletes, and nothing downstream would have refused it.
    #[error(
        "`{path}` is a directory that is not empty; the mirror shows the server's truth and \
         clears every child of its root at a sign-out"
    )]
    NotEmpty {
        /// What was typed.
        path: String,
    },
    /// A name with a character no line of text survives.
    ///
    /// The name goes into the diagnostic log as a field, to the server as `requested_name` and
    /// into the console. `edms_cfapi::checks::check_name` refuses exactly this class for a name
    /// in the mirror; a name the operator reads deserves the same rule.
    #[error("a value for `{variable}` carries a control character; a name is one line of text")]
    ControlCharacter {
        /// The variable the value belongs to.
        variable: &'static str,
    },
    /// The root of the mirror is relative.
    #[error(
        "`{path}` is not absolute; the root of the mirror names one place on this machine and not \
         one relative to wherever the client happened to be started"
    )]
    NotAbsolute {
        /// What was typed.
        path: String,
    },
    /// A language without a catalogue behind it.
    #[error("`{tag}` names no language the folder client speaks; it speaks {known}")]
    Language {
        /// What was typed.
        tag: String,
        /// The tags that would have been understood.
        known: String,
    },
    /// The local state did not take it.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl SettingRefused {
    /// The whole sentence for the person who typed the value — through the catalogue, like every
    /// other sentence a user reads.
    ///
    /// The variants above are the diagnostic half and stay English; this is the other half. The
    /// three "not this page's to set" variants have one sentence between them: the wizard never
    /// offers such a value, the source discards it before it reaches the store (ADR-D13 §1), and
    /// a sentence that arrives all the same has to say what is true rather than which of three
    /// reasons it was.
    pub const fn user_key(&self) -> edms_i18n::Key {
        use edms_i18n::key;
        match self {
            Self::Fixed { .. } | Self::NotOffered { .. } | Self::Spent { .. } => {
                key::SETUP_WRONG_NOT_YOURS
            }
            Self::Empty { .. } => key::SETUP_WRONG_EMPTY,
            Self::Address(edms_net::ConnectionError::Plaintext { .. }) => {
                key::SETUP_WRONG_PLAINTEXT
            }
            Self::Address(_) => key::SETUP_WRONG_ADDRESS,
            Self::Path(_) => key::SETUP_WRONG_PATH_TAKEN,
            Self::Contains { .. } => key::SETUP_WRONG_PATH_HOLDS,
            Self::NotEmpty { .. } => key::SETUP_WRONG_PATH_NOT_EMPTY,
            Self::ControlCharacter { .. } => key::SETUP_WRONG_CONTROL,
            Self::NotAbsolute { .. } => key::SETUP_WRONG_PATH_ABSOLUTE,
            Self::Language { .. } => key::SETUP_WRONG_LANGUAGE,
            Self::Store(_) => key::SETUP_WRONG_NOT_STORED,
        }
    }

    /// Whether this is "not this page's to set" — the three the source discards in silence,
    /// because the wizard never offered the value and a sentence about it would be a complaint
    /// about a click the user did not make.
    pub const fn is_not_offered(&self) -> bool {
        matches!(self, Self::Fixed { .. } | Self::NotOffered { .. } | Self::Spent { .. })
    }
}

/// Stores a value a human being typed — the only door through which one gets into the `setting`
/// table, and therefore the place every check stands.
///
/// Returns what was stored: trimmed, and for an address as [`edms_net::connection::check`] returned
/// it — without the trailing slash, so that `edms_wire::basics::is_below` later compares against
/// one string and not two.
///
/// # Errors
///
/// [`SettingRefused`], naming what is wrong with the value or why this value is not this page's to
/// set.
pub fn set_value(
    store: &mut Store,
    resolution: &Resolution,
    which: Value,
    text: &str,
) -> Result<String, SettingRefused> {
    let Some(key) = which.setting_key() else {
        return Err(SettingRefused::NotOffered {
            variable: which.variable(),
            reason: not_offered_because(which),
        });
    };
    if resolution.is_fixed(which) {
        return Err(SettingRefused::Fixed { variable: which.variable() });
    }
    if which == Value::DeviceName && matches!(resolution.counterpart, Counterpart::Enrolled { .. })
    {
        return Err(SettingRefused::Spent {
            variable: which.variable(),
            reason: "this device is enrolled under the name the console shows, and a later rename \
                     is not carried to the server yet (ADR-D13 §6)",
        });
    }
    let text = text.trim();
    if text.is_empty() {
        return Err(SettingRefused::Empty { variable: which.variable(), purpose: which.purpose() });
    }
    // `[GAP → PROPOSAL]` ADR-D13 §6 closes the folder's place too, "until a sync root is
    // registered". The store cannot see that: Windows remembers its roots per volume, and the
    // File Provider domain is the operating system's. Only the device name closes here; the
    // mirror path is refused by `edms_cfapi::Mirror` at the next start instead, which is one
    // start too late to be a good sentence.
    let checked = check_alone(which, text)?;
    // The rules about the mirror's root need the other three paths, so they cannot stand in
    // `check_alone`. The first is the engine's own (`check_paths`), not a second one written here.
    if which == Value::MirrorPath {
        if let (Some(staging), Some(holding)) =
            (resolution.text(Value::Staging), resolution.text(Value::Holding))
        {
            check_paths(Path::new(&checked), Path::new(staging), Path::new(holding))?;
        }
        check_root(resolution, &checked)?;
    }
    store.set_setting(key, &checked)?;
    Ok(checked)
}

/// What a root of the mirror must not be, beyond the three-are-not-one rule.
///
/// Both refusals come from the same fact: at a sign-out `Mirror::clear_everything` iterates the
/// root and deletes every child, folder or file. Whatever lies under the root is therefore the
/// client's to delete, and a person typing a path here is not told that.
fn check_root(resolution: &Resolution, root: &str) -> Result<(), SettingRefused> {
    for which in [Value::DataPath, Value::Staging, Value::Holding] {
        let Some(inner) = resolution.text(which) else { continue };
        if holds(Path::new(root), Path::new(inner)) {
            return Err(SettingRefused::Contains {
                path: root.to_owned(),
                inner: inner.to_owned(),
                variable: which.variable(),
            });
        }
    }
    // The root that already holds is not refused for holding something: it holds the mirror, and
    // whoever walks the set-up again has to be able to leave the answer standing.
    if resolution.text(Value::MirrorPath) == Some(root) {
        return Ok(());
    }
    // A path that is not there yet is the normal case and the good one. A directory we cannot
    // read is not refused either: "the client could not look" is no verdict on the place, and the
    // rule above is the one that protects the local state.
    let mut entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    if entries.next().is_some() {
        return Err(SettingRefused::NotEmpty { path: root.to_owned() });
    }
    Ok(())
}

/// Whether `root` is `inner` or lies above it — compared component by component, so that a name
/// that merely begins the same way (`…\data-old` under `…\data`) is not read as "inside".
///
/// On Windows the comparison ignores ASCII case: `C:\edms\Staging` and `C:\edms\staging` are one
/// directory there, and `PathBuf`'s own `==` says they are two.
fn holds(root: &Path, inner: &Path) -> bool {
    let mut theirs = inner.components();
    for ours in root.components() {
        match theirs.next() {
            Some(mine) if same_component(ours, mine) => {}
            _ => return false,
        }
    }
    true
}

#[cfg(windows)]
fn same_component(left: std::path::Component<'_>, right: std::path::Component<'_>) -> bool {
    left.as_os_str().eq_ignore_ascii_case(right.as_os_str())
}

#[cfg(not(windows))]
fn same_component(left: std::path::Component<'_>, right: std::path::Component<'_>) -> bool {
    left == right
}

/// Everything that can be said about one value without knowing the others.
///
/// The same function on both sides of the table: [`set_value`] judges with it what a human being
/// typed, and [`resolve_one`] judges with it what an earlier run stored. A value that would not be
/// accepted today is not handed to the engine today either, whichever run wrote it.
fn check_alone(which: Value, text: &str) -> Result<String, SettingRefused> {
    match which {
        // The very function the environment path goes through (`edms_net::Connection::new`).
        // A second judgement about the same string would be a second answer — and the one the
        // set-up made would be the friendlier of the two.
        Value::ApiBase => Ok(edms_net::connection::check("API base", text)?),
        Value::AuthBase => Ok(edms_net::connection::check("sign-in base", text)?),
        Value::AppBase => Ok(edms_net::connection::check("web interface base", text)?),
        Value::MirrorPath => {
            if Path::new(text).is_absolute() {
                Ok(text.to_owned())
            } else {
                Err(SettingRefused::NotAbsolute { path: text.to_owned() })
            }
        }
        // A name is one line of text. It goes into the diagnostic log as a field, to the server
        // as `requested_name` and into the console; a newline in it writes a line of its own into
        // an operator's log. `edms_cfapi::checks::check_name` refuses the same class for a name
        // in the mirror, and this is the same kind of value.
        Value::DeviceName if text.chars().any(|c| c.is_control()) => {
            Err(SettingRefused::ControlCharacter { variable: which.variable() })
        }
        Value::DeviceName => Ok(text.to_owned()),
        Value::Language => match Language::from_tag(text) {
            Some(language) => Ok(language.tag().to_owned()),
            None => Err(SettingRefused::Language {
                tag: text.to_owned(),
                known: Language::ALL.map(Language::tag).join(", "),
            }),
        },
        Value::DataPath | Value::Staging | Value::Holding => Err(SettingRefused::NotOffered {
            variable: which.variable(),
            reason: not_offered_because(which),
        }),
    }
}

/// Why a value has no key in the `setting` table (ADR-D13 §6). One sentence per value, and each of
/// them is the reason a review can hold to.
const fn not_offered_because(which: Value) -> &'static str {
    match which {
        Value::DataPath => {
            "the setting table lies at the end of this path, and a setting that says where the \
             settings live cannot live among them"
        }
        Value::Staging => {
            "a scratch area, and the only real question is which volume: a network path makes \
             every hydration slow, a removable one breaks it mid-file"
        }
        Value::Holding => {
            "files the server has not confirmed yet lie there, and the uninstall protects only \
             the default place"
        }
        Value::ApiBase
        | Value::AuthBase
        | Value::AppBase
        | Value::MirrorPath
        | Value::DeviceName
        | Value::Language => "it is offered",
    }
}

/// Notes that the set-up was walked to its last page.
///
/// Written when the last page is **reached**, not when everything works: a device that waits for
/// an administrator to approve its fingerprint has finished its set-up honestly (ADR-D13 §11).
///
/// # Errors
///
/// When the local state does not take it.
pub fn mark_completed(store: &mut Store) -> Result<(), StoreError> {
    store.set_setting(SETTING_COMPLETED, YES)
}

/// The three addresses as one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    /// The resource API.
    pub api_base: String,
    /// The authorization server.
    pub auth_base: String,
    /// The web interface.
    pub app_base: String,
}

/// What the comparison against the counterpart this device enrolled against found (ADR-D13 §4).
///
/// The order of precedence decides which value the **client** prefers; it cannot stop a value from
/// changing underneath it. This comparison turns a silent re-point into a visible re-set-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counterpart {
    /// Nothing to compare: the device is not enrolled. The effective addresses are remembered all
    /// the same, so that the enrolment of this run is sealed against the next start.
    NotEnrolled,
    /// Enrolled, and against the addresses this client is pointed at now.
    Enrolled {
        /// Whether the three keys were already there — `false` for a client enrolled before the
        /// seal existed, which writes them at its next start against whatever it then has.
        /// Nobody can reconstruct where such a device was enrolled; this is the honest best
        /// available (ADR-D13 §4, `[GAP → PROPOSAL]`).
        sealed: bool,
    },
    /// Enrolled against another server than the one this client is pointed at now.
    Changed(Box<Addresses>),
}

/// What the counterpart comparison says about this store and this configuration.
///
/// # Errors
///
/// When the local state cannot be read. Deliberately not swallowed: a database that will not
/// answer must not look like a device that never moved.
pub fn counterpart_of(
    store: &Store,
    configuration: &EngineConfiguration,
) -> Result<Counterpart, StoreError> {
    let enrolled = store.setting(SETTING_ENROLLED)?.as_deref() == Some(YES);
    let stored = addresses(
        store.setting(SETTING_COUNTERPART_API_BASE)?,
        store.setting(SETTING_COUNTERPART_AUTH_BASE)?,
        store.setting(SETTING_COUNTERPART_APP_BASE)?,
    );
    Ok(compare(enrolled, stored, Some(&Addresses::of(configuration))))
}

/// Remembers the three effective addresses as the counterpart of this device.
///
/// ADR-D13 §4 has them written at the enrolment. They are written **here**, at the start, and the
/// difference is named because it matters: the enrolment happens inside the engine, and while the
/// device is not yet enrolled these keys are kept in step with every start. Once
/// `device.enrolled` stands they are frozen and only compared — so a change of the environment
/// between two runs is caught either way, and the engine keeps a set-up path it does not need to
/// know about.
///
/// # Errors
///
/// When the local state does not take them.
pub fn remember_counterpart(
    store: &mut Store,
    configuration: &EngineConfiguration,
) -> Result<(), StoreError> {
    store.set_setting(SETTING_COUNTERPART_API_BASE, &configuration.api_base)?;
    store.set_setting(SETTING_COUNTERPART_AUTH_BASE, &configuration.auth_base)?;
    store.set_setting(SETTING_COUNTERPART_APP_BASE, &configuration.app_base)
}

/// Notes which server this device was pointed away from, and that the set-up is no longer complete.
///
/// Both belong together: the set-up has to open again (§11, point 3), and the page that says what
/// happened cannot say it unless somebody wrote it down.
///
/// # Errors
///
/// When the local state does not take it.
pub fn note_counterpart_changed(store: &mut Store, old: &Addresses) -> Result<(), StoreError> {
    store.set_setting(SETTING_COUNTERPART_CHANGED, &old.api_base)?;
    store.delete_setting(SETTING_COMPLETED)?;
    Ok(())
}

/// Forgets the note above — for the page that has shown it.
///
/// # Errors
///
/// When the local state does not take it.
pub fn forget_counterpart_changed(store: &mut Store) -> Result<(), StoreError> {
    store.delete_setting(SETTING_COUNTERPART_CHANGED)?;
    Ok(())
}

impl Addresses {
    /// The three addresses of a configuration.
    pub fn of(configuration: &EngineConfiguration) -> Self {
        Self {
            api_base: configuration.api_base.clone(),
            auth_base: configuration.auth_base.clone(),
            app_base: configuration.app_base.clone(),
        }
    }
}

/// Three stored values are a counterpart only when all three stand.
fn addresses(
    api_base: Option<String>,
    auth_base: Option<String>,
    app_base: Option<String>,
) -> Option<Addresses> {
    Some(Addresses {
        api_base: trimmed(api_base)?,
        auth_base: trimmed(auth_base)?,
        app_base: trimmed(app_base)?,
    })
}

/// The comparison itself, without a store in sight.
fn compare(enrolled: bool, stored: Option<Addresses>, now: Option<&Addresses>) -> Counterpart {
    if !enrolled {
        return Counterpart::NotEnrolled;
    }
    let Some(stored) = stored else { return Counterpart::Enrolled { sealed: false } };
    match now {
        Some(now) if !same_server(&stored, now) => Counterpart::Changed(Box::new(stored)),
        // Either the same server, or no effective address to compare against. Both are "this
        // device has not been pointed somewhere else", and only the first can be said out loud.
        _ => Counterpart::Enrolled { sealed: true },
    }
}

/// Whether two sets of addresses name the same counterpart.
///
/// What this comparison decides is whether a workstation is signed out and its mirror cleared. It
/// therefore has to say "the same server" wherever the two strings really are the same server —
/// a false alarm costs every managed device its session, its key set and its local copy at once.
fn same_server(stored: &Addresses, now: &Addresses) -> bool {
    same_address(&stored.api_base, &now.api_base)
        && same_address(&stored.auth_base, &now.auth_base)
        && same_address(&stored.app_base, &now.app_base)
}

/// Two addresses, compared the way RFC 3986 §6.2.2.1 says they may be: scheme and authority are
/// case-insensitive, everything behind the first slash is not.
///
/// The trailing slash is already gone on both sides — [`as_written`] and [`set_value`] both run
/// every address through `edms_net::connection::check`. What is left is letter case, and only in
/// the half where it means nothing: `https://API.acme` and `https://api.acme` are one host.
///
/// **What it deliberately does not do:** no default port is folded away (`:443` stays a
/// difference), no IDN is normalised, no path is touched. `/Acme` and `/acme` may be two tenants
/// on one host, and a re-point that is missed is the one failure this seal exists to prevent.
fn same_address(stored: &str, now: &str) -> bool {
    let split = |text: &str| -> (String, usize) {
        let start = text.find("://").map_or(0, |at| at + 3);
        let end = text[start..].find('/').map_or(text.len(), |at| start + at);
        (text[..end].to_ascii_lowercase(), end)
    };
    let (left, left_end) = split(stored);
    let (right, right_end) = split(now);
    left == right && stored[left_end..] == now[right_end..]
}

/// The store the settings lie in — stage 1, and the only reader that runs before the resolution.
///
/// `None` for every reason there is: no data directory, a directory that cannot be created, a
/// database that will not open. None of them aborts here; the start says a moment later what is
/// missing, and with the store's own sentence.
pub fn open_for_settings() -> Option<Store> {
    open_settings_with(&|name: &str| std::env::var(name).ok())
}

/// The same, over an arbitrary lookup function — see [`read`] on why no test sets a variable.
fn open_settings_with(lookup: &dyn Fn(&str) -> Option<String>) -> Option<Store> {
    let path = PathBuf::from(data_path(lookup).filter(|found| !found.text.is_empty())?.text);
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty())
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        tracing::debug!(%error, path = %parent.display(), "the data directory could not be set up.");
        return None;
    }
    match Store::open(&path) {
        Ok(store) => Some(store),
        Err(error) => {
            tracing::debug!(%error, "the local state could not be opened for the settings.");
            None
        }
    }
}

/// Stage 1: the data path, from the environment or computed. Never from a setting — see the
/// module header.
fn data_path(lookup: &dyn Fn(&str) -> Option<String>) -> Option<Resolved> {
    resolve_one(Value::DataPath, lookup, &|_| None, FALLBACK)
}

/// The folder client's local data directory — the same one as for the single-instance lock.
fn data_directory() -> Option<PathBuf> {
    directories::ProjectDirs::from("de", "elasticdms", "folderclient")
        .map(|p| p.data_local_dir().to_path_buf())
}

/// The signed-in user's home directory — the mirror lives there, because the user finds it
/// immediately in Finder or Explorer.
fn home_directory() -> Option<PathBuf> {
    directories::UserDirs::new().map(|d| d.home_dir().to_path_buf())
}

/// A computed path as the text a setting and a report carry.
///
/// `None` when the path is no valid text. Then there is no default, and the error names the
/// variable with which the path can be set — "you set the path" is the only honest answer for a
/// home directory this client cannot even write down.
fn as_text(path: &Path) -> Option<String> {
    path.to_str().map(ToOwned::to_owned)
}

/// A value that is set to nothing is not a value that has been set — for the two channels where
/// that holds (the stored side, and the enrolment code).
fn trimmed(value: Option<String>) -> Option<String> {
    value.map(|text| text.trim().to_owned()).filter(|text| !text.is_empty())
}

/// The name under which this workstation appears in the console.
///
/// **It names the machine, never the person.** The chain used to end in `USERNAME` and `USER`,
/// and on this Mac those were the only two that answered: MEASURED on macOS 26.6, 2026-09-13 —
/// `COMPUTERNAME` and `HOSTNAME` are unset in a shell and `launchctl getenv` has neither, so a
/// Finder launch has neither. The set-up therefore prefilled "elasticdms on nolotz" — a login
/// name — directly under its own hint "it should name the machine and not the person". The two
/// are gone from the chain, and macOS is asked for its own name instead
/// (`edms_fileprovider::machine`). Windows needs no call: `COMPUTERNAME` stands in every session
/// there.
///
/// If nothing answers, an honest substitute name rather than an invented identifier. Whoever
/// needs a particular name sets `EDMS_DEVICE_NAME`; that is what `--help` says.
fn device_name(lookup: &dyn Fn(&str) -> Option<String>) -> String {
    for variable in ["COMPUTERNAME", "HOSTNAME"] {
        if let Some(value) = lookup(variable) {
            let value = value.trim();
            if !value.is_empty() {
                return on_machine(value);
            }
        }
    }
    match machine_name() {
        Some(name) => on_machine(&name),
        None => DEVICE_NAME_FALLBACK.to_owned(),
    }
}

/// What this platform calls itself, or `None` where nobody can be asked.
fn machine_name() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        edms_fileprovider::machine::machine_name()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The proposed name, put together.
///
/// The joining word stays English, and deliberately so: it is not a sentence the user reads but a
/// value the user may replace, and it goes on to the server as `requested_name` and into the
/// console, where an administrator reads names from every workstation side by side. A name that
/// read differently per workstation language would be one archive's device list in two languages.
fn on_machine(name: &str) -> String {
    format!("{FOLDER_NAME} on {name}")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use edms_engine::config::{
        SETTING_API_BASE, SETTING_APP_BASE, SETTING_AUTH_BASE, SETTING_DEVICE_NAME,
        SETTING_LANGUAGE, SETTING_MIRROR_PATH, VAR_API_BASE, VAR_APP_BASE, VAR_AUTH_BASE,
        VAR_DATA_PATH, VAR_DEVICE_NAME, VAR_HOLDING_PATH, VAR_LANGUAGE_OVERRIDE, VAR_MIRROR_PATH,
        VAR_STAGING,
    };

    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    fn only_address() -> HashMap<String, String> {
        map(&[
            (VAR_API_BASE, "https://api.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ])
    }

    /// The resolution over two arbitrary channels — environment and `setting` table.
    fn resolution(
        environment: &HashMap<String, String>,
        settings: &HashMap<String, String>,
    ) -> Resolution {
        read(
            &|name| environment.get(name).cloned(),
            &|key| settings.get(key).cloned(),
            Language::De,
        )
    }

    fn from(environment: &HashMap<String, String>) -> Resolution {
        resolution(environment, &HashMap::new())
    }

    /// An open store in a directory of its own.
    fn store() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().expect("a directory for the test");
        let store = Store::open(&directory.path().join(DATABASE_NAME)).expect("a fresh state");
        (directory, store)
    }

    #[test]
    fn the_three_addresses_suffice_because_everything_else_has_a_default() {
        let k = from(&only_address()).configuration().expect("three addresses are enough");
        assert_eq!(k.api_base, "https://api.example");
        assert!(k.data_path.ends_with(DATABASE_NAME), "{:?}", k.data_path);
        assert!(k.mirror_path.ends_with(FOLDER_NAME), "{:?}", k.mirror_path);
        assert!(k.holding.ends_with(HOLDING_NAME), "{:?}", k.holding);
        assert!(!k.device_name.is_empty());
        assert_eq!(k.enrollment_code, None, "the code is optional");
    }

    #[test]
    fn every_missing_address_is_named() {
        for variable in [VAR_API_BASE, VAR_AUTH_BASE, VAR_APP_BASE] {
            let mut values = only_address();
            values.remove(variable);
            let error = from(&values)
                .configuration()
                .expect_err("without a mandatory value there is no start");
            assert!(
                matches!(error, ConfigurationError::Missing { variable: v, .. } if v == variable)
            );
            assert!(error.to_string().contains(variable), "{error}");
            assert!(
                error.to_string().contains("it names"),
                "the sentence also says what for: {error}"
            );
        }
    }

    #[test]
    fn an_empty_variable_fixes_the_value_to_nothing_and_nothing_is_not_a_value() {
        // "To set it is to fix it" holds for the empty string too — otherwise clearing a variable
        // would be the way to hand a value the administrator fixed back to the user's own setting.
        for (which, variable) in [
            (Value::AppBase, VAR_APP_BASE),
            (Value::DeviceName, VAR_DEVICE_NAME),
            (Value::MirrorPath, VAR_MIRROR_PATH),
        ] {
            let mut values = only_address();
            values.insert(variable.to_owned(), "   ".to_owned());
            let settings = map(&[
                (SETTING_APP_BASE, "https://stored.example"),
                (SETTING_DEVICE_NAME, "stored name"),
                (SETTING_MIRROR_PATH, "/tmp/edms/stored-mirror"),
            ]);
            let found = resolution(&values, &settings);
            assert!(found.is_fixed(which), "{variable}");
            let error = found.configuration().expect_err("whitespace is not a value");
            assert!(
                matches!(error, ConfigurationError::Empty { variable: v, .. } if v == variable),
                "{variable}: {error}"
            );
        }
    }

    #[test]
    fn the_environment_wins_over_the_setting_and_the_setting_over_the_default() {
        // The whole order in one table: every value that has all three channels, in every
        // combination. This is the test the ADR's first decision stands or falls by.
        let cases: [(Value, &str, &str, &str); 4] = [
            (Value::ApiBase, VAR_API_BASE, SETTING_API_BASE, "https://api"),
            (Value::AuthBase, VAR_AUTH_BASE, SETTING_AUTH_BASE, "https://auth"),
            (Value::AppBase, VAR_APP_BASE, SETTING_APP_BASE, "https://app"),
            (Value::DeviceName, VAR_DEVICE_NAME, SETTING_DEVICE_NAME, "a name"),
        ];
        for (which, variable, key, _) in cases {
            let both = resolution(
                &map(&[(variable, "https://from-environment.example")]),
                &map(&[(key, "https://from-setting.example")]),
            );
            assert_eq!(both.text(which), Some("https://from-environment.example"), "{which:?}");
            assert_eq!(both.of(which).map(Resolved::origin), Some(Origin::Environment));
            assert!(both.is_fixed(which), "the set-up shows it and offers no field");

            let stored_only =
                resolution(&HashMap::new(), &map(&[(key, "https://from-setting.example")]));
            assert_eq!(stored_only.text(which), Some("https://from-setting.example"), "{which:?}");
            assert_eq!(stored_only.of(which).map(Resolved::origin), Some(Origin::Setting));
            assert!(!stored_only.is_fixed(which), "a stored value is the user's own");

            let neither = resolution(&HashMap::new(), &HashMap::new());
            assert!(
                neither.of(which).is_none_or(|found| found.origin() == Origin::Default),
                "{which:?} came from nowhere and is not a default"
            );
        }
    }

    #[test]
    fn a_value_that_may_not_be_stored_is_not_read_out_of_the_setting_table_either() {
        // Somebody who writes `setup.data-path` into the database by hand must not reach the
        // resolution with it: there is no key for these three, and a reader that looked for one
        // anyway would be the second channel ADR-D13 §1 refuses.
        let settings = map(&[
            ("setup.data-path", "/tmp/edms/smuggled.sqlite"),
            ("setup.staging", "/tmp/edms/smuggled-staging"),
            ("setup.holding", "/tmp/edms/smuggled-holding"),
        ]);
        let found = resolution(&only_address(), &settings);
        for which in [Value::DataPath, Value::Staging, Value::Holding] {
            assert_eq!(which.setting_key(), None, "{which:?}");
            let text = found.text(which).expect("a computed default");
            assert!(!text.contains("smuggled"), "{which:?}: {text}");
            assert_eq!(found.of(which).map(Resolved::origin), Some(Origin::Default));
        }
    }

    #[test]
    fn a_stored_value_that_does_not_hold_is_passed_over_and_the_default_takes_its_place() {
        // The three shapes a stored value can go wrong in: an address that hides its host behind
        // userinfo (the refusal ADR-D13 §8 added, so an installed client can carry one), plaintext
        // against a real host, and a relative mirror path.
        let settings = map(&[
            (SETTING_API_BASE, "https://api.elasticdms.io@attacker.example"),
            (SETTING_AUTH_BASE, "http://auth.example"),
            (SETTING_MIRROR_PATH, "relative/folder"),
            (SETTING_LANGUAGE, "fr"),
        ]);
        let found = resolution(&HashMap::new(), &settings);
        assert_eq!(found.text(Value::ApiBase), None, "no channel carries a usable API address");
        assert_eq!(found.text(Value::AuthBase), None);
        assert_ne!(found.text(Value::MirrorPath), Some("relative/folder"));
        assert_eq!(found.of(Value::MirrorPath).map(Resolved::origin), Some(Origin::Default));
        assert_eq!(found.language(), Language::De, "the operating system's choice holds");
    }

    #[test]
    fn a_stored_address_is_used_and_is_stored_without_its_trailing_slash() {
        let settings = map(&[
            (SETTING_API_BASE, "https://api.example/"),
            (SETTING_AUTH_BASE, "https://auth.example"),
            (SETTING_APP_BASE, "https://app.example"),
        ]);
        let k = resolution(&HashMap::new(), &settings)
            .configuration()
            .expect("the settings carry all three");
        assert_eq!(k.api_base, "https://api.example", "one string for `is_below`, not two");
    }

    #[test]
    fn every_path_can_be_overridden_on_its_own() {
        let mut values = only_address();
        for (variable, path) in [
            (VAR_DATA_PATH, "/tmp/edms/own.sqlite"),
            (VAR_MIRROR_PATH, "/tmp/edms/own-mirror"),
            (VAR_HOLDING_PATH, "/tmp/edms/own-holding"),
            (VAR_STAGING, "/tmp/edms/own-staging"),
        ] {
            values.insert(variable.to_owned(), path.to_owned());
        }
        values.insert(VAR_DEVICE_NAME.to_owned(), " Buchhaltung EG ".to_owned());
        values.insert(VAR_ENROLLMENT_CODE.to_owned(), " K7QM-4T2X ".to_owned());
        let k = from(&values).configuration().expect("every value is set");
        assert_eq!(k.data_path, PathBuf::from("/tmp/edms/own.sqlite"));
        assert_eq!(k.mirror_path, PathBuf::from("/tmp/edms/own-mirror"));
        assert_eq!(k.holding, PathBuf::from("/tmp/edms/own-holding"));
        assert_eq!(k.staging, PathBuf::from("/tmp/edms/own-staging"));
        assert_eq!(k.device_name, "Buchhaltung EG");
        assert_eq!(k.enrollment_code.as_deref(), Some("K7QM-4T2X"));
    }

    #[test]
    fn an_enrolment_code_that_is_set_to_nothing_is_a_property_nobody_filled_in() {
        // The MSI carries the code as a public property; an empty one must not abort the start,
        // which is why this one value keeps the old rule.
        let mut values = only_address();
        values.insert(VAR_ENROLLMENT_CODE.to_owned(), "   ".to_owned());
        let found = from(&values);
        assert!(!found.has_enrollment_code());
        assert_eq!(found.configuration().expect("the code is optional").enrollment_code, None);
    }

    #[test]
    fn the_holding_directory_must_not_be_the_mirror() {
        let mut values = only_address();
        values.insert(VAR_MIRROR_PATH.to_owned(), "/tmp/edms/one".to_owned());
        values.insert(VAR_HOLDING_PATH.to_owned(), "/tmp/edms/one".to_owned());
        let error = from(&values)
            .configuration()
            .expect_err("the mirror shows the server's truth, not our spool");
        assert!(matches!(error, ConfigurationError::PathEqual { .. }), "{error}");
    }

    #[test]
    fn the_holding_directory_lies_in_the_data_directory_and_not_in_the_home_directory() {
        // Namespace v2 §5: the inbox folder next to the mirror is gone; what is handed in goes
        // into the app's own data directory, next to the database.
        let k = from(&only_address()).configuration().expect("three addresses are enough");
        let data = k.data_path.parent().expect("the database lies in a directory");
        assert_eq!(k.holding.parent(), Some(data), "{:?} is not next to {:?}", k.holding, data);
    }

    #[test]
    fn the_device_name_comes_from_the_machine_s_environment() {
        let mut values = only_address();
        values.insert("COMPUTERNAME".to_owned(), "PC-BUCHHALTUNG".to_owned());
        assert_eq!(
            from(&values).configuration().unwrap().device_name,
            "elasticdms on PC-BUCHHALTUNG"
        );
    }

    #[test]
    fn the_proposed_name_names_the_machine_and_never_the_person() {
        // The chain used to end in `USERNAME` and `USER`, and on a Mac those were the only two
        // that answered: the set-up prefilled the person's login name directly under its own hint
        // "it should name the machine and not the person". Neither is asked any more — what is
        // left is what the machine calls itself.
        let login = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok();
        let proposed = device_name(&|_| None);
        if let Some(login) = login.filter(|name| !name.is_empty()) {
            assert_ne!(proposed, on_machine(&login), "a login name is not a device name");
        }
        // Either this machine has a name of its own, or nobody named it and the substitute says
        // so. No invented identifier either way.
        match machine_name() {
            Some(name) => assert_eq!(proposed, on_machine(&name)),
            None => assert_eq!(proposed, DEVICE_NAME_FALLBACK),
        }
        assert!(!proposed.chars().any(char::is_control), "{proposed}");
    }

    #[test]
    fn the_language_follows_the_same_order_and_falls_back_instead_of_aborting() {
        let system = resolution(&HashMap::new(), &HashMap::new());
        assert_eq!(system.language(), Language::De);
        assert_eq!(system.of(Value::Language).map(Resolved::origin), Some(Origin::Default));

        let stored = resolution(&HashMap::new(), &map(&[(SETTING_LANGUAGE, "en")]));
        assert_eq!(stored.language(), Language::En);
        assert_eq!(stored.of(Value::Language).map(Resolved::origin), Some(Origin::Setting));

        let fixed = resolution(
            &map(&[(VAR_LANGUAGE_OVERRIDE, "en-GB")]),
            &map(&[(SETTING_LANGUAGE, "de")]),
        );
        assert_eq!(fixed.language(), Language::En, "the environment wins here too");
        assert!(fixed.is_fixed(Value::Language));

        // Set but not understood, and set to nothing: both fall through, both loudly
        // (`edms_i18n::Language::from_value` writes the line). A locale must not keep a window shut.
        for value in ["fr", "   "] {
            let odd = resolution(
                &map(&[(VAR_LANGUAGE_OVERRIDE, value)]),
                &map(&[(SETTING_LANGUAGE, "en")]),
            );
            assert_eq!(odd.language(), Language::En, "the stored value takes over: {value}");
        }
    }

    #[test]
    fn what_is_missing_is_named_value_by_value_and_the_language_never_is() {
        let nothing = resolution(&HashMap::new(), &HashMap::new());
        let missing = nothing.missing();
        assert!(missing.contains(&Value::ApiBase));
        assert!(missing.contains(&Value::AuthBase));
        assert!(missing.contains(&Value::AppBase));
        assert!(!missing.contains(&Value::Language), "{missing:?}");
        assert!(!missing.contains(&Value::DeviceName), "it has a default: {missing:?}");
        assert!(from(&only_address()).missing().is_empty());
    }

    #[test]
    fn the_setter_refuses_a_value_the_environment_has_fixed() {
        // A page can be bypassed, a setter cannot: this is where the order of precedence holds
        // even when somebody calls past the page that would not have offered the field.
        let (_directory, mut store) = store();
        let found = resolution(&map(&[(VAR_API_BASE, "https://fixed.example")]), &HashMap::new());
        let refused = set_value(&mut store, &found, Value::ApiBase, "https://own.example")
            .expect_err("the environment decided");
        assert!(matches!(refused, SettingRefused::Fixed { variable: VAR_API_BASE }), "{refused}");
        assert_eq!(store.setting(SETTING_API_BASE).unwrap(), None, "and nothing was written");
    }

    #[test]
    fn the_setter_refuses_a_value_that_is_shown_and_not_offered() {
        let (_directory, mut store) = store();
        let found = from(&only_address());
        for which in [Value::DataPath, Value::Staging, Value::Holding] {
            let refused = set_value(&mut store, &found, which, "/tmp/anywhere")
                .expect_err("it is not this page's to set");
            assert!(matches!(refused, SettingRefused::NotOffered { .. }), "{which:?}: {refused}");
            assert!(refused.to_string().len() > 40, "the sentence says why: {refused}");
        }
    }

    #[test]
    fn the_setter_checks_an_address_with_the_function_the_environment_path_goes_through() {
        let (_directory, mut store) = store();
        let found = resolution(&HashMap::new(), &HashMap::new());
        for bad in [
            "https://api.elasticdms.io@attacker.example",
            "http://api.example",
            "api.example",
            "https://api.example?tenant=acme",
            "   ",
        ] {
            let refused = set_value(&mut store, &found, Value::ApiBase, bad)
                .expect_err("`{bad}` is not an address");
            assert!(
                matches!(refused, SettingRefused::Address(_) | SettingRefused::Empty { .. }),
                "{bad}: {refused}"
            );
        }
        assert_eq!(store.setting(SETTING_API_BASE).unwrap(), None, "nothing unusable was written");

        let stored = set_value(&mut store, &found, Value::ApiBase, " https://api.example/ ")
            .expect("an https address with a host");
        assert_eq!(stored, "https://api.example");
        assert_eq!(
            store.setting(SETTING_API_BASE).unwrap().as_deref(),
            Some("https://api.example")
        );
    }

    #[test]
    fn the_setter_refuses_a_mirror_path_that_is_relative_or_one_of_the_other_two_directories() {
        let (_directory, mut store) = store();
        let found = from(&only_address());
        let staging = found.text(Value::Staging).expect("a computed default").to_owned();

        let refused = set_value(&mut store, &found, Value::MirrorPath, "elasticdms")
            .expect_err("a root is one place, not a relative one");
        assert!(matches!(refused, SettingRefused::NotAbsolute { .. }), "{refused}");

        let refused = set_value(&mut store, &found, Value::MirrorPath, &staging)
            .expect_err("the mirror shows the server's truth, not our scratch area");
        assert!(matches!(refused, SettingRefused::Path(_)), "{refused}");
        assert_eq!(store.setting(SETTING_MIRROR_PATH).unwrap(), None);

        let good = set_value(&mut store, &found, Value::MirrorPath, "/tmp/edms/elsewhere")
            .expect("an absolute path of its own");
        assert_eq!(good, "/tmp/edms/elsewhere");
    }

    #[test]
    fn the_setter_stores_a_language_by_its_primary_subtag_and_refuses_one_without_a_catalogue() {
        let (_directory, mut store) = store();
        let found = from(&only_address());
        assert_eq!(set_value(&mut store, &found, Value::Language, " de-AT ").unwrap(), "de");
        let refused = set_value(&mut store, &found, Value::Language, "fr")
            .expect_err("there is no French catalogue");
        assert!(matches!(refused, SettingRefused::Language { .. }), "{refused}");
        assert!(refused.to_string().contains("de"), "the sentence names what is spoken: {refused}");
    }

    #[test]
    fn the_device_name_closes_once_the_device_is_enrolled() {
        let (_directory, mut store) = store();
        let found = from(&only_address());
        assert!(set_value(&mut store, &found, Value::DeviceName, "Front desk").is_ok());

        store.set_setting(SETTING_ENROLLED, YES).unwrap();
        let enrolled = read(
            &|name| only_address().get(name).cloned(),
            &|key| store.setting(key).ok().flatten(),
            Language::De,
        );
        let refused = set_value(&mut store, &enrolled, Value::DeviceName, "Back office")
            .expect_err("the console shows the name this device enrolled under");
        assert!(matches!(refused, SettingRefused::Spent { .. }), "{refused}");
        assert_eq!(store.setting(SETTING_DEVICE_NAME).unwrap().as_deref(), Some("Front desk"));
    }

    #[test]
    fn the_completed_mark_is_written_and_read_back() {
        let (_directory, mut store) = store();
        assert!(!from(&only_address()).completed());
        mark_completed(&mut store).unwrap();
        let found = read(
            &|name| only_address().get(name).cloned(),
            &|key| store.setting(key).ok().flatten(),
            Language::De,
        );
        assert!(found.completed());
    }

    fn configuration_at(api: &str, auth: &str, app: &str) -> EngineConfiguration {
        EngineConfiguration::builder(Path::new("/tmp/edms/probe"))
            .with_address(api, auth, app)
            .finished()
    }

    #[test]
    fn a_device_that_is_not_enrolled_has_no_counterpart_to_compare() {
        let (_directory, mut store) = store();
        let k =
            configuration_at("https://api.example", "https://auth.example", "https://app.example");
        assert_eq!(counterpart_of(&store, &k).unwrap(), Counterpart::NotEnrolled);
        remember_counterpart(&mut store, &k).unwrap();
        // Still nothing to compare — and that is the point: the keys are kept in step until the
        // enrolment freezes them.
        assert_eq!(counterpart_of(&store, &k).unwrap(), Counterpart::NotEnrolled);
    }

    #[test]
    fn an_enrolled_device_pointed_at_another_server_is_a_changed_counterpart() {
        let (_directory, mut store) = store();
        let old = configuration_at("https://api.acme", "https://auth.acme", "https://app.acme");
        remember_counterpart(&mut store, &old).unwrap();
        store.set_setting(SETTING_ENROLLED, YES).unwrap();
        assert_eq!(counterpart_of(&store, &old).unwrap(), Counterpart::Enrolled { sealed: true });

        // One of the three suffices: whoever sets `app_base` decides what counts as "our own web
        // interface" for every browser prompt afterwards.
        for changed in [
            configuration_at("https://api.other", "https://auth.acme", "https://app.acme"),
            configuration_at("https://api.acme", "https://auth.other", "https://app.acme"),
            configuration_at("https://api.acme", "https://auth.acme", "https://app.other"),
        ] {
            let found = counterpart_of(&store, &changed).unwrap();
            let Counterpart::Changed(stored) = found else {
                panic!("a re-point has to be visible: {found:?}");
            };
            assert_eq!(stored.api_base, "https://api.acme");
            assert_eq!(stored.app_base, "https://app.acme");
        }
    }

    #[test]
    fn a_device_enrolled_before_the_seal_existed_is_not_read_as_a_re_point() {
        // Nobody can reconstruct where such a device was enrolled; it writes the keys at its next
        // start and the seal is armed from there (ADR-D13 §4, `[GAP → PROPOSAL]`).
        let (_directory, mut store) = store();
        store.set_setting(SETTING_ENROLLED, YES).unwrap();
        let k =
            configuration_at("https://api.example", "https://auth.example", "https://app.example");
        assert_eq!(counterpart_of(&store, &k).unwrap(), Counterpart::Enrolled { sealed: false });
        remember_counterpart(&mut store, &k).unwrap();
        assert_eq!(counterpart_of(&store, &k).unwrap(), Counterpart::Enrolled { sealed: true });
    }

    #[test]
    fn a_device_without_a_single_address_is_not_read_as_a_re_point() {
        // The state a client is in the moment before its first set-up: enrolled once, nothing
        // configured now. Comparing a stored counterpart against an empty string would report a
        // re-point — and `doctor` would tell a support call to expect a sign-out that is not coming.
        let found = resolution(
            &HashMap::new(),
            &map(&[
                (SETTING_ENROLLED, YES),
                ("counterpart.api-base", "https://api.acme"),
                ("counterpart.auth-base", "https://auth.acme"),
                ("counterpart.app-base", "https://app.acme"),
            ]),
        );
        assert_eq!(*found.counterpart(), Counterpart::Enrolled { sealed: true });
    }

    #[test]
    fn two_of_three_stored_addresses_are_no_counterpart() {
        // A half-written seal must not read as "unchanged": that would be the one case in which a
        // re-point goes through quietly.
        let (_directory, mut store) = store();
        store.set_setting(SETTING_ENROLLED, YES).unwrap();
        store.set_setting(SETTING_COUNTERPART_API_BASE, "https://api.acme").unwrap();
        store.set_setting(SETTING_COUNTERPART_AUTH_BASE, "https://auth.acme").unwrap();
        let k = configuration_at("https://api.acme", "https://auth.acme", "https://app.acme");
        assert_eq!(counterpart_of(&store, &k).unwrap(), Counterpart::Enrolled { sealed: false });
    }

    #[test]
    fn a_changed_counterpart_is_noted_and_takes_the_completed_mark_with_it() {
        let (_directory, mut store) = store();
        mark_completed(&mut store).unwrap();
        let old = Addresses {
            api_base: "https://api.acme".to_owned(),
            auth_base: "https://auth.acme".to_owned(),
            app_base: "https://app.acme".to_owned(),
        };
        note_counterpart_changed(&mut store, &old).unwrap();
        let found = read(
            &|name| only_address().get(name).cloned(),
            &|key| store.setting(key).ok().flatten(),
            Language::De,
        );
        assert_eq!(found.counterpart_changed(), Some("https://api.acme"));
        assert!(!found.completed(), "the set-up opens again (ADR-D13 §11, point 3)");
        forget_counterpart_changed(&mut store).unwrap();
        assert_eq!(store.setting(SETTING_COUNTERPART_CHANGED).unwrap(), None);
    }

    #[test]
    fn one_server_written_two_ways_is_one_counterpart() {
        // The seal used to compare the two channels' raw strings. A stored address came back from
        // `connection::check` without its trailing slash; one out of the environment came back
        // exactly as an administrator had typed it. Changing `EDMS_API_BASE` from
        // `https://api.acme` to `https://api.acme/` — the same server, and `Connection::new`
        // trims the slash itself — therefore read as a re-point: revoke at the old server, every
        // child of the mirror root deleted, `device.enrolled` and the key set gone, a fresh
        // enrolment code needed per workstation. One cosmetic edit to a GPO value, every managed
        // device at once.
        let sealed = map(&[
            (SETTING_ENROLLED, YES),
            (SETTING_COUNTERPART_API_BASE, "https://api.acme"),
            (SETTING_COUNTERPART_AUTH_BASE, "https://auth.acme"),
            (SETTING_COUNTERPART_APP_BASE, "https://app.acme"),
        ]);
        for (api, auth, app) in [
            ("https://api.acme/", "https://auth.acme", "https://app.acme"),
            ("https://api.acme", "https://auth.acme///", "https://app.acme/"),
            // Scheme and host are case-insensitive (RFC 3986 §6.2.2.1) — one host, not two.
            ("https://API.acme", "https://Auth.Acme", "https://app.ACME"),
        ] {
            let environment =
                map(&[(VAR_API_BASE, api), (VAR_AUTH_BASE, auth), (VAR_APP_BASE, app)]);
            let found = resolution(&environment, &sealed);
            assert_eq!(
                *found.counterpart(),
                Counterpart::Enrolled { sealed: true },
                "{api} is the server this device is enrolled against"
            );
        }

        // And a real re-point is still one.
        let elsewhere = map(&[
            (VAR_API_BASE, "https://api.other"),
            (VAR_AUTH_BASE, "https://auth.acme"),
            (VAR_APP_BASE, "https://app.acme"),
        ]);
        assert!(matches!(resolution(&elsewhere, &sealed).counterpart(), Counterpart::Changed(_)));
        // A path is not case-insensitive, and two tenants can differ only there.
        let other_tenant = map(&[
            (VAR_API_BASE, "https://api.acme/ACME"),
            (VAR_AUTH_BASE, "https://auth.acme"),
            (VAR_APP_BASE, "https://app.acme"),
        ]);
        let with_path = map(&[
            (SETTING_ENROLLED, YES),
            (SETTING_COUNTERPART_API_BASE, "https://api.acme/acme"),
            (SETTING_COUNTERPART_AUTH_BASE, "https://auth.acme"),
            (SETTING_COUNTERPART_APP_BASE, "https://app.acme"),
        ]);
        assert!(matches!(
            resolution(&other_tenant, &with_path).counterpart(),
            Counterpart::Changed(_)
        ));
    }

    #[test]
    fn an_address_out_of_the_environment_is_written_the_way_a_stored_one_is() {
        // The one function on both channels — the repair behind the test above, stated on its
        // own so that a change to either channel has to come past it.
        let environment = map(&[
            (VAR_API_BASE, "  https://api.example/  "),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ]);
        let from_environment = from(&environment);
        let from_setting = resolution(
            &HashMap::new(),
            &map(&[
                (SETTING_API_BASE, "https://api.example/"),
                (SETTING_AUTH_BASE, "https://auth.example"),
                (SETTING_APP_BASE, "https://app.example"),
            ]),
        );
        assert_eq!(from_environment.text(Value::ApiBase), Some("https://api.example"));
        assert_eq!(from_environment.text(Value::ApiBase), from_setting.text(Value::ApiBase));

        // A value `check` refuses stays as it was typed: the start then ends where it always did,
        // at `Connection::new`, and with the same sentence. Passing an administrator's unusable
        // value over would be the one thing the order of precedence forbids.
        let broken = map(&[
            (VAR_API_BASE, "https://api.example@attacker.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ]);
        assert_eq!(
            from(&broken).text(Value::ApiBase),
            Some("https://api.example@attacker.example"),
            "not passed over, not quietly repaired"
        );
        assert!(from(&broken).is_fixed(Value::ApiBase));
    }

    #[test]
    fn the_setter_refuses_a_root_that_would_hold_the_local_state() {
        // `check_paths` compares the three directories for equality and nothing else, and
        // equality is not the dangerous shape: a root that merely *contains* the local state
        // passes every later check, and at a sign-out `Mirror::clear_everything` deletes every
        // child of the root — the holding directory with the unconfirmed ingests included.
        let (directory, mut store) = store();
        let data = directory.path().join("state").join(DATABASE_NAME);
        let inside = map(&[
            (VAR_API_BASE, "https://api.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
            (VAR_DATA_PATH, data.to_str().expect("a path of this test's own")),
        ]);
        let found = from(&inside);
        let root = directory.path().to_str().expect("a path of this test's own");
        let refused = set_value(&mut store, &found, Value::MirrorPath, root)
            .expect_err("the mirror would hold the database it is configured from");
        assert!(matches!(refused, SettingRefused::Contains { .. }), "{refused}");
        assert_eq!(store.setting(SETTING_MIRROR_PATH).unwrap(), None);
        // A name that merely begins the same way is not "inside".
        let beside = format!("{root}-elsewhere");
        assert!(set_value(&mut store, &found, Value::MirrorPath, &beside).is_ok(), "{beside}");
    }

    #[test]
    fn the_setter_refuses_a_root_somebody_already_keeps_files_in() {
        // `C:\Users\erika\Documents` passed every check there was, and the next sign-out would
        // have deleted every child of it.
        let (directory, mut store) = store();
        let theirs = directory.path().join("documents");
        std::fs::create_dir_all(theirs.join("2026")).expect("a directory with something in it");
        let found = from(&only_address());
        let path = theirs.to_str().expect("a path of this test's own");
        let refused = set_value(&mut store, &found, Value::MirrorPath, path)
            .expect_err("a sign-out would clear it");
        assert!(matches!(refused, SettingRefused::NotEmpty { .. }), "{refused}");

        // An empty one, and one that is not there yet, are both fine.
        let empty = directory.path().join("empty");
        std::fs::create_dir_all(&empty).expect("an empty directory");
        assert!(
            set_value(
                &mut store,
                &found,
                Value::MirrorPath,
                empty.to_str().expect("a path of this test's own")
            )
            .is_ok()
        );
        let fresh = directory.path().join("not-there-yet");
        assert!(
            set_value(
                &mut store,
                &found,
                Value::MirrorPath,
                fresh.to_str().expect("a path of this test's own")
            )
            .is_ok()
        );
    }

    #[test]
    fn the_root_that_already_holds_may_be_typed_again() {
        // Whoever walks the set-up a second time has to be able to leave the answer standing, and
        // by then the mirror is full of the server's truth.
        let (directory, mut store) = store();
        let root = directory.path().join("mirror");
        std::fs::create_dir_all(root.join("Briefkoerbe")).expect("a mirror with something in it");
        let path = root.to_str().expect("a path of this test's own").to_owned();
        let mut environment = only_address();
        environment.insert(VAR_MIRROR_PATH.to_owned(), path.clone());
        let found = from(&environment);
        // Out of the environment it is fixed; out of a setting it is the user's, and that is the
        // case this test is about.
        let stored = resolution(&only_address(), &map(&[(SETTING_MIRROR_PATH, &path)]));
        assert!(found.is_fixed(Value::MirrorPath));
        assert!(set_value(&mut store, &stored, Value::MirrorPath, &path).is_ok());
    }

    #[test]
    fn a_device_name_is_one_line_of_text() {
        // The name goes into the diagnostic log as a field, to the server as `requested_name` and
        // into the console. A newline in it writes a line of its own into an operator's log, and
        // the house already refuses this class for a name in the mirror
        // (`edms_cfapi::checks::check_name`).
        let (_directory, mut store) = store();
        let found = from(&only_address());
        for name in ["Front\ndesk", "Front\rdesk", "Front\u{7f}desk", "Front\u{0}desk"] {
            let refused = set_value(&mut store, &found, Value::DeviceName, name)
                .expect_err("a name is one line");
            assert!(matches!(refused, SettingRefused::ControlCharacter { .. }), "{refused}");
        }
        assert!(set_value(&mut store, &found, Value::DeviceName, "Büro 4 – EG").is_ok());
    }

    #[test]
    fn every_refusal_carries_a_sentence_for_the_person_who_typed_the_value() {
        // Two faces, like every error in this house. The English diagnostic goes into the log;
        // this is the other half, and a refusal without one would be a dead end in the wizard.
        let catalogue = edms_i18n::Catalog::of(Language::De);
        let refusals = [
            SettingRefused::Fixed { variable: VAR_API_BASE },
            SettingRefused::NotOffered { variable: VAR_DATA_PATH, reason: "it lies at the end" },
            SettingRefused::Spent { variable: VAR_DEVICE_NAME, reason: "enrolled" },
            SettingRefused::Empty { variable: VAR_API_BASE, purpose: "the API" },
            SettingRefused::Address(
                edms_net::connection::check("API base", "nonsense").expect_err("no scheme"),
            ),
            SettingRefused::Address(
                edms_net::connection::check("API base", "http://api.example")
                    .expect_err("plaintext"),
            ),
            SettingRefused::Path(ConfigurationError::PathEqual {
                a: VAR_MIRROR_PATH,
                other: VAR_STAGING,
                path: PathBuf::from("/tmp/edms"),
            }),
            SettingRefused::Contains {
                path: "/tmp/edms".to_owned(),
                inner: "/tmp/edms/state".to_owned(),
                variable: VAR_DATA_PATH,
            },
            SettingRefused::NotEmpty { path: "/tmp/edms".to_owned() },
            SettingRefused::ControlCharacter { variable: VAR_DEVICE_NAME },
            SettingRefused::NotAbsolute { path: "elasticdms".to_owned() },
            SettingRefused::Language { tag: "fr".to_owned(), known: "de, en".to_owned() },
        ];
        for refused in refusals {
            let sentence = catalogue.text(refused.user_key());
            assert!(sentence.len() > 20, "{refused}: {sentence}");
            assert!(!sentence.contains('{'), "no placeholder is left open: {sentence}");
        }
    }
}
