//! What the engine has to know before the first call — and where it comes from.
//!
//! Every value stands in an environment variable with the prefix `EDMS_`. **None has a quiet
//! fallback value.** Filling a missing base address with `https://api.elasticdms.io` would mean: a
//! wrongly set-up workstation speaks to the wrong tenant and nobody notices, because everything
//! works. If something is missing, the error names the variable and its purpose, and the start
//! aborts (the same attitude as `edms_net::Connection`: check when building, not when sending).
//!
//! Since ADR-D13 a value can reach the client through up to three channels, and this module names
//! all three per value ([`Value`]) together with the order they are read in ([`Origin`]):
//!
//! ```text
//! EDMS_* in this process's environment  ->  the setting table  ->  the computed default
//! ```
//!
//! **The engine itself reads only the first one.** [`Self::from_environment`] is the engine
//! started without an app, and an engine without an app has neither a local state it may open
//! before its configuration stands nor a machine layout it could compute a default from. The whole
//! order is walked by the app (`crate::…` has no `directories` and no store of its own before
//! this struct exists) — which is why the second and third channel stand here only as a name and a
//! key, and never as a reader.
//!
//! For tests there is [`Builder`]: it puts all paths under one directory and takes the three base
//! addresses from the mock — no test sets environment variables, because those belong to the whole
//! process and two tests side by side would pull the values away from each other.

use std::path::{Path, PathBuf};

use edms_i18n::{FALLBACK, Language, VAR_LANGUAGE};

/// Base address of the resource API (`https://api.…`).
pub const VAR_API_BASE: &str = "EDMS_API_BASE";
/// Base address of the authorization server (`https://auth.…`).
pub const VAR_AUTH_BASE: &str = "EDMS_AUTH_BASE";
/// Base address of the web interface; the client opens only targets below it in the browser.
pub const VAR_APP_BASE: &str = "EDMS_APP_BASE";
/// Path of the SQLite file holding the local state.
pub const VAR_DATA_PATH: &str = "EDMS_DATA_PATH";
/// Directory of the scratch area into which content is loaded before the checksum matches.
pub const VAR_STAGING: &str = "EDMS_STAGING_DIR";
/// Root of the mirror in the Explorer or the Finder.
pub const VAR_MIRROR_PATH: &str = "EDMS_MIRROR_PATH";
/// Directory in which an ingested file waits until the server has confirmed it.
///
/// In the app's own data directory, **never** in the mirror: the mirror shows the server's
/// truth, not our spool (namespace v2 §5). The drop target is a mail basket inside the mirror,
/// and there is no inbox folder next to it any more.
pub const VAR_HOLDING_PATH: &str = "EDMS_HOLDING_DIR";
/// The name under which this workstation stands in the console.
pub const VAR_DEVICE_NAME: &str = "EDMS_DEVICE_NAME";
/// The enrolment code from the console; needed only at the first set-up.
pub const VAR_ENROLLMENT_CODE: &str = "EDMS_ENROLLMENT_CODE";
/// The language of the user interface; overrides the operating system's choice
/// ([`edms_i18n::VAR_LANGUAGE`]).
pub const VAR_LANGUAGE_OVERRIDE: &str = VAR_LANGUAGE;

/// Setting key of the resource API's base address.
pub const SETTING_API_BASE: &str = "setup.api-base";
/// Setting key of the authorization server's base address.
pub const SETTING_AUTH_BASE: &str = "setup.auth-base";
/// Setting key of the web interface's base address.
pub const SETTING_APP_BASE: &str = "setup.app-base";
/// Setting key of the name this workstation shows in the console.
pub const SETTING_DEVICE_NAME: &str = "setup.device-name";
/// Setting key of the mirror's place.
pub const SETTING_MIRROR_PATH: &str = "setup.mirror-path";
/// Setting key of the user interface's language.
pub const SETTING_LANGUAGE: &str = "setup.language";

/// Setting key of the mark that the set-up was walked to its last page.
///
/// Written when the last page is **reached**, not when everything works: a device can be set up
/// honestly and still wait for an administrator to approve its fingerprint, and a set-up that
/// completed only on full success would open again at every login on a device whose user can do
/// least about it (ADR-D13 §11).
pub const SETTING_COMPLETED: &str = "setup.completed";

/// The value every mark in the `setting` table carries when it holds.
///
/// The same word `device.enrolled` uses — one spelling for "yes" in one table.
pub const YES: &str = "yes";

/// Setting key of the resource API this device enrolled against.
pub const SETTING_COUNTERPART_API_BASE: &str = "counterpart.api-base";
/// Setting key of the authorization server this device enrolled against.
pub const SETTING_COUNTERPART_AUTH_BASE: &str = "counterpart.auth-base";
/// Setting key of the web interface this device enrolled against.
pub const SETTING_COUNTERPART_APP_BASE: &str = "counterpart.app-base";

/// Setting key holding the address a device was pointed away from (ADR-D13 §4).
///
/// The one key ADR-D13 §6's table does not list, and the reason is §4's own last point: the seal
/// opens the set-up "at a page that says what happened", and a page can say nothing that nobody
/// wrote down. It holds the old resource API, is written when the seal fires and is forgotten once
/// the page has been shown.
pub const SETTING_COUNTERPART_CHANGED: &str = "setup.counterpart-changed";

/// Which of the three channels a value came from.
///
/// **To set it is to fix it** (ADR-D13 §1): a value an administrator has set is a value the
/// administrator has decided, so the set-up shows it and does not offer it. A value they have not
/// set is the user's, all the way down to the default. There is no per-value exception and no
/// second channel through which a value could be marked as "the user may override this one" — an
/// exception list is a place where one wrong entry silently re-opens the tenant address.
///
/// The labels are English and do **not** go through the catalogue: they are read in `doctor`, by
/// whoever takes the support call (ADR-D10, and the rule `crate::report` already follows).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// An `EDMS_*` variable of this process. It wins over everything below it.
    Environment,
    /// The `setting` table of the local state — what this client was told through its own surface.
    Setting,
    /// Computed on this machine, because nobody said anything.
    Default,
}

impl Origin {
    /// The word `doctor` prints in its source column.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Setting => "setting",
            Self::Default => "default",
        }
    }

    /// Whether this origin takes the choice away from the user.
    pub const fn is_fixed(self) -> bool {
        matches!(self, Self::Environment)
    }
}

/// A value the client is configured with — the same value through up to three channels.
///
/// Every one of them has a variable; six also have a key in the `setting` table, and the three
/// that do not are a decision with a reason each (ADR-D13 §6):
///
/// | Value | key | why not |
/// |---|---|---|
/// | [`Self::DataPath`] | — | the setting table lies at the end of this path; a setting that says where the settings live cannot live among them |
/// | [`Self::Staging`] | — | a scratch area, and the only real question is which volume: a network path makes every hydration slow, a removable one breaks it mid-file |
/// | [`Self::Holding`] | — | files the server has not confirmed lie there, and the uninstall protects only the default place |
///
/// **The enrolment code is not among them.** It is a one-time secret from the console, it goes
/// from the field straight into `crate::Engine::set_enrollment_code`, it is never stored, and it
/// never stands in a report. A value that cannot appear in this list cannot be printed out of it
/// by accident either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Value {
    /// The resource API.
    ApiBase,
    /// The authorization server.
    AuthBase,
    /// The web interface — the yardstick of every browser prompt.
    AppBase,
    /// The file holding the local state.
    DataPath,
    /// The scratch area.
    Staging,
    /// The root of the mirror.
    MirrorPath,
    /// The holding directory.
    Holding,
    /// The name of this workstation in the console.
    DeviceName,
    /// The language of the user interface.
    Language,
}

impl Value {
    /// Every value, in the order a report reads them.
    pub const ALL: [Self; 9] = [
        Self::ApiBase,
        Self::AuthBase,
        Self::AppBase,
        Self::DeviceName,
        Self::Language,
        Self::DataPath,
        Self::Staging,
        Self::MirrorPath,
        Self::Holding,
    ];

    /// How many there are — the length of an array kept per value.
    pub const COUNT: usize = Self::ALL.len();

    /// The place of this value in an array of length [`Self::COUNT`].
    pub const fn index(self) -> usize {
        match self {
            Self::ApiBase => 0,
            Self::AuthBase => 1,
            Self::AppBase => 2,
            Self::DeviceName => 3,
            Self::Language => 4,
            Self::DataPath => 5,
            Self::Staging => 6,
            Self::MirrorPath => 7,
            Self::Holding => 8,
        }
    }

    /// The environment variable that fixes this value.
    pub const fn variable(self) -> &'static str {
        match self {
            Self::ApiBase => VAR_API_BASE,
            Self::AuthBase => VAR_AUTH_BASE,
            Self::AppBase => VAR_APP_BASE,
            Self::DataPath => VAR_DATA_PATH,
            Self::Staging => VAR_STAGING,
            Self::MirrorPath => VAR_MIRROR_PATH,
            Self::Holding => VAR_HOLDING_PATH,
            Self::DeviceName => VAR_DEVICE_NAME,
            Self::Language => VAR_LANGUAGE_OVERRIDE,
        }
    }

    /// The key under which the set-up may remember this value — `None` where nothing may remember
    /// it (see the table on [`Value`]).
    ///
    /// [`Self::MirrorPath`] keeps its key on both platforms although on macOS the value decides
    /// nothing (`crate::…` never places the root there; the File Provider names it). A key behind
    /// a `cfg` would be a database that reads differently depending on which build opened it, and
    /// whether the **field** is offered is the set-up's question, not the store's.
    pub const fn setting_key(self) -> Option<&'static str> {
        match self {
            Self::ApiBase => Some(SETTING_API_BASE),
            Self::AuthBase => Some(SETTING_AUTH_BASE),
            Self::AppBase => Some(SETTING_APP_BASE),
            Self::DeviceName => Some(SETTING_DEVICE_NAME),
            Self::MirrorPath => Some(SETTING_MIRROR_PATH),
            Self::Language => Some(SETTING_LANGUAGE),
            Self::DataPath | Self::Staging | Self::Holding => None,
        }
    }

    /// What the value stands for — the sentence that tells the human being what to enter.
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::ApiBase => "the base address of the elasticdms API",
            Self::AuthBase => "the base address of the authorization server",
            Self::AppBase => "the base address of the web interface",
            Self::DataPath => "the file holding the local state (SQLite)",
            Self::Staging => "the directory into which content is loaded before it is checked",
            Self::MirrorPath => "the root of the mirror",
            Self::Holding => {
                "the directory in which an ingested file waits for the server's confirmation"
            }
            Self::DeviceName => "the name of this workstation in the console",
            Self::Language => "the language of the user interface",
        }
    }
}

/// Why the configuration does not stand. Read by a person setting a workstation up, on the
/// error output — an operator surface, and therefore English like every other diagnostic in this
/// house.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigurationError {
    /// The variable is not set.
    #[error("the environment variable {variable} is missing; it names {purpose}")]
    Missing {
        /// The name of the variable.
        variable: &'static str,
        /// What it stands for — the sentence that tells the human being what to enter.
        purpose: &'static str,
    },
    /// The variable is set, but empty or only whitespace.
    #[error("the environment variable {variable} is empty; it names {purpose}")]
    Empty {
        /// The name of the variable.
        variable: &'static str,
        /// What it stands for.
        purpose: &'static str,
    },
    /// Two paths point at the same place.
    #[error(
        "{a} and {other} both point at `{path}`; the holding directory and the staging area lie \
         in the app's own data directory, and neither of them in the mirror (namespace v2 §5)"
    )]
    PathEqual {
        /// The first variable.
        a: &'static str,
        /// The second variable.
        other: &'static str,
        /// The path both name.
        path: PathBuf,
    },
}

/// Everything the engine needs at the start.
///
/// The addresses stay `String`: they go to [`edms_net::Connection`], and that one checks them —
/// checking twice would mean two judgements about the same string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfiguration {
    /// Base address of the resource API.
    pub api_base: String,
    /// Base address of the authorization server.
    pub auth_base: String,
    /// Base address of the web interface; target of every browser prompt.
    pub app_base: String,
    /// The SQLite file holding the local state.
    pub data_path: PathBuf,
    /// Directory into which content is loaded and checked completely before a single byte reaches
    /// the platform (`edms_core::port`, "The promise about the content").
    pub staging: PathBuf,
    /// Root of the mirror.
    pub mirror_path: PathBuf,
    /// Where an ingested file waits for the server's confirmation — outside the mirror.
    pub holding: PathBuf,
    /// The name of this workstation in the console.
    pub device_name: String,
    /// The enrolment code, if it is already known at the start.
    ///
    /// `None` is the normal case at a workstation: the code is typed into the app by a human being,
    /// and the app passes it on with [`crate::Engine::set_enrollment_code`]. It is set for
    /// unattended rollout and in tests.
    pub enrollment_code: Option<String>,
    /// The language of every sentence the engine says to the user.
    ///
    /// Set by the app, which asks the operating system (`crate::…` has no platform API, and
    /// asking for the locale here would be one). [`Self::from_environment`] reads only
    /// [`VAR_LANGUAGE_OVERRIDE`] and otherwise takes the fallback — an engine started without an
    /// app has no user interface whose locale it could follow.
    pub language: Language,
}

impl EngineConfiguration {
    /// Reads the configuration from this process's `EDMS_*` variables — **and from nothing else**.
    ///
    /// For an engine started without an app: every value mandatory, no default, no `setting` table.
    /// The app does **not** come this way; it walks the whole order of ADR-D13 §1 in
    /// `crates/app/src/setup.rs`, and a second caller here would be the second reader that order
    /// exists to prevent. Measured on 2026-09-13: nothing in this workspace calls it.
    ///
    /// # Errors
    ///
    /// For every missing or empty mandatory variable a sentence that names it
    /// ([`ConfigurationError`]).
    pub fn from_environment() -> Result<Self, ConfigurationError> {
        Self::read(&|name| std::env::var(name).ok())
    }

    /// A builder for tests: all paths under `directory`, addresses from the mock.
    pub fn builder(directory: &Path) -> Builder {
        Builder::new(directory)
    }

    /// Creates the directories that belong to the engine: that of the database, the scratch area
    /// and the holding directory.
    ///
    /// **Not** the mirror — that one is created by the platform layer
    /// (`FileSystem::place_ready`); a second creator of the same root would be a second owner.
    /// The holding directory does stand here: since namespace v2 §5 it lies in the app's own data
    /// directory, and nobody else has a reason to know it.
    ///
    /// # Errors
    ///
    /// When a directory cannot be created.
    pub fn create_directories(&self) -> Result<(), std::io::Error> {
        if let Some(parent) = self.data_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&self.staging)?;
        std::fs::create_dir_all(&self.holding)
    }

    /// Three directories with three jobs must not be the same.
    ///
    /// Public since ADR-D13 §7: whoever puts a configuration together out of defaults instead of
    /// [`Self::from_environment`] — the app does, and so does the set-up before it stores a path —
    /// used to repeat the rule. Two places that decide the same question are two answers to it.
    ///
    /// # Errors
    ///
    /// [`ConfigurationError::PathEqual`], naming both variables and the path they share.
    pub fn check(&self) -> Result<(), ConfigurationError> {
        check_paths(&self.mirror_path, &self.staging, &self.holding)
    }

    /// The configuration from an arbitrary lookup function — the testable core of
    /// [`Self::from_environment`].
    fn read(lookup: &dyn Fn(&'static str) -> Option<String>) -> Result<Self, ConfigurationError> {
        let required = |value: Value| -> Result<String, ConfigurationError> {
            let (variable, purpose) = (value.variable(), value.purpose());
            match lookup(variable) {
                None => Err(ConfigurationError::Missing { variable, purpose }),
                Some(value) if value.trim().is_empty() => {
                    Err(ConfigurationError::Empty { variable, purpose })
                }
                Some(value) => Ok(value.trim().to_owned()),
            }
        };
        let configuration = Self {
            api_base: required(Value::ApiBase)?,
            auth_base: required(Value::AuthBase)?,
            app_base: required(Value::AppBase)?,
            data_path: PathBuf::from(required(Value::DataPath)?),
            staging: PathBuf::from(required(Value::Staging)?),
            mirror_path: PathBuf::from(required(Value::MirrorPath)?),
            holding: PathBuf::from(required(Value::Holding)?),
            device_name: required(Value::DeviceName)?,
            enrollment_code: lookup(VAR_ENROLLMENT_CODE)
                .map(|code| code.trim().to_owned())
                .filter(|code| !code.is_empty()),
            language: Language::from_value(lookup(VAR_LANGUAGE_OVERRIDE).as_deref())
                .unwrap_or(FALLBACK),
        };
        configuration.check()?;
        Ok(configuration)
    }
}

/// Three directories with three jobs must not be the same — the rule on its own, for whoever holds
/// three paths and not yet a configuration.
///
/// # Errors
///
/// [`ConfigurationError::PathEqual`], naming both variables and the path they share.
pub fn check_paths(
    mirror_path: &Path,
    staging: &Path,
    holding: &Path,
) -> Result<(), ConfigurationError> {
    let pairs: [(&'static str, &Path, &'static str, &Path); 3] = [
        (VAR_MIRROR_PATH, mirror_path, VAR_HOLDING_PATH, holding),
        (VAR_MIRROR_PATH, mirror_path, VAR_STAGING, staging),
        (VAR_HOLDING_PATH, holding, VAR_STAGING, staging),
    ];
    for (a, left, other, right) in pairs {
        if left == right {
            return Err(ConfigurationError::PathEqual { a, other, path: left.to_path_buf() });
        }
    }
    Ok(())
}

/// Puts a configuration together for tests and development runs.
#[derive(Debug, Clone)]
pub struct Builder {
    configuration: EngineConfiguration,
}

impl Builder {
    /// All paths under `directory`, addresses still on the loopback.
    pub fn new(directory: &Path) -> Self {
        Self {
            configuration: EngineConfiguration {
                api_base: "http://127.0.0.1:1".to_owned(),
                auth_base: "http://127.0.0.1:1".to_owned(),
                app_base: "http://127.0.0.1:1".to_owned(),
                data_path: directory.join("state.sqlite"),
                staging: directory.join("staging"),
                mirror_path: directory.join("mirror"),
                holding: directory.join("holding"),
                device_name: "Workstation under test".to_owned(),
                enrollment_code: Some("K7QM-4T2X".to_owned()),
                language: Language::De,
            },
        }
    }

    /// Sets the three base addresses as a running mock names them.
    #[must_use]
    pub fn with_address(mut self, api: &str, auth: &str, app: &str) -> Self {
        self.configuration.api_base = api.to_owned();
        self.configuration.auth_base = auth.to_owned();
        self.configuration.app_base = app.to_owned();
        self
    }

    /// Sets the device name.
    #[must_use]
    pub fn with_device_name(mut self, name: &str) -> Self {
        self.configuration.device_name = name.to_owned();
        self
    }

    /// Sets the enrolment code; `None` makes the engine ask for it.
    #[must_use]
    pub fn with_enrollment_code(mut self, code: Option<&str>) -> Self {
        self.configuration.enrollment_code = code.map(ToOwned::to_owned);
        self
    }

    /// Sets the language of the user interface.
    #[must_use]
    pub fn with_language(mut self, language: Language) -> Self {
        self.configuration.language = language;
        self
    }

    /// The finished configuration.
    pub fn finished(self) -> EngineConfiguration {
        self.configuration
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn complete() -> HashMap<&'static str, String> {
        [
            (VAR_API_BASE, "https://api.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
            (VAR_DATA_PATH, "/tmp/edms/state.sqlite"),
            (VAR_STAGING, "/tmp/edms/staging"),
            (VAR_MIRROR_PATH, "/tmp/edms/mirror"),
            (VAR_HOLDING_PATH, "/tmp/edms/holding"),
            (VAR_DEVICE_NAME, "Buchhaltung EG"),
        ]
        .into_iter()
        .map(|(name, value)| (name, value.to_owned()))
        .collect()
    }

    fn read(
        values: &HashMap<&'static str, String>,
    ) -> Result<EngineConfiguration, ConfigurationError> {
        EngineConfiguration::read(&|name| values.get(name).cloned())
    }

    #[test]
    fn a_complete_environment_yields_the_configuration() {
        let c = read(&complete()).expect("all mandatory values stand");
        assert_eq!(c.api_base, "https://api.example");
        assert_eq!(c.data_path, PathBuf::from("/tmp/edms/state.sqlite"));
        assert_eq!(c.device_name, "Buchhaltung EG");
        assert_eq!(c.enrollment_code, None, "the code is optional");
    }

    #[test]
    fn every_missing_mandatory_variable_is_named() {
        for variable in complete().keys().copied() {
            let mut values = complete();
            values.remove(variable);
            let error =
                read(&values).expect_err("without a mandatory value there is no configuration");
            match &error {
                ConfigurationError::Missing { variable: named, purpose } => {
                    assert_eq!(*named, variable);
                    assert!(
                        !purpose.is_empty(),
                        "the sentence also says what the value stands for"
                    );
                }
                other => panic!("expected a missing value, came: {other}"),
            }
            assert!(error.to_string().contains(variable), "{error}");
        }
    }

    #[test]
    fn an_empty_variable_is_not_a_set_value() {
        let mut values = complete();
        values.insert(VAR_DEVICE_NAME, "   ".to_owned());
        let error = read(&values).expect_err("whitespace is not a name");
        assert!(matches!(error, ConfigurationError::Empty { variable: VAR_DEVICE_NAME, .. }));
    }

    #[test]
    fn the_holding_directory_must_not_be_the_mirror() {
        let mut values = complete();
        values.insert(VAR_HOLDING_PATH, "/tmp/edms/mirror".to_owned());
        let error =
            read(&values).expect_err("the mirror shows the server's truth (namespace v2 §5)");
        assert!(matches!(error, ConfigurationError::PathEqual { .. }), "{error}");
    }

    #[test]
    fn an_enrolment_code_that_is_set_arrives_and_is_trimmed() {
        let mut values = complete();
        values.insert(VAR_ENROLLMENT_CODE, " K7QM-4T2X \n".to_owned());
        assert_eq!(read(&values).unwrap().enrollment_code.as_deref(), Some("K7QM-4T2X"));
        values.insert(VAR_ENROLLMENT_CODE, String::new());
        assert_eq!(read(&values).unwrap().enrollment_code, None, "empty means not set");
    }

    #[test]
    fn every_value_is_listed_once_and_its_index_finds_it_again() {
        // `index` addresses an array kept per value; a duplicate would silently overwrite the
        // neighbour's origin, and a report would then name the wrong source.
        let mut seen = [false; Value::COUNT];
        for value in Value::ALL {
            assert!(!seen[value.index()], "{value:?} takes an index twice");
            seen[value.index()] = true;
            assert_eq!(Value::ALL[value.index()], value);
        }
        assert!(seen.into_iter().all(|found| found), "an index without a value: {seen:?}");
    }

    #[test]
    fn every_value_names_a_variable_and_a_purpose_and_the_variables_are_distinct() {
        let mut variables = std::collections::HashSet::new();
        for value in Value::ALL {
            assert!(value.variable().starts_with("EDMS_"), "{value:?}: {}", value.variable());
            assert!(!value.purpose().is_empty(), "{value:?}");
            assert!(variables.insert(value.variable()), "{value:?} shares its variable");
        }
    }

    #[test]
    fn the_three_values_without_a_key_are_exactly_the_three_that_may_not_be_stored() {
        // ADR-D13 §6. The data path carries the setting table itself; the staging area and the
        // holding directory are places a user can only make worse. A key that appeared here would
        // be a value the set-up could be talked into writing.
        let without: Vec<Value> =
            Value::ALL.into_iter().filter(|v| v.setting_key().is_none()).collect();
        assert_eq!(without, vec![Value::DataPath, Value::Staging, Value::Holding]);
        let mut keys = std::collections::HashSet::new();
        for value in Value::ALL {
            if let Some(key) = value.setting_key() {
                assert!(key.starts_with("setup."), "{value:?}: {key}");
                assert!(keys.insert(key), "{value:?} shares its key");
            }
        }
    }

    #[test]
    fn a_fixed_value_is_the_one_the_environment_carries() {
        assert!(Origin::Environment.is_fixed());
        assert!(!Origin::Setting.is_fixed());
        assert!(!Origin::Default.is_fixed());
        assert_eq!(Origin::Environment.label(), "environment");
        assert_eq!(Origin::Setting.label(), "setting");
        assert_eq!(Origin::Default.label(), "default");
    }

    #[test]
    fn the_rule_about_the_three_directories_holds_without_a_configuration_too() {
        let mirror = Path::new("/tmp/edms/mirror");
        assert!(
            check_paths(mirror, Path::new("/tmp/edms/staging"), Path::new("/tmp/edms/h")).is_ok()
        );
        let error = check_paths(mirror, Path::new("/tmp/edms/staging"), mirror)
            .expect_err("the mirror shows the server's truth, not our spool");
        assert!(matches!(error, ConfigurationError::PathEqual { .. }), "{error}");
    }

    #[test]
    fn the_builder_puts_everything_under_one_directory() {
        let c = EngineConfiguration::builder(Path::new("/tmp/probe"))
            .with_address("http://127.0.0.1:8480", "http://127.0.0.1:8481", "http://127.0.0.1:8481")
            .finished();
        assert!(c.data_path.starts_with("/tmp/probe"));
        assert_ne!(c.mirror_path, c.holding);
        assert_eq!(c.auth_base, "http://127.0.0.1:8481");
    }
}
