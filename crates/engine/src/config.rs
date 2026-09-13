//! What the engine has to know before the first call — and where it comes from.
//!
//! All values stand in environment variables with the prefix `EDMS_`. **None has a quiet fallback
//! value.** Filling a missing base address with `https://api.elasticdms.io` would mean: a wrongly
//! set-up workstation speaks to the wrong tenant and nobody notices, because everything works. If
//! something is missing, the error names the variable and its purpose, and the start aborts (the
//! same attitude as `edms_net::Connection`: check when building, not when sending).
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
    /// Reads the configuration from this process's `EDMS_*` variables.
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

    /// The configuration from an arbitrary lookup function — the testable core of
    /// [`Self::from_environment`].
    fn read(lookup: &dyn Fn(&'static str) -> Option<String>) -> Result<Self, ConfigurationError> {
        let required = |variable: &'static str, purpose: &'static str| -> Result<String, _> {
            match lookup(variable) {
                None => Err(ConfigurationError::Missing { variable, purpose }),
                Some(value) if value.trim().is_empty() => {
                    Err(ConfigurationError::Empty { variable, purpose })
                }
                Some(value) => Ok(value.trim().to_owned()),
            }
        };
        let configuration = Self {
            api_base: required(VAR_API_BASE, "the base address of the elasticdms API")?,
            auth_base: required(VAR_AUTH_BASE, "the base address of the authorization server")?,
            app_base: required(VAR_APP_BASE, "the base address of the web interface")?,
            data_path: PathBuf::from(required(
                VAR_DATA_PATH,
                "the file holding the local state (SQLite)",
            )?),
            staging: PathBuf::from(required(
                VAR_STAGING,
                "the directory into which content is loaded before it is checked",
            )?),
            mirror_path: PathBuf::from(required(VAR_MIRROR_PATH, "the root of the mirror")?),
            holding: PathBuf::from(required(
                VAR_HOLDING_PATH,
                "the directory in which an ingested file waits for the server's confirmation",
            )?),
            device_name: required(VAR_DEVICE_NAME, "the name of this workstation in the console")?,
            enrollment_code: lookup(VAR_ENROLLMENT_CODE)
                .map(|code| code.trim().to_owned())
                .filter(|code| !code.is_empty()),
            language: Language::from_value(lookup(VAR_LANGUAGE_OVERRIDE).as_deref())
                .unwrap_or(FALLBACK),
        };
        configuration.check_path()?;
        Ok(configuration)
    }

    /// Three directories with three jobs must not be the same.
    fn check_path(&self) -> Result<(), ConfigurationError> {
        let pairs: [(&'static str, &PathBuf, &'static str, &PathBuf); 3] = [
            (VAR_MIRROR_PATH, &self.mirror_path, VAR_HOLDING_PATH, &self.holding),
            (VAR_MIRROR_PATH, &self.mirror_path, VAR_STAGING, &self.staging),
            (VAR_HOLDING_PATH, &self.holding, VAR_STAGING, &self.staging),
        ];
        for (a, left, other, right) in pairs {
            if left == right {
                return Err(ConfigurationError::PathEqual { a, other, path: left.clone() });
            }
        }
        Ok(())
    }
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
    fn the_builder_puts_everything_under_one_directory() {
        let c = EngineConfiguration::builder(Path::new("/tmp/probe"))
            .with_address("http://127.0.0.1:8480", "http://127.0.0.1:8481", "http://127.0.0.1:8481")
            .finished();
        assert!(c.data_path.starts_with("/tmp/probe"));
        assert_ne!(c.mirror_path, c.holding);
        assert_eq!(c.auth_base, "http://127.0.0.1:8481");
    }
}
