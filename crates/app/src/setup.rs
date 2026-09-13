//! Where the app takes its settings from — and what it demands instead of guessing.
//!
//! [`edms_engine::EngineConfiguration`] knows nine `EDMS_*` variables and makes **all** of them
//! mandatory: the engine must not invent a default, because it does not know the layout of this
//! machine. The app does — it asks `directories` for the data and home directory. That is why
//! only **three** values are mandatory here, and they are exactly the three nobody may guess:
//!
//! | Variable | Why no default |
//! |---|---|
//! | `EDMS_API_BASE`  | An invented host would mean: wrong tenant, and everything "works". |
//! | `EDMS_AUTH_BASE` | The same — and here the sign-in secret would go there as well. |
//! | `EDMS_APP_BASE`  | Against this address the engine checks every browser target (anti-phishing). |
//!
//! The paths and the device name have defaults, and each can be overridden with the same variable
//! the engine reads ([`edms_engine::config`]). If a mandatory variable is missing, the start is
//! aborted and the sentence names it together with its purpose — the same sentence the engine
//! would write ([`ConfigurationError`]), because two wordings for the same lack would be one too
//! many.

use std::path::PathBuf;

use edms_i18n::Language;

use edms_engine::EngineConfiguration;
use edms_engine::config::{
    ConfigurationError, VAR_API_BASE, VAR_APP_BASE, VAR_AUTH_BASE, VAR_DATA_PATH, VAR_DEVICE_NAME,
    VAR_ENROLLMENT_CODE, VAR_HOLDING_PATH, VAR_MIRROR_PATH, VAR_STAGING,
};

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

/// Reads the configuration out of this process's environment.
///
/// # Errors
///
/// For every missing or empty mandatory variable a sentence that names it; also when no home or
/// data directory can be determined (the error then names the variable with which the path can be
/// set), or when two paths point at the same place.
pub fn configuration() -> Result<EngineConfiguration, ConfigurationError> {
    read(&|name| std::env::var(name).ok(), crate::locale::language())
}

/// The testable core of [`configuration`]: the same work, only with an arbitrary lookup function.
/// No test sets environment variables — those belong to the whole process, and two tests running
/// alongside each other would pull the values out from under one another.
fn read(
    lookup: &dyn Fn(&'static str) -> Option<String>,
    language: Language,
) -> Result<EngineConfiguration, ConfigurationError> {
    let value = |variable: &'static str| -> Option<String> {
        lookup(variable).map(|w| w.trim().to_owned()).filter(|w| !w.is_empty())
    };
    let required = |variable: &'static str, purpose: &'static str| -> Result<String, _> {
        match lookup(variable) {
            None => Err(ConfigurationError::Missing { variable, purpose }),
            Some(raw) if raw.trim().is_empty() => {
                Err(ConfigurationError::Empty { variable, purpose })
            }
            Some(raw) => Ok(raw.trim().to_owned()),
        }
    };
    let path = |variable: &'static str,
                purpose: &'static str,
                default: &dyn Fn() -> Option<PathBuf>|
     -> Result<PathBuf, ConfigurationError> {
        match value(variable) {
            Some(set) => Ok(PathBuf::from(set)),
            // Without a home or data directory there is no default. The error then names the
            // variable: "you set the path" is the only honest answer.
            None => default().ok_or(ConfigurationError::Missing { variable, purpose }),
        }
    };

    let configuration = EngineConfiguration {
        api_base: required(VAR_API_BASE, "the base address of the elasticdms API")?,
        auth_base: required(VAR_AUTH_BASE, "the base address of the authorization server")?,
        app_base: required(VAR_APP_BASE, "the base address of the web interface")?,
        data_path: path(VAR_DATA_PATH, "the file holding the local state (SQLite)", &|| {
            data_directory().map(|v| v.join(DATABASE_NAME))
        })?,
        staging: path(
            VAR_STAGING,
            "the directory into which content is loaded before it is checked",
            &|| data_directory().map(|v| v.join(STAGING_NAME)),
        )?,
        mirror_path: path(VAR_MIRROR_PATH, "the root of the mirror", &|| {
            home_directory().map(|v| v.join(FOLDER_NAME))
        })?,
        // Not in the home directory: the holding directory is our spool, not a place the user
        // files into (namespace v2 §5). The drop target is a mail basket inside the mirror.
        holding: path(VAR_HOLDING_PATH, "the holding directory for files handed in", &|| {
            data_directory().map(|v| v.join(HOLDING_NAME))
        })?,
        device_name: value(VAR_DEVICE_NAME).unwrap_or_else(|| device_name(lookup)),
        enrollment_code: value(VAR_ENROLLMENT_CODE),
        // The app resolves the language, not the engine: only the app knows both the platform
        // layer that asks the operating system and the text catalogue (`crate::locale`).
        language,
    };
    check_path(&configuration)?;
    Ok(configuration)
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

/// The name under which this workstation appears in the console.
///
/// `std` does not know the machine name, and a system call for it (`gethostname`,
/// `GetComputerNameW`) would be platform API for one line of display text. Hence the environment —
/// and if that stays silent too, an honest substitute name instead of an invented identifier.
/// Whoever needs the name sets `EDMS_DEVICE_NAME`; that is what `--help` says.
fn device_name(lookup: &dyn Fn(&'static str) -> Option<String>) -> String {
    for variable in ["COMPUTERNAME", "HOSTNAME", "USERNAME", "USER"] {
        if let Some(value) = lookup(variable) {
            let value = value.trim();
            if !value.is_empty() {
                return format!("{FOLDER_NAME} on {value}");
            }
        }
    }
    DEVICE_NAME_FALLBACK.to_owned()
}

/// Three directories with three jobs must not be the same.
///
/// `[GAP → PROPOSAL]` `EngineConfiguration::check_path` is private; whoever does not build the
/// configuration through `from_environment` (as here, because of the defaults) has to repeat the
/// check. The engine should offer it publicly as `EngineConfiguration::check`.
fn check_path(k: &EngineConfiguration) -> Result<(), ConfigurationError> {
    let pairs = [
        (VAR_MIRROR_PATH, &k.mirror_path, VAR_HOLDING_PATH, &k.holding),
        (VAR_MIRROR_PATH, &k.mirror_path, VAR_STAGING, &k.staging),
        (VAR_HOLDING_PATH, &k.holding, VAR_STAGING, &k.staging),
    ];
    for (a, left, other, right) in pairs {
        if left == right {
            return Err(ConfigurationError::PathEqual { a, other, path: left.clone() });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn environment(pairs: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
        pairs.iter().map(|(k, v)| (*k, (*v).to_owned())).collect()
    }

    fn only_address() -> HashMap<&'static str, String> {
        environment(&[
            (VAR_API_BASE, "https://api.example"),
            (VAR_AUTH_BASE, "https://auth.example"),
            (VAR_APP_BASE, "https://app.example"),
        ])
    }

    fn read_from(
        values: &HashMap<&'static str, String>,
    ) -> Result<EngineConfiguration, ConfigurationError> {
        read(&|name| values.get(name).cloned(), Language::De)
    }

    #[test]
    fn the_three_addresses_suffice_because_everything_else_has_a_default() {
        let k = read_from(&only_address()).expect("three addresses are enough");
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
            let error =
                read_from(&values).expect_err("without a mandatory value there is no start");
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
    fn an_empty_address_is_not_a_value_that_has_been_set() {
        let mut values = only_address();
        values.insert(VAR_APP_BASE, "   ".to_owned());
        let error = read_from(&values).expect_err("whitespace is not an address");
        assert!(matches!(error, ConfigurationError::Empty { variable: VAR_APP_BASE, .. }));
    }

    #[test]
    fn every_path_can_be_overridden_on_its_own() {
        let mut values = only_address();
        values.insert(VAR_DATA_PATH, "/tmp/edms/own.sqlite".to_owned());
        values.insert(VAR_MIRROR_PATH, "/tmp/edms/own-mirror".to_owned());
        values.insert(VAR_HOLDING_PATH, "/tmp/edms/own-holding".to_owned());
        values.insert(VAR_STAGING, "/tmp/edms/own-staging".to_owned());
        values.insert(VAR_DEVICE_NAME, " Buchhaltung EG ".to_owned());
        values.insert(VAR_ENROLLMENT_CODE, " K7QM-4T2X ".to_owned());
        let k = read_from(&values).expect("every value is set");
        assert_eq!(k.data_path, PathBuf::from("/tmp/edms/own.sqlite"));
        assert_eq!(k.mirror_path, PathBuf::from("/tmp/edms/own-mirror"));
        assert_eq!(k.holding, PathBuf::from("/tmp/edms/own-holding"));
        assert_eq!(k.staging, PathBuf::from("/tmp/edms/own-staging"));
        assert_eq!(k.device_name, "Buchhaltung EG");
        assert_eq!(k.enrollment_code.as_deref(), Some("K7QM-4T2X"));
    }

    #[test]
    fn the_holding_directory_must_not_be_the_mirror() {
        let mut values = only_address();
        values.insert(VAR_MIRROR_PATH, "/tmp/edms/one".to_owned());
        values.insert(VAR_HOLDING_PATH, "/tmp/edms/one".to_owned());
        let error =
            read_from(&values).expect_err("the mirror shows the server's truth, not our spool");
        assert!(matches!(error, ConfigurationError::PathEqual { .. }), "{error}");
    }

    #[test]
    fn the_holding_directory_lies_in_the_data_directory_and_not_in_the_home_directory() {
        // Namespace v2 §5: the inbox folder next to the mirror is gone; what is handed in goes
        // into the app's own data directory, next to the database.
        let k = read_from(&only_address()).expect("three addresses are enough");
        let data = k.data_path.parent().expect("the database lies in a directory");
        assert_eq!(k.holding.parent(), Some(data), "{:?} is not next to {:?}", k.holding, data);
    }

    #[test]
    fn the_device_name_comes_from_the_machine_s_environment() {
        let mut values = only_address();
        values.insert("COMPUTERNAME", "PC-BUCHHALTUNG".to_owned());
        assert_eq!(read_from(&values).unwrap().device_name, "elasticdms on PC-BUCHHALTUNG");
    }

    #[test]
    fn without_any_information_there_is_an_honest_substitute_name() {
        // No invented machine name: the person at the console should see that nobody named it, and
        // set `EDMS_DEVICE_NAME`.
        assert_eq!(device_name(&|_| None), DEVICE_NAME_FALLBACK);
    }
}
