//! Settings: key and value, both text.
//!
//! For what the app remembers (page last shown, window size) — **never for secrets** (ADR-D03,
//! point 4). The store cannot check that; it can only say that it would be wrong.
//!
//! ## Since ADR-D13 this table also carries which server this client speaks to
//!
//! The set-up writes the three base addresses, the device name, the mirror's place, the language
//! and its completed mark here under `setup.*`, and the counterpart the device enrolled against
//! under `counterpart.*`. **They live here and nowhere else**, and the reason is a measurement, not
//! a preference: the uninstall removes the directory this file lies in — on Windows
//! `uninstall::clear_state`, on macOS `packaging/macos/elasticdms-uninstall.sh`. A JSON file beside
//! the binary, an `HKCU` key or a plist would each need a new line in both of those paths, and a
//! forgotten line there is a tenant address that outlives the uninstallation.
//!
//! That is also why the enrolment code is **not** among them: it is a one-time secret from the
//! console, and the sentence above about secrets holds for it exactly as written.
//!
//! The keys are dotted, lower-case and hyphenated — `device.enrolled`, `delivery.cursor`,
//! `session.identity-guessed`, `setup.api-base`. Each of them is a constant in the crate that
//! writes it; the store knows only that a key is text.

use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;

impl Store {
    /// The value for a key; `None` when none is set.
    pub fn setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .connection
            .prepare_cached("SELECT value FROM setting WHERE key = ?1")?
            .query_row(params![key], |row| row.get(0))
            .optional()?)
    }

    /// Sets or replaces a value. An empty key is an error.
    pub fn set_setting(&mut self, key: &str, value: &str) -> Result<(), StoreError> {
        if key.is_empty() {
            return Err(StoreError::EmptyKey);
        }
        self.connection
            .prepare_cached(
                "INSERT INTO setting (key, value) VALUES (?1, ?2) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            )?
            .execute(params![key, value])?;
        Ok(())
    }

    /// Removes a value; `true` when there was one.
    pub fn delete_setting(&mut self, key: &str) -> Result<bool, StoreError> {
        let deleted = self
            .connection
            .prepare_cached("DELETE FROM setting WHERE key = ?1")?
            .execute(params![key])?;
        Ok(deleted > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::StoreError;
    use crate::test_support::store;

    #[test]
    fn a_setting_is_set_overwritten_and_deleted() {
        let mut s = store();
        assert_eq!(s.setting("page").unwrap(), None);
        s.set_setting("page", "log").unwrap();
        s.set_setting("page", "setting").unwrap();
        assert_eq!(s.setting("page").unwrap().as_deref(), Some("setting"));
        assert!(s.delete_setting("page").unwrap());
        assert!(!s.delete_setting("page").unwrap());
        assert_eq!(s.setting("page").unwrap(), None);
    }

    #[test]
    fn an_empty_key_is_rejected() {
        let mut s = store();
        assert!(matches!(s.set_setting("", "x"), Err(StoreError::EmptyKey)));
    }
}
