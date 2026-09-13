//! What this Mac calls itself — the one place in the workspace that asks macOS for its name.
//!
//! The app shows the answer in the set-up as the proposed device name and sends it to the server
//! as `requested_name`; an administrator reads it in the console (ADR-D13 §6). Before this module
//! existed the app took that name from the environment and fell through
//! `COMPUTERNAME → HOSTNAME → USERNAME → USER`. MEASURED on macOS 26.6, 2026-09-13: the first two
//! are unset in a shell and `launchctl getenv` has neither, so a Finder launch has neither — only
//! `USER` answered, and the set-up prefilled the person's login name directly under its own hint
//! "it should name the machine and not the person".
//!
//! **Why here and not in the app.** The platform call lives in the platform crate (architecture
//! rules R4 and R5, ADR-D02), the same way `locale::preferred_languages` does. Windows needs no
//! counterpart: `COMPUTERNAME` stands in every session there, including the one the installer
//! runs `--uninstall` in.
//!
//! `gethostname` and not `NSProcessInfo.hostName`: the Foundation property can go to the resolver
//! for a reverse lookup, and this is asked on the start path. `libc` is already this crate's
//! (`home.rs` reads `getpwuid_r` for the same kind of reason).

/// The name of this machine, or `None` when the system names none.
///
/// The leftmost label only: `gethostname` answers with whatever the machine is known as on the
/// network, and on a Mac that carries the mDNS or NIS domain behind a dot — MEASURED on this
/// machine, `NoahJeromesMBP2.localdomain`. The domain is not part of the name a person gave the
/// machine, and it is not what an administrator expects to read in a console.
pub fn machine_name() -> Option<String> {
    let name = inner::host_name()?;
    let short = name.split('.').next().unwrap_or(&name).trim();
    if short.is_empty() { None } else { Some(short.to_owned()) }
}

#[cfg(target_os = "macos")]
mod inner {
    /// `_SC_HOST_NAME_MAX` is 255 on macOS; one more for the terminating zero.
    const LIMIT: usize = 256;

    pub(super) fn host_name() -> Option<String> {
        let mut buffer: [libc::c_char; LIMIT] = [0; LIMIT];
        // SAFETY: the buffer belongs to this stack frame and outlives the call; its length is
        // passed as the byte count, exactly as gethostname(3) demands. A non-zero return means
        // nothing usable was written, and then nothing is read.
        let answered = unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len()) };
        if answered != 0 {
            return None;
        }
        // gethostname truncates without terminating when the name does not fit; the last byte is
        // forced to zero so that the scan below cannot run off the end.
        buffer[LIMIT - 1] = 0;
        let bytes: Vec<u8> = buffer.iter().take_while(|b| **b != 0).map(|b| *b as u8).collect();
        String::from_utf8(bytes).ok()
    }
}

#[cfg(not(target_os = "macos"))]
mod inner {
    /// Off the platform there is no name to ask for. This build exists only so that the pure
    /// parts of this crate can be checked on a machine that is not a Mac.
    pub(super) fn host_name() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_name_is_one_line_of_text_and_carries_no_domain() {
        // Whatever this machine is called: what comes out is either nothing or a single label —
        // the app puts it in front of a person in the set-up and sends it to the server.
        let Some(name) = machine_name() else { return };
        assert!(!name.is_empty());
        assert!(!name.contains('.'), "{name}");
        assert!(!name.chars().any(char::is_control), "{name}");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn off_the_platform_nobody_is_asked() {
        assert_eq!(machine_name(), None);
    }
}
