# ADR-D10: The language of the user interface — a catalogue, not a hard-coded German

**Status:** Accepted (2026-09-12).

Two rules at once: everything developers touch is English, identifiers included; and every sentence
a user reads is multi-language, never a hard-coded literal.

## Context

Until this decision the folder client was German in both senses at once: its identifiers, comments
and stored values were German, and so was every sentence the user read. The first half is now
English throughout. This ADR is about the
second half, and it is a different problem: a German sentence in a source file is not a naming
question but a missing feature — the client is sold into companies whose staff do not all read
German, and a GoBD/DSGVO archive is exactly the kind of system where a sentence nobody understands
("Auf Anordnung entfernt") becomes a support call instead of a piece of transparency.

## Decision

1. **One catalogue per language, in the binary.** `crates/i18n` (package `edms-i18n`) holds
   `catalog/de.toml` and `catalog/en.toml`, embedded with `include_str!`. German is the text that
   grew with the product; English is a real translation and at the same time the fallback.
2. **A key is a value.** `edms_i18n::Key` can be built only from the list in `KEYS`; call sites
   write `catalogue.text(key::MENU_OPEN)`. A key that is in no catalogue — or in one catalogue too
   many — is a red test (`crates/i18n/tests/catalogs.rs`), never a hole in a window.
3. **Named placeholders** (`{account}`, `{count}`), never positional ones: a positional `{0}`
   cannot be translated, because whoever swaps two of them breaks exactly one language and no test
   sees it. A test compares the placeholder set of every key across all languages.
4. **Resolution:** `EDMS_LANG` first, then the operating system's list of interface languages,
   then English — and the fallback is written into the diagnostic log once per process. The
   platform call lives in the platform crates (`edms_fileprovider::locale` with
   `NSLocale.preferredLanguages`, `edms_cfapi::locale` with `GetUserDefaultUILanguage`), because
   that is where platform API belongs (architecture rules R4 and R5). The app joins the two and
   hands the answer down; it is settled **once** at the start, so that menu and window never speak
   two languages at the same time.
5. **Errors keep two faces.** `Display` (`#[error(…)]`) stays the English diagnostic sentence for
   log, ticket and support call; `user_text(&Catalog)` is the sentence the person at the machine
   reads. A new variant makes the `user_text` match red, so the two cannot drift apart quietly.
   What is a **server** judgement is carried through untranslated — the client does not put words
   into the server's mouth.
6. **The window carries keys, not sentences.** `window::page` puts the whole catalogue into the
   page as JSON; the HTML marks its texts with `data-text="<key>"` and the script fills them in. A
   German string in `view.html` or `view.js` would be a second catalogue, and a second catalogue is
   the one that gets forgotten when the first is translated.
7. **The mirror is named in the user's language too** — the case-file and saved-search containers,
   and the hint file including **its file name**: `README.txt` in English, `LIESMICH.txt` in
   German. `edms-core` builds them and takes the language as a parameter; it asks no operating
   system, as before.
8. **What is stored stays a value.** The redaction marker in the usage log used to be the German
   sentence „Dokument auf Anordnung entfernt"; it is now `REDACTED`, and the sentence is chosen at
   display time (store migration 4 rewrites existing rows). A database that held sentences would
   hold them in the language of the day they were written.

## Consequences

- **`edms-i18n` lies below `edms-core`.** It is the only crate below it, and it has to be: the core
  builds the mirror's names, and nothing else could supply them without turning the dependency
  direction around. The architecture rules carry the new edge.
- **Every function that produces a sentence takes the catalogue.** `menu_state`,
  `Row::from_entry`, `window::page`, `root_entries`, `LogKind::label` — the catalogue is handed in,
  never fetched. That is what makes both languages testable in one test run without setting an
  environment variable for the whole process.
- **A language change is a restart**, and in the mirror it is a rename: the hint file's version
  carries the language (`hint-2-de-…`), so the platform fetches the text afresh instead of keeping
  the old one because two translations happened to have the same length.
- **Three names stay German for now** (the first of them has since disappeared entirely: namespace
  v2 replaced the inbox folder with the mail baskets inside the mirror, ADR-D11 §5): the inbox
  folder (`elasticdms Eingang`), the database file
  (`zustand.sqlite`) and the staging directory (`zwischenablage`). They are paths, not sentences,
  and renaming them needs a migration — an installed client has files in the old inbox folder and a
  database under the old name. `crates/app/src/setup.rs` says so at the constants.
- **Operator surfaces stay English**: `--help`, `doctor`, `--uninstall` and every `tracing` line.
  They are read in a terminal, pasted into a ticket and searched for; a translated diagnosis cannot
  be found again.

## Rejected alternatives

- **A `toml` crate for the catalogues.** Eight transitive dependencies for twelve dozen key-value
  pairs, and its generality buys nothing: whatever it could read beyond our subset must not stand in
  a catalogue anyway. `crates/i18n/src/reader.rs` reads the subset and refuses everything else, and
  `scripts/check-catalogs.py` parses the same files with a second, foreign implementation, so that
  "it really is TOML" is checked and not believed.
- **`fluent` / ICU MessageFormat.** Plural and gender rules for a catalogue whose only plural cases
  are "1 document" and "n documents" — which two keys say more plainly than one format string with
  a rule engine behind it.
- **Sentences in the error types, one language per build.** A build per language means a release
  per language, and a support call in which nobody knows which binary the customer has.
- **Reading the locale in `edms-core`.** It would give the core an operating system, and with it
  every reason the core has for being checkable in milliseconds would be gone.

## Correction to “three names stay German” (2026-09-12)

Namespace v2 (**ADR-D11** §5) drops the inbox folder next to the mirror, and with it the first of
the three names. Two are left, and for them the reasoning stands word for word: the database file
(`zustand.sqlite`) and the staging directory (`zwischenablage`) are paths, not sentences, and an
installed client would have files under the old names.

The place where a handed-in file waits for its confirmation is new and therefore has no old name
to keep: it lies in the app's own data directory, is called `holding`, and is set by
`EDMS_HOLDING_DIR`. English, like every other name this repository invented after 2026-09-12.

## Correction to “two names stay German” and to the operator surfaces (2026-09-13)

The reason the consequence above and its first correction rest on — *an installed client has files
under the old names* — is void. MEASURED on this development machine on 2026-09-13: no
`/Applications/elasticdms.app`, no plist in either `LaunchAgents` directory, no `pkgutil` receipt,
no File Provider container, no `~/Library/CloudStorage/elasticdms-*`. STATED by the owner the same
day: no customer has the client, no package has been published, no App ID is registered with Apple,
and no Windows machine has ever run it. Nothing to migrate means nothing to weigh against the
owner's decision of 2026-09-12, so four things changed:

1. **The two path names are English.** `zustand.sqlite` → `state.sqlite`, `zwischenablage` →
   `staging` (`crates/app/src/setup.rs`). With them the single-instance files
   `einzelinstanz.sperre` / `einzelinstanz.adresse` → `single-instance.lock` /
   `single-instance.address` and the request line `ELASTICDMS FENSTER` → `ELASTICDMS WINDOW`
   (`crates/app/src/single_instance.rs`). Those three were kept for a second reason of their own —
   they are the compatibility surface between two versions running at the same time — and that
   reason fails on the same measurement: there is no old instance for a new one to meet.
2. **The identity is English.** `de.elasticdms.ordnerclient` → `de.elasticdms.folderclient`, with
   `….dateianbieter` → `….fileprovider` and `….anmeldeobjekt` → `….loginitem`. It is the macOS
   bundle identifier of the app and of the File Provider extension, the keychain service, the data
   directory on both platforms, the launch-agent plist including its **file name**, the two
   `pkgutil` receipt ids, and the MSIX package identity (`Identity Name` and `Application Id` in
   `packaging/windows/AppxManifest.xml`); `packaging/macos/README.md` carried the same migration
   argument and now carries the measurement.
   Two things it is **not**, against what the first draft of this correction said. The **File
   Provider domain** identifier is `elasticdms-` plus 16 hex digits of the SHA-256 of the account
   (`crates/fileprovider/src/domain.rs`) and appears as `~/Library/CloudStorage/elasticdms-<display
   name>`; it never carried the German word and did not move. No **Windows registry** name carried
   it either: the autostart value is `…\CurrentVersion\Run\elasticdms`, the settings key is
   `SOFTWARE\Lotzer Digital\elasticdms`, and the sync-root key is `…\SyncRootManager\elasticdms!…`
   from `PROVIDER` in `crates/cfapi/src/sync_root.rs`. On Windows only the `AppData\Local`
   directory and the MSIX identity moved.
   What the **extension's** bundle identifier moving does mean: `NSFileProviderManager` hands a
   provider only its own domains, so a domain registered by a build carrying
   `….dateianbieter` is invisible to a build carrying `….fileprovider`, and `Sign out` —
   the route `packaging/macos/elasticdms-uninstall.sh` sends the operator down — could not remove
   it. MEASURED on 2026-09-13: there is no such domain here (`~/Library/CloudStorage` holds no
   `elasticdms-*` entry), so nothing is stranded; the case is recorded because it is the one
   consequence of item 2 that a later reader would otherwise have to rediscover.
3. **`doctor` speaks English**, as the consequence “operator surfaces stay English” already
   required and as the code did not do: the headings `Diagnose (ohne Netz)`, `Einrichtung` and the
   keychain row `Zustand … erreichbar` were German, and so was every line `--uninstall` printed
   except two. Both are English now, together with the reason the engine gives when no space
   measurer is set — that sentence still named `Motor::setze_platzmesser`, a method the conversion
   of 2026-09-12 had renamed to `Engine::set_space_probe`. One German word reached the operator
   through `doctor` from outside `doctor`: the reason of `DatabaseReport::NotReadable` was built
   from the labels `Sitzung` and `Zustellung` in `crates/engine/src/report.rs`, so a locked
   database printed `Database  NOT readable: Sitzung: …` inside an otherwise English frame. The
   three labels are now `VIEW_SESSION` / `VIEW_DELIVERY` / `VIEW_JOURNAL`, public so that the
   app's test builds its fixture from the same words instead of from an English guess — it had
   been passing on a hand-written `session:` while production said `Sitzung:`.
4. **The stored values are English too**, on the same measurement and for the same reason. In
   `crates/engine`: the setting keys `geraet.enrollt` → `device.enrolled`,
   `sitzung.identitaet_geraten` → `session.identity-guessed`, `zustellung.cursor` →
   `delivery.cursor`, their values `ja` / `nein` → `yes` / `no`, the synthetic account a token
   without `sub` produces (`geraet:<device>` → `device:<device>`), and the suffix of every
   half-finished load in the scratch area (`<ulid>.teil` → `<ulid>.part`) — the scratch area was
   renamed in item 1 and the files inside it had been left German. In `crates/app`: the keychain
   header marker `edms-tresor/1` → `edms-vault/1`, whose comment still argued that an installed
   client's entries must stay readable **twenty lines below** the keychain service that item 2
   changed on the opposite reasoning; the argument also defeated itself, because once the service
   name moves those entries are out of reach whatever the marker says. Precedent, measured in the
   leftover database on this machine: the conversion of 2026-09-12 had already renamed the setting
   key `schluesselsatz` to `key-set` with no migration and no note.

### What the rename costs on the one machine where it costs anything

The measurement above is about what is *installed*. It is not the whole account of what is left
behind, and the sixth place is the one that matters: **the login keychain**. MEASURED on
2026-09-13 with `security dump-keychain` (attributes only, no secrets read): ten generic-password
items stand under the service `de.elasticdms.ordnerclient` — `device-key`, `device-key#1`,
`session-key`, `session-key#1`, `refresh-token`, `refresh-token#1`, and four German-named orphans
(`geraeteschluessel`, `sitzungsschluessel`, each with its `#1`) that the conversion of 2026-09-12
had already stranded. They are not nothing: read-only `sqlite3` on the paired
`~/Library/Application Support/de.elasticdms.ordnerclient/zustand.sqlite` (114 688 bytes) returns
`device.enrolled`'s predecessor `geraet.enrollt|ja`, a confirmed key set, and the session row
`dev_4P019GSCGDVR83Z7HPV4SM97R7|SIGNED_IN|t_acme`. So this machine holds a completed enrolment
whose private device key sits in the keychain under a service name the repository no longer
contains.

Nothing in the tree can see it any more, and that is deliberate: `elasticdms --uninstall` and
`packaging/macos/elasticdms-uninstall.sh` were pointed at the new names only, and no build carries
the old spelling to look for. **Both are removed by hand, once, on this machine** — `rm -rf` the
directory and delete the ten keychain items — and nothing in the product searches for them. A
leftover-finder would have to name `de.elasticdms.ordnerclient` in code that no customer machine
can ever match, because no package with the old identity was published; it would be dead on the
day it shipped, and it would put the very string back in the tree that this pass removed. The
price of that decision is written here rather than paid in code: the next `doctor` on this machine
creates `…/de.elasticdms.folderclient`, mints a **new** device identifier and a **new** device key
(an empty slot is indistinguishable from a virgin machine, `crates/engine/src/device_key.rs`), and
drives the enrolment again — a second out-of-band confirmation by an administrator, per ADR-D12
decision 5 — while the old device stays registered and approved on the server with nothing on the
client pointing at it. That is the correct behaviour for a virgin machine and the correct price
for a development machine; it would be a defect only if a customer could reach it, and none can.

From the first package that leaves this repository the identity is an identity again: it is then
registered with the system, stands in MDM payloads and in customers' receipts, and changing it is a
migration and no longer a rename.

**Still open, and not part of this pass:** the consequence “operator surfaces stay English” holds
for `--help`, `doctor`, `--uninstall` and every `tracing` line, but decision 5 — `Display` is the
English diagnostic sentence — does not hold in the code. Measured on 2026-09-13, counting every
`#[error(…)]` text that carries an umlaut or a German function word: **189** of the workspace's
**314** such texts, in **25** files across `edms-cfapi`, `edms-crypto`, `edms-store`, `edms-net`,
`edms-wire`, `edms-fileprovider`, `edms-core` and the app (`edms-engine` has none). The counting
rule stands here because an earlier draft of this correction said “115 in 21 files” and no
threshold reproduces that figure; the crate list was right, the number was not. They are what
a support call quotes, so they belong in the same English as the rest; it is a pass of its own,
because a few of them are asserted on in tests.

The open pass is not cosmetic, and item 3 above does not fully hold until it is done: the operator
surfaces print an English **frame** around those sentences, and on a failure path the content
inside the frame is German. The worst case is the one nobody here can run: on Windows `elasticdms
--uninstall` forwards the cfAPI error verbatim (`mirror.clear_everything().map_err(|f|
f.to_string())`, `crates/app/src/uninstall.rs`), so a sync root that will not unregister prints
`The synchronisation root C:\… stayed behind:` followed by one of the 25 German sentences among
the 26 `#[error(…)]` texts in `crates/cfapi/src/error.rs`. The macOS build compiles the
`#[cfg(not(windows))]` stub instead, whose message is English, so no run on this machine can show
it. Translating those 25 is part of the open pass, not of this one.
