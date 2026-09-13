# ADR-D13: The set-up wizard — what the administrator decides, and what the user sees of it

**Status:** Proposed (2026-09-13). Nothing of this is built. What is measured below was measured on
macOS 26.6 (build 25G72); everything else is read in this repository on the same day and says where.
Every statement about a running Windows machine is marked as unproven — there is none here.
*On the number:* `D10`, `D11` and `D12` are taken; `D13` is the next free one.

## Context

The client is set up today through nine `EDMS_*` variables, and three of them are mandatory: without
`EDMS_API_BASE`, `EDMS_AUTH_BASE` and `EDMS_APP_BASE` the start aborts with a sentence on the error
output that names the missing variable and its purpose (`crates/app/src/setup.rs`). The sentence is
right, and it reaches nobody. The comment in `packaging/windows/elasticdms.wxs` says so about its
own case — *“on a managed device nobody would see it”* — and on an unmanaged one it is a terminal
message from a program that has no terminal: the macOS login item starts the app at sign-in,
deliberately without `KeepAlive`, so exactly one failed start stands in the system log and the
person in front of the screen sees nothing at all.

The two kinds of device are not the same case, and today both get the same treatment:

* **Managed.** The three addresses come with the MSI as public properties and are written as
  **system** variables (`elasticdms.wxs`, component `Environment`); on macOS they stand in
  `EnvironmentVariables` of `/Library/LaunchAgents/de.elasticdms.folderclient.plist` when they were
  set at build time, and otherwise come from an MDM payload afterwards (`docs/DELIVERY.md`). The
  enrolment code can come with them — `EDMS_ENROLLMENT_CODE`, the unattended case
  `crates/engine/src/config.rs` already names. Everything else takes the defaults in `setup.rs`.
* **Unmanaged.** Nothing at all, and the defaults in `setup.rs` for the rest.

So the wizard has two jobs that pull against each other: ask an unmanaged user for everything nobody
has told the client, and ask a managed user for **nothing** — while still letting them see what
their device was told, because which server this client speaks to is the fact the whole
anti-phishing check rests on (`EDMS_APP_BASE` and `edms_wire::basics::is_below`).

And one step that no installer on macOS can take off the user: ADR-D05 §4 — the extension has to be
switched on by hand, and until then the domain is `userEnabled = false` and every access hangs.

## The question that decides the shape

**What wins when an administrator has set a value and the user changes it?**

This is not a matter of taste. A user who can repoint `EDMS_API_BASE` can aim a client that holds a
signed-in session, a device key and a mirror of a GoBD archive at a server of someone else's
choosing. Repointing all three moves the anti-phishing check along with the target: `is_below`
compares an address from an answer against `app_base`, so whoever sets `app_base` decides what
counts as “our own web interface”. The only thing that would still hold is the anchored key set
(ADR-D04 §3): a foreign server cannot sign a delivery command. It can do everything else.

## Measured and read, not assumed

1. **The System Settings pane has a name and an identifier, and both are stable in two directions.**
   `/System/Library/ExtensionKit/Extensions/LoginItems.appex/Contents/Info.plist` on macOS 26.6:
   `CFBundleIdentifier = com.apple.LoginItems-Settings.extension`,
   `allowsXAppleSystemPreferencesURLScheme = true`, `alt_name = Login Items & Extensions`, and
   `url_alias` contains the older identifier `com.apple.ExtensionsPreferences` — the pane answers
   to both, so a button built on either keeps working. Its `Localizable.loctable` carries
   `Login Items & Extensions` / `Anmeldeobjekte & Erweiterungen`, its `InfoPlist.loctable`
   `Login Items` / `Anmeldeobjekte`.
   **Not proven:** that a query parameter jumps to the *File Providers* section. No settings pane's
   `loctable` on this machine carries the string “File Provider” at all (searched over every
   `/System/Library/ExtensionKit/Extensions/*/Contents/Resources/*.loctable`), and the pane binary
   yields no `extensionPointIdentifier` string. Whoever builds the button checks the deep link on a
   screen before the catalogue sentence quotes a section heading.
2. **`edms_net` refuses plaintext off the loopback and accepts userinfo on https.**
   `crates/net/src/connection.rs`, `check` and `shows_on_loop`: the loopback exception compares the
   host as a whole, so `http://127.0.0.1@attacker.example` and `http://attacker.example@127.0.0.1`
   are both refused — but the `https` arm returns `Ok` for anything that has a host and no query or
   fragment. Transcribed into a script and exercised: `https://api.elasticdms.io@attacker.example`
   is **accepted** today.
3. **The same fault was already found and fixed one crate higher.** `check_login_address` /
   `is_loopback` in `crates/app/src/event_loop.rs` refuses an `@` in the host part and says why:
   *“in `http://localhost:8481@foreign.example/`, `localhost:8481` is the userinfo part and
   `foreign.example` is the host”*. That check guards the browser target, not the base address.
4. **Only the three addresses travel through any delivery path today.** `EDMS_LANG`,
   `EDMS_DEVICE_NAME` and `EDMS_MIRROR_PATH` appear in no installer, no script and no plist
   (grepped over `packaging/` and `scripts/`; `EDMS_MIRROR_PATH` occurs twice in
   `packaging/windows/README.md`, as prose about the uninstall).
5. **On macOS `EDMS_MIRROR_PATH` decides nothing.** Outside the Windows branch,
   `crates/app/src/platform.rs` reads `let _ = mirror_path;`. The root is named by File Provider
   and lies under `~/Library/CloudStorage/` (`crates/fileprovider/src/domain.rs`).
6. **The seam for the extension question already exists and says what it is for.**
   `MacFileSystem::management()`: *“The management, for instance to query `userEnabled` for the user
   interface”*, and `DomainDetails.enabled`: *“until then every access hangs (measured, ADR-D05).
   The app should say so.”*
7. **The uninstall takes the database with it.** Windows: `uninstall::clear_state` removes the whole
   local state directory, and keeps only the holding directory when files still lie in it awaiting
   the server's confirmation — `state.sqlite` goes in both branches. macOS:
   `packaging/macos/elasticdms-uninstall.sh` removes
   `~/Library/Application Support/de.elasticdms.folderclient`, which is what
   `ProjectDirs::from("de", "elasticdms", "folderclient")` resolves to there.
8. **The setting table is already used this way.** `device.enrolled`, `delivery.cursor`,
   `session.identity-guessed`, `key-set` — dotted keys, text values, and a header that says what it
   is not for: *“never for secrets (ADR-D03, point 4)”*.
9. **The catalogue test compares against the key list, not against call sites.**
   `no_catalogue_carries_a_key_the_program_does_not_ask_for` measures the two TOML files against
   `edms_i18n::KEYS`. A page that exists only on macOS therefore costs the catalogue nothing, as
   long as its key constants stay unconditional.

## Decision

### 1. The environment wins. For every value, and without an exception list.

Every value resolves in this order, and in no other:

```text
EDMS_* in this process's environment  ->  the setting table  ->  the computed default (setup.rs)
```

**To set it is to fix it.** A value an administrator has set is a value the administrator has
decided; the wizard shows it and does not offer it. A value they have not set is the user's, all the
way down to the default.

No per-value exception, and no second channel through which an administrator could mark a value as
“the user may override this one”. Two reasons, and the second is the heavier: an exception list is a
place where a mistake becomes invisible — one wrong column and the address is user-writable again —
and the operator would have to learn a second mechanism to say what the absence of a variable
already says.

*What it costs, named:* a user on a device whose operator sets `EDMS_LANG` cannot change the
language of their own user interface, which is a decision about a person's eyes, not about a
tenant. Today that costs nothing at all (measurement 4: no delivery path sets it, and the MSI has
properties for exactly three values), and the operator who wants to hand the choice back does it by
not setting the variable. If that ever starts to hurt, the place to change it is this paragraph, not
the resolution order.

### 2. A stored value is never deleted because the environment speaks. It lies dormant.

The obvious tidiness — “the environment carries it, so throw the stored one away” — is wrong here,
and this repository's own way of working says why: a run against the mock sets the three addresses
on the command line and nothing else (`README.md`, *Getting started*; `EDMS_DATA_PATH` is not among
them), so it lands on the **default** data path. A client that deleted its settings whenever a
variable stood would wipe a developer's own configured client on every such run.

Dormant values are only safe because of §4: if the environment falls silent again and the dormant
value points somewhere else, the seal fires and the device is set up afresh instead of quietly
speaking to yesterday's server.

### 3. A fixed value is a line of text with its origin named, never a greyed-out field

* **Open value:** an input field, prefilled with the current effective value.
* **Fixed value:** the value as text, and beneath it one catalogue sentence: *“Your IT department
  has set this for this device.”* No input, no lock icon, no tooltip. A disabled field is a field
  that failed; a line of text is a fact about the device.
* **The sentence does not name the variable.** `EDMS_API_BASE` is an operator surface: it belongs in
  `doctor`, in English, out of the catalogue (the rule `crates/engine/src/report.rs` already
  follows), and `doctor` gains a column naming the source of each value — environment, setting, or
  default. A support call then has one place to look, and the user's window is not it.
* **If every value of a page is fixed, that page is not a step.** Its values stand as a short block
  on the first page instead (“This client speaks to …”), with the same origin sentence. On a fully
  managed device the wizard is therefore: what this is (with the three addresses as facts) → sign in
  → on macOS switch the folder on → done. Nobody clicks through a form with nothing in it, and the
  one fact that matters against phishing is still read once, on the first screen.

### 4. The counterpart this device enrolled against is remembered; a changed one is a re-set-up

At the enrolment the three effective addresses are written to the `setting` table
(`counterpart.api-base`, `counterpart.auth-base`, `counterpart.app-base`), exactly as `edms_net`'s
check returned them. At every start, before the engine is built, they are compared against the
effective values. If the device is enrolled (`device.enrolled = yes`), all three stored values are
there and one of them differs, the client does not start into the new counterpart. Instead it

1. builds the engine against the **stored** addresses, signs out through the normal path
   (`Engine::sign_out`: revoke at the old server, clear the mirror, empty the namespace, forget the
   session — the revoke may fail and the clearing happens anyway), stops it,
2. clears `device.enrolled` and `key-set` — the anchored key set belongs to the old server, and an
   anchor from another tenant would silently discard every delivery command of the new one (“when in
   doubt, preserve” would become “never again”),
3. keeps the device key and the device identifier (they are this machine's, and a new device key is
   a different device — ADR-D12 §6),
4. opens the wizard at a page that says what happened, in one sentence, without blaming anyone.

This is what makes §1 more than a good intention. The resolution order decides which value the
**client** prefers; it cannot stop a value from changing underneath it. The seal turns a silent
re-point into a visible re-set-up.

`[GAP → PROPOSAL]` A client enrolled before this exists has no stored counterpart. It writes the
three keys at its next start, against whatever addresses it then has, and the seal is armed from
there. That is the honest best available: nobody can reconstruct where a device was enrolled.

### 5. The pages, and what each of them is for

| # | Page | Shown |
|---|---|---|
| 1 | **What this is** — the folder is a view, every opening is recorded; and the language | always |
| 2 | **The server** — the three addresses | only if one of them is open (§3) |
| 3 | **This workstation** — the device name; on Windows the folder's place | only if one is open |
| 4 | **The enrolment code** | only when not enrolled and no code stands in the environment |
| 5 | **Sign in** — the device flow: user code, check code, the button to the page | always |
| 6 | **Switch the folder on** — System Settings | macOS only, while `userEnabled` is false |
| 7 | **Done** — what is set, where the folder lies, how to come back here | always |

Why these, and why in this order:

* **Page 1 carries the language** because every page after it is read in that language, and it
  carries the one sentence about what this folder is — the sentence that otherwise first appears in
  `README.txt` *inside* a mirror that does not exist yet.
* **Page 4 comes before page 5** because the enrolment is the first thing `sign_in` does
  (`place_device_safe`), and a device flow that stops at a missing code would show the user a
  failure for a value nobody asked them for.
* **Page 6 comes after page 5** because the domain does not exist before the sign-in: `place_ready`
  needs the account identifier, and the engine calls it once the session stands.
* **The wizard asks for nothing it can work out.** The device name is prefilled from the chain
  `setup.rs::device_name` already computes (`COMPUTERNAME`, `HOSTNAME`, `USERNAME`, `USER`); the
  folder's place is prefilled with `~/elasticdms`; the language is prefilled from the resolution
  ADR-D10 already decided. Three addresses and an enrolment code are what an unmanaged device
  cannot know, and they are all it is asked.
* **The wizard lives in the existing window** (`wry`, the embedded page, the typed `message.rs`
  protocol), as a second page beside the usage log, with new `Request`/`Notice` variants. It is not
  a second window and not a program of its own: a set-up that ran before the app would have to build
  a second user interface for the same catalogue, and the window is where this client already
  explains itself. This widens ADR-D07's *“the first and for now only content: the local usage
  log”* by exactly one page; nothing else of D07 moves, and the tray menu gains no entry.

### 6. What the wizard stores, and what it refuses to store

| Setting key | holds | sign-out | uninstall |
|---|---|---|---|
| `setup.api-base`, `setup.auth-base`, `setup.app-base` | the three addresses | stays | goes |
| `setup.device-name` | the name in the console | stays | goes |
| `setup.mirror-path` | the folder's place — **Windows only** (measurement 5) | stays | goes |
| `setup.language` | the language of the user interface | stays | goes |
| `setup.completed` | `yes` once the last page was reached | stays | goes |
| the three `counterpart.…-base` keys | §4; written at the enrolment | stays | goes |

*Goes* means: with the database, and only with it — see below.

**Nothing of this goes on sign-out.** Requirement 4 is about the user's name and the user's
documents, and `clear_after_sign_out` clears exactly those. An address is not a person; a client
that forgot its tenant every time somebody signed out would make the next person type it again, and
`setup.completed` that fell away would reopen the wizard after every sign-out — the nag this ADR
exists to avoid.

*The one uncomfortable row is the device name.* A user may type “Jane Doe's laptop”, and that stays
on disk after a sign-out. It stays anyway, because it belongs to the machine and not to the session:
the operator sees it in the console and a device that renamed itself on every sign-out would be
unusable for an inventory. The field carries a catalogue sentence saying that the IT department sees
this name and that it should name the machine.

**They live in the `setting` table and nowhere else**, and the reason is measurement 7: the table
lies in `state.sqlite`, and the uninstall on both platforms removes the directory that holds it. A
JSON file beside the binary, an `HKCU` key or a plist would each need a new line in
`crates/app/src/uninstall.rs` **and** in `packaging/macos/elasticdms-uninstall.sh`, and a forgotten
line there is a tenant address that outlives the uninstallation.

**The enrolment code is not stored.** It goes from the field straight into
`Engine::set_enrollment_code` and lives in memory until the enrolment consumes it. It is a one-time
secret from the console; a copy in a database nobody ever reads again is a copy that can leak. If
the enrolment fails, the user types it again — the field is on the page they came from.

**Three values the wizard shows and does not offer:**

* `EDMS_DATA_PATH` — the setting table lives at the end of this path. A setting that says where the
  settings live cannot live among them, and a second place to keep it would be exactly the second
  place the paragraph above refuses. Shown as text, changeable only with the variable.
* `EDMS_STAGING_DIR` — a scratch area. The only real question here is which volume, and a user who
  chooses one can only make it worse: a network path would make every hydration slow, a removable
  one would break it mid-file. `doctor` already watches the free space (`SPACE_MIN`).
* `EDMS_HOLDING_DIR` — files the server has not yet confirmed lie there, and the uninstall protects
  only the default place (`uninstall.rs` says so itself). A user-movable holding directory is a user
  who can move the last copy of a handed-in document somewhere the clean-up does not look.

`EDMS_VAULT` and `EDMS_LOG` are development and diagnostic switches and do not appear in the wizard
at all — `EDMS_VAULT=memory` moves the device key out of the keychain, which is not a thing to offer
behind a friendly label.

*The field closes when the value is spent:* the device name is editable until the enrolment, the
folder's place until a sync root is registered — afterwards each is a line of text with a sentence
saying what would have to happen first. A mirror path changed under a registered root would leave
that root behind, and Windows remembers roots per volume (`packaging/windows/README.md`).
`[GAP → PROPOSAL]` Whether the counterpart takes a later rename of a device is not settled here;
until it is, the name closes at the enrolment.

### 7. One resolver, in two stages, for the app, `doctor` and the wizard

`setup::configuration()` is today the only resolver, and it reads only the environment. It grows a
second stage rather than a second reader:

```text
stage 1 (no store):   data path, staging, holding, vault choice   — environment or computed default
                      create_directories, Store::open
stage 2 (with store): the three addresses, device name, mirror path, language
                      — environment → setting → default
                      then build_engine(configuration, store)
```

`build_engine` opens the store today; it takes the open one instead. `doctor` uses the same resolver
and therefore stops saying “the setup does not stand” about a client that runs perfectly well from
its settings — which it would do the moment the wizard exists and nothing else changed. Two readers
of one configuration would be two answers to the same question, which is the argument
`crates/engine/src/config.rs` already makes about checking the addresses twice.

If the store cannot be opened at all, the start still aborts with the English sentence on the error
output, exactly as today: without a database there is nothing to configure and nowhere to put it.

### 8. Validation: shape only, and in `edms_net`. No network.

The wizard checks with **the same function the environment path uses** —
`edms_net::connection::check`, made public for this. A second judgement about the same string would
be a second answer.

That function gains one refusal, and the refusal helps both paths: **an authority carrying userinfo
is not an address.** `https://api.elasticdms.io@attacker.example` is accepted today (measurement 2),
reads to a human like the right server, and would become the `app_base` that every later
“is this address ours” question is measured against. The app already refuses exactly this for
browser targets and says why (measurement 3); the check belongs where the value enters, not only
where it is used.

Beyond that the wizard checks: the value is not empty after trimming; the three addresses are three
values, each mandatory on its own; the folder's place is absolute and is none of the other two
directories (the rule `check_path` already enforces). It stores what the check returned, trailing
slash removed — so that `is_below` compares against one string and not two.

**It does not reach the server. Deliberately.** Four reasons:

1. **Neither outcome is a verdict on the typed text.** A server that answers proves nothing about
   *which tenant* it is, and a server that does not answer is far more often a VPN that is not up, a
   laptop being set up at home the evening before its first office day, or a proxy.
2. **The real check is one page later and it is an authenticated one.** The enrolment
   (`PUT /v1/devices/{deviceId}`) comes back with the tenant's own key set and anchors it. That is a
   checked answer, not a ping. The sign-in page reports its failure in a whole sentence and the user
   walks **back** to the address page — that back button is the ergonomics a reachability test was
   supposed to buy, and it is honest.
3. **A probe would be the first request this client ever sends to an address a user typed**, from a
   process that holds a device key, before anything about that address has been established.
   Nothing leaks through a bare handshake, but redirects, timeouts, proxies and certificate prompts
   would all have to be got right for an answer that decides nothing.
4. A wizard that asked the user about a certificate would be teaching them to click through
   certificate warnings.

The wizard also does not check whether the three addresses belong to the same tenant — it cannot
know — and does not create the mirror: `place_ready` owns that root, and *“a second creator of the
same root would be a second owner”* (`config.rs`).

### 9. macOS: how the wizard learns the extension is on — and what it does not touch until it is

The header of `crates/fileprovider/src/domain.rs` is the constraint: *“Every call waits at most one
deadline … `removeDomain` was measured hanging for a domain whose extension had never started
(`userEnabled = false`). Never call from the main thread.”*

* The wizard asks **only** `DomainManagement::domain()` and reads `DomainDetails.enabled`. Every
  other call on that domain — signal, evict, visible location, remove — is **not made** while
  `enabled` is false. That is the rule the warning forces, and it is one a review can hold to.
  `getDomainsWithCompletionHandler` is a class method and asks the system for its list of domains,
  not our extension for anything; that it therefore cannot hang is **not proven**, which is why the
  next point matters more than the reasoning.
* Always off the user-interface thread, always through the existing deadline
  (`DEFAULT_DEADLINE`, 30 s). **A timeout is read as “not on yet”, never as an error**: the page
  says the same thing either way, and a dialog about `NSFileProviderErrorDomain` would be a sentence
  nobody can act on.
* The page polls every two seconds while it is open, and carries a *Check again* button for the
  person who does not want to wait. When `enabled` turns true, the page moves on by itself — the
  user has just switched something on in another app and should not have to come back and confirm
  it.
* The button opens `x-apple.systempreferences:com.apple.LoginItems-Settings.extension`
  (measurement 1). The old identifier `com.apple.ExtensionsPreferences` is kept as the fallback,
  because it is the one macOS itself lists as the alias. Whether a deeper link into the *File
  Providers* section works is unproven and is not built on a guess.
* **The user may leave without switching it on.** Done stays available: the client is otherwise
  finished, and a wizard that could not be left would be a wizard that has to be killed. What
  remains is a status the app carries for as long as `enabled` is false — the sentence
  `DomainDetails` already asks for. That is the honest nag: a status line, not a window that jumps
  up.

*Named beside this, because whoever builds page 5 will meet it:* `place_ready` calls `remove_all`
first, and `remove_domain` is exactly the call measured hanging. On a Mac carrying a stale domain
from another account, the sign-in step can sit for one deadline per domain. That belongs in the
sign-in page's waiting text, not in a surprise.

### 10. Windows has no extension step, and the catalogue keeps its sentences all the same

Page 6 exists behind `#[cfg(target_os = "macos")]`, not behind a runtime `if`. A page that exists on
Windows but never shows is a page a wrong index can reach, and the wizard's Back/Next are indices.

The **key constants stay unconditional** in `catalogue_keys!`, and both TOML files carry the
sentences on both platforms. Measurement 9: the catalogue test compares the files against
`edms_i18n::KEYS`, so a `cfg` on the page costs nothing — while a `cfg` on the keys would break the
Windows build of the test suite the day somebody ran it.

Every sentence of the wizard lives under `setup.` in both catalogues. Nothing in the page's HTML,
per ADR-D10 and the rule `window.rs` states: the page carries key paths, the app puts the catalogue
in.

### 11. When it opens by itself, and when it stops

It opens by itself at start when, and only when, one of three things holds:

1. a mandatory value is missing after the resolution of §7 — the client cannot work at all;
2. `setup.completed` is not `yes` — this device has never been walked through to the end;
3. §4 fired — the counterpart changed, and it opens at the page that says so.

It never opens with `--demo`, which has no store to read and nothing to configure. And it never
opens by itself for an expired session, a device waiting for approval, a signed-out user, a
switched-off extension or an unreachable server. Every one of those already has its place — the
status line, the sign-in panel in the window, the menu (ADR-D07) — and a window jumping up for them
is precisely the nagging this decision forbids.

**`setup.completed` is written when the last page is reached, not when everything works.** A device
can finish its set-up honestly and still be waiting for an administrator to approve its fingerprint
(`EngineState::AwaitingApproval`), or sit behind a VPN that is not up. Completing only on full
success would mean a wizard that reopens at every login on a device that is waiting for somebody
else — the nag again, and this time aimed at the person who can do least about it.

It stays reachable by hand from the window at any time, and on a device where nothing is open it
shows the facts and one sentence saying the IT department set this device up. Never a dead end.

## Rationale

Two things here were ours to settle; everything else follows from them or from a measurement.

**Why the environment and not the user.** The distribution channel is the argument. `DELIVERY.md`
and the MSI are built for a device an operator owns, and on such a device the operator is
accountable for where the documents come from — the GoBD and DSGVO arguments this archive carries
are theirs to answer for, not the user's. A precedence that let the user win would make every
central setting a suggestion, and the one setting that must not be a suggestion is the address the
signed-in session speaks to. The reverse cost is small and visible: an unmanaged user is asked once
for the four values nobody else can supply — three addresses and a code.

**Why a wizard at all, rather than a better error message.** Because the error message is already
good and reaches nobody (Context). The values the client needs are not knowable by the client, and
the one person who can supply them on an unmanaged device has no terminal, no `launchctl print` and
no reason to know either exists.

## Consequences

- **The app must be able to run without an engine.** No addresses, no `Connection`, so no `Engine`.
  The event loop holds its `DisplaySource` behind one swap point, set once when the wizard completes
  and the engine is built. A re-exec of the process would have been simpler and is wrong: it drops
  the single-instance lock, and on macOS the launch agent will not start it again.
- **`doctor` grows a column** (environment / setting / default) and loses its right to say “the
  setup does not stand” for values a wizard supplied.
- **`edms_net::connection::check` becomes public and one refusal stricter.** The stricter refusal
  can in principle break an installed client whose administrator set an address with userinfo in it
  — which would be an address nobody should have set, and the start then names it.
- **`crates/app/src/cli.rs` HELP keeps every variable** and gains one sentence: these values can
  also be set in the client, and a value set here wins. The help text stays English and outside the
  catalogue (it is an operator surface).
- **The window gains a second view**, so `message.rs` gains request and notice kinds and `view.js`
  a second view to render. The protocol stays closed and typed — an unknown kind stays an error,
  not an addition.
- **A first start on an unmanaged Mac now ends in a window** instead of a failed launch agent. That
  is the point, and it means the app must reach the tray and the web view before it has a
  configuration.

## Rejected alternatives

- **The user wins, the administrator's value is a default.** This is the shape most desktop
  applications have, and it is the one shape this product cannot have: it makes the tenant address a
  suggestion (see “The question that decides the shape”).
- **A per-value policy saying which values a user may override.** A second mechanism to learn, and a
  list in which one wrong entry silently re-opens the address. The absence of a variable already
  says “the user decides”.
- **Deleting the stored value when the environment carries one.** Tidier on paper; it would wipe a
  developer's configured client on every mock run against the default data path (§2).
- **A configuration file, a registry key or a plist instead of the `setting` table.** Each needs a
  line in two uninstall paths, and a forgotten line is a tenant address that outlives the
  uninstallation (measurement 7).
- **Asking for one tenant address and deriving the other two** (`api.`, `auth.`, `app.`). That is
  inventing two hostnames from one, and one of the invented ones is where the sign-in secret goes —
  the exact mistake `config.rs` refuses when it declines a default for `EDMS_API_BASE`.
- **Fetching a discovery document to fill the fields.** OIDC discovery would at best confirm the
  authorization server; it names neither the resource API nor the web interface, so two of the three
  values would still be typed — and the wizard would have made a network request that decides
  nothing (§8).
- **Testing reachability before storing.** Same reason, in full in §8.
- **A separate set-up program that runs before the app.** A second user interface for the same
  catalogue, a second binary to sign and notarise, and a second place where the resolution order
  could be got wrong.
- **A nag dialog or a FileProviderUI extension for the macOS step.** The extension point would buy a
  button inside Finder and costs a second `.appex` to sign; the status line and a page in the wizard
  say the same thing for nothing.
- **Making the wizard the place to change tenant later.** It is not. A changed counterpart is a
  sign-out and a re-enrolment (§4), and dressing that up as an editable field would hide the fact
  that everything local is thrown away.

## Residual risk, named

**On Windows the precedence decided here does not reach the place where it would matter most.** The
MSI writes the three addresses as **system** variables (`System="yes"` in `elasticdms.wxs`), and
per Microsoft's documented behaviour a user's own variable in `HKCU\Environment` takes precedence
over the machine's for that user's processes. A user who can set their own environment — which
needs no administrator on Windows — can therefore hand this client a different `EDMS_API_BASE`
before it ever reaches the resolution order above. **Not measured here:** there is no Windows
machine in this project; Windows is compile-checked only.

So what §1 actually buys is narrower than it looks, and it is worth saying plainly: it keeps the
wizard — the friendly, discoverable, one-click surface — from being the tool that does it. The
operating system's environment stays what it always was. What catches the rest is §4: the client
notices that it is being pointed somewhere else, throws away the mirror and the session before it
speaks a word to the new address, and says so. A determined user can still set their machine up
against another server. They cannot do it quietly, and they cannot carry yesterday's signed-in
session across.

The same gap exists on macOS wherever a user can edit the launch agent's environment, and there it
needs `sudo` for `/Library/LaunchAgents` — which is the difference between the two platforms and the
reason this risk is named for Windows first.
