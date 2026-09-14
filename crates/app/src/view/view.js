// The window's script: it draws the usage log and sends clicks to the app.
//
// Two rules govern every line here:
//
// 1. **No `innerHTML` with data.** Names, locations and explanations come out of the archive;
//    they are set exclusively through `textContent`. A document called "<img onerror=…>.pdf" is
//    therefore a file name and not a script.
// 2. **No name on an erasure row.** The app sends none for ERASED_BY_ORDER anyway
//    (`edms_core::log` does not permit one at all), and here stands the second lock: even if one
//    did arrive, this page does not draw it.
//
// The local time is computed by the script, not by the core: the web view knows the machine's
// time zone (`edms_core::time`: "no local time here").
//
// 3. **No sentence of its own.** Every text comes out of the catalogue the app hands in
//    (`window.__edmsCatalog`, filled by `window::page`). A German string in this file would be a
//    second catalogue that nobody translates when the first one is translated.

(() => {
  "use strict";

  const field = (identifier) => document.getElementById(identifier);

  /** The text catalogue of this run, keyed by the same dotted paths the Rust side uses. */
  const CATALOG = window.__edmsCatalog || {};

  /** The sentence for a key. A key that is missing shows its own path — visible, and loud in the
   *  console; `edms-i18n`'s tests make sure it cannot happen in a shipped build. */
  function text(key) {
    const found = CATALOG[key];
    if (found === undefined) {
      console.error("no sentence in the catalogue for", key);
      return key;
    }
    return found;
  }

  /** A sentence with its named placeholders filled in — the same rule as `Catalog::format`: by
   *  name, never by position.
   *
   *  Every placeholder of one sentence in one call. Filling them one after another would mean
   *  looking the already filled sentence up as if it were a key, and the catalogue would report a
   *  key it does not have on every step of the wizard — MEASURED on 2026-09-13, in the console of
   *  the walk-through: "no sentence in the catalogue for Schritt 1 von {count}".
   *
   *  **One pass over the sentence, and the same one `Catalog::format` makes.** A loop of
   *  `String.replace` with a string argument differs from it twice: it replaces only the first
   *  occurrence of a name, and it looks at text it has already put in. Today every value passed
   *  is a number, so neither bites — but a catalogue sentence that named one placeholder twice
   *  would read differently in the window than in the menu, and that is the kind of difference
   *  nobody finds by looking. A name nothing was passed for stays standing, as it does there. */
  function fill(key, values) {
    return text(key).replace(/\{([^}]*)\}/g, (whole, name) =>
      Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : whole,
    );
  }

  /** The locale for Intl: number words and date formats follow the user interface. */
  const LANGUAGE = text("locale.tag");

  /** The glyph per log kind. Every kind of the core stands here; a new one falls into `default`
   *  and is reported as a gap by `every_log_kind_has_a_glyph` (window.rs). */
  const GLYPHS = {
    OPENED: "eye",
    OPEN_FAILED: "warning",
    NEW_VERSION: "cloud",
    SPACE_RECLAIMED: "cloud",
    ACCESS_REVOKED: "lock",
    ERASED_BY_ORDER: "recycle_bin",
    INGEST_ACCEPTED: "inbox",
    INGEST_FAILED: "warning",
    DEVICE_REGISTERED: "device",
    SIGNED_IN: "person",
    SIGNED_OUT: "person",
    LOGIN_REQUIRED: "lock",
    CONNECTION_LOST: "disconnected",
    CONNECTION_RESTORED: "connected",
    SECURITY_WARNING: "warning",
  };

  /** The paths of the glyphs, drawn on 24×24 (stroke, no fill). */
  const PATHS = {
    eye: ["M1.8 12S5.4 5.5 12 5.5 22.2 12 22.2 12 18.6 18.5 12 18.5 1.8 12 1.8 12Z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"],
    cloud: ["M7 18.5a4.2 4.2 0 0 1-.3-8.4 5.4 5.4 0 0 1 10.4-1.3A3.9 3.9 0 0 1 17.6 18.5Z", "M12 15.5v-6", "M9.6 11.9 12 9.5l2.4 2.4"],
    lock: ["M6.5 10.5h11v8h-11z", "M9 10.5V8a3 3 0 0 1 6 0v2.5", "M12 14v2"],
    recycle_bin: ["M5 7h14", "M9.5 7V5.2h5V7", "M7 7l.8 12h8.4L17 7", "M10.5 10.5v5.5", "M13.5 10.5v5.5"],
    inbox: ["M4 13.5h4l1.3 2.2h5.4L16 13.5h4", "M4 13.5 6.6 5.4h10.8L20 13.5v5H4Z"],
    device: ["M5.5 4.5h13v11h-13z", "M9 19.5h6", "M12 15.5v4"],
    person: ["M12 11.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z", "M4.8 19.5a7.2 7.2 0 0 1 14.4 0"],
    disconnected: ["M3 5.5 21 19", "M5.5 11.2a9 9 0 0 1 13 0", "M8.6 14.4a4.6 4.6 0 0 1 6.8 0", "M12 18.2h.01"],
    connected: ["M3.2 9.6a12 12 0 0 1 17.6 0", "M6.5 13.1a7.4 7.4 0 0 1 11 0", "M9.7 16.5a3 3 0 0 1 4.6 0", "M12 19.6h.01"],
    warning: ["M12 4.4 21 19.6H3Z", "M12 10v4", "M12 16.8h.01"],
    default: ["M12 4.5a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15Z", "M12 8.2v4.4", "M12 15.6h.01"],
  };

  const RELATIVE = new Intl.RelativeTimeFormat(LANGUAGE, { numeric: "auto" });
  const EXACT = new Intl.DateTimeFormat(LANGUAGE, { dateStyle: "full", timeStyle: "medium" });
  /** From the smallest to the largest unit, with the factor to the next one. */
  const UNITS = [
    ["second", 60],
    ["minute", 60],
    ["hour", 24],
    ["day", 7],
    ["week", 4.34524],
    ["month", 12],
    ["year", Infinity],
  ];

  /** "3 minutes ago", "2 days ago" — out of milliseconds since 1970, in the window's language. */
  function relative(millis) {
    let value = (millis - Date.now()) / 1000;
    for (const [unit, factor] of UNITS) {
      if (factor === Infinity || Math.abs(value) < factor) {
        return RELATIVE.format(Math.round(value), unit);
      }
      value /= factor;
    }
    return "";
  }

  function glyph(kind) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "glyph");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    for (const d of PATHS[GLYPHS[kind]] || PATHS.default) {
      const path = document.createElementNS(ns, "path");
      path.setAttribute("d", d);
      svg.appendChild(path);
    }
    return svg;
  }

  // The parameter is called `content`, not `text`: `text()` is the catalogue lookup, and a
  // parameter of that name would shadow it inside this function.
  function child(parent, tag, cls, content) {
    const element = document.createElement(tag);
    if (cls) {
      element.className = cls;
    }
    if (content !== undefined && content !== null) {
      element.textContent = content;
    }
    parent.appendChild(element);
    return element;
  }

  /** The visible line of a row: glyph, text, time. */
  function line(row, expandable) {
    const box = document.createElement("div");
    box.className = "line";
    box.appendChild(glyph(row.kind));

    // `body`, not `text`: `text()` is the catalogue lookup and must stay reachable in here.
    const body = child(box, "div", "text");
    child(body, "div", "label", row.label);
    // Lock 2 (see the header): an erasure row never gets a name here.
    if (row.name && row.kind !== "ERASED_BY_ORDER") {
      const name = child(body, "span", row.redacted ? "name redacted" : "name", row.name);
      if (row.redacted) {
        name.title = text("window.list.redacted_title");
      }
    }
    if (row.location) {
      child(body, "span", "location", row.location);
    }

    const time = child(box, "div", "time");
    const marker = child(time, "time", null, relative(row.time));
    marker.dateTime = new Date(row.time).toISOString();
    marker.title = EXACT.format(new Date(row.time));
    marker.dataset.time = String(row.time);
    if (expandable) {
      child(time, "span", "arrow", "›").setAttribute("aria-hidden", "true");
    }
    return box;
  }

  /** One row of the list; expandable when it has an explanation (keyboard: Tab and Space). */
  function build(row) {
    const entry = document.createElement("li");
    entry.className = `row severity-${String(row.severity).toLowerCase()}`;
    const more = row.detail || row.document;
    if (!more) {
      entry.appendChild(line(row, false));
      return entry;
    }
    const expander = child(entry, "details", null);
    const handle = child(expander, "summary", null);
    handle.appendChild(line(row, true));
    const explanation = child(expander, "p", "detail", row.detail || "");
    if (row.document) {
      child(explanation, "span", "identifier", row.document);
    }
    return entry;
  }

  // ── State ──────────────────────────────────────────────────────────────────

  const list = field("list");
  /** The smallest identifier shown — the cursor for "load older". */
  let oldest = null;
  /** The state as it last arrived. The set-up wizard reads the sign-in out of it, so that its
   *  sign-in page follows the device flow instead of a snapshot. */
  let shown = null;

  function showRows(message) {
    if (message.mode === "replace") {
      list.replaceChildren();
      oldest = null;
    }
    for (const row of message.rows) {
      list.appendChild(build(row));
      if (oldest === null || row.id < oldest) {
        oldest = row.id;
      }
    }
    const empty = list.childElementCount === 0;
    field("empty").hidden = !empty;
    list.hidden = empty;
    field("button-more").hidden = !message.more;
    field("button-more").disabled = false;
  }

  function showState(state) {
    shown = state;
    // With an account: the name as the heading, the state without it below. Without an account
    // there is no heading that could carry it — then the full line of the menu.
    field("account-name").textContent = state.account || "elasticdms";
    field("statusLine").textContent = state.account ? state.shortStatus : state.statusLine;
    // The engine's hint belongs in the message panel: with an account the status line shows only
    // the short state, and the sentence would otherwise be lost in the window (it would then stand
    // only in the menu).
    if (state.hint) {
      showMessage(state.hint);
    }
    field("dot").dataset.tone = state.tone;
    document.title = state.account
      ? text("window.title_with_account").replace("{account}", state.account)
      : "elasticdms";

    field("button-sign-in").hidden = !state.signInPossible;
    folderButton(field("button-folder"), state.folder, text("window.folder_missing"));
    folderButton(field("button-baskets"), state.baskets, text("window.baskets_missing"));

    const login = state.login;
    // While the wizard is open the panel stays away: it carries its own sign-in page, and the
    // panel would otherwise stand behind it and show the same code twice.
    field("login-panel").hidden = !login || !wizard.hidden;
    if (login) {
      field("userCode").textContent = login.userCode;
      field("login-address").textContent = login.address;
      field("login-anchor").textContent = login.anchor || text("window.login.anchor_missing");
    }
    if (!wizard.hidden) {
      showLogin();
    }
  }

  function folderButton(button, path, missing) {
    button.disabled = !path;
    button.title = path || missing;
  }

  /** The app's sentence, in the place that belongs to what the user is looking at.
   *
   *  While the wizard is open it goes **inside** the wizard, above its footer, and for two
   *  reasons. It belongs to the page that caused it — a refusal of a value is about the field one
   *  step back, not about the window. And the window's own message bar is `position: sticky;
   *  bottom: 0` like `.setup-foot` and stands later in the document, so it painted **over** "Back"
   *  and "Next": MEASURED at the shipped window height, each button covered for 28 of its 31
   *  pixels, and `document.elementFromPoint` at the centre of "Next" returned the message. The
   *  two buttons the user needs to answer the message were not reachable. */
  function showMessage(text) {
    const inWizard = !wizard.hidden;
    for (const [element, mine] of [
      [field("notice"), !inWizard],
      [field("setup-notice"), inWizard],
    ]) {
      element.textContent = mine ? text : "";
      element.hidden = !(mine && text);
    }
  }

  // ── The set-up wizard (ADR-D13) ────────────────────────────────────────────
  //
  // Three things are settled here and nowhere else in this file:
  //
  // 1. **The steps are read out of the document, never written down as a list.** On Windows the
  //    extension page is not in the page at all, on macOS the folder's place is not
  //    (`window::EXTENSION`, `window::MIRROR`); Back and Next are indices into what exists, so
  //    there is no index that reaches a step this build does not carry.
  // 2. **A fixed value is a line of text with the sentence that says where it comes from** — not
  //    a greyed-out field. A disabled field is a field that failed.
  // 3. **The check here is the one `edms_net::connection::check` makes**, shape only, no network.
  //    It is the immediate answer to "why is Next grey", not the verdict: the app checks the
  //    value again before it stores it, and says so in the message bar when it refuses.

  /** The longest value the app takes in one field (`message::MAX_VALUE`). Longer, and the whole
   *  request would be discarded on the other side with nothing but a line in the log — the user
   *  would have clicked "Next" and nothing at all would have happened. */
  const MAX_VALUE = 256;

  /** How often the extension page asks macOS again while it is open (ADR-D13 §9). */
  const EXTENSION_INTERVAL = 2000;

  /** The sentence for each reason a value cannot be changed here (`display::Fixed`). */
  const ORIGIN = {
    OPERATOR: "setup.fixed.operator",
    ENROLLED: "setup.fixed.enrolled",
    MIRROR: "setup.fixed.mirror",
    VARIABLE: "setup.fixed.variable",
  };

  /** The state line of the extension page, per `display::ExtensionState`. */
  const EXTENSION_TEXT = {
    ON: "setup.extension.on",
    OFF: "setup.extension.off",
    ASKING: "setup.extension.asking",
  };

  /** Whether the host behind `://` is this machine itself — the same comparison as
   *  `edms_net::connection::shows_on_loop`: the host as a whole, so that
   *  `127.0.0.1.foreign.example` is not the loopback. */
  function onLoop(authority) {
    const bracket = authority.indexOf("]");
    const host = bracket >= 0 ? authority.slice(0, bracket + 1) : authority.split(":")[0];
    return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
  }

  /** A base address, checked the way the app checks it. Returns the key of the sentence that says
   *  what is wrong, or `null`. */
  function checkAddress(raw) {
    const value = raw.trim().replace(/\/+$/, "");
    if (!value) {
      return "setup.wrong.empty";
    }
    const split = value.indexOf("://");
    if (split < 0) {
      return "setup.wrong.scheme";
    }
    const scheme = value.slice(0, split).toLowerCase();
    const rest = value.slice(split + 3);
    if (!rest || rest.startsWith("/")) {
      return "setup.wrong.host";
    }
    if (rest.includes("?") || rest.includes("#")) {
      return "setup.wrong.query";
    }
    // The refusal ADR-D13 §8 adds: what stands in front of an @ is the userinfo, and the host is
    // what stands behind it. An address written that way reads to a human like the right server
    // and would become the one every later "is this ours?" is measured against. The sentence in
    // the catalogue spells the example out; here no address is written at all, because no part of
    // this page may name an origin (`the_page_names_no_foreign_origin`).
    const authority = rest.split("/")[0];
    if (authority.includes("@")) {
      return "setup.wrong.userinfo";
    }
    if (scheme === "https") {
      return null;
    }
    if (scheme === "http") {
      return onLoop(authority) ? null : "setup.wrong.plaintext";
    }
    return "setup.wrong.scheme";
  }

  /** A value that only has to be there. */
  function checkPlain(raw) {
    return raw.trim() ? null : "setup.wrong.empty";
  }

  /** The enrolment code — its own sentence, because "this value is needed" would leave the user
   *  wondering where they are supposed to get it. */
  function checkCode(raw) {
    return raw.trim() ? null : "setup.wrong.code";
  }

  /** Where the mirror is to lie. Windows only — the field exists nowhere else. */
  function checkPath(raw) {
    const value = raw.trim();
    if (!value) {
      return "setup.wrong.empty";
    }
    if (!/^[A-Za-z]:[\\/]/.test(value) && !value.startsWith("\\\\")) {
      return "setup.wrong.path_absolute";
    }
    // The rule `EngineConfiguration::check_path` already enforces: three directories with three
    // jobs must not be the same one.
    const flat = (path) => path.replace(/[\\/]+$/, "").toLowerCase();
    const taken = [setup.dataPath, setup.stagingPath, setup.holdingPath].map(flat);
    return taken.includes(flat(value)) ? "setup.wrong.path_taken" : null;
  }

  /** Every value the wizard can ask about: where it stands, and how it is checked. A field whose
   *  element this build does not carry is left out when the page is read in. */
  const FIELDS = [
    // `show` turns a stored value into the one the user reads. Only the language needs it: it is
    // kept as a tag (`de`), and a line of text saying "de" would be the set-up talking to itself.
    // A tag with no name behind it stays as it is rather than showing a key path — the list of
    // languages is closed (`edms_i18n::Language`), but a stored value is not the page's to vouch
    // for.
    {
      name: "language",
      page: "welcome",
      check: null,
      show: (raw) => CATALOG["setup.language." + raw] || raw,
    },
    // The one address. Its value is not the app's — `setup.base` is put together here out of
    // the three below, because the app said they are one question (`SetupView.oneAddress`) — and
    // nothing travels back under this name: `typed` sends the one answer as all three.
    //
    // `suggest` is the only place in this page where a field may stand filled with something
    // that does not hold: the development address, while elasticdms is not released
    // (`setup::DEVELOPMENT_BASE`). The app decides whether there is one at all.
    {
      name: "base",
      page: "server",
      check: checkAddress,
      suggest: () => (setup && setup.suggestedBase) || "",
    },
    { name: "apiBase", page: "server", check: checkAddress },
    { name: "authBase", page: "server", check: checkAddress },
    { name: "appBase", page: "server", check: checkAddress },
    { name: "deviceName", page: "workstation", check: checkPlain },
    { name: "mirrorPath", page: "workstation", check: checkPath },
    { name: "enrollmentCode", page: "code", check: checkCode },
  ];

  /** The set-up as the app last reported it (`message::Notice::Setup`). */
  let setup = null;
  /** The steps of this device, in document order. */
  let steps = [];
  /** Which of them is shown. */
  let at = 0;
  /** The timer of the extension page; `null` while no such page is open. */
  let asking = null;
  /** What is outstanding, and what is to happen when the app's set-up message comes.
   *
   *  * `null` — nothing was asked for. A set-up message is then the app's own invitation (it
   *    opens the wizard on a workstation that has not been set up, ADR-D13 §11) and opens it.
   *  * `"open"` — the "Set-up" button asked for it.
   *  * `"next"` — "Next" handed values over; the page after this one is where to go, and only
   *    once the app has said the values were taken.
   *  * `"left"` — an answer is still on its way and the user has left the wizard. It is dropped:
   *    a just-closed wizard must not pop back open over the log. */
  let expecting = null;

  const wizard = field("setup");
  const PAGES = Array.from(document.querySelectorAll(".setup-page"));

  for (const definition of FIELDS) {
    definition.box = document.querySelector('[data-field="' + definition.name + '"]');
    if (!definition.box) {
      continue;
    }
    definition.control = definition.box.querySelector(".setup-input");
    definition.control.maxLength = MAX_VALUE;
    definition.control.addEventListener("input", () => {
      definition.box.dataset.typed = "yes";
      checkStep();
    });
    definition.control.addEventListener("blur", () => {
      definition.box.dataset.typed = "yes";
      checkStep();
    });
  }

  function page(name) {
    return PAGES.find((p) => p.dataset.page === name);
  }

  /** The three addresses, in the order the app carries them. */
  const ADDRESSES = ["apiBase", "authBase", "appBase"];

  /** The fields of one page that this build carries **and this device shows**.
   *
   *  The second half is the address page: either the one field or the three, never both. A box
   *  that is not in the page is not a field of it — it is not checked, it is not a reason for the
   *  page to be a step, it is not a fact, and nothing is sent from it. */
  function fieldsOf(name) {
    return FIELDS.filter((d) => d.page === name && d.box && !d.box.hidden);
  }

  function valueOf(name) {
    return setup ? setup[name] : null;
  }

  function isOpen(name) {
    const value = valueOf(name);
    return Boolean(value) && value.fixed === "NO";
  }

  /** Whether a field stands on the page the user is standing on.
   *
   *  Only one field in this wizard needs to be asked (`typed`, and the measurement beside it):
   *  the one that may stand filled with something nobody typed. */
  function isOnPage(definition) {
    return Boolean(definition && steps[at]) && steps[at].dataset.page === definition.page;
  }

  /** Whether a page is a step on this device. A page on which nothing is open is not a step
   *  (ADR-D13 §3); its values stand as facts on the first page instead. */
  function isStep(name) {
    switch (name) {
      case "server":
      case "workstation":
        return fieldsOf(name).some((d) => isOpen(d.name));
      case "code":
        return !setup.enrolled && isOpen("enrollmentCode");
      case "extension":
        return setup.extension !== "ON";
      default:
        return true;
    }
  }

  /** The value as the user reads it — see `show` in [`FIELDS`]. */
  function shownValue(definition, value) {
    return definition.show ? definition.show(value.value) : value.value;
  }

  /** One value as a line of text with the sentence that says where it comes from. */
  function fact(list, label, value, reason) {
    child(list, "dt", null, label);
    const box = child(list, "dd", null, value);
    if (reason) {
      child(box, "p", "setup-origin", text(reason));
    }
  }

  /** Everything from a page that is not a step here — shown, never hidden (ADR-D13 §3). */
  function showFacts() {
    const list = field("setup-facts-list");
    list.replaceChildren();
    for (const name of ["server", "workstation"]) {
      if (isStep(name)) {
        continue;
      }
      for (const definition of fieldsOf(name)) {
        const value = valueOf(definition.name);
        const label = definition.box.querySelector(".setup-label").textContent;
        fact(list, label, shownValue(definition, value), ORIGIN[value.fixed]);
      }
      if (name === "workstation") {
        fact(list, text("setup.workstation.data"), setup.dataPath, null);
        fact(list, text("setup.workstation.staging"), setup.stagingPath, null);
        fact(list, text("setup.workstation.holding"), setup.holdingPath, "setup.fixed.variable");
      }
    }
    field("setup-facts").hidden = list.childElementCount === 0;
  }

  /** Which shape the address page has — one question or three (ADR-D13, correction of
   *  2026-09-14).
   *
   *  **The app decides it, not this page.** `SetupView.oneAddress` is true only when the three
   *  addresses carry the same text through the same channel. The moment they differ — an
   *  administrator who set one of the three variables, three hosts out of a policy — the three
   *  stand here as they were given. A page that averaged them would either throw two of an
   *  administrator's values away or show one value as if it held for three.
   *
   *  The one field's value is put together here because there is no such value on the other
   *  side: it is the first of three that are all the same. Nothing travels back under this name;
   *  `typed` sends the one answer as all three. */
  function placeAddresses() {
    const one = Boolean(setup.oneAddress);
    setup.base = one ? { value: setup.apiBase.value, fixed: setup.apiBase.fixed } : null;
    for (const definition of FIELDS) {
      if (!definition.box) {
        continue;
      }
      if (definition.name === "base") {
        definition.box.hidden = !one;
      } else if (ADDRESSES.includes(definition.name)) {
        definition.box.hidden = one;
      }
    }
    const paragraph = field("setup-server-text");
    paragraph.textContent = text(one ? paragraph.dataset.text : paragraph.dataset.textSeparate);
  }

  /** Whether two addresses name the same host — the page's half of `doctor::is_development`.
   *
   *  A trailing slash and the case of scheme and host say nothing about which server is meant
   *  (RFC 3986 §6.2.2.1), and the app folds exactly these two away before it objects. Only ASCII
   *  case, like `str::eq_ignore_ascii_case` on the other side: `toLowerCase` also folds
   *  characters outside ASCII, and two sides of one comparison that fold differently are a
   *  difference nobody finds by looking. */
  function sameAddress(one, other) {
    const fold = (raw) =>
      raw
        .trim()
        .replace(/\/+$/, "")
        .replace(/[A-Z]/g, (letter) => letter.toLowerCase());
    return fold(one) === fold(other);
  }

  /** The sentence under the address field while it carries the development address
   *  (`setup::DEVELOPMENT_BASE`, which the app names in `developmentBase`).
   *
   *  It stands for as long as that address stands in the field — however it got there and however
   *  it is written — and it goes the moment somebody types over it: the sentence says what is
   *  *in* the field.
   *
   *  It used to be tied to the suggestion of **this** render (`suggestedBase`, which the app
   *  sends only while no channel carries an address at all) and compared byte for byte. Both
   *  halves switched the one warning this design has off in the ordinary case. MEASURED on
   *  2026-09-14: the address as the app stores it — the same host without the trailing slash the
   *  offer carries — did not match the offer; and one "Next" followed by one "Back" brought the
   *  page back with the address stored, nothing suggested any more, and no sentence under a
   *  field labelled "Address of your archive". */
  function showSuggestion() {
    const base = FIELDS.find((d) => d.name === "base");
    const standing =
      Boolean(setup && setup.developmentBase) &&
      Boolean(base && base.box && !base.box.hidden) &&
      isOpen("base") &&
      sameAddress(base.control.value, setup.developmentBase);
    field("setup-development").hidden = !standing;
  }

  /** A value as a field, or as a line of text with its origin. */
  function showField(definition) {
    const value = valueOf(definition.name);
    const box = definition.box;
    const open = value.fixed === "NO";
    const label = box.querySelector(".setup-label");
    const line = box.querySelector(".setup-value");
    const origin = box.querySelector(".setup-origin");
    const hint = box.querySelector(".setup-hint");
    definition.control.hidden = !open;
    line.hidden = open;
    origin.hidden = open;
    if (hint) {
      hint.hidden = !open;
    }
    if (open) {
      // The one place in this page where a field may stand filled with something that does not
      // hold — see `suggest` in FIELDS. Everywhere else `value.value` is the effective value or
      // nothing at all.
      definition.control.value = value.value || (definition.suggest ? definition.suggest() : "");
      // A label points at its field; without one it is the heading of a fact and points nowhere.
      label.htmlFor = definition.control.id;
    } else {
      line.textContent = shownValue(definition, value);
      origin.textContent = text(ORIGIN[value.fixed]);
      label.htmlFor = "";
    }
    delete box.dataset.typed;
  }

  /** Where the wizard stands after the steps have been worked out afresh.
   *
   *  By the page's name and not by the old index: which pages are steps is recomputed from the
   *  answer, and a page can stop being one between two renders — the device name closes at the
   *  enrolment, the code page falls away once `enrolled`. An index kept across that lands on a
   *  different page than the one the user pressed "Next" towards. */
  function placeOf(wasOn, advance) {
    const last = steps.length - 1;
    const found = wasOn === null ? -1 : steps.findIndex((p) => p.dataset.page === wasOn);
    const here = found < 0 ? Math.min(at, last) : found;
    return Math.max(0, Math.min(advance ? here + 1 : here, last));
  }

  /** The whole wizard, from the message the app sent.
   *
   *  The app answers `applySetup` with the whole view (event_loop.rs: "Afresh afterwards, and
   *  only then"), and that answer can arrive after the user has already left the wizard — from
   *  "Back" on the first page, or from "Done". Acting on it then would reopen the wizard over the
   *  log, which is what `"left"` is for. Everything else opens it, the app's own invitation
   *  included. */
  function showSetup(view) {
    if (expecting === "left") {
      expecting = null;
      return;
    }
    const advance = expecting === "next";
    const wasOn = steps[at] ? steps[at].dataset.page : null;
    expecting = null;
    setup = view;
    // Before the fields are drawn: it decides which of them are in the page at all, and
    // `showField` on a box that is not is a line of text nobody sees being kept up to date.
    placeAddresses();
    for (const definition of FIELDS) {
      if (definition.box && !definition.box.hidden) {
        showField(definition);
      }
    }
    showSuggestion();
    field("setup-counterpart").hidden = view.reason !== "COUNTERPART";
    field("setup-data-path").textContent = view.dataPath;
    field("setup-staging-path").textContent = view.stagingPath;
    field("setup-holding-path").textContent = view.holdingPath;
    showFacts();
    showLogin();

    steps = PAGES.filter((p) => isStep(p.dataset.page));
    at = placeOf(wasOn, advance);
    wizard.hidden = false;
    for (const element of [field("header"), field("login-panel"), field("main")]) {
      element.hidden = true;
    }
    showStep();
  }

  /** The sign-in step and the folder on the last page.
   *
   *  Both read the **live** state and not the set-up message: the code appears while this page is
   *  open, and a page that only knew what the set-up message once said would show an empty box
   *  for the whole device flow. */
  function showLogin() {
    const login = shown ? shown.login : null;
    field("setup-signed-in").hidden = !(shown && shown.account && shown.status === "SIGNED_IN");
    field("setup-login").hidden = !login;
    field("setup-sign-in").hidden = !(shown && shown.signInPossible);
    field("setup-login-page").hidden = !login;
    if (login) {
      field("setup-user-code").textContent = login.userCode;
      field("setup-login-address").textContent = login.address;
      field("setup-login-anchor").textContent = login.anchor || text("window.login.anchor_missing");
    }
    field("setup-done-folder").hidden = !(shown && shown.folder);
    field("setup-folder").textContent = (shown && shown.folder) || "";
  }

  /** What a step is called in the list.
   *
   *  The address page has two names, exactly as it has two paragraphs (`placeAddresses`): one
   *  address is "Address", three that were given apart are "Addresses". The list is read together
   *  with the page it points at, and a singular over a page carrying three fields is the two of
   *  them disagreeing in writing. */
  function stepName(element) {
    const separate = element.dataset.stepSeparate;
    return separate && setup && !setup.oneAddress ? separate : element.dataset.step;
  }

  /** The step indicator, the two buttons, and which page is on. */
  function showStep() {
    const list = field("setup-steps");
    list.replaceChildren();
    steps.forEach((element, place) => {
      const entry = child(list, "li", null, text(stepName(element)));
      entry.dataset.state = place === at ? "current" : place < at ? "done" : "open";
    });
    field("setup-count").textContent =
      fill("setup.step", { number: at + 1, count: steps.length });
    for (const element of PAGES) {
      element.hidden = element !== steps[at];
    }
    const last = at === steps.length - 1;
    field("setup-next").hidden = last;
    field("setup-finish").hidden = !last;
    askAboutExtension();
    checkStep();
  }

  /** The forward button lights up when every open field of this step is right, and every field
   *  that is wrong says so in a sentence of its own.
   *
   *  The sentence appears as soon as something stands in the field — not only when it is left.
   *  A grey button with no explanation is a dead end, and this is the explanation. An untouched
   *  empty field says nothing: on arriving at a page nobody has filled in yet, "this value is
   *  needed" under every field would be a page full of complaints about the user's inactivity. */
  function checkStep() {
    let right = true;
    for (const definition of fieldsOf(steps[at] ? steps[at].dataset.page : "")) {
      if (!isOpen(definition.name) || !definition.check) {
        continue;
      }
      const raw = definition.control.value;
      const wrong = raw.length > MAX_VALUE ? "setup.wrong.too_long" : definition.check(raw);
      const say = wrong && (raw.trim() !== "" || definition.box.dataset.typed === "yes");
      const message = definition.box.querySelector(".setup-wrong");
      message.hidden = !say;
      message.textContent = say
        ? wrong === "setup.wrong.too_long"
          ? fill(wrong, { count: MAX_VALUE })
          : text(wrong)
        : "";
      // The border follows the sentence and never stands on its own: a red field with nothing
      // said about it is a colour saying "no" and nothing else — and on arriving at a page nobody
      // has filled in yet, every field would be red at once. MEASURED on 2026-09-13 at 470 px:
      // two empty fields in red, no sentence anywhere.
      definition.box.dataset.wrong = say ? "yes" : "no";
      right = right && !wrong;
    }
    field("setup-next").disabled = !right;
    field("setup-finish").disabled = !right;
    // Here too, and not only when the page is drawn: this runs on every keystroke, and the
    // sentence about the development address has to go the moment it stops being true.
    showSuggestion();
  }

  /** What the user typed, for the app.
   *
   *  Only what was offered: a fixed value is not the page's to send, and the app would discard it
   *  anyway (ADR-D13 §1). And only what stands there: a field the user has not reached yet
   *  travels as nothing, not as an empty value — the store's door refuses an empty value and says
   *  so, and "Next" on the address page would answer with a complaint about the enrolment code
   *  three pages further on. Nothing can be *cleared* this way, and nothing should be: every
   *  field here is one the client cannot work without, and "Next" stays grey while one is empty. */
  function typed() {
    const values = {};
    for (const definition of FIELDS) {
      // The one address is this page's own field and not a value of the app's: it answers for
      // the three below, which is what the loop after this does. A member named `base` in the
      // message would be a value nothing on the other side has ever heard of.
      if (definition.name === "base") {
        continue;
      }
      const raw =
        definition.box && !definition.box.hidden && isOpen(definition.name)
          ? definition.control.value.trim()
          : "";
      values[definition.name] = raw === "" ? null : raw;
    }
    // One question, three answers. The three settings stay what they always were — the
    // administrator who sets one of the three variables apart is still answered value by value
    // (ADR-D13 §1 and its correction of 2026-09-14) — and what changed is only how often the
    // user is asked. Each of the three goes through the store's own door on the other side, so
    // one that is refused is refused on its own.
    //
    // **And only from the page it stands on.** Every other field is empty until somebody types in
    // it, so "not reached yet" and "empty" are the same thing and the rule above carries them.
    // This one is not: it is the only field in the wizard that may stand filled with something
    // nobody typed (`suggest` in FIELDS), and without this line the first "Next" — pressed on the
    // overview page, two pages before the address is so much as explained — made the development
    // address a value of this workstation. MEASURED on 2026-09-14 in the preview of a fresh
    // unmanaged workstation: one click on "Step 1 of 7" posted the development host as `apiBase`,
    // `authBase` and `appBase`, and the sentence saying what that address is was never shown to
    // anybody.
    const base = FIELDS.find((d) => d.name === "base");
    if (isOnPage(base) && base.box && !base.box.hidden && isOpen("base")) {
      const one = base.control.value.trim() || null;
      for (const name of ADDRESSES) {
        values[name] = one;
      }
    }
    // What the check accepted is what is stored: the trailing slash is gone, so that the app
    // compares against one string and not two.
    for (const name of ADDRESSES) {
      if (values[name]) {
        values[name] = values[name].replace(/\/+$/, "");
      }
    }
    return values;
  }

  /** Hands the values over before the page that needs them; `true` when something was sent.
   *
   *  Whoever sends waits: the app answers `applySetup` with the whole view on success and with a
   *  refusal on failure, and only the answer says which of the two happened. */
  function handOver() {
    if (!fieldsOf(steps[at].dataset.page).some((d) => isOpen(d.name))) {
      return false;
    }
    send({ kind: "applySetup", values: typed() });
    return true;
  }

  /** The extension page asks macOS while it is open, and stops asking when it is left. */
  function askAboutExtension() {
    const open = steps[at] && steps[at].dataset.page === "extension";
    if (!open) {
      if (asking !== null) {
        clearInterval(asking);
        asking = null;
      }
      return;
    }
    showExtension(setup.extension);
    send({ kind: "checkExtension" });
    if (asking === null) {
      asking = setInterval(() => send({ kind: "checkExtension" }), EXTENSION_INTERVAL);
    }
  }

  /** What macOS answered — and, when it is on, the step is over: the user has just switched
   *  something on in another app and should not have to come back here and confirm it. */
  function showExtension(state) {
    if (setup) {
      setup.extension = state;
    }
    const line = field("setup-extension-state");
    if (!line) {
      return;
    }
    line.dataset.state = state;
    line.textContent = text(EXTENSION_TEXT[state] || EXTENSION_TEXT.ASKING);
    if (state === "ON" && steps[at] && steps[at].dataset.page === "extension") {
      steps = PAGES.filter((p) => isStep(p.dataset.page));
      at = Math.min(at, steps.length - 1);
      showStep();
    }
  }

  /** Back to the window. The wizard keeps nothing: what it had, the app has. */
  function leaveSetup() {
    if (asking !== null) {
      clearInterval(asking);
      asking = null;
    }
    // An answer that is still on its way belongs to the wizard the user has just closed, and is
    // dropped when it arrives.
    expecting = expecting === null ? null : "left";
    showMessage("");
    wizard.hidden = true;
    at = 0;
    for (const element of [field("header"), field("main")]) {
      element.hidden = false;
    }
    // The **live** state, as everywhere else in this file (`showState`, `showLogin`). It used to
    // read `setup`, which is the `SetupView` from `Notice::Setup` — and `display::SetupView` has
    // no `login` member at all, so the expression was `!undefined` and the panel came back hidden
    // every single time. MEASURED with a device flow running: leaving the wizard took the code
    // the user has to type into their browser off the screen, until the next state push happened
    // to arrive.
    field("login-panel").hidden = !(shown && shown.login);
  }

  // ── The fixed texts of the page ────────────────────────────────────────────

  /** Fills every element that names a key. The page carries the keys, the catalogue the words.
   *
   *  An element may name a second key for the build that carries the folder's place
   *  (`data-text-with-mirror`). Which one holds is read out of the document, like the steps
   *  themselves: the field is in the page on Windows and nowhere else, so a sentence that
   *  promises to ask where the folder lies is only said where it is asked. */
  function fillTexts() {
    const withMirror = FIELDS.some((d) => d.name === "mirrorPath" && d.box);
    for (const element of document.querySelectorAll("[data-text]")) {
      const other = element.dataset.textWithMirror;
      element.textContent = text(withMirror && other ? other : element.dataset.text);
    }
  }

  // ── The way to the app ─────────────────────────────────────────────────────

  function send(message) {
    if (window.ipc && typeof window.ipc.postMessage === "function") {
      window.ipc.postMessage(JSON.stringify(message));
    }
  }

  function onClick(identifier, message) {
    field(identifier).addEventListener("click", () => {
      showMessage("");
      send(typeof message === "function" ? message() : message);
    });
  }

  /** The same, for a button that only one platform's page carries. A missing element is the
   *  normal case here and not a typo — `onClick` stays strict so that a typo in a button that
   *  does exist still breaks loudly. */
  function onClickIfThere(identifier, message) {
    if (field(identifier)) {
      onClick(identifier, message);
    }
  }

  onClick("button-sign-in", { kind: "signIn" });
  onClick("button-folder", { kind: "openFolder" });
  onClick("button-baskets", { kind: "openBaskets" });
  onClick("button-login-page", { kind: "openLoginPage" });
  onClick("button-setup", () => {
    expecting = "open";
    return { kind: "openSetup" };
  });
  onClick("setup-sign-in", { kind: "signIn" });
  onClick("setup-login-page", { kind: "openLoginPage" });
  onClickIfThere("setup-extension-open", { kind: "openExtensionSettings" });
  onClickIfThere("setup-extension-again", { kind: "checkExtension" });

  // Back on the first step leads out of the wizard and not into nothing: whoever opened it by
  // hand has to be able to leave it by hand (ADR-D13 §11 — never a dead end).
  field("setup-back").addEventListener("click", () => {
    showMessage("");
    if (at === 0) {
      leaveSetup();
      return;
    }
    // An answer to a "Next" that is still on its way must not carry the user forward from the
    // page they have just gone back to.
    expecting = null;
    at -= 1;
    showStep();
  });

  // Forward only once the app has taken the values. The answer is asynchronous, and advancing in
  // the same breath meant that a refusal — a store that will not write, or the second,
  // authoritative `connection::check` catching something this page's copy let through — arrived
  // while the user was already one page on, about a field they could no longer see. `showSetup`
  // is what moves on, because it is what knows the values were taken.
  field("setup-next").addEventListener("click", () => {
    showMessage("");
    if (handOver()) {
      expecting = "next";
      return;
    }
    at = Math.min(at + 1, steps.length - 1);
    showStep();
  });

  // "Done" leaves either way: the last page is **reached**, not succeeded (ADR-D13 §11), and a
  // device waiting for its approval has finished its set-up honestly. A refusal of the values
  // then stands in the window's message bar, where the wizard's own has just gone.
  field("setup-finish").addEventListener("click", () => {
    showMessage("");
    handOver();
    send({ kind: "completeSetup" });
    leaveSetup();
  });
  field("button-more").addEventListener("click", () => {
    showMessage("");
    field("button-more").disabled = true;
    send({ kind: "loadOlder", beforeId: oldest === null ? 0 : oldest });
  });

  /** The app delivers here (`message::Notice::as_script`). */
  window.receive = (message) => {
    switch (message.kind) {
      case "state":
        showState(message.state);
        break;
      case "rows":
        showRows(message);
        break;
      case "error":
        // This is the answer that was being waited for, and it is a no: the page stays where it
        // is, and the sentence stands under the fields it is about.
        expecting = null;
        showMessage(message.text);
        field("button-more").disabled = false;
        break;
      case "setup":
        showSetup(message.setup);
        break;
      case "setupExtension":
        showExtension(message.state);
        break;
      default:
        break;
    }
  };

  // "3 minutes ago" has to become "4 minutes ago" without anybody reopening the window.
  setInterval(() => {
    for (const marker of list.querySelectorAll("time[data-time]")) {
      marker.textContent = relative(Number(marker.dataset.time));
    }
  }, 30000);

  fillTexts();

  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  send({ kind: "ready", language: navigator.language || null, timeZone: zone || null });
})();
