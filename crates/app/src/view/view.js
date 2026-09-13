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
    field("login-panel").hidden = !login;
    if (login) {
      field("userCode").textContent = login.userCode;
      field("login-address").textContent = login.address;
      field("login-anchor").textContent = login.anchor || text("window.login.anchor_missing");
    }
  }

  function folderButton(button, path, missing) {
    button.disabled = !path;
    button.title = path || missing;
  }

  function showMessage(text) {
    const element = field("notice");
    element.textContent = text;
    element.hidden = !text;
  }

  // ── The fixed texts of the page ────────────────────────────────────────────

  /** Fills every element that names a key. The page carries the keys, the catalogue the words. */
  function fillTexts() {
    for (const element of document.querySelectorAll("[data-text]")) {
      element.textContent = text(element.dataset.text);
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

  onClick("button-sign-in", { kind: "signIn" });
  onClick("button-folder", { kind: "openFolder" });
  onClick("button-baskets", { kind: "openBaskets" });
  onClick("button-login-page", { kind: "openLoginPage" });
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
        showMessage(message.text);
        field("button-more").disabled = false;
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
