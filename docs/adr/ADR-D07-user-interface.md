# ADR-D07: User interface — tray icon and usage log

**Status:** Accepted (2026-09-11).

Every operating system gets an icon in the taskbar or menu bar whose menu offers signing out and
opening the app, and the app shows the local usage log.

## Decision

- **Icon:** Windows in the notification area, macOS in the menu bar (as a template image that
  adapts to light and dark mode). Menu: status line · Open elasticdms · Open folder · Open inbox
  folder · Sign in/Sign out · Quit.
- **A window on demand**, and closing it does not mean quitting — the app lives on in the icon. On
  macOS there is no dock icon.
- **The first and for now only content: the local usage log** (`edms_core::log`), newest row first:
  opened, local copy released, access revoked, erased by order, taken into the inbox, sign-in,
  connection, security warning.
- **It says what it is:** “Local view – the authoritative access log is kept by the server.”
- **Rows belong to the account** that was signed in. Another user on the same machine does not see
  them (requirement 4).
- **Technology:** tao (event loop), wry (web view; WebView2 on Windows, WebKit on macOS),
  tray-icon (icon and menu) — the same foundation as Tauri, without its framework. The page is
  embedded, loads nothing afterwards and navigates nowhere.
- **Every sentence comes from the catalogue** (`edms-i18n`, ADR-D10). The page carries keys, not
  sentences.

## Rationale

The event loop belongs to the program, not to the window: an icon program lives on without a window
and opens one again when needed. With eframe/egui the loop belongs to the window, and a hidden
window gets no more updates on macOS — the “Open” menu entry would then hang on exactly the part
that is not running.

## Rejected alternatives

- **eframe/egui** — see the rationale.
- **Tauri as a framework** — it brings a bundler of its own, which collides with the hand-built
  macOS extension.
- **Two native user interfaces** — two code bases for one list.

## Correction to the menu (2026-09-12): “Open mailbaskets” instead of “Open inbox folder”

Namespace v2 (**ADR-D11**) moved the drop target into the mirror, so the entry that opened the
folder next to it has no folder left to open. In its place the catalogue carries `menu.baskets` —
“Open mailbaskets” / „Briefkörbe öffnen“. The rest of this ADR is untouched, the usage log
included: `LogKind::IngestAccepted` keeps its meaning, because the inbox it names is the server's
and never was a folder on the disk.
