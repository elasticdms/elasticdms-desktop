# ADR-D08: Inbox folder next to the mirror

**Status:** Accepted (2026-09-11).

## Context

Requirement 2: *„Zieht ein Nutzer eine Datei hinein, öffnet sich der Browser und startet den
Erfassungsvorgang. Der Eingangsordner ist ein Auslöser, kein Ablageziel."* — “If a user drags a
file in, the browser opens and starts the capture workflow. The inbox folder is a trigger, not a
filing destination.” What stayed open: 200 files at once; the user closes the browser before
tagging; behaviour when offline.

## Decision

1. **An ordinary folder next to the mirror** — Windows `%USERPROFILE%\elasticdms Eingang`, macOS
   `~/elasticdms Eingang`. No placeholder, no platform API. The name stays German for now: it is a
   path on installed machines, and renaming it needs a migration (ADR-D10).
2. **Upload first, then open the browser.** The clarification-case invariant (`scope-cut` A6)
   demands: *„Ein Ereignis endet nie ohne persistiertes Ergebnis."* — “An event never ends without
   a persisted result.” If the document is already in the inbox, a closed browser is harmless —
   **question 2 answered.**
3. **A file counts as finished** when size and modification time have stood still for two seconds;
   files with `.crdownload`, `.part`, `.tmp` or a `~$` prefix are passed over.
4. **Many files at once:** taken over in a queue (at most three at a time), one error per file,
   never one for the whole batch. For up to three files one capture tab opens each; for more,
   **one** tab opens with the mailbox (`/postkorb`, which already exists in the server) — 200 tabs
   would no longer be a workstation. **Question 1 answered.**
5. **After the take-over** the file moves to `Eingangsordner/.uebertragen/<uploadId>/` — never
   deleted: until the server has confirmed the ingest, the local file is the only copy (GoBD
   completeness — the German principles for keeping books and records in electronic form).
6. **Offline**, files stay put, the icon shows “N files waiting”, and the take-over starts by itself
   at the next contact. **Question 3 answered** (for the inbox; for the mirror see ADR-D01,
   point 8).

## Consequences

- The server needs an upload path for clients (gap G-20, contract §7.4).
- Duplicate files are not suppressed but marked (`duplicateOf`); the human in the browser decides.

## Correction to §1 and §5 (2026-09-12): the mail basket takes the place of the folder

Namespace v2 (**ADR-D11**) moves the drop target into the mirror. Two of the six points change;
the other four are the reason this ADR is corrected and not replaced — they were about handing
over a file, not about where it lay.

* **§1, the place.** Not `%USERPROFILE%\elasticdms Eingang` / `~/elasticdms Eingang` next to the
  mirror, but a **mail basket inside** it: `Mailbaskets/<basket>/` (de `Briefkörbe/<Briefkorb>/`),
  one folder per basket the server lists. `Container::accepts_new_files()` is true for a basket and
  for nothing else, and it is the only place that decides it. Nothing is installed anywhere yet, so
  there is no folder to migrate; the German name of the old folder, and the migration that hung on
  renaming it, are gone with it.
* **§5, where the file goes afterwards.** Not `Eingangsordner/.uebertragen/<uploadId>/` but
  `<holding>/<uploadId>/` in the app's own data directory (`EDMS_HOLDING_DIR`). **Never deleted**
  stays: until the server has confirmed the ingest the local file is the only copy (GoBD
  completeness). What changes is only that our spool no longer lies in the mirror — the mirror
  shows the server's truth, and a file of ours in it would be the one entry the server knows
  nothing about.
* **New, and not a correction but an addition:** the submission names the basket it came out of
  (`basketId`, contract §7.4.1). A basket that is no longer visible is answered `404 not-found`;
  the file stays lying where it is and is filed nowhere else.

**Unchanged:** upload first, then the browser (§2); a file counts as finished when size and
modification time have stood still for two seconds, and `.crdownload`, `.part`, `.tmp`, `~$…` are
passed over (§3); at most three at a time, above three files one tab with the mailbox (§4);
offline everything stays lying and goes by itself at the next contact (§6). And the sentence of
requirement 2 that this ADR is built on holds for the basket word for word: *„Der Eingangsordner
ist ein Auslöser, kein Ablageziel."* — a trigger, not a filing destination.
