# ADR-D01: What the folder client is

**Status:** Accepted (2026-09-11).

## Context

The requirements lay down five things: the folders are read-only, without exception (1). An inbox
folder opens the browser with the capture workflow when a file is dragged in (2). The tree shows
case files (Akten) and saved searches (3). The view and the placeholder list are bound to the user
(4). Downloaded copies must be removable by delivery (5). Further points follow from those there —
one authorization path instead of two, dehydrating instead of deleting, long poll as the delivery
channel, every hydration a logged access, pinning no assurance, no silent disappearance, dynamic
folders.

## Decision

1. **A reading mirror.** Every writing operation in the mirror is refused: on macOS over the
   capabilities of the entries (`allowsReading` alone) and the refusal in `createItem`,
   `modifyItem`, `deleteItem`; on Windows over the veto in `NOTIFY_DELETE`/`NOTIFY_RENAME` and the
   attribute `FILE_ATTRIBUTE_READONLY` (for the limit see ADR-D06).
2. **The tree has a fixed shape** (`edms_core::namespace`): `Case files/`, `Saved searches/` and a
   file `README.txt` — in German `Akten/`, `Gespeicherte Suchen/` and `LIESMICH.txt` (ADR-D10).
   Below them one folder per case file or search, holding the documents.
3. **The list arrives from the server already filtered.** A folder listing is a search and runs
   server-side through the same ADR-008 path. The client filters nothing; it has nothing to filter.
4. **Every hydration runs over the server and is logged there** (proposal §7.2 in the contract).
   For that the client reports the name of the program that opens the file. The local usage log
   shows the same thing, but it is a display, not evidence (ADR-D07).
5. **No byte reaches the user's disk before the checksum matches** (`edms_core::port`).
6. **Removing means dehydrating**; only in the case of a DSGVO (the German GDPR implementation)
   erasure does the entry disappear as well (ADR-D04).
7. **The inbox folder lies next to the mirror, not inside it** (ADR-D08).
8. **Offline**, pinned and already loaded files open; a placeholder without a connection reports a
   network error to the program, which the operating system shows as “not available”. The tree
   stays visible; it is reconciled at the next contact.

## Rationale

The requirements leave little room, and that is a good thing. The two points at which the design
had to decide for itself:

- **Why the hint file `README.txt` (`LIESMICH.txt`)?** The requirement demands that the user be
  told *while pinning* that pinning is no assurance. Neither platform reports the moment of pinning
  to the provider in a shape a hint could hang on (Windows sets the pin state itself; macOS offers
  third parties no system entry for it at all). The file in the mirror is the only place every user
  sees before pinning.
- **Why check before handing over?** The server only notices a hash error at the last `Read`, after
  `200` has already been sent (`architecture.md`, blob path). Whoever passes bytes through puts down
  a mangled file and takes it for complete.

## Consequences

- The server needs endpoints that do not exist yet (gaps G-1 to G-24, contract
  `docs/spec/03-api-contract-folder-client.md`). Until then the client runs against `edms-mock`.
- Large files are loaded completely first and handed over afterwards. For a 200 MB PDF that costs
  disk space once in the staging directory; progressive loading therefore does not exist.

## Rejected alternatives

- **The inbox inside the mirror.** On macOS every filing would require a write path (`createItem`),
  on Windows there is no callback for new files — and both blur the rule that nothing comes into
  being inside the mirror.
- **Filtering in the client.** The second check, “and it drifts” (requirement).
- **Bidirectional synchronisation.** Explicitly not asked for.

## Correction to §2 and §7 (2026-09-12): three branches, and the drop target moves inside

Namespace v2 (**ADR-D11**, the owner's decision of that day) changes two of the eight points. The
rest of this ADR stands unchanged — the read-only rule of §1 above all.

* **§2, the shape of the tree.** Three branches instead of two: `Mailbaskets/`, `Archives/` and
  `Saved searches/` (de `Briefkörbe/`, `Archive/`, `Gespeicherte Suchen/`), with `README.txt`
  beside them. A case file no longer hangs under a top-level `Case files/` but under **its
  archive**, and it carries that archive in its identifier: `Container::Case { archive, case }`,
  text form `arc_…/cas_…`. `Cases` as a container is gone.
* **§7, the place of the inbox folder.** The drop target now lies **inside** the mirror: a mail
  basket. The folder next to the mirror is dropped (ADR-D08 §1, likewise corrected).

**What that does to the rejected alternative “the inbox inside the mirror”.** It is no longer
rejected, and the price named there is paid, not talked away: on macOS a basket really does need
`createItem`, on Windows cfAPI really does report no creation and `edms-cfapi` therefore looks
every few seconds instead of being told. What makes the answer a yes now is how narrow the path
can be cut: `Container::accepts_new_files()` is true for one container kind, the platform takes a
**creation** there and nothing else — no rename, no deletion, no folder, no write to an entry that
already stands. Everywhere else in the mirror the refusal of §1 is untouched. The reasoning stands
in ADR-D11.
