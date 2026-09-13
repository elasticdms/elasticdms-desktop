# ADR-D11: Namespace v2 — three branches, and the drop target inside the mirror

**Status:** Accepted (2026-09-12).

Corrects ADR-D01 §2 and §7 and ADR-D08 §1 and §5; both carry a correction section of that date and
are otherwise untouched.

## Context

The tree of ADR-D01 §2 had two branches, and each of them had a hole.

**A case file floated.** `Container::Case(CaseIdentifier)` named an Akte and not the archive it
hangs in. While the client only listed case files that stayed invisible. It stops being invisible
at the first endpoint that has to address one: the listing path needs the archive
(`GET /v1/mirror/archives/{arc}/cases`, contract §7.1.1), `Container::parent()` cannot be computed
without it, and every layer above would have had to keep a lookup table for something the
identifier can say itself.

**The drop target lay outside.** ADR-D08 §1 put it next to the mirror,
`%USERPROFILE%\elasticdms Eingang` / `~/elasticdms Eingang` — a second place, with a German name
on installed machines whose renaming needs a migration (ADR-D10), and the one folder of this
product a user has to be told about before they can use it. The hint file in the mirror does
exactly that today: it points out of the mirror at a folder next to it.

ADR-D01 rejected the inbox *inside* the mirror, and the reason was right: on macOS a filing needs
a write path (`createItem`), on Windows cfAPI has no callback for a creation at all. What this
decision changes is not that price but what is bought for it. With mail baskets the drop target
lies where the user is already looking, and the write path can be cut so narrow that requirement 1
— the folders are read-only, without exception — survives it: one kind of container, one operation,
nothing else.

## Decision

1. **Three branches under the root.** `edms_core::namespace` has the fixed shape:

   ```text
   <root>                                  Container::Root            read-only
   ├── README.txt                          Hint{Root, ReadMe}         (de: LIESMICH.txt)
   ├── Mailbaskets/                        Container::Baskets         read-only
   │   └── <basket>/                       Container::Basket(bsk_…)   files may be put here
   ├── Archives/                           Container::Archives        read-only
   │   └── <archive>/                      Container::Archive(arc_…)  read-only
   │       └── <case file>/                Container::Case{archive, case}
   │           └── <document>.pdf          Document{Location::Case{…}, doc_…}
   └── Saved searches/                     Container::Searches        read-only
       └── <search>/                       Container::Search(srch_…)
           ├── <document>.pdf              Document{Location::Search(…), doc_…}
           └── Result list truncated – README.txt   Hint{Search(…), Truncated}
   ```

   `Cases` as a top-level container is **gone**, and with it the catalogue key `mirror.cases`.

2. **A case file carries its archive.** `Container::Case { archive, case }`, and
   `Location::Case { archive, case }` with it. The text form of the entry identifier — a key, never
   translated — is `arc_…/cas_…`, the document below it `arc_…/cas_…/doc_…`. The old forms `cases`
   and a bare `cas_…` are a read error (`EntryIdentifierError::Shape`), not a silent
   reinterpretation.
   *Reason:* Guessing an archive for a stored `cas_…` would be an invention with the weight of a
   filing. A row that cannot be read is thrown away (point 8); a row that is read wrongly stays.

3. **A basket is a trigger, not a heap.** `Container::accepts_new_files()` is `true` for
   `Basket(_)` and `false` everywhere else, and it is **the only place that decides it**: the
   platform layers ask that function instead of matching on variants of their own, so that a
   container added later is writable in every layer at once or in none. Inside a basket the
   platform takes a **file creation** and nothing further — no rename, no deletion, no folder, no
   write to an entry that already stands there.

4. **A basket lists nothing of the server's.** There is no `…/baskets/{id}/documents`; a basket
   holds no document, because the document is filed into an archive. What a user drops in stays
   visible locally until the ingest is confirmed — until then the local copy is the only one (GoBD
   completeness, ADR-D08 §5) — and disappears from the basket afterwards, because it is then in an
   archive.

5. **The external inbox folder is gone**, and the spool goes with it. The file awaiting
   confirmation moves into the app's own data directory, `<holding>/<uploadId>/`
   (`EDMS_HOLDING_DIR`), never into a hidden folder inside the mirror.
   *Reason:* The mirror shows the server's truth. A file of ours lying in it would be the one entry
   in the tree the server knows nothing about — and the first question at the next reconciliation
   would be what to do with it.

6. **The two new names come from the catalogue, the titles do not.** `mirror.baskets`
   (de `Briefkörbe`, en `Mailbaskets`) and `mirror.archives` (de `Archive`, en `Archives`);
   `mirror.searches` stays. The names of baskets, archives, case files and searches are server
   titles and are **not** translated — they pass through `filename::name` as before: sanitised,
   free of collisions, stable.

7. **The wire follows the tree** (contract §7.1.1, §7.4): six listing endpoints under `/v1/mirror`,
   a case file addressed below its archive, and a submission that names the basket it came out of
   (`basketId`). A basket that is no longer visible is answered `404 not-found` — the document is
   filed nowhere else.

8. **The store empties instead of guessing.** Schema 5 clears `entry`, `container_state` and the
   journal, and lets the change counter run on by one — the anchor of the old tree then expires
   instead of being answered with changes of the new one. The next contact fetches the whole tree
   afresh.
   *Reason:* The namespace tables are a cache of the server's truth, and the truth has changed
   shape. Rewriting rows would mean inventing the archive of every stored case file.

## Rationale

Two of the eight points were ours to decide; the rest follow from them.

**Why the archive stands in the identifier and not in a table.** The alternative is a map from
`cas_…` to `arc_…`, kept somewhere — in the store, or in the engine's memory. That map has to be
filled before the first listing can be answered, has to survive a restart, and is exactly the kind
of state that is right on the development machine and stale on the twentieth workstation. The
identifier carries 26 characters more and needs no map at all.

**Why the basket may be written to and everything else may not.** Requirement 2 asks for a place
where a file dragged in starts the capture workflow. Any such place needs a write path on macOS,
and on Windows a way to notice the creation — cfAPI reports none, so `edms-cfapi` looks every few
seconds instead (`crates/cfapi/src/intake.rs` names the three reasons; the engine takes a file only
once its size and modification time have stood still for two seconds, ADR-D08 §3, so a watch that
reported the creation in the same millisecond would buy nothing). Given that the path has to exist,
the question is only how wide it is. One container kind, one operation, decided in one function, is
the narrowest shape in which the answer is still a yes.

## Consequences

- **The store file of this build cannot be opened by the previous one.** Schema 5: an older build
  sees `SchemaTooNew`, and a schema-4 file opened read-only reports `SchemaStale` — the engine has
  to open it for writing once. Nothing is installed anywhere yet, so there is no inbox folder to
  migrate either (namespace v2 §5).
- **The hint file says something else.** It told the user about `elasticdms Eingang` next to the
  mirror; that folder no longer exists. `mirror.readme.body` in `crates/i18n/catalog/*.toml` now
  names the three branches and sends new documents into a folder under `Briefkörbe` / `Mailbaskets`
  (rewritten 2026-09-13); `the_hint_of_the_mirror_sends_the_user_to_a_mail_basket_and_not_beside_the_folder`
  in `crates/i18n/tests/catalogs.rs` keeps it that way.
- **Two more identifier prefixes** (`arc_`, `bsk_`) that the counterpart has not laid down;
  contract §7.0.2 marks them as a proposal like the four before them.
- **`RECONCILE` carries a container of the namespace**, read by the core's own reader
  (`Container::from_str`), no longer a hand-written list of two prefixes in `edms-wire`. That list
  is what would have gone stale here, silently and in exactly one place.

## Open point: the word „Briefkorb“ is taken, and there it means the opposite

In the platform's own design note (`elasticdms/docs/design/docuware-abgleich.md`, section „Der
Begriff, an dem die Hälfte des Katalogs hängt“) the word *Briefkorb* names precisely the DocuWare
concept elasticdms rejects: *„die Vorablage vor der Indexierung — ein Haufen, den jemand später
sortiert"* — the pre-filing heap that somebody sorts later. The note's own conclusion is that
elasticdms does not have it and shall not have it: the rule in the ingest path decides the filing,
and what cannot be filed becomes a clarification case with a cause and a hint, not a heap.

What is built here is not that heap. A basket holds nothing, files nothing and decides nothing; it
announces a file and is empty again. The word is the owner's choice and stays. This section records
that the design document uses it for something else, so that whoever reads both does not take the
one for the other — and so that on the day somebody asks “why do we have a Briefkorb, we decided
against that”, the answer is written down instead of remembered.

## Rejected alternatives

- **Keeping `Cases` as a third top-level container.** The tree would have shown every case file of
  every archive in one folder, and the archive would have had to come from a lookup table (see
  Rationale). It is also a list that corresponds to nothing in the archive.
- **Leaving the inbox folder where it was and adding the baskets besides.** Two drop targets with
  different rules, one of them invisible from the mirror. Whoever then drops a file into the wrong
  one gets a different behaviour for the same gesture.
- **A basket that also lists on the server what lies in it.** That is the heap — the one thing the
  section above records that elasticdms does not want.
- **Rewriting the stored `cas_…` rows into `arc_…/cas_…` with the archive of the first listing.**
  A guess, written into the table that the platform layers read as the truth about the folder.
