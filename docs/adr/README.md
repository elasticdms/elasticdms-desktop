# Architecture decisions of the folder client

Same format as in the server repository (`elasticdms/docs/adr/`): Context, Decision, Rationale,
Consequences, Rejected alternatives, Status. The numbers carry a `D` (desktop) so that they are
never confused with the server ADRs `ADR-001` … `ADR-015` they rest on.

**Precedence:** `elasticdms/docs/architecture.md` and the server ADRs stand above these documents.
Where an ADR here departs from them, it says so and names the place.

| No. | Title | Status |
|---|---|---|
| [ADR-D01](ADR-D01-what-the-folder-client-is.md) | What the folder client is | Accepted — requirements of 2026-09-10, §2 and §7 corrected 2026-09-12 |
| [ADR-D02](ADR-D02-platform-scope.md) | Platform scope: Windows and macOS | Accepted — instruction of 2026-09-11 |
| [ADR-D03](ADR-D03-login.md) | Sign-in: device plus user | Proposed |
| [ADR-D04](ADR-D04-delivery-channel.md) | Delivery channel and the three occasions | Proposed |
| [ADR-D05](ADR-D05-macos-file-provider.md) | macOS: File Provider extension in Rust | Proposed |
| [ADR-D06](ADR-D06-windows-cloud-filter.md) | Windows: Cloud Filter API over the windows bindings | Proposed |
| [ADR-D07](ADR-D07-user-interface.md) | User interface: tray icon and usage log | Accepted — instruction of 2026-09-11, menu corrected 2026-09-12 |
| [ADR-D08](ADR-D08-inbox-folder.md) | Inbox folder next to the mirror | Proposed — §1 and §5 corrected 2026-09-12 (ADR-D11) |
| [ADR-D09](ADR-D09-delivery-and-packaging.md) | Delivery: .pkg, MSI and the release pipeline | Proposed |
| [ADR-D10](ADR-D10-user-interface-language.md) | The language of the user interface: a catalogue, not a hard-coded German | Proposed — the three German names corrected 2026-09-12, the last two of them and the identity retired 2026-09-13 |
| [ADR-D11](ADR-D11-namespace-v2.md) | Namespace v2: three branches, and the drop target inside the mirror | Accepted — decision of 2026-09-12 |
| [ADR-D12](ADR-D12-hardware-bound-device-key.md) | The hardware-bound device key: one trait, two platforms, and a fallback that says so | Proposed — the seam is built, the two platform calls are not |
| [ADR-D13](ADR-D13-setup-wizard.md) | The set-up wizard: what the administrator decides, and what the user sees of it | Proposed — decided, not yet built |

“Proposed” means: built as described, but not yet confirmed by the owner. Two say otherwise in
their own status line: in ADR-D12 the seam is built and the two platform calls behind it are not,
and ADR-D13 is decided with nothing of it built yet. Every one of these ADRs names the place in the
code where a different decision would start.
