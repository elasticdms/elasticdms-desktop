# ADR-D04: Delivery channel and the three occasions

**Status:** Accepted (2026-09-11).

## Context

Requirement 5: downloaded copies must be removable by delivery. The requirements fix the transport
— *„Zustellkanal: Long-Poll, wie in ADR-013 für den NAV-Agenten entschieden. Kein neuer
Transport."* — “Delivery channel: long poll, as decided in ADR-013 for the NAV agent. No new
transport.” ADR-013 brings the second rule along with it: no free-form command, but **signed orders
from a closed catalogue**, with quantity and rate limits in the agent itself.

## Decision

1. **Long poll** `GET /v1/delivery/commands?wait=25` (contract §7.3). Outbound only; no listening
   port on the workstation.
2. **A closed catalogue** (`edms_core::delivery::Command`): `DEHYDRATE`, `RECONCILE`, `SIGN_OUT`,
   `REFRESH_KEYS`. An unknown kind is acknowledged `REJECTED` and not executed. The values are
   English because they are ours: the delivery channel is a proposal of this repository
   (`[GAP → PROPOSAL]` in the contract), not something the counterpart's spec prescribes.
3. **Every command is signed** (detached JWS, `typ edms-delivery-command+jwt`, role
   `evidence-signing`) and is verified against the **anchored** key set (geraete-auth §5.2–§5.4).
   If the check fails, nothing is executed, the acknowledgement reads `REJECTED`, and the usage log
   shows a security warning.
4. **Limits in the client:** at most 500 documents per command, at most 30 commands per minute
   (`edms_core::delivery`). Delivered at least once; the client de-duplicates over `commandId` and
   holds unsent acknowledgements across a crash.

### The three occasions

| Occasion | Release the pin | Entry | Hint to the user |
|---|---|---|---|
| `ERASURE` (DSGVO — the German GDPR implementation, ADR-011) | yes | remove — the name goes too | yes, without the document title |
| `ACCESS_REVOKED` | yes | dehydrate; the next list takes it out | no (self-explanatory) |
| `SPACE_RECLAIM` | **no** | dehydrate if not pinned | no |

**Why this differs from the note of 2026-09-10:** What was decided there is only *„Der Löschbefehl hebt die Anheftung auf."*
— “The erasure command releases the pin.” The threefold split stands in the requirements as a
*proposal, not decided*. The proposal is what is implemented, because only it separates space
reclamation from the two compelling occasions. For erasure and revoked access, decision and
proposal agree. Should space reclamation release the pin as well, that is one line in
`edms_core::delivery::actions` — and the test `space_reclamation_respects_the_pin` goes off, as it
should.

**Erasure in the local log:** the row “Erased by order” carries no name (the type does not allow
it), and earlier rows about the same document have the name taken from them. Otherwise the very
title the erasure is meant to expunge would stand in the window built for transparency.

## Rationale

A delivery channel that executes arbitrary commands is a remote-wipe tool for anybody holding the
server or the load balancer. The signature against an anchored key shuts out exactly that attacker
(the threat model names the compromised server explicitly, geraete-auth §5.4); the quantity limit
bounds what even a valid but misused key can do in one go.

## Consequences

- The server has to sign commands. As long as it has deposited no key, the client executes no
  erasure command — following the house's principle: when in doubt, preserve (geraete-auth §5.8,
  “no key deposited”).
- The signature shape of the command is a proposal (`[GAP → PROPOSAL]`); the check stands in
  exactly one place (`edms_crypto`), so that a different shape is one change, not two.

## Rejected alternatives

- **SSE or WebSocket.** The requirement rules out a new transport; AND-10 already struck SSE at the
  kiosk.
- **Push over APNs/WNS.** A third party in the delivery path, and the server would need credentials
  from both vendors.
- **Unsigned commands over TLS.** TLS authenticates exactly the counterpart that the threat model
  allows to be the attacker.
