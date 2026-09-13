# HTTP contract: elasticdms folder client ⇄ elasticdms server

**Part 7 of the canonical specification, seen from the workstation.** It stands beside
`elasticdms-escan/docs/spec/03-api-vertrag.md` (below **03**; the counterpart's file name, which
is theirs and stays German) and adds to it; it does not replace it. Where 03 is silent, a proposal
stands here, and every proposal is marked `[GAP → PROPOSAL]` — so that nobody later takes an
invention for a decision.

**Still binding:** 03 §6.0 (ground rules, valid for **every** endpoint), 03 §6.1 (discovery),
03 §6.2 (enrollment, device token, server keys), 03 §6.3 (user sign-in), 03 §6.4.1 (heartbeat)
and the conditions from `06-auflagen.md`, which take precedence over 03 — in particular **AND-4**
(the device flow is the only way to sign in) and **A-33/AND-3** (a stale anchor never blocks token
issuance).

**Not applicable** are the capture parts of 03: §6.5–§6.15 (folders, batches, page upload, visual
inspection, four-eyes, paper disposition, cancellation, webhooks). The folder client scans
nothing, declares nothing and destroys no paper; it reads.

## The golden files are the truth

Every JSON block in this document carries a marker of the form `<!-- golden: <name>.json -->`
above it and is **byte-identical** with `crates/wire/testdata/<name>.json`. The test
`crates/wire/tests/contract_document.rs` breaks as soon as one of the two changes without the
other; `crates/wire/tests/golden_bodies.rs` reads every file into its wire type and writes it back
unchanged.

> *„Spiegeln heißt: dieselben Rümpfe als Golden Files in `testdata/`, nicht als Code."*
> (`geraete-auth.md` §9.1) — “Mirroring means: the same bodies as golden files in `testdata/`, not
> as code.”

This is no formality: document, wire types, mock (`edms-mock`) and client (`edms-net`) are four
transcripts of the same contract. Four transcripts drift apart as soon as the contract changes —
and all four stay green, because each checks against itself. One source breaks that circle.

All bodies stand here in the same shape: UTF-8, two spaces of indentation, trailing newline. That
is the shape of the files, not the shape of the wire — on the wire whitespace carries no meaning,
except in the **signed** bytes, and for those JCS applies and nothing else (RFC 8785, 03 §6.2.4).

---

## §7.0 Scope — what of 03 §6.0–§6.4 holds here

### §7.0.1 Hosts, version, tenant

Unchanged from 03 §6.0.1: resource API `https://api.elasticdms.io`, authorization server
`https://auth.elasticdms.io`, path version `/v1/`, header `Elasticdms-Version: 2026-09-01`.

**Rule:** The folder client sends `Elasticdms-Version` on **every** request to **both** hosts,
`/v1/oauth/*` included. `[GAP → PROPOSAL]` 03 §6.0.1 leaves open whether the AS requires the
header (finding Q-6).
*Reason:* A header that only sometimes travels along is forgotten exactly when the server starts
evaluating it — and the fault then shows up as an inexplicable `400` in a single call.

**Rule:** The tenant comes solely from the claim `https://elasticdms.io/tenant`. No header, no
query parameter, no path segment, no choice in the user interface.
*Reason:* A tenant the client can choose is a tenant a faulty client can confuse — and a mix-up
here is a tenant breach (ADR-007).

**Rule:** A mirror belongs to exactly one tenant; a second tenant is a second mirror folder.
*Reason:* Otherwise the file path would have to carry the tenant, and the first reconciliation
error would blend two archives into one folder.

### §7.0.2 Identifiers

Unchanged from 03 §6.0.3: a 128-bit value, on the wire `<prefix>_<26 characters of Crockford
Base32>`, read strictly (no lower case, no `I`/`L`/`O`/`U`, no hyphens, no UUID text, first
character at most `7`).

`[GAP → PROPOSAL]` 03 §6.0.3 knows the prefixes `dev_` `usr_` `upl_` (and the capture kinds). The
folder client needs six more:

| Prefix | Resource | Source |
|---|---|---|
| `dev_` | device | 03 §6.0.3 |
| `usr_` | user | 03 §6.0.3 |
| `upl_` | submission out of a mail basket | 03 §6.0.3 |
| `doc_` | document | **proposal** |
| `arc_` | archive | **proposal** |
| `cas_` | case file (Akte) | **proposal** |
| `bsk_` | mail basket (Briefkorb) | **proposal** |
| `srch_` | saved search | **proposal** |
| `cmd_` | delivery-channel command | **proposal** |

*Reason:* An identifier without a prefix can be used in every place that expects 128 bits; with a
prefix, a case identifier in a document path already fails while being read instead of only in the
result.

**Rule:** The client reads identifiers exactly as strictly as the server checks them.
*Reason:* A client more lenient than the server takes identifiers for valid that the server
rejects with `400 invalid-resource-id` — a fault that only shows up in production (contract test
T17).

> **A note on the examples in 03.** The identifier used throughout there,
> `dev_01JB8Z5K3M4N6P7Q8R9S0T1U2V`, carries a `U` in position 24 and is therefore not itself
> canonical under 03 §6.0.3; `usr_01JADMIN0000000000000000` has 24 characters and an `I`. In the
> golden files of this contract both are canonicalised. The test
> `the_example_identifier_from_03_is_itself_not_canonical` records the finding.

### §7.0.3 Headers, error shape, pages, ETag, idempotency, rates

03 §6.0.4 to §6.0.11 hold unchanged. Four points at which the folder client commits itself:

**Rule:** Two error shapes, never smoothed over: resource endpoints answer
`application/problem+json` (RFC 9457), `/v1/oauth/*` per RFC 6749 §5.2. The bridge into the
catalogue is `error_uri`.
*Reason:* A client that expects problem+json at the token endpoint breaks at a place where all it
can still say is “unknown error”.

**Rule:** A problem is **always** read — an empty body, an HTML block page from the load balancer
or an extension field of unexpected shape included. When in doubt a problem arises with
`type: "about:blank"` and the HTTP status.
*Reason:* An error reader that fails itself swallows exactly the message somebody needs in order
to track down the fault.

**Rule:** `nextCursor` is set exactly when `hasMore` is true. A contradiction is an error, not a
matter of interpretation.
*Reason:* Whoever resolved it in favour of `hasMore: false` would silently show a truncated case
file — and a missing document in the folder is precisely the lie this client must not tell.

**Rule:** `Retry-After` beats every local backoff; `RateLimit-Policy` names the buckets.
*Reason:* A client with a schedule of its own turns throttling into overload.

**Rule:** The client uses strong ETags; a `W/` ETag is rejected.
*Reason:* A weak ETag says “semantically equivalent”, and no `If-Match` for bytes that a
placeholder carries with a checksum can be founded on that (03 §6.0.9).

### §7.0.4 Discovery

Unchanged from 03 §6.1 / `geraete-auth §3.0`. On first start the client loads only the two base
addresses from its configuration.

<!-- golden: authorization_server_metadata.json -->
```json
{
  "issuer": "https://auth.elasticdms.io",
  "token_endpoint": "https://auth.elasticdms.io/v1/oauth/token",
  "device_authorization_endpoint": "https://auth.elasticdms.io/v1/oauth/device_authorization",
  "revocation_endpoint": "https://auth.elasticdms.io/v1/oauth/revoke",
  "jwks_uri": "https://auth.elasticdms.io/.well-known/jwks.json",
  "grant_types_supported": [
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token"
  ],
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt"
  ],
  "token_endpoint_auth_signing_alg_values_supported": [
    "ES256"
  ],
  "dpop_signing_alg_values_supported": [
    "ES256"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "scopes_supported": [
    "device:self",
    "kiosk:login",
    "audit:anchor",
    "batch:transport",
    "openid",
    "profile",
    "folders:read",
    "scan:operate",
    "scan:review",
    "approvals:decide",
    "destruction:acknowledge",
    "documents:read",
    "documents:retract"
  ],
  "authorization_response_iss_parameter_supported": true
}
```

**Rule:** Three start conditions, no features. (1) `issuer` is exactly the expected issuer.
(2) `code_challenge_methods_supported` contains `S256`. (3) Every adopted endpoint lies **below**
the issuer.
*Reason for (1):* Otherwise the client would fetch the endpoints of a foreign authorization server
(mix-up, RFC 8414 §3.3). *Reason for (2):* The client does not use the code flow, but 03 §6.1
makes its absence an abort condition, and a server without `S256` is not the one this contract was
written for. *Reason for (3):* A document that puts the token endpoint on a foreign host would
send every client assertion there.

**Rule:** The comparison is always against `<base>/`, never against `<base>` alone.
*Reason:* Otherwise `https://api.elasticdms.io.example.org/v1/x` would lie “below”
`https://api.elasticdms.io`, and the check would be blind to exactly the attack it exists for.

**Rule:** `authorization_endpoint` is neither expected nor used. If it stands in the document, it
stays unused.
*Reason:* AND-4 struck the code flow for device clients without replacement; a client that took it
when the opportunity arose would have the struck class of attack back.

`[GAP → PROPOSAL]` `scopes_supported` above shows the counterpart's state today. The server has to
extend the list by `desktop:login`, `delivery:receive` and `ingest:submit` (§7.5.2). The client
does **not** check `scopes_supported` — what counts is what the token endpoint actually grants.
*Reason:* A start-up check against a list the server keeps merely for display locks the client out
as soon as somebody forgets the list — without anything being broken.

<!-- golden: resource_metadata.json -->
```json
{
  "resource": "https://api.elasticdms.io",
  "authorization_servers": [
    "https://auth.elasticdms.io"
  ],
  "bearer_methods_supported": [
    "dpop"
  ],
  "scopes_supported": [
    "device:self",
    "folders:read",
    "documents:read",
    "ingest:submit",
    "delivery:receive"
  ]
}
```

`[GAP → PROPOSAL]` `geraete-auth §3.0` leaves the resource's `scopes_supported` open as `"…"`;
here stands the set the folder client needs.

### §7.0.5 Enrolling a workstation

`[GAP → PROPOSAL]` 03 §6.2.1 describes the body of a scanner kiosk: `hardware`,
`scannerCapabilities`, `badgeReader`, `networkTargets`, `lifetimeSheetCounter`,
`attestation.certificateChain`. A workstation has none of that (finding Q-2).

**Rule:** The folder client enrolls like a kiosk — `PUT /v1/devices/{deviceId}`, **without**
`Authorization` and **without** DPoP, with `If-None-Match: *` — but with the following body.

<!-- golden: enrollment_request_desktop.json -->
```json
{
  "enrollmentCode": "K7QM-4T2X",
  "deviceKind": "desktop",
  "publicJwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "alg": "ES256",
    "use": "sig",
    "kid": "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB#1"
  },
  "attestation": {
    "type": "none",
    "available": false
  },
  "platform": {
    "os": "Windows",
    "osVersion": "10.0.26100",
    "arch": "x86_64"
  },
  "app": {
    "packageName": "de.elasticdms.folderclient",
    "versionName": "1.0.0",
    "buildHash": "sha256:924fb28aff51ee6e70cf048ac486fcbf9c3fd7a609fbc537f07173fdd5cda441",
    "signatureSha256": "sha256:cd00868ed978944d17c592fd5d711cdb6263f60baa40c7bf6fa4a33ec9996864"
  },
  "requestedName": "Arbeitsplatz Buchhaltung EG"
}
```

*Reason for `PUT` instead of `POST`:* The call can break off after the server has created the
device; a `POST` retry would produce a second device with the same key (03 §6.2.1).
*Reason for the missing `Authorization` header:* The enrollment code **is** the credential of this
one call; there is no token yet with which one could fetch it.

**Rule:** `412 precondition-failed` is **success**. The client then reads back via
`GET /v1/devices/me`.
*Reason:* Only this way can a retry after a network break be told apart from a real collision
(contract tests T2, T3).

**Rule:** `409 device-id-conflict` is **not** a retry. The client aborts and asks for a new code.
*Reason:* A different public key lies under that identifier — either a fault while generating the
identifier or a foreign device (contract test T5).

**Rule:** `attestation` is `{"type": "none", "available": false}`. The client **never** claims a
chain.
*Reason:* An invented chain would be worse than none; the honest statement leads to tier
`SOFTWARE` and hence to the documented path over an administrator's confirmation.

**Rule:** `deviceKind: "desktop"` selects the server-side check scheme without factory targets.
*Reason:* `device-network-targets-enabled` (03 §6.2.1) checks a panel's scan-to-SMB, -FTP, -SMTP
and -USB; a workstation has no such targets, and a scheme that demanded them could only be
satisfied by a lie.

**Rule:** `requestedName` is a name chosen by the user, never the machine name taken unasked.
*Reason:* In many houses the machine name carries initials or surnames; it would stand unasked in
the tenant's device list.

**Rule:** Neither `publicJwk.d` nor any other private part ever leaves the device; a JWK with `d`
is rejected while still being read.
*Reason:* A key whose private part once travelled over the network counts as disclosed
(`geraete-auth §3.1`).

The response — `201` the first time, `200` after the `GET` in the `412` case:

<!-- golden: device_desktop.json -->
```json
{
  "deviceId": "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
  "state": "pending_admin_approval",
  "deviceKind": "desktop",
  "name": "Arbeitsplatz Buchhaltung EG",
  "tenant": {
    "id": "t_acme",
    "name": "ACME GmbH"
  },
  "attestation": {
    "tier": "SOFTWARE",
    "verdict": {
      "chainRootsInGoogleAttestationRoot": false,
      "verifiedBootState": null,
      "reason": "attestation_type_none"
    },
    "keyThumbprint": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
    "adminConfirmationRequired": true
  },
  "oauth": {
    "clientId": "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
    "tokenEndpoint": "https://auth.elasticdms.io/v1/oauth/token",
    "tokenEndpointAuthMethod": "private_key_jwt",
    "tokenEndpointAuthSigningAlg": "ES256",
    "grantTypes": [
      "client_credentials",
      "urn:ietf:params:oauth:grant-type:device_code",
      "refresh_token"
    ],
    "deviceScopes": [
      "device:self",
      "desktop:login",
      "delivery:receive"
    ],
    "dpopBoundAccessTokens": true
  },
  "policy": {
    "heartbeatIntervalSeconds": 300,
    "idleSessionSeconds": 28800,
    "absoluteSessionSeconds": 43200,
    "deliveryWaitSeconds": 25,
    "expectedAppSignatureSha256": "sha256:cd00868ed978944d17c592fd5d711cdb6263f60baa40c7bf6fa4a33ec9996864"
  },
  "serverKeys": {
    "keySetVersion": 7,
    "issuer": "https://api.elasticdms.io",
    "tenantId": "t_acme",
    "generatedAt": "2026-09-02T08:14:22Z",
    "refreshAfter": "2026-09-09T08:14:22Z",
    "nextRotationAt": "2027-06-01T00:00:00Z",
    "anchorSetFingerprint": "NGJQ-CWV1-AHAR-Z4FJ",
    "trustAnchors": [
      {
        "kid": "edms-anchor-a-2026",
        "kty": "EC",
        "crv": "P-256",
        "x": "KR8R1P0MYXQSkmTLEUy76S4-mcDVbNBGSblM0nVghbQ",
        "y": "bWqbl_fHbboDqf1kHx1VLMi9lXR5Iqu-nWefmpONuTY",
        "alg": "ES256",
        "use": "sig",
        "role": "trust-anchor",
        "issuer": "https://api.elasticdms.io",
        "tenantId": "t_acme",
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2036-01-01T00:00:00Z",
        "thumbprint": "LAsBA719DG2FA0dsYL6V-xZPqUvH2HX8f1Zu55HYrYc",
        "custody": "offline-hsm",
        "serverSignature": null
      },
      {
        "kid": "edms-anchor-b-2026",
        "kty": "EC",
        "crv": "P-256",
        "x": "wr6dslMI-t-ZLz27kBKpD2vRymV7IiJbrxoya1NdsfU",
        "y": "7uOZTl1LDSvO0pVlXAu318k809hLYh_XLpVilV2BHGo",
        "alg": "ES256",
        "use": "sig",
        "role": "trust-anchor",
        "issuer": "https://api.elasticdms.io",
        "tenantId": "t_acme",
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2036-01-01T00:00:00Z",
        "thumbprint": "zOY49754F5BPDBEnGA6qlv1SSbW_EvyagTv_Ik_2XBc",
        "custody": "offline-hsm-reserve",
        "serverSignature": null
      }
    ],
    "signingKeys": [
      {
        "kid": "edms-kms-2026-09",
        "kty": "EC",
        "crv": "P-256",
        "x": "gbSRUaCT8FRHbSq1oR2QP2Y4OKDSuiC3_aigrNgEzfw",
        "y": "1lis6j8wpAYp0ZQeYB3srLGomXGVhf-ExpmyZPfzP30",
        "alg": "ES256",
        "use": "sig",
        "role": "evidence-signing",
        "issuer": "https://api.elasticdms.io",
        "tenantId": "t_acme",
        "notBefore": "2026-09-01T00:00:00Z",
        "notAfter": "2027-09-01T00:00:00Z",
        "keySetVersion": 7,
        "supersedes": "edms-kms-2025-09",
        "thumbprint": "8ji41YR5dcmyQ9yXVvI2DegpkzJlf8EK1EnNjMlv-eA",
        "serverSignature": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVkbXMtc2VydmVyLWtleStqd3QiLCJraWQiOiJlZG1zLWFuY2hvci1hLTIwMjYifQ..MEQCIH2rXk9pQeVwT4mB1sZ0dLcJx7oNfR3aYuK8gPqW5tCvAiA9fL0mXbQ7zH1uEjR6oNcP4sVtY2gKdW8xB3rMqLeZTw"
      }
    ]
  },
  "enrolledAt": "2026-09-11T08:14:22Z",
  "enrolledBy": {
    "sub": "usr_01JKE0M2P4R6T8V0X2Z4B6D8F0",
    "displayName": "Thomas Berg"
  }
}
```

**Rule:** `state: "pending_admin_approval"` is the rule, not the exception. Until the
administrator confirms the thumbprint, every token request answers `403 device-pending-approval`;
the app shows “device waiting for approval” together with the fingerprint it computed itself.
*Reason:* Without the comparison by a human, anybody who installs the software could enroll a
device against the tenant.

**Rule:** The displayed fingerprint is **computed by the client itself**, never taken from
`anchorSetFingerprint`.
*Reason:* Whoever can forge the response forges the field too; only the self-computed value
carries the comparison against the procedural documentation (Verfahrensdokumentation, 03 §6.2.4).

**Rule:** If `serverKeys` is missing, the device stays without an anchor — and **nothing** is ever
removed by order.
*Reason:* The house's principle reads: when in doubt, preserve (`geraete-auth §5.8`). An erasure
command without a checkable signature is a remote-wipe tool for anybody who holds the load
balancer.

### §7.0.6 Device token

Unchanged from 03 §6.2.2: `grant_type=client_credentials`, `private_key_jwt` with the device key,
no refresh token.

<!-- golden: token_device_desktop.json -->
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.desktop-device-access-token",
  "token_type": "DPoP",
  "expires_in": 900,
  "scope": "device:self desktop:login delivery:receive"
}
```

**Rule:** The device token may do nothing of substance — no document, no case file, no content. It
carries exactly `device:self`, `desktop:login` and `delivery:receive`.
*Reason:* Otherwise a stolen workstation would be full access to the archive without a human ever
having signed in.

**Rule:** `delivery:receive` lies with the **device**, not with the user.
*Reason:* An erasure has to reach a device even when the user's session has expired — and that is
exactly when pinned copies still lie on the disk (§7.3).

**Rule:** `token_type` is `DPoP`. A `Bearer` token fails while being read, not only in a check.
*Reason:* An unbound token would be usable without this device's key; the binding on which 03
§6.0.6 rests would be gone — and a check one can forget will be forgotten.

### §7.0.7 User sign-in — device flow in the system browser, and nothing else

**Rule:** The device authorization grant (RFC 8628) is the **only** way to sign in. No PAR, no
`authorization_endpoint`, no WebView, no embedded browser.
*Reason:* AND-4 / A-03 struck path B without replacement: in a WebView the corporate credentials
flow through our process, and the host process can read the password field. The system browser
carries the sign-in at Entra including conditional access anyway.

**Rule:** The request to `/v1/oauth/device_authorization` carries **no** DPoP header, but
`dpop_jkt`.
*Reason:* RFC 9449 §5 binds the future token over the thumbprint; the proof only comes when
fetching it — and then with the **session** key, while the client assertion is signed with the
**device** key (03 §6.3.1).

<!-- golden: device_authorization_desktop.json -->
```json
{
  "device_code": "GmRhmhcxhwEzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WQPX-7TRM",
  "verification_uri": "https://app.elasticdms.io/geraet",
  "verification_uri_complete": "https://app.elasticdms.io/geraet?user_code=WQPX-7TRM&anchor=K7M4",
  "expires_in": 300,
  "interval": 5,
  "urn:elasticdms:anchor": "K7-M4",
  "urn:elasticdms:device_label": "Arbeitsplatz Buchhaltung EG · ACME GmbH"
}
```

**Rule:** The client opens `verification_uri_complete` in the **system browser** — but only if the
address lies below the configured web interface.
*Reason:* A response that sends the user to a foreign host would be the template for a phishing
page adorned with a real code and a real anchor.

**Rule:** The four-character anchor from `urn:elasticdms:anchor` stands in the app's window, and
the confirmation page repeats it. The human compares.
*Reason:* A foreign flow slipped in cannot know the anchor (03 §6.3.1, third defence).

**Rule:** If `interval` is missing, five seconds hold. `slow_down` raises the spacing
**permanently** by five seconds.
*Reason:* RFC 8628 §3.5 prescribes it; a client that forgets the surcharge after the next attempt
throttles itself into an endless loop.

The four intermediate states are four different screens, not one shared error:

<!-- golden: oauth_authorization_pending.json -->
```json
{
  "error": "authorization_pending"
}
```

<!-- golden: oauth_slow_down.json -->
```json
{
  "error": "slow_down"
}
```

<!-- golden: oauth_code_expired.json -->
```json
{
  "error": "expired_token"
}
```

<!-- golden: oauth_access_denied.json -->
```json
{
  "error": "access_denied"
}
```

*Reason:* “The human declined” and “the time ran out” lead to different sentences on the screen;
whoever throws them together sends somebody off to wait who was refused.

Success:

<!-- golden: token_user_desktop.json -->
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9.desktop-user-access-token",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "rt_01JKF2P4R6T8V0X2Z4B6D8F0H2",
  "refresh_token_expires_in": 43200,
  "scope": "openid profile folders:read documents:read ingest:submit",
  "id_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.desktop-id-token"
}
```

`[GAP → PROPOSAL]` **`acr_values`.** 03 §6.3.1 sends `urn:elasticdms:acr:kiosk:badge-pin` — a
kiosk artefact (badge plus PIN at the panel). Proposed is **`urn:elasticdms:acr:desktop`**:
sign-in in the system browser of the signed-in workstation user, without a badge reader.
*Reason:* The class has to be nameable, because `authenticatorClass` is derived server-side from
`amr` and checked against folder policies; running a workstation under the kiosk class would claim
a badge reader that does not exist.

`[GAP → PROPOSAL]` **`login_hint`** is omitted at first sign-in. At step-up (03 §6.3.5) it carries
the user of the running session, together with `max_age` and `prompt=login` from the challenge.
*Reason:* There is no `login_hint` from a badge UID here; at step-up, by contrast, the same human
has to confirm, otherwise the reinforcement could be satisfied by a colleague.

### §7.0.8 Session lifetimes

`[GAP → PROPOSAL]` 03 §6.3.3 lays down for the kiosk: access token 5 min, refresh 30 min absolute,
session hard 30 min, not extendable. For a workstation that runs for eight hours those values are
no good (finding Q-4).

| Value | Kiosk (03 §6.3.3) | **Proposal for the workstation** |
|---|---|---|
| Access token | 5 min | 15 min |
| Refresh token | 30 min absolute | 12 h absolute |
| Session, idle | 90 s lock | 8 h |
| Session, absolute | 30 min, hard | 12 h |

*Reason:* On shared hallway hardware a short hard limit is right — whoever walks on leaves no
session standing. A workstation is personal and locked by the operating system; a 30-minute limit
would force sixteen sign-ins a day, and the first reaction to that would be to close the client.

The values come from the device object's `policy` (§7.0.5), not from a constant in the program.
*Reason:* Otherwise every change would be an update on every workstation instead of a
configuration change.

**Rule:** When the session expires, the tree stays visible. Opening fails with “sign-in required”,
the tray icon shows it, and a non-modal hint offers to sign in.
*Reason:* Silently emptying the tree would look to the user like an erasure — and afterwards they
would search where nothing is left.

<!-- golden: oauth_session_expired.json -->
```json
{
  "error": "invalid_grant",
  "error_description": "Die Sitzung ist abgelaufen. Bitte melden Sie sich neu an.",
  "error_uri": "https://errors.elasticdms.io/session-expired"
}
```

**Rule:** A refresh attempt is **never** blindly repeated.
*Reason:* Reusing a rotated refresh token revokes the whole token family across devices (03
§6.3.3) — a retry after a lost response packet would sign the user out everywhere.

<!-- golden: oauth_refresh_reused.json -->
```json
{
  "error": "invalid_grant",
  "error_description": "Dieses Refresh-Token wurde bereits eingelöst; die Token-Familie ist widerrufen.",
  "error_uri": "https://errors.elasticdms.io/refresh-token-reuse"
}
```

**Rule:** This case is a **security event**, not the end of a session. It stands in the local
usage log with a security warning.
*Reason:* It means that somebody else has used the same token; showing it as an ordinary
expiry would take from the user the only chance to notice.

**Rule:** Signing out revokes the refresh token (`POST /v1/oauth/revoke`, RFC 7009), clears the
mirror completely and empties the namespace.
*Reason:* Afterwards no name of the old user stands on the disk any more (requirement 4). Per RFC
7009 `revoke` always answers `200`, even for an unknown token — the client does not take the
status as proof but clears in every case.

### §7.0.9 DPoP and nonces

Unchanged from 03 §6.0.5: every call carries a DPoP proof; the server issues nonces.

<!-- golden: problem_dpop_nonce_required.json -->
```json
{
  "type": "https://errors.elasticdms.io/dpop-nonce-required",
  "title": "DPoP-Nonce erforderlich",
  "status": 401,
  "detail": "Der Proof muss die im Header DPoP-Nonce gelieferte Nonce enthalten.",
  "instance": "/v1/folders",
  "traceId": "01JB8Z5K3M4N6P7Q8R9S0T1U2V"
}
```

**Rule:** Exactly **one** retry with the new nonce. A second `use_dpop_nonce` response to the same
request is an error.
*Reason:* A loop would be a self-inflicted DoS here (contract test T9).

**Rule:** The nonce is remembered per origin; `api.` and `auth.` have separate nonces.
*Reason:* A nonce of one host presented at the other is invalid, and the client would run into a
loop of two alternating demands.

**Rule:** The proof is produced with the **session** key, not with the device key — except for
calls that run under the device token (`/v1/devices/me`, `:heartbeat`, `/v1/server-keys`,
`/v1/delivery/*`).
*Reason:* The device key is long-lived and attests the device's identity; using it for every
request would turn every proof into an occasion to use it.

### §7.0.10 Heartbeat

From 03 §6.4.1, with two blocks for the workstation and without the kiosk blocks.

<!-- golden: heartbeat_desktop.json -->
```json
{
  "sentAtDevice": "2026-09-11T09:35:02+02:00",
  "app": {
    "versionName": "1.0.0",
    "buildHash": "sha256:924fb28aff51ee6e70cf048ac486fcbf9c3fd7a609fbc537f07173fdd5cda441",
    "signatureSha256": "sha256:cd00868ed978944d17c592fd5d711cdb6263f60baa40c7bf6fa4a33ec9996864"
  },
  "platform": {
    "os": "Windows",
    "osVersion": "10.0.26100",
    "arch": "x86_64"
  },
  "serverKeys": {
    "keySetVersion": 7,
    "anchorState": "confirmed",
    "anchorSetFingerprint": "NGJQ-CWV1-AHAR-Z4FJ",
    "signingKidsHeld": [
      "edms-kms-2026-09"
    ],
    "revocationsHeld": 0,
    "findings": []
  },
  "delivery": {
    "unacknowledgedCommands": 1,
    "oldestUnacknowledgedAt": "2026-09-11T07:30:04Z",
    "lastPollAt": "2026-09-11T09:34:37Z"
  }
}
```

`[GAP → PROPOSAL]` **`delivery`** is new: open commands, executed but not yet acknowledged.
*Reason:* This way the server sees a device whose acknowledgements are stuck without asking it —
and that device is exactly the one at which an ordered erasure may not have arrived.

**Rule:** `sentAtDevice` is an observation, never a proof. The device's clock is never set from
`clockOffsetMs`; the value only corrects displays.
*Reason:* A clock set by a network response depends on the network response — and so does every
local timestamp after it.

<!-- golden: heartbeat_response_desktop.json -->
```json
{
  "serverTime": "2026-09-11T07:35:02.318Z",
  "clockOffsetMs": -412,
  "deviceState": "active",
  "configEtag": "8",
  "commands": [
    {
      "command": "resyncServerKeys",
      "reason": "key_rotated",
      "message": "Der Serverschlüsselsatz wurde erneuert."
    }
  ],
  "nextHeartbeatSeconds": 300
}
```

**Rule:** Commands in the heartbeat response are **unsigned**. There the folder client follows
only `resyncPolicy` and `resyncServerKeys`. `forceLogout`, `lockDevice`, `blockNewBatches`,
`uploadDiagnostics` and every unknown value are not executed.
*Reason:* Everything that removes copies or signs out comes signed over the delivery channel and
nowhere else (§7.3); an unsigned command that cleared the mirror would be a remote-wipe tool for
anybody holding the load balancer (ADR-D04).
*Reason for the two exceptions:* Both are only a fetch, and the fetch checks itself.

**Rule:** A stale anchor **never** blocks token issuance and never the heartbeat.
*Reason:* A-33/AND-3: a device that can no longer sign in can no longer report anything either —
a closed failure on the preserving side, that is, the forbidden direction.

---

## §7.1 Namespace — baskets, archives, case files, saved searches and their documents

`[GAP → PROPOSAL]` Entirely new. The server has no JSON endpoint today (gaps G-1, G-15, G-16);
`/suche` delivers German HTML for the browser. The shape of the tree these six endpoints fill is
namespace v2 (ADR-D11).

### §7.1.0 The one rule above all others

**Rule:** **A listing IS a search.** The server computes every list over the same ADR-008 path as
the search in the web client: `acl_read && $subject_tokens`,
`NOT (acl_deny && $subject_tokens)`, `node_path <@ ANY($visible_paths)` (at most 50 paths), tenant
filter, full-text predicate. `$subject_tokens` and `$visible_paths` come from the **session**,
never from a request parameter.
*Reason:* One authorization path, not two. Two paths drift apart, and the more dangerous one wins
— when in doubt the one that shows too much.

**Rule:** The client **never filters**. There is no function in `edms-wire` that leaves entries
out.
*Reason:* What arrives stands in the folder; what does not arrive does not exist for this user. A
client-side filter would be a second permission logic in exactly the place where it is checked
least (contract test T11).

### §7.1.1 The six endpoints

| Call | Response | Scope |
|---|---|---|
| `GET /v1/mirror/baskets` | page of mail baskets | `folders:read` |
| `GET /v1/mirror/archives` | page of archives | `folders:read` |
| `GET /v1/mirror/archives/{archiveId}/cases` | page of case files | `folders:read` |
| `GET /v1/mirror/archives/{archiveId}/cases/{caseId}/documents` | page of documents | `documents:read` |
| `GET /v1/mirror/searches` | page of saved searches | `folders:read` |
| `GET /v1/mirror/searches/{savedSearchId}/documents` | page of documents | `documents:read` |

Namespace v2 (ADR-D11, the owner's decision of 2026-09-12) gave the tree a third branch and the
paths a common base: everything that answers a folder of the mirror lies below `/v1/mirror`, and
nothing else does.

**Rule:** A case file is addressed **below its archive**, never on its own. There is no
`GET /v1/cases` and no list of all case files.
*Reason:* In the tree a case file hangs in exactly one archive, and the entry identifier of the
client says so: `arc_…/cas_…`. A path without the archive would be a second address for the same
list — and a second address is a second place at which the authorization of §7.1.0 is decided.

**Rule:** A mail basket delivers **no** documents. There is no
`GET /v1/mirror/baskets/{basketId}/documents`.
*Reason:* A basket holds nothing. What is dropped into it is filed into an archive by the ingest
rule (§7.4); an endpoint that listed a basket's content would promise a filing place that does not
exist — and that place is exactly what a basket is not (ADR-D11).

Query parameters: **only** `cursor` and `limit` (1 to 1000, default 200). No `q`, no filter, no
`offset`.
*Reason:* Every further parameter would be a second way to determine a list — and the folder in
the file system has no place at which one could set it. What the user wants to narrow down, they
narrow down in the browser and save as a search.

<!-- golden: baskets_page.json -->
```json
{
  "items": [
    {
      "basketId": "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5",
      "title": "Briefkorb Buchhaltung"
    },
    {
      "basketId": "bsk_01JKD3S7W9X1Y3Z5A7B9C2D4E6",
      "title": "Scanner Empfang"
    }
  ],
  "nextCursor": null,
  "hasMore": false
}
```

<!-- golden: archives_page.json -->
```json
{
  "items": [
    {
      "archiveId": "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3",
      "title": "Rechnungseingang"
    },
    {
      "archiveId": "arc_01JKB1Q5T7V9W1X3Y5Z7A9B2C4",
      "title": "Bauvorhaben"
    }
  ],
  "nextCursor": null,
  "hasMore": false
}
```

**Rule:** A basket row and an archive row carry an identifier and a title, nothing further — not
even an `updatedAt`.
*Reason:* Neither of the two is a list of documents: the client hangs a folder name on them and
asks the next endpoint. A field nobody reads is still a promise the server has to keep, and the
first version is the cheap moment to leave it out. The test
`the_two_new_containers_list_an_identifier_and_a_title_and_nothing_else` reads the raw JSON and
holds the two fields fast.

<!-- golden: cases_page.json -->
```json
{
  "items": [
    {
      "caseId": "cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7",
      "title": "Sulzer Pumpen GmbH – Rahmenvertrag 2026",
      "updatedAt": "2026-09-10T16:04:11+02:00"
    },
    {
      "caseId": "cas_01JKA8N3R0S5T7V9W2X4Y6Z8A1",
      "title": "Bauvorhaben Rothenbaumchaussee 12",
      "updatedAt": "2026-09-09T08:21:03Z"
    }
  ],
  "nextCursor": "eyJ0IjoxNzcyNDQ4MjkyfQ",
  "hasMore": true
}
```

<!-- golden: searches_page.json -->
```json
{
  "items": [
    {
      "savedSearchId": "srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2",
      "title": "Offene Eingangsrechnungen",
      "updatedAt": "2026-09-08T11:47:52Z"
    }
  ],
  "nextCursor": null,
  "hasMore": false
}
```

**Rule:** A case row does **not** repeat its archive; the request has already named it.
*Reason:* Two statements about the same thing in one answer can contradict each other, and the
client would then have to decide which of the two counts. The archive is the one the caller asked
for — the client builds `arc_…/cas_…` from the request and the row.

**Rule:** The cursor is opaque and is never read out, only handed back.
*Reason:* A client that builds cursors itself ties itself to the server's sort keys; if the server
changes the ordering, the client silently reads past entries.

**Rule:** An unreadable cursor is an **error**, never a silent jump back to page 1.

<!-- golden: problem_cursor_invalid.json -->
```json
{
  "type": "https://errors.elasticdms.io/invalid-cursor",
  "title": "Cursor unlesbar",
  "status": 400,
  "detail": "Der übergebene cursor gehört nicht zu dieser Liste oder ist nicht mehr gültig. Die Liste ist von vorn zu lesen.",
  "instance": "/v1/mirror/archives/arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3/cases/cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7/documents",
  "traceId": "01JKC4D6E8F0G2H4J6K8M0N2P4"
}
```

*Reason:* A jump back to page 1 in the middle of reconciliation would produce duplicate entries
and leave the gap at the end unnoticed (contract test T16).

### §7.1.2 Document lists and visible truncation

<!-- golden: case_documents_page.json -->
```json
{
  "items": [
    {
      "documentId": "doc_01JK6T9ZS0P5Q7R8V1X2YZABCD",
      "title": "Rahmenvertrag 2026 (geschwärzt)",
      "mediaType": "application/pdf",
      "size": 1048576,
      "sha256": "sha256:f0b1a47360f3e5f8d4a7243d99c66b762fc1b90b489d90d11e9777c17561cd44",
      "version": "12",
      "createdAt": "2026-01-08T07:55:00Z",
      "updatedAt": "2026-08-31T15:41:19+02:00"
    },
    {
      "documentId": "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
      "title": "Rechnung 2026-0412",
      "mediaType": "application/pdf",
      "size": 284173,
      "sha256": "sha256:8b2d0e13d600e99b8f897dc8dd4df00b4f94a3b9f4c5fce1ecc44790a3304c96",
      "version": "3",
      "createdAt": "2026-03-14T09:12:44Z",
      "updatedAt": "2026-09-02T08:14:22Z"
    },
    {
      "documentId": "doc_01JK5S8ZR9N4P6Q7T0W1XYZABC",
      "title": "Lieferschein 88213",
      "mediaType": "application/pdf",
      "size": 61204,
      "sha256": "sha256:5019f53cc6d0340b0af6d05a069e56425629b88d8e8294155ba33a8136a01043",
      "version": "1",
      "createdAt": "2026-03-12T14:02:07Z",
      "updatedAt": "2026-03-12T14:02:07Z"
    }
  ],
  "nextCursor": null,
  "hasMore": false,
  "totalCapped": false,
  "displayLimit": 5000,
  "refineUrl": null
}
```

**Rule:** `size`, `sha256` and `mediaType` describe the **delivered representation** — redacted or
view —, never the original record (Urschrift, §7.2).
*Reason:* The placeholder in the file system carries size and checksum before a single byte is
loaded; if the original record's values stood there, every hydration would fail with a checksum
error.

**Rule:** `version` is opaque and changes with every change of the delivered bytes. It is the
strong ETag of the content.
*Reason:* Without it there would be no `If-Match` on fetching, and the client could not tell a new
version from the same one.

**Rule:** A version marker from which no strong ETag can be made makes the whole page fail.
*Reason:* A list from which individual rows silently drop out is an incomplete folder — and
incomplete without saying so is worse than not loaded at all.

**Rule:** `totalCapped`, `displayLimit` and `refineUrl` belong together. Beyond `displayLimit`
(proposal: `domain.FacetThreshold`, 5000) the server delivers only up to the limit and sets
`totalCapped: true`.

<!-- golden: search_documents_truncated.json -->
```json
{
  "items": [
    {
      "documentId": "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
      "title": "Rechnung 2026-0412",
      "mediaType": "application/pdf",
      "size": 284173,
      "sha256": "sha256:8b2d0e13d600e99b8f897dc8dd4df00b4f94a3b9f4c5fce1ecc44790a3304c96",
      "version": "3",
      "createdAt": "2026-03-14T09:12:44Z",
      "updatedAt": "2026-09-02T08:14:22Z"
    }
  ],
  "nextCursor": "eyJ0IjoxNzcyNDQ4MjkzfQ",
  "hasMore": true,
  "totalCapped": true,
  "displayLimit": 5000,
  "refineUrl": "https://app.elasticdms.io/suche?gespeichert=srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2"
}
```

**Rule:** Truncation is **visible, never silent**: the core then places the hint file
`Result list truncated – README.txt` (in German `Trefferliste gekappt – LIESMICH.txt`) into the
folder, with the number and the address from `refineUrl`.
*Reason:* Finding Q-12. A folder that shows 5000 of 40 000 documents and says nothing leads to the
statement “that document does not exist” — in front of an auditor the most expensive way to be
wrong.

**Rule:** If a page delivers more entries than `displayLimit`, it is not taken over.
*Reason:* Then either the limit or the list is wrong; believing both would mean deciding on one
version without knowing it.

### §7.1.3 Noticing changes

**Rule:** Every list delivers a strong `ETag`; the client sends `If-None-Match` and accepts
`304 Not Modified`.
*Reason:* Otherwise a workstation with 200 case files fetches 200 complete lists on every tick,
and the archive bears the load of a display that has not changed.

`[GAP → PROPOSAL]` There is no change stream (delta, change feed) (gap G-17). Until there is one,
the client reconciles periodically with `ETag` and lets itself be nudged in between by `RECONCILE`
from the delivery channel (§7.3).
*Reason:* A self-built change stream over repeated full reconciliations would be expensive and
inaccurate all the same; better an honestly named tick than a delta with holes in it.

**Rule:** A saved search is a **dynamic** folder: its content changes without anybody doing
anything.
*Reason:* The user has to know that, otherwise they take the disappearance of a hit for an
erasure. The core marks such folders (`Container::is_dynamic`).

**Rule:** A saved search the server cannot execute is an error with a reason — not an empty
folder.

<!-- golden: problem_search_not_executable.json -->
```json
{
  "type": "https://errors.elasticdms.io/saved-search-not-executable",
  "title": "Gespeicherte Suche nicht ausführbar",
  "status": 422,
  "detail": "Die gespeicherte Suche filtert auf das Feld „gehalt“, das Sie nicht lesen dürfen.",
  "instance": "/v1/mirror/searches/srch_01JKB2N4P6Q8R0S2T4V6W8X0Y2/documents",
  "errors": [
    {
      "field": "gehalt",
      "code": "field-not-readable"
    }
  ]
}
```

*Reason:* ADR-014 knows exactly two outcomes for an attribute search: permitted, or an error with
a message. An empty folder at this point would be the third, forbidden answer — it would look like
“nothing found” and would be “not allowed”.

---

## §7.2 Content — the fetch that is an access

`[GAP → PROPOSAL]` Today's server has only `GET /dokumente/{id}/ansicht` for the browser (gaps
G-18, G-19).

```http
GET /v1/documents/doc_01JK6T9ZS0P5Q7R8V1X2YZABCD/content HTTP/1.1
Host: api.elasticdms.io
Authorization: DPoP <user token>
DPoP: <proof>
Elasticdms-Version: 2026-09-01
If-Match: "12"
Elasticdms-Accessing-Application: WINWORD.EXE
```

```http
HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Length: 1048576
ETag: "12"
Repr-Digest: sha-256=:8LGkc2Dz5fjUpyQ9mcZrdi/BuQtInZDRHpd3wXVhzUQ=:
Cache-Control: private, no-store
X-Content-Type-Options: nosniff
```

### §7.2.1 Which version is delivered

**Rule:** The server chooses the representation in the fixed order
**`redacted` → `view` → `thumbnail`**. The **original record is never delivered** — not even to a
native viewer.
*Reason:* Finding Q-13. The server treats the role `original` as `403` (“the original record is
not shown in the browser”); a folder client that put it on the disk would have circumvented that
rule without anybody having changed it.

**Rule:** If there is no deliverable version, that is an error — not an empty file.

<!-- golden: problem_rendition_missing.json -->
```json
{
  "type": "https://errors.elasticdms.io/representation-unavailable",
  "title": "Keine auslieferbare Fassung",
  "status": 404,
  "detail": "Von diesem Dokument gibt es weder eine geschwärzte noch eine Ansichtsfassung; die Urschrift wird nie ausgeliefert.",
  "instance": "/v1/documents/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB/content"
}
```

*Reason:* A file of zero bytes in the folder looks like an empty document; under GoBD (the German
principles for keeping books and records in electronic form) that is the wrong statement about a
voucher.

**Rule:** The client loads **whole files**, no `Range`.
*Reason:* The checksum can only be computed over the whole body. The server also only notices a
hash error at the last `Read`, after `200` and the headers have already been sent — the client
would otherwise see a short body without an error status (contract test T13).

> `[GAP → PROPOSAL]` For a placeholder file system `Range`/`206` would be the natural way (the
> Cloud Filter API asks for ranges). As long as the server reports the hash error only at the end,
> a range fetch is **not** checkable; the decision “whole file” is therefore no convenience but
> the only one under which a mangled file is noticed.

### §7.2.2 What the client checks before it takes over a single byte

**Rule:** Four headers are mandatory: `Content-Type`, `Content-Length`, `ETag`, `Repr-Digest`. If
one is missing, nothing is loaded.
*Reason:* A missing checksum is not a skipped check but a fetch without a statement about what
arrives.

**Rule:** Version, checksum and size are checked against the row of the list **before** the body
is read.
*Reason:* If something differs, the document has changed since the list; the placeholder would
then carry the size and checksum of a different version, and the file system would later report
corruption instead of a change.

**Rule:** After loading, SHA-256 is computed over the received bytes and held against
`Repr-Digest`. If it differs, the hydration has **failed** — the file stays empty, and the error
stands in the usage log.
*Reason:* See above: a short body arrives with `200`. Only this comparison turns it into a failed
hydration instead of a silent forgery of the voucher.

### §7.2.3 Every hydration is an access

**Rule:** On every `200` from this endpoint the server **must** write the audit event
`document.read`, with user, device, document, version and time.
*Reason:* Gap G-18 — today the server records the fetch only in the application log. Exactly here
the requirement “every hydration is an access and belongs in the log” is met; without this entry
the archive's statement about who has seen a document is wrong — and it is the statement that
counts in court.

**Rule:** The client makes sure that **every** hydration runs over this endpoint. There is no
second source for document bytes — no preview cache that replaces a hydration, no copy from an
earlier run.
*Reason:* A byte that comes from a source the server does not see is an access the log does not
know about.

**Rule:** If the access log cannot be reached, **no content** is delivered.

<!-- golden: problem_access_log_missing.json -->
```json
{
  "type": "https://errors.elasticdms.io/access-log-unavailable",
  "title": "Zugriff nicht protokollierbar",
  "status": 503,
  "detail": "Das Zugriffsprotokoll ist nicht erreichbar. Ohne Protokolleintrag wird kein Inhalt ausgeliefert.",
  "instance": "/v1/documents/doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB/content"
}
```

*Reason:* An access without a log entry is worse than a refused access: the refused one is noticed
and fixed, the unlogged one is only noticed when somebody needs the log.

### §7.2.4 `Elasticdms-Accessing-Application`

`[GAP → PROPOSAL]` New. The value is the **file name** of the program that opens the file,
percent-encoded outside the visible ASCII characters (`Übersicht` → `%C3%9Cbersicht`).

**Rule:** Only the file name, never a path.
*Reason:* On Windows and macOS a path contains the user name (`C:\Users\<name>\…`); it would thus
stand in every log line of the archive, although the archive already knows the user from the
token.

**Rule:** The value is percent-encoded, not cut off.
*Reason:* Header values are ASCII, a localised program name is not; a mangled display in the log
is a statement one can no longer believe.

**Rule:** The value is an observation, not a permission. The server decides nothing by it.
*Reason:* A client can send any name; whoever tied a decision to it would have an access control
the attacker fills in themselves.

---

## §7.3 Delivery channel — signed orders from a closed catalogue

`[GAP → PROPOSAL]` The largest invented surface (gap G-13, finding Q-18). Laid down is only the
transport: *„Zustellkanal: Long-Poll, wie in ADR-013 für den NAV-Agenten entschieden. Kein neuer
Transport."* — “Delivery channel: long poll, as decided in ADR-013 for the NAV agent. No new
transport.” ADR-013 brings the second rule with it: no free-form command, but signed orders from a
closed catalogue, with quantity and rate limits **in the client itself**.

### §7.3.1 The poll

```http
GET /v1/delivery/commands?wait=25&cursor=eyJzIjoxODAyfQ HTTP/1.1
Host: api.elasticdms.io
Authorization: DPoP <device token, scope delivery:receive>
DPoP: <proof>
Elasticdms-Version: 2026-09-01
Accept: application/json
```

**Rule:** Outbound only. No listening port, no inbound connection on the workstation.
*Reason:* ADR-013: *„Die gefährlichere Richtung ist aus der Cloud ins interne Netz, nicht
umgekehrt."* — “The more dangerous direction is from the cloud into the internal network, not the
other way round.”

**Rule:** `wait` at most 25 seconds.
*Reason:* Above that, load balancers and corporate proxies do not hold the connection, and the
failure shows up as a sporadic connection break instead of an error (ADR-013).

**Rule:** The channel runs with the **device** token.
*Reason:* An erasure has to reach a device even when nobody is signed in — and that is exactly
when pinned copies still lie on the disk.

**Rule:** Backoff on `503` or a network error: exponential with jitter, at most five minutes.
*Reason:* A client that runs against a failed service on a 25-second tick prolongs the outage.

<!-- golden: delivery_commands.json -->
```json
{
  "items": [
    {
      "commandId": "cmd_01JKC4D6E8F0G2H4J6K8M0N2P4",
      "deviceId": "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
      "kind": "DEHYDRATE",
      "issuedAt": "2026-09-11T07:30:00Z",
      "payload": {
        "documentIds": [
          "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB"
        ],
        "reason": "ERASURE"
      },
      "serverSignature": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVkbXMtZGVsaXZlcnktY29tbWFuZCtqd3QiLCJraWQiOiJlZG1zLWttcy0yMDI2LTA5In0..MEQCIH2rXk9pQeVwT4mB1sZ0dLcJx7oNfR3aYuK8gPqW5tCvAiA9fL0mXbQ7zH1uEjR6oNcP4sVtY2gKdW8xB3rMqLeZTw"
    },
    {
      "commandId": "cmd_01JKC5E7F9G1H3J5K7M9N1P3Q5",
      "deviceId": "dev_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
      "kind": "RECONCILE",
      "issuedAt": "2026-09-11T07:30:04Z",
      "payload": {
        "container": "arc_01JKA9P4S6T8V0W2X4Y6Z8A1B3/cas_01JKA7M2Q9R4S6T8V0W1X3Y5Z7"
      },
      "serverSignature": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVkbXMtZGVsaXZlcnktY29tbWFuZCtqd3QiLCJraWQiOiJlZG1zLWttcy0yMDI2LTA5In0..MEUCIQCw8n2LrV6tYqJ0dM5xBfKe3sPzR1oNhTgW7uXvA4iQcgIgL9mBd0KpXzS6yNfW2rEjHt1oPvQ3kCbUZ8aM5RxTnLE"
    }
  ],
  "nextCursor": "eyJzIjoxODAyfQ"
}
```

<!-- golden: delivery_empty.json -->
```json
{
  "items": [],
  "nextCursor": "eyJzIjoxODAyfQ"
}
```

**Rule:** An empty `items` list is the normal case of an expired wait, not an error. The cursor
moves on all the same.
*Reason:* Otherwise the client would count every quiet day as a fault — and in the end would no
longer know when it really had one.

**Rule:** At most 50 commands per response; while being read, every entry stays a **raw** JSON
value until it is translated one by one.
*Reason:* A broken command must not block the whole page and with it the channel — otherwise a
single faulty order would hold up every later erasure.

### §7.3.2 The closed catalogue

| `kind` | Payload | Effect |
|---|---|---|
| `DEHYDRATE` | `{"documentIds": [...], "reason": "ERASURE" \| "ACCESS_REVOKED" \| "SPACE_RECLAIM"}` | release local copies, more depending on the occasion |
| `RECONCILE` | `{"container": "<a container of §7.1.1>" \| null}` | fetch one list again immediately; `null` means all |
| `SIGN_OUT` | `{}` | end the session, clear the mirror |
| `REFRESH_KEYS` | `{}` | run `GET /v1/server-keys` |

**Rule:** What does not stand here is not executed. An unknown kind is acknowledged `REJECTED`.
*Reason:* A delivery channel that executes arbitrary commands is a remote-wipe tool for anybody
holding the server or the load balancer.

**Rule:** A payload with an unknown field is `REJECTED`, not half executed.
*Reason:* A field the client does not know can restrict the meaning of the command
(`"includePinned": false`); executing it without that field would mean doing more than was
ordered.

**Rule:** `RECONCILE` requires `container` **explicitly**. A missing field is an error; `null`
means “all”.
*Reason:* Otherwise a typo in the field name would be a silent full reconciliation.

**Rule:** `container` is the text form of a container of the namespace, exactly as the client
writes it: `root`, `baskets`, `bsk_…`, `archives`, `arc_…`, `arc_…/cas_…`, `searches`, `srch_…`.
Everything else is `REJECTED`.
*Reason:* The client hands the value to the core's own reader (`Container::from_str`) instead of
comparing prefixes itself. The list of prefixes that stood here before namespace v2 is the reason:
a bare `cas_…` was a container then and is a read error now, and a hand-written list would have
gone stale in exactly this place without any test noticing.

### §7.3.3 The three occasions (ADR-D04)

| Occasion | Release the pin | Entry | Hint to the user |
|---|---|---|---|
| `ERASURE` (DSGVO — the German GDPR implementation, ADR-011) | yes | remove — the name goes too | yes, **without** the document title |
| `ACCESS_REVOKED` | yes | dehydrate; the next list takes it out | no |
| `SPACE_RECLAIM` | **no** | dehydrate if not pinned | no |

*Reason for releasing the pin:* Without it, dehydrating fails — `ERROR_CLOUD_FILE_PINNED` on
Windows, `NonEvictable` on macOS —, and an ordered erasure would get stuck on a user setting.
*Reason for the exception at `SPACE_RECLAIM`:* Routine is no occasion to override a deliberate
decision of the user; space is made elsewhere.

**Why this differs from the note of 2026-09-10:** What was decided there is only *„Der Löschbefehl hebt die Anheftung auf."*
— “The erasure command releases the pin.” The threefold split stands in the requirements as a
*proposal, not decided* (ADR-D04).

**Rule:** The hint on `ERASURE` names **no** document title, and earlier rows of the local usage
log have the name taken from them.
*Reason:* Otherwise the very title the erasure is meant to expunge would stand in the window built
for transparency (ADR-011: the erasure register is content-free).

### §7.3.4 The signature

```
signed bytes     = JCS( command without the field "serverSignature" )     [RFC 8785]
serverSignature  = detached compact JWS, "<b64u(header)>..<b64u(signature)>"
protected header = { "alg": "ES256",
                     "typ": "edms-delivery-command+jwt",
                     "kid": "<kid of an evidence-signing key>" }
```

**Rule:** It is the same construction, the same canonicalisation and the same verifier as for
`QcClearance`, `ReleaseGrant` and the key statement (03 §6.2.4) — one rule for the whole procedure,
not five similar ones.
*Reason:* Five similar rules are five occasions to implement one of them wrongly, and the wrong
one is only noticed when a signature would have to be verified.

**Rule:** `typ` is part of the check.
*Reason:* Without that binding a signature from another context would be reusable here as soon as
two canonicalised bodies coincide even once (03 §6.2.4, P11).

**Rule:** The client verifies against the **anchored** key set. Without an anchor **no** command
is executed.
*Reason:* The threat model names the compromised server explicitly (`geraete-auth §5.4`); TLS
authenticates exactly the counterpart that is allowed to be the attacker there.

**Rule:** The envelope holds the **raw value** of the command, unknown fields included.
*Reason:* Whoever translated it into a model first and back afterwards would lose them — and an
honest server's signature would no longer hold (rule P2).

**Rule:** The command is meant for this device; `deviceId` stands in the signed bytes and is
compared.
*Reason:* Otherwise a real, validly signed erasure command could be replayed from one device to
any other.

### §7.3.5 Limits in the client

**Rule:** At most **500 documents per command**, at most **30 commands per minute**.
*Reason:* The limit does not prevent the erasure — the server splits large erasures up — but
prevents a single forged or misused command from emptying the whole mirror in one go (ADR-013).

**Rule:** A `DEHYDRATE` without a document, and a document that stands twice in the command, are
errors.
*Reason:* Both are faults on the counterpart's side; smoothing them over silently would cover up a
defect at exactly the point where documents disappear.

### §7.3.6 Acknowledgement

```http
POST /v1/delivery/commands/cmd_01JKC4D6E8F0G2H4J6K8M0N2P4:acknowledge HTTP/1.1
Host: api.elasticdms.io
Authorization: DPoP <device token>
DPoP: <proof>
Idempotency-Key: 01JKC6F8G0H2J4K6M8N0P2Q4R6
Content-Type: application/json
```

<!-- golden: acknowledgement_rejected.json -->
```json
{
  "outcome": "REJECTED",
  "detail": "the command kind `DELETE_EVERYTHING` is not in this client's catalogue; it is not executed"
}
```

<!-- golden: acknowledgement_receipt.json -->
```json
{
  "commandId": "cmd_01JKC4D6E8F0G2H4J6K8M0N2P4",
  "outcome": "APPLIED",
  "acknowledgedAt": "2026-09-11T07:30:12Z"
}
```

**Rule:** Four outcomes: `APPLIED`, `NOT_APPLICABLE`, `REJECTED`, `FAILED`. Only `FAILED` is
**not** final; the server then delivers again.
*Reason:* “The document was not on this device” and “I did not manage it” are different
situations: the first is settled, the second has to come back.

**Rule:** Delivered at least once. The client de-duplicates over `commandId` and holds unsent
acknowledgements across a crash.
*Reason:* A command whose acknowledgement was lost on the network comes again; without
de-duplication it would run a second time, and at `ERASURE` that would be a second log entry about
a document that no longer exists.

**Rule:** `Idempotency-Key` is a ULID **per attempt**, not per command.
*Reason:* 03 §6.0.10 / AND-2. The same key with a differing body is `422 idempotency-key-reuse`;
one key per command would make a second, different acknowledgement impossible.

<!-- golden: problem_command_already_acknowledged.json -->
```json
{
  "type": "https://errors.elasticdms.io/delivery-command-already-acknowledged",
  "title": "Befehl bereits quittiert",
  "status": 409,
  "detail": "Dieser Befehl wurde bereits mit APPLIED quittiert; eine zweite Quittung ändert nichts.",
  "instance": "/v1/delivery/commands/cmd_01JKC4D6E8F0G2H4J6K8M0N2P4:acknowledge"
}
```

**Rule:** `409 delivery-command-already-acknowledged` is **success** for the client: the command
is settled, the acknowledgement may leave the queue.
*Reason:* Otherwise an acknowledgement the server has long had would stay behind forever — and
`delivery.unacknowledgedCommands` in the heartbeat would permanently report a fault that is none.

**Rule:** `detail` **never** names a document title or file name, at most 500 characters.
*Reason:* The erasure register is content-free (ADR-011); a reason that named the title would carry
exactly the content the erasure removed back into the log.

---

## §7.4 Ingest — taking over from a mail basket

`[GAP → PROPOSAL]` Entirely new (gap G-20, finding Q-9). The drop target is a **mail basket inside
the mirror** — since namespace v2 the only place in the tree where a file may come into being at
all (ADR-D11, §7.1.1). The inbox folder next to the mirror is gone; what it was for stays
(ADR-D08 §1, amended).

### §7.4.1 The order is the rule

**Rule:** **Upload first, then open the browser.**
*Reason:* The clarification-case invariant (`scope-cut` A6): *„Ein Ereignis endet nie ohne
persistiertes Ergebnis."* — “An event never ends without a persisted result.” If the document is
already at the server, a closed browser is harmless. In the reverse order every abort would lose
the document — and the user would believe they had handed it in.

Three steps: `POST /v1/ingest-uploads` · `PUT <uploadUrl>` · `POST …:complete`.

<!-- golden: ingest_request.json -->
```json
{
  "basketId": "bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5",
  "fileName": "Rechnung 2026-0412.pdf",
  "mediaType": "application/pdf",
  "size": 284173,
  "sha256": "sha256:189a92c221f3d69b68a569df83d04a28e881b62cbefc3b6c50a441711c5a1721"
}
```

**Rule:** The submission names the basket it came out of: `basketId` is mandatory.
*Reason:* The basket is the only statement of intent a dragged-in file carries. Without it the
server would have to pick a target — and a pick at this point is a filing decision, which is
precisely what the basket does not make (ADR-D11).

**Rule:** A basket that is not (or no longer) visible to this user is a `404` with the type of
§7.0.3. The document is filed **nowhere else**.

<!-- golden: problem_basket_unknown.json -->
```json
{
  "type": "https://errors.elasticdms.io/not-found",
  "title": "Briefkorb nicht sichtbar",
  "status": 404,
  "detail": "Der Briefkorb bsk_01JKC2R6V8W0X2Y4Z6A8B1C3D5 ist für Sie nicht sichtbar. Die Datei bleibt liegen, bis ein sichtbarer Briefkorb gewählt ist.",
  "instance": "/v1/ingest-uploads",
  "traceId": "01JKC4D6E8F0G2H4J6K8M0N2P5"
}
```

*Reason:* `404 not-found` means “not visible to you”, never “does not exist” (§7.5.1). A server
that quietly filed the submission into some other basket would take a decision the user did not —
and nobody would look again. The file stays where it lies; the error applies to that one file and
not to the batch (ADR-D08 point 4), and the next reconciliation shows whether the basket is still
there. The test `a_basket_that_is_gone_is_an_error_and_never_a_filing_somewhere_else` holds it.

**Rule:** `fileName` is a bare file name, at most 255 bytes, without a path and without control
characters.
*Reason:* A path would give away the user name; a control character would be a problem in every
display that later shows it.

**Rule:** `mediaType` is the operating system's statement. The server detects the type **itself,
anew**, and does not rely on it.
*Reason:* The extension on a workstation is a claim of the user's, not a property of the bytes.

<!-- golden: ingest_grant.json -->
```json
{
  "uploadId": "upl_01JKD8H0J2K4M6N8P0Q2R4S6T8",
  "uploadUrl": "https://api.elasticdms.io/v1/ingest-uploads/upl_01JKD8H0J2K4M6N8P0Q2R4S6T8/content",
  "duplicateOf": null,
  "expiresAt": "2026-09-11T08:00:00Z"
}
```

**Rule:** `uploadUrl` is used only if it lies **below the API**. No pre-signed address of a foreign
host.
*Reason:* An `uploadUrl` on a foreign host would send a document's bytes there — and the user would
notice nothing, because the operation succeeds.

**Rule:** The `PUT` carries `Content-Digest: sha-256=:…:` over exactly the bytes sent.
*Reason:* Otherwise the server cannot tell whether a different file arrived or the line damaged it.

<!-- golden: problem_upload_digest.json -->
```json
{
  "type": "https://errors.elasticdms.io/ingest-content-digest-mismatch",
  "title": "Prüfsumme weicht ab",
  "status": 422,
  "detail": "Der serverseitig gerechnete sha-256-Wert der übertragenen Bytes weicht vom angekündigten ab.",
  "instance": "/v1/ingest-uploads/upl_01JKD8H0J2K4M6N8P0Q2R4S6T8/content",
  "errors": [
    {
      "field": "sha256",
      "code": "mismatch",
      "expected": "sha256:189a92c221f3d69b68a569df83d04a28e881b62cbefc3b6c50a441711c5a1721"
    }
  ]
}
```

*Reason for the error instead of a silent acceptance:* A voucher that lies in the archive
differently from how it lay on the workstation is an integrity break under GoBD — and it would
never be noticed again.

### §7.4.2 Duplicates

<!-- golden: ingest_grant_duplicate.json -->
```json
{
  "uploadId": "upl_01JKD8H0J2K4M6N8P0Q2R4S6T8",
  "uploadUrl": "https://api.elasticdms.io/v1/ingest-uploads/upl_01JKD8H0J2K4M6N8P0Q2R4S6T8/content",
  "duplicateOf": {
    "documentId": "doc_01JK4R7ZQ8M3N5P6T9V0WXYZAB",
    "title": "Rechnung 2026-0412",
    "createdAt": "2026-03-14T09:12:44Z"
  },
  "expiresAt": "2026-09-11T08:00:00Z"
}
```

**Rule:** A duplicate is **marked, not suppressed**. The upload continues; the human in the browser
decides.
*Reason:* Two invoices with an identical PDF can be two transactions. A client that swallows the
second takes away from the human a decision only they can make.

**Rule:** `duplicateOf` is set only if the user is **allowed to read** the existing document;
otherwise `null`.
*Reason:* Otherwise the hint would be an oracle for the existence of documents this user must not
see — every file could be tested against the archive.

### §7.4.3 Completion

<!-- golden: ingest_completed.json -->
```json
{
  "uploadId": "upl_01JKD8H0J2K4M6N8P0Q2R4S6T8",
  "state": "IN_INBOX",
  "captureUrl": "https://app.elasticdms.io/erfassung?upload=upl_01JKD8H0J2K4M6N8P0Q2R4S6T8"
}
```

**Rule:** Every `state` means: the event is persisted. `ACCEPTED`, `IN_INBOX` and `IN_REVIEW` only
differ in where it lies. An unknown value is taken over and displayed, not reinterpreted.
*Reason:* After `:complete` the client must in no case claim the operation is still open — the
local file is then no longer the only copy.

**Rule:** `captureUrl` is opened only if it lies below the web interface.
*Reason:* A foreign capture page in the user's browser is a sign-in form that looks real because
the client opened it.

**Rule:** A mail basket is a **trigger, not a filing destination**. After the submission the file
moves out of the mirror into the app's own data directory, `<holding>/<uploadId>/`
(`EDMS_HOLDING_DIR`) — **never** deleted.
*Reason:* Until the server has confirmed the ingest, the local file is the only copy (GoBD
completeness). It does not stay in the basket either: the mirror shows the server's truth, not our
spool (namespace v2 §5, ADR-D11) — a file lying there after the hand-over would be the one entry
in the tree the server knows nothing about. And what a workstation hands in goes through the
ingest, never directly into a case file — otherwise the folder would be a file share with a search
function (ADR-D08, risk 11).

**Rule:** Up to three files open one capture tab each; above that **one** tab with the mailbox.
*Reason:* 200 tabs would no longer be a workstation.

---

## §7.5 Error catalogue and scope matrix

### §7.5.1 Error catalogue

All `type`s lie under `https://errors.elasticdms.io/`. **The `type` never changes**, even when
`title` changes (03 §6.17). A `type` that does not lie under this base is **not** translated into
the catalogue.
*Reason:* Otherwise `https://example.org/device-revoked` out of a foreign response would suggest a
device lock — a fault an attacker could trigger.

**From 03 §6.17, relevant for the folder client:**

| `type` | HTTP | Trigger | Security event |
|---|---|---|---|
| `device-enrollment-code-invalid` | 401 | enrollment code wrong | — |
| `device-enrollment-code-expired` | 401 | enrollment code older than 15 min | — |
| `device-id-conflict` | 409 | identifier taken, different key | — |
| `device-network-targets-enabled` | 422 | kiosk; a workstation reports none | — |
| `device-pending-approval` | 403 | the rule at tier `SOFTWARE` | — |
| `device-revoked` | 403 | device locked | — |
| `device-quota-exceeded` | 403 | plan limit | — |
| `device-not-in-network-segment` | 403 | source IP outside the segment | **yes** |
| `device-signature-mismatch` | 403 | reported program signature differs | **yes** |
| `device-assertion-invalid` | 400 | `private_key_jwt` | — |
| `server-keys-not-anchored` | 403 | anchor set not confirmed | — |
| `server-keys-unavailable` | 503 | KMS unreachable; the device keeps its state | — |
| `server-key-revoked` | 409 | evidence from a revoked key | **yes** |
| `server-key-set-stale` | 409 | device lies behind the authoritative revocation | — |
| `dpop-nonce-required` | 401 | RFC 9449 §8; exactly one retry | — |
| `token-device-binding-mismatch` | 403 | `device_id` claim ≠ DPoP device | **yes** |
| `refresh-token-reuse` | 400 (`error_uri`) | rotation violated; family revoked | **yes** |
| `insufficient-authentication` | 401 | step-up per RFC 9470 | — |
| `step-up-subject-mismatch` | 403 | a different human confirmed | **yes** |
| `tenant-identity-incomplete` | 403 | `personId` missing | — |
| `unsupported-media-type` | 415 | upload | — |
| `idempotency-in-progress` | 409 | the same key in progress | — |
| `idempotency-key-reuse` | 422 | same key, different body | — |
| `precondition-required` / `precondition-failed` | 428 / 412 | `If-Match` / `If-None-Match: *` | — |
| `mutually-exclusive-parameters` | 400 | input | — |
| `invalid-resource-id` | 400 | identifier not canonical (T17) | — |
| `validation-failed` | 422 | input | — |
| `insufficient-scope` | 403 | scope missing | — |
| `rate-limited` | 429 | `Retry-After` beats every local backoff | — |
| `client-version-too-old` | 426 | version no longer served | — |
| `not-found` | 404 | not visible | — |

**Rule:** `404 not-found` never means “does not exist”, always “not visible to you”.
*Reason:* The distinction would be an oracle for the existence of other people's documents (tenant
separation, ADR-007).

`[GAP → PROPOSAL]` **New for the folder client:**

| `type` | HTTP | Trigger | Golden |
|---|---|---|---|
| `desktop-client-not-permitted` | 403 | the tenant has not enabled the folder client | — |
| `session-expired` | 400 (`error_uri`) | session over; sign in again | `oauth_session_expired.json` |
| `device-code-expired` | 400 (`error_uri`) | device code expired (`geraete-auth §2.3`) | `oauth_device_code_expired.json` |
| `invalid-cursor` | 400 | cursor unreadable; **never** a jump back to page 1 | `problem_cursor_invalid.json` |
| `saved-search-not-executable` | 422 | field unknown, not queryable or not readable | `problem_search_not_executable.json` |
| `representation-unavailable` | 404 | no deliverable version | `problem_rendition_missing.json` |
| `access-log-unavailable` | 503 | without a log entry, no content | `problem_access_log_missing.json` |
| `delivery-command-unknown` | 404 | acknowledgement for an unknown command | — |
| `delivery-command-already-acknowledged` | 409 | **success** for the client | `problem_command_already_acknowledged.json` |
| `ingest-content-digest-mismatch` | 422 | `Content-Digest` differs | `problem_upload_digest.json` |
| `ingest-upload-incomplete` | 409 | `:complete` before the last byte | — |
| `ingest-upload-expired` | 410 | `expiresAt` passed | — |
| `ingest-too-large` | 413 | above the upper limit | — |

**Rule:** A `type` this client does not know is a value — no crash and no reinterpretation into a
known one.
*Reason:* The server may introduce new types; a client that stopped at that with a read error
would not be maintainable in the field, and one that read them as a known type would do the wrong
thing.

### §7.5.2 Scope matrix

| Scope | Endpoints | Carrier | Source |
|---|---|---|---|
| `device:self` | `GET /v1/devices/me`, `:heartbeat`, `GET /v1/server-keys` | device token | 03 §6.16 |
| `desktop:login` | `POST /v1/oauth/device_authorization` | device token | **proposal** |
| `delivery:receive` | `GET /v1/delivery/commands`, `:acknowledge` | device token | **proposal** |
| `folders:read` | `GET /v1/mirror/baskets`, `GET /v1/mirror/archives`, `GET /v1/mirror/archives/{arc}/cases`, `GET /v1/mirror/searches` | user token | 03 §6.16 |
| `documents:read` | `GET /v1/mirror/archives/{arc}/cases/{cas}/documents`, `GET /v1/mirror/searches/{id}/documents`, `GET /v1/documents/{id}/content` | user token | 03 §6.16 |
| `ingest:submit` | `POST /v1/ingest-uploads`, `PUT <uploadUrl>`, `:complete` | user token | **proposal** |
| `openid`, `profile` | identity in the user interface | user token | 03 §6.16 |

**Rule:** `desktop:login` means what `kiosk:login` means at the panel — and is a name of its own.
*Reason:* A tenant has to be able to enable workstations without enabling kiosk devices; a shared
scope would force both or neither.

**Rule:** The folder client **never** asks for `scan:operate`, `scan:review`, `approvals:decide`,
`destruction:acknowledge`, `documents:retract` or `audit:anchor`.
*Reason:* It captures nothing, releases nothing, destroys no paper and cancels nothing. A scope one
holds is a scope a fault can use.

**Rule:** The folder client keeps **no** audit journal of its own and no anchor chain.
*Reason:* Finding Q-5. A reading client that destroys no paper has no evidence to anchor; the
server logs the hydration (§7.2.3). Were the server nevertheless to demand anchors from every
device, that would be a server decision — not a client workaround.

Missing scope → `403` with
`WWW-Authenticate: DPoP error="insufficient_scope", scope="documents:read"` and `type`
`…/insufficient-scope`.

---

## §7.6 The contract tests

They stand in `crates/wire/tests/` and in the unit tests of `edms-wire`; the numbers T1–T17 are
those of the contract extract, T18 upwards are new.

| No. | Assurance | Place |
|---|---|---|
| T1 | Enrollment goes out as `PUT` **without** `Authorization` and **without** DPoP | `edms-net` |
| T2 | Retry after a break: `412` is **success**, `If-None-Match: *` is present | `edms-net` |
| T3 | The complete response also delivers `serverKeys` | `the_device_object_waits_for_approval_and_carries_the_key_block` |
| T5 | `409 device-id-conflict` is **not** an idempotent retry | `every_problem_golden_carries_the_error_kind_its_name_promises` |
| T6 | Anchor fingerprint: same value on both sides, even in a different order | `edms-crypto` |
| T7 | A smaller `keySetVersion` does not change the state | `edms-crypto` |
| T8 | An entry that counter-signs itself is discarded | `edms-crypto` |
| T9 | `use_dpop_nonce` leads to **exactly one** retry | `edms-net` |
| T11 | A list is taken into the namespace **unfiltered** | `edms-engine` |
| T12 | `ERASURE` removes the entry, `ACCESS_REVOKED` dehydrates, `SPACE_RECLAIM` leaves pinned files alone | `edms_core::delivery` |
| T13 | A mangled content body is a **failed** hydration | `edms-engine` |
| T14 | A lost refresh response packet is **not** blindly repeated | `edms-net` |
| T15 | JCS corpus (RFC 8785) | `edms-crypto` |
| T16 | An unreadable cursor is an **error**, not a jump back to page 1 | `every_problem_golden_carries_the_error_kind_its_name_promises` |
| T17 | Identifiers: lower case, `I`/`L`/`O`/`U`, hyphens, UUID text, overflow | `edms_core::identifier` |
| **T18** | Every golden file survives `body → type → body` unchanged | `every_golden_file_survives_the_round_trip_through_its_type` |
| **T19** | Every JSON block of this document is byte-identical with its golden file | `every_json_block_stands_byte_identical_in_its_golden_file` |
| **T20** | Every short code of the error catalogue stands in this document | `the_error_catalogue_of_the_code_stands_completely_in_the_contract` |
| **T21** | A bearer token fails while still being read | `a_bearer_token_is_rejected_already_while_reading` |
| **T22** | An unsigned command never becomes a command of the core | `without_a_signature_no_command_arises` |
| **T23** | A command for another device is never executed | `a_command_for_another_device_is_never_executed` |
| **T24** | An address out of a response is used only below its base | `a_prefix_is_not_yet_an_origin` |
| **T25** | A token stands in no `Debug` output | `a_token_appears_in_no_debug_output` |

> **T4 and T10 are dropped.** T4 checks `device-network-targets-enabled` at a panel with factory
> targets, T10 the `QcClearance` of a capture batch. A workstation has neither the one nor the
> other; the tests stay with the counterpart instead of being rebuilt here.

---

## What this contract leaves open

| No. | Open | Provisional |
|---|---|---|
| Q-1 | Is the folder client a device or a browser client? Nothing classifies it. | Both, in layers: device credential plus user token (ADR-D03). **The counterpart's decision.** |
| Q-7 | The complete shape of `serverKeys` is binding nowhere; field names carry weight for JCS. | Golden taken from 03 §6.2.4, verifier behind **one** type. **Blocking for `edms-crypto`.** |
| Q-14 | No endpoint delivers revocation statements. | Part of `GET /v1/server-keys`; announced over `resyncServerKeys`. |
| Q-18 | The whole delivery channel (§7.3) is invented. | **To be confirmed before the counterpart builds.** |
| — | `Range`/`206` for hydration (gap G-19) | Whole files, see §7.2.1. |
| — | Change stream for the namespace (gap G-17) | `ETag` plus `RECONCILE`, see §7.1.3. |
