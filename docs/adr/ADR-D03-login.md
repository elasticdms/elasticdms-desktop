# ADR-D03: Sign-in — device plus user

**Status:** Accepted (2026-09-11).

## Context

ADR-015 (server, binding) governs the sign-in of kiosk devices: an authorization server of its own,
`private_key_jwt`, DPoP, device flow; the device token is a principal of kind `service`. Humans in
the browser sign in over Entra OIDC and receive a server-side `app_session`. A folder client on the
workstation stands between the two, and **no document classifies it** (finding Q-1 in the contract
extract).

Requirement 4 demands that the list return only what **the user** has rights to. A service
principal has the device's rights, not those of the human in front of it.

## Decision

1. **The device gets a key of its own and signs in** like a kiosk device:
   `PUT /v1/devices/{deviceId}` without `Authorization` and without DPoP, `If-None-Match: *`, a
   `412` is success (03 §6.2.1, contract tests T1–T5). Attestation `{"type":"none"}` — a
   workstation has no Android key attestation; the server classifies the device as `SOFTWARE` and
   may demand an approval. The app then shows “device waiting for approval” together with the
   fingerprint.
2. **The human signs in over the device flow** (RFC 8628), in the system browser. The token carries
   the token set of the **user** (ADR-008), bound to this device's DPoP key
   (`https://elasticdms.io/device`, 03 §6.0.6). All lists and content run under this token.
3. **DPoP on every call**, nonce mandatory, exactly one retry (03 §6.0.5, T9).
4. **Secrets live in the operating system's keychain**, never in SQLite: refresh token and private
   key. v1 uses a software key in the keychain; Secure Enclave (macOS) and TPM (Windows) are
   foreseen but not built — `TODO` in the code, listed in the implementation status.
5. **Signing out** revokes the refresh token (RFC 7009), clears the mirror completely and empties
   the namespace. Afterwards no name of the old user stands on the disk any more (requirement 4).

## Rationale

Only this combination satisfies requirement 4 **and** uses a mechanism that has already been
decided. Per AND-4 the device flow is the house's only remaining way to sign in; an embedded
browser (WebView) is explicitly struck there, and the system browser carries the sign-in at Entra
including conditional access anyway.

## Consequences

- The server needs an enrollment path without the scanner blocks and a set of scopes for the folder
  client (contract §7.0). Both are marked there as proposals.
- Session lifetime: the kiosk values (30 min hard) are no good for a workstation. Proposed are the
  browser values (8 h idle, 12 h absolute). When the session expires the tree stays visible, opening
  fails with “sign-in required”, and the tray icon shows it — never a silent emptying of the tree.

## Rejected alternatives

- **The device token alone.** A service principal cannot be bound to the user — a breach of
  requirement 4.
- **An Entra session over WebView and cookie.** AND-4 strikes the WebView path; a cookie session is
  also no API access.
- **PAR.** Struck without replacement by AND-4.
