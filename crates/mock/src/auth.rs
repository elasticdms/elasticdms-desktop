//! The authorization server: discovery, device token, device flow, revocation — and the two pages
//! a human sees in the browser.
//!
//! It runs on its **own** listener, and therefore under its own origin. That is not a convenience:
//! DPoP nonces are kept per origin (§7.0.9), and a client that throws both hosts into one pot runs
//! into a loop of two alternating demands. Only two real origins show that.
//!
//! The way in is **exclusively** the device authorization grant (RFC 8628, AND-4/A-03): no PAR, no
//! `authorization_endpoint`, no web view. The mock therefore offers none either — what does not
//! exist a client cannot take by accident.
//!
//! `[GAP -> PROPOSAL]` The two **pages** (`/geraet`, `/erfassung`) are invented. The contract only
//! fixes their addresses (§7.0.7, §7.4.3) and what has to stand on the confirmation page: the
//! anchor the human compares with the app's. Everything else — shape, text, two buttons — is the
//! simplest form that makes the flow checkable, and never a template for the real web interface.
//!
//! The two paths stay German (`/geraet`, `/erfassung`): they are the addresses the contract's
//! own examples show (03 §6, `verification_uri`, `captureUrl`), they stand in the golden files
//! `device_authorization_desktop.json` and `ingest_completed.json`, and tests of `edms-net` and
//! `edms-app` read them. The mock imitates the server; it does not define it. What the pages
//! **say** is English like everything else on the wire: it is the mock speaking, not the German
//! product.

use axum::Router;
use axum::routing::{get, post};
use edms_core::identifier::DeviceIdentifier;
use edms_crypto::jws::CompactJws;
use edms_crypto::key::PublicKey;
use edms_wire::basics::ErrorKind;
use edms_wire::discovery::{
    ALGORITHM_ES256, AUTH_METHOD_PRIVATE_KEY_JWT, AuthorizationServerMetadata, PATH_AS_METADATA,
    PKCE_S256,
};
use edms_wire::login::{
    DEVICE_SCOPES, DeviceAuthorization, DeviceAuthorizationRequest, DpopTokenKind,
    PATH_DEVICE_AUTHORIZATION, PATH_REVOCATION, PATH_TOKEN, RevocationRequest, TokenRequest,
    TokenResponse, USER_SCOPES, scope_text,
};
use serde_json::Value;

use crate::http::{
    Context, Inbox, check_proof, empty, golden_oauth, html, json_response, oauth_error,
};
use crate::state::{Access, Device, DeviceState, LoginFlow, LoginState};
use crate::time::now;

/// The alphabet of the `user_code` — without the `0/O`, `1/I/L`, `U/V` confusions (RFC 8628 §6.1).
///
/// The human types it off. Every character that can be confused with another one is a sign-in
/// attempt that fails out of a misreading — and the human looks for the reason in himself.
const CODE_ALPHABET: &[u8] = b"BCDFGHJKMNPQRSTWXZ23456789";

/// The path of the confirmation page.
pub const PATH_DEVICE_PAGE: &str = "/geraet";

/// The path of the capture page (§7.4.3).
pub const PATH_CAPTURE: &str = "/erfassung";

/// Builds the router of the authorization server.
pub fn router(context: Context) -> Router {
    Router::new()
        .route(PATH_AS_METADATA, get(metadata))
        .route(PATH_DEVICE_AUTHORIZATION, post(device_authorization))
        .route(PATH_TOKEN, post(token))
        .route(PATH_REVOCATION, post(revocation))
        .route(PATH_DEVICE_PAGE, get(device_page).post(device_page_decision))
        .route(PATH_CAPTURE, get(capture_page))
        .fallback(crate::http::unknown_path)
        .method_not_allowed_fallback(crate::http::wrong_method)
        .with_state(context)
}

/// `GET /.well-known/oauth-authorization-server` (03 §6.1).
async fn metadata(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let _ = inbox;
    let base = context.state.auth_base.trim_end_matches('/').to_owned();
    let metadata = AuthorizationServerMetadata {
        issuer: base.clone(),
        token_endpoint: format!("{base}{PATH_TOKEN}"),
        device_authorization_endpoint: Some(format!("{base}{PATH_DEVICE_AUTHORIZATION}")),
        revocation_endpoint: Some(format!("{base}{PATH_REVOCATION}")),
        jwks_uri: Some(format!("{base}/.well-known/jwks.json")),
        grant_types_supported: Some(
            ["client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        ),
        token_endpoint_auth_methods_supported: Some(vec![AUTH_METHOD_PRIVATE_KEY_JWT.to_owned()]),
        token_endpoint_auth_signing_alg_values_supported: Some(vec![ALGORITHM_ES256.to_owned()]),
        dpop_signing_alg_values_supported: Some(vec![ALGORITHM_ES256.to_owned()]),
        code_challenge_methods_supported: Some(vec![PKCE_S256.to_owned()]),
        // §7.0.4: the server has to extend the list by `desktop:login`, `delivery:receive` and
        // `ingest:submit`. The mock is the server that has already done it.
        scopes_supported: Some(
            DEVICE_SCOPES.iter().chain(USER_SCOPES.iter()).map(|s| (*s).to_owned()).collect(),
        ),
        authorization_response_iss_parameter_supported: Some(true),
        further: serde_json::Map::new(),
    };
    json_response(200, &metadata)
}

/// `POST /v1/oauth/device_authorization` (RFC 8628 §3.1, §7.0.7).
///
/// **Without a DPoP header, but with `dpop_jkt`:** RFC 9449 §5 binds the future token through the
/// thumbprint; the proof comes only when it is fetched, and then with the session key.
async fn device_authorization(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let field = inbox.as_form();
    let request = match DeviceAuthorizationRequest::from_form(&field) {
        Ok(request) => request,
        Err(error) => {
            return oauth_error(400, "invalid_request", Some(&error.to_string()), None);
        }
    };
    let device = match check_assertion(&context, &request.client_assertion) {
        Ok(device) => device,
        Err(response) => return response,
    };
    if let Some(response) = check_device_state(&device) {
        return response;
    }
    if request.dpop_jkt.trim().is_empty() {
        return oauth_error(
            400,
            "invalid_request",
            Some("dpop_jkt is missing; without it the future token would be bound to no key."),
            None,
        );
    }

    let default_confirmed = context.state.configuration.auto_confirmation;
    let user = context.state.signed_in_user();
    let (device_code, user_code, anchor) = {
        let mut inner = context.state.lock();
        let device_code = inner.secret("dc_");
        let user_code = format!("{}-{}", code(&mut inner, 4), code(&mut inner, 4));
        let anchor = format!("{}-{}", code(&mut inner, 2), code(&mut inner, 2));
        (device_code, user_code, anchor)
    };
    let designation = format!(
        "{} · {}",
        device.name.clone().unwrap_or_else(|| device.identifier.to_string()),
        context.state.configuration.tenant_name
    );
    let valid = context.state.configuration.device_code_second;
    let flow = LoginFlow {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        anchor: anchor.clone(),
        device: device.identifier,
        jkt: request.dpop_jkt.clone(),
        scope: request.scope.clone(),
        designation: designation.clone(),
        expires: now().plus_millis(i64::try_from(valid).unwrap_or(300).saturating_mul(1_000)),
        state: if default_confirmed { LoginState::Confirmed(user) } else { LoginState::Pending },
        slower: false,
    };
    context.state.lock().login.push(flow);

    let app = context.state.app_base.trim_end_matches('/');
    let response = DeviceAuthorization {
        device_code,
        user_code: user_code.clone(),
        verification_uri: format!("{app}{PATH_DEVICE_PAGE}"),
        verification_uri_complete: Some(format!(
            "{app}{PATH_DEVICE_PAGE}?user_code={}&anchor={}",
            crate::form::encode(&user_code),
            anchor.replace('-', "")
        )),
        expires_in: valid,
        interval: Some(edms_wire::login::DEFAULT_INTERVAL_SECOND),
        anchor: Some(anchor),
        device_designation: Some(designation),
    };
    json_response(200, &response)
}

/// `POST /v1/oauth/token` — three grants, one endpoint (03 §6.2.2, §6.3.1, §6.3.3).
async fn token(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    // The proof first: whoever checks the nonce only after the form answers an attacker without a
    // key the question of which grants exist (geraete-auth §2.4).
    let report = match check_proof(&context, &inbox, None, None) {
        Ok(report) => report,
        Err(response) => return response,
    };
    let field = inbox.as_form();
    let request = match TokenRequest::from_form(&field) {
        Ok(request) => request,
        Err(error) => {
            return oauth_error(400, "invalid_request", Some(&error.to_string()), None);
        }
    };
    let assertion = match &request {
        TokenRequest::ClientCredentials { client_assertion, .. }
        | TokenRequest::DeviceCode { client_assertion, .. }
        | TokenRequest::RefreshToken { client_assertion, .. } => client_assertion.clone(),
    };
    let device = match check_assertion(&context, &assertion) {
        Ok(device) => device,
        Err(response) => return response,
    };
    if let Some(response) = check_device_state(&device) {
        return response;
    }

    match request {
        TokenRequest::ClientCredentials { scope, resource, .. } => {
            if resource.trim_end_matches('/') != context.state.api_base.trim_end_matches('/') {
                return oauth_error(
                    400,
                    "invalid_target",
                    Some("resource does not name this server's resource API (RFC 8707)."),
                    None,
                );
            }
            let issued: Vec<String> = scope
                .split_whitespace()
                .filter(|s| DEVICE_SCOPES.contains(s))
                .map(ToOwned::to_owned)
                .collect();
            if issued.is_empty() {
                return oauth_error(
                    400,
                    "invalid_scope",
                    Some(
                        "A device token carries exactly device:self, desktop:login and delivery:receive.",
                    ),
                    None,
                );
            }
            let token = issue_access(&context, &report.jkt, device.identifier, None, &issued, None);
            json_response(
                200,
                &TokenResponse {
                    access_token: token,
                    token_type: DpopTokenKind,
                    expires_in: context.state.configuration.access_token_second,
                    refresh_token: None,
                    refresh_token_expires_in: None,
                    scope: Some(scope_text(&issued.iter().map(String::as_str).collect::<Vec<_>>())),
                    id_token: None,
                },
            )
        }
        TokenRequest::DeviceCode { device_code, .. } => {
            fetch_after_device_code(&context, &device_code, &report.jkt, device.identifier)
        }
        TokenRequest::RefreshToken { refresh_token, .. } => {
            refresh(&context, &refresh_token, &report.jkt, device.identifier)
        }
    }
}

/// The poll after the confirmation in the browser — four intermediate states, four screens
/// (§7.0.7).
fn fetch_after_device_code(
    context: &Context,
    device_code: &str,
    jkt: &str,
    device: DeviceIdentifier,
) -> axum::response::Response {
    let mut inner = context.state.lock();
    let now = now();
    let Some(flow) = inner.login.iter_mut().find(|flow| flow.device_code == device_code) else {
        return golden_oauth("oauth_device_code_expired.json", 400);
    };
    if flow.device != device {
        return oauth_error(
            400,
            "invalid_grant",
            Some("This device code belongs to a different device."),
            None,
        );
    }
    if flow.expires <= now && flow.state == LoginState::Pending {
        flow.state = LoginState::Lapsed;
    }
    if flow.slower {
        flow.slower = false;
        return golden_oauth("oauth_slow_down.json", 400);
    }
    let state = flow.state;
    let (jkt_expected, scope) = (flow.jkt.clone(), flow.scope.clone());
    match state {
        LoginState::Pending => golden_oauth("oauth_authorization_pending.json", 400),
        LoginState::Rejected => golden_oauth("oauth_access_denied.json", 400),
        LoginState::Lapsed => golden_oauth("oauth_code_expired.json", 400),
        LoginState::Confirmed(user) => {
            if jkt_expected != jkt {
                // RFC 9449 §5: the token belongs to the key `dpop_jkt` named. Without this check
                // a confirmed code could be redeemed with a foreign key.
                return oauth_error(
                    400,
                    "invalid_dpop_proof",
                    Some("The proof names a different key from the dpop_jkt of the authorization."),
                    None,
                );
            }
            inner.login.retain(|flow| flow.device_code != device_code);
            drop(inner);
            let issued: Vec<String> = scope
                .split_whitespace()
                .filter(|s| USER_SCOPES.contains(s))
                .map(ToOwned::to_owned)
                .collect();
            let family = context.state.lock().secret("fam_");
            let access = issue_access(context, jkt, device, Some(user), &issued, Some(&family));
            let refresh = issue_refresh(context, jkt, device, user, &issued, &family);
            json_response(
                200,
                &TokenResponse {
                    access_token: access,
                    token_type: DpopTokenKind,
                    expires_in: context.state.configuration.access_token_second,
                    refresh_token: Some(refresh),
                    refresh_token_expires_in: Some(context.state.configuration.refresh_second),
                    scope: Some(scope_text(&issued.iter().map(String::as_str).collect::<Vec<_>>())),
                    id_token: Some(format!("idt.{user}")),
                },
            )
        }
    }
}

/// Renewing with rotation and reuse detection (03 §6.3.3, contract test T14).
fn refresh(
    context: &Context,
    refresh_token: &str,
    jkt: &str,
    device: DeviceIdentifier,
) -> axum::response::Response {
    let mut inner = context.state.lock();
    let Some(old) = inner.refresh.get(refresh_token).cloned() else {
        return golden_oauth("oauth_session_expired.json", 400);
    };
    if old.redeemed {
        // Reusing a rotated token revokes the whole family across every device. That is a
        // security event, not the end of a session: somebody else used the same token.
        inner.revoke_family(&old.family);
        drop(inner);
        tracing::warn!(family = %old.family, "refresh token reused; family revoked");
        return golden_oauth("oauth_refresh_reused.json", 400);
    }
    if old.device != device || old.jkt != jkt {
        return oauth_error(
            400,
            "invalid_grant",
            Some("This refresh token belongs to a different device or key."),
            None,
        );
    }
    if old.expires <= now() {
        return golden_oauth("oauth_session_expired.json", 400);
    }
    if let Some(entry) = inner.refresh.get_mut(refresh_token) {
        entry.redeemed = true;
    }
    drop(inner);
    let access = issue_access(context, jkt, device, Some(old.user), &old.scopes, Some(&old.family));
    let new = issue_refresh(context, jkt, device, old.user, &old.scopes, &old.family);
    json_response(
        200,
        &TokenResponse {
            access_token: access,
            token_type: DpopTokenKind,
            expires_in: context.state.configuration.access_token_second,
            refresh_token: Some(new),
            refresh_token_expires_in: Some(context.state.configuration.refresh_second),
            scope: Some(scope_text(&old.scopes.iter().map(String::as_str).collect::<Vec<_>>())),
            id_token: None,
        },
    )
}

/// `POST /v1/oauth/revoke` (RFC 7009) — always `200`, even for an unknown token.
async fn revocation(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let field = inbox.as_form();
    let Ok(request) = RevocationRequest::from_form(&field) else {
        // RFC 7009 §2.2.1 knows `invalid_request`; an unknown token, by contrast, is a success.
        return oauth_error(400, "invalid_request", Some("token is missing."), None);
    };
    if check_assertion(&context, &request.client_assertion).is_err() {
        return oauth_error(
            401,
            "invalid_client",
            Some("The client assertion does not hold."),
            None,
        );
    }
    let mut inner = context.state.lock();
    if let Some(entry) = inner.refresh.get(&request.token).cloned() {
        inner.revoke_family(&entry.family);
    }
    // The client does not take the status as proof but clears up in every case (§7.0.8).
    empty(200)
}

// ───────────────────────────── The pages in the browser ─────────────────────────────

/// `GET /geraet` — the confirmation page of the device flow (§7.0.7).
async fn device_page(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let user_code = inbox.query_value("user_code").unwrap_or_default().to_owned();
    let flow = context.state.lock().login.iter().find(|flow| flow.user_code == user_code).cloned();
    let content = match flow {
        Some(flow) if flow.state == LoginState::Pending => format!(
            "<p>The device <strong>{}</strong> wants to sign in.</p>\n\
             <p class=\"anchor\">Anchor: <strong>{}</strong> — it has to match the one the app \
             shows.</p>\n\
             <form method=\"post\" action=\"{PATH_DEVICE_PAGE}\">\n\
             <input type=\"hidden\" name=\"user_code\" value=\"{}\">\n\
             <button type=\"submit\" name=\"action\" value=\"confirm\">Confirm</button>\n\
             <button type=\"submit\" name=\"action\" value=\"reject\">Reject</button>\n\
             </form>",
            escape(&flow.designation),
            escape(&flow.anchor),
            escape(&flow.user_code)
        ),
        Some(_) => "<p>This code has already been decided.</p>".to_owned(),
        None => format!(
            "<p>Type in the code the app shows.</p>\n\
             <form method=\"get\" action=\"{PATH_DEVICE_PAGE}\">\n\
             <input name=\"user_code\" value=\"{}\" placeholder=\"XXXX-XXXX\">\n\
             <button type=\"submit\">Continue</button>\n\
             </form>",
            escape(&user_code)
        ),
    };
    html(200, page("Sign in a device", &content))
}

/// `POST /geraet` — what the human decided.
async fn device_page_decision(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let field = inbox.as_form();
    let user_code = crate::form::field(&field, "user_code").unwrap_or_default().to_owned();
    let action = crate::form::field(&field, "action").unwrap_or_default();
    let control = crate::Control::new(context.state.clone());
    let content = match action {
        "confirm" if control.confirm(&user_code) => {
            "<p>Signed in. You can close this window.</p>".to_owned()
        }
        "reject" if control.reject(&user_code) => {
            "<p>Rejected. Nothing was released on the device.</p>".to_owned()
        }
        _ => "<p>There is no open sign-in for this code.</p>".to_owned(),
    };
    html(200, page("Sign in a device", &content))
}

/// `GET /erfassung` — the page the client opens after a take-over (§7.4.3).
async fn capture_page(
    axum::extract::State(context): axum::extract::State<Context>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let inbox = match Inbox::read(&context, request).await {
        Ok(inbox) => inbox,
        Err(response) => return response,
    };
    let upload = inbox.query_value("upload").unwrap_or_default().to_owned();
    // The page names the basket the file came out of: it is the basket's rule that decides where
    // the document lands (§7.4), so the human in the browser has to see which one it was. A basket
    // that has been removed in the meantime keeps its identifier here — that is still the truth.
    let submission = upload.parse().ok().and_then(|id| {
        let inner = context.state.lock();
        inner.upload.get(&id).map(|entry| {
            let basket = inner
                .baskets
                .iter()
                .find(|candidate| candidate.identifier == entry.basket)
                .map_or_else(|| entry.basket.to_string(), |candidate| candidate.title.clone());
            (entry.filename.clone(), basket)
        })
    });
    let content = match submission {
        Some((name, basket)) => format!(
            "<p>Out of the mail basket <strong>{}</strong>: <strong>{}</strong></p>\n\
             <p>The file is taken over. The capture happens in the browser; the folder client \
             uploads nothing that does not already lie here.</p>",
            escape(&basket),
            escape(&name)
        ),
        None => format!("<p>Nothing lies in the inbox for <code>{}</code>.</p>", escape(&upload)),
    };
    html(200, page("Capture", &content))
}

/// A very simple HTML skeleton. It is a test harness, not a web interface.
fn page(title: &str, content: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">\
         <title>{title} — elasticdms (mock)</title></head>\n<body>\n<h1>{title}</h1>\n\
         {content}\n<hr>\n<p><em>This page belongs to the server mock “edms-mock”. \
         It is a test harness and never a product.</em></p>\n</body>\n</html>\n"
    )
}

/// Escapes the five characters that have a meaning in HTML.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ───────────────────────────── Shared ─────────────────────────────

/// Checks the client assertion (RFC 7523 §2.2, 03 §6.2.2) against the device's key.
///
/// It is the defence against reverse phishing of the device flow: only an enrolled device gets a
/// `user_code`.
// The error side of these results is the **finished HTTP answer**, not a reason one is made out of
// afterwards. That is deliberate: every rejection of the contract has exactly one body, one header
// and one status, and whoever builds it at the place it occurs cannot accidentally build it
// differently elsewhere. `Response` is large for that (128 bytes); a box around it would save
// nothing on a test harness and would bring a `*` to every place it occurs.
#[allow(clippy::result_large_err)]
fn check_assertion(context: &Context, assertion: &str) -> Result<Device, axum::response::Response> {
    let reject = |reason: &str| -> axum::response::Response {
        oauth_error(
            400,
            "invalid_client",
            Some(reason),
            ErrorKind::DeviceAssertionInvalid.typ_uri().as_deref(),
        )
    };
    let jws = CompactJws::read(assertion).map_err(|error| reject(&error.to_string()))?;
    let claims = jws.payload();
    let claim = |name: &str| claims.get(name).and_then(Value::as_str).unwrap_or_default();
    let identifier: DeviceIdentifier = claim("sub")
        .parse()
        .map_err(|error: edms_core::identifier::IdentifierError| reject(&error.to_string()))?;
    if claim("iss") != claim("sub") {
        return Err(reject("iss and sub of a device assertion are the same identifier."));
    }
    let audience = claim("aud");
    let base = context.state.auth_base.trim_end_matches('/');
    if audience != base && !audience.starts_with(&format!("{base}/")) {
        return Err(reject(
            "aud does not name this authorization server; without a recipient binding the \
             assertion could be reused elsewhere.",
        ));
    }
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or_default();
    if exp.saturating_mul(1_000) <= now().unix_millis() {
        return Err(reject("The client assertion has expired (60 s, 03 §6.2.2)."));
    }
    let device = context
        .state
        .lock()
        .devices
        .get(&identifier)
        .cloned()
        .ok_or_else(|| reject("This device is not enrolled."))?;
    let public = PublicKey::from_jwk(&device.jwk).map_err(|error| reject(&error.to_string()))?;
    jws.check(&public).map_err(|_| {
        reject("The signature of the client assertion does not hold against the device's key.")
    })?;
    Ok(device)
}

/// `403` as long as a device is not approved, or is revoked (§7.0.5, §7.5.1).
fn check_device_state(device: &Device) -> Option<axum::response::Response> {
    match device.state {
        DeviceState::Active => None,
        DeviceState::AwaitingApproval => Some(oauth_error(
            403,
            "invalid_client",
            Some("The device is waiting for an administrator's approval."),
            ErrorKind::DeviceApprovalPending.typ_uri().as_deref(),
        )),
        DeviceState::Locked => Some(oauth_error(
            403,
            "invalid_client",
            Some("This device is locked."),
            ErrorKind::DeviceLocked.typ_uri().as_deref(),
        )),
    }
}

/// Creates an access token and returns it.
fn issue_access(
    context: &Context,
    jkt: &str,
    device: DeviceIdentifier,
    user: Option<edms_core::identifier::UserIdentifier>,
    scopes: &[String],
    family: Option<&str>,
) -> String {
    let second = context.state.configuration.access_token_second;
    let mut inner = context.state.lock();
    let token = inner.secret("at_");
    inner.accesses.insert(
        token.clone(),
        Access {
            jkt: jkt.to_owned(),
            device,
            user,
            scopes: scopes.to_vec(),
            expires: now().plus_millis(i64::try_from(second).unwrap_or(900).saturating_mul(1_000)),
            family: family.map(ToOwned::to_owned),
        },
    );
    token
}

/// Creates a refresh token.
fn issue_refresh(
    context: &Context,
    jkt: &str,
    device: DeviceIdentifier,
    user: edms_core::identifier::UserIdentifier,
    scopes: &[String],
    family: &str,
) -> String {
    let second = context.state.configuration.refresh_second;
    let mut inner = context.state.lock();
    let token = inner.secret("rt_");
    inner.refresh.insert(
        token.clone(),
        crate::state::Refresh {
            family: family.to_owned(),
            device,
            user,
            jkt: jkt.to_owned(),
            scopes: scopes.to_vec(),
            expires: now()
                .plus_millis(i64::try_from(second).unwrap_or(43_200).saturating_mul(1_000)),
            redeemed: false,
        },
    );
    token
}

/// `length` characters out of [`CODE_ALPHABET`].
fn code(inner: &mut crate::state::Inner, length: usize) -> String {
    let raw = inner.secret("");
    raw.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .take(length)
        .map(|byte| char::from(CODE_ALPHABET[usize::from(byte) % CODE_ALPHABET.len()]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::state::State;

    #[test]
    fn a_user_code_contains_no_confusable_characters() {
        let state = State::new(
            crate::config::Configuration::default(),
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
        )
        .expect("the forge");
        let mut inner = state.lock();
        for _ in 0..50 {
            let value = code(&mut inner, 4);
            assert_eq!(value.len(), 4, "too short: {value}");
            assert!(
                !value.contains(['O', 'I', 'L', 'U', '0', '1']),
                "a confusable character in {value}"
            );
        }
    }

    #[test]
    fn html_is_escaped_so_that_a_title_does_not_become_a_script() {
        assert_eq!(escape("<script>&\"x\""), "&lt;script&gt;&amp;&quot;x&quot;");
    }

    #[test]
    fn every_page_says_of_itself_that_it_is_a_test_harness() {
        let html = page("Title", "<p>x</p>");
        assert!(html.contains("test harness"), "{html}");
        assert!(html.starts_with("<!doctype html>"));
    }
}
