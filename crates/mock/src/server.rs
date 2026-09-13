//! Two listeners, two origins, one state — and the pass every request takes.
//!
//! **Why two listeners.** `api.` and `auth.` are two hosts in the contract (§7.0.1), and the DPoP
//! nonce is kept per origin (§7.0.9). A mock with a single port could not show the mistake this
//! rule prevents: a nonce of one host presented at the other is invalid, and a client that throws
//! both into one pot runs into a loop of two alternating demands. Two real ports show that on the
//! first attempt.
//!
//! **It listens on 127.0.0.1 only.** No other machine reaches this test harness. The development
//! path `/mock/commands` checks the peer on top of that: it is a remote control, and a remote
//! control that were reachable from the network is a remote erasure tool.
//!
//! **The pass** in this order: fault (a deliberate failure), version header, endpoint, append
//! `DPoP-Nonce`, write the recording. The recording stands at the end because it carries the
//! status along — what came in **and** what went back.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State as AxumState};
use axum::middleware::Next;
use axum::response::Response;
use edms_wire::basics::{API_VERSION, ErrorKind, header};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use crate::control::Control;
use crate::error::MockError;
use crate::http::{Context, catalogue, golden_problem};
use crate::state::{Origin, Recording, State};
use crate::time::now;

/// A running mock. As long as it lives both listeners listen; when it is dropped they stop.
#[derive(Debug)]
pub struct Mock {
    api_base: String,
    auth_base: String,
    app_base: String,
    state: Arc<State>,
    stopper: Vec<oneshot::Sender<()>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Mock {
    /// Binds both listeners and starts serving.
    pub async fn start(configuration: Configuration) -> Result<Self, MockError> {
        let (api_listener, api_base) = bind("API", configuration.api_port).await?;
        let (auth_listener, auth_base) = bind("auth", configuration.auth_port).await?;
        let with_seed = configuration.with_seed;
        let state = Arc::new(State::new(configuration, api_base.clone(), auth_base.clone())?);
        if with_seed {
            crate::seed::sow(&state);
        }
        let app_base = state.app_base.clone();

        let mut stopper = Vec::with_capacity(2);
        let mut tasks = Vec::with_capacity(2);
        for (listener, origin) in [(api_listener, Origin::Api), (auth_listener, Origin::Login)] {
            let context = Context { state: Arc::clone(&state), origin };
            let router = match origin {
                Origin::Api => crate::api::router(context.clone()),
                Origin::Login => crate::auth::router(context.clone()),
            };
            let router = router.layer(axum::middleware::from_fn_with_state(context, pass));
            let (sender, receiver) = oneshot::channel::<()>();
            stopper.push(sender);
            tasks.push(tokio::spawn(async move {
                let service = router.into_make_service_with_connect_info::<SocketAddr>();
                let result = axum::serve(listener, service)
                    .with_graceful_shutdown(async move {
                        // A closed channel is the same signal as a sent one: whoever drops the
                        // mock wants it stopped.
                        let _ = receiver.await;
                    })
                    .await;
                if let Err(error) = result {
                    tracing::error!(listener = origin_name(origin), %error, "listener stopped");
                }
            }));
        }

        Ok(Self { api_base, auth_base, app_base, state, stopper, tasks })
    }

    /// The base address of the resource API, e.g. `http://127.0.0.1:8480` (`EDMS_API_BASE`).
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    /// The base address of the authorization server (`EDMS_AUTH_BASE`).
    pub fn auth_base(&self) -> &str {
        &self.auth_base
    }

    /// The base address of the web interface (`EDMS_APP_BASE`) — the pages `/geraet` and
    /// `/erfassung`.
    pub fn app_base(&self) -> &str {
        &self.app_base
    }

    /// The remote control for tests and development.
    pub fn control(&self) -> Control {
        Control::new(Arc::clone(&self.state))
    }

    /// Stops both listeners and waits until they are closed.
    pub async fn stop(mut self) {
        for sender in self.stopper.drain(..) {
            let _ = sender.send(());
        }
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}

/// Binds a listener on 127.0.0.1 and returns its base address.
async fn bind(name: &'static str, port: u16) -> Result<(TcpListener, String), MockError> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(address).await.map_err(|reason| MockError::Binding {
        name,
        address,
        reason,
    })?;
    let real = listener.local_addr().map_err(|reason| MockError::Address { name, reason })?;
    Ok((listener, format!("http://127.0.0.1:{}", real.port())))
}

/// The name of an origin for the log.
const fn origin_name(origin: Origin) -> &'static str {
    origin.name()
}

/// The pass every request takes.
async fn pass(AxumState(context): AxumState<Context>, request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_ascii_uppercase();
    let path = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), ToString::to_string);
    let only_path = request.uri().path().to_owned();
    let header: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (name.as_str().to_ascii_lowercase(), value.to_str().unwrap_or("<not ASCII>").to_owned())
        })
        .collect();
    let peer =
        request.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(address)| *address);

    let mut response = if let Some(denied) = foreign_peer(&only_path, peer) {
        denied
    } else if let Some(disturbed) = fault(&context, &only_path).await {
        disturbed
    } else if let Some(without_version) = missing_version(&context, &only_path, &header) {
        without_version
    } else {
        next.run(request).await
    };

    // Every answer carries the currently valid nonce of this origin. If the mock rotates it on
    // every answer, the new value has to **overwrite**: otherwise the client would get the
    // already-stale nonce in response to a nonce demand and would run into exactly the loop
    // §7.0.9 forbids.
    let nonce = if context.state.configuration.nonce_per_response {
        context.state.rotate_nonce(context.origin)
    } else {
        context.state.nonce(context.origin)
    };
    if let Ok(value) = axum::http::HeaderValue::from_str(&nonce) {
        response.headers_mut().insert(header::DPOP_NONCE, value);
    }

    // One ULID per request, so that a bug report out of development can be found again in the
    // mock's log (03 §6.0.4).
    if !response.headers().contains_key(header::X_REQUEST_ID)
        && let Ok(identifier) = edms_crypto::random::ulid(now())
        && let Ok(value) = axum::http::HeaderValue::from_str(&identifier)
    {
        response.headers_mut().insert(header::X_REQUEST_ID, value);
    }

    context.state.lock().recording.push(Recording {
        timestamp: now(),
        origin: context.origin,
        method,
        path,
        header,
        status: response.status().as_u16(),
    });
    response
}

/// `403` when the remote control is called from outside this machine.
fn foreign_peer(path: &str, peer: Option<SocketAddr>) -> Option<Response> {
    if !path.starts_with("/mock/") {
        return None;
    }
    match peer {
        Some(address) if address.ip().is_loopback() => None,
        _ => Some(catalogue(
            ErrorKind::Unknown,
            403,
            "The mock's remote control holds from 127.0.0.1 only.",
            path,
        )),
    }
}

/// Applies a configured fault if one matches this path.
async fn fault(context: &Context, path: &str) -> Option<Response> {
    let (status, delay) = {
        let mut inner = context.state.lock();
        let hit = inner.fault.iter_mut().find(|f| path.starts_with(&f.path))?;
        hit.times = hit.times.saturating_sub(1);
        let values = (hit.status, hit.delay_millis);
        inner.fault.retain(|f| f.times > 0);
        values
    };
    if delay > 0 {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
    }
    let status = status?;
    Some(match status {
        // `Retry-After` beats every local backoff (§7.0.3); without the header nobody would be
        // checking whether the client keeps to it.
        429 => {
            let mut response = golden_problem("problem_rate_limited.json", 429, path);
            for (name, value) in [
                (header::RETRY_AFTER, "1"),
                // `RateLimit-Policy` names the buckets (03 §6.0.11); without them a client does
                // not know what it is waiting for.
                (header::RATE_LIMIT_POLICY, "\"mock\";q=100;w=60"),
                (header::RATE_LIMIT, "\"mock\";r=0;t=1"),
            ] {
                if let (Ok(name), Ok(value)) = (
                    axum::http::HeaderName::try_from(name),
                    axum::http::HeaderValue::from_str(value),
                ) {
                    response.headers_mut().insert(name, value);
                }
            }
            response
        }
        503 => catalogue(
            ErrorKind::Unknown,
            503,
            "The mock disturbs on purpose: this service is not reachable right now.",
            path,
        ),
        other => catalogue(ErrorKind::Unknown, other, "The mock disturbs on purpose.", path),
    })
}

/// `400` when `Elasticdms-Version` is missing on `/v1/*` or is not the dated version.
///
/// A header that only goes along sometimes is forgotten exactly when the server starts to
/// evaluate it — and the mistake then shows up as an unexplainable `400` in a single call
/// (§7.0.1). Here it stands out on the first attempt.
///
/// `[GAP -> PROPOSAL]` 03 §6.0.1 leaves open whether the authorization server demands the header
/// (finding Q-6) and what follows on a **different** dated version. The mock demands it on every
/// `/v1/` path of both hosts and answers a foreign version with `426 client-version-too-old`.
/// Whoever does not want that for one experiment switches
/// [`crate::Configuration::requires_version`] off — the mock never gives way silently.
fn missing_version(context: &Context, path: &str, header: &[(String, String)]) -> Option<Response> {
    if !context.state.configuration.requires_version || !path.starts_with("/v1/") {
        return None;
    }
    let wanted = header::ELASTICDMS_VERSION.to_ascii_lowercase();
    match header.iter().find(|(name, _)| *name == wanted) {
        Some((_, value)) if value == API_VERSION => None,
        Some((_, value)) => Some(catalogue(
            ErrorKind::ClientTooOld,
            426,
            &format!(
                "This server speaks {API_VERSION}; the request names “{value}” \
                 ({}, 03 §6.0.1).",
                header::ELASTICDMS_VERSION
            ),
            path,
        )),
        None => Some(catalogue(
            ErrorKind::ValidationFailed,
            400,
            &format!(
                "The {} header is missing; it belongs on every request to both hosts (§7.0.1).",
                header::ELASTICDMS_VERSION
            ),
            path,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_peer_does_not_reach_the_remote_control() {
        let foreign = SocketAddr::from(([10, 0, 0, 7], 4711));
        let own = SocketAddr::from(([127, 0, 0, 1], 4711));
        assert!(foreign_peer("/mock/commands", Some(foreign)).is_some());
        assert!(foreign_peer("/mock/commands", Some(own)).is_none());
        assert!(foreign_peer("/mock/commands", None).is_some(), "without a peer: no");
        assert!(
            foreign_peer("/v1/mirror/archives", Some(foreign)).is_none(),
            "the contract holds for all"
        );
    }
}
