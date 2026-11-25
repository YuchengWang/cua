// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Localhost-only, token-gated CDP WebSocket forwarding proxy.
//!
//! Keeps a single upstream browser-level WebSocket (`CdpConnection`) open per
//! approved Chrome instance so external DevTools/MCP clients (such as
//! `chrome-devtools-mcp`) can connect, disconnect, and reconnect without
//! triggering duplicate "Allow remote debugging?" consent dialogs.
//!
//! Security boundaries:
//! - Binds strictly to `127.0.0.1:0` (IPv4 loopback only).
//! - Gates upgrades on a 256-bit cryptographic random path token checked in
//!   constant time, with no query parameters.
//! - Rejects any HTTP `Origin` header (prevents CSWSH) and non-loopback `Host`
//!   headers (prevents DNS rebinding).
//! - Never reveals upstream Chrome WebSocket URLs or user profile directories.
//! - Blocks `Browser.close`, `Browser.crash`, and `Browser.crashGpuProcess` on
//!   `ExistingProfile` sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;

use super::cdp_ws::{CdpConnection, CdpMethodPolicy, CdpPool};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const PATH_PREFIX: &str = "/devtools/browser/";

type TouchCallback = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct ProxyKey {
    session: String,
    pid: i64,
}

#[derive(Clone)]
enum UpstreamSource {
    Connected(Arc<CdpConnection>),
    Lazy {
        pool: CdpPool,
        ws_url: String,
        conn: Arc<Mutex<Option<Arc<CdpConnection>>>>,
    },
}

impl UpstreamSource {
    async fn acquire(&self) -> Result<Arc<CdpConnection>, String> {
        match self {
            Self::Connected(conn) => {
                if conn.is_closed() {
                    Err("upstream browser socket closed".to_owned())
                } else {
                    Ok(conn.clone())
                }
            }
            Self::Lazy { pool, ws_url, conn } => {
                let mut guard = conn.lock().await;
                if let Some(existing) = guard.as_ref() {
                    if !existing.is_closed() {
                        return Ok(existing.clone());
                    }
                }
                let connected = pool.get(ws_url).await.map_err(|e| e.to_string())?;
                *guard = Some(connected.clone());
                Ok(connected)
            }
        }
    }

    fn connected_conn(&self) -> Option<&Arc<CdpConnection>> {
        match self {
            Self::Connected(conn) => Some(conn),
            Self::Lazy { .. } => None,
        }
    }
}

struct ProxyEntry {
    id: u64,
    pid: i64,
    owner_sessions: Vec<String>,
    ws_endpoint: String,
    upstream: UpstreamSource,
    shutdown_tx: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl ProxyEntry {
    fn is_live(&self) -> bool {
        if *self.shutdown_tx.borrow() || self.accept_task.is_finished() {
            return false;
        }
        if let Some(conn) = self.upstream.connected_conn() {
            if conn.is_closed() {
                return false;
            }
        }
        true
    }

    fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.accept_task.abort();
    }
}

impl Drop for ProxyEntry {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Default)]
struct ProxyState {
    next_id: AtomicU64,
    entries: StdMutex<HashMap<ProxyKey, Arc<ProxyEntry>>>,
}

impl Drop for ProxyState {
    fn drop(&mut self) {
        let entries = self.entries.get_mut().unwrap();
        for entry in entries.values() {
            entry.shutdown();
        }
        entries.clear();
    }
}

/// Manages local restricted CDP forwarding endpoints tied to browser engine
/// lifecycle (session end, grant revocation/expiration, isolated browser
/// cleanup, or upstream socket closure).
#[derive(Clone, Default)]
pub(crate) struct CdpProxyManager {
    state: Arc<ProxyState>,
}

impl CdpProxyManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensures a loopback proxy exists for an already-connected, consented
    /// `ExistingProfile` socket (`Arc<CdpConnection>`). Reuses the existing
    /// proxy endpoint if the same `(session, pid)` and live upstream socket
    /// are already active.
    pub async fn ensure_existing_profile_proxy(
        &self,
        session: &str,
        owner_sessions: Vec<String>,
        pid: i64,
        conn: Arc<CdpConnection>,
        on_activity: Option<TouchCallback>,
    ) -> anyhow::Result<String> {
        let key = ProxyKey {
            session: session.to_owned(),
            pid,
        };
        {
            let mut entries = self.state.entries.lock().unwrap();
            if let Some(existing) = entries.get(&key) {
                let same_conn = existing
                    .upstream
                    .connected_conn()
                    .is_some_and(|c| Arc::ptr_eq(c, &conn));
                if existing.is_live() && same_conn {
                    return Ok(existing.ws_endpoint.clone());
                }
                existing.shutdown();
                entries.remove(&key);
            }
        }
        self.spawn_entry(
            key,
            owner_sessions,
            UpstreamSource::Connected(conn),
            on_activity,
        )
        .await
    }

    /// Ensures a loopback proxy exists for a driver-owned isolated Chromium
    /// process. Upstream dialing happens lazily on first downstream client
    /// connection so mock/stubbed launches never trigger spurious early dials.
    pub async fn ensure_isolated_proxy(
        &self,
        session: &str,
        owner_sessions: Vec<String>,
        pid: i64,
        pool: CdpPool,
        upstream_ws_url: String,
        on_activity: Option<TouchCallback>,
    ) -> anyhow::Result<String> {
        let key = ProxyKey {
            session: session.to_owned(),
            pid,
        };
        {
            let mut entries = self.state.entries.lock().unwrap();
            if let Some(existing) = entries.get(&key) {
                let same_url = matches!(
                    &existing.upstream,
                    UpstreamSource::Lazy { ws_url, .. } if ws_url == &upstream_ws_url
                );
                if existing.is_live() && same_url {
                    return Ok(existing.ws_endpoint.clone());
                }
                existing.shutdown();
                entries.remove(&key);
            }
        }
        self.spawn_entry(
            key,
            owner_sessions,
            UpstreamSource::Lazy {
                pool,
                ws_url: upstream_ws_url,
                conn: Arc::new(Mutex::new(None)),
            },
            on_activity,
        )
        .await
    }

    async fn spawn_entry(
        &self,
        key: ProxyKey,
        mut owner_sessions: Vec<String>,
        upstream: UpstreamSource,
        on_activity: Option<TouchCallback>,
    ) -> anyhow::Result<String> {
        if !owner_sessions.contains(&key.session) {
            owner_sessions.push(key.session.clone());
        }
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let token = generate_proxy_token()?;
        let expected_path = format!("{PATH_PREFIX}{token}");
        let ws_endpoint = format!("ws://127.0.0.1:{}{expected_path}", local_addr.port());
        let expected_port = local_addr.port();

        let id = self.state.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let active_clients = Arc::new(AtomicUsize::new(0));
        let upstream_close_rx = upstream
            .connected_conn()
            .map(|conn| conn.subscribe_close());

        let state_weak = Arc::downgrade(&self.state);
        let entry_key = key.clone();
        let entry_upstream = upstream.clone();
        let accept_shutdown_tx = shutdown_tx.clone();
        let accept_task = tokio::spawn(run_accept_loop(AcceptLoopConfig {
            id,
            key: entry_key,
            listener,
            expected_path,
            expected_port,
            upstream: entry_upstream,
            owner_sessions: owner_sessions.clone(),
            on_activity,
            active_clients,
            shutdown_tx: accept_shutdown_tx,
            shutdown_rx,
            upstream_close_rx,
            state_weak,
        }));

        let entry = Arc::new(ProxyEntry {
            id,
            pid: key.pid,
            owner_sessions,
            ws_endpoint: ws_endpoint.clone(),
            upstream,
            shutdown_tx,
            accept_task,
        });

        let mut entries = self.state.entries.lock().unwrap();
        if let Some(prev) = entries.insert(key, entry) {
            prev.shutdown();
        }
        Ok(ws_endpoint)
    }

    pub fn remove_session(&self, session: &str) {
        let mut entries = self.state.entries.lock().unwrap();
        entries.retain(|_, entry| {
            let owned = entry.owner_sessions.iter().any(|s| s == session);
            if owned {
                entry.shutdown();
            }
            !owned
        });
    }

    pub fn remove_pid(&self, pid: i64) {
        let mut entries = self.state.entries.lock().unwrap();
        entries.retain(|_, entry| {
            if entry.pid == pid {
                entry.shutdown();
                false
            } else {
                true
            }
        });
    }

    pub fn remove_for_session_and_pid(&self, session: &str, pid: i64) {
        let mut entries = self.state.entries.lock().unwrap();
        entries.retain(|_, entry| {
            let matches = entry.pid == pid && entry.owner_sessions.iter().any(|s| s == session);
            if matches {
                entry.shutdown();
            }
            !matches
        });
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.state.entries.lock().unwrap().len()
    }
}

struct AcceptLoopConfig {
    id: u64,
    key: ProxyKey,
    listener: TcpListener,
    expected_path: String,
    expected_port: u16,
    upstream: UpstreamSource,
    owner_sessions: Vec<String>,
    on_activity: Option<TouchCallback>,
    active_clients: Arc<AtomicUsize>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    upstream_close_rx: Option<watch::Receiver<bool>>,
    state_weak: Weak<ProxyState>,
}

async fn run_accept_loop(mut cfg: AcceptLoopConfig) {
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            changed = cfg.shutdown_rx.changed() => {
                if changed.is_err() || *cfg.shutdown_rx.borrow() {
                    break;
                }
            }
            closed = async {
                match cfg.upstream_close_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if closed.is_err() || cfg.upstream_close_rx.as_ref().is_some_and(|rx| *rx.borrow()) {
                    let _ = cfg.shutdown_tx.send(true);
                    break;
                }
            }
            _ = keepalive.tick() => {
                if cfg.active_clients.load(Ordering::Relaxed) > 0 {
                    touch_owners(&cfg.owner_sessions, cfg.on_activity.as_ref());
                }
            }
            accepted = cfg.listener.accept() => {
                let Ok((stream, peer_addr)) = accepted else {
                    break;
                };
                if !peer_addr.ip().is_loopback() {
                    continue;
                }
                let expected_path = cfg.expected_path.clone();
                let expected_port = cfg.expected_port;
                let upstream = cfg.upstream.clone();
                let owner_sessions = cfg.owner_sessions.clone();
                let on_activity = cfg.on_activity.clone();
                let active_clients = cfg.active_clients.clone();
                let shutdown_rx = cfg.shutdown_rx.clone();
                tokio::spawn(handle_proxy_client(
                    stream,
                    peer_addr,
                    expected_path,
                    expected_port,
                    upstream,
                    owner_sessions,
                    on_activity,
                    active_clients,
                    shutdown_rx,
                ));
            }
        }
    }

    if let Some(state) = cfg.state_weak.upgrade() {
        let mut entries = state.entries.lock().unwrap();
        if entries.get(&cfg.key).is_some_and(|e| e.id == cfg.id) {
            entries.remove(&cfg.key);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_proxy_client(
    stream: TcpStream,
    peer_addr: SocketAddr,
    expected_path: String,
    expected_port: u16,
    upstream: UpstreamSource,
    owner_sessions: Vec<String>,
    on_activity: Option<TouchCallback>,
    active_clients: Arc<AtomicUsize>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if !peer_addr.ip().is_loopback() || *shutdown_rx.borrow() {
        return;
    }

    let ws_stream = match tokio_tungstenite::accept_hdr_async(
        stream,
        |req: &Request, response: Response| validate_upgrade_request(req, response, &expected_path, expected_port),
    )
    .await
    {
        Ok(ws) => ws,
        Err(_) => return,
    };

    let Ok(conn) = upstream.acquire().await else {
        return;
    };
    let Ok((client_id, mut from_upstream_rx)) = conn.register_proxy_client() else {
        return;
    };

    active_clients.fetch_add(1, Ordering::Relaxed);
    touch_owners(&owner_sessions, on_activity.as_ref());

    let (mut ws_write, mut ws_read) = ws_stream.split();
    let mut upstream_close_rx = conn.subscribe_close();

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = ws_write.send(Message::Close(None)).await;
                    break;
                }
            }
            closed = upstream_close_rx.changed() => {
                if closed.is_err() || *upstream_close_rx.borrow() {
                    let _ = ws_write.send(Message::Close(None)).await;
                    break;
                }
            }
            frame = from_upstream_rx.recv() => {
                let Some(text) = frame else {
                    let _ = ws_write.send(Message::Close(None)).await;
                    break;
                };
                if ws_write.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
            incoming = ws_read.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let keep_going = process_downstream_text(
                            &text,
                            client_id,
                            &conn,
                            &mut ws_write,
                        ).await;
                        touch_owners(&owner_sessions, on_activity.as_ref());
                        if !keep_going {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(Message::Binary(_))) | Some(Ok(Message::Frame(_))) => break,
                }
            }
        }
    }

    active_clients.fetch_sub(1, Ordering::Relaxed);
    conn.unregister_proxy_client(client_id).await;
    touch_owners(&owner_sessions, on_activity.as_ref());
}

async fn process_downstream_text<S>(
    text: &str,
    client_id: u64,
    conn: &Arc<CdpConnection>,
    ws_write: &mut S,
) -> bool
where
    S: futures_util::Sink<Message> + Unpin,
{
    let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(text) else {
        return true;
    };
    let Some(id) = obj.get("id").cloned().filter(|v| !v.is_null()) else {
        return true;
    };
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        let reply = json!({
            "id": id,
            "error": { "code": -32600, "message": "Invalid CDP request: missing method" }
        })
        .to_string();
        return ws_write.send(Message::Text(reply)).await.is_ok();
    };

    if conn.method_policy() == CdpMethodPolicy::ExistingProfile
        && matches!(
            method,
            "Browser.close" | "Browser.crash" | "Browser.crashGpuProcess"
        )
    {
        let reply = json!({
            "id": id,
            "error": {
                "code": -32000,
                "message": format!("{method} is blocked on existing-profile CDP proxy; disconnect instead")
            }
        })
        .to_string();
        return ws_write.send(Message::Text(reply)).await.is_ok();
    }

    if let Err(err) = conn.forward_proxy_request(client_id, obj).await {
        let reply = json!({
            "id": id,
            "error": { "code": -32000, "message": err }
        })
        .to_string();
        if ws_write.send(Message::Text(reply)).await.is_err() {
            return false;
        }
        return !conn.is_closed();
    }
    true
}

fn validate_upgrade_request(
    req: &Request,
    response: Response,
    expected_path: &str,
    expected_port: u16,
) -> Result<Response, ErrorResponse> {
    if req.method() != tokio_tungstenite::tungstenite::http::Method::GET {
        return Err(error_response(StatusCode::METHOD_NOT_ALLOWED));
    }
    if req.headers().contains_key(tokio_tungstenite::tungstenite::http::header::ORIGIN) {
        return Err(error_response(StatusCode::FORBIDDEN));
    }
    if let Some(host_val) = req.headers().get(tokio_tungstenite::tungstenite::http::header::HOST) {
        let Ok(host) = host_val.to_str() else {
            return Err(error_response(StatusCode::FORBIDDEN));
        };
        let expected_host_with_port = format!("127.0.0.1:{expected_port}");
        if host != "127.0.0.1" && host != expected_host_with_port {
            return Err(error_response(StatusCode::FORBIDDEN));
        }
    }
    if req.uri().query().is_some() {
        return Err(error_response(StatusCode::NOT_FOUND));
    }
    if !constant_time_eq(req.uri().path().as_bytes(), expected_path.as_bytes()) {
        return Err(error_response(StatusCode::NOT_FOUND));
    }
    Ok(response)
}

fn error_response(status: StatusCode) -> ErrorResponse {
    tokio_tungstenite::tungstenite::http::Response::builder()
        .status(status)
        .body(None)
        .unwrap()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_proxy_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|err| anyhow::anyhow!("failed to generate token: {err}"))?;
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Ok(hex)
}

fn touch_owners(owner_sessions: &[String], on_activity: Option<&TouchCallback>) {
    for session in owner_sessions {
        crate::session::touch_session_activity(session);
    }
    if let Some(cb) = on_activity {
        cb();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::cdp_ws::CdpPool;
    use crate::browser::mock_cdp::{MockCdpServer, MockEvent, MockReply};
    use std::sync::Arc as StdArc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    #[tokio::test]
    async fn security_rejects_wrong_token_query_origin_and_non_loopback_host() {
        let server = MockCdpServer::start(StdArc::new(|_| MockReply::ok(json!({})))).await;
        let conn = Arc::new(CdpConnection::connect(&server.ws_url()).await.unwrap());
        let mgr = CdpProxyManager::new();
        let ws_endpoint = mgr
            .ensure_existing_profile_proxy("s1", vec!["s1".to_owned()], 101, conn, None)
            .await
            .unwrap();

        assert!(ws_endpoint.starts_with("ws://127.0.0.1:"));
        let parsed = url::Url::parse(&ws_endpoint).unwrap();
        let port = parsed.port().unwrap();
        assert_eq!(parsed.host_str(), Some("127.0.0.1"));
        assert!(parsed.path().starts_with(PATH_PREFIX));
        assert_eq!(parsed.path().len(), PATH_PREFIX.len() + 64);

        // Wrong token rejected.
        let bad_token = format!("ws://127.0.0.1:{port}{PATH_PREFIX}{}", "a".repeat(64));
        assert!(tokio_tungstenite::connect_async(&bad_token).await.is_err());

        // Query string rejected.
        let with_query = format!("{ws_endpoint}?token=extra");
        assert!(tokio_tungstenite::connect_async(&with_query).await.is_err());

        // Browser Origin header (CSWSH) rejected.
        let mut with_origin = ws_endpoint.as_str().into_client_request().unwrap();
        with_origin
            .headers_mut()
            .insert("Origin", "https://evil.example".parse().unwrap());
        assert!(tokio_tungstenite::connect_async(with_origin).await.is_err());

        // Non-loopback Host header (DNS rebinding) rejected.
        let mut bad_host = ws_endpoint.as_str().into_client_request().unwrap();
        bad_host
            .headers_mut()
            .insert("Host", "evil.example:9222".parse().unwrap());
        assert!(tokio_tungstenite::connect_async(bad_host).await.is_err());

        // Valid request connects cleanly.
        let (ws, _) = tokio_tungstenite::connect_async(&ws_endpoint).await.unwrap();
        drop(ws);
    }

    #[tokio::test]
    async fn existing_profile_proxy_reuses_single_upstream_across_reconnects_and_blocks_browser_close() {
        let seen_methods = StdArc::new(StdMutex::new(Vec::<String>::new()));
        let rec = seen_methods.clone();
        let server = MockCdpServer::start(StdArc::new(move |call| {
            rec.lock().unwrap().push(call.method.clone());
            match call.method.as_str() {
                "Browser.getVersion" => MockReply::ok(json!({ "product": "Chrome/135.0" })),
                "Target.setAutoAttach" => {
                    if call.params.get("autoAttach") == Some(&Value::Bool(true)) {
                        MockReply::ok(json!({})).with_events(vec![MockEvent {
                            method: "Target.attachedToTarget".to_owned(),
                            params: json!({ "sessionId": "child-1", "targetInfo": { "targetId": "t1" } }),
                            session_id: None,
                        }])
                    } else {
                        MockReply::ok(json!({}))
                    }
                }
                _ => MockReply::ok(json!({})),
            }
        }))
        .await;

        let conn = Arc::new(CdpConnection::connect(&server.ws_url()).await.unwrap());
        conn.restrict_to_existing_profile();
        assert_eq!(server.accepted_connections(), 1);

        let mgr = CdpProxyManager::new();
        let ws_endpoint_1 = mgr
            .ensure_existing_profile_proxy("s1", vec!["s1".to_owned()], 202, conn.clone(), None)
            .await
            .unwrap();
        let ws_endpoint_2 = mgr
            .ensure_existing_profile_proxy("s1", vec!["s1".to_owned()], 202, conn.clone(), None)
            .await
            .unwrap();
        assert_eq!(ws_endpoint_1, ws_endpoint_2, "same session+pid+conn reuses proxy endpoint");

        // First client connects, sets autoAttach, attempts Browser.close, then disconnects.
        {
            let (mut ws, _) = tokio_tungstenite::connect_async(&ws_endpoint_1).await.unwrap();
            ws.send(Message::Text(
                json!({ "id": 1, "method": "Browser.close" }).to_string(),
            ))
            .await
            .unwrap();
            let close_reply: Value =
                serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap();
            assert_eq!(close_reply["id"], 1);
            assert!(close_reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("blocked"));

            ws.send(Message::Text(
                json!({
                    "id": 2,
                    "method": "Target.setAutoAttach",
                    "params": { "autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true }
                })
                .to_string(),
            ))
            .await
            .unwrap();
            let ev: Value =
                serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap();
            assert_eq!(ev["method"], "Target.attachedToTarget");
            let rep: Value =
                serde_json::from_str(&ws.next().await.unwrap().unwrap().into_text().unwrap())
                    .unwrap();
            assert_eq!(rep["id"], 2);
            let _ = ws.close(None).await;
        }

        // Wait briefly for disconnect cleanup to dispatch upstream.
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let methods = seen_methods.lock().unwrap();
            assert!(!methods.iter().any(|m| m == "Browser.close"));
            assert!(methods.iter().any(|m| m == "Target.detachFromTarget"));
        }

        // Second client reconnects to the SAME proxy URL without opening a second upstream WS.
        let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_endpoint_1).await.unwrap();
        ws2.send(Message::Text(
            json!({ "id": 10, "method": "Browser.getVersion" }).to_string(),
        ))
        .await
        .unwrap();
        let ver_reply: Value =
            serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        assert_eq!(ver_reply["id"], 10);
        assert_eq!(ver_reply["result"]["product"], "Chrome/135.0");
        assert_eq!(server.accepted_connections(), 1, "still only ONE upstream Chrome WS handshake");

        // Removing session shuts down proxy and closes downstream WS.
        mgr.remove_session("s1");
        assert_eq!(mgr.active_count(), 0);
        let closed_or_eof = tokio::time::timeout(Duration::from_secs(1), ws2.next()).await;
        assert!(closed_or_eof.is_ok());
    }

    #[tokio::test]
    async fn isolated_proxy_dials_lazily_and_reuses_single_connection() {
        let server = MockCdpServer::start(StdArc::new(|call| match call.method.as_str() {
            "Browser.getVersion" => MockReply::ok(json!({ "product": "Isolated/135.0" })),
            _ => MockReply::ok(json!({})),
        }))
        .await;

        let pool = CdpPool::new();
        let mgr = CdpProxyManager::new();
        let ws_endpoint = mgr
            .ensure_isolated_proxy(
                "s-iso",
                vec!["s-iso".to_owned()],
                303,
                pool,
                server.ws_url(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(server.accepted_connections(), 0, "must not dial upstream until first client attaches");

        let (mut ws1, _) = tokio_tungstenite::connect_async(&ws_endpoint).await.unwrap();
        ws1.send(Message::Text(
            json!({ "id": 1, "method": "Browser.getVersion" }).to_string(),
        ))
        .await
        .unwrap();
        let rep1: Value =
            serde_json::from_str(&ws1.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        assert_eq!(rep1["result"]["product"], "Isolated/135.0");
        assert_eq!(server.accepted_connections(), 1);
        drop(ws1);

        let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_endpoint).await.unwrap();
        ws2.send(Message::Text(
            json!({ "id": 2, "method": "Browser.getVersion" }).to_string(),
        ))
        .await
        .unwrap();
        let rep2: Value =
            serde_json::from_str(&ws2.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        assert_eq!(rep2["id"], 2);
        assert_eq!(server.accepted_connections(), 1);
    }
}
