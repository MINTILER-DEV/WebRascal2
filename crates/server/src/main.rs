use axum::body::{to_bytes, Body};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_SECURITY_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, REFERER,
    SET_COOKIE, VARY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::routing::{any, get};
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use proxy_core::{decode_target, resolve_and_proxy};
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::{Captures, Regex};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio_tungstenite::connect_async;
use tower_http::services::ServeDir;
use url::form_urlencoded;
use url::Url;

type OriginCookies = HashMap<String, String>;
type SessionCookies = HashMap<String, OriginCookies>;

#[derive(Default)]
struct CookieStore {
    inner: RwLock<HashMap<String, SessionCookies>>,
}

impl CookieStore {
    fn cookie_header(&self, sid: &str, origin: &str) -> Option<String> {
        let guard = self.inner.read().ok()?;
        let by_origin = guard.get(sid)?;
        let cookies = by_origin.get(origin)?;
        if cookies.is_empty() {
            return None;
        }
        let joined = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        Some(joined)
    }

    fn store_set_cookie_headers(&self, sid: &str, origin: &str, headers: &HeaderMap) {
        let mut guard = match self.inner.write() {
            Ok(lock) => lock,
            Err(_) => return,
        };
        let by_origin = guard.entry(sid.to_string()).or_default();
        let jar = by_origin.entry(origin.to_string()).or_default();

        for header in headers.get_all(SET_COOKIE).iter() {
            let Ok(raw) = header.to_str() else {
                continue;
            };
            let pair = raw.split(';').next().unwrap_or_default().trim();
            if pair.is_empty() {
                continue;
            }
            let mut split = pair.splitn(2, '=');
            let Some(name) = split.next() else {
                continue;
            };
            let Some(value) = split.next() else {
                continue;
            };
            jar.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
}

#[derive(Clone)]
struct AppState {
    client: Client,
    cookies: Arc<CookieStore>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let state = Arc::new(AppState {
        client,
        cookies: Arc::new(CookieStore::default()),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/ws/:encoded", get(ws_proxy_handler))
        .route("/proxy/:encoded", any(proxy_handler))
        .with_state(state)
        .nest_service(
            "/",
            ServeDir::new("web").append_index_html_on_directories(true),
        );

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 8080)).await?;
    println!("proxy-server listening on http://127.0.0.1:8080");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_handler(
    Path(encoded): Path<String>,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let headers = parts.headers.clone();
    let uri = parts.uri.clone();

    if method == Method::OPTIONS {
        return Ok(preflight_response(&headers));
    }

    let body_bytes = to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let target = decode_target(&encoded).map_err(|_| StatusCode::BAD_REQUEST)?;
    let target_origin = origin_string(&target);
    let sid = session_id_from_request(&headers, &uri);

    let mut upstream_builder = state.client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
        target.as_str(),
    );
    upstream_builder = copy_request_headers(upstream_builder, &headers, &target_origin);
    if !body_bytes.is_empty() {
        upstream_builder = upstream_builder.body(body_bytes.to_vec());
    }
    if let Some(cookie_header) = state.cookies.cookie_header(&sid, &target_origin) {
        upstream_builder = upstream_builder.header(COOKIE.as_str(), cookie_header);
    }

    let upstream = upstream_builder
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = upstream.status();
    let upstream_headers = upstream.headers().clone();
    let mut output_headers = HeaderMap::new();

    state
        .cookies
        .store_set_cookie_headers(&sid, &target_origin, &upstream_headers);

    let content_type = upstream_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let upstream_body = upstream
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .to_vec();

    let (body_out, html_nonce) = if content_type.contains("text/html") {
        let raw = String::from_utf8_lossy(&upstream_body).to_string();
        let rewritten = rewrite_html(&raw, &target, &sid);
        (rewritten.0.into_bytes(), rewritten.1)
    } else if content_type.contains("text/css") {
        let raw = String::from_utf8_lossy(&upstream_body).to_string();
        (rewrite_css(&raw, &target).into_bytes(), None)
    } else if content_type.contains("javascript")
        || content_type.contains("ecmascript")
        || content_type.contains("application/x-javascript")
    {
        let raw = String::from_utf8_lossy(&upstream_body).to_string();
        (rewrite_javascript(&raw, &target).into_bytes(), None)
    } else {
        (upstream_body, None)
    };

    for (name, value) in &upstream_headers {
        if should_drop_response_header(name.as_str()) {
            continue;
        }
        output_headers.append(name.clone(), value.clone());
    }

    if let Some(value) = output_headers.get(CONTENT_SECURITY_POLICY).cloned() {
        if let Ok(csp) = value.to_str() {
            if let Some(nonce) = html_nonce.clone() {
                let rewritten = rewrite_csp(csp, &nonce);
                if let Ok(parsed) = HeaderValue::from_str(&rewritten) {
                    output_headers.insert(CONTENT_SECURITY_POLICY, parsed);
                }
            }
        }
    }
    output_headers.remove(CONTENT_SECURITY_POLICY_REPORT_ONLY);
    output_headers.remove(CONTENT_LENGTH);
    output_headers.remove(CONTENT_ENCODING);
    output_headers.remove(X_FRAME_OPTIONS);
    output_headers.remove(X_CONTENT_TYPE_OPTIONS);

    attach_cors_headers(&mut output_headers, &headers);

    if let Some(location) = upstream_headers.get(LOCATION).and_then(|v| v.to_str().ok()) {
        if let Some(proxy_location) = resolve_and_proxy(location, &target) {
            if let Ok(value) = HeaderValue::from_str(&proxy_location) {
                output_headers.insert(LOCATION, value);
            }
        }
    }

    let mut response = Response::builder()
        .status(status.as_u16())
        .body(Body::from(body_out))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    *response.headers_mut() = output_headers;

    Ok(response)
}

async fn ws_proxy_handler(
    ws: WebSocketUpgrade,
    Path(encoded): Path<String>,
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let target = decode_target(&encoded).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !matches!(target.scheme(), "ws" | "wss") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sid = session_id_from_request(req.headers(), req.uri());
    let origin_key = ws_origin_key(&target);
    let cookie_header = state.cookies.cookie_header(&sid, &origin_key);

    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(err) = bridge_websocket(socket, target, cookie_header).await {
            eprintln!("websocket bridge error: {err}");
        }
    }))
}

fn preflight_response(request_headers: &HeaderMap) -> Response<Body> {
    let mut headers = HeaderMap::new();
    attach_cors_headers(&mut headers, request_headers);
    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()));
    *response.headers_mut() = headers;
    response
}

fn copy_request_headers(
    mut builder: reqwest::RequestBuilder,
    headers: &HeaderMap,
    target_origin: &str,
) -> reqwest::RequestBuilder {
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "host"
                | "content-length"
                | "cookie"
                | "origin"
                | "referer"
                | "connection"
                | "x-proxy-session"
                | "accept-encoding"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.clone());
    }

    builder = builder.header(ORIGIN.as_str(), target_origin.to_string());
    builder.header(REFERER.as_str(), format!("{target_origin}/"))
}

fn rewrite_html(input: &str, base: &Url, sid: &str) -> (String, Option<String>) {
    let mut output = HTML_ATTR_RE
        .replace_all(input, |caps: &Captures| {
            let attr = caps.name("attr").map(|m| m.as_str()).unwrap_or_default();
            let quote = caps.name("quote").map(|m| m.as_str()).unwrap_or("\"");
            let raw_url = caps.name("url").map(|m| m.as_str()).unwrap_or_default();
            match resolve_and_proxy(raw_url, base) {
                Some(rewritten) => format!("{attr}{quote}{rewritten}{quote}"),
                None => caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }
        })
        .to_string();
    output = rewrite_css(&output, base);

    let nonce = random_nonce();
    let bootstrap = format!(
        r#"<script nonce="{nonce}">window.__PROXY_SESSION="{sid}";window.__PROXY_BASE="{base}";window.__PROXY_ORIGIN="{origin}";</script><script nonce="{nonce}" type="module" src="/boot.js"></script>"#,
        base = base.as_str(),
        origin = origin_string(base)
    );

    if HEAD_CLOSE_RE.is_match(&output) {
        output = HEAD_CLOSE_RE
            .replace(&output, format!("{bootstrap}</head>"))
            .to_string();
    } else {
        output = format!("{bootstrap}{output}");
    }
    (output, Some(nonce))
}

fn rewrite_css(input: &str, base: &Url) -> String {
    let with_url = CSS_URL_RE
        .replace_all(input, |caps: &Captures| {
            let quote = caps.name("quote").map(|m| m.as_str()).unwrap_or("");
            let raw_url = caps.name("url").map(|m| m.as_str()).unwrap_or_default();
            match resolve_and_proxy(raw_url, base) {
                Some(rewritten) => format!("url({quote}{rewritten}{quote})"),
                None => caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }
        })
        .to_string();

    CSS_IMPORT_RE
        .replace_all(&with_url, |caps: &Captures| {
            let quote = caps.name("quote").map(|m| m.as_str()).unwrap_or("\"");
            let raw_url = caps.name("url").map(|m| m.as_str()).unwrap_or_default();
            match resolve_and_proxy(raw_url, base) {
                Some(rewritten) => format!("@import {quote}{rewritten}{quote}"),
                None => caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }
        })
        .to_string()
}

fn rewrite_javascript(input: &str, base: &Url) -> String {
    JS_URL_LITERAL_RE
        .replace_all(input, |caps: &Captures| {
            let quote = caps.name("quote").map(|m| m.as_str()).unwrap_or("\"");
            let raw_url = caps.name("url").map(|m| m.as_str()).unwrap_or_default();
            match resolve_and_proxy(raw_url, base) {
                Some(rewritten) => format!("{quote}{rewritten}{quote}"),
                None => caps
                    .get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }
        })
        .to_string()
}

fn rewrite_csp(input: &str, nonce: &str) -> String {
    let mut directives = Vec::new();
    let mut has_script_src = false;
    let mut has_connect_src = false;

    for raw in input.split(';') {
        let directive = raw.trim();
        if directive.is_empty() {
            continue;
        }
        if directive.starts_with("frame-ancestors") {
            continue;
        }
        if directive.starts_with("script-src") {
            has_script_src = true;
            directives.push(format!(
                "{directive} 'self' 'unsafe-inline' 'unsafe-eval' blob: 'nonce-{nonce}'"
            ));
            continue;
        }
        if directive.starts_with("connect-src") {
            has_connect_src = true;
            directives.push(format!("{directive} 'self' https: wss:"));
            continue;
        }
        directives.push(directive.to_string());
    }

    if !has_script_src {
        directives.push(format!(
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: 'nonce-{nonce}'"
        ));
    }
    if !has_connect_src {
        directives.push("connect-src 'self' https: wss:".to_string());
    }
    directives.join("; ")
}

fn attach_cors_headers(headers: &mut HeaderMap, request_headers: &HeaderMap) {
    let origin = request_headers
        .get(ORIGIN)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("*"));
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*, x-proxy-session, content-type, authorization"),
    );
    headers.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("content-type, content-length, location"),
    );
    headers.insert(VARY, HeaderValue::from_static("Origin"));
}

fn origin_string(url: &Url) -> String {
    if let Some(port) = url.port() {
        format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().unwrap_or_default()
        )
    } else {
        format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default())
    }
}

fn session_id_from_request(headers: &HeaderMap, uri: &axum::http::Uri) -> String {
    headers
        .get("x-proxy-session")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.to_string())
        .or_else(|| sid_from_query(uri))
        .unwrap_or_else(random_nonce)
}

fn sid_from_query(uri: &axum::http::Uri) -> Option<String> {
    let query = uri.query()?;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        if key == "__sid" && !value.is_empty() {
            return Some(value.into_owned());
        }
    }
    None
}

async fn bridge_websocket(
    socket: WebSocket,
    target: Url,
    cookie_header: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut request = http::Request::builder().uri(target.as_str());
    if let Some(cookie) = cookie_header {
        request = request.header(COOKIE, cookie);
    }
    let request = request.body(())?;

    let (upstream, _) = connect_async(request).await?;
    let (mut client_tx, mut client_rx) = socket.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();

    let to_upstream = async {
        while let Some(msg) = client_rx.next().await {
            let Ok(msg) = msg else {
                break;
            };
            let translated = match msg {
                Message::Text(text) => tokio_tungstenite::tungstenite::Message::Text(text),
                Message::Binary(data) => tokio_tungstenite::tungstenite::Message::Binary(data),
                Message::Ping(data) => tokio_tungstenite::tungstenite::Message::Ping(data),
                Message::Pong(data) => tokio_tungstenite::tungstenite::Message::Pong(data),
                Message::Close(frame) => {
                    let close = frame.map(|close| {
                        let code_u16: u16 = close.code.into();
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::from(code_u16),
                            reason: close.reason,
                        }
                    });
                    tokio_tungstenite::tungstenite::Message::Close(close)
                }
            };
            if upstream_tx.send(translated).await.is_err() {
                break;
            }
        }
    };

    let to_client = async {
        while let Some(msg) = upstream_rx.next().await {
            let Ok(msg) = msg else {
                break;
            };
            let translated = match msg {
                tokio_tungstenite::tungstenite::Message::Text(text) => Message::Text(text),
                tokio_tungstenite::tungstenite::Message::Binary(data) => Message::Binary(data),
                tokio_tungstenite::tungstenite::Message::Ping(data) => Message::Ping(data),
                tokio_tungstenite::tungstenite::Message::Pong(data) => Message::Pong(data),
                tokio_tungstenite::tungstenite::Message::Close(frame) => {
                    let close = frame.map(|close| axum::extract::ws::CloseFrame {
                        code: close.code.into(),
                        reason: close.reason,
                    });
                    Message::Close(close)
                }
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };
            if client_tx.send(translated).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = to_upstream => {},
        _ = to_client => {},
    }
    Ok(())
}

fn ws_origin_key(url: &Url) -> String {
    let scheme = if url.scheme() == "wss" {
        "https"
    } else {
        "http"
    };
    if let Some(port) = url.port() {
        format!("{scheme}://{}:{port}", url.host_str().unwrap_or_default())
    } else {
        format!("{scheme}://{}", url.host_str().unwrap_or_default())
    }
}

fn random_nonce() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect::<String>()
}

fn should_drop_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length"
            | "content-encoding"
            | "transfer-encoding"
            | "connection"
            | "set-cookie"
            | "strict-transport-security"
            | "x-frame-options"
            | "x-content-type-options"
            | "cross-origin-opener-policy"
            | "cross-origin-embedder-policy"
            | "cross-origin-resource-policy"
    )
}

static HTML_ATTR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(?P<attr>\b(?:href|src|action|poster|data)\b\s*=\s*)(?P<quote>["'])(?P<url>[^"']+)(?P=quote)"#,
    )
    .expect("valid HTML attr regex")
});
static CSS_URL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"url\(\s*(?P<quote>["']?)(?P<url>[^"')]+)(?P=quote)\s*\)"#)
        .expect("valid CSS url regex")
});
static CSS_IMPORT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"@import\s+(?P<quote>["'])(?P<url>[^"']+)(?P=quote)"#)
        .expect("valid CSS import regex")
});
static JS_URL_LITERAL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?P<quote>["'])(?P<url>(?:https?://[^"']+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|\.\.?/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+))(?P=quote)"#)
        .expect("valid JS URL literal regex")
});
static HEAD_CLOSE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)</head>").expect("valid head close regex"));
