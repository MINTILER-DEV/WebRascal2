# Rust + WASM Scramjet-Style Browser Proxy

This repository implements a browser-first web proxy architecture with:

- A minimal Rust server (`crates/server`) that fetches upstream resources.
- A Rust/WASM client runtime (`crates/client-wasm`) for service worker interception and runtime API shims.
- A shared URL codec/rewriter core (`crates/proxy-core`).

## Run

1. Build client WASM package:

```powershell
./scripts/build-wasm.ps1
```

2. Run the server:

```powershell
cargo run -p proxy-server
```

3. Open `http://127.0.0.1:8080`.

## Architecture

### 1) Server component responsibilities

- Accept proxied requests at `/proxy/:encoded`.
- Decode target URLs (base64url) and fetch upstream resources.
- Maintain per-session, per-origin cookie jars in server memory.
  - Session id comes from `x-proxy-session` or `?__sid=...`.
  - Browser does not receive upstream `Set-Cookie`; cookies remain isolated server-side.
- Rewrite upstream response bodies:
  - `text/html`: rewrite URL-bearing attributes, rewrite embedded CSS URLs, inject runtime bootstrap scripts.
  - `text/css`: rewrite `url(...)` and `@import`.
  - JavaScript MIME types: rewrite URL-like string literals as a best-effort pass.
- Rewrite security/network headers:
  - Rebuild CSP to allow injected runtime via nonce and proxy connectivity.
  - Rewrite `Location` redirects through `/proxy/`.
  - Remove conflicting headers (`content-encoding`, `x-frame-options`, etc.) when needed.
- Handle CORS preflight (`OPTIONS`) at proxy endpoints.
- Bridge WebSocket traffic through `/ws/:encoded`.

### 2) Client-side service worker logic

`web/sw.js` boots `client-wasm` and calls `init_service_worker()`:

- Intercepts fetch events in scope.
- Rewrites direct cross-origin requests to `/proxy/:encoded`.
- Rewrites same-origin requests that originated from proxied documents by deriving the proxied base from `referrer`.
- Preserves session identity by attaching `x-proxy-session` and/or `?__sid=...`.
- Passes through local assets (`/`, `/sw.js`, `/boot.js`, `/pkg/*`, existing `/proxy/*`, `/ws/*`).

### 3) URL rewriting strategy

- Canonical proxy URL format: `/proxy/<base64url(absolute_target_url)>`.
- Server-side URL rewrite transforms absolute and relative links/resources in HTML/CSS/JS responses.
- Runtime shims rewrite dynamic API URLs at execution time (`fetch`, `XMLHttpRequest`, `iframe.src`, `WebSocket`).
- Redirect headers (`Location`) are rewritten server-side.

### 4) JavaScript sandboxing strategy

The injected runtime (initialized by WASM) monkey-patches high-risk browser APIs:

- `fetch`: rewrites URL and injects session header.
- `XMLHttpRequest.open`: rewrites URL.
- `WebSocket`: rewrites to same-origin `/ws/:encoded` tunnel.
- `HTMLIFrameElement.src`: rewrites navigations through `/proxy/`.

This is a compatibility sandbox, not a full JS VM isolation boundary.

### 5) Cookie and storage isolation approach

- Cookies:
  - Upstream cookies stored server-side in `CookieStore` keyed by `(session_id, target_origin)`.
  - Upstream `Set-Cookie` headers do not enter the browser cookie jar.
  - Outbound proxy fetches attach only cookies for that `(session, origin)` pair.
- Storage:
  - Runtime patches `Storage.prototype` methods and prefixes keys:
    - `__proxy:<sid>:<target_origin>:<key>`
  - This isolates `localStorage`/`sessionStorage` keys across sessions and upstream origins.

### 6) CSP and CORS handling

- CSP:
  - Server attempts minimal relaxation for script bootstrap and proxy networking (`script-src` nonce, `connect-src` updates).
  - `frame-ancestors` is stripped to avoid iframe embed failures in proxy UI.
  - Original CSP strictness is reduced when needed for compatibility.
- CORS:
  - Browser-side requests go same-origin (`/proxy/*`), avoiding most browser CORS failures.
  - Proxy responses include permissive CORS headers and preflight handling.
  - Upstream CORS remains relevant only for server-to-server behavior and rewritten script behavior.

### 7) Limitations and security tradeoffs

- Regex-based HTML/JS rewriting is best-effort and can miss edge cases.
- Monkey-patching runtime APIs is bypassable by advanced scripts.
- CSP relaxation weakens origin protections for compatibility.
- Cookie store is in-memory (not durable, not distributed, no eviction policy yet).
- WebSocket proxying is tunneled but does not yet implement advanced origin spoofing policies.
- Service Worker cannot intercept every browser primitive (e.g., all navigation edge cases, browser internals).
- This is a research/architecture baseline, not a hardened production anonymity/security proxy.

## Workspace layout

- `crates/proxy-core`: shared URL encoding/decoding + URL resolution helpers.
- `crates/server`: Axum proxy + fetcher + rewriters + cookie isolation + WS bridge.
- `crates/client-wasm`: WASM service worker logic + runtime shim bootstrap.
- `web/`: static entrypoint and JS loaders for WASM bootstrap.

