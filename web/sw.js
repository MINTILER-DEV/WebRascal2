import init, { proxy_encode } from "/pkg/client_wasm.js";

let wasmReady = false;
let sid = "";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Must be registered during initial worker evaluation.
self.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data && data.type === "proxy-meta" && typeof data.sid === "string" && data.sid) {
    sid = data.sid;
  }
});

// Must be registered during initial worker evaluation.
self.addEventListener("fetch", (event) => {
  event.respondWith(handleFetch(event));
});

init()
  .then(() => {
    wasmReady = true;
  })
  .catch((err) => {
    console.error("service worker wasm bootstrap failed", err);
  });

async function handleFetch(event) {
  const request = event.request;
  const rewritten = rewriteRequest(request);
  return fetch(rewritten ?? request);
}

function rewriteRequest(request) {
  const requestUrl = new URL(request.url);
  if (requestUrl.protocol !== "http:" && requestUrl.protocol !== "https:") return null;

  const scopeOrigin = new URL(self.registration.scope).origin;
  const sameOrigin = requestUrl.origin === scopeOrigin;

  let proxiedPath = null;
  if (sameOrigin) {
    if (shouldPassThrough(requestUrl.pathname)) return null;

    if (requestUrl.pathname.startsWith("/proxy/")) {
      const decoded = decodeProxiedTarget(requestUrl.pathname);
      if (decoded) {
        proxiedPath = `${requestUrl.pathname}${requestUrl.search}${requestUrl.hash}`;
      } else {
        const base = targetFromReferrer(request.referrer);
        if (!base) return null;
        const relative = requestUrl.pathname.slice("/proxy/".length);
        const target = new URL(`${relative}${requestUrl.search}${requestUrl.hash}`, base);
        proxiedPath = encodeProxyPath(target.toString());
      }
    } else if (requestUrl.pathname.startsWith("/ws/")) {
      proxiedPath = `${requestUrl.pathname}${requestUrl.search}${requestUrl.hash}`;
    } else {
      const base = targetFromReferrer(request.referrer);
      if (!base) return null;
      const target = new URL(`${requestUrl.pathname}${requestUrl.search}${requestUrl.hash}`, base);
      proxiedPath = encodeProxyPath(target.toString());
    }
  } else {
    proxiedPath = encodeProxyPath(requestUrl.toString());
  }

  if (sid) {
    proxiedPath = withSid(proxiedPath, sid);
  }

  let proxiedRequest = new Request(proxiedPath, request);
  if (sid) {
    const headers = new Headers(proxiedRequest.headers);
    headers.set("x-proxy-session", sid);
    proxiedRequest = new Request(proxiedRequest, { headers });
  }
  return proxiedRequest;
}

function targetFromReferrer(referrer) {
  if (!referrer) return null;
  try {
    const parsed = new URL(referrer);
    if (!parsed.pathname.startsWith("/proxy/")) return null;
    const encoded = parsed.pathname.slice("/proxy/".length);
    const target = decodeBase64Url(encoded);
    return new URL(target).toString();
  } catch {
    return null;
  }
}

function encodeProxyPath(url) {
  if (wasmReady) {
    return proxy_encode(url);
  }
  return `/proxy/${encodeBase64Url(url)}`;
}

function shouldPassThrough(pathname) {
  return (
    pathname === "/" ||
    pathname === "/index.html" ||
    pathname === "/sw.js" ||
    pathname === "/boot.js" ||
    pathname === "/favicon.ico" ||
    pathname === "/healthz" ||
    pathname.startsWith("/pkg/") ||
    pathname.startsWith("/ws/")
  );
}

function decodeProxiedTarget(pathname) {
  if (!pathname.startsWith("/proxy/")) return null;
  const encoded = pathname.slice("/proxy/".length);
  if (!encoded) return null;
  try {
    const decoded = decodeBase64Url(encoded);
    const parsed = new URL(decoded);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed;
  } catch {
    return null;
  }
}

function withSid(path, sessionId) {
  const parsed = new URL(path, self.registration.scope);
  parsed.searchParams.set("__sid", sessionId);
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

function encodeBase64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  const binary = atob(normalized + padding);
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
