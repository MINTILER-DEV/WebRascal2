use proxy_core::{decode_proxy_path, encode_target, proxied_path_for_url, PROXY_PREFIX};
use std::cell::RefCell;
use url::Url;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{FetchEvent, MessageEvent, Request, RequestInit, ServiceWorkerGlobalScope, Window};

thread_local! {
    static SESSION_ID: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[wasm_bindgen]
pub fn init_client_runtime() -> Result<(), JsValue> {
    let window = web_sys::window().ok_or_else(|| JsValue::from_str("window unavailable"))?;
    let sid = get_or_create_session_id(&window)?;

    let base = current_proxy_base(&window).unwrap_or_else(|| {
        window
            .location()
            .href()
            .unwrap_or_else(|_| "http://invalid.local/".to_string())
    });
    let origin = Url::parse(&base)
        .ok()
        .map(|u| {
            if let Some(port) = u.port() {
                format!(
                    "{}://{}:{port}",
                    u.scheme(),
                    u.host_str().unwrap_or_default()
                )
            } else {
                format!("{}://{}", u.scheme(), u.host_str().unwrap_or_default())
            }
        })
        .unwrap_or_default();

    set_global_value("___proxySession", &sid)?;
    set_global_value("___proxyBase", &base)?;
    set_global_value("___proxyOrigin", &origin)?;
    notify_service_worker(&sid, &base, &origin)?;
    install_runtime_js_shims()?;
    Ok(())
}

#[wasm_bindgen]
pub fn init_service_worker() -> Result<(), JsValue> {
    let scope: ServiceWorkerGlobalScope = js_sys::global().dyn_into()?;

    let on_message = Closure::wrap(Box::new(move |event: MessageEvent| {
        let data = event.data();
        if !data.is_object() {
            return;
        }
        let sid = js_sys::Reflect::get(&data, &JsValue::from_str("sid"))
            .ok()
            .and_then(|v| v.as_string());
        if let Some(value) = sid {
            SESSION_ID.with(|cell| {
                *cell.borrow_mut() = Some(value);
            });
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    scope.add_event_listener_with_callback("message", on_message.as_ref().unchecked_ref())?;
    on_message.forget();

    let fetch_scope = scope.clone();
    let on_fetch = Closure::wrap(Box::new(move |event: FetchEvent| {
        let request = event.request();
        let replacement = rewrite_request_for_service_worker(&fetch_scope, &request);
        let promise = match replacement {
            Ok(Some(new_request)) => fetch_scope.fetch_with_request(&new_request),
            Ok(None) => fetch_scope.fetch_with_request(&request),
            Err(_) => fetch_scope.fetch_with_request(&request),
        };
        let _ = event.respond_with(&promise);
    }) as Box<dyn FnMut(FetchEvent)>);
    scope.add_event_listener_with_callback("fetch", on_fetch.as_ref().unchecked_ref())?;
    on_fetch.forget();
    Ok(())
}

#[wasm_bindgen]
pub fn proxy_encode(url: &str) -> String {
    encode_target(url)
        .map(|value| format!("{PROXY_PREFIX}{value}"))
        .unwrap_or_else(|_| url.to_string())
}

fn get_or_create_session_id(window: &Window) -> Result<String, JsValue> {
    let storage = window.session_storage()?;
    if let Some(storage) = storage {
        if let Ok(Some(existing)) = storage.get_item("__proxy_sid") {
            if !existing.trim().is_empty() {
                SESSION_ID.with(|cell| {
                    *cell.borrow_mut() = Some(existing.clone());
                });
                return Ok(existing);
            }
        }
        let sid = new_session_id();
        storage.set_item("__proxy_sid", &sid)?;
        SESSION_ID.with(|cell| {
            *cell.borrow_mut() = Some(sid.clone());
        });
        return Ok(sid);
    }
    let sid = new_session_id();
    SESSION_ID.with(|cell| {
        *cell.borrow_mut() = Some(sid.clone());
    });
    Ok(sid)
}

fn current_proxy_base(window: &Window) -> Option<String> {
    let path = window.location().pathname().ok()?;
    if !path.starts_with(PROXY_PREFIX) {
        return None;
    }
    let encoded = path.trim_start_matches(PROXY_PREFIX);
    decode_proxy_path(encoded).ok().map(|url| url.to_string())
}

fn new_session_id() -> String {
    format!(
        "{:x}{:x}{:x}",
        js_sys::Date::now() as u64,
        (js_sys::Math::random() * 1_000_000_000.0) as u64,
        (js_sys::Math::random() * 1_000_000_000.0) as u64
    )
}

fn set_global_value(name: &str, value: &str) -> Result<(), JsValue> {
    js_sys::Reflect::set(
        &js_sys::global(),
        &JsValue::from_str(name),
        &JsValue::from_str(value),
    )?;
    Ok(())
}

fn notify_service_worker(sid: &str, base: &str, origin: &str) -> Result<(), JsValue> {
    let Some(window) = web_sys::window() else {
        return Ok(());
    };
    let nav = window.navigator();
    let container = nav.service_worker();
    let controller = container.controller();
    let Some(controller) = controller else {
        return Ok(());
    };
    let msg = js_sys::Object::new();
    js_sys::Reflect::set(
        &msg,
        &JsValue::from_str("type"),
        &JsValue::from_str("proxy-meta"),
    )?;
    js_sys::Reflect::set(&msg, &JsValue::from_str("sid"), &JsValue::from_str(sid))?;
    js_sys::Reflect::set(&msg, &JsValue::from_str("base"), &JsValue::from_str(base))?;
    js_sys::Reflect::set(
        &msg,
        &JsValue::from_str("origin"),
        &JsValue::from_str(origin),
    )?;
    let _ = controller.post_message(&msg);
    Ok(())
}

fn install_runtime_js_shims() -> Result<(), JsValue> {
    let source = r#"
(() => {
  const PREFIX = "/proxy/";
  const sid = globalThis.___proxySession || "";
  const base = globalThis.___proxyBase || location.href;
  const origin = globalThis.___proxyOrigin || location.origin;

  const toBase64Url = (value) => {
    const bytes = new TextEncoder().encode(value);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };
  const toProxy = (input) => {
    try {
      const absolute = new URL(input, base);
      if (!/^https?:$/i.test(absolute.protocol)) return input;
      const proxied = `${PREFIX}${toBase64Url(absolute.toString())}`;
      return sid ? `${proxied}?__sid=${encodeURIComponent(sid)}` : proxied;
    } catch {
      return input;
    }
  };
  const toProxyWs = (input) => {
    try {
      const absolute = new URL(input, base);
      if (!(absolute.protocol === "ws:" || absolute.protocol === "wss:")) return input;
      const encoded = toBase64Url(absolute.toString());
      const suffix = sid ? `?__sid=${encodeURIComponent(sid)}` : "";
      return `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws/${encoded}${suffix}`;
    } catch {
      return input;
    }
  };

  const originalFetch = globalThis.fetch?.bind(globalThis);
  if (originalFetch) {
    globalThis.fetch = (input, init = {}) => {
      let nextInput = input;
      if (typeof input === "string") {
        nextInput = toProxy(input);
      } else if (input?.url) {
        nextInput = toProxy(input.url);
      }
      init.headers = new Headers(init.headers || {});
      if (sid) init.headers.set("x-proxy-session", sid);
      return originalFetch(nextInput, init);
    };
  }

  const XHR = globalThis.XMLHttpRequest;
  if (XHR?.prototype?.open) {
    const originalOpen = XHR.prototype.open;
    XHR.prototype.open = function(method, url, ...rest) {
      const rewritten = typeof url === "string" ? toProxy(url) : url;
      return originalOpen.call(this, method, rewritten, ...rest);
    };
    const originalSetRequestHeader = XHR.prototype.setRequestHeader;
    XHR.prototype.setRequestHeader = function(name, value) {
      originalSetRequestHeader.call(this, name, value);
      if (sid && name.toLowerCase() !== "x-proxy-session") {
        originalSetRequestHeader.call(this, "x-proxy-session", sid);
      }
    };
  }

  const NativeWS = globalThis.WebSocket;
  if (NativeWS) {
    globalThis.WebSocket = function(url, protocols) {
      return new NativeWS(toProxyWs(url), protocols);
    };
    globalThis.WebSocket.prototype = NativeWS.prototype;
  }

  const IFrameProto = globalThis.HTMLIFrameElement?.prototype;
  if (IFrameProto) {
    const desc = Object.getOwnPropertyDescriptor(IFrameProto, "src");
    if (desc?.set && desc?.get) {
      Object.defineProperty(IFrameProto, "src", {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
          desc.set.call(this, toProxy(String(value)));
        },
      });
    }
  }

  const keyPrefix = `__proxy:${sid}:${origin}:`;
  const StorageProto = globalThis.Storage?.prototype;
  if (StorageProto) {
    const rawGet = StorageProto.getItem;
    const rawSet = StorageProto.setItem;
    const rawRemove = StorageProto.removeItem;
    StorageProto.getItem = function(key) { return rawGet.call(this, keyPrefix + key); };
    StorageProto.setItem = function(key, value) { return rawSet.call(this, keyPrefix + key, value); };
    StorageProto.removeItem = function(key) { return rawRemove.call(this, keyPrefix + key); };
  }
})();
"#;

    let shim = js_sys::Function::new_no_args(source);
    let _ = shim.call0(&JsValue::NULL)?;
    Ok(())
}

fn rewrite_request_for_service_worker(
    scope: &ServiceWorkerGlobalScope,
    request: &Request,
) -> Result<Option<Request>, JsValue> {
    let method = request.method().to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return Ok(None);
    }

    let request_url = Url::parse(&request.url()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if !matches!(request_url.scheme(), "http" | "https") {
        return Ok(None);
    }

    let scope_origin = scope.location().origin();
    let same_origin = request_url.origin().ascii_serialization() == scope_origin;
    let target = if same_origin {
        if should_passthrough_local_path(request_url.path()) {
            return Ok(None);
        }
        let Some(base) = proxy_base_from_referrer(&request.referrer()) else {
            return Ok(None);
        };
        let mut rebuilt = Url::parse(&base).map_err(|e| JsValue::from_str(&e.to_string()))?;
        rebuilt.set_path(request_url.path());
        rebuilt.set_query(request_url.query());
        rebuilt.set_fragment(request_url.fragment());
        rebuilt
    } else {
        request_url
    };

    let mut proxied = proxied_path_for_url(&target);
    if let Some(sid) = current_session_id() {
        proxied.push_str("?__sid=");
        proxied.push_str(&encode_uri_component(&sid));
    }

    let headers = request.headers();
    if let Some(sid) = current_session_id() {
        let _ = headers.set("x-proxy-session", &sid);
    }

    let init = RequestInit::new();
    init.set_method(&method);
    init.set_headers(&headers);
    init.set_mode(request.mode());
    init.set_cache(request.cache());
    init.set_credentials(request.credentials());
    init.set_redirect(request.redirect());
    init.set_referrer(&request.referrer());
    let new_request = Request::new_with_str_and_init(&proxied, &init)?;
    Ok(Some(new_request))
}

fn current_session_id() -> Option<String> {
    SESSION_ID.with(|cell| cell.borrow().clone())
}

fn proxy_base_from_referrer(referrer: &str) -> Option<String> {
    if referrer.trim().is_empty() {
        return None;
    }
    let parsed = Url::parse(referrer).ok()?;
    let path = parsed.path();
    if !path.starts_with(PROXY_PREFIX) {
        return None;
    }
    let encoded = path.trim_start_matches(PROXY_PREFIX);
    let absolute = decode_proxy_path(encoded).ok()?;
    Some(absolute.to_string())
}

fn should_passthrough_local_path(path: &str) -> bool {
    path == "/"
        || path == "/index.html"
        || path == "/boot.js"
        || path == "/sw.js"
        || path == "/favicon.ico"
        || path.starts_with("/pkg/")
        || path.starts_with("/ws/")
        || path.starts_with(PROXY_PREFIX)
        || path == "/healthz"
}

fn encode_uri_component(value: &str) -> String {
    js_sys::encode_uri_component(value)
        .as_string()
        .unwrap_or_else(|| value.to_string())
}
