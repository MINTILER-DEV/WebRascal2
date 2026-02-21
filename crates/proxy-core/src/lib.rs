use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::fmt::{Display, Formatter};
use url::Url;

pub const PROXY_PREFIX: &str = "/proxy/";

#[derive(Debug)]
pub enum ProxyError {
    InvalidUrl(url::ParseError),
    InvalidEncoded(base64::DecodeError),
    InvalidUtf8(std::string::FromUtf8Error),
}

impl Display for ProxyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(err) => write!(f, "invalid URL: {err}"),
            Self::InvalidEncoded(err) => write!(f, "invalid encoded URL: {err}"),
            Self::InvalidUtf8(err) => write!(f, "invalid UTF-8 in encoded URL: {err}"),
        }
    }
}

impl std::error::Error for ProxyError {}

pub fn encode_target(raw: &str) -> Result<String, ProxyError> {
    let parsed = Url::parse(raw).map_err(ProxyError::InvalidUrl)?;
    let normalized = parsed.to_string();
    Ok(URL_SAFE_NO_PAD.encode(normalized.as_bytes()))
}

pub fn decode_target(encoded: &str) -> Result<Url, ProxyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(ProxyError::InvalidEncoded)?;
    let value = String::from_utf8(bytes).map_err(ProxyError::InvalidUtf8)?;
    Url::parse(&value).map_err(ProxyError::InvalidUrl)
}

pub fn proxied_path_for_url(url: &Url) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(url.as_str().as_bytes());
    format!("{PROXY_PREFIX}{encoded}")
}

pub fn decode_proxy_path(path: &str) -> Result<Url, ProxyError> {
    let encoded = path.strip_prefix(PROXY_PREFIX).unwrap_or(path);
    decode_target(encoded)
}

pub fn resolve_and_proxy(raw: &str, base: &Url) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    if is_ignored_scheme(raw) || raw.starts_with('#') {
        return None;
    }

    let absolute = match Url::parse(raw) {
        Ok(parsed) => parsed,
        Err(url::ParseError::RelativeUrlWithoutBase) => base.join(raw).ok()?,
        Err(_) => return None,
    };
    if !matches!(absolute.scheme(), "http" | "https") {
        return None;
    }
    Some(proxied_path_for_url(&absolute))
}

fn is_ignored_scheme(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("mailto:")
        || lower.starts_with("tel:")
        || lower.starts_with("about:")
        || lower.starts_with("blob:")
}
