//! Outbound HTTP guardrails for AI and evidence integrations.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use reqwest::Url;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use url::Host;

use crate::{CoreError, CoreResult};

const ALLOWED_HEADERS: &[&str] = &[
    "content-type",
    "authorization",
    "api-key",
    "x-api-key",
    "anthropic-version",
    "anthropic-beta",
    "accept",
];

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => (address.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => *address == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(address) => *address == Ipv6Addr::UNSPECIFIED,
    }
}

/// Parse an HTTP endpoint and reject credential injection, unspecified hosts,
/// link-local addresses, and cloud metadata literals.
///
/// Loopback and RFC1918 hosts remain valid for offline Ollama/intranet use.
pub fn validate_outbound_url(raw: &str) -> CoreResult<Url> {
    let parsed = raw
        .parse::<Url>()
        .map_err(|error| CoreError::validation("outbound URL", error.to_string()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(CoreError::validation(
            "outbound URL",
            format!("only http/https are allowed, got {}", parsed.scheme()),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CoreError::validation(
            "outbound URL",
            "embedded usernames and passwords are forbidden",
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| CoreError::validation("outbound URL", "host is required"))?;
    let literal_ip = match host {
        Host::Ipv4(address) => Some(IpAddr::V4(address)),
        Host::Ipv6(address) => Some(IpAddr::V6(address)),
        Host::Domain(_) => None,
    };
    if let Some(ip) = literal_ip {
        if is_unspecified(&ip) {
            return Err(CoreError::validation(
                "outbound URL",
                format!("unspecified address {ip} is forbidden"),
            ));
        }
        if is_link_local(&ip) {
            return Err(CoreError::validation(
                "outbound URL",
                format!("link-local address {ip} is forbidden"),
            ));
        }
    }
    Ok(parsed)
}

/// Retain only provider headers. Invalid names/values are reported as dropped.
pub fn filter_headers(headers: &HashMap<String, String>) -> (Vec<(String, String)>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        let valid_wire_value = reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_ok()
            && reqwest::header::HeaderValue::from_str(value).is_ok();
        if ALLOWED_HEADERS.contains(&lower.as_str()) && valid_wire_value {
            kept.push((name.clone(), value.clone()));
        } else {
            dropped.push(name.clone());
        }
    }
    (kept, dropped)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    Http,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettings {
    pub proxy_type: ProxyType,
    pub proxy_url: String,
}

impl ProxySettings {
    fn cache_key(&self) -> String {
        format!("{:?}|{}", self.proxy_type, self.proxy_url)
    }

    pub fn validate(&self) -> CoreResult<()> {
        build_proxy(self).map(|_| ())
    }
}

fn build_proxy(settings: &ProxySettings) -> CoreResult<reqwest::Proxy> {
    let parsed = Url::parse(&settings.proxy_url)
        .map_err(|error| CoreError::validation("proxy URL", error.to_string()))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CoreError::validation(
            "proxy URL",
            "embedded proxy credentials are forbidden; secret-bearing proxy auth is not yet supported",
        ));
    }
    let scheme_matches = match settings.proxy_type {
        ProxyType::Http => matches!(parsed.scheme(), "http" | "https"),
        ProxyType::Socks5 => parsed.scheme() == "socks5",
    };
    if !scheme_matches {
        return Err(CoreError::validation(
            "proxy URL",
            format!(
                "scheme {} does not match proxy type {:?}",
                parsed.scheme(),
                settings.proxy_type
            ),
        ));
    }
    reqwest::Proxy::all(settings.proxy_url.as_str())
        .map_err(|error| CoreError::validation("proxy URL", error.to_string()))
}

fn proxied_client(
    settings: &ProxySettings,
    cache: &Mutex<Option<(String, reqwest::Client)>>,
    stream: bool,
) -> CoreResult<reqwest::Client> {
    let key = settings.cache_key();
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((cached_key, client)) = guard.as_ref()
        && *cached_key == key
    {
        return Ok(client.clone());
    }
    let mut builder = guarded_client_builder().proxy(build_proxy(settings)?);
    if !stream {
        builder = builder.timeout(Duration::from_secs(60));
    }
    let client = builder
        .build()
        .map_err(|error| CoreError::validation("HTTP client", error.to_string()))?;
    *guard = Some((key, client.clone()));
    Ok(client)
}

/// Start every outbound client from the same SSRF-safe redirect policy.
///
/// Validation applies to the configured URL only. Following a provider or proxy
/// response to a second URL would bypass that boundary (for example, a public
/// endpoint redirecting to cloud metadata), so redirects are surfaced to the
/// typed domain service as ordinary 30x responses and are never followed here.
fn guarded_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .redirect(Policy::none())
}

pub fn http_client(proxy: Option<&ProxySettings>) -> CoreResult<reqwest::Client> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    static PROXY_CACHE: Mutex<Option<(String, reqwest::Client)>> = Mutex::new(None);
    match proxy {
        Some(settings) => proxied_client(settings, &PROXY_CACHE, false),
        None => CLIENT
            .get_or_init(|| {
                guarded_client_builder()
                    .timeout(Duration::from_secs(60))
                    .build()
                    .map_err(|error| error.to_string())
            })
            .clone()
            .map_err(|error| CoreError::validation("HTTP client", error)),
    }
}

pub fn stream_client(proxy: Option<&ProxySettings>) -> CoreResult<reqwest::Client> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    static PROXY_CACHE: Mutex<Option<(String, reqwest::Client)>> = Mutex::new(None);
    match proxy {
        Some(settings) => proxied_client(settings, &PROXY_CACHE, true),
        None => CLIENT
            .get_or_init(|| {
                guarded_client_builder()
                    .build()
                    .map_err(|error| error.to_string())
            })
            .clone()
            .map_err(|error| CoreError::validation("streaming HTTP client", error)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn blocks_ssrf_literals_and_url_credentials() {
        for value in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "http://user:pass@example.com/v1",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.1.1/x",
            "http://[fe80::1]/x",
            "http://0.0.0.0:8080/x",
            "http://[::]:8080/x",
        ] {
            assert!(
                validate_outbound_url(value).is_err(),
                "should reject {value}"
            );
        }
    }

    #[test]
    fn permits_offline_and_intranet_inference() {
        for value in [
            "http://localhost:11434/api/chat",
            "http://127.0.0.1:11434/v1/chat/completions",
            "http://192.168.1.50:8000/v1/chat/completions",
            "http://10.0.0.5:8080/v1/chat/completions",
            "https://api.openai.com/v1/chat/completions",
        ] {
            assert!(validate_outbound_url(value).is_ok(), "should allow {value}");
        }
    }

    #[test]
    fn provider_header_allowlist_drops_forgery_and_newlines() {
        let headers = HashMap::from([
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Authorization".to_owned(), "Bearer sk-x".to_owned()),
            ("x-api-key".to_owned(), "k".to_owned()),
            ("Host".to_owned(), "internal.corp".to_owned()),
            ("X-Forwarded-For".to_owned(), "127.0.0.1".to_owned()),
            ("Accept".to_owned(), "ok\r\nInjected: yes".to_owned()),
        ]);
        let (kept, dropped) = filter_headers(&headers);
        assert_eq!(kept.len(), 3);
        assert!(dropped.contains(&"Host".to_owned()));
        assert!(dropped.contains(&"X-Forwarded-For".to_owned()));
        assert!(dropped.contains(&"Accept".to_owned()));
    }

    #[test]
    fn validates_proxy_type_and_scheme() {
        for settings in [
            ProxySettings {
                proxy_type: ProxyType::Http,
                proxy_url: "http://127.0.0.1:8080".to_owned(),
            },
            ProxySettings {
                proxy_type: ProxyType::Http,
                proxy_url: "https://proxy.internal:8443".to_owned(),
            },
            ProxySettings {
                proxy_type: ProxyType::Socks5,
                proxy_url: "socks5://127.0.0.1:1080".to_owned(),
            },
        ] {
            settings.validate().unwrap();
            http_client(Some(&settings)).unwrap();
            stream_client(Some(&settings)).unwrap();
        }
        assert!(
            ProxySettings {
                proxy_type: ProxyType::Http,
                proxy_url: "socks5://127.0.0.1:1080".to_owned(),
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxySettings {
                proxy_type: ProxyType::Http,
                proxy_url: "http://user:password@127.0.0.1:8080".to_owned(),
            }
            .validate()
            .is_err()
        );
    }

    async fn redirect_server(location: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_headers(&mut socket).await;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        (format!("http://{address}/redirect"), task)
    }

    async fn proxy_redirect_server() -> (ProxySettings, Arc<AtomicBool>, tokio::task::JoinHandle<()>)
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let followed = Arc::new(AtomicBool::new(false));
        let observed_follow = followed.clone();
        let task = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            read_headers(&mut first).await;
            first
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            drop(first);

            if let Ok(Ok((mut second, _))) =
                tokio::time::timeout(Duration::from_millis(250), listener.accept()).await
            {
                observed_follow.store(true, Ordering::SeqCst);
                read_headers(&mut second).await;
                let _ = second
                    .write_all(
                        b"HTTP/1.1 418 Followed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        (
            ProxySettings {
                proxy_type: ProxyType::Http,
                proxy_url: format!("http://{address}"),
            },
            followed,
            task,
        )
    }

    async fn read_headers(socket: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1_024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 32_768, "test request headers are bounded");
        }
    }

    #[tokio::test]
    async fn regular_and_stream_clients_never_follow_redirects_to_link_local_targets() {
        for client in [http_client(None).unwrap(), stream_client(None).unwrap()] {
            let (endpoint, server) =
                redirect_server("http://169.254.169.254/latest/meta-data/").await;
            let response = client.get(&endpoint).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::FOUND);
            assert_eq!(response.url().as_str(), endpoint);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn proxied_regular_and_stream_clients_inherit_the_no_redirect_policy() {
        for stream in [false, true] {
            let (proxy, followed, server) = proxy_redirect_server().await;
            let client = if stream {
                stream_client(Some(&proxy)).unwrap()
            } else {
                http_client(Some(&proxy)).unwrap()
            };
            let response = client
                .get("http://provider.example.invalid/v1/models")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::FOUND);
            server.await.unwrap();
            assert!(!followed.load(Ordering::SeqCst));
        }
    }
}
