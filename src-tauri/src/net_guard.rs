//! 出站请求防护
//!
//! `ai_proxy_request` / `ai_proxy_stream` 接受来自 webview 的任意 URL 与任意
//! header。webview 里一旦有 XSS，就等于拿到一个**跑在宿主进程内、CSP 完全管
//! 不到**的可控 HTTP 客户端 —— 可以打内网、读云元数据、并把响应体原样取回。
//!
//! 本模块把 lib.rs 的 `open_web_terminal` 已有的那套校验抽出来复用，并补上
//! header 白名单与共享客户端。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use reqwest::Url;
use url::Host;

/// 允许透传的 header。
///
/// 覆盖 aiService.getAPIEndpoint() 会发出的全部 header（Content-Type /
/// Authorization / x-api-key / anthropic-version），所以现有任何一条 provider
/// 路径都不受影响。其余 header 会被丢弃并记日志 —— 放任任意 header 等于把
/// `Host:` / `X-Forwarded-For` 伪造能力交给攻击者去打内网服务。
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
        // 169.254.0.0/16 —— 含云厂商元数据地址 169.254.169.254
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => *v6 == Ipv6Addr::UNSPECIFIED,
    }
}

/// 校验一个出站 URL 是否允许请求。
///
/// 放行策略刻意**不**拦 loopback 与 RFC1918：本工具的主场景是离线应急，大量
/// 用户跑本地 Ollama（默认 `http://localhost:11434`）或内网自建推理服务，
/// 硬拦会直接打断主用例。换来的代价是 XSS 仍可探测本机/内网 —— 但 header
/// 白名单已经拿掉了伪造 Host 的能力，且响应仍受 `ai_proxy` 自身约束。
///
/// 只解析 URL 里的**字面量 IP**，不做 DNS 解析：解析会引入 TOCTOU（校验时
/// 与请求时可能解析到不同地址），也挡不住 DNS rebinding。对桌面工具而言，
/// 拦住直接写 IP 的那条路已经覆盖了现实中的攻击形态。
pub fn validate_outbound_url(raw: &str) -> Result<Url, String> {
    let parsed = raw
        .parse::<Url>()
        .map_err(|e| format!("无效的请求 URL: {}", e))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("只允许 http/https，收到: {}", parsed.scheme()));
    }
    let host = parsed
        .host()
        .ok_or_else(|| "请求 URL 必须包含主机名".to_string())?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("请求 URL 不允许内嵌用户名或密码".to_string());
    }

    // 必须用带类型的 host()：host_str() 对 IPv6 返回的是**带方括号**的
    // `[fe80::1]`，直接 parse::<IpAddr>() 会失败并让检查被静默跳过，
    // 结果只拦住 IPv4 —— 单元测试就是这么抓到的。
    let literal_ip: Option<IpAddr> = match host {
        Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        Host::Domain(_) => None,
    };

    if let Some(ip) = literal_ip {
        if is_unspecified(&ip) {
            return Err(format!("不允许请求未指定地址: {}", ip));
        }
        if is_link_local(&ip) {
            return Err(format!(
                "不允许请求链路本地地址 {}（含云元数据 169.254.169.254）",
                ip
            ));
        }
    }

    Ok(parsed)
}

/// 按白名单过滤 header，返回 (保留的, 被丢弃的名字)
pub fn filter_headers(headers: &HashMap<String, String>) -> (Vec<(String, String)>, Vec<String>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();

    for (key, value) in headers {
        if ALLOWED_HEADERS.contains(&key.to_ascii_lowercase().as_str()) {
            kept.push((key.clone(), value.clone()));
        } else {
            dropped.push(key.clone());
        }
    }

    (kept, dropped)
}

/// 非流式请求用的共享客户端（带整体超时）
///
/// 共享而非每次 build：每请求重建会丢掉连接池并重做 TLS 握手。
pub fn http_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(8))
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

/// 流式请求用的共享客户端
///
/// 刻意不设整体 timeout：流式补全可能持续很久，设了会从中间被切断。
pub fn stream_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(8))
                .build()
                .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))
        })
        .as_ref()
        .map_err(|e| e.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        for raw in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
        ] {
            assert!(validate_outbound_url(raw).is_err(), "should reject {raw}");
        }
    }

    #[test]
    fn rejects_embedded_credentials() {
        assert!(validate_outbound_url("http://user:pass@example.com/v1").is_err());
        assert!(validate_outbound_url("http://user@example.com/v1").is_err());
    }

    #[test]
    fn rejects_cloud_metadata_and_link_local() {
        // 云元数据端点 —— SSRF 的头号目标
        assert!(validate_outbound_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(validate_outbound_url("http://169.254.1.1/x").is_err());
        assert!(validate_outbound_url("http://[fe80::1]/x").is_err());
    }

    #[test]
    fn rejects_unspecified_address() {
        assert!(validate_outbound_url("http://0.0.0.0:8080/x").is_err());
        assert!(validate_outbound_url("http://[::]:8080/x").is_err());
    }

    #[test]
    fn allows_local_inference_endpoints() {
        // 离线主场景：本地 Ollama / 内网自建推理服务，必须放行
        for raw in [
            "http://localhost:11434/api/chat/completions",
            "http://127.0.0.1:11434/v1/chat/completions",
            "http://192.168.1.50:8000/v1/chat/completions",
            "http://10.0.0.5:8080/v1/chat/completions",
            "https://api.openai.com/v1/chat/completions",
        ] {
            assert!(validate_outbound_url(raw).is_ok(), "should allow {raw}");
        }
    }

    #[test]
    fn header_allowlist_keeps_provider_headers_and_drops_forgery() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("Authorization".into(), "Bearer sk-x".into());
        headers.insert("x-api-key".into(), "k".into());
        headers.insert("anthropic-version".into(), "2023-06-01".into());
        // 伪造内网身份用的
        headers.insert("Host".into(), "internal.corp".into());
        headers.insert("X-Forwarded-For".into(), "127.0.0.1".into());

        let (kept, dropped) = filter_headers(&headers);
        assert_eq!(kept.len(), 4, "四条 provider header 都应保留");
        assert_eq!(dropped.len(), 2);
        assert!(dropped.contains(&"Host".to_string()));
        assert!(dropped.contains(&"X-Forwarded-For".to_string()));
    }
}
