//! AI API 代理模块
//! 通过 Rust 后端转发 AI 请求，绕过浏览器 CORS 限制

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Debug, Deserialize)]
pub struct AIProxyRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String, // JSON string
    /// API Key（可为 enc:v1: 密文），后端解密后自行注入认证头
    pub api_key: Option<String>,
    /// "authorization-bearer" | "x-api-key"
    pub api_key_header: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AIProxyResponse {
    pub status: u16,
    pub body: String,
    pub ok: bool,
}

/// 解析 API Key：带 enc:v1: 前缀的先解密，解密失败返回明确错误；
/// 空串视为未提供。
pub fn resolve_api_key(api_key: Option<String>) -> Result<Option<String>, String> {
    match api_key {
        None => Ok(None),
        Some(key) if key.is_empty() => Ok(None),
        Some(key) if crate::crypto::is_encrypted(&key) => crate::crypto::decrypt_text(&key)
            .map(Some)
            .map_err(|e| format!("API Key 解密失败: {}", e)),
        Some(key) => Ok(Some(key)),
    }
}

/// 按 api_key_header 约定把认证头注入请求。未提供 Key 时原样返回。
pub fn inject_auth_header(
    builder: reqwest::RequestBuilder,
    api_key: Option<&str>,
    api_key_header: Option<&str>,
) -> Result<reqwest::RequestBuilder, String> {
    let key = match api_key {
        Some(k) if !k.is_empty() => k,
        _ => return Ok(builder),
    };

    match api_key_header.unwrap_or("authorization-bearer") {
        "authorization-bearer" => Ok(builder.header("Authorization", format!("Bearer {}", key))),
        "x-api-key" => Ok(builder.header("x-api-key", key)),
        other => Err(format!("不支持的 api_key_header: {}", other)),
    }
}

/// 从 settings.json 读取 AI 代理配置（ai.useProxy/proxyType/proxyUrl）。
/// 不耦合 AppSettings 类型，直接按 JSON 取值；未启用或配置不完整时返回 None。
pub fn ai_proxy_settings() -> Option<crate::net_guard::ProxySettings> {
    let settings_path = crate::settings::get_app_data_dir()
        .ok()?
        .join("settings.json");
    let content = std::fs::read_to_string(&settings_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;

    let ai = value.get("ai")?;
    if ai.get("useProxy").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let proxy_url = ai.get("proxyUrl").and_then(|v| v.as_str())?.trim();
    if proxy_url.is_empty() {
        return None;
    }
    let proxy_type = ai
        .get("proxyType")
        .and_then(|v| v.as_str())
        .unwrap_or("http");

    Some(crate::net_guard::ProxySettings {
        proxy_type: proxy_type.to_string(),
        proxy_url: proxy_url.to_string(),
    })
}

// ==================== 模型列表 ====================

/// 由补全端点推导模型列表端点（镜像前端 aiConfig.ensureCompletionsPath 的约定）：
/// - ollama → {origin}/api/tags
/// - 其余 → 去掉 /chat/completions 或 /messages 后缀后补 /models；
///   路径不含 /v1 或 /api 片段时先补 /v1（与 ensureCompletionsPath 同哲学：
///   含版本片段的路径交给用户自己负责正确性）
pub fn models_endpoint(base_url: &str, provider_type: &str) -> Result<String, String> {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("Base URL 不能为空".to_string());
    }

    if provider_type == "ollama" {
        let url = trimmed
            .parse::<reqwest::Url>()
            .map_err(|e| format!("无效的 Base URL: {}", e))?;
        return Ok(format!("{}/api/tags", url.origin().ascii_serialization()));
    }

    let stem = trimmed
        .strip_suffix("/chat/completions")
        .or_else(|| trimmed.strip_suffix("/messages"))
        .unwrap_or(trimmed);

    // 只看 path，避免 api.openai.com 这类主机名造成误判（同前端实现）
    let path = stem
        .parse::<reqwest::Url>()
        .map(|u| u.path().to_string())
        .unwrap_or_default();
    let versioned = path.contains("/v1") || path.contains("/api");

    if stem.ends_with("/v1") || versioned {
        Ok(format!("{}/models", stem))
    } else {
        Ok(format!("{}/v1/models", stem))
    }
}

/// 解析模型列表响应：OpenAI/Claude 的 {"data":[{"id":...}]}，
/// Ollama 的 {"models":[{"name":...}]}。去重去空，保持原始顺序。
pub fn parse_model_list(body: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("模型列表响应不是有效 JSON: {}", e))?;

    let collect = |arr: &Vec<serde_json::Value>, fields: [&str; 2]| -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        arr.iter()
            .filter_map(|item| {
                fields
                    .iter()
                    .find_map(|f| item.get(*f).and_then(|v| v.as_str()))
            })
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && seen.insert(s.clone()))
            .collect()
    };

    let models = if let Some(arr) = value.get("data").and_then(|v| v.as_array()) {
        collect(arr, ["id", "name"])
    } else if let Some(arr) = value.get("models").and_then(|v| v.as_array()) {
        collect(arr, ["name", "id"])
    } else {
        return Err("无法解析模型列表响应（既无 data 也无 models 字段）".to_string());
    };

    if models.is_empty() {
        return Err("提供商返回了空的模型列表".to_string());
    }
    Ok(models)
}

// ==================== 流式请求取消管理 ====================

fn stream_cancel_registry() -> &'static Mutex<HashMap<String, Arc<tokio::sync::Notify>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 注册一条流的取消句柄，返回用于在读取循环里 select! 的 Notify。
pub fn register_stream_cancel(stream_id: &str) -> Arc<tokio::sync::Notify> {
    let notify = Arc::new(tokio::sync::Notify::new());
    let mut registry = stream_cancel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.insert(stream_id.to_string(), notify.clone());
    notify
}

fn unregister_stream_cancel(stream_id: &str) {
    let mut registry = stream_cancel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.remove(stream_id);
}

/// 触发一条流的取消。stream_id 未知时返回 false。
pub fn cancel_stream(stream_id: &str) -> bool {
    let registry = stream_cancel_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(notify) = registry.get(stream_id) {
        notify.notify_one();
        true
    } else {
        false
    }
}

/// RAII 守卫：流结束（含任何错误路径 return）时自动移除取消句柄。
pub struct StreamCancelGuard(String);

impl StreamCancelGuard {
    pub fn new(stream_id: &str) -> Self {
        Self(stream_id.to_string())
    }
}

impl Drop for StreamCancelGuard {
    fn drop(&mut self) {
        unregister_stream_cancel(&self.0);
    }
}

/// 非流式 AI 请求代理
pub async fn proxy_ai_request(request: AIProxyRequest) -> Result<AIProxyResponse, String> {
    // URL 与 header 都来自 webview，先过防护再发出。
    let url = crate::net_guard::validate_outbound_url(&request.url)?;
    let (headers, dropped) = crate::net_guard::filter_headers(&request.headers);
    if !dropped.is_empty() {
        crate::alog_error!("[ai_proxy] 已丢弃不在白名单的 header: {:?}", dropped);
    }

    let api_key = resolve_api_key(request.api_key)?;
    let proxy = ai_proxy_settings();

    // 共享客户端：每请求重建会丢掉连接池并重做 TLS 握手。
    // connect_timeout 让断网时快速失败(默认无连接超时会干等约 30s)，
    // 整体上限宽松，避免异常挂死又不切断正常的较慢补全。
    let client = crate::net_guard::http_client(proxy.as_ref())?;

    let mut builder = client.post(url);

    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    // 认证头由后端注入，前端 headers 不再携带 Key。
    builder = inject_auth_header(
        builder,
        api_key.as_deref(),
        request.api_key_header.as_deref(),
    )?;

    let response = builder
        .body(request.body)
        .send()
        .await
        .map_err(|e| format!("AI 请求发送失败: {}", e))?;

    let status = response.status().as_u16();
    let ok = response.status().is_success();
    let body = response
        .text()
        .await
        .map_err(|e| format!("AI 响应读取失败: {}", e))?;

    Ok(AIProxyResponse { status, body, ok })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_api_key_passthrough() {
        assert_eq!(resolve_api_key(None).unwrap(), None);
        assert_eq!(resolve_api_key(Some(String::new())).unwrap(), None);
        assert_eq!(
            resolve_api_key(Some("sk-plain".to_string())).unwrap(),
            Some("sk-plain".to_string())
        );
    }

    #[test]
    fn resolve_api_key_rejects_bad_ciphertext() {
        // 带 enc:v1: 前缀但内容损坏，必须明确报错而不是把密文当 Key 发出去
        let result = resolve_api_key(Some("enc:v1:corrupted".to_string()));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("解密失败"));
    }

    #[test]
    fn cancel_unknown_stream_returns_false() {
        assert!(!cancel_stream("no-such-stream-id"));
    }

    #[test]
    fn register_then_cancel_roundtrip() {
        let id = "test-stream-cancel-roundtrip";
        let _notify = register_stream_cancel(id);
        assert!(cancel_stream(id));
        unregister_stream_cancel(id);
        assert!(!cancel_stream(id));
    }

    #[test]
    fn guard_unregisters_on_drop() {
        let id = "test-stream-guard-drop";
        register_stream_cancel(id);
        {
            let _guard = StreamCancelGuard::new(id);
        }
        assert!(!cancel_stream(id));
    }

    #[test]
    fn models_endpoint_openai_style() {
        assert_eq!(
            models_endpoint("https://api.openai.com/v1", "openai").unwrap(),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(
            models_endpoint("https://api.openai.com/v1/chat/completions", "openai").unwrap(),
            "https://api.openai.com/v1/models"
        );
        assert_eq!(
            models_endpoint("https://api.deepseek.com", "deepseek").unwrap(),
            "https://api.deepseek.com/v1/models"
        );
        // 含版本片段的自定义路径不再补 /v1
        assert_eq!(
            models_endpoint("http://192.168.1.5:8000/api/v2/chat/completions", "custom").unwrap(),
            "http://192.168.1.5:8000/api/v2/models"
        );
    }

    #[test]
    fn models_endpoint_claude_and_ollama() {
        assert_eq!(
            models_endpoint("https://api.anthropic.com/v1/messages", "claude").unwrap(),
            "https://api.anthropic.com/v1/models"
        );
        assert_eq!(
            models_endpoint("http://localhost:11434/v1/chat/completions", "ollama").unwrap(),
            "http://localhost:11434/api/tags"
        );
        assert!(models_endpoint("", "openai").is_err());
    }

    #[test]
    fn parse_model_list_openai_and_ollama() {
        let openai = r#"{"data":[{"id":"gpt-4o"},{"id":"gpt-4o-mini"},{"id":"gpt-4o"}]}"#;
        assert_eq!(
            parse_model_list(openai).unwrap(),
            vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string()]
        );
        let ollama = r#"{"models":[{"name":"qwen2.5:7b"},{"name":"llama3.1:8b"}]}"#;
        assert_eq!(
            parse_model_list(ollama).unwrap(),
            vec!["qwen2.5:7b".to_string(), "llama3.1:8b".to_string()]
        );
        assert!(parse_model_list("{}").is_err());
        assert!(parse_model_list("not json").is_err());
        assert!(parse_model_list(r#"{"data":[]}"#).is_err());
    }
}
