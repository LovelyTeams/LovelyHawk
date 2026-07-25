//! AI API 代理模块
//! 通过 Rust 后端转发 AI 请求，绕过浏览器 CORS 限制

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct AIProxyRequest {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String, // JSON string
}

#[derive(Debug, Serialize)]
pub struct AIProxyResponse {
    pub status: u16,
    pub body: String,
    pub ok: bool,
}

/// 非流式 AI 请求代理
pub async fn proxy_ai_request(request: AIProxyRequest) -> Result<AIProxyResponse, String> {
    // URL 与 header 都来自 webview，先过防护再发出。
    let url = crate::net_guard::validate_outbound_url(&request.url)?;
    let (headers, dropped) = crate::net_guard::filter_headers(&request.headers);
    if !dropped.is_empty() {
        eprintln!("[ai_proxy] 已丢弃不在白名单的 header: {:?}", dropped);
    }

    // 共享客户端：每请求重建会丢掉连接池并重做 TLS 握手。
    // connect_timeout 让断网时快速失败(默认无连接超时会干等约 30s)，
    // 整体上限宽松，避免异常挂死又不切断正常的较慢补全。
    let client = crate::net_guard::http_client()?;

    let mut builder = client.post(url);

    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let response = builder
        .body(request.body)
        .send()
        .await
        .map_err(|e| format!("AI 请求发送失败: {}", e))?;

    let status = response.status().as_u16();
    let ok = response.status().is_success();
    let body = response.text().await
        .map_err(|e| format!("AI 响应读取失败: {}", e))?;

    Ok(AIProxyResponse { status, body, ok })
}
