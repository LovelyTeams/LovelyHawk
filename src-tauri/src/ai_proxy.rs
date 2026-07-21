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
    // 断网/目标不可达时靠 connect_timeout 快速失败(默认无连接超时会干等约 30s);
    // 再加一个宽松的整体上限,避免异常挂死,同时不至于切断正常的较慢补全。
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(8))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

    let mut builder = client.post(&request.url);

    for (key, value) in &request.headers {
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
