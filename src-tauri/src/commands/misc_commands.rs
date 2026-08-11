// Window management, theme, settings, device info, fonts, etc.

use crate::settings;
use crate::AppState;
use tauri::State;

// 窗口控制命令
#[tauri::command]
pub async fn minimize_window(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn toggle_maximize(window: tauri::Window) -> Result<(), String> {
    if window.is_maximized().map_err(|e| e.to_string())? {
        window.unmaximize().map_err(|e| e.to_string())
    } else {
        window.maximize().map_err(|e| e.to_string())
    }
}

#[tauri::command]
pub async fn close_window(window: tauri::Window) -> Result<(), String> {
    window.close().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_devtools(app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;

    // 获取主窗口
    if let Some(window) = app.get_webview_window("main") {
        #[cfg(debug_assertions)]
        {
            window.open_devtools();
            crate::alog_info!("开发者工具已打开 (开发模式)");
            Ok(())
        }
        #[cfg(not(debug_assertions))]
        {
            // 生产环境禁止打开开发者工具
            let _ = window;
            Err("生产环境不支持此操作".to_string())
        }
    } else {
        Err("无法找到主窗口".to_string())
    }
}

// 主题管理命令
#[tauri::command]
pub async fn get_theme_settings(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "获取设置锁失败".to_string())?;
    Ok(serde_json::json!({
        "current_theme": settings.theme
    }))
}

#[tauri::command]
pub async fn set_current_theme(
    app: tauri::AppHandle,
    theme: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    use tauri::Emitter;

    let mut settings = state
        .settings
        .lock()
        .map_err(|_| "获取设置锁失败".to_string())?;
    settings.theme = theme.clone();

    // 保存设置
    settings::save_settings(&*settings)?;

    // 向所有窗口广播主题变更事件
    if let Err(e) = app.emit("theme-changed", theme.clone()) {
        crate::alog_error!("发送主题变更事件失败: {}", e);
    }

    #[cfg(debug_assertions)]
    crate::alog_info!("主题模式已更新为: {}", theme);
    Ok(())
}

// 设置管理命令
#[tauri::command]
pub async fn get_app_settings(state: State<'_, AppState>) -> Result<settings::AppSettings, String> {
    let settings = state
        .settings
        .lock()
        .map_err(|_| "获取设置锁失败".to_string())?;
    Ok(settings.clone())
}

#[tauri::command]
pub async fn save_app_settings(
    new_settings: settings::AppSettings,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut settings = state
        .settings
        .lock()
        .map_err(|_| "获取设置锁失败".to_string())?;
    *settings = new_settings.clone();

    // 保存到文件
    settings::save_settings(&new_settings)?;

    crate::alog_info!("应用设置已保存");
    Ok(())
}

/// 读取设置文件
#[tauri::command]
pub async fn read_settings_file() -> Result<String, String> {
    use std::fs;

    // 获取应用数据目录
    let mut settings_path = settings::get_app_data_dir()?;
    settings_path.push("settings.json");

    crate::alog_info!("SSH终端读取设置文件路径: {:?}", settings_path);

    if settings_path.exists() {
        let content =
            fs::read_to_string(&settings_path).map_err(|e| format!("读取设置文件失败: {}", e))?;
        crate::alog_info!("设置文件内容长度: {} 字符", content.len());
        Ok(content)
    } else {
        crate::alog_warn!("设置文件不存在: {:?}", settings_path);
        // 如果文件不存在，返回空字符串
        Ok(String::new())
    }
}

/// 写入设置文件
#[tauri::command]
pub async fn write_settings_file(content: String) -> Result<(), String> {
    use std::fs;

    // 获取应用数据目录
    let mut settings_path = settings::get_app_data_dir()?;
    settings_path.push("settings.json");

    fs::write(&settings_path, content).map_err(|e| format!("写入设置文件失败: {}", e))
}

// 加密相关命令

/// 加密 AI API Key（enc:v1: 格式），设置页保存时调用
#[tauri::command]
pub fn encrypt_ai_key(plaintext: String) -> Result<String, String> {
    crate::crypto::encrypt_text(&plaintext)
}

/// 迁移 settings.json 中明文存储的 AI API Key 为 enc:v1: 密文。
/// 返回迁移条数。应用启动时（lib.rs setup）与前端均可调用。
pub fn migrate_ai_keys_impl() -> Result<u32, String> {
    let settings_path = settings::get_app_data_dir()?.join("settings.json");
    if !settings_path.exists() {
        return Ok(0);
    }

    let content =
        std::fs::read_to_string(&settings_path).map_err(|e| format!("读取设置文件失败: {}", e))?;
    if content.trim().is_empty() {
        return Ok(0);
    }

    let mut value: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("解析设置文件失败: {}", e))?;

    let mut migrated = 0u32;
    if let Some(providers) = value
        .get_mut("ai")
        .and_then(|ai| ai.get_mut("providers"))
        .and_then(|p| p.as_array_mut())
    {
        for provider in providers.iter_mut() {
            let key = match provider.get("apiKey").and_then(|k| k.as_str()) {
                Some(k) if !k.is_empty() && !crate::crypto::is_encrypted(k) => k.to_string(),
                _ => continue,
            };
            let encrypted = crate::crypto::encrypt_text(&key)?;
            provider["apiKey"] = serde_json::Value::String(encrypted);
            migrated += 1;
        }
    }

    if migrated > 0 {
        let pretty = serde_json::to_string_pretty(&value)
            .map_err(|e| format!("序列化设置文件失败: {}", e))?;
        std::fs::write(&settings_path, pretty).map_err(|e| format!("写入设置文件失败: {}", e))?;
        crate::alog_info!("已迁移 {} 个 AI API Key 为加密存储", migrated);
    }

    Ok(migrated)
}

/// 迁移明文 AI Key 的 Tauri 命令入口
#[tauri::command]
pub fn migrate_ai_keys() -> Result<u32, String> {
    migrate_ai_keys_impl()
}

/// 获取系统字体列表
#[tauri::command]
pub async fn get_system_fonts() -> Result<Vec<String>, String> {
    #[cfg(target_os = "windows")]
    {
        // 方法1: 使用WinAPI EnumFontFamilies (最可靠)
        match get_fonts_from_winapi() {
            Ok(fonts) => {
                if fonts.len() > 10 {
                    return Ok(fonts);
                }
            }
            Err(_) => {
                // WinAPI方法失败，尝试其他方法
            }
        }

        // 方法2: 尝试从注册表获取字体
        match get_fonts_from_registry() {
            Ok(fonts) => {
                if fonts.len() > 10 {
                    return Ok(fonts);
                }
            }
            Err(_) => {}
        }

        // 方法3: 尝试遍历字体文件夹
        match get_fonts_from_directory() {
            Ok(fonts) => {
                if fonts.len() > 10 {
                    return Ok(fonts);
                }
            }
            Err(_) => {}
        }

        // 方法4: 所有方法都失败，使用默认字体列表
        Ok(get_default_fonts())
    }

    #[cfg(not(target_os = "windows"))]
    {
        // 非Windows系统，返回默认字体列表
        Ok(get_default_fonts())
    }
}

/// 使用WinAPI EnumFontFamilies获取字体列表
#[cfg(target_os = "windows")]
fn get_fonts_from_winapi() -> Result<Vec<String>, String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;
    use std::sync::Mutex;
    use winapi::shared::minwindef::LPARAM;
    use winapi::shared::windef::{HDC, HWND};
    use winapi::um::wingdi::{EnumFontFamiliesW, LOGFONTW};
    use winapi::um::winuser::{GetDC, ReleaseDC};

    // 用于存储字体名称的全局变量
    static FONT_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

    // 回调函数，用于接收枚举的字体信息
    unsafe extern "system" fn enum_font_proc(
        lplf: *const LOGFONTW,
        _lptm: *const winapi::um::wingdi::TEXTMETRICW,
        _font_type: u32,
        _lparam: LPARAM,
    ) -> i32 {
        if lplf.is_null() {
            return 1; // 继续枚举
        }

        // 从LOGFONT结构中提取字体名称
        let logfont = &*lplf;
        let font_name_slice = &logfont.lfFaceName;

        // 找到字符串的结尾（null terminator）
        let mut len = 0;
        for &ch in font_name_slice.iter() {
            if ch == 0 {
                break;
            }
            len += 1;
        }

        if len > 0 {
            // 将UTF-16转换为String
            let font_name_utf16 = &font_name_slice[..len];
            let font_name = OsString::from_wide(font_name_utf16)
                .to_string_lossy()
                .to_string();

            // 添加到字体列表
            if let Ok(mut fonts) = FONT_NAMES.lock() {
                if !font_name.is_empty() && !fonts.contains(&font_name) {
                    fonts.push(font_name);
                }
            }
        }

        1 // 继续枚举
    }

    unsafe {
        // 获取桌面设备上下文
        let hdc: HDC = GetDC(ptr::null_mut() as HWND);
        if hdc.is_null() {
            return Err("无法获取设备上下文".to_string());
        }

        // 清空字体列表
        if let Ok(mut fonts) = FONT_NAMES.lock() {
            fonts.clear();
        }

        // 枚举所有字体族
        let result = EnumFontFamiliesW(hdc, ptr::null(), Some(enum_font_proc), 0);

        // 释放设备上下文
        ReleaseDC(ptr::null_mut() as HWND, hdc);

        if result == 0 {
            return Err("EnumFontFamiliesW调用失败".to_string());
        }

        // 获取结果
        let mut fonts = if let Ok(fonts) = FONT_NAMES.lock() {
            fonts.clone()
        } else {
            return Err("无法获取字体列表".to_string());
        };

        // 添加系统默认选项并排序
        fonts.insert(0, "系统默认".to_string());
        fonts.sort();
        fonts.dedup();

        Ok(fonts)
    }
}

#[cfg(not(target_os = "windows"))]
fn get_fonts_from_winapi() -> Result<Vec<String>, String> {
    Err("非Windows系统不支持WinAPI方法".to_string())
}

/// 从Windows注册表获取字体列表
#[cfg(target_os = "windows")]
fn get_fonts_from_registry() -> Result<Vec<String>, String> {
    use std::process::Command;

    // 使用reg命令查询字体注册表
    let output = Command::new("reg")
        .args(&[
            "query",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts",
            "/v",
            "*",
        ])
        .output()
        .map_err(|e| format!("执行reg命令失败: {}", e))?;

    if output.status.success() {
        let registry_str = String::from_utf8_lossy(&output.stdout);
        let mut fonts = Vec::new();

        // 添加系统默认选项
        fonts.push("系统默认".to_string());

        // 解析注册表输出，提取字体名称
        for line in registry_str.lines() {
            if line.contains("REG_SZ") && !line.trim().is_empty() {
                // 注册表行格式: "    字体名称 (TrueType)    REG_SZ    字体文件名"
                let parts: Vec<&str> = line.split("REG_SZ").collect();
                if parts.len() >= 1 {
                    let font_entry = parts[0].trim();
                    if !font_entry.is_empty() {
                        // 清理字体名称
                        let font_name = font_entry
                            .replace(" (TrueType)", "")
                            .replace(" (OpenType)", "")
                            .replace(" Bold", "")
                            .replace(" Italic", "")
                            .replace(" Regular", "")
                            .replace(" Light", "")
                            .replace(" Medium", "")
                            .trim()
                            .to_string();

                        if !font_name.is_empty()
                            && !fonts.contains(&font_name)
                            && font_name.len() > 1
                        {
                            fonts.push(font_name);
                        }
                    }
                }
            }
        }

        fonts.sort();
        fonts.dedup();

        Ok(fonts)
    } else {
        let error_str = String::from_utf8_lossy(&output.stderr);
        Err(format!("注册表查询失败: {}", error_str))
    }
}

#[cfg(not(target_os = "windows"))]
fn get_fonts_from_registry() -> Result<Vec<String>, String> {
    Err("非Windows系统不支持注册表方法".to_string())
}

/// 从字体目录获取字体列表
#[cfg(target_os = "windows")]
fn get_fonts_from_directory() -> Result<Vec<String>, String> {
    use std::fs;
    use std::path::Path;

    let font_dirs = vec!["C:\\Windows\\Fonts", "C:\\Windows\\System32\\Fonts"];

    let mut fonts = Vec::new();
    fonts.push("系统默认".to_string());

    for font_dir in font_dirs {
        let path = Path::new(font_dir);
        if path.exists() && path.is_dir() {
            match fs::read_dir(path) {
                Ok(entries) => {
                    for entry in entries {
                        if let Ok(entry) = entry {
                            let file_name = entry.file_name();
                            let file_name_str = file_name.to_string_lossy();

                            // 只处理字体文件
                            if file_name_str.ends_with(".ttf")
                                || file_name_str.ends_with(".otf")
                                || file_name_str.ends_with(".ttc")
                            {
                                // 从文件名提取字体名称
                                let font_name = file_name_str
                                    .replace(".ttf", "")
                                    .replace(".otf", "")
                                    .replace(".ttc", "")
                                    .replace("_", " ")
                                    .replace("-", " ");

                                if !font_name.is_empty() && !fonts.contains(&font_name) {
                                    fonts.push(font_name);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    fonts.sort();
    fonts.dedup();

    Ok(fonts)
}

#[cfg(not(target_os = "windows"))]
fn get_fonts_from_directory() -> Result<Vec<String>, String> {
    Err("非Windows系统不支持字体目录方法".to_string())
}

/// 获取默认字体列表（作为后备方案）
fn get_default_fonts() -> Vec<String> {
    vec![
        // 系统默认
        "系统默认".to_string(),
        // Windows 中文字体
        "Microsoft YaHei".to_string(),
        "Microsoft YaHei UI".to_string(),
        "微软雅黑".to_string(),
        "SimSun".to_string(),
        "宋体".to_string(),
        "SimHei".to_string(),
        "黑体".to_string(),
        "KaiTi".to_string(),
        "楷体".to_string(),
        "FangSong".to_string(),
        "仿宋".to_string(),
        "Microsoft JhengHei".to_string(),
        "微软正黑体".to_string(),
        "DengXian".to_string(),
        "等线".to_string(),
        "YouYuan".to_string(),
        "幼圆".to_string(),
        "LiSu".to_string(),
        "隶书".to_string(),
        "STXihei".to_string(),
        "华文细黑".to_string(),
        "STKaiti".to_string(),
        "华文楷体".to_string(),
        "STSong".to_string(),
        "华文宋体".to_string(),
        "STFangsong".to_string(),
        "华文仿宋".to_string(),
        // macOS 中文字体
        "PingFang SC".to_string(),
        "苹方".to_string(),
        "Hiragino Sans GB".to_string(),
        "冬青黑体简体中文".to_string(),
        // 开源中文字体
        "Noto Sans CJK SC".to_string(),
        "思源黑体".to_string(),
        "Source Han Sans SC".to_string(),
        "Noto Serif CJK SC".to_string(),
        "思源宋体".to_string(),
        "Source Han Serif SC".to_string(),
        // Windows 英文字体
        "Arial".to_string(),
        "Times New Roman".to_string(),
        "Calibri".to_string(),
        "Segoe UI".to_string(),
        "Tahoma".to_string(),
        "Verdana".to_string(),
        "Georgia".to_string(),
        "Trebuchet MS".to_string(),
        "Comic Sans MS".to_string(),
        "Impact".to_string(),
        "Lucida Console".to_string(),
        "Palatino Linotype".to_string(),
        // 等宽字体
        "Consolas".to_string(),
        "Courier New".to_string(),
        "JetBrains Mono".to_string(),
        "Fira Code".to_string(),
        "Source Code Pro".to_string(),
        "Monaco".to_string(),
        "Menlo".to_string(),
        "Inconsolata".to_string(),
        "Roboto Mono".to_string(),
        "Ubuntu Mono".to_string(),
        // 设计字体
        "Helvetica".to_string(),
        "Helvetica Neue".to_string(),
        "San Francisco".to_string(),
        "Roboto".to_string(),
        "Open Sans".to_string(),
        "Lato".to_string(),
        "Montserrat".to_string(),
        "Poppins".to_string(),
    ]
}

// ==================== AI 代理命令 ====================

/// AI 请求代理（绕过 CORS）— 非流式
#[tauri::command]
pub async fn ai_proxy_request(
    url: String,
    headers: std::collections::HashMap<String, String>,
    body: String,
    api_key: Option<String>,
    api_key_header: Option<String>,
) -> Result<crate::ai_proxy::AIProxyResponse, String> {
    crate::ai_proxy::proxy_ai_request(crate::ai_proxy::AIProxyRequest {
        url,
        headers,
        body,
        api_key,
        api_key_header,
    })
    .await
}

/// 拉取提供商的模型列表（OpenAI/Claude 的 /models，Ollama 的 /api/tags）。
/// 端点推导、URL 校验、Key 解密与代理配置全部走后端既有防护。
#[tauri::command]
pub async fn ai_list_models(
    base_url: String,
    provider_type: String,
    api_key: Option<String>,
    api_key_header: Option<String>,
) -> Result<Vec<String>, String> {
    let endpoint = crate::ai_proxy::models_endpoint(&base_url, &provider_type)?;
    let url = crate::net_guard::validate_outbound_url(&endpoint)?;

    let key = crate::ai_proxy::resolve_api_key(api_key)?;
    let proxy = crate::ai_proxy::ai_proxy_settings();
    let client = crate::net_guard::http_client(proxy.as_ref())?;

    let mut builder = client.get(url);
    builder =
        crate::ai_proxy::inject_auth_header(builder, key.as_deref(), api_key_header.as_deref())?;
    if provider_type == "claude" {
        // Anthropic 的所有端点都要求这个版本头
        builder = builder.header("anthropic-version", "2023-06-01");
    }

    let response = builder
        .send()
        .await
        .map_err(|e| format!("拉取模型列表失败: {}", e))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("模型列表响应读取失败: {}", e))?;
    if !status.is_success() {
        let snippet: String = body.chars().take(200).collect();
        return Err(format!(
            "拉取模型列表失败 (HTTP {}): {}",
            status.as_u16(),
            snippet
        ));
    }

    crate::ai_proxy::parse_model_list(&body)
}

/// 取消一条进行中的 AI 流式请求。未知 stream_id 也返回 Ok（幂等）。
#[tauri::command]
pub fn ai_proxy_stream_cancel(stream_id: String) -> Result<(), String> {
    if crate::ai_proxy::cancel_stream(&stream_id) {
        crate::alog_info!("[ai_proxy_stream] 已请求取消流 {}", stream_id);
    } else {
        crate::alog_warn!(
            "[ai_proxy_stream] 取消请求针对未知的 stream_id: {}",
            stream_id
        );
    }
    Ok(())
}

/// AI 流式请求代理（绕过 CORS）— 通过事件逐块发送。
///
/// 事件只发给调用窗口，payload 均带 stream_id 供前端按流过滤：
/// - `ai_stream_chunk` `{ stream_id, chunk }`
/// - `ai_stream_error` `{ stream_id, error }`
/// - `ai_stream_done`  `{ stream_id }`
#[tauri::command]
pub async fn ai_proxy_stream(
    url: String,
    headers: std::collections::HashMap<String, String>,
    body: String,
    stream_id: String,
    api_key: Option<String>,
    api_key_header: Option<String>,
    window: tauri::WebviewWindow,
) -> Result<(), String> {
    use tauri::Emitter;

    // URL 与 header 都来自 webview，先过防护再发出。
    let url = crate::net_guard::validate_outbound_url(&url)?;
    let (headers, dropped) = crate::net_guard::filter_headers(&headers);
    if !dropped.is_empty() {
        crate::alog_error!("[ai_proxy_stream] 已丢弃不在白名单的 header: {:?}", dropped);
    }

    let api_key = crate::ai_proxy::resolve_api_key(api_key)?;
    let proxy = crate::ai_proxy::ai_proxy_settings();

    // 共享客户端。仅设连接超时:断网时快速失败,但不切断可能较长的流式响应
    let client = crate::net_guard::stream_client(proxy.as_ref())?;
    let mut builder = client.post(url);

    for (key, value) in &headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    // 认证头由后端注入，前端 headers 不再携带 Key。
    builder = crate::ai_proxy::inject_auth_header(
        builder,
        api_key.as_deref(),
        api_key_header.as_deref(),
    )?;

    let label = window.label().to_string();

    // 注册取消句柄；guard 保证任何退出路径都会从注册表移除
    let cancel_notify = crate::ai_proxy::register_stream_cancel(&stream_id);
    let _cancel_guard = crate::ai_proxy::StreamCancelGuard::new(&stream_id);

    macro_rules! emit_error {
        ($msg:expr) => {{
            let _ = window.emit_to(&label, "ai_stream_error", serde_json::json!({
                "stream_id": stream_id,
                "error": $msg,
            }));
        }};
    }

    let response = match builder.body(body).send().await {
        Ok(response) => response,
        Err(e) => {
            let message = format!("AI 请求发送失败: {}", e);
            emit_error!(message);
            return Err(message);
        }
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        let err_body = response.text().await.unwrap_or_default();
        let message = format!("AI API 请求失败: {} - {}", status, err_body);
        emit_error!(message);
        return Err(message);
    }

    // 逐块读取并发送事件。HTTP 字节分片不保证落在 UTF-8 字符边界上，
    // 因此必须保留不完整的尾部，不能对每个网络分片单独 lossy 解码。
    use futures::StreamExt;
    let mut stream = response.bytes_stream();
    let mut pending_utf8 = Vec::<u8>::new();

    macro_rules! emit_chunk {
        ($text:expr) => {{
            let _ = window.emit_to(&label, "ai_stream_chunk", serde_json::json!({
                "stream_id": stream_id,
                "chunk": $text,
            }));
        }};
    }

    loop {
        // 每次读取包两层保险：120s 空闲超时 + 取消通知
        let chunk = tokio::select! {
            _ = cancel_notify.notified() => {
                crate::alog_info!("[ai_proxy_stream] 流 {} 已被取消", stream_id);
                let _ = window.emit_to(&label, "ai_stream_done", serde_json::json!({
                    "stream_id": stream_id,
                }));
                return Ok(());
            }
            read = tokio::time::timeout(std::time::Duration::from_secs(120), stream.next()) => {
                match read {
                    Ok(Some(chunk)) => chunk,
                    Ok(None) => break,
                    Err(_) => {
                        let message = "AI 响应流空闲超时（120 秒无数据）".to_string();
                        emit_error!(message);
                        return Err(message);
                    }
                }
            }
        };

        match chunk {
            Ok(bytes) => {
                pending_utf8.extend_from_slice(&bytes);

                loop {
                    match std::str::from_utf8(&pending_utf8) {
                        Ok(text) => {
                            if !text.is_empty() {
                                emit_chunk!(text);
                            }
                            pending_utf8.clear();
                            break;
                        }
                        Err(error) => {
                            let valid_up_to = error.valid_up_to();
                            let invalid_len = error.error_len();

                            if valid_up_to > 0 {
                                let text = String::from_utf8_lossy(&pending_utf8[..valid_up_to])
                                    .into_owned();
                                emit_chunk!(text);
                                pending_utf8.drain(..valid_up_to);
                            }

                            if let Some(invalid_len) = invalid_len {
                                let drain_len = invalid_len.min(pending_utf8.len());
                                pending_utf8.drain(..drain_len);
                                emit_chunk!("�");
                                continue;
                            }

                            break;
                        }
                    }
                }
            }
            Err(e) => {
                let message = format!("AI 响应流读取失败: {}", e);
                emit_error!(message);
                return Err(message);
            }
        }
    }

    if !pending_utf8.is_empty() {
        let text = String::from_utf8_lossy(&pending_utf8).into_owned();
        if !text.is_empty() {
            emit_chunk!(text);
        }
    }

    let _ = window.emit_to(
        &label,
        "ai_stream_done",
        serde_json::json!({
            "stream_id": stream_id,
        }),
    );
    Ok(())
}
