//! 后端运行日志环形缓冲区
//!
//! 正式包里 stdout 不可见，裸 println 等于白记。所有后端日志经由本模块
//! 同时写入 500 条内存环形缓冲，前端日志面板通过 `get_backend_logs` 读取。

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Clone, serde::Serialize)]
pub struct BackendLogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

const MAX_BUFFER: usize = 500;

static BUFFER: Mutex<VecDeque<BackendLogEntry>> = Mutex::new(VecDeque::new());

pub fn log(level: &str, message: String) {
    let entry = BackendLogEntry {
        timestamp: chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S%.3f")
            .to_string(),
        level: level.to_string(),
        message,
    };
    {
        let mut buf = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
        buf.push_back(entry.clone());
        while buf.len() > MAX_BUFFER {
            buf.pop_front();
        }
    }
    // 保留 stdout 输出，dev 模式下仍可在控制台看到
    match level {
        "ERROR" | "WARN" => eprintln!("[{}] {}", entry.level, entry.message),
        _ => println!("[{}] {}", entry.level, entry.message),
    }
}

#[tauri::command]
pub fn get_backend_logs() -> Vec<BackendLogEntry> {
    BUFFER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .cloned()
        .collect()
}

#[tauri::command]
pub fn clear_backend_logs() {
    BUFFER.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

fn write_frontend_ready_marker(path: &Path) -> Result<(), String> {
    let temp_root = std::fs::canonicalize(std::env::temp_dir())
        .map_err(|error| format!("无法解析系统临时目录: {}", error))?;
    let parent = path
        .parent()
        .ok_or_else(|| "前端就绪标记缺少父目录".to_string())?;
    let parent = std::fs::canonicalize(parent)
        .map_err(|error| format!("无法解析前端就绪标记目录: {}", error))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "前端就绪标记文件名无效".to_string())?;
    if parent != temp_root
        || !file_name.starts_with("lovelyres-ready-")
        || !file_name.ends_with(".json")
    {
        return Err("前端就绪标记只能写入系统临时目录的 lovelyres-ready-*.json".to_string());
    }

    let payload = serde_json::json!({
        "schema": "lovelyres-smoke-ready/v1",
        "status": "ready",
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("创建前端就绪标记失败: {}", error))?;
    file.write_all(payload.to_string().as_bytes())
        .map_err(|error| format!("写入前端就绪标记失败: {}", error))?;
    file.sync_all()
        .map_err(|error| format!("持久化前端就绪标记失败: {}", error))?;
    Ok(())
}

#[tauri::command]
pub fn report_frontend_ready() -> Result<(), String> {
    crate::alog_info!("LovelyRes 前端核心初始化完成");
    let Some(path) = std::env::var_os("LOVELYRES_SMOKE_READY_FILE") else {
        return Ok(());
    };
    write_frontend_ready_marker(Path::new(&path))
}

/// 记录 INFO 级日志（替代 println!）
#[macro_export]
macro_rules! alog_info {
    ($($arg:tt)*) => { $crate::app_log::log("INFO", format!($($arg)*)) };
}

/// 记录 WARN 级日志
#[macro_export]
macro_rules! alog_warn {
    ($($arg:tt)*) => { $crate::app_log::log("WARN", format!($($arg)*)) };
}

/// 记录 ERROR 级日志（替代 eprintln!）
#[macro_export]
macro_rules! alog_error {
    ($($arg:tt)*) => { $crate::app_log::log("ERROR", format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::write_frontend_ready_marker;

    #[test]
    fn ready_marker_is_single_use_and_limited_to_system_temp() {
        let path =
            std::env::temp_dir().join(format!("lovelyres-ready-{}.json", uuid::Uuid::new_v4()));
        write_frontend_ready_marker(&path).expect("write ready marker");
        let payload: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read ready marker"))
                .expect("parse ready marker");
        assert_eq!(payload["schema"], "lovelyres-smoke-ready/v1");
        assert_eq!(payload["status"], "ready");
        assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
        assert!(write_frontend_ready_marker(&path).is_err());
        std::fs::remove_file(path).expect("clean ready marker");

        let outside = std::env::current_dir()
            .expect("current directory")
            .join("lovelyres-ready-forbidden.json");
        assert!(write_frontend_ready_marker(&outside).is_err());
        assert!(!outside.exists());
    }
}
