// All SFTP operations (list, read, write, upload, download, compress, extract, chmod, get_file_details)

use tauri::State;
use crate::AppState;
use crate::ssh_manager_russh;

#[tauri::command]
pub async fn sftp_list_files(
    path: String,
    state: State<'_, AppState>,
) -> Result<Vec<ssh_manager_russh::SftpFileInfo>, String> {
    let manager = &state.ssh_manager;
    manager.list_sftp_files(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_read_file(
    path: String,
    max_bytes: Option<usize>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;
    let content = manager
        .read_sftp_file(&path)
        .map_err(|e| e.to_string())?;

    // Apply max_bytes limit if specified. If the cut lands in the middle of a
    // UTF-8 code point, keep the largest valid prefix instead of failing a
    // perfectly valid text file at an arbitrary network/UI byte limit.
    let was_truncated = max_bytes.is_some_and(|max| content.len() > max);
    let limited_content = if let Some(max) = max_bytes {
        if content.len() > max {
            content[..max].to_vec()
        } else {
            content
        }
    } else {
        content
    };

    match String::from_utf8(limited_content) {
        Ok(text) => Ok(text),
        Err(error) if was_truncated && error.utf8_error().error_len().is_none() => {
            let valid_up_to = error.utf8_error().valid_up_to();
            String::from_utf8(error.into_bytes()[..valid_up_to].to_vec())
                .map_err(|e| format!("Failed to decode file as UTF-8: {}", e))
        }
        Err(error) => Err(format!("Failed to decode file as UTF-8: {}", error)),
    }
}

#[tauri::command]
pub async fn sftp_chmod(path: String, mode: u32, state: State<'_, AppState>) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager.chmod_sftp(&path, mode).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_get_file_details(
    path: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::SftpFileDetails, String> {
    let manager = &state.ssh_manager;
    manager.get_file_details(&path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_write_file(
    path: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .write_sftp_file(&path, content.as_bytes())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_compress(
    source_path: String,
    target_path: String,
    format: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .compress_file(&source_path, &target_path, &format)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_extract(
    archive_path: String,
    target_dir: String,
    overwrite: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .extract_file(&archive_path, &target_dir, overwrite)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_upload(
    local_path: String,
    remote_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // local_path 来自 webview：只放行 save_temp_file 产出的受管暂存文件，
    // 否则一个 XSS 就能把 ~/.ssh/id_rsa 上传到攻击者控制的靶机上。
    crate::path_guard::ensure_managed_upload_source(&local_path)?;

    let manager = &state.ssh_manager;
    let result = manager
        .upload_file(&local_path, &remote_path)
        .map_err(|e| e.to_string());

    // Files created by save_temp_file are single-use staging files. Always
    // clean them up after the upload attempt, including failed remote writes.
    if is_managed_upload_temp_file(&local_path) {
        let _ = std::fs::remove_file(&local_path);
    }

    result
}

#[tauri::command]
pub async fn sftp_download(
    remote_path: String,
    local_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 部分缓解：拒 .. 与敏感目录。完整修复需把保存对话框挪进 Rust，
    // 让路径不经 webview 往返 —— 详见 path_guard::ensure_safe_download_target
    crate::path_guard::ensure_safe_download_target(&local_path)?;

    let manager = &state.ssh_manager;
    manager
        .download_file(&remote_path, &local_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_create_directory(
    remote_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .create_directory(&remote_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_rename(
    old_path: String,
    new_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .rename_sftp_file(&old_path, &new_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_delete(
    path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .delete_sftp_file(&path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_temp_file(file_name: String, data: Vec<u8>) -> Result<String, String> {
    use std::io::Write;

    let temp_dir = managed_upload_temp_dir();
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("创建临时目录失败: {}", e))?;

    // Never join a frontend-provided path directly onto the temp directory.
    // Keep only a short, inert extension and use a random filename to prevent
    // traversal, absolute-path replacement, collisions, and symlink races.
    let extension = std::path::Path::new(&file_name)
        .extension()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && value.len() <= 16)
        .filter(|value| value.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .map(|value| format!(".{}", value))
        .unwrap_or_default();
    let temp_file_path = temp_dir.join(format!("{}{}", uuid::Uuid::new_v4(), extension));

    // 写入文件数据
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_file_path)
        .map_err(|e| format!("创建临时文件失败: {}", e))?;

    file.write_all(&data)
        .map_err(|e| format!("写入临时文件失败: {}", e))?;

    // 返回临时文件路径
    Ok(temp_file_path.to_string_lossy().to_string())
}

// 实现已移入 crate::path_guard，与 sftp_upload 的准入校验共用同一份判定
use crate::path_guard::{is_managed_upload_temp_file, managed_upload_temp_dir};
