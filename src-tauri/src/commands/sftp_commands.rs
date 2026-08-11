// All SFTP operations (list, read, write, upload, download, compress, extract, chmod, get_file_details)

use crate::ssh_manager_russh;
use crate::AppState;
use tauri::State;

fn validate_remote_absolute_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 4096 || !path.starts_with('/') || path.contains('\0') {
        return Err("Remote path must be a non-empty absolute path".to_string());
    }
    if path.split('/').any(|part| part == "..") {
        return Err("Remote path must not contain parent traversal".to_string());
    }
    Ok(())
}

fn validate_atomic_write_request(
    path: &str,
    backup_path: &str,
    content_len: usize,
) -> Result<(), String> {
    validate_remote_absolute_path(path)?;
    validate_remote_absolute_path(backup_path)?;
    if content_len > 2 * 1024 * 1024 {
        return Err("Atomic editor writes are limited to 2 MiB".to_string());
    }
    let required_prefix = format!("{}.lovelyres.bak.", path);
    if !backup_path.starts_with(&required_prefix) {
        return Err("Backup path must use the target .lovelyres.bak.* namespace".to_string());
    }
    Ok(())
}

#[tauri::command]
pub async fn sftp_list_files(
    path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ssh_manager_russh::SftpFileInfo>, String> {
    let manager = &state.ssh_manager;
    manager
        .list_sftp_files_on_session(&session_id, &path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_read_file(
    path: String,
    max_bytes: Option<usize>,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let manager = &state.ssh_manager;
    let content = manager
        .read_sftp_file_on_session(&session_id, &path)
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
pub async fn sftp_chmod(
    path: String,
    mode: u32,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .chmod_sftp_on_session(&session_id, &path, mode)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_get_file_details(
    path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::SftpFileDetails, String> {
    let manager = &state.ssh_manager;
    manager
        .get_file_details_on_session(&session_id, &path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_write_file(
    path: String,
    content: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .write_sftp_file_on_session(&session_id, &path, content.as_bytes())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_atomic_write_file(
    path: String,
    backup_path: String,
    content: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager_russh::AtomicSftpWriteReceipt, String> {
    validate_atomic_write_request(&path, &backup_path, content.len())?;
    let manager = &state.ssh_manager;
    manager.atomic_write_sftp_file_on_session(&session_id, &path, &backup_path, content.as_bytes())
}

#[cfg(test)]
mod atomic_write_tests {
    use super::{validate_atomic_write_request, validate_remote_absolute_path};

    #[test]
    fn remote_path_rejects_relative_and_parent_traversal() {
        assert!(validate_remote_absolute_path("/etc/ssh/sshd_config").is_ok());
        assert!(validate_remote_absolute_path("etc/passwd").is_err());
        assert!(validate_remote_absolute_path("/etc/../tmp/x").is_err());
        assert!(validate_remote_absolute_path("/tmp/a\0b").is_err());
    }

    #[test]
    fn backup_namespace_is_target_specific() {
        let path = "/etc/ssh/sshd_config";
        assert!(
            validate_atomic_write_request(path, &format!("{}.lovelyres.bak.123", path), 1024)
                .is_ok()
        );
        assert!(validate_atomic_write_request(path, "/tmp/unrelated", 1024).is_err());
        assert!(validate_atomic_write_request(
            path,
            &format!("{}.lovelyres.bak.123", path),
            3 * 1024 * 1024
        )
        .is_err());
    }
}

#[tauri::command]
pub async fn sftp_compress(
    source_path: String,
    target_path: String,
    format: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .compress_file_on_session(&session_id, &source_path, &target_path, &format)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_extract(
    archive_path: String,
    target_dir: String,
    overwrite: bool,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .extract_file_on_session(&session_id, &archive_path, &target_dir, overwrite)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_upload(
    local_path: String,
    remote_path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // local_path 来自 webview：只放行 save_temp_file 产出的受管暂存文件，
    // 否则一个 XSS 就能把 ~/.ssh/id_rsa 上传到攻击者控制的靶机上。
    crate::path_guard::ensure_managed_upload_source(&local_path)?;

    let manager = &state.ssh_manager;
    let result = manager
        .upload_file_on_session(&session_id, &local_path, &remote_path)
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
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    // 部分缓解：拒 .. 与敏感目录。完整修复需把保存对话框挪进 Rust，
    // 让路径不经 webview 往返 —— 详见 path_guard::ensure_safe_download_target
    crate::path_guard::ensure_safe_download_target(&local_path)?;

    let manager = &state.ssh_manager;
    manager
        .download_file_on_session(&session_id, &remote_path, &local_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_create_directory(
    remote_path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .create_sftp_directory_on_session(&session_id, &remote_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_rename(
    old_path: String,
    new_path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .rename_sftp_file_on_session(&session_id, &old_path, &new_path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn sftp_delete(
    path: String,
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let manager = &state.ssh_manager;
    manager
        .delete_sftp_file_on_session(&session_id, &path)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_temp_file(file_name: String, data: Vec<u8>) -> Result<String, String> {
    use std::io::Write;

    let temp_dir = managed_upload_temp_dir();
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("创建临时目录失败: {}", e))?;

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
