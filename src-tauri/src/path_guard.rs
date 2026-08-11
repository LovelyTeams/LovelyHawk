//! 本地路径防护
//!
//! `sftp_upload` / `sftp_download` 的 `local_path` 直接来自 webview。
//! 注意这两条的受害者是**应急人员自己的工作机**，不是被检目标 —— 一个 XSS
//! 可以把 `~/.ssh/id_rsa` 上传到攻击者控制的靶机（横向移动到响应方），
//! 或把远端内容覆写到本地任意文件。

use std::path::{Path, PathBuf};

/// 受管上传暂存目录：save_temp_file 写入、sftp_upload 读取的唯一位置
pub fn managed_upload_temp_dir() -> PathBuf {
    std::env::temp_dir().join("lovelyres-upload")
}

/// 判断路径是否是 save_temp_file 产出的受管暂存文件
pub fn is_managed_upload_temp_file(path: &str) -> bool {
    let Ok(candidate) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(root) = std::fs::canonicalize(managed_upload_temp_dir()) else {
        return false;
    };
    candidate.parent() == Some(root.as_path())
}

/// 上传源必须是受管暂存文件。
///
/// 这条限制之所以能收得这么死，是因为前端唯一的上传路径本来就是
/// `save_temp_file(bytes)` → 拿到 UUID 路径 → `sftp_upload(那个路径)`：
/// 用户是通过 `<input type=file>` 选的文件，字节由前端交给 Rust 落盘。
/// 也就是说合法流程**从不**传一个任意本地路径进来，收紧零 UX 代价，
/// 却彻底消掉了"任意本地文件读取并外传"这个原语。
pub fn ensure_managed_upload_source(local_path: &str) -> Result<(), String> {
    if is_managed_upload_temp_file(local_path) {
        return Ok(());
    }
    Err(format!(
        "上传源必须是通过 save_temp_file 暂存的文件，拒绝任意本地路径: {}",
        local_path
    ))
}

/// 下载目标里绝对不能碰的目录（相对用户主目录）
const SENSITIVE_HOME_SUBDIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/LovelyRes",
    ".docker",
    ".kube",
];

/// 校验下载落盘路径。
///
/// 这里刻意**不**收敛到某个固定下载根目录：前端主路径
/// （sftpContextMenuHandler）走的是 `dialog.save()`，由用户自己挑位置 ——
/// 那本来就是正确的授权模型，锁死目录反而会打断它。
///
/// **这是部分缓解，不是完整修复。** 后端无从分辨路径究竟来自保存对话框
/// 还是注入脚本。彻底的做法是把对话框挪进 Rust（tauri-plugin-dialog 已是
/// 依赖），让路径根本不经过 webview 往返。那是独立的 UX 改造。
pub fn ensure_safe_download_target(local_path: &str) -> Result<(), String> {
    let path = Path::new(local_path);

    if local_path.trim().is_empty() {
        return Err("下载目标路径不能为空".to_string());
    }
    // 目标文件通常还不存在，所以校验它的父目录
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("下载目标路径不允许包含 ..: {}", local_path));
    }

    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };
    // 父目录可能尚未创建，canonicalize 失败时退回原始路径比较
    let target = std::fs::canonicalize(path.parent().unwrap_or(path))
        .unwrap_or_else(|_| path.parent().unwrap_or(path).to_path_buf());

    for sub in SENSITIVE_HOME_SUBDIRS {
        let mut forbidden = home.clone();
        for part in sub.split('/') {
            forbidden.push(part);
        }
        let forbidden = std::fs::canonicalize(&forbidden).unwrap_or(forbidden);
        if target == forbidden || target.starts_with(&forbidden) {
            return Err(format!("拒绝写入敏感目录 {}: {}", sub, local_path));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_rejects_arbitrary_local_paths() {
        // 这些都不在受管暂存目录里，必须拒绝
        for p in [
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            "../../secret.txt",
            "",
        ] {
            assert!(
                ensure_managed_upload_source(p).is_err(),
                "上传源不该放行 {p}"
            );
        }
    }

    #[test]
    fn download_rejects_parent_dir_traversal() {
        assert!(ensure_safe_download_target("../../evil").is_err());
        assert!(ensure_safe_download_target("a/../../b").is_err());
        assert!(ensure_safe_download_target("").is_err());
    }

    #[test]
    fn download_rejects_sensitive_home_dirs() {
        let Some(home) = dirs::home_dir() else { return };
        let ssh = home.join(".ssh").join("authorized_keys");
        // 仅当 ~/.ssh 真实存在时该用例才有意义（canonicalize 需要真实路径）
        if home.join(".ssh").is_dir() {
            assert!(
                ensure_safe_download_target(&ssh.to_string_lossy()).is_err(),
                "不该允许写入 ~/.ssh"
            );
        }
    }

    #[test]
    fn download_allows_ordinary_targets() {
        let tmp = std::env::temp_dir().join("lovelyres-dl-test.bin");
        assert!(ensure_safe_download_target(&tmp.to_string_lossy()).is_ok());
    }
}
