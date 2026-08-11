//! 共享加密模块
//!
//! AES-256-GCM 文本加解密，密钥与 SSH 连接密码共用同一份
//! `app_data_dir/encryption.key`。
//!
//! 文本密文格式：`enc:v1:` + base64(nonce ‖ ciphertext)，用于 AI API Key 等
//! 需要落盘的文本密文。SSH 连接密码的既有 base64(nonce‖ciphertext) 线格式
//! 保留在 ssh_connection_manager.rs 中，不受影响——两者只差 `enc:v1:` 前缀。

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use std::fs;
use std::path::Path;

/// 加密文本的版本前缀。用于识别密文、拒绝把明文误当密文解密。
pub const ENC_PREFIX: &str = "enc:v1:";

/// 加载或创建 AES-256 加密密钥（`app_data_dir/encryption.key`）。
///
/// 与 SSH 连接密码共用同一把密钥与同一个密钥文件；路径与生成逻辑与
/// ssh_connection_manager 原有实现逐字节一致，存量密文不受影响。
pub fn get_or_create_encryption_key() -> Result<[u8; 32], String> {
    let data_paths =
        crate::types::AppDataPaths::new().map_err(|e| format!("获取应用数据目录失败: {}", e))?;
    load_or_create_key(&data_paths.app_data_dir)
}

fn load_or_create_key(app_data_dir: &Path) -> Result<[u8; 32], String> {
    let key_file = app_data_dir.join("encryption.key");

    if key_file.exists() {
        // 加载现有密钥
        let key_data = fs::read(&key_file).map_err(|e| format!("读取加密密钥失败: {}", e))?;

        if key_data.len() != 32 {
            return Err("加密密钥长度错误".to_string());
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);

        crate::alog_info!("加载现有加密密钥");
        Ok(key)
    } else {
        // 生成新密钥
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        // 保存密钥
        fs::write(&key_file, &key).map_err(|e| format!("保存加密密钥失败: {}", e))?;

        crate::alog_info!("生成新的加密密钥");
        Ok(key)
    }
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("创建加密器失败: {}", e))?;

    // 生成随机nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("文本加密失败: {}", e))?;

    // 将nonce和密文组合，加版本前缀后编码为base64
    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);

    Ok(format!(
        "{}{}",
        ENC_PREFIX,
        general_purpose::STANDARD.encode(encrypted_data)
    ))
}

fn decrypt_with_key(key: &[u8; 32], input: &str) -> Result<String, String> {
    let encoded = input
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| "密文缺少 enc:v1: 前缀，拒绝按密文解密".to_string())?;

    let encrypted_data = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64解码失败: {}", e))?;

    if encrypted_data.len() < 12 {
        return Err("加密数据格式错误".to_string());
    }

    // 分离nonce和密文
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("创建解密器失败: {}", e))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("文本解密失败: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("解密结果不是有效UTF-8: {}", e))
}

/// 加密文本为 `enc:v1:` 格式密文。
pub fn encrypt_text(plaintext: &str) -> Result<String, String> {
    let key = get_or_create_encryption_key()?;
    encrypt_with_key(&key, plaintext)
}

/// 解密 `enc:v1:` 格式密文。非该格式的输入会明确报错，绝不静默放行。
pub fn decrypt_text(input: &str) -> Result<String, String> {
    let key = get_or_create_encryption_key()?;
    decrypt_with_key(&key, input)
}

/// 判断字符串是否已是 `enc:v1:` 格式密文。
pub fn is_encrypted(s: &str) -> bool {
    s.starts_with(ENC_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        // 固定密钥，避免测试读写真实 app_data_dir
        [42u8; 32]
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let plaintext = "sk-test-api-key-12345";
        let encrypted = encrypt_with_key(&key, plaintext).unwrap();
        assert!(encrypted.starts_with(ENC_PREFIX));
        assert!(!encrypted.contains(plaintext));
        assert_eq!(decrypt_with_key(&key, &encrypted).unwrap(), plaintext);
    }

    #[test]
    fn roundtrip_unicode_and_empty() {
        let key = test_key();
        for plaintext in ["", "中文密钥🔑", "line1\nline2"] {
            let encrypted = encrypt_with_key(&key, plaintext).unwrap();
            assert_eq!(decrypt_with_key(&key, &encrypted).unwrap(), plaintext);
        }
    }

    #[test]
    fn decrypt_rejects_non_prefixed_input() {
        let key = test_key();
        // 明文 Key / 垃圾 / SSH 风格的无前缀 base64 都必须报错
        assert!(decrypt_with_key(&key, "sk-plaintext").is_err());
        assert!(decrypt_with_key(&key, "enc:v2:AAAA").is_err());
        assert!(decrypt_with_key(&key, "").is_err());
        let ssh_style = general_purpose::STANDARD.encode(b"0123456789abcdef0123456789");
        assert!(decrypt_with_key(&key, &ssh_style).is_err());
    }

    #[test]
    fn decrypt_rejects_garbage_after_prefix() {
        let key = test_key();
        assert!(decrypt_with_key(&key, "enc:v1:not-valid-base64!!!").is_err());
        // 合法 base64 但太短（不足 nonce 长度）
        let short = general_purpose::STANDARD.encode(b"short");
        assert!(decrypt_with_key(&key, &format!("enc:v1:{}", short)).is_err());
        // 篡改一个字符，GCM 认证必须失败
        let encrypted = encrypt_with_key(&key, "secret").unwrap();
        let mut tampered = encrypted.clone();
        let pos = tampered.len() - 2;
        let orig = tampered.as_bytes()[pos] as char;
        let replacement = if orig == 'A' { 'B' } else { 'A' };
        tampered.replace_range(pos..pos + 1, &replacement.to_string());
        assert!(decrypt_with_key(&key, &tampered).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let encrypted = encrypt_with_key(&test_key(), "secret").unwrap();
        let other_key = [7u8; 32];
        assert!(decrypt_with_key(&other_key, &encrypted).is_err());
    }

    #[test]
    fn is_encrypted_detection() {
        assert!(is_encrypted("enc:v1:AAAA"));
        assert!(!is_encrypted("sk-plaintext"));
        assert!(!is_encrypted(""));
        assert!(!is_encrypted("enc:v2:AAAA"));
        assert!(!is_encrypted(" enc:v1:AAAA"));
    }
}
