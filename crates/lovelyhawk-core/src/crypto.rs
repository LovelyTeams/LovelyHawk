//! AES-256-GCM sealing for credentials stored in the portable data directory.

use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose};
use zeroize::Zeroizing;

use crate::{CoreError, CoreResult, PortableStore};

pub const ENC_PREFIX: &str = "enc:v1:";

/// A short-lived plaintext secret that zeroes its allocation on drop.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Process-local access to the portable encryption key.
#[derive(Clone)]
pub struct CryptoVault {
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for CryptoVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CryptoVault([REDACTED])")
    }
}

impl CryptoVault {
    pub fn load(store: &PortableStore) -> CoreResult<Self> {
        let key = store.load_or_create_secret_key(|| {
            let mut key = [0_u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        })?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
    }

    pub(crate) fn seal(&self, secret: &SecretValue) -> CoreResult<String> {
        encrypt_with_key(&self.key, secret.expose())
    }

    #[allow(dead_code)] // consumed by the SSH/AI domain services as they move into this crate
    pub(crate) fn open(&self, encrypted: &str) -> CoreResult<SecretValue> {
        decrypt_with_key(&self.key, encrypted).map(SecretValue::new)
    }
}

/// Detect the only ciphertext wire format accepted by the new core.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

fn encrypt_with_key(key: &[u8; 32], plaintext: &str) -> CoreResult<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|error| CoreError::Crypto(format!("cannot initialize cipher: {error}")))?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|error| CoreError::Crypto(format!("encryption failed: {error}")))?;
    let mut bytes = nonce_bytes.to_vec();
    bytes.extend_from_slice(&ciphertext);
    Ok(format!(
        "{ENC_PREFIX}{}",
        general_purpose::STANDARD.encode(bytes)
    ))
}

#[allow(dead_code)] // production entry is CryptoVault::open; unit vectors call this directly
fn decrypt_with_key(key: &[u8; 32], encrypted: &str) -> CoreResult<String> {
    let payload = encrypted
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| CoreError::Crypto("ciphertext is missing the enc:v1: prefix".to_owned()))?;
    let bytes = general_purpose::STANDARD
        .decode(payload)
        .map_err(|error| CoreError::Crypto(format!("invalid ciphertext base64: {error}")))?;
    if bytes.len() < 12 {
        return Err(CoreError::Crypto(
            "ciphertext is shorter than the nonce".to_owned(),
        ));
    }
    let (nonce, ciphertext) = bytes.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|error| CoreError::Crypto(format!("cannot initialize cipher: {error}")))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|error| CoreError::Crypto(format!("authentication failed: {error}")))?;
    String::from_utf8(plaintext)
        .map_err(|error| CoreError::Crypto(format!("plaintext is not UTF-8: {error}")))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-crypto-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn matches_enc_v1_roundtrip_vectors() {
        let key = [42_u8; 32];
        for plaintext in ["sk-test-api-key-12345", "", "中文密钥🔑", "line1\nline2"] {
            let encrypted = encrypt_with_key(&key, plaintext).unwrap();
            assert!(is_encrypted(&encrypted));
            assert!(!encrypted.contains(plaintext) || plaintext.is_empty());
            assert_eq!(decrypt_with_key(&key, &encrypted).unwrap(), plaintext);
        }
    }

    #[test]
    fn rejects_plaintext_corruption_and_wrong_keys() {
        let key = [42_u8; 32];
        for invalid in ["sk-plaintext", "enc:v2:AAAA", "", "enc:v1:not-base64!!!"] {
            assert!(decrypt_with_key(&key, invalid).is_err());
        }
        let encrypted = encrypt_with_key(&key, "secret").unwrap();
        assert!(decrypt_with_key(&[7_u8; 32], &encrypted).is_err());

        let mut tampered = encrypted.into_bytes();
        let index = tampered.len() - 2;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        assert!(decrypt_with_key(&key, std::str::from_utf8(&tampered).unwrap()).is_err());
    }

    #[test]
    fn key_lives_only_below_explicit_portable_root() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let first = CryptoVault::load(&store).unwrap();
        let encrypted = first.seal(&SecretValue::new("password")).unwrap();
        drop(first);

        assert_eq!(
            fs::metadata(store.root().join("encryption.key"))
                .unwrap()
                .len(),
            32
        );
        let second = CryptoVault::load(&store).unwrap();
        assert_eq!(second.open(&encrypted).unwrap().expose(), "password");
    }
}
