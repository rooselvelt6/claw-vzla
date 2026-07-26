//! Cryptographic utilities for secure storage - God Level Implementation

use aes_gcm::{
    aead::{KeyInit, OsRng},
    Aes256Gcm, Nonce as AesNonce,
};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, XNonce};
use kraken_errors::SecurityError;
use password_hash::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

const NONCE_SIZE_AES: usize = 12;
const NONCE_SIZE_XCHACHA: usize = 24;
const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    #[default]
    XChaCha20Poly1305,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum KdfAlgorithm {
    #[default]
    Argon2id,
    #[deprecated(note = "Use KdfAlgorithm::Argon2id instead — SHA-256 KDF is weak")]
    Sha256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KdfParams {
    pub mem_cost: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            mem_cost: 65536,
            time_cost: 4,
            lanes: 4,
        }
    }
}

impl KdfParams {
    pub fn interactive() -> Self {
        KdfParams {
            mem_cost: 65536,
            time_cost: 4,
            lanes: 4,
        }
    }

    pub fn sensitive() -> Self {
        KdfParams {
            mem_cost: 131072,
            time_cost: 6,
            lanes: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub algorithm: EncryptionAlgorithm,
    pub kdf: KdfAlgorithm,
    pub nonce: String,
    pub ciphertext: String,
    pub salt: Option<String>,
    pub params: Option<KdfParams>,
}

pub struct Key {
    algorithm: KdfAlgorithm,
    salt: [u8; SALT_SIZE],
    params: KdfParams,
    inner: [u8; KEY_SIZE],
}

impl Drop for Key {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl Key {
    pub fn generate() -> Self {
        let mut inner = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut inner);
        Key {
            algorithm: KdfAlgorithm::default(),
            salt: [0u8; SALT_SIZE],
            params: KdfParams::default(),
            inner,
        }
    }

    pub fn from_password_argon2id(
        password: &str,
        salt: &[u8; SALT_SIZE],
        params: KdfParams,
    ) -> Self {
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                params.mem_cost,
                params.time_cost,
                params.lanes,
                Some(KEY_SIZE),
            )
            .unwrap(),
        );

        let salt_str = password_hash::SaltString::encode_b64(salt).unwrap();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .unwrap();

        let hash_str = hash.to_string();
        let parsed = password_hash::PasswordHash::new(&hash_str).unwrap();
        let hash_bytes = parsed.hash.unwrap();

        let mut inner = [0u8; KEY_SIZE];
        let bytes = hash_bytes.as_bytes();
        inner.copy_from_slice(&bytes[..KEY_SIZE.min(bytes.len())]);

        Key {
            algorithm: KdfAlgorithm::Argon2id,
            salt: *salt,
            params,
            inner,
        }
    }

    #[deprecated(note = "Use Key::from_password_argon2id() instead — SHA-256 KDF is weak")]
    pub fn from_password_sha256(password: &str, salt: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();

        let mut inner = [0u8; KEY_SIZE];
        inner.copy_from_slice(&result[..KEY_SIZE]);

        let mut s = [0u8; SALT_SIZE];
        s[..salt.len().min(SALT_SIZE)].copy_from_slice(&salt[..salt.len().min(SALT_SIZE)]);

        Key {
            algorithm: KdfAlgorithm::Sha256,
            salt: s,
            params: KdfParams::default(),
            inner,
        }
    }

    pub fn constant_time_eq(&self, other: &Key) -> bool {
        bool::from(self.inner.ct_eq(&other.inner))
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.inner)
    }

    pub fn from_base64(encoded: &str) -> Option<Self> {
        let decoded = BASE64.decode(encoded).ok()?;
        if decoded.len() != KEY_SIZE {
            return None;
        }
        let mut inner = [0u8; KEY_SIZE];
        inner.copy_from_slice(&decoded);
        Some(Key {
            algorithm: KdfAlgorithm::default(),
            salt: [0u8; SALT_SIZE],
            params: KdfParams::default(),
            inner,
        })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.inner
    }

    pub fn algorithm(&self) -> KdfAlgorithm {
        self.algorithm
    }

    pub fn salt(&self) -> &[u8; SALT_SIZE] {
        &self.salt
    }

    pub fn params(&self) -> KdfParams {
        self.params
    }
}

pub struct Encryptor;

impl Encryptor {
    pub fn encrypt(data: &[u8], key: &Key) -> Result<EncryptedData, SecurityError> {
        Self::encrypt_with_algorithm(data, key, EncryptionAlgorithm::default())
    }

    pub fn encrypt_with_algorithm(
        data: &[u8],
        key: &Key,
        algorithm: EncryptionAlgorithm,
    ) -> Result<EncryptedData, SecurityError> {
        match algorithm {
            EncryptionAlgorithm::Aes256Gcm => Self::encrypt_aes(data, key),
            EncryptionAlgorithm::XChaCha20Poly1305 => Self::encrypt_chacha(data, key),
        }
    }

    fn encrypt_aes(data: &[u8], key: &Key) -> Result<EncryptedData, SecurityError> {
        let cipher = Aes256Gcm::new_from_slice(&key.inner)
            .map_err(|e| SecurityError::CipherInit(format!("AES cipher init failed: {}", e)))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE_AES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| SecurityError::Encrypt(format!("AES encryption failed: {}", e)))?;

        Ok(EncryptedData {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            kdf: key.algorithm,
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
            salt: Some(BASE64.encode(key.salt)),
            params: Some(key.params),
        })
    }

    fn encrypt_chacha(data: &[u8], key: &Key) -> Result<EncryptedData, SecurityError> {
        let cipher = XChaCha20Poly1305::new_from_slice(&key.inner)
            .map_err(|e| SecurityError::CipherInit(format!("XChaCha cipher init failed: {}", e)))?;

        let mut nonce_bytes = [0u8; NONCE_SIZE_XCHACHA];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| SecurityError::Encrypt(format!("XChaCha encryption failed: {}", e)))?;

        Ok(EncryptedData {
            algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
            kdf: key.algorithm,
            nonce: BASE64.encode(nonce_bytes),
            ciphertext: BASE64.encode(ciphertext),
            salt: Some(BASE64.encode(key.salt)),
            params: Some(key.params),
        })
    }

    pub fn decrypt(encrypted: &EncryptedData, key: &Key) -> Result<Vec<u8>, SecurityError> {
        match encrypted.algorithm {
            EncryptionAlgorithm::Aes256Gcm => Self::decrypt_aes(encrypted, key),
            EncryptionAlgorithm::XChaCha20Poly1305 => Self::decrypt_chacha(encrypted, key),
        }
    }

    fn decrypt_aes(encrypted: &EncryptedData, key: &Key) -> Result<Vec<u8>, SecurityError> {
        let cipher = Aes256Gcm::new_from_slice(&key.inner)
            .map_err(|e| SecurityError::CipherInit(format!("AES cipher init failed: {}", e)))?;

        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|e| SecurityError::Decode(format!("AES nonce decode failed: {}", e)))?;
        let ciphertext = BASE64
            .decode(&encrypted.ciphertext)
            .map_err(|e| SecurityError::Decode(format!("AES ciphertext decode failed: {}", e)))?;

        let nonce = AesNonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| SecurityError::Decrypt(format!("AES decryption failed: {}", e)))
    }

    fn decrypt_chacha(encrypted: &EncryptedData, key: &Key) -> Result<Vec<u8>, SecurityError> {
        let cipher = XChaCha20Poly1305::new_from_slice(&key.inner)
            .map_err(|e| SecurityError::CipherInit(format!("XChaCha cipher init failed: {}", e)))?;

        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|e| SecurityError::Decode(format!("XChaCha nonce decode failed: {}", e)))?;
        let ciphertext = BASE64
            .decode(&encrypted.ciphertext)
            .map_err(|e| SecurityError::Decode(format!("XChaCha ciphertext decode failed: {}", e)))?;

        let nonce = XNonce::from_slice(&nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| SecurityError::Decrypt(format!("XChaCha decryption failed: {}", e)))
    }
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate();
        let encoded = key.to_base64();
        let decoded = Key::from_base64(&encoded).unwrap();
        assert!(key.constant_time_eq(&decoded));
    }

    #[test]
    fn test_argon2id_key_derivation() {
        let password = "kraken-god-level-2026";
        let salt = [1u8; SALT_SIZE];
        let params = KdfParams::interactive();

        let key = Key::from_password_argon2id(password, &salt, params);
        assert_eq!(key.algorithm(), KdfAlgorithm::Argon2id);

        let key2 = Key::from_password_argon2id(password, &salt, params);
        assert!(key.constant_time_eq(&key2));
    }

    #[test]
    #[allow(deprecated)]
    fn test_sha256_legacy_compatibility() {
        let password = "legacy-password";
        let salt = [2u8; SALT_SIZE];

        let key = Key::from_password_sha256(password, &salt);
        assert_eq!(key.algorithm(), KdfAlgorithm::Sha256);
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = Key::generate();
        let plaintext = b"API_KEY=sk-test-12345-vzla";

        let encrypted =
            Encryptor::encrypt_with_algorithm(plaintext, &key, EncryptionAlgorithm::Aes256Gcm)
                .unwrap();
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::Aes256Gcm);

        let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    #[test]
    fn test_xchacha_encrypt_decrypt() {
        let key = Key::generate();
        let plaintext = b"API_KEY=sk-test-12345-vzla-xchacha";

        let encrypted = Encryptor::encrypt_with_algorithm(
            plaintext,
            &key,
            EncryptionAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();
        assert_eq!(encrypted.algorithm, EncryptionAlgorithm::XChaCha20Poly1305);

        let decrypted = Encryptor::decrypt(&encrypted, &key).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    #[test]
    fn test_algorithm_agility() {
        let key = Key::generate();
        let plaintext = b"test-agility";

        let aes_enc =
            Encryptor::encrypt_with_algorithm(plaintext, &key, EncryptionAlgorithm::Aes256Gcm)
                .unwrap();
        let xchacha_enc = Encryptor::encrypt_with_algorithm(
            plaintext,
            &key,
            EncryptionAlgorithm::XChaCha20Poly1305,
        )
        .unwrap();

        let aes_dec = Encryptor::decrypt(&aes_enc, &key).unwrap();
        let xchacha_dec = Encryptor::decrypt(&xchacha_enc, &key).unwrap();

        assert_eq!(plaintext.as_slice(), &aes_dec);
        assert_eq!(plaintext.as_slice(), &xchacha_dec);
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &a[..31]));
    }

    #[test]
    fn test_owasp_params() {
        let interactive = KdfParams::interactive();
        assert_eq!(interactive.mem_cost, 65536);
        assert_eq!(interactive.time_cost, 4);

        let sensitive = KdfParams::sensitive();
        assert_eq!(sensitive.mem_cost, 131072);
        assert_eq!(sensitive.time_cost, 6);
    }
}
