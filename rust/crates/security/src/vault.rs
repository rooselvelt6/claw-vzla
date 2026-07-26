use base64::Engine;
use kraken_errors::SecurityError;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::crypto::{EncryptedData, EncryptionAlgorithm, Encryptor, KdfParams, Key};

const VAULT_VERSION: u32 = 1;
const SALT_SIZE: usize = 16;

#[derive(Debug)]
pub struct MasterKey {
    inner: Vec<u8>,
    locked: bool,
}

impl MasterKey {
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("KRAKEN_MASTER_KEY").ok()?;
        if key.is_empty() {
            return None;
        }
        Self::from_password(&key)
    }

    pub fn from_password(password: &str) -> Option<Self> {
        let mut inner = password.as_bytes().to_vec();
        #[cfg(unix)]
        let locked = unsafe { lock_memory(&mut inner) };
        #[cfg(not(unix))]
        let locked = false;
        Some(Self { inner, locked })
    }

    pub fn derive_key(&self, salt: &[u8; SALT_SIZE], params: KdfParams) -> Key {
        let password = String::from_utf8_lossy(&self.inner);
        Key::from_password_argon2id(&password, salt, params)
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.locked {
            unsafe { unlock_memory(&mut self.inner) };
        }
        self.inner.zeroize();
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct VaultFile {
    version: u32,
    algorithm: EncryptionAlgorithm,
    kdf_params: KdfParams,
    salt: String,
    encrypted: EncryptedData,
}

#[derive(Debug)]
pub struct CredentialVault {
    path: PathBuf,
    data: serde_json::Value,
    algorithm: EncryptionAlgorithm,
    kdf_params: KdfParams,
}

impl CredentialVault {
    pub fn open_or_create(path: PathBuf, master_key: &MasterKey) -> Result<Self, SecurityError> {
        if path.exists() {
            Self::open(path, master_key)
        } else {
            let vault = Self {
                path,
                data: serde_json::Value::Object(serde_json::Map::new()),
                algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
                kdf_params: KdfParams::sensitive(),
            };
            vault.save(master_key)?;
            Ok(vault)
        }
    }

    pub fn open(path: PathBuf, master_key: &MasterKey) -> Result<Self, SecurityError> {
        let content = fs::read_to_string(&path)?;

        if let Ok(vault_file) = serde_json::from_str::<VaultFile>(&content) {
            let salt_bytes = base64_decode_array(&vault_file.salt)?;
            let key = master_key.derive_key(&salt_bytes, vault_file.kdf_params);
            let decrypted = Encryptor::decrypt(&vault_file.encrypted, &key)?;
            let data: serde_json::Value = serde_json::from_slice(&decrypted)?;
            Ok(Self {
                path,
                data,
                algorithm: vault_file.algorithm,
                kdf_params: vault_file.kdf_params,
            })
        } else if let Ok(root) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&content) {
            let data = serde_json::Value::Object(root);
            let vault = Self {
                path,
                data,
                algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
                kdf_params: KdfParams::sensitive(),
            };
            vault.save(master_key)?;
            Ok(vault)
        } else {
            Err(SecurityError::Vault("vault file is not valid encrypted nor plain JSON".into()))
        }
    }

    pub fn save(&self, master_key: &MasterKey) -> Result<(), SecurityError> {
        let salt = random_salt();
        let key = master_key.derive_key(&salt, self.kdf_params);
        let plaintext = serde_json::to_vec_pretty(&self.data)?;
        let encrypted = Encryptor::encrypt_with_algorithm(&plaintext, &key, self.algorithm)?;

        let vault_file = VaultFile {
            version: VAULT_VERSION,
            algorithm: self.algorithm,
            kdf_params: self.kdf_params,
            salt: base64_encode_array(&salt),
            encrypted,
        };

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let rendered = serde_json::to_string_pretty(&vault_file)?;

        let temp_path = self.path.with_extension("vault.tmp");
        fs::write(&temp_path, format!("{rendered}\n"))?;

        #[cfg(unix)]
        set_600_permissions(&temp_path)?;

        fs::rename(&temp_path, &self.path)?;

        #[cfg(unix)]
        set_600_permissions(&self.path)?;

        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    pub fn set(&mut self, key: &str, value: serde_json::Value) {
        if let Some(obj) = self.data.as_object_mut() {
            obj.insert(key.to_string(), value);
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        if let Some(obj) = self.data.as_object_mut() {
            obj.remove(key)
        } else {
            None
        }
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        self.data.get(key)?.as_str().map(String::from)
    }

    pub fn data(&self) -> &serde_json::Value {
        &self.data
    }

    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    pub fn set_algorithm(&mut self, algorithm: EncryptionAlgorithm) {
        self.algorithm = algorithm;
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn random_salt() -> [u8; SALT_SIZE] {
    use rand::Rng;
    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill_bytes(&mut salt);
    salt
}

fn base64_encode_array(arr: &[u8; SALT_SIZE]) -> String {
    base64::engine::general_purpose::STANDARD.encode(arr)
}

fn base64_decode_array(s: &str) -> Result<[u8; SALT_SIZE], SecurityError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| SecurityError::Decode(format!("base64 decode: {e}")))?;
    if decoded.len() != SALT_SIZE {
        return Err(SecurityError::Decode(format!("salt length mismatch: got {}", decoded.len())));
    }
    let mut arr = [0u8; SALT_SIZE];
    arr.copy_from_slice(&decoded);
    Ok(arr)
}

#[cfg(unix)]
fn set_600_permissions(path: &PathBuf) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
unsafe fn lock_memory(data: &mut [u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    libc::mlock(data.as_ptr() as *const std::ffi::c_void, data.len()) == 0
}

#[cfg(unix)]
unsafe fn unlock_memory(data: &mut [u8]) {
    if data.is_empty() {
        return;
    }
    let _ = libc::munlock(data.as_ptr() as *const std::ffi::c_void, data.len());
}

pub fn vault_path() -> Result<PathBuf, SecurityError> {
    if let Some(path) = std::env::var_os("KRAKEN_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("credentials.vault"));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| SecurityError::Vault("HOME not set".into()))?;
    Ok(PathBuf::from(home).join(".kraken").join("credentials.vault"))
}

pub fn legacy_json_path() -> Result<PathBuf, SecurityError> {
    if let Some(path) = std::env::var_os("KRAKEN_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("credentials.json"));
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| SecurityError::Vault("HOME not set".into()))?;
    Ok(PathBuf::from(home).join(".kraken").join("credentials.json"))
}

pub fn open_credential_vault(master_key: &MasterKey) -> Result<CredentialVault, SecurityError> {
    let vault_p = vault_path()?;
    if vault_p.exists() {
        return CredentialVault::open(vault_p, master_key);
    }
    let legacy_p = legacy_json_path()?;
    if legacy_p.exists() {
        eprintln!("[kraken] migrating legacy credentials.json to encrypted vault...");
        let content = fs::read_to_string(&legacy_p)?;
        let root: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&content)?;
        let data = serde_json::Value::Object(root);
        let vault = CredentialVault {
            path: vault_p.clone(),
            data,
            algorithm: EncryptionAlgorithm::XChaCha20Poly1305,
            kdf_params: KdfParams::sensitive(),
        };
        vault.save(master_key)?;
        fs::rename(&legacy_p, legacy_p.with_extension("json.bak"))?;
        eprintln!("[kraken] migrated to encrypted vault at {}", vault_p.display());
        return Ok(vault);
    }
    CredentialVault::open_or_create(vault_p, master_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_master_key() -> MasterKey {
        MasterKey::from_password("test-master-key-2027-kraken").unwrap()
    }

    #[test]
    fn test_vault_create_save_load() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.vault");
        let master_key = test_master_key();

        let mut vault = CredentialVault::open_or_create(path.clone(), &master_key).unwrap();
        vault.set("oauth", serde_json::json!({
            "access_token": "test-token",
            "refresh_token": "test-refresh",
        }));
        vault.save(&master_key).unwrap();

        let loaded = CredentialVault::open(path.clone(), &master_key).unwrap();
        assert_eq!(
            loaded.get_string("oauth"),
            None
        );
        assert!(loaded.get("oauth").is_some());
    }

    #[test]
    fn test_legacy_migration() {
        let tmp = TempDir::new().unwrap();
        let legacy = tmp.path().join("credentials.json");

        fs::write(&legacy, r#"{"oauth":{"access_token":"legacy-token"}}"#).unwrap();

        let master_key = MasterKey::from_password("migration-test-key").unwrap();

        std::env::set_var("KRAKEN_CONFIG_HOME", tmp.path());
        let vault = open_credential_vault(&master_key).unwrap();
        assert!(vault.get("oauth").is_some());
        assert!(!legacy.exists(), "legacy should be renamed to .bak");
        assert!(legacy.with_extension("json.bak").exists());
        std::env::remove_var("KRAKEN_CONFIG_HOME");
    }

    #[test]
    fn test_master_key_roundtrip() {
        let key = MasterKey::from_password("secure-password-123").unwrap();
        let salt = random_salt();
        let params = KdfParams::interactive();
        let derived = key.derive_key(&salt, params);
        assert_eq!(derived.algorithm(), crate::crypto::KdfAlgorithm::Argon2id);
    }
}
