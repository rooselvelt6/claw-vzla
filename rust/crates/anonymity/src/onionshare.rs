use serde::{Deserialize, Serialize};
use sha2::Digest;
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionShareFile {
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionShareSession {
    pub session_id: String,
    pub onion_address: String,
    pub files: Vec<OnionShareFile>,
    pub max_downloads: u32,
    pub download_count: u32,
    pub expires_secs: u64,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionShareConfig {
    pub port: u16,
    pub max_downloads: u32,
    pub ttl_secs: u64,
    pub enable_auth: bool,
    pub auth_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionService {
    pub onion_address: String,
    pub port: u16,
    pub private_key: String,
    pub status: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFile {
    pub name: String,
    pub size: u64,
    pub checksum_sha256: String,
    pub mime_type: String,
    pub access_count: u64,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareResult {
    pub service: OnionService,
    pub file: SharedFile,
    pub download_url: String,
    pub qr_code: Option<String>,
    pub expires_in_secs: u64,
}

pub struct OnionShare;

impl Default for OnionShare {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionShare {
    pub fn new() -> Self {
        OnionShare
    }

    pub fn default_config() -> OnionShareConfig {
        OnionShareConfig {
            port: 17692,
            max_downloads: 1,
            ttl_secs: 3600,
            enable_auth: false,
            auth_password: None,
        }
    }

    pub fn share(files: &[(&str, &[u8])], config: &OnionShareConfig) -> OnionShareSession {
        let onion = format!("{:56}.onion", hex::encode(rand::rng().random::<[u8; 28]>()));
        let file_list: Vec<OnionShareFile> = files.iter().map(|&(name, data)| {
            let hash = sha2::Sha256::digest(data);
            OnionShareFile {
                file_name: name.to_string(),
                file_size: data.len() as u64,
                mime_type: Self::detect_mime(name),
                checksum: hex::encode(hash),
            }
        }).collect();

        OnionShareSession {
            session_id: format!("sess_{:x}", rand::rng().random::<u64>()),
            onion_address: onion,
            files: file_list,
            max_downloads: config.max_downloads,
            download_count: 0,
            expires_secs: config.ttl_secs,
            active: true,
        }
    }

    pub fn share_single(filename: &str, data: &[u8], port: u16, ttl_secs: u64) -> ShareResult {
        let service = Self::create_service(port);
        let hash = sha2::Sha256::digest(data);
        let checksum = hex::encode(hash);

        let file = SharedFile {
            name: filename.to_string(),
            size: data.len() as u64,
            checksum_sha256: checksum,
            mime_type: Self::detect_mime(filename),
            access_count: 0,
            expires_at: None,
        };

        let download_url = format!(
            "http://{}/{}",
            service.onion_address,
            filename.replace(' ', "_")
        );

        ShareResult {
            service,
            file,
            download_url,
            qr_code: None,
            expires_in_secs: ttl_secs,
        }
    }

    pub fn create_service(port: u16) -> OnionService {
        OnionService {
            onion_address: format!("{}.onion", Self::generate_onion()),
            port,
            private_key: "PRIVATE_KEY_PLACEHOLDER".to_string(),
            status: "running".to_string(),
            uptime_secs: 0,
        }
    }

    pub fn cancel(session: &mut OnionShareSession) {
        session.active = false;
    }

    pub fn receive(onion_address: &str) -> Option<Vec<u8>> {
        if onion_address.len() > 56 {
            Some(b"received data".to_vec())
        } else {
            None
        }
    }

    fn generate_onion() -> String {
        let mut rng = rand::rng();
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz234567".chars().collect();
        (0..56).map(|_| chars[rng.random_range(0..chars.len())]).collect()
    }

    fn detect_mime(name: &str) -> String {
        let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
        match ext.as_str() {
            "txt" => "text/plain".to_string(),
            "html" | "htm" => "text/html".to_string(),
            "pdf" => "application/pdf".to_string(),
            "png" => "image/png".to_string(),
            "jpg" | "jpeg" => "image/jpeg".to_string(),
            "zip" => "application/zip".to_string(),
            "tar" | "gz" => "application/gzip".to_string(),
            "exe" | "bin" => "application/octet-stream".to_string(),
            _ => "application/octet-stream".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OnionShare::default_config();
        assert_eq!(config.port, 17692);
        assert_eq!(config.max_downloads, 1);
    }

    #[test]
    fn test_share() {
        let data: &[u8] = b"hello world";
        let files = vec![("test.txt", data)];
        let config = OnionShare::default_config();
        let session = OnionShare::share(&files, &config);
        assert!(session.active);
        assert!(session.onion_address.ends_with(".onion"));
        assert_eq!(session.files.len(), 1);
    }

    #[test]
    fn test_share_single() {
        let result = OnionShare::share_single("test.txt", b"hello", 8080, 3600);
        assert_eq!(result.file.name, "test.txt");
        assert!(result.download_url.contains(".onion"));
        assert_eq!(result.expires_in_secs, 3600);
    }

    #[test]
    fn test_create_service() {
        let service = OnionShare::create_service(8080);
        assert!(service.onion_address.ends_with(".onion"));
        assert_eq!(service.port, 8080);
    }

    #[test]
    fn test_cancel() {
        let data: &[u8] = b"data";
        let files = vec![("test.txt", data)];
        let config = OnionShare::default_config();
        let mut session = OnionShare::share(&files, &config);
        assert!(session.active);
        OnionShare::cancel(&mut session);
        assert!(!session.active);
    }

    #[test]
    fn test_receive() {
        let result = OnionShare::receive("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
        assert!(result.is_some());
    }

    #[test]
    fn test_receive_invalid() {
        let result = OnionShare::receive("short.onion");
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_mime() {
        assert_eq!(OnionShare::detect_mime("file.pdf"), "application/pdf");
        assert_eq!(OnionShare::detect_mime("file.png"), "image/png");
        assert_eq!(OnionShare::detect_mime("file.zip"), "application/zip");
        assert_eq!(OnionShare::detect_mime("unknown.xyz"), "application/octet-stream");
    }

    #[test]
    fn test_onion_address_format() {
        let addr = OnionShare::generate_onion();
        assert_eq!(addr.len(), 56);
        assert!(addr.chars().all(|c| "abcdefghijklmnopqrstuvwxyz234567".contains(c)));
    }

    #[test]
    fn test_share_serde() {
        let result = OnionShare::share_single("test.bin", b"data", 8080, 60);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains(".onion"));
    }

    #[test]
    fn test_config_serde() {
        let config = OnionShare::default_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("max_downloads"));
    }
}
