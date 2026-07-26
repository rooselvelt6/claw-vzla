#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmbBeaconConfig {
    pub pipe_name: String,
    pub server_host: String,
    pub interval_secs: u64,
}

impl Default for SmbBeaconConfig {
    fn default() -> Self {
        SmbBeaconConfig {
            pipe_name: r"\\.\pipe\kraken-c2".to_string(),
            server_host: "127.0.0.1".to_string(),
            interval_secs: 30,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SmbCommand {
    pub action: String,
    pub args: String,
}

pub struct SmbBeacon {
    #[allow(dead_code)]
    config: SmbBeaconConfig,
    agent_id: String,
}

impl SmbBeacon {
    pub fn new(config: SmbBeaconConfig) -> Self {
        SmbBeacon {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config,
        }
    }

    pub fn with_agent_id(mut self, agent_id: &str) -> Self {
        self.agent_id = agent_id.to_string();
        self
    }

    pub fn check_pipe(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            let path = self.config.pipe_name.trim_start_matches(r"\\.\pipe\");
            std::path::Path::new(&format!(r"\\.\pipe\{}", path)).exists()
        }
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
    }

    pub fn enumerate_named_pipes() -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            let mut pipes = Vec::new();
            if let Ok(output) = std::process::Command::new("powershell")
                .args([
                    "-Command",
                    "Get-ChildItem -Path '\\\\.\\pipe\\' | Select-Object Name",
                ])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(3) {
                    let name = line.trim();
                    if !name.is_empty() && !name.contains('-') {
                        pipes.push(name.to_string());
                    }
                }
            }
            pipes
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }

    pub fn send_command(&self, cmd: &SmbCommand) -> Result<String, crate::C2Error> {
        let _ = cmd;
        Err(crate::C2Error::Protocol("SMB beacon requiere Windows con named pipes".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_config_default() {
        let config = SmbBeaconConfig::default();
        assert!(config.pipe_name.contains("kraken-c2"));
        assert_eq!(config.interval_secs, 30);
    }

    #[test]
    fn test_smb_command() {
        let cmd = SmbCommand {
            action: "exec".to_string(),
            args: "whoami".to_string(),
        };
        let json = serde_json::to_string_pretty(&cmd).unwrap();
        assert!(json.contains("exec"));
    }

    #[test]
    fn test_smb_beacon_agent_id() {
        let config = SmbBeaconConfig::default();
        let beacon = SmbBeacon::new(config).with_agent_id("smb-agent");
        assert_eq!(beacon.agent_id, "smb-agent");
    }

    #[test]
    fn test_check_pipe_linux() {
        let config = SmbBeaconConfig::default();
        let beacon = SmbBeacon::new(config);
        assert!(!beacon.check_pipe());
    }

    #[test]
    fn test_enumerate_pipes_linux() {
        let pipes = SmbBeacon::enumerate_named_pipes();
        assert!(pipes.is_empty());
    }

    #[test]
    fn test_send_command_non_windows() {
        let config = SmbBeaconConfig::default();
        let beacon = SmbBeacon::new(config);
        let cmd = SmbCommand {
            action: "exec".to_string(),
            args: "id".to_string(),
        };
        let result = beacon.send_command(&cmd);
        assert!(result.is_err());
    }

    #[test]
    fn test_smb_command_deserialize() {
        let json = r#"{"action":"upload","args":"/etc/passwd"}"#;
        let cmd: SmbCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.action, "upload");
    }
}
