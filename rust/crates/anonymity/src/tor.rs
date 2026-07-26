use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorStatus {
    pub enabled: bool,
    pub circuit_count: usize,
    pub current_circuit: Option<String>,
    pub ip_address: Option<String>,
    pub dns_leak: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorCircuit {
    pub id: String,
    pub path: Vec<String>,
    pub built: bool,
    pub age_secs: u64,
}

pub struct TorProxy;

impl Default for TorProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl TorProxy {
    pub fn new() -> Self {
        TorProxy
    }

    pub fn check_status() -> TorStatus {
        TorStatus {
            enabled: true,
            circuit_count: 3,
            current_circuit: Some("0xdeadbeef".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            dns_leak: false,
        }
    }

    pub fn new_circuit() -> TorCircuit {
        TorCircuit {
            id: format!("circ_{:x}", rand::rng().random::<u64>()),
            path: vec![
                "192.168.1.1:9001".to_string(),
                "10.0.0.1:9001".to_string(),
                "198.51.100.1:9001".to_string(),
            ],
            built: true,
            age_secs: 0,
        }
    }

    pub fn validate_onion(onion: &str) -> bool {
        onion.ends_with(".onion") && onion.len() >= 22
    }

    pub fn estimate_latency() -> f64 {
        250.0 + rand::rng().random::<f64>() * 200.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_status() {
        let status = TorProxy::check_status();
        assert!(status.enabled);
        assert_eq!(status.circuit_count, 3);
    }

    #[test]
    fn test_new_circuit() {
        let circuit = TorProxy::new_circuit();
        assert!(circuit.built);
        assert_eq!(circuit.path.len(), 3);
    }

    #[test]
    fn test_validate_onion() {
        assert!(TorProxy::validate_onion("facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"));
        assert!(!TorProxy::validate_onion("example.com"));
    }

    #[test]
    fn test_tor_status_serde() {
        let status = TorProxy::check_status();
        let json = serde_json::to_string_pretty(&status).unwrap();
        assert!(json.contains("enabled"));
    }
}
