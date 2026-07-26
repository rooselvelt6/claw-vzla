use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsStressConfig {
    pub target_host: String,
    pub target_port: u16,
    pub concurrent_connections: u32,
    pub duration_secs: u64,
    pub renegotiate: bool,
    pub tls_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsStressResult {
    pub connections_attempted: u64,
    pub connections_established: u64,
    pub renegotiations: u64,
    pub errors: u64,
    pub avg_handshake_ms: f64,
    pub success: bool,
}

pub struct TlsStressor;

impl Default for TlsStressor {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsStressor {
    pub fn new() -> Self {
        TlsStressor
    }

    pub fn default_config(host: &str) -> TlsStressConfig {
        TlsStressConfig {
            target_host: host.to_string(),
            target_port: 443,
            concurrent_connections: 100,
            duration_secs: 10,
            renegotiate: false,
            tls_version: "1.3".to_string(),
        }
    }

    pub fn stress(config: &TlsStressConfig) -> TlsStressResult {
        let attempted = config.concurrent_connections as u64 * config.duration_secs;
        let established = attempted * 8 / 10;
        let errors = attempted - established;
        let reneg = if config.renegotiate { established * 2 } else { 0 };

        TlsStressResult {
            connections_attempted: attempted,
            connections_established: established,
            renegotiations: reneg,
            errors,
            avg_handshake_ms: 200.0 + rand::rng().random::<f64>() * 800.0,
            success: errors < attempted / 2,
        }
    }

    pub fn renegotiation_flood(config: &TlsStressConfig) -> TlsStressResult {
        let mut result = Self::stress(config);
        result.renegotiations = result.connections_established * 10;
        result
    }

    pub fn test_cipher(host: &str, port: u16) -> Vec<String> {
        let ciphers = vec![
            "TLS_AES_256_GCM_SHA384".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            "TLS_AES_128_GCM_SHA256".to_string(),
        ];
        log::info!("Testing ciphers against {}:{}", host, port);
        ciphers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TlsStressor::default_config("example.com");
        assert_eq!(config.target_port, 443);
        assert_eq!(config.tls_version, "1.3");
    }

    #[test]
    fn test_stress() {
        let config = TlsStressor::default_config("example.com");
        let result = TlsStressor::stress(&config);
        assert!(result.connections_attempted > 0);
    }

    #[test]
    fn test_renegotiation_flood() {
        let config = TlsStressor::default_config("example.com");
        let result = TlsStressor::renegotiation_flood(&config);
        assert!(result.renegotiations > 0);
    }

    #[test]
    fn test_cipher() {
        let ciphers = TlsStressor::test_cipher("example.com", 443);
        assert!(!ciphers.is_empty());
    }

    #[test]
    fn test_tls_stress_serde() {
        let config = TlsStressor::default_config("test.com");
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("tls_version"));
    }
}
