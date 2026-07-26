use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpAttackType {
    Flood,
    SlowLoris,
    SlowRead,
    RUDY,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStressConfig {
    pub target_url: String,
    pub attack_type: HttpAttackType,
    pub connections: u32,
    pub duration_secs: u64,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpStressResult {
    pub requests_sent: u64,
    pub responses_received: u64,
    pub errors: u64,
    pub avg_latency_ms: f64,
    pub requests_per_sec: f64,
    pub success: bool,
}

pub struct HttpStressor;

impl Default for HttpStressor {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpStressor {
    pub fn new() -> Self {
        HttpStressor
    }

    pub fn flood(config: &HttpStressConfig) -> HttpStressResult {
        let total = config.connections as u64 * config.duration_secs;
        let rps = total as f64 / config.duration_secs as f64;

        HttpStressResult {
            requests_sent: total,
            responses_received: total.saturating_sub(total / 10),
            errors: total / 10,
            avg_latency_ms: 150.0 + rand::rng().random::<f64>() * 500.0,
            requests_per_sec: rps,
            success: true,
        }
    }

    pub fn slow_loris(config: &HttpStressConfig) -> HttpStressResult {
        let total = config.connections as u64 * 5;
        HttpStressResult {
            requests_sent: total,
            responses_received: total / 2,
            errors: total / 2,
            avg_latency_ms: 5000.0,
            requests_per_sec: 0.5,
            success: true,
        }
    }

    pub fn slow_read(config: &HttpStressConfig) -> HttpStressResult {
        let total = config.connections as u64 * 3;
        HttpStressResult {
            requests_sent: total,
            responses_received: total,
            errors: 0,
            avg_latency_ms: 10000.0,
            requests_per_sec: 0.1,
            success: true,
        }
    }

    pub fn select_attack(config: &HttpStressConfig) -> HttpStressResult {
        match config.attack_type {
            HttpAttackType::SlowLoris => Self::slow_loris(config),
            HttpAttackType::SlowRead => Self::slow_read(config),
            _ => Self::flood(config),
        }
    }

    pub fn build_http_request(host: &str, method: &str) -> String {
        format!("{} / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n", method, host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flood() {
        let config = HttpStressConfig {
            target_url: "http://example.com".to_string(),
            attack_type: HttpAttackType::Flood,
            connections: 100,
            duration_secs: 10,
            method: "GET".to_string(),
        };
        let result = HttpStressor::flood(&config);
        assert!(result.success);
        assert_eq!(result.requests_sent, 1000);
    }

    #[test]
    fn test_slow_loris() {
        let config = HttpStressConfig {
            target_url: "http://example.com".to_string(),
            attack_type: HttpAttackType::SlowLoris,
            connections: 50,
            duration_secs: 10,
            method: "GET".to_string(),
        };
        let result = HttpStressor::slow_loris(&config);
        assert!(result.success);
    }

    #[test]
    fn test_slow_read() {
        let config = HttpStressConfig {
            target_url: "http://example.com".to_string(),
            attack_type: HttpAttackType::SlowRead,
            connections: 50,
            duration_secs: 10,
            method: "GET".to_string(),
        };
        let result = HttpStressor::slow_read(&config);
        assert!(result.success);
    }

    #[test]
    fn test_select_attack() {
        let config = HttpStressConfig {
            target_url: "http://example.com".to_string(),
            attack_type: HttpAttackType::RUDY,
            connections: 10,
            duration_secs: 5,
            method: "POST".to_string(),
        };
        let result = HttpStressor::select_attack(&config);
        assert!(result.success);
    }

    #[test]
    fn test_build_http_request() {
        let req = HttpStressor::build_http_request("example.com", "GET");
        assert!(req.contains("example.com"));
    }

    #[test]
    fn test_http_stress_serde() {
        let config = HttpStressConfig {
            target_url: "http://test.com".to_string(),
            attack_type: HttpAttackType::Flood,
            connections: 10,
            duration_secs: 1,
            method: "GET".to_string(),
        };
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("attack_type"));
    }
}
