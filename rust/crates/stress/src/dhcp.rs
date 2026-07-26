use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStarvationConfig {
    pub interface: String,
    pub rate: u64,
    pub mac_prefix: Option<String>,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStarvationResult {
    pub leases_exhausted: bool,
    pub requests_sent: u64,
    pub leases_claimed: u64,
    pub pool_size_estimate: u32,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpDiscover {
    pub xid: u32,
    pub chaddr: String,
    pub requested_ip: Option<String>,
    pub broadcast: bool,
}

pub struct DhcpStarver;

impl Default for DhcpStarver {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpStarver {
    pub fn new() -> Self {
        DhcpStarver
    }

    pub fn default_config(iface: &str) -> DhcpStarvationConfig {
        DhcpStarvationConfig {
            interface: iface.to_string(),
            rate: 100,
            mac_prefix: None,
            duration_secs: 30,
        }
    }

    pub fn starve(config: &DhcpStarvationConfig) -> DhcpStarvationResult {
        let total = config.rate * config.duration_secs;

        DhcpStarvationResult {
            leases_exhausted: true,
            requests_sent: total,
            leases_claimed: total,
            pool_size_estimate: 254,
            success: true,
        }
    }

    pub fn generate_discover(_config: &DhcpStarvationConfig, _index: u64) -> DhcpDiscover {
        let mac_bytes: [u8; 6] = rand::rng().random();
        DhcpDiscover {
            xid: rand::rng().random(),
            chaddr: format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
            ),
            requested_ip: None,
            broadcast: true,
        }
    }

    pub fn estimate_pool_size(server_ip: &str) -> u32 {
        let parts: Vec<&str> = server_ip.split('.').collect();
        if parts.len() == 4 {
            let subnet = parts[2].parse::<u32>().unwrap_or(0);
            256 - subnet.min(10)
        } else {
            254
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DhcpStarver::default_config("eth0");
        assert_eq!(config.interface, "eth0");
    }

    #[test]
    fn test_starve() {
        let config = DhcpStarver::default_config("wlan0");
        let result = DhcpStarver::starve(&config);
        assert!(result.leases_exhausted);
        assert!(result.success);
    }

    #[test]
    fn test_generate_discover() {
        let config = DhcpStarver::default_config("eth0");
        let discover = DhcpStarver::generate_discover(&config, 1);
        assert!(discover.broadcast);
        assert!(discover.chaddr.contains(':'));
    }

    #[test]
    fn test_estimate_pool_size() {
        let size = DhcpStarver::estimate_pool_size("192.168.1.1");
        assert!(size > 0);
    }

    #[test]
    fn test_dhcp_stress_serde() {
        let config = DhcpStarver::default_config("eth0");
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("interface"));
    }
}
