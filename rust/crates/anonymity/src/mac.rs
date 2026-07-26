use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacAddress {
    pub address: String,
    pub vendor: Option<String>,
    pub randomized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub current_mac: MacAddress,
    pub randomized_mac: MacAddress,
    pub supported: bool,
}

pub struct MacRandomizer;

impl Default for MacRandomizer {
    fn default() -> Self {
        Self::new()
    }
}

impl MacRandomizer {
    pub fn new() -> Self {
        MacRandomizer
    }

    pub fn list_interfaces() -> Vec<NetworkInterface> {
        vec![
            NetworkInterface {
                name: "wlan0".to_string(),
                current_mac: MacAddress {
                    address: "00:11:22:33:44:55".to_string(),
                    vendor: Some("Intel Corp".to_string()),
                    randomized: false,
                },
                randomized_mac: MacAddress {
                    address: Self::generate_mac(),
                    vendor: None,
                    randomized: true,
                },
                supported: true,
            },
            NetworkInterface {
                name: "eth0".to_string(),
                current_mac: MacAddress {
                    address: "aa:bb:cc:dd:ee:ff".to_string(),
                    vendor: Some("Realtek".to_string()),
                    randomized: false,
                },
                randomized_mac: MacAddress {
                    address: Self::generate_mac(),
                    vendor: None,
                    randomized: true,
                },
                supported: true,
            },
        ]
    }

    pub fn generate_mac() -> String {
        let bytes: [u8; 6] = rand::rng().random();
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0] & 0xfc | 0x02,
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }

    pub fn randomize(_iface: &NetworkInterface) -> MacAddress {
        MacAddress {
            address: Self::generate_mac(),
            vendor: None,
            randomized: true,
        }
    }

    pub fn validate_mac(mac: &str) -> bool {
        let parts: Vec<&str> = mac.split(':').collect();
        if parts.len() != 6 {
            return false;
        }
        parts.iter().all(|p| u8::from_str_radix(p, 16).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mac() {
        let mac = MacRandomizer::generate_mac();
        assert!(mac.split(':').count() == 6);
        assert!(MacRandomizer::validate_mac(&mac));
    }

    #[test]
    fn test_validate_mac() {
        assert!(MacRandomizer::validate_mac("02:00:00:00:00:01"));
        assert!(!MacRandomizer::validate_mac("invalid"));
        assert!(!MacRandomizer::validate_mac("gg:00:00:00:00:00"));
    }

    #[test]
    fn test_list_interfaces() {
        let ifaces = MacRandomizer::list_interfaces();
        assert!(!ifaces.is_empty());
        assert!(ifaces.iter().any(|i| i.name == "wlan0"));
    }

    #[test]
    fn test_randomize() {
        let ifaces = MacRandomizer::list_interfaces();
        let new_mac = MacRandomizer::randomize(&ifaces[0]);
        assert!(new_mac.randomized);
        assert!(MacRandomizer::validate_mac(&new_mac.address));
    }

    #[test]
    fn test_mac_serde() {
        let mac = MacRandomizer::generate_mac();
        let addr = MacAddress { address: mac, vendor: None, randomized: true };
        let json = serde_json::to_string_pretty(&addr).unwrap();
        assert!(json.contains("randomized"));
    }
}
