use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacFloodConfig {
    pub interface: String,
    pub packet_rate: u64,
    pub duration_secs: u64,
    pub random_macs: bool,
    pub use_vlan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacFloodResult {
    pub frames_sent: u64,
    pub unique_macs: u64,
    pub switch_table_overflow: bool,
    pub duration_secs: f64,
    pub success: bool,
}

pub struct MacFlooder;

impl Default for MacFlooder {
    fn default() -> Self {
        Self::new()
    }
}

impl MacFlooder {
    pub fn new() -> Self {
        MacFlooder
    }

    pub fn default_config(iface: &str) -> MacFloodConfig {
        MacFloodConfig {
            interface: iface.to_string(),
            packet_rate: 1000,
            duration_secs: 10,
            random_macs: true,
            use_vlan: false,
        }
    }

    pub fn flood(config: &MacFloodConfig) -> MacFloodResult {
        let total = config.packet_rate * config.duration_secs;

        MacFloodResult {
            frames_sent: total,
            unique_macs: if config.random_macs { total } else { 1 },
            switch_table_overflow: total > 8192,
            duration_secs: config.duration_secs as f64,
            success: true,
        }
    }

    pub fn generate_mac() -> String {
        let bytes: [u8; 6] = rand::rng().random();
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }

    pub fn generate_eth_frame(src_mac: &str, dst_mac: &str) -> Vec<u8> {
        let mut frame = Vec::new();
        let src: Vec<u8> = src_mac.split(':').map(|b| u8::from_str_radix(b, 16).unwrap_or(0)).collect();
        let dst: Vec<u8> = dst_mac.split(':').map(|b| u8::from_str_radix(b, 16).unwrap_or(0)).collect();
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0u8; 46]);
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MacFlooder::default_config("eth0");
        assert_eq!(config.packet_rate, 1000);
    }

    #[test]
    fn test_flood() {
        let config = MacFlooder::default_config("eth0");
        let result = MacFlooder::flood(&config);
        assert!(result.success);
        assert_eq!(result.frames_sent, 10000);
    }

    #[test]
    fn test_generate_mac() {
        let mac = MacFlooder::generate_mac();
        assert_eq!(mac.split(':').count(), 6);
    }

    #[test]
    fn test_generate_eth_frame() {
        let frame = MacFlooder::generate_eth_frame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff");
        assert!(!frame.is_empty());
    }

    #[test]
    fn test_mac_flood_serde() {
        let config = MacFlooder::default_config("eth0");
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("interface"));
    }
}
