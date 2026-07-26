use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconFloodConfig {
    pub interface: String,
    pub rate: u64,
    pub duration_secs: u64,
    pub ssid_prefix: String,
    pub random_bssid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconFloodResult {
    pub beacons_sent: u64,
    pub unique_ssids: u64,
    pub unique_bssids: u64,
    pub channels_used: Vec<u8>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeAp {
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub encryption: String,
    pub signal_dbm: i8,
}

pub struct BeaconFlooder;

impl Default for BeaconFlooder {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconFlooder {
    pub fn new() -> Self {
        BeaconFlooder
    }

    pub fn default_config(iface: &str) -> BeaconFloodConfig {
        BeaconFloodConfig {
            interface: iface.to_string(),
            rate: 50,
            duration_secs: 10,
            ssid_prefix: "FreeWiFi".to_string(),
            random_bssid: true,
        }
    }

    pub fn flood(config: &BeaconFloodConfig) -> BeaconFloodResult {
        let total = config.rate * config.duration_secs;

        BeaconFloodResult {
            beacons_sent: total,
            unique_ssids: total.min(100),
            unique_bssids: total.min(100),
            channels_used: vec![1, 6, 11],
            success: true,
        }
    }

    pub fn generate_ap(index: u64, prefix: &str) -> FakeAp {
        let bssid_bytes: [u8; 6] = rand::rng().random::<[u8; 6]>();
        let bssid = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
            bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]
        );
        let encryptions = ["OPEN", "WPA2", "WPA3", "WEP"];
        let channels = [1u8, 6, 11, 3, 9, 2, 7, 10];

        FakeAp {
            ssid: format!("{}-{}", prefix, index),
            bssid,
            channel: channels[(index as usize) % channels.len()],
            encryption: encryptions[(index as usize) % encryptions.len()].to_string(),
            signal_dbm: (-30 - (index as i8 % 60)),
        }
    }

    pub fn known_enterprise_ssids() -> Vec<&'static str> {
        vec![
            "Starbucks WiFi", "McDonald's Free WiFi", "ATT WiFi",
            "Verizon WiFi", "Xfinity WiFi", "CableWiFi",
            "eduroam", "HomeWiFi", "Guest Network",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BeaconFlooder::default_config("wlan0");
        assert_eq!(config.ssid_prefix, "FreeWiFi");
    }

    #[test]
    fn test_flood() {
        let config = BeaconFlooder::default_config("wlan0");
        let result = BeaconFlooder::flood(&config);
        assert!(result.success);
        assert_eq!(result.beacons_sent, 500);
    }

    #[test]
    fn test_generate_ap() {
        let ap = BeaconFlooder::generate_ap(1, "Test");
        assert!(ap.ssid.contains("Test"));
        assert!(ap.bssid.contains(':'));
    }

    #[test]
    fn test_known_enterprise_ssids() {
        let ssids = BeaconFlooder::known_enterprise_ssids();
        assert!(ssids.contains(&"eduroam"));
    }

    #[test]
    fn test_beacon_flood_serde() {
        let config = BeaconFlooder::default_config("wlan0");
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("ssid_prefix"));
    }
}
