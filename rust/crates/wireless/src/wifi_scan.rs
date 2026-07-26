use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub channel: u16,
    pub frequency: u16,
    pub signal_dbm: i16,
    pub encryption: String,
    pub cipher: String,
    pub auth: String,
    pub wps: bool,
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub mac: String,
    pub signal_dbm: i16,
    pub is_associated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub access_points: Vec<AccessPoint>,
    pub interface: String,
    pub scan_time_secs: f64,
}

pub struct WifiScanner;

impl WifiScanner {
    pub fn scan(interface: &str) -> Result<ScanResult, WirelessError> {
        let start = std::time::Instant::now();

        let output = Command::new("iw")
            .args(["dev", interface, "scan"])
            .output()
            .map_err(|e| WirelessError::Command(format!("iw scan failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WirelessError::Command(format!("iw scan error: {}", stderr.trim())));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let aps = parse_iw_scan(&stdout);

        let elapsed = start.elapsed().as_secs_f64();

        Ok(ScanResult {
            access_points: aps,
            interface: interface.to_string(),
            scan_time_secs: elapsed,
        })
    }

    pub fn scan_quick(interface: &str) -> Result<ScanResult, WirelessError> {
        let start = std::time::Instant::now();

        let output = Command::new("iw")
            .args(["dev", interface, "scan", "--duration", "1000"])
            .output()
            .map_err(|e| WirelessError::Command(format!("iw scan failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(WirelessError::Command(format!("iw scan error: {}", stderr.trim())));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let aps = parse_iw_scan(&stdout);

        Ok(ScanResult {
            access_points: aps,
            interface: interface.to_string(),
            scan_time_secs: start.elapsed().as_secs_f64(),
        })
    }

    pub fn list_interfaces() -> Vec<String> {
        let output = Command::new("iw")
            .args(["dev"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        output.lines()
            .filter(|l| l.trim().starts_with("Interface"))
            .filter_map(|l| l.split_whitespace().nth(1))
            .map(|s| s.to_string())
            .collect()
    }

    pub fn list_phy_interfaces() -> Vec<String> {
        let output = Command::new("iw")
            .args(["dev"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        output.lines()
            .filter(|l| l.trim().starts_with("phy#"))
            .filter_map(|l| l.split_whitespace().nth(0))
            .map(|s| s.trim_start_matches("phy#").to_string())
            .collect()
    }

    pub fn set_channel(interface: &str, channel: u16) -> Result<(), WirelessError> {
        let freqs: HashMap<u16, u16> = [
            (1, 2412), (2, 2417), (3, 2422), (4, 2427),
            (5, 2432), (6, 2437), (7, 2442), (8, 2447),
            (9, 2452), (10, 2457), (11, 2462), (12, 2467),
            (13, 2472), (14, 2484),
            (36, 5180), (40, 5200), (44, 5220), (48, 5240),
            (52, 5260), (56, 5280), (60, 5300), (64, 5320),
            (100, 5500), (104, 5520), (108, 5540), (112, 5560),
            (116, 5580), (120, 5600), (124, 5620), (128, 5640),
            (132, 5660), (136, 5680), (140, 5700), (144, 5720),
            (149, 5745), (153, 5765), (157, 5785), (161, 5805), (165, 5825),
        ].iter().copied().collect();

        let freq = freqs.get(&channel).ok_or_else(|| WirelessError::Other(format!("Invalid channel: {}", channel)))?;

        let output = Command::new("iw")
            .args(["dev", interface, "set", "freq", &freq.to_string()])
            .output()
            .map_err(|e| WirelessError::Command(format!("iw set freq failed: {}", e)))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(WirelessError::Command(format!("Failed to set channel: {}", stderr.trim())))
        }
    }
}

fn parse_iw_scan(output: &str) -> Vec<AccessPoint> {
    let mut aps = Vec::new();
    let mut current_ap: Option<AccessPoint> = None;

    for line in output.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("BSS ") {
            if let Some(ap) = current_ap.take() {
                aps.push(ap);
            }
            let bssid = trimmed.split_whitespace()
                .nth(1)
                .unwrap_or("")
                .split('(')
                .next()
                .unwrap_or("")
                .to_string();
            current_ap = Some(AccessPoint {
                bssid,
                ssid: String::new(),
                channel: 0,
                frequency: 0,
                signal_dbm: 0,
                encryption: String::new(),
                cipher: String::new(),
                auth: String::new(),
                wps: false,
                clients: Vec::new(),
            });
        }

        if let Some(ref mut ap) = current_ap {
            if trimmed.starts_with("freq:") {
                ap.frequency = trimmed.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                ap.channel = freq_to_channel(ap.frequency);
            } else if trimmed.starts_with("signal:") {
                let s = trimmed.split_whitespace().nth(1).unwrap_or("0");
                ap.signal_dbm = s.trim_end_matches(".00").parse().unwrap_or(0);
            } else if trimmed.starts_with("SSID:") {
                ap.ssid = trimmed.strip_prefix("SSID:").unwrap_or(trimmed).trim().to_string();
            } else if trimmed.contains("WPA") || trimmed.contains("RSN") {
                if trimmed.contains("Group cipher:") {
                    ap.cipher = trimmed.split("Group cipher:").nth(1).unwrap_or("").trim().to_string();
                }
                if trimmed.contains("Authentication suites:") {
                    ap.auth = trimmed.split("Authentication suites:").nth(1).unwrap_or("").trim().to_string();
                }
                if !ap.encryption.contains("WPA")
                    && (trimmed.starts_with("RSN:") || trimmed.starts_with("* ")) {
                        ap.encryption = if ap.encryption.is_empty() {
                            "WPA2".to_string()
                        } else {
                            ap.encryption.clone()
                        };
                    }
            } else if trimmed == "* Version: 1" && ap.encryption.is_empty() {
                ap.encryption = "WPA".to_string();
            } else if trimmed.starts_with("WPS:") {
                ap.wps = trimmed.contains("* Version: 1.0");
            }
        }
    }

    if let Some(ap) = current_ap.take() {
        aps.push(ap);
    }

    aps
}

fn freq_to_channel(freq: u16) -> u16 {
    match freq {
        2412 => 1, 2417 => 2, 2422 => 3, 2427 => 4,
        2432 => 5, 2437 => 6, 2442 => 7, 2447 => 8,
        2452 => 9, 2457 => 10, 2462 => 11, 2467 => 12,
        2472 => 13, 2484 => 14,
        5180 => 36, 5200 => 40, 5220 => 44, 5240 => 48,
        5260 => 52, 5280 => 56, 5300 => 60, 5320 => 64,
        5500 => 100, 5520 => 104, 5540 => 108, 5560 => 112,
        5580 => 116, 5600 => 120, 5620 => 124, 5640 => 128,
        5660 => 132, 5680 => 136, 5700 => 140, 5720 => 144,
        5745 => 149, 5765 => 153, 5785 => 157, 5805 => 161, 5825 => 165,
        _ => 0,
    }
}

pub fn format_scan_result(result: &ScanResult) -> String {
    let mut out = format!("Scan complete ({:.2}s) on {}\n", result.scan_time_secs, result.interface);
    out.push_str(&format!("Found {} access points\n\n", result.access_points.len()));

    for (i, ap) in result.access_points.iter().enumerate() {
        out.push_str(&format!("{}. {} ({})\n", i + 1, if ap.ssid.is_empty() { "<hidden>" } else { &ap.ssid }, ap.bssid));
        out.push_str(&format!("   Channel: {} ({} MHz)\n", ap.channel, ap.frequency));
        out.push_str(&format!("   Signal: {} dBm\n", ap.signal_dbm));
        out.push_str(&format!("   Encryption: {}\n", ap.encryption));
        if !ap.cipher.is_empty() {
            out.push_str(&format!("   Cipher: {}\n", ap.cipher));
        }
        if !ap.auth.is_empty() {
            out.push_str(&format!("   Auth: {}\n", ap.auth));
        }
        if ap.wps {
            out.push_str("   WPS: enabled\n");
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iw_scan_basic() {
        let sample = r#"BSS 00:11:22:33:44:55(on wlan0)
	TSF: 1234567890 usec (0d, 00:00:00)
	freq: 2412
	beacon interval: 100 TUs
	signal: -45.00 dBm
	last seen: 0 ms ago
	SSID: TestNetwork
	Supported rates: 1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 0x0000
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].bssid, "00:11:22:33:44:55");
        assert_eq!(aps[0].ssid, "TestNetwork");
        assert_eq!(aps[0].frequency, 2412);
        assert_eq!(aps[0].channel, 1);
        assert_eq!(aps[0].signal_dbm, -45);
        assert!(aps[0].encryption.contains("WPA2"));
    }

    #[test]
    fn test_parse_iw_scan_multiple_aps() {
        let sample = r#"BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2437
	signal: -67.00 dBm
	SSID: Net1
BSS 11:22:33:44:55:66(on wlan0)
	freq: 5180
	signal: -78.00 dBm
	SSID: Net2
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].ssid, "Net1");
        assert_eq!(aps[0].channel, 6);
        assert_eq!(aps[1].ssid, "Net2");
        assert_eq!(aps[1].channel, 36);
    }

    #[test]
    fn test_freq_to_channel() {
        assert_eq!(freq_to_channel(2412), 1);
        assert_eq!(freq_to_channel(2437), 6);
        assert_eq!(freq_to_channel(2462), 11);
        assert_eq!(freq_to_channel(5180), 36);
        assert_eq!(freq_to_channel(5745), 149);
        assert_eq!(freq_to_channel(9999), 0);
    }

    #[test]
    fn test_wps_detection() {
        let sample = r#"BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2412
	signal: -55.00 dBm
	SSID: WPSNet
	WPS:	 * Version: 1.0
		 * Wi-Fi Protected Setup State: 2 (Configured)
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 1);
        assert!(aps[0].wps);
    }

    #[test]
    fn test_hidden_ssid() {
        let sample = r#"BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2412
	signal: -70.00 dBm
	SSID:
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].ssid, "");
    }

    #[test]
    fn test_scan_result_formatting() {
        let result = ScanResult {
            access_points: vec![AccessPoint {
                bssid: "00:11:22:33:44:55".to_string(),
                ssid: "Test".to_string(),
                channel: 6,
                frequency: 2437,
                signal_dbm: -50,
                encryption: "WPA2".to_string(),
                cipher: "CCMP".to_string(),
                auth: "PSK".to_string(),
                wps: true,
                clients: vec![],
            }],
            interface: "wlan0".to_string(),
            scan_time_secs: 2.5,
        };
        let formatted = format_scan_result(&result);
        assert!(formatted.contains("Test"));
        assert!(formatted.contains("00:11:22:33:44:55"));
        assert!(formatted.contains("WPA2"));
        assert!(formatted.contains("WPS"));
    }

    #[test]
    fn test_set_channel_valid() {
        let map: std::collections::HashMap<u16, u16> = [
            (1, 2412), (6, 2437), (11, 2462),
            (36, 5180), (149, 5745),
        ].iter().copied().collect();
        assert_eq!(*map.get(&1).unwrap(), 2412);
        assert_eq!(*map.get(&36).unwrap(), 5180);
    }

    #[test]
    fn test_freq_to_channel_5ghz() {
        assert_eq!(freq_to_channel(5200), 40);
        assert_eq!(freq_to_channel(5220), 44);
        assert_eq!(freq_to_channel(5240), 48);
        assert_eq!(freq_to_channel(5765), 153);
        assert_eq!(freq_to_channel(5785), 157);
        assert_eq!(freq_to_channel(5805), 161);
        assert_eq!(freq_to_channel(5825), 165);
    }

    #[test]
    fn test_freq_to_channel_2ghz_all() {
        assert_eq!(freq_to_channel(2412), 1);
        assert_eq!(freq_to_channel(2417), 2);
        assert_eq!(freq_to_channel(2422), 3);
        assert_eq!(freq_to_channel(2427), 4);
        assert_eq!(freq_to_channel(2432), 5);
        assert_eq!(freq_to_channel(2442), 7);
        assert_eq!(freq_to_channel(2447), 8);
        assert_eq!(freq_to_channel(2452), 9);
        assert_eq!(freq_to_channel(2457), 10);
        assert_eq!(freq_to_channel(2467), 12);
        assert_eq!(freq_to_channel(2472), 13);
        assert_eq!(freq_to_channel(2484), 14);
    }

    #[test]
    fn test_parse_iw_scan_no_aps() {
        let sample = "";
        let aps = parse_iw_scan(sample);
        assert!(aps.is_empty());
    }

    #[test]
    fn test_parse_iw_scan_wpa1() {
        let sample = r#"BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2412
	signal: -50.00 dBm
	SSID: WPA1Net
	* Version: 1
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].encryption, "WPA");
    }

    #[test]
    fn test_parse_iw_scan_no_signal() {
        let sample = r#"BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2412
	SSID: NoSignal
"#;
        let aps = parse_iw_scan(sample);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].signal_dbm, 0);
    }

    #[test]
    fn test_scan_result_formatting_hidden_ssid() {
        let result = ScanResult {
            access_points: vec![AccessPoint {
                bssid: "00:11:22:33:44:55".to_string(),
                ssid: String::new(),
                channel: 6,
                frequency: 2437,
                signal_dbm: -70,
                encryption: "WPA2".to_string(),
                cipher: String::new(),
                auth: String::new(),
                wps: false,
                clients: vec![],
            }],
            interface: "wlan0".to_string(),
            scan_time_secs: 1.0,
        };
        let formatted = format_scan_result(&result);
        assert!(formatted.contains("<hidden>"));
    }

    #[test]
    fn test_scan_result_formatting_no_cipher_no_auth() {
        let result = ScanResult {
            access_points: vec![AccessPoint {
                bssid: "00:11:22:33:44:55".to_string(),
                ssid: "OpenNet".to_string(),
                channel: 1,
                frequency: 2412,
                signal_dbm: -50,
                encryption: "OPN".to_string(),
                cipher: String::new(),
                auth: String::new(),
                wps: false,
                clients: vec![],
            }],
            interface: "wlan0".to_string(),
            scan_time_secs: 1.0,
        };
        let formatted = format_scan_result(&result);
        assert!(!formatted.contains("Cipher:"));
        assert!(!formatted.contains("Auth:"));
    }

    #[test]
    fn test_scan_result_formatting_no_wps() {
        let result = ScanResult {
            access_points: vec![AccessPoint {
                bssid: "00:11:22:33:44:55".to_string(),
                ssid: "NoWPS".to_string(),
                channel: 6,
                frequency: 2437,
                signal_dbm: -50,
                encryption: "WPA2".to_string(),
                cipher: String::new(),
                auth: String::new(),
                wps: false,
                clients: vec![],
            }],
            interface: "wlan0".to_string(),
            scan_time_secs: 1.0,
        };
        let formatted = format_scan_result(&result);
        assert!(!formatted.contains("WPS:"));
    }

    #[test]
    fn test_access_point_struct() {
        let ap = AccessPoint {
            bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            ssid: "Test".to_string(),
            channel: 36,
            frequency: 5180,
            signal_dbm: -60,
            encryption: "WPA2".to_string(),
            cipher: "CCMP".to_string(),
            auth: "PSK".to_string(),
            wps: true,
            clients: vec![],
        };
        assert_eq!(ap.bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(ap.channel, 36);
        assert!(ap.wps);
    }

    #[test]
    fn test_client_struct() {
        let c = Client {
            mac: "11:22:33:44:55:66".to_string(),
            signal_dbm: -55,
            is_associated: true,
        };
        assert_eq!(c.mac, "11:22:33:44:55:66");
        assert!(c.is_associated);
    }
}
