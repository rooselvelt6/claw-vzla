use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeInfo {
    pub bssid: String,
    pub essid: String,
    pub client_mac: String,
    pub capture_time: String,
    pub key_version: u8,
    pub is_complete: bool,
    pub pmkid: Option<String>,
    pub anonce: Option<String>,
    pub snonce: Option<String>,
    pub mic: Option<String>,
    pub eapol_frame_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCapture {
    pub interface: String,
    pub bssid: String,
    pub channel: u16,
    pub output_file: String,
    pub handshakes: Vec<HandshakeInfo>,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub bssid: String,
    pub essid: String,
    pub password: Option<String>,
    pub method: CrackMethod,
    pub duration_secs: f64,
    pub attempts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrackMethod {
    Dictionary,
    PMKID,
}

pub struct HandshakeCapture {
    pub interface: String,
    pub bssid: String,
    pub channel: u16,
    pub output_dir: String,
    running: Arc<AtomicBool>,
}

impl HandshakeCapture {
    pub fn new(interface: &str, bssid: &str, channel: u16, output_dir: &str) -> Self {
        HandshakeCapture {
            interface: interface.to_string(),
            bssid: bssid.to_string(),
            channel,
            output_dir: output_dir.to_string(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn start_capture(&mut self, timeout_secs: u64) -> Result<PcapCapture, WirelessError> {
        self.running.store(true, Ordering::SeqCst);

        std::fs::create_dir_all(&self.output_dir)
            .map_err(WirelessError::Io)?;

        let output_file = format!("{}/handshake_{}.pcap", self.output_dir, self.bssid.replace(':', ""));

        let mut child = Command::new("airodump-ng")
            .args([
                &self.interface,
                "--bssid", &self.bssid,
                "--channel", &self.channel.to_string(),
                "--write", output_file.trim_end_matches(".pcap"),
                "--output-format", "pcap",
            ])
            .spawn()
            .map_err(|e| WirelessError::Command(format!("airodump-ng failed: {}", e)))?;

        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > Duration::from_secs(timeout_secs) {
                break;
            }
            if !self.running.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }

        let _ = child.kill();
        let _ = child.wait();

        let handshakes = self.parse_handshakes(&output_file);

        Ok(PcapCapture {
            interface: self.interface.clone(),
            bssid: self.bssid.clone(),
            channel: self.channel,
            output_file,
            handshakes,
            duration_secs: start.elapsed().as_secs(),
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    fn parse_handshakes(&self, pcap_file: &str) -> Vec<HandshakeInfo> {
        let mut handshakes = Vec::new();

        if !std::path::Path::new(pcap_file).exists() {
            return handshakes;
        }

        let output = Command::new("tshark")
            .args([
                "-r", pcap_file,
                "-Y", "eapol",
                "-T", "fields",
                "-e", "wlan.sa",
                "-e", "wlan.da",
                "-e", "wlan.bssid",
                "-e", "eapol.keydes_info",
                "-e", "eapol.keydes_key_info",
                "-e", "eapol.keydes_nonce",
            ])
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

        let mut current: Option<HandshakeInfo> = None;
        let mut eapol_count = 0u8;

        for line in output.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() < 4 {
                continue;
            }

            let key_info = fields.get(3).unwrap_or(&"");
            let key_version = key_info.chars().next().and_then(|c| c.to_digit(10)).unwrap_or(0) as u8;

            let bssid = fields.get(2).unwrap_or(&"").to_string().to_uppercase();
            eapol_count += 1;

            let h = HandshakeInfo {
                bssid: bssid.clone(),
                essid: String::new(),
                client_mac: fields.first().unwrap_or(&"").to_string(),
                capture_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                key_version,
                is_complete: eapol_count >= 4,
                pmkid: None,
                anonce: fields.get(5).map(|s| s.to_string()),
                snonce: fields.get(4).map(|s| s.to_string()),
                mic: None,
                eapol_frame_count: eapol_count,
            };

            if eapol_count >= 4 {
                current = Some(h);
            }
        }

        if let Some(h) = current {
            handshakes.push(h);
        }

        if handshakes.is_empty() {
            handshakes.push(HandshakeInfo {
                bssid: self.bssid.clone(),
                essid: String::new(),
                client_mac: String::new(),
                capture_time: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                key_version: 0,
                is_complete: false,
                pmkid: None,
                anonce: None,
                snonce: None,
                mic: None,
                eapol_frame_count: 0,
            });
        }

        handshakes
    }
}

pub struct PmkidAttack {
    pub interface: String,
    pub bssid: String,
    pub client_mac: String,
    pub output_file: String,
}

impl PmkidAttack {
    pub fn new(interface: &str, bssid: &str, client_mac: &str, output_file: &str) -> Self {
        PmkidAttack {
            interface: interface.to_string(),
            bssid: bssid.to_string(),
            client_mac: client_mac.to_string(),
            output_file: output_file.to_string(),
        }
    }

    pub fn capture_pmkid(&self, timeout_secs: u64) -> Result<HashMap<String, String>, WirelessError> {
        let _start = std::time::Instant::now();
        let _timeout = Duration::from_secs(timeout_secs);

        let output = Command::new("hcxdumptool")
            .args([
                "-i", &self.interface,
                "-o", &self.output_file,
                "--enable_status=15",
            ])
            .output()
            .map_err(|e| WirelessError::Command(format!("hcxdumptool failed: {}", e)))?;

        let mut result = HashMap::new();
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("PMKID") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "PMKID" {
                            if let Some(pmkid) = parts.get(i + 1) {
                                result.insert("pmkid".to_string(), pmkid.to_string());
                            }
                        }
                    }
                }
                if line.contains("APSSID") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "APSSID" {
                            if let Some(essid) = parts.get(i + 1) {
                                result.insert("essid".to_string(), essid.to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

pub struct WpaCracker {
    pub wordlist_path: String,
}

impl WpaCracker {
    pub fn new(wordlist_path: &str) -> Self {
        WpaCracker {
            wordlist_path: wordlist_path.to_string(),
        }
    }

    pub fn crack_handshake(&self, pcap_file: &str, bssid: &str) -> Result<CrackResult, WirelessError> {
        let start = std::time::Instant::now();

        let output = Command::new("aircrack-ng")
            .args([
                "-w", &self.wordlist_path,
                "-b", bssid,
                pcap_file,
            ])
            .output()
            .map_err(|e| WirelessError::Command(format!("aircrack-ng failed: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut password = None;
        let mut attempts = 0u64;

        for line in stdout.lines() {
            if line.contains("KEY FOUND!") {
                let parts: Vec<&str> = line.split("[").collect();
                if parts.len() > 1 {
                    password = Some(parts[1].trim_end_matches(']').to_string());
                }
            }
            if line.contains("tried") {
                if let Some(num_part) = line.split_whitespace().find(|w| w.chars().all(|c| c.is_ascii_digit())) {
                    attempts = num_part.parse().unwrap_or(0);
                }
            }
        }

        let elapsed = start.elapsed().as_secs_f64();

        Ok(CrackResult {
            bssid: bssid.to_string(),
            essid: String::new(),
            password,
            method: CrackMethod::Dictionary,
            duration_secs: elapsed,
            attempts,
        })
    }

    pub fn crack_pmkid(&self, pmkid_file: &str, essid: &str) -> Result<CrackResult, WirelessError> {
        let start = std::time::Instant::now();

        let output = Command::new("hashcat")
            .args([
                "-m", "16800",
                "-a", "0",
                pmkid_file,
                &self.wordlist_path,
                "--potfile-disable",
                "--show",
            ])
            .output()
            .map_err(|e| WirelessError::Command(format!("hashcat failed: {}", e)))?;

        let mut password = None;
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 && parts[0] == essid {
                password = Some(parts[1].to_string());
                break;
            }
        }

        Ok(CrackResult {
            bssid: String::new(),
            essid: essid.to_string(),
            password,
            method: CrackMethod::PMKID,
            duration_secs: start.elapsed().as_secs_f64(),
            attempts: 0,
        })
    }

    pub fn compute_pmk(passphrase: &str, ssid: &str) -> [u8; 32] {
        let mut pmk = [0u8; 32];
        let salt = ssid.as_bytes();
        let pass = passphrase.as_bytes();

        let mut prev = Vec::new();
        for _ in 0..=4096 {
            let mut hasher = Sha256::new();
            hasher.update(&prev);
            hasher.update(pass);
            hasher.update(salt);
            prev = hasher.finalize().to_vec();
        }

        pmk.copy_from_slice(&prev[..32]);
        pmk
    }
}

pub fn detect_wps_pmkid(bssid: &str, essid: &str) -> Option<String> {
    let bssid_bytes: Vec<u8> = bssid.split(':')
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect();

    if bssid_bytes.len() != 6 {
        return None;
    }

    let pmk = WpaCracker::compute_pmk("", essid);

    let mut hasher = Sha256::new();
    hasher.update(pmk);
    hasher.update(b"PMK Name");
    hasher.update(&bssid_bytes);
    hasher.update(essid.as_bytes());
    let hash = hasher.finalize();

    let pmkid = hex::encode(&hash[..16]);
    Some(pmkid)
}

pub fn format_crack_result(result: &CrackResult) -> String {
    let mut out = format!("Crack Result for {} ({})\n", result.bssid, result.essid);
    out.push_str(&format!("Method: {:?}\n", result.method));
    out.push_str(&format!("Duration: {:.2}s\n", result.duration_secs));
    out.push_str(&format!("Attempts: {}\n", result.attempts));
    match &result.password {
        Some(pwd) => out.push_str(&format!("Password: {}\n", pwd)),
        None => out.push_str("Password: NOT FOUND\n"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpa_cracker_pmk_computation() {
        let pmk = WpaCracker::compute_pmk("password", "TestSSID");
        assert_eq!(pmk.len(), 32);
    }

    #[test]
    fn test_pmkid_generation() {
        let pmkid = detect_wps_pmkid("00:11:22:33:44:55", "TestNet");
        assert!(pmkid.is_some());
        assert_eq!(pmkid.unwrap().len(), 32);
    }

    #[test]
    fn test_crack_result_password_found() {
        let result = CrackResult {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "Test".to_string(),
            password: Some("secret123".to_string()),
            method: CrackMethod::Dictionary,
            duration_secs: 1.5,
            attempts: 1000,
        };
        let formatted = format_crack_result(&result);
        assert!(formatted.contains("secret123"));
        assert!(formatted.contains("Dictionary"));
    }

    #[test]
    fn test_crack_result_not_found() {
        let result = CrackResult {
            bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            essid: "NotFound".to_string(),
            password: None,
            method: CrackMethod::PMKID,
            duration_secs: 0.5,
            attempts: 500,
        };
        let formatted = format_crack_result(&result);
        assert!(formatted.contains("NOT FOUND"));
        assert!(formatted.contains("PMKID"));
    }

    #[test]
    fn test_handshake_info_default() {
        let hs = HandshakeInfo {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "Test".to_string(),
            client_mac: "66:77:88:99:aa:bb".to_string(),
            capture_time: "2026-01-01 00:00:00".to_string(),
            key_version: 2,
            is_complete: true,
            pmkid: Some("abcdef1234567890".to_string()),
            anonce: None,
            snonce: None,
            mic: None,
            eapol_frame_count: 4,
        };
        assert!(hs.is_complete);
        assert_eq!(hs.key_version, 2);
        assert_eq!(hs.eapol_frame_count, 4);
    }

    #[test]
    fn test_pmki_detection_missing_essid() {
        let pmkid = detect_wps_pmkid("00:11:22:33:44:55", "");
        assert!(pmkid.is_some());
    }

    #[test]
    fn test_pmk_computation_deterministic() {
        let pmk1 = WpaCracker::compute_pmk("testpass", "MyWiFi");
        let pmk2 = WpaCracker::compute_pmk("testpass", "MyWiFi");
        assert_eq!(pmk1, pmk2);

        let pmk3 = WpaCracker::compute_pmk("different", "MyWiFi");
        assert_ne!(pmk1, pmk3);
    }

    #[test]
    fn test_pmk_computation_empty_passphrase() {
        let pmk = WpaCracker::compute_pmk("", "TestSSID");
        assert_eq!(pmk.len(), 32);
        assert_ne!(pmk, [0u8; 32]);
    }

    #[test]
    fn test_pmk_computation_empty_ssid() {
        let pmk = WpaCracker::compute_pmk("password", "");
        assert_eq!(pmk.len(), 32);
    }

    #[test]
    fn test_pmk_different_ssid_different_output() {
        let pmk1 = WpaCracker::compute_pmk("pass", "SSID_A");
        let pmk2 = WpaCracker::compute_pmk("pass", "SSID_B");
        assert_ne!(pmk1, pmk2);
    }

    #[test]
    fn test_pmk_different_passphrase_different_output() {
        let pmk1 = WpaCracker::compute_pmk("pass1", "SSID");
        let pmk2 = WpaCracker::compute_pmk("pass2", "SSID");
        assert_ne!(pmk1, pmk2);
    }

    #[test]
    fn test_pmkid_generation_deterministic() {
        let pmkid1 = detect_wps_pmkid("00:11:22:33:44:55", "TestNet");
        let pmkid2 = detect_wps_pmkid("00:11:22:33:44:55", "TestNet");
        assert_eq!(pmkid1, pmkid2);
    }

    #[test]
    fn test_pmkid_generation_different_bssid() {
        let pmkid1 = detect_wps_pmkid("00:11:22:33:44:55", "TestNet");
        let pmkid2 = detect_wps_pmkid("aa:bb:cc:dd:ee:ff", "TestNet");
        assert_ne!(pmkid1, pmkid2);
    }

    #[test]
    fn test_pmkid_generation_invalid_bssid() {
        let result = detect_wps_pmkid("not-a-mac", "TestNet");
        assert!(result.is_none());
    }

    #[test]
    fn test_pmkid_format() {
        let pmkid = detect_wps_pmkid("00:11:22:33:44:55", "TestNet").unwrap();
        assert!(pmkid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_crack_result_struct() {
        let result = CrackResult {
            bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            essid: "MyNet".to_string(),
            password: Some("pass123".to_string()),
            method: CrackMethod::Dictionary,
            duration_secs: 10.0,
            attempts: 5000,
        };
        assert_eq!(result.bssid, "aa:bb:cc:dd:ee:ff");
        assert!(matches!(result.method, CrackMethod::Dictionary));
    }

    #[test]
    fn test_crack_method_variants() {
        let dict = CrackMethod::Dictionary;
        let pmkid = CrackMethod::PMKID;
        assert!(matches!(dict, CrackMethod::Dictionary));
        assert!(matches!(pmkid, CrackMethod::PMKID));
    }

    #[test]
    fn test_handshake_info_incomplete() {
        let hs = HandshakeInfo {
            bssid: "00:11:22:33:44:55".to_string(),
            essid: "Test".to_string(),
            client_mac: String::new(),
            capture_time: "2026-01-01 00:00:00".to_string(),
            key_version: 0,
            is_complete: false,
            pmkid: None,
            anonce: None,
            snonce: None,
            mic: None,
            eapol_frame_count: 2,
        };
        assert!(!hs.is_complete);
        assert_eq!(hs.eapol_frame_count, 2);
        assert!(hs.pmkid.is_none());
    }

    #[test]
    fn test_pcap_capture_struct() {
        let cap = PcapCapture {
            interface: "wlan0".to_string(),
            bssid: "00:11:22:33:44:55".to_string(),
            channel: 6,
            output_file: "/tmp/capture.pcap".to_string(),
            handshakes: vec![],
            duration_secs: 30,
        };
        assert_eq!(cap.channel, 6);
        assert!(cap.handshakes.is_empty());
    }

    #[test]
    fn test_format_crack_result_with_duration() {
        let result = CrackResult {
            bssid: "aa:bb:cc:dd:ee:ff".to_string(),
            essid: "Test".to_string(),
            password: None,
            method: CrackMethod::PMKID,
            duration_secs: 45.5,
            attempts: 10000,
        };
        let formatted = format_crack_result(&result);
        assert!(formatted.contains("45.50"));
        assert!(formatted.contains("10000"));
    }

    #[test]
    fn test_wpa_cracker_new() {
        let cracker = WpaCracker::new("/path/to/wordlist.txt");
        assert_eq!(cracker.wordlist_path, "/path/to/wordlist.txt");
    }

    #[test]
    fn test_pmkid_attack_new() {
        let attack = PmkidAttack::new("wlan0", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "/tmp/out.pcap");
        assert_eq!(attack.interface, "wlan0");
        assert_eq!(attack.bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(attack.client_mac, "11:22:33:44:55:66");
        assert_eq!(attack.output_file, "/tmp/out.pcap");
    }

    #[test]
    fn test_handshake_capture_new() {
        let cap = HandshakeCapture::new("wlan0", "00:11:22:33:44:55", 6, "/tmp/output");
        assert_eq!(cap.interface, "wlan0");
        assert_eq!(cap.bssid, "00:11:22:33:44:55");
        assert_eq!(cap.channel, 6);
        assert_eq!(cap.output_dir, "/tmp/output");
    }
}
