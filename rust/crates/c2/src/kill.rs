use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillSwitchConfig {
    pub kill_password: String,
    pub reconnect_url: Option<String>,
    pub max_reconnect_attempts: u32,
}

impl Default for KillSwitchConfig {
    fn default() -> Self {
        KillSwitchConfig {
            kill_password: "KRAKEN_KILL".to_string(),
            reconnect_url: None,
            max_reconnect_attempts: 3,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KillCommand {
    pub action: KillAction,
    pub password: String,
    pub reconnect_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum KillAction {
    Kill,
    Reconnect,
    Sleep,
    Shutdown,
}

pub struct KillSwitch {
    killed: Arc<AtomicBool>,
    config: KillSwitchConfig,
}

impl KillSwitch {
    pub fn new(config: KillSwitchConfig) -> Self {
        KillSwitch {
            killed: Arc::new(AtomicBool::new(false)),
            config,
        }
    }

    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    pub fn process_command(&self, cmd: &KillCommand) -> Result<String, crate::C2Error> {
        if cmd.password != self.config.kill_password {
            return Err(crate::C2Error::Protocol("Invalid kill password".to_string()));
        }

        match cmd.action {
            KillAction::Kill => {
                self.killed.store(true, Ordering::SeqCst);
                Ok("KILL signal processed".to_string())
            }
            KillAction::Reconnect => {
                let url = cmd.reconnect_url.as_ref()
                    .or(self.config.reconnect_url.as_ref())
                    .ok_or_else(|| crate::C2Error::Protocol("No reconnect URL provided".to_string()))?;
                Ok(format!("RECONNECT to {}", url))
            }
            KillAction::Sleep => {
                Ok("SLEEP: entering deep sleep mode".to_string())
            }
            KillAction::Shutdown => {
                self.killed.store(true, Ordering::SeqCst);
                std::process::exit(0);
            }
        }
    }

    pub fn create_kill_command(action: KillAction, password: &str) -> KillCommand {
        KillCommand {
            action,
            password: password.to_string(),
            reconnect_url: None,
        }
    }

    pub fn get_signal(&self) -> Arc<AtomicBool> {
        self.killed.clone()
    }

    pub fn reset(&self) {
        self.killed.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch_default() {
        let config = KillSwitchConfig::default();
        assert_eq!(config.kill_password, "KRAKEN_KILL");
        assert_eq!(config.max_reconnect_attempts, 3);
    }

    #[test]
    fn test_process_kill() {
        let ks = KillSwitch::new(KillSwitchConfig::default());
        let cmd = KillSwitch::create_kill_command(KillAction::Kill, "KRAKEN_KILL");
        let result = ks.process_command(&cmd);
        assert!(result.is_ok());
        assert!(ks.is_killed());
    }

    #[test]
    fn test_process_kill_wrong_password() {
        let ks = KillSwitch::new(KillSwitchConfig::default());
        let cmd = KillCommand {
            action: KillAction::Kill,
            password: "wrong".to_string(),
            reconnect_url: None,
        };
        let result = ks.process_command(&cmd);
        assert!(result.is_err());
        assert!(!ks.is_killed());
    }

    #[test]
    fn test_process_reconnect() {
        let mut config = KillSwitchConfig::default();
        config.reconnect_url = Some("https://c2.kraken.local/reconnect".to_string());
        let ks = KillSwitch::new(config);
        let cmd = KillCommand {
            action: KillAction::Reconnect,
            password: "KRAKEN_KILL".to_string(),
            reconnect_url: None,
        };
        let result = ks.process_command(&cmd);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("RECONNECT"));
    }

    #[test]
    fn test_process_sleep() {
        let ks = KillSwitch::new(KillSwitchConfig::default());
        let cmd = KillSwitch::create_kill_command(KillAction::Sleep, "KRAKEN_KILL");
        let result = ks.process_command(&cmd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_shutdown() {
        let ks = KillSwitch::new(KillSwitchConfig::default());
        let cmd = KillSwitch::create_kill_command(KillAction::Shutdown, "KRAKEN_KILL");
        let result = ks.process_command(&cmd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reset() {
        let ks = KillSwitch::new(KillSwitchConfig::default());
        let cmd = KillSwitch::create_kill_command(KillAction::Kill, "KRAKEN_KILL");
        ks.process_command(&cmd).ok();
        assert!(ks.is_killed());
        ks.reset();
        assert!(!ks.is_killed());
    }

    #[test]
    fn test_kill_command_serialization() {
        let cmd = KillSwitch::create_kill_command(KillAction::Kill, "KRAKEN_KILL");
        let json = serde_json::to_string_pretty(&cmd).unwrap();
        assert!(json.contains("Kill"));
        assert!(json.contains("KRAKEN_KILL"));
    }

    #[test]
    fn test_kill_action_enum() {
        assert!(matches!(KillAction::Kill, KillAction::Kill));
        assert!(matches!(KillAction::Reconnect, KillAction::Reconnect));
    }
}
