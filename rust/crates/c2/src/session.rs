use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentSession {
    pub agent_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub external_ip: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub beacon_type: String,
    pub alive: bool,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionStats {
    pub total_agents: usize,
    pub alive_agents: usize,
    pub dead_agents: usize,
    pub by_os: HashMap<String, usize>,
    pub by_beacon: HashMap<String, usize>,
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, AgentSession>>>,
    timeout_secs: u64,
}

impl SessionManager {
    pub fn new(timeout_secs: u64) -> Self {
        SessionManager {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            timeout_secs,
        }
    }

    pub async fn register_session(&self, session: AgentSession) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session.agent_id.clone(), session);
    }

    pub async fn heartbeat(&self, agent_id: &str) -> Result<(), crate::C2Error> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(agent_id)
            .ok_or_else(|| crate::C2Error::Session(format!("Agent {} not registered", agent_id)))?;
        session.last_seen = chrono::Utc::now().to_rfc3339();
        session.alive = true;
        Ok(())
    }

    pub async fn mark_dead(&self, agent_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(agent_id) {
            session.alive = false;
        }
    }

    pub async fn get_session(&self, agent_id: &str) -> Option<AgentSession> {
        let sessions = self.sessions.read().await;
        sessions.get(agent_id).cloned()
    }

    pub async fn list_alive(&self) -> Vec<AgentSession> {
        let sessions = self.sessions.read().await;
        sessions.values()
            .filter(|s| s.alive)
            .cloned()
            .collect()
    }

    pub async fn list_all(&self) -> Vec<AgentSession> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    pub async fn remove_agent(&self, agent_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(agent_id);
    }

    pub async fn update_tags(&self, agent_id: &str, tags: Vec<String>) -> Result<(), crate::C2Error> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(agent_id)
            .ok_or_else(|| crate::C2Error::AgentNotFound(agent_id.to_string()))?;
        session.tags = tags;
        Ok(())
    }

    pub async fn stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;
        let total = sessions.len();
        let mut alive = 0;
        let mut dead = 0;
        let mut by_os: HashMap<String, usize> = HashMap::new();
        let mut by_beacon: HashMap<String, usize> = HashMap::new();

        for s in sessions.values() {
            if s.alive { alive += 1; } else { dead += 1; }
            *by_os.entry(s.os.clone()).or_default() += 1;
            *by_beacon.entry(s.beacon_type.clone()).or_default() += 1;
        }

        SessionStats { total_agents: total, alive_agents: alive, dead_agents: dead, by_os, by_beacon }
    }

    pub async fn check_timeouts(&self) {
        let mut sessions = self.sessions.write().await;
        let now = chrono::Utc::now();
        for session in sessions.values_mut() {
            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&session.last_seen) {
                let last_utc = last.with_timezone(&chrono::Utc);
                let elapsed = (now - last_utc).num_seconds() as u64;
                if elapsed > self.timeout_secs {
                    session.alive = false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(agent_id: &str) -> AgentSession {
        AgentSession {
            agent_id: agent_id.to_string(),
            hostname: "victim".to_string(),
            username: "root".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            external_ip: None,
            first_seen: chrono::Utc::now().to_rfc3339(),
            last_seen: chrono::Utc::now().to_rfc3339(),
            beacon_type: "http".to_string(),
            alive: true,
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn test_register_and_get() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        let session = sm.get_session("agent-1").await;
        assert!(session.is_some());
        assert_eq!(session.unwrap().agent_id, "agent-1");
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        assert!(sm.heartbeat("agent-1").await.is_ok());
        assert!(sm.heartbeat("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_mark_dead() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        sm.mark_dead("agent-1").await;
        let session = sm.get_session("agent-1").await.unwrap();
        assert!(!session.alive);
    }

    #[tokio::test]
    async fn test_list_alive() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        let mut dead = test_session("agent-2");
        dead.alive = false;
        sm.register_session(dead).await;
        let alive = sm.list_alive().await;
        assert_eq!(alive.len(), 1);
    }

    #[tokio::test]
    async fn test_remove_agent() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        sm.remove_agent("agent-1").await;
        assert!(sm.get_session("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn test_stats() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        sm.register_session(test_session("agent-2")).await;
        let stats = sm.stats().await;
        assert_eq!(stats.total_agents, 2);
        assert_eq!(stats.alive_agents, 2);
    }

    #[tokio::test]
    async fn test_update_tags() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("agent-1")).await;
        sm.update_tags("agent-1", vec!["dmz".to_string(), "production".to_string()]).await.unwrap();
        let session = sm.get_session("agent-1").await.unwrap();
        assert_eq!(session.tags.len(), 2);
    }

    #[test]
    fn test_session_serialization() {
        let session = test_session("agent-1");
        let json = serde_json::to_string_pretty(&session).unwrap();
        assert!(json.contains("agent-1"));
        assert!(json.contains("http"));
    }

    #[tokio::test]
    async fn test_list_all() {
        let sm = SessionManager::new(300);
        sm.register_session(test_session("a")).await;
        sm.register_session(test_session("b")).await;
        assert_eq!(sm.list_all().await.len(), 2);
    }
}
