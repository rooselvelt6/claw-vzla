use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: String,
    pub name: String,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
    pub is_online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: u64,
    pub user_id: String,
    pub user_name: String,
    pub text: String,
    pub timestamp: DateTime<Utc>,
    pub message_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabSession {
    pub id: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub users: Vec<SessionUser>,
    pub messages: Vec<ChatMessage>,
    pub findings_shared: Vec<SharedFinding>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub shared_by: String,
    pub shared_at: DateTime<Utc>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollabServer {
    pub sessions: HashMap<String, CollabSession>,
    pub max_users_per_session: usize,
    pub session_timeout_minutes: u32,
}

impl CollabServer {
    pub fn new(max_users: usize, timeout_minutes: u32) -> Self {
        Self {
            sessions: HashMap::new(),
            max_users_per_session: max_users,
            session_timeout_minutes: timeout_minutes,
        }
    }

    pub fn create_session(&mut self, name: String) -> String {
        let id = generate_session_id();
        let session = CollabSession {
            id: id.clone(),
            name,
            created_at: Utc::now(),
            users: Vec::new(),
            messages: Vec::new(),
            findings_shared: Vec::new(),
            is_active: true,
        };
        self.sessions.insert(id.clone(), session);
        id
    }

    pub fn close_session(&mut self, session_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.is_active = false;
            for user in &mut session.users {
                user.is_online = false;
            }
            true
        } else {
            false
        }
    }

    pub fn join_session(&mut self, session_id: &str, user: SessionUser) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "Session not found".to_string())?;

        if !session.is_active {
            return Err("Session is closed".to_string());
        }

        let online_count = session.users.iter().filter(|u| u.is_online).count();
        if online_count >= self.max_users_per_session {
            return Err("Session is full".to_string());
        }

        if session.users.iter().any(|u| u.id == user.id) {
            return Err("User already in session".to_string());
        }

        session.users.push(user);
        Ok(())
    }

    pub fn leave_session(&mut self, session_id: &str, user_id: &str) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            let len = session.users.len();
            session.users.retain(|u| u.id != user_id);
            session.users.len() < len
        } else {
            false
        }
    }

    pub fn send_message(&mut self, session_id: &str, user_id: &str, text: &str) -> Result<ChatMessage, String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "Session not found".to_string())?;

        let user = session
            .users
            .iter()
            .find(|u| u.id == user_id)
            .ok_or_else(|| "User not in session".to_string())?;

        let msg = ChatMessage {
            id: session.messages.len() as u64 + 1,
            user_id: user_id.to_string(),
            user_name: user.name.clone(),
            text: text.to_string(),
            timestamp: Utc::now(),
            message_type: "chat".to_string(),
        };

        session.messages.push(msg.clone());
        Ok(msg)
    }

    pub fn share_finding(
        &mut self,
        session_id: &str,
        title: &str,
        severity: &str,
        shared_by: &str,
        notes: &str,
    ) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "Session not found".to_string())?;

        let finding = SharedFinding {
            id: generate_finding_id(),
            title: title.to_string(),
            severity: severity.to_string(),
            shared_by: shared_by.to_string(),
            shared_at: Utc::now(),
            notes: notes.to_string(),
        };

        session.findings_shared.push(finding);
        Ok(())
    }

    pub fn active_sessions(&self) -> Vec<&CollabSession> {
        self.sessions.values().filter(|s| s.is_active).collect()
    }

    pub fn user_online_count(&self, session_id: &str) -> usize {
        self.sessions
            .get(session_id)
            .map(|s| s.users.iter().filter(|u| u.is_online).count())
            .unwrap_or(0)
    }

    pub fn session_summary(&self, session_id: &str) -> Option<String> {
        self.sessions.get(session_id).map(|s| {
            format!(
                "Session: {} | Users online: {} | Messages: {} | Findings: {}",
                s.name,
                s.users.iter().filter(|u| u.is_online).count(),
                s.messages.len(),
                s.findings_shared.len(),
            )
        })
    }
}

fn generate_session_id() -> String {
    let mut rng = rand::rng();
    let id: u64 = rng.random();
    format!("sess_{:016x}", id)
}

fn generate_finding_id() -> String {
    let mut rng = rand::rng();
    let id: u64 = rng.random();
    format!("find_{:016x}", id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(id: &str) -> SessionUser {
        SessionUser {
            id: id.to_string(),
            name: format!("User {}", id),
            role: "analyst".into(),
            joined_at: Utc::now(),
            last_active: Utc::now(),
            is_online: true,
        }
    }

    #[test]
    fn test_new_server() {
        let server = CollabServer::new(10, 60);
        assert_eq!(server.max_users_per_session, 10);
        assert!(server.sessions.is_empty());
    }

    #[test]
    fn test_create_session() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("Test Scan".into());
        assert!(server.sessions.contains_key(&id));
    }

    #[test]
    fn test_join_session() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("Scan".into());
        assert!(server.join_session(&id, test_user("u1")).is_ok());
        assert_eq!(server.user_online_count(&id), 1);
    }

    #[test]
    fn test_join_nonexistent() {
        let mut server = CollabServer::new(5, 30);
        assert!(server.join_session("nonexistent", test_user("u1")).is_err());
    }

    #[test]
    fn test_leave_session() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("S".into());
        server.join_session(&id, test_user("u1")).unwrap();
        assert!(server.leave_session(&id, "u1"));
        assert_eq!(server.user_online_count(&id), 0);
    }

    #[test]
    fn test_send_message() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("S".into());
        server.join_session(&id, test_user("u1")).unwrap();
        let msg = server.send_message(&id, "u1", "Hello team");
        assert!(msg.is_ok());
        assert_eq!(msg.unwrap().text, "Hello team");
    }

    #[test]
    fn test_share_finding() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("Audit".into());
        server.join_session(&id, test_user("analyst1")).unwrap();
        assert!(server
            .share_finding(&id, "SQL Injection", "Critical", "analyst1", "Found in login")
            .is_ok());
    }

    #[test]
    fn test_close_session() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("S".into());
        server.join_session(&id, test_user("u1")).unwrap();
        assert!(server.close_session(&id));
        let session = server.sessions.get(&id).unwrap();
        assert!(!session.is_active);
    }

    #[test]
    fn test_active_sessions() {
        let mut server = CollabServer::new(5, 30);
        server.create_session("Active".into());
        let id2 = server.create_session("Closed".into());
        server.close_session(&id2);
        assert_eq!(server.active_sessions().len(), 1);
    }

    #[test]
    fn test_session_summary() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("My Session".into());
        server.join_session(&id, test_user("u1")).unwrap();
        let summary = server.session_summary(&id);
        assert!(summary.is_some());
        assert!(summary.unwrap().contains("My Session"));
    }

    #[test]
    fn test_join_when_full() {
        let mut server = CollabServer::new(1, 30);
        let id = server.create_session("Full".into());
        server.join_session(&id, test_user("u1")).unwrap();
        assert!(server.join_session(&id, test_user("u2")).is_err());
    }

    #[test]
    fn test_send_message_not_member() {
        let mut server = CollabServer::new(5, 30);
        let id = server.create_session("S".into());
        let msg = server.send_message(&id, "outsider", "Hi");
        assert!(msg.is_err());
    }
}
