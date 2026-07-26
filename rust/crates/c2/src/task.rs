use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Task {
    pub id: String,
    pub agent_id: String,
    pub action: String,
    pub args: String,
    pub status: TaskStatus,
    pub created_at: String,
    pub result: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "Pending"),
            TaskStatus::Running => write!(f, "Running"),
            TaskStatus::Completed => write!(f, "Completed"),
            TaskStatus::Failed => write!(f, "Failed"),
            TaskStatus::Cancelled => write!(f, "Cancelled"),
        }
    }
}

pub struct TaskManager {
    tasks: Arc<Mutex<HashMap<String, Task>>>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        TaskManager {
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn create_task(&self, agent_id: &str, action: &str, args: &str) -> Task {
        let task = Task {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: agent_id.to_string(),
            action: action.to_string(),
            args: args.to_string(),
            status: TaskStatus::Pending,
            created_at: chrono::Utc::now().to_rfc3339(),
            result: None,
        };
        let id = task.id.clone();
        let mut tasks = self.tasks.lock().await;
        tasks.insert(id, task.clone());
        task
    }

    pub async fn update_status(&self, task_id: &str, status: TaskStatus, result: Option<String>) -> Result<(), crate::C2Error> {
        let mut tasks = self.tasks.lock().await;
        let task = tasks.get_mut(task_id).ok_or_else(|| crate::C2Error::TaskNotFound(task_id.to_string()))?;
        task.status = status;
        if let Some(r) = result {
            task.result = Some(r);
        }
        Ok(())
    }

    pub async fn get_task(&self, task_id: &str) -> Option<Task> {
        let tasks = self.tasks.lock().await;
        tasks.get(task_id).cloned()
    }

    pub async fn get_pending_tasks(&self, agent_id: &str) -> Vec<Task> {
        let tasks = self.tasks.lock().await;
        tasks.values()
            .filter(|t| t.agent_id == agent_id && t.status == TaskStatus::Pending)
            .cloned()
            .collect()
    }

    pub async fn list_agent_tasks(&self, agent_id: &str) -> Vec<Task> {
        let tasks = self.tasks.lock().await;
        tasks.values()
            .filter(|t| t.agent_id == agent_id)
            .cloned()
            .collect()
    }

    pub async fn cancel_task(&self, task_id: &str) -> Result<(), crate::C2Error> {
        self.update_status(task_id, TaskStatus::Cancelled, None).await
    }

    pub async fn task_count(&self) -> usize {
        let tasks = self.tasks.lock().await;
        tasks.len()
    }

    pub async fn generate_task_report(&self, agent_id: &str) -> String {
        let tasks = self.list_agent_tasks(agent_id).await;
        let mut report = format!("=== Task Report for Agent {} ===\n", agent_id);
        for task in &tasks {
            report.push_str(&format!(
                "[{}] {}: {} -> {:?}\n",
                task.id.chars().take(8).collect::<String>(),
                task.action, task.status, task.result.as_deref().unwrap_or(""),
            ));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_task() {
        let tm = TaskManager::new();
        let task = tm.create_task("agent-1", "exec", "whoami").await;
        assert_eq!(task.action, "exec");
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[tokio::test]
    async fn test_update_task_status() {
        let tm = TaskManager::new();
        let task = tm.create_task("agent-1", "exec", "id").await;
        let result = tm.update_status(&task.id, TaskStatus::Completed, Some("uid=0(root)".to_string())).await;
        assert!(result.is_ok());
        let updated = tm.get_task(&task.id).await.unwrap();
        assert_eq!(updated.status, TaskStatus::Completed);
        assert_eq!(updated.result.unwrap(), "uid=0(root)");
    }

    #[tokio::test]
    async fn test_get_pending_tasks() {
        let tm = TaskManager::new();
        tm.create_task("agent-1", "exec", "whoami").await;
        tm.create_task("agent-2", "exec", "id").await;
        let pending = tm.get_pending_tasks("agent-1").await;
        assert_eq!(pending.len(), 1);
    }

    #[tokio::test]
    async fn test_cancel_task() {
        let tm = TaskManager::new();
        let task = tm.create_task("agent-1", "sleep", "60").await;
        tm.cancel_task(&task.id).await.unwrap();
        let t = tm.get_task(&task.id).await.unwrap();
        assert_eq!(t.status, TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn test_task_count() {
        let tm = TaskManager::new();
        tm.create_task("agent-1", "exec", "ls").await;
        tm.create_task("agent-1", "exec", "pwd").await;
        assert_eq!(tm.task_count().await, 2);
    }

    #[test]
    fn test_task_serialization() {
        let task = Task {
            id: "123".to_string(),
            agent_id: "agent-1".to_string(),
            action: "exec".to_string(),
            args: "whoami".to_string(),
            status: TaskStatus::Completed,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            result: Some("root".to_string()),
        };
        let json = serde_json::to_string_pretty(&task).unwrap();
        assert!(json.contains("Completed"));
    }

    #[test]
    fn test_task_status_partial_eq() {
        assert_eq!(TaskStatus::Pending, TaskStatus::Pending);
        assert_ne!(TaskStatus::Pending, TaskStatus::Completed);
    }

    #[tokio::test]
    async fn test_generate_report() {
        let tm = TaskManager::new();
        tm.create_task("agent-1", "exec", "whoami").await;
        let report = tm.generate_task_report("agent-1").await;
        assert!(report.contains("agent-1"));
    }

    #[tokio::test]
    async fn test_list_agent_tasks() {
        let tm = TaskManager::new();
        tm.create_task("agent-1", "exec", "a").await;
        tm.create_task("agent-1", "exec", "b").await;
        tm.create_task("agent-2", "exec", "c").await;
        assert_eq!(tm.list_agent_tasks("agent-1").await.len(), 2);
    }
}
