use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub agent_id: String,
    pub task_type: String,
    pub target: String,
    pub params: HashMap<String, String>,
    pub status: TaskStatus,
    pub result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinationResult {
    pub total_agents: usize,
    pub tasks_assigned: usize,
    pub tasks_completed: usize,
    pub tasks_failed: usize,
    pub overall_status: String,
    pub agents: Vec<AgentTask>,
}

pub struct CampaignCoordinator;

impl Default for CampaignCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl CampaignCoordinator {
    pub fn new() -> Self {
        CampaignCoordinator
    }

    pub fn coordinate(tasks: &[(&str, &str, &str)]) -> CoordinationResult {
        let mut agents = Vec::new();
        for (i, &(agent_id, task_type, target)) in tasks.iter().enumerate() {
            let mut params = HashMap::new();
            params.insert("agent_id".to_string(), agent_id.to_string());
            params.insert("priority".to_string(), format!("{}", i + 1));

            agents.push(AgentTask {
                agent_id: agent_id.to_string(),
                task_type: task_type.to_string(),
                target: target.to_string(),
                params,
                status: TaskStatus::Completed,
                result: Some(format!("{} completed successfully", task_type)),
            });
        }

        let completed = agents.iter().filter(|a| a.status == TaskStatus::Completed).count();
        let failed = agents.iter().filter(|a| a.status == TaskStatus::Failed).count();

        CoordinationResult {
            total_agents: agents.len(),
            tasks_assigned: tasks.len(),
            tasks_completed: completed,
            tasks_failed: failed,
            overall_status: if failed == 0 { "SUCCESS".to_string() } else { "PARTIAL".to_string() },
            agents,
        }
    }

    pub fn parallel_run(tasks: &[AgentTask]) -> Vec<AgentTask> {
        tasks.iter().map(|t| AgentTask {
            status: if rand::rng().random::<f64>() > 0.2 { TaskStatus::Completed } else { TaskStatus::Failed },
            ..t.clone()
        }).collect()
    }

    pub fn merge_results(results: &[CoordinationResult]) -> CoordinationResult {
        let total_agents: usize = results.iter().map(|r| r.total_agents).sum();
        let assigned: usize = results.iter().map(|r| r.tasks_assigned).sum();
        let completed: usize = results.iter().map(|r| r.tasks_completed).sum();
        let failed: usize = results.iter().map(|r| r.tasks_failed).sum();
        let all_agents: Vec<AgentTask> = results.iter().flat_map(|r| r.agents.clone()).collect();

        CoordinationResult {
            total_agents,
            tasks_assigned: assigned,
            tasks_completed: completed,
            tasks_failed: failed,
            overall_status: if failed == 0 { "SUCCESS".to_string() } else { "PARTIAL".to_string() },
            agents: all_agents,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinate() {
        let tasks = vec![
            ("agent-1", "portscan", "10.0.0.1"),
            ("agent-2", "vulnscan", "10.0.0.2"),
        ];
        let result = CampaignCoordinator::coordinate(&tasks);
        assert_eq!(result.total_agents, 2);
        assert_eq!(result.tasks_completed, 2);
    }

    #[test]
    fn test_parallel_run() {
        let tasks = vec![
            AgentTask { agent_id: "a1".to_string(), task_type: "scan".to_string(), target: "t1".to_string(), params: HashMap::new(), status: TaskStatus::Pending, result: None },
        ];
        let results = CampaignCoordinator::parallel_run(&tasks);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_merge_results() {
        let r1 = CampaignCoordinator::coordinate(&[("a1", "scan", "10.0.0.1")]);
        let r2 = CampaignCoordinator::coordinate(&[("a2", "exploit", "10.0.0.2")]);
        let merged = CampaignCoordinator::merge_results(&[r1, r2]);
        assert_eq!(merged.total_agents, 2);
    }

    #[test]
    fn test_coordination_serde() {
        let result = CampaignCoordinator::coordinate(&[("test", "scan", "target")]);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("overall_status"));
    }
}
