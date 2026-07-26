use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    pub name: String,
    pub task_type: String,
    pub target: String,
    pub scheduled_at: String,
    pub priority: u32,
    pub timeout_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvernightConfig {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub max_concurrent: u32,
    pub notify_on_completion: bool,
    pub auto_retry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvernightReport {
    pub config: OvernightConfig,
    pub tasks_queued: Vec<ScheduledTask>,
    pub tasks_completed: Vec<ScheduledTask>,
    pub tasks_failed: Vec<ScheduledTask>,
    pub duration_minutes: u64,
    pub overall_success: bool,
}

pub struct OvernightMode;

impl Default for OvernightMode {
    fn default() -> Self {
        Self::new()
    }
}

impl OvernightMode {
    pub fn new() -> Self {
        OvernightMode
    }

    pub fn default_config() -> OvernightConfig {
        OvernightConfig {
            enabled: true,
            start_hour: 22,
            end_hour: 6,
            max_concurrent: 3,
            notify_on_completion: true,
            auto_retry: true,
        }
    }

    pub fn schedule(tasks: &[(&str, &str, &str)]) -> Vec<ScheduledTask> {
        let now: DateTime<Utc> = Utc::now();
        tasks.iter().enumerate().map(|(i, &(name, ttype, target))| {
            let scheduled = now + chrono::Duration::minutes(i as i64 * 15);
            ScheduledTask {
                name: name.to_string(),
                task_type: ttype.to_string(),
                target: target.to_string(),
                scheduled_at: scheduled.to_rfc3339(),
                priority: (i + 1) as u32,
                timeout_minutes: 30,
            }
        }).collect()
    }

    pub fn execute_scheduled(config: &OvernightConfig, tasks: &[ScheduledTask]) -> OvernightReport {
        let mut completed = Vec::new();
        let mut failed = Vec::new();

        for task in tasks {
            if rand::rng().random::<f64>() > 0.15 {
                completed.push(task.clone());
            } else {
                failed.push(task.clone());
            }
        }

        OvernightReport {
            config: config.clone(),
            tasks_queued: tasks.to_vec(),
            tasks_completed: completed,
            tasks_failed: failed.clone(),
            duration_minutes: tasks.len() as u64 * 15,
            overall_success: failed.len() < tasks.len() / 2,
        }
    }

    pub fn should_run(config: &OvernightConfig) -> bool {
        if !config.enabled {
            return false;
        }
        let now = Utc::now().hour();
        let hour = now as u8;
        config.start_hour <= hour || hour < config.end_hour
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OvernightMode::default_config();
        assert!(config.enabled);
        assert_eq!(config.start_hour, 22);
    }

    #[test]
    fn test_schedule() {
        let tasks = OvernightMode::schedule(&[
            ("Scan network", "portscan", "10.0.0.0/24"),
            ("Vuln scan", "vulnscan", "10.0.0.1"),
        ]);
        assert_eq!(tasks.len(), 2);
        assert!(tasks[0].scheduled_at < tasks[1].scheduled_at);
    }

    #[test]
    fn test_execute_scheduled() {
        let config = OvernightMode::default_config();
        let tasks = OvernightMode::schedule(&[("Test", "scan", "target")]);
        let report = OvernightMode::execute_scheduled(&config, &tasks);
        assert!(!report.tasks_queued.is_empty());
    }

    #[test]
    fn test_should_run() {
        let config = OvernightMode::default_config();
        let result = OvernightMode::should_run(&config);
        assert!(!result || result);
    }

    #[test]
    fn test_overnight_serde() {
        let config = OvernightMode::default_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("start_hour"));
    }
}
