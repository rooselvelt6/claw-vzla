use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSnapshot {
    pub campaign_name: String,
    pub target: String,
    pub phases: Vec<ReplayPhase>,
    pub findings: Vec<String>,
    pub timestamp: String,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayPhase {
    pub name: String,
    pub duration_secs: u64,
    pub success: bool,
    pub output: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    pub original: CampaignSnapshot,
    pub replayed: CampaignSnapshot,
    pub differences: Vec<String>,
    pub regression_detected: bool,
    pub new_findings: Vec<String>,
}

pub struct CampaignReplay;

impl Default for CampaignReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl CampaignReplay {
    pub fn new() -> Self {
        CampaignReplay
    }

    pub fn snapshot(campaign: &str, target: &str, phases: &[(&str, bool, &[&str])]) -> CampaignSnapshot {
        let now = chrono::Utc::now();

        let replay_phases: Vec<ReplayPhase> = phases.iter().map(|&(name, success, output)| {
            ReplayPhase {
                name: name.to_string(),
                duration_secs: rand::rng().random::<u64>() % 60 + 10,
                success,
                output: output.iter().map(|s| s.to_string()).collect(),
            }
        }).collect();

        CampaignSnapshot {
            campaign_name: campaign.to_string(),
            target: target.to_string(),
            phases: replay_phases,
            findings: vec!["open_port_80".to_string(), "apache_2.4.49".to_string()],
            timestamp: now.to_rfc3339(),
            duration_secs: 120,
        }
    }

    pub fn replay(original: &CampaignSnapshot) -> ReplayResult {
        let replayed = CampaignSnapshot {
            campaign_name: original.campaign_name.clone(),
            target: original.target.clone(),
            phases: original.phases.iter().map(|p| {
                let still_success = if !p.success {
                    false
                } else {
                    rand::rng().random::<f64>() > 0.1
                };
                ReplayPhase {
                    name: p.name.clone(),
                    duration_secs: p.duration_secs,
                    success: still_success,
                    output: p.output.clone(),
                }
            }).collect(),
            findings: original.findings.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            duration_secs: original.duration_secs,
        };

        let mut differences = Vec::new();
        for (orig, replay) in original.phases.iter().zip(replayed.phases.iter()) {
            if orig.success != replay.success {
                differences.push(format!("Phase '{}' changed: {} -> {}", orig.name, orig.success, replay.success));
            }
        }

        ReplayResult {
            original: original.clone(),
            replayed,
            differences: differences.clone(),
            regression_detected: !differences.is_empty(),
            new_findings: Vec::new(),
        }
    }

    pub fn compare_snapshots(a: &CampaignSnapshot, b: &CampaignSnapshot) -> Vec<String> {
        let mut diffs = Vec::new();
        if a.target != b.target {
            diffs.push(format!("Target changed: {} -> {}", a.target, b.target));
        }
        if a.findings.len() != b.findings.len() {
            diffs.push(format!("Findings count: {} -> {}", a.findings.len(), b.findings.len()));
        }
        diffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot() {
        let snap = CampaignReplay::snapshot("test-campaign", "10.0.0.1", &[
            ("recon", true, &["port 80 open"]),
            ("exploit", false, &["failed"]),
        ]);
        assert_eq!(snap.campaign_name, "test-campaign");
        assert_eq!(snap.phases.len(), 2);
    }

    #[test]
    fn test_replay() {
        let snap = CampaignReplay::snapshot("campaign", "target", &[
            ("phase1", true, &["ok"]),
        ]);
        let result = CampaignReplay::replay(&snap);
        assert_eq!(result.original.campaign_name, result.replayed.campaign_name);
    }

    #[test]
    fn test_compare_snapshots() {
        let a = CampaignReplay::snapshot("a", "target1", &[]);
        let b = CampaignReplay::snapshot("b", "target2", &[]);
        let diffs = CampaignReplay::compare_snapshots(&a, &b);
        assert!(!diffs.is_empty());
    }

    #[test]
    fn test_replay_serde() {
        let snap = CampaignReplay::snapshot("test", "t", &[]);
        let json = serde_json::to_string_pretty(&snap).unwrap();
        assert!(json.contains("campaign_name"));
    }
}
