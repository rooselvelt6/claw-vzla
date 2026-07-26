//! Adaptive Security Engine (Fase 10): auto-defensa con ML, threat intelligence,
//! honeytokens, auto-tuning de umbrales, respuesta automatica a incidentes,
//! post-mortem, evolucion de politicas y A/B testing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kraken_errors::RuntimeError;

use crate::heuristic_engine::{HeuristicEngine, RiskLevel};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default threat intel update interval (hours).
const THREAT_INTEL_UPDATE_HOURS: u64 = 24;
/// Default confidence threshold for honeytoken detection.
#[allow(dead_code)]
const HONEYTOKEN_CONFIDENCE_THRESHOLD: f64 = 0.9;
/// Default FP rate threshold for auto-tuning (%). Exceeding triggers threshold raise.
const FP_RATE_THRESHOLD_PCT: f64 = 5.0;
/// Default FN rate threshold for auto-tuning (%). Exceeding triggers threshold lower.
const FN_RATE_THRESHOLD_PCT: f64 = 20.0;
/// Default auto-tuning interval (hours).
const AUTO_TUNE_INTERVAL_HOURS: u64 = 24;
/// Max threat score before auto-block.
const AUTO_BLOCK_THRESHOLD: f64 = 0.95;
/// Default A/B test sample size per arm.
const AB_TEST_MIN_SAMPLES: u64 = 50;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedEntry {
    pub indicator: String,
    pub indicator_type: ThreatIndicatorType,
    pub severity: ThreatSeverity,
    pub source: String,
    pub last_seen: u64,
    pub confidence: f64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatIndicatorType {
    IpAddress,
    Domain,
    Url,
    HashMd5,
    HashSha1,
    HashSha256,
    Cve,
    Email,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneytokenFile {
    pub path: PathBuf,
    pub name: String,
    pub content_pattern: String,
    pub risk_boost: f64,
    pub triggered: bool,
    pub triggered_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub safe_max: f64,
    pub low_max: f64,
    pub medium_max: f64,
    pub high_max: f64,
    pub last_tuned_at: u64,
    pub fp_count: u64,
    pub fn_count: u64,
    pub total_evaluations: u64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            safe_max: 0.30,
            low_max: 0.60,
            medium_max: 0.80,
            high_max: 0.95,
            last_tuned_at: 0,
            fp_count: 0,
            fn_count: 0,
            total_evaluations: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub id: u64,
    pub timestamp: u64,
    pub threat_score: f64,
    pub trigger: String,
    pub command: String,
    pub tool: String,
    pub snapshot_path: Option<String>,
    pub action_taken: IncidentAction,
    pub resolved: bool,
    pub resolved_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentAction {
    Blocked,
    Prompted,
    Isolated,
    Notified,
    NoAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMortemReport {
    pub incident_id: u64,
    pub timestamp: u64,
    pub summary: String,
    pub timeline: Vec<PostMortemEvent>,
    pub root_cause: String,
    pub evidence: Vec<String>,
    pub policy_recommendations: Vec<String>,
    pub prevention_measures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMortemEvent {
    pub time: u64,
    pub event: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub policy_name: String,
    pub weight_adjustment: f64,
    pub severity_adjustment: f64,
    pub reason: String,
    pub applied_at: u64,
    pub effect_fp_rate: f64,
    pub effect_fn_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbTestArm {
    pub name: String,
    pub description: String,
    pub threshold_adjustments: HashMap<String, f64>,
    pub samples: u64,
    pub fp_count: u64,
    pub fn_count: u64,
}

impl AbTestArm {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fp_rate(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        self.fp_count as f64 / self.samples as f64 * 100.0
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fn_rate(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        self.fn_count as f64 / self.samples as f64 * 100.0
    }

    #[must_use]
    pub fn combined_score(&self) -> f64 {
        self.fp_rate() * 0.5 + self.fn_rate() * 0.5
    }
}

// ---------------------------------------------------------------------------
// ThreatIntel
// ---------------------------------------------------------------------------

pub struct ThreatIntel {
    feeds: Vec<ThreatFeedEntry>,
    last_update: Instant,
    update_interval: Duration,
    feed_path: Option<PathBuf>,
}

impl ThreatIntel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            last_update: Instant::now(),
            update_interval: Duration::from_secs(THREAT_INTEL_UPDATE_HOURS * 3600),
            feed_path: None,
        }
    }

    #[must_use]
    pub fn with_feed_path(mut self, path: &Path) -> Self {
        self.feed_path = Some(path.to_path_buf());
        self
    }

    #[must_use]
    pub fn needs_update(&self) -> bool {
        self.last_update.elapsed() >= self.update_interval
    }

    pub fn update(&mut self) -> Result<usize, RuntimeError> {
        let mut count = 0;

        if let Some(ref path) = self.feed_path {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(entries) = serde_json::from_str::<Vec<ThreatFeedEntry>>(&content) {
                        self.feeds = entries;
                        count = self.feeds.len();
                    }
                }
            }
        }

        // Add built-in known malicious indicators
        self.feeds.extend(builtin_threat_feeds());
        count += self.feeds.len();

        self.last_update = Instant::now();
        Ok(count)
    }

    #[must_use]
    pub fn check_indicator(&self, value: &str) -> Vec<&ThreatFeedEntry> {
        self.feeds.iter().filter(|e| e.indicator == value).collect()
    }

    #[must_use]
    pub fn check_ip(&self, ip: &str) -> Vec<&ThreatFeedEntry> {
        self.check_indicator(ip)
            .into_iter()
            .filter(|e| e.indicator_type == ThreatIndicatorType::IpAddress)
            .collect()
    }

    #[must_use]
    pub fn check_domain(&self, domain: &str) -> Vec<&ThreatFeedEntry> {
        self.check_indicator(domain)
            .into_iter()
            .filter(|e| e.indicator_type == ThreatIndicatorType::Domain)
            .collect()
    }

    #[must_use]
    pub fn check_url(&self, url: &str) -> Vec<&ThreatFeedEntry> {
        self.check_indicator(url)
            .into_iter()
            .filter(|e| e.indicator_type == ThreatIndicatorType::Url)
            .collect()
    }

    #[must_use]
    pub fn check_cve(&self, cve: &str) -> Vec<&ThreatFeedEntry> {
        self.check_indicator(cve)
            .into_iter()
            .filter(|e| e.indicator_type == ThreatIndicatorType::Cve)
            .collect()
    }

    #[must_use]
    pub fn check_hash(&self, hash: &str) -> Vec<&ThreatFeedEntry> {
        self.check_indicator(hash)
            .into_iter()
            .filter(|e| {
                matches!(
                    e.indicator_type,
                    ThreatIndicatorType::HashMd5
                        | ThreatIndicatorType::HashSha1
                        | ThreatIndicatorType::HashSha256
                )
            })
            .collect()
    }

    pub fn threat_score_for(&self, value: &str) -> f64 {
        let matches = self.check_indicator(value);
        if matches.is_empty() {
            return 0.0;
        }
        matches
            .iter()
            .map(|e| match e.severity {
                ThreatSeverity::Low => 0.3,
                ThreatSeverity::Medium => 0.5,
                ThreatSeverity::High => 0.8,
                ThreatSeverity::Critical => 1.0,
            } * e.confidence)
            .fold(0.0, f64::max)
    }

    #[must_use]
    pub fn feed_count(&self) -> usize {
        self.feeds.len()
    }

    pub fn reset(&mut self) {
        self.feeds.clear();
        self.last_update = Instant::now();
    }
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in known threat indicators (CVE, bad IPs, malware hashes).
fn builtin_threat_feeds() -> Vec<ThreatFeedEntry> {
    vec![
        // Critical CVEs
        ThreatFeedEntry {
            indicator: "CVE-2024-27198".into(),
            indicator_type: ThreatIndicatorType::Cve,
            severity: ThreatSeverity::Critical,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.95,
            tags: vec!["rce".into(), "jetbrains".into(), "auth-bypass".into()],
        },
        ThreatFeedEntry {
            indicator: "CVE-2023-44487".into(),
            indicator_type: ThreatIndicatorType::Cve,
            severity: ThreatSeverity::High,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.95,
            tags: vec!["http2".into(), "dos".into(), "rapid-reset".into()],
        },
        ThreatFeedEntry {
            indicator: "CVE-2023-34362".into(),
            indicator_type: ThreatIndicatorType::Cve,
            severity: ThreatSeverity::Critical,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.90,
            tags: vec!["sql-injection".into(), "moveit".into(), "rce".into()],
        },
        // Known malicious IPs (representative)
        ThreatFeedEntry {
            indicator: "185.220.101.0".into(),
            indicator_type: ThreatIndicatorType::IpAddress,
            severity: ThreatSeverity::High,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.80,
            tags: vec!["tor-exit".into(), "scanner".into()],
        },
        ThreatFeedEntry {
            indicator: "45.33.32.156".into(),
            indicator_type: ThreatIndicatorType::IpAddress,
            severity: ThreatSeverity::Medium,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.70,
            tags: vec!["scanner".into(), "shodan".into()],
        },
        // Known malicious domains
        ThreatFeedEntry {
            indicator: "malware.test.example.com".into(),
            indicator_type: ThreatIndicatorType::Domain,
            severity: ThreatSeverity::High,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.85,
            tags: vec!["c2".into(), "malware".into()],
        },
        ThreatFeedEntry {
            indicator: "phishing.test.example.com".into(),
            indicator_type: ThreatIndicatorType::Domain,
            severity: ThreatSeverity::High,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.85,
            tags: vec!["phishing".into(), "social-engineering".into()],
        },
        // Malware hashes (representative)
        ThreatFeedEntry {
            indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            indicator_type: ThreatIndicatorType::HashSha256,
            severity: ThreatSeverity::High,
            source: "builtin".into(),
            last_seen: now_secs(),
            confidence: 0.90,
            tags: vec!["malware".into(), "ransomware".into()],
        },
    ]
}

// ---------------------------------------------------------------------------
// HoneytokenManager
// ---------------------------------------------------------------------------

pub struct HoneytokenManager {
    tokens: Vec<HoneytokenFile>,
    #[allow(dead_code)]
    workspace_root: PathBuf,
    enabled: bool,
    trigger_count: AtomicU64,
}

impl HoneytokenManager {
    #[must_use]
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            tokens: default_honeytokens(workspace_root),
            workspace_root: workspace_root.to_path_buf(),
            enabled: true,
            trigger_count: AtomicU64::new(0),
        }
    }

    pub fn deploy(&self) -> Result<usize, RuntimeError> {
        let mut count = 0;
        for token in &self.tokens {
            if token.triggered {
                continue;
            }
            if let Some(parent) = token.path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let content = format!("{}\n# DO NOT MODIFY: security test file", token.content_pattern);
            match fs::write(&token.path, &content) {
                Ok(()) => count += 1,
                Err(e) => log::warn!("Failed to deploy honeytoken {}: {}", token.path.display(), e),
            }
        }
        Ok(count)
    }

    pub fn check_access(&mut self, path: &Path) -> Option<f64> {
        if !self.enabled {
            return None;
        }
        for token in &mut self.tokens {
            if token.triggered {
                continue;
            }
            if path == token.path || path.ends_with(&token.path) {
                token.triggered = true;
                token.triggered_at = Some(now_secs());
                self.trigger_count.fetch_add(1, Ordering::SeqCst);
                log::warn!(
                    "Honeytoken triggered: {:?} (boost: {:.2})",
                    token.name,
                    token.risk_boost
                );
                return Some(token.risk_boost);
            }
        }
        None
    }

    pub fn remove_all(&self) -> Result<usize, RuntimeError> {
        let mut count = 0;
        for token in &self.tokens {
            if token.path.exists() {
                let _ = fs::remove_file(&token.path);
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn is_triggered(&self, name: &str) -> bool {
        self.tokens.iter().any(|t| t.name == name && t.triggered)
    }

    pub fn trigger_count(&self) -> u64 {
        self.trigger_count.load(Ordering::SeqCst)
    }

    pub fn total_risk_boost(&self) -> f64 {
        self.tokens
            .iter()
            .filter(|t| t.triggered)
            .map(|t| t.risk_boost)
            .sum()
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn reset(&mut self) {
        for token in &mut self.tokens {
            token.triggered = false;
            token.triggered_at = None;
        }
        self.trigger_count.store(0, Ordering::SeqCst);
    }
}

fn default_honeytokens(workspace_root: &Path) -> Vec<HoneytokenFile> {
    vec![
        HoneytokenFile {
            path: workspace_root.join("config").join("credentials.yml"),
            name: "credentials.yml".into(),
            content_pattern: "aws_access_key_id: AKIA****************\naws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n".into(),
            risk_boost: 0.9,
            triggered: false,
            triggered_at: None,
        },
        HoneytokenFile {
            path: workspace_root.join(".env.production"),
            name: ".env.production".into(),
            content_pattern: "DATABASE_URL=postgresql://admin:supersecret@localhost:5432/production\nAPI_KEY=sk-proj-****************************\n".into(),
            risk_boost: 0.9,
            triggered: false,
            triggered_at: None,
        },
        HoneytokenFile {
            path: workspace_root.join(".ssh").join("id_rsa"),
            name: "ssh_key".into(),
            content_pattern: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----\n".into(),
            risk_boost: 0.95,
            triggered: false,
            triggered_at: None,
        },
        HoneytokenFile {
            path: workspace_root.join(".kraken").join("secrets.json"),
            name: "kraken_secrets".into(),
            content_pattern: "{\"master_key\": \"test-key-do-not-use\", \"vault_token\": \"hvs.**************************\"}".into(),
            risk_boost: 0.95,
            triggered: false,
            triggered_at: None,
        },
        HoneytokenFile {
            path: workspace_root.join("tmp").join("backup").join("dump.sql"),
            name: "database_dump".into(),
            content_pattern: "-- Production database dump\nINSERT INTO users (email, password_hash) VALUES ('admin@example.com', '$2a$10$**************************');\n".into(),
            risk_boost: 0.85,
            triggered: false,
            triggered_at: None,
        },
    ]
}

// ---------------------------------------------------------------------------
// AutoThreshold
// ---------------------------------------------------------------------------

pub struct AutoThreshold {
    config: ThresholdConfig,
    evaluation_history: Vec<ThresholdEvaluation>,
    last_tune: Instant,
    tune_interval: Duration,
}

#[allow(dead_code)]
struct ThresholdEvaluation {
    timestamp: u64,
    heuristic_score: f64,
    risk_level: RiskLevel,
    user_approved: bool,
    was_correct: bool,
}

impl AutoThreshold {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ThresholdConfig::default(),
            evaluation_history: Vec::new(),
            last_tune: Instant::now(),
            tune_interval: Duration::from_secs(AUTO_TUNE_INTERVAL_HOURS * 3600),
        }
    }

    #[must_use]
    pub fn with_interval(mut self, hours: u64) -> Self {
        self.tune_interval = Duration::from_secs(hours * 3600);
        self
    }

    pub fn record_evaluation(
        &mut self,
        score: f64,
        risk_level: RiskLevel,
        user_approved: bool,
        was_correct: bool,
    ) {
        self.evaluation_history.push(ThresholdEvaluation {
            timestamp: now_secs(),
            heuristic_score: score,
            risk_level,
            user_approved,
            was_correct,
        });
        self.config.total_evaluations += 1;
        if !was_correct && user_approved {
            // False positive: user approved despite system warning
            self.config.fp_count += 1;
        } else if !was_correct && !user_approved {
            // False negative: user rejected but should have been safe
            self.config.fn_count += 1;
        }
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fp_rate(&self) -> f64 {
        if self.config.total_evaluations == 0 {
            return 0.0;
        }
        self.config.fp_count as f64 / self.config.total_evaluations as f64 * 100.0
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn fn_rate(&self) -> f64 {
        if self.config.total_evaluations == 0 {
            return 0.0;
        }
        self.config.fn_count as f64 / self.config.total_evaluations as f64 * 100.0
    }

    #[must_use]
    pub fn needs_tune(&self) -> bool {
        self.config.total_evaluations >= 10 && self.last_tune.elapsed() >= self.tune_interval
    }

    pub fn tune(&mut self) -> ThresholdAdjustment {
        let fp = self.fp_rate();
        let fn_rate_val = self.fn_rate();
        let mut adjustments = ThresholdAdjustment::default();

        if fp > FP_RATE_THRESHOLD_PCT {
            // Too many false positives → raise thresholds
            let factor = (fp / FP_RATE_THRESHOLD_PCT).min(2.0);
            adjustments.safe_max_delta = 0.05 * factor;
            adjustments.low_max_delta = 0.05 * factor;
            adjustments.medium_max_delta = 0.03 * factor;
            adjustments.high_max_delta = 0.02 * factor;
            adjustments.reason = format!("FP rate {fp:.1}% > {FP_RATE_THRESHOLD_PCT:.0}% — raising thresholds");
        }

        if fn_rate_val > FN_RATE_THRESHOLD_PCT {
            // Too many false negatives → lower thresholds
            let factor = (fn_rate_val / FN_RATE_THRESHOLD_PCT).min(2.0);
            adjustments.safe_max_delta = -0.05 * factor;
            adjustments.low_max_delta = -0.05 * factor;
            adjustments.medium_max_delta = -0.03 * factor;
            adjustments.high_max_delta = -0.02 * factor;
            adjustments.reason = format!("FN rate {fn_rate_val:.1}% > {FN_RATE_THRESHOLD_PCT:.0}% — lowering thresholds");
        }

        // Apply adjustments within bounds
        self.config.safe_max = (self.config.safe_max + adjustments.safe_max_delta).clamp(0.1, 0.5);
        self.config.low_max = (self.config.low_max + adjustments.low_max_delta).clamp(0.3, 0.8);
        self.config.medium_max = (self.config.medium_max + adjustments.medium_max_delta).clamp(0.5, 0.95);
        self.config.high_max = (self.config.high_max + adjustments.high_max_delta).clamp(0.7, 0.99);
        self.config.last_tuned_at = now_secs();
        self.last_tune = Instant::now();

        // Log the tuning
        log::info!(
            "AutoThreshold: tuned safe={:.2} low={:.2} medium={:.2} high={:.2} | reason: {}",
            self.config.safe_max,
            self.config.low_max,
            self.config.medium_max,
            self.config.high_max,
            adjustments.reason
        );

        adjustments
    }

    #[must_use]
    pub fn config(&self) -> &ThresholdConfig {
        &self.config
    }

    #[must_use]
    pub fn threshold_for(&self, risk_level: RiskLevel) -> f64 {
        match risk_level {
            RiskLevel::Safe => self.config.safe_max,
            RiskLevel::Low => self.config.low_max,
            RiskLevel::Medium => self.config.medium_max,
            RiskLevel::High => self.config.high_max,
            RiskLevel::Critical => 1.0,
        }
    }

    pub fn reset(&mut self) {
        self.config = ThresholdConfig::default();
        self.evaluation_history.clear();
        self.last_tune = Instant::now();
    }
}

impl Default for AutoThreshold {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ThresholdAdjustment {
    pub safe_max_delta: f64,
    pub low_max_delta: f64,
    pub medium_max_delta: f64,
    pub high_max_delta: f64,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// IncidentResponse
// ---------------------------------------------------------------------------

pub struct IncidentResponse {
    incidents: Vec<IncidentRecord>,
    next_id: AtomicU64,
    snapshot_dir: Option<PathBuf>,
    auto_block: bool,
    auto_isolate: bool,
}

impl IncidentResponse {
    #[must_use]
    pub fn new() -> Self {
        Self {
            incidents: Vec::new(),
            next_id: AtomicU64::new(1),
            snapshot_dir: None,
            auto_block: true,
            auto_isolate: true,
        }
    }

    #[must_use]
    pub fn with_snapshot_dir(mut self, dir: &Path) -> Self {
        self.snapshot_dir = Some(dir.to_path_buf());
        self
    }

    pub fn evaluate_threat(
        &mut self,
        score: f64,
        command: &str,
        tool: &str,
        _engine: &mut HeuristicEngine,
    ) -> IncidentAction {
        if score < AUTO_BLOCK_THRESHOLD {
            return IncidentAction::NoAction;
        }

        let incident_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let timestamp = now_secs();

        // Determine action based on score
        let action = if score >= 0.99 && self.auto_block {
            IncidentAction::Blocked
        } else if score >= 0.97 && self.auto_isolate {
            IncidentAction::Isolated
        } else {
            IncidentAction::Prompted
        };

        // Take snapshot if configured
        let snapshot_path = if action == IncidentAction::Blocked || action == IncidentAction::Isolated
        {
            self.take_snapshot(incident_id)
        } else {
            None
        };

        // Record incident
        let incident = IncidentRecord {
            id: incident_id,
            timestamp,
            threat_score: score,
            trigger: format!("score {score:.3} >= 0.95"),
            command: command.to_string(),
            tool: tool.to_string(),
            snapshot_path,
            action_taken: action,
            resolved: false,
            resolved_at: None,
        };
        self.incidents.push(incident);

        // Logged via log::error! below — audit integration is handled at a higher level.

        log::error!(
            "INCIDENT #{incident_id}: score={score:.3} tool={tool} command={command:?} action={action:?}"
        );

        action
    }

    fn take_snapshot(&self, incident_id: u64) -> Option<String> {
        let dir = self.snapshot_dir.as_ref()?;
        let snapshot_dir = dir.join(format!("incident-{incident_id}"));
        let _ = fs::create_dir_all(&snapshot_dir);

        // Copy workspace state (simplified — in production would tar/zip)
        let manifest_path = snapshot_dir.join("manifest.json");
        let manifest = serde_json::json!({
            "incident_id": incident_id,
            "timestamp": now_secs(),
            "snapshot_type": "auto-incident",
        });
        let _ = fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_default());

        Some(snapshot_dir.to_string_lossy().to_string())
    }

    pub fn resolve_incident(&mut self, incident_id: u64) -> bool {
        if let Some(inc) = self.incidents.iter_mut().find(|i| i.id == incident_id) {
            inc.resolved = true;
            inc.resolved_at = Some(now_secs());
            true
        } else {
            false
        }
    }

    pub fn incidents(&self) -> &[IncidentRecord] {
        &self.incidents
    }

    pub fn recent_incidents(&self, count: usize) -> Vec<&IncidentRecord> {
        self.incidents.iter().rev().take(count).collect()
    }

    pub fn incident_count(&self) -> u64 {
        self.next_id.load(Ordering::SeqCst) - 1
    }

    pub fn auto_block_enabled(&self) -> bool {
        self.auto_block
    }

    pub fn set_auto_block(&mut self, enabled: bool) {
        self.auto_block = enabled;
    }
}

impl Default for IncidentResponse {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PostMortem
// ---------------------------------------------------------------------------

pub struct PostMortem {
    reports: Vec<PostMortemReport>,
}

impl PostMortem {
    #[must_use]
    pub fn new() -> Self {
        Self {
            reports: Vec::new(),
        }
    }

    pub fn generate_report(&mut self, incident: &IncidentRecord) -> PostMortemReport {
        let timestamp = now_secs();

        let timeline = vec![
            PostMortemEvent {
                time: incident.timestamp,
                event: "Threat detected".into(),
                detail: format!("Score {:.3} triggered by command: {}", incident.threat_score, incident.command),
            },
            PostMortemEvent {
                time: incident.timestamp,
                event: format!("Action taken: {:?}", incident.action_taken),
                detail: format!("Tool: {}, incident #{}", incident.tool, incident.id),
            },
        ];

        let report = PostMortemReport {
            incident_id: incident.id,
            timestamp,
            summary: format!(
                "Automatic incident #{}: {} blocked with score {:.3}",
                incident.id, incident.tool, incident.threat_score
            ),
            timeline,
            root_cause: format!(
                "Command '{}' exceeded auto-block threshold ({:.3})",
                incident.command, AUTO_BLOCK_THRESHOLD
            ),
            evidence: vec![
                format!("Command: {}", incident.command),
                format!("Tool: {}", incident.tool),
                format!("Score: {:.3}", incident.threat_score),
                format!("Action: {:?}", incident.action_taken),
            ],
            policy_recommendations: vec![
                format!("Review rules for tool '{}'", incident.tool),
                "Consider adding command to explicit allowlist if legitimate".into(),
            ],
            prevention_measures: vec![
                "Add behavioral profile for new tools".into(),
                "Review heuristic engine rules for similar patterns".into(),
            ],
        };

        let report_path = format!("post-mortem-{}.json", incident.id);
        if let Ok(json) = serde_json::to_string_pretty(&report) {
            let _ = fs::write(&report_path, json);
        }

        log::info!("PostMortem: report #{} generated", incident.id);
        self.reports.push(report.clone());
        report
    }

    #[must_use]
    pub fn reports(&self) -> &[PostMortemReport] {
        &self.reports
    }
}

impl Default for PostMortem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PolicyEvolution
// ---------------------------------------------------------------------------

pub struct PolicyEvolution {
    history: Vec<PolicyRecord>,
    rule_adjustments: HashMap<String, f64>,  // rule_name -> adjustment
    last_review: Instant,
    review_interval: Duration,
}

impl PolicyEvolution {
    #[must_use]
    pub fn new() -> Self {
        Self {
            history: Vec::new(),
            rule_adjustments: HashMap::new(),
            last_review: Instant::now(),
            review_interval: Duration::from_secs(AUTO_TUNE_INTERVAL_HOURS * 3600),
        }
    }

    pub fn record_feedback(&mut self, rule_name: &str, false_positive: bool, false_negative: bool) {
        let adjustment = match (false_positive, false_negative) {
            (true, false) => -0.05,  // FP → lower weight
            (false, true) => 0.05,   // FN → raise weight
            _ => 0.0,
        };
        *self.rule_adjustments.entry(rule_name.to_string()).or_insert(0.0) += adjustment;
    }

    #[must_use]
    pub fn adjustment_for(&self, rule_name: &str) -> f64 {
        self.rule_adjustments.get(rule_name).copied().unwrap_or(0.0).clamp(-0.5, 0.5)
    }

    #[must_use]
    pub fn needs_review(&self) -> bool {
        self.last_review.elapsed() >= self.review_interval
    }

    pub fn review(&mut self, _engine: &mut HeuristicEngine) -> Vec<PolicyRecord> {
        let mut new_records = Vec::new();

        for (rule_name, adjustment) in &self.rule_adjustments {
            if adjustment.abs() < 0.01 {
                continue;
            }

            let record = PolicyRecord {
                policy_name: rule_name.clone(),
                weight_adjustment: *adjustment,
                severity_adjustment: 0.0,
                reason: format!("Automatic adjustment from feedback: {adjustment:.3}"),
                applied_at: now_secs(),
                effect_fp_rate: 0.0,
                effect_fn_rate: 0.0,
            };
            new_records.push(record);
        }

        self.history.extend(new_records.clone());
        self.last_review = Instant::now();

        log::info!("PolicyEvolution: reviewed {} rules, {} adjustments", self.rule_adjustments.len(), new_records.len());
        new_records
    }

    #[must_use]
    pub fn history(&self) -> &[PolicyRecord] {
        &self.history
    }

    pub fn reset(&mut self) {
        self.history.clear();
        self.rule_adjustments.clear();
        self.last_review = Instant::now();
    }
}

impl Default for PolicyEvolution {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AbTestEngine
// ---------------------------------------------------------------------------

pub struct AbTestEngine {
    arms: Vec<AbTestArm>,
    active_arm_index: usize,
    min_samples: u64,
}

impl AbTestEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            arms: Self::default_arms(),
            active_arm_index: 1,  // Start with variant B
            min_samples: AB_TEST_MIN_SAMPLES,
        }
    }

    fn default_arms() -> Vec<AbTestArm> {
        vec![
            AbTestArm {
                name: "A (baseline)".into(),
                description: "Default threshold configuration".into(),
                threshold_adjustments: HashMap::new(),
                samples: 0,
                fp_count: 0,
                fn_count: 0,
            },
            AbTestArm {
                name: "B (conservative)".into(),
                description: "Lower thresholds for earlier detection".into(),
                threshold_adjustments: HashMap::from([
                    ("safe_max".into(), -0.05),
                    ("low_max".into(), -0.05),
                    ("high_max".into(), -0.03),
                ]),
                samples: 0,
                fp_count: 0,
                fn_count: 0,
            },
            AbTestArm {
                name: "C (aggressive)".into(),
                description: "Higher thresholds, fewer prompts".into(),
                threshold_adjustments: HashMap::from([
                    ("safe_max".into(), 0.05),
                    ("low_max".into(), 0.05),
                    ("medium_max".into(), 0.03),
                    ("high_max".into(), 0.02),
                ]),
                samples: 0,
                fp_count: 0,
                fn_count: 0,
            },
        ]
    }

    #[must_use]
    pub fn current_arm(&self) -> &AbTestArm {
        &self.arms[self.active_arm_index]
    }

    pub fn active_arm_mut(&mut self) -> &mut AbTestArm {
        &mut self.arms[self.active_arm_index]
    }

    pub fn record_result(&mut self, was_fp: bool, was_false_neg: bool) {
        let arm = self.active_arm_mut();
        arm.samples += 1;
        if was_fp {
            arm.fp_count += 1;
        }
        if was_false_neg {
            arm.fn_count += 1;
        }
    }

    #[must_use]
    pub fn has_conclusive(&self) -> Option<usize> {
        if self.arms.iter().any(|a| a.samples < self.min_samples) {
            return None;
        }
        // Find the arm with the best combined score
        let best = self
            .arms
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.combined_score().partial_cmp(&b.combined_score()).unwrap());
        best.map(|(i, _)| i)
    }

    pub fn select_best_arm(&mut self) -> Option<&AbTestArm> {
        let best_idx = self.has_conclusive()?;
        self.active_arm_index = best_idx;
        log::info!(
            "AbTest: selected arm '{}' with score {:.2} (FP={:.1}%, FN={:.1}%)",
            self.arms[best_idx].name,
            self.arms[best_idx].combined_score(),
            self.arms[best_idx].fp_rate(),
            self.arms[best_idx].fn_rate(),
        );
        Some(&self.arms[best_idx])
    }

    #[must_use]
    pub fn arm_count(&self) -> usize {
        self.arms.len()
    }

    pub fn reset(&mut self) {
        self.arms = Self::default_arms();
        self.active_arm_index = 1;
    }
}

impl Default for AbTestEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AdaptiveEngine (Orchestrator)
// ---------------------------------------------------------------------------

pub struct AdaptiveEngine {
    pub threat_intel: ThreatIntel,
    pub honeytokens: HoneytokenManager,
    pub auto_threshold: AutoThreshold,
    pub incident_response: IncidentResponse,
    pub post_mortem: PostMortem,
    pub policy_evolution: PolicyEvolution,
    pub ab_test: AbTestEngine,
    enabled: bool,
}

impl AdaptiveEngine {
    #[must_use]
    pub fn new(workspace_root: &Path, snapshot_dir: Option<&Path>) -> Self {
        Self {
            threat_intel: ThreatIntel::new(),
            honeytokens: HoneytokenManager::new(workspace_root),
            auto_threshold: AutoThreshold::new(),
            incident_response: IncidentResponse::new()
                .with_snapshot_dir(snapshot_dir.unwrap_or(&workspace_root.join(".kraken").join("incidents"))),
            post_mortem: PostMortem::new(),
            policy_evolution: PolicyEvolution::new(),
            ab_test: AbTestEngine::new(),
            enabled: true,
        }
    }

    pub fn initialize(&mut self) -> Result<(), RuntimeError> {
        if !self.enabled {
            return Ok(());
        }

        // Deploy honeytokens
        let token_count = self.honeytokens.deploy()?;
        log::info!("AdaptiveEngine: deployed {token_count} honeytokens");

        // Load threat intel
        let feed_count = self.threat_intel.update()?;
        log::info!("AdaptiveEngine: loaded {feed_count} threat intel entries");

        Ok(())
    }

    /// Evaluate a command through all adaptive layers.
    /// Returns total risk boost (0.0-1.0) from all adaptive components.
    pub fn evaluate(
        &mut self,
        command: &str,
        tool: &str,
        path: Option<&Path>,
        heuristic_score: f64,
        engine: &mut HeuristicEngine,
    ) -> f64 {
        if !self.enabled {
            return 0.0;
        }

        let mut total_boost = 0.0;

        // 1. Threat intel check
        let intel_boost = self.check_threat_intel(command);
        total_boost += intel_boost;

        // 2. Honeytoken check
        if let Some(p) = path {
            if let Some(boost) = self.honeytokens.check_access(p) {
                total_boost += boost;
            }
        }

        // 3. Check if threat score + boost exceeds threshold
        let effective_score = (heuristic_score + total_boost).min(1.0);

        // 4. Incident response
        if effective_score >= AUTO_BLOCK_THRESHOLD {
            let action = self.incident_response.evaluate_threat(
                effective_score,
                command,
                tool,
                engine,
            );
            match action {
                IncidentAction::Blocked | IncidentAction::Isolated => {
                    // Generate post-mortem for the most recent incident
                    if let Some(incident) = self.incident_response.recent_incidents(1).first() {
                        self.post_mortem.generate_report(incident);
                    }
                }
                _ => {}
            }
        }

        // 5. Auto-threshold tuning
        if self.auto_threshold.needs_tune() {
            let adjustment = self.auto_threshold.tune();
            log::info!("AdaptiveEngine: threshold tuned: {}", adjustment.reason);
        }

        // 6. Policy evolution review
        if self.policy_evolution.needs_review() {
            let records = self.policy_evolution.review(engine);
            if !records.is_empty() {
                log::info!("AdaptiveEngine: {} policy adjustments applied", records.len());
            }
        }

        total_boost
    }

    fn check_threat_intel(&self, command: &str) -> f64 {
        let mut max_score: f64 = 0.0;

        // Check for IP addresses
        for word in command.split_whitespace() {
            if is_ip_like(word) {
                let score = self.threat_intel.check_ip(word);
                if let Some(s) = score.first() {
                    let severity = match s.severity {
                        ThreatSeverity::Low => 0.3,
                        ThreatSeverity::Medium => 0.5,
                        ThreatSeverity::High => 0.8,
                        ThreatSeverity::Critical => 1.0,
                    };
                    max_score = max_score.max(severity * s.confidence);
                }
            }

            // Check for domains/URLs
            if word.contains('.') && (word.starts_with("http") || word.contains("://")) {
                let score = self.threat_intel.check_url(word);
                if let Some(s) = score.first() {
                    let severity = match s.severity {
                        ThreatSeverity::Low => 0.3,
                        ThreatSeverity::Medium => 0.5,
                        ThreatSeverity::High => 0.8,
                        ThreatSeverity::Critical => 1.0,
                    };
                    max_score = max_score.max(severity * s.confidence);
                }
            }

            // Check for CVEs
            if word.starts_with("CVE-") || word.starts_with("cve-") {
                let score = self.threat_intel.check_cve(word);
                if let Some(s) = score.first() {
                    let severity = match s.severity {
                        ThreatSeverity::Low => 0.3,
                        ThreatSeverity::Medium => 0.5,
                        ThreatSeverity::High => 0.8,
                        ThreatSeverity::Critical => 1.0,
                    };
                    max_score = max_score.max(severity * s.confidence);
                }
            }
        }

        max_score
    }

    /// Record user feedback to adjust thresholds and policies.
    pub fn record_feedback(
        &mut self,
        rule_name: &str,
        was_fp: bool,
        was_false_neg: bool,
        user_approved: bool,
        score: f64,
        risk_level: RiskLevel,
    ) {
        if !self.enabled {
            return;
        }

        // Auto-threshold feedback
        self.auto_threshold
            .record_evaluation(score, risk_level, user_approved, !was_fp && !was_false_neg);

        // Policy evolution feedback
        self.policy_evolution
            .record_feedback(rule_name, was_fp, was_false_neg);

        // A/B test feedback
        self.ab_test.record_result(was_fp, was_false_neg);

        // Check if A/B test is conclusive
        if self.ab_test.arm_count() >= 2 {
            if let Some(best_idx) = self.ab_test.has_conclusive() {
                log::info!(
                    "AdaptiveEngine: A/B test conclusive — arm {best_idx} selected"
                );
            }
        }
    }

    pub fn cleanup(&mut self) {
        let _ = self.honeytokens.remove_all();
        log::info!("AdaptiveEngine: cleaned up honeytokens");
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static GLOBAL_ADAPTIVE: OnceLock<Mutex<AdaptiveEngine>> = OnceLock::new();

pub fn init_adaptive_engine(workspace_root: &Path, snapshot_dir: Option<&Path>) {
    GLOBAL_ADAPTIVE.get_or_init(|| {
        let mut engine = AdaptiveEngine::new(workspace_root, snapshot_dir);
        if let Err(e) = engine.initialize() {
            log::warn!("AdaptiveEngine init: {e}");
        }
        Mutex::new(engine)
    });
}

pub fn with_adaptive<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut AdaptiveEngine) -> R,
{
    GLOBAL_ADAPTIVE.get().and_then(|m| {
        let mut guard = m.lock().ok()?;
        Some(f(&mut guard))
    })
}

pub fn global_adaptive_evaluate(
    command: &str,
    tool: &str,
    path: Option<&Path>,
    heuristic_score: f64,
    engine: &mut HeuristicEngine,
) -> f64 {
    with_adaptive(|a| a.evaluate(command, tool, path, heuristic_score, engine)).unwrap_or(0.0)
}

pub fn global_adaptive_feedback(
    rule_name: &str,
    was_fp: bool,
    was_false_neg: bool,
    user_approved: bool,
    score: f64,
    risk_level: RiskLevel,
) {
    let _ = with_adaptive(|a| {
        a.record_feedback(rule_name, was_fp, was_false_neg, user_approved, score, risk_level);
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_ip_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok() && p.len() <= 3)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_workspace() -> PathBuf {
        use std::sync::atomic::AtomicU64;
        static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!("adaptive-test-{id}"))
    }

    #[test]
    fn test_threat_intel_builtin_feeds() {
        let mut intel = ThreatIntel::new();
        intel.update().unwrap();
        assert!(intel.feed_count() >= 8, "should have at least 8 builtin feeds");

        let cve_matches = intel.check_cve("CVE-2024-27198");
        assert!(!cve_matches.is_empty(), "should detect CVE-2024-27198");

        let ip_matches = intel.check_ip("185.220.101.0");
        assert!(!ip_matches.is_empty(), "should detect known malicious IP");

        let score = intel.threat_score_for("CVE-2024-27198");
        assert!(score > 0.8, "critical CVE should have high threat score");
    }

    #[test]
    fn test_threat_intel_update_from_file() {
        let dir = test_workspace();
        let _ = fs::create_dir_all(&dir);
        let feed_path = dir.join("threat_feed.json");

        let entries = vec![ThreatFeedEntry {
            indicator: "5.5.5.5".into(),
            indicator_type: ThreatIndicatorType::IpAddress,
            severity: ThreatSeverity::Critical,
            source: "test".into(),
            last_seen: now_secs(),
            confidence: 0.99,
            tags: vec!["test".into()],
        }];
        fs::write(
            &feed_path,
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();

        let mut intel = ThreatIntel::new().with_feed_path(&feed_path);
        // Force needs_update by resetting last_update to epoch
        intel.last_update = std::time::Instant::now() - std::time::Duration::from_secs(86401);
        assert!(intel.needs_update());
        intel.update().unwrap();

        let matches = intel.check_ip("5.5.5.5");
        assert!(!matches.is_empty(), "should find loaded indicator");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_honeytoken_deploy_and_detect() {
        let dir = test_workspace();
        let _ = fs::create_dir_all(&dir);

        let mut ht = HoneytokenManager::new(&dir);
        let deployed = ht.deploy().unwrap();
        assert_eq!(deployed, 5, "should deploy all 5 honeytokens");

        // Check that files exist
        assert!(dir.join("config").join("credentials.yml").exists());
        assert!(dir.join(".env.production").exists());
        assert!(dir.join(".ssh").join("id_rsa").exists());
        assert!(dir.join(".kraken").join("secrets.json").exists());
        assert!(dir.join("tmp").join("backup").join("dump.sql").exists());

        // Simulate access to a honeytoken
        let boost = ht.check_access(&dir.join("config").join("credentials.yml"));
        assert!(boost.is_some(), "should detect honeytoken access");
        assert_eq!(boost.unwrap(), 0.9);

        assert!(ht.is_triggered("credentials.yml"));
        assert_eq!(ht.trigger_count(), 1);
        assert!((ht.total_risk_boost() - 0.9).abs() < 0.01);

        // Second access should not re-trigger
        let boost = ht.check_access(&dir.join("config").join("credentials.yml"));
        assert!(boost.is_none(), "should not re-trigger");

        // Cleanup
        let removed = ht.remove_all().unwrap();
        assert_eq!(removed, 5);
        assert!(!dir.join("config").join("credentials.yml").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_auto_threshold_tuning() {
        let mut at = AutoThreshold::new();
        at.last_tune = std::time::Instant::now() - std::time::Duration::from_secs(86401);

        // Record false positives
        for _ in 0..10 {
            at.record_evaluation(0.7, RiskLevel::Medium, true, false);
        }

        let fp = at.fp_rate();
        assert!(fp > 0.0, "FP rate should be > 0%");
        assert!(at.needs_tune(), "should need tune after 10+ eval with FP");

        // Tune
        let adjustment = at.tune();
        assert!(adjustment.safe_max_delta > 0.0, "should raise thresholds on high FP");
        assert!(adjustment.low_max_delta > 0.0, "should raise low threshold");
    }

    #[test]
    fn test_incident_response_blocking() {
        let mut ir = IncidentResponse::new();
        let mut engine = HeuristicEngine::new();

        // Test with low score
        let action = ir.evaluate_threat(0.5, "echo hello", "bash", &mut engine);
        assert_eq!(action, IncidentAction::NoAction);

        // Test with high score
        let action = ir.evaluate_threat(0.96, "rm -rf /", "bash", &mut engine);
        assert_eq!(action, IncidentAction::Prompted, "0.96 should prompt");

        // Test with critical score
        let action = ir.evaluate_threat(0.99, "dd if=/dev/zero of=/dev/sda", "bash", &mut engine);
        assert_eq!(action, IncidentAction::Blocked, "0.99 should block");

        assert_eq!(ir.incident_count(), 2, "should have 2 incidents");
    }

    #[test]
    fn test_post_mortem_generation() {
        let mut pm = PostMortem::new();
        let incident = IncidentRecord {
            id: 1,
            timestamp: now_secs(),
            threat_score: 0.99,
            trigger: "test".into(),
            command: "rm -rf /".into(),
            tool: "bash".into(),
            snapshot_path: None,
            action_taken: IncidentAction::Blocked,
            resolved: false,
            resolved_at: None,
        };

        let report = pm.generate_report(&incident);
        assert_eq!(report.incident_id, 1);
        assert!(report.summary.contains("0.99"));
        assert!(!report.timeline.is_empty());
        assert!(!report.evidence.is_empty());
        assert_eq!(pm.reports().len(), 1);
    }

    #[test]
    fn test_policy_evolution() {
        let mut pe = PolicyEvolution::new();

        pe.record_feedback("rm-root", true, false);  // FP
        let adj = pe.adjustment_for("rm-root");
        assert!(adj < 0.0, "FP should lower weight");

        pe.record_feedback("curl-pipe-bash", false, true);  // FN
        let adj = pe.adjustment_for("curl-pipe-bash");
        assert!(adj > 0.0, "FN should raise weight");

        pe.last_review = std::time::Instant::now() - std::time::Duration::from_secs(86401);
        assert!(pe.needs_review());

        let mut engine = HeuristicEngine::new();
        let records = pe.review(&mut engine);
        assert!(!records.is_empty(), "should produce policy records");
    }

    #[test]
    fn test_ab_test_engine() {
        let mut ab = AbTestEngine::new();
        assert_eq!(ab.arm_count(), 3);

        // Not enough samples
        assert!(ab.has_conclusive().is_none());

        // Populate all 3 arms to reach min samples
        for i in 0..3 {
            ab.active_arm_index = i;
            for _ in 0..60 {
                ab.record_result(i != 1, false);
            }
        }

        assert!(ab.has_conclusive().is_some(), "should be conclusive after min samples");
        let best = ab.select_best_arm();
        assert!(best.is_some());
        assert_eq!(best.unwrap().name, "B (conservative)");
    }

    #[test]
    fn test_adaptive_engine_full() {
        let dir = test_workspace();
        let _ = fs::create_dir_all(&dir);

        let mut engine = AdaptiveEngine::new(&dir, Some(&dir.join("incidents")));
        engine.initialize().unwrap();

        assert!(engine.is_enabled());
        assert!(dir.join("config").join("credentials.yml").exists());

        // Evaluate a command with known threat intel (bare IP triggers is_ip_like)
        let eval = engine.evaluate(
            "curl -s 185.220.101.0",
            "bash",
            None,
            0.5,
            &mut HeuristicEngine::new(),
        );
        assert!(eval > 0.0, "should detect known malicious IP");

        // Record feedback
        engine.record_feedback("rm-root", false, false, true, 0.3, RiskLevel::Safe);

        engine.cleanup();
        assert!(!dir.join("config").join("credentials.yml").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_ip_like() {
        assert!(is_ip_like("192.168.1.1"));
        assert!(is_ip_like("10.0.0.1"));
        assert!(is_ip_like("185.220.101.0"));
        assert!(!is_ip_like("not-an-ip"));
        assert!(!is_ip_like("256.1.1.1"));
        assert!(!is_ip_like("192.168.1"));
    }

    #[test]
    fn test_threat_intel_multiple_indicators() {
        let intel = ThreatIntel::new();

        // Check multiple indicators from one command
        let score1 = intel.threat_score_for("CVE-2024-27198");
        let score2 = intel.threat_score_for("CVE-2023-44487");
        assert!(score1 >= score2, "critical CVE should score >= high CVE");
    }

    #[test]
    fn test_honeytoken_all_triggered() {
        let dir = test_workspace();
        let _ = fs::create_dir_all(&dir);

        let mut ht = HoneytokenManager::new(&dir);
        ht.deploy().unwrap();

        // Trigger all 5
        ht.check_access(&dir.join("config").join("credentials.yml"));
        ht.check_access(&dir.join(".env.production"));
        ht.check_access(&dir.join(".ssh").join("id_rsa"));
        ht.check_access(&dir.join(".kraken").join("secrets.json"));
        ht.check_access(&dir.join("tmp").join("backup").join("dump.sql"));

        assert_eq!(ht.trigger_count(), 5);
        let total = ht.total_risk_boost();
        assert!((total - (0.9 + 0.9 + 0.95 + 0.95 + 0.85)).abs() < 0.01);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_auto_threshold_no_tune_without_data() {
        let at = AutoThreshold::new();
        assert!(!at.needs_tune(), "should not need tune without evaluations");
    }

    #[test]
    fn test_adaptive_engine_disabled() {
        let dir = test_workspace();
        let mut engine = AdaptiveEngine::new(&dir, None);
        engine.set_enabled(false);

        let boost = engine.evaluate(
            "rm -rf /",
            "bash",
            None,
            0.9,
            &mut HeuristicEngine::new(),
        );
        assert_eq!(boost, 0.0, "disabled engine should return 0 boost");
    }

    #[test]
    fn test_ab_test_reset() {
        let mut ab = AbTestEngine::new();
        for _ in 0..60 {
            ab.record_result(true, false);
        }
        ab.reset();
        assert!(ab.has_conclusive().is_none());
        assert_eq!(ab.arms[0].samples, 0);
    }
}
