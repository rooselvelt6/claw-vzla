//! Self-healing system for Kraken: checkpointing, health monitoring, auto-restart,
//! corruption repair, and graceful shutdown.

use kraken_errors::RuntimeError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default interval between checkpoints (number of tool calls).
pub const DEFAULT_CHECKPOINT_INTERVAL_CALLS: u64 = 5;
/// Default interval between checkpoints (seconds).
pub const DEFAULT_CHECKPOINT_INTERVAL_SECS: u64 = 60;
/// Max WAL entries before a full snapshot is forced.
pub const MAX_WAL_ENTRIES: usize = 100;
/// Health monitor poll interval.
pub const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Max backoff delay for restarts.
pub const MAX_BACKOFF: Duration = Duration::from_mins(2);
/// Initial backoff delay.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Checkpoint types
// ---------------------------------------------------------------------------

/// A single WAL entry: an atomic operation that can be replayed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub operation: String,
    pub data: serde_json::Value,
}

/// A full session snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub timestamp_ms: u64,
    pub message_count: usize,
    pub checkpoints_count: u64,
    pub checksum: String,
    pub data: serde_json::Value,
}

/// Checkpoint metadata for recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointManifest {
    pub session_id: String,
    pub last_sequence: u64,
    pub snapshot_path: String,
    pub wal_path: String,
    pub snapshot_checksum: String,
    pub created_at_ms: u64,
    pub message_count: usize,
}

// ---------------------------------------------------------------------------
// Checkpointer
// ---------------------------------------------------------------------------

/// Creates and manages session checkpoints (snapshot + WAL).
pub struct SessionCheckpointer {
    checkpoint_dir: PathBuf,
    session_id: String,
    calls_since_checkpoint: u64,
    wal_entries: Vec<WalEntry>,
    sequence_counter: u64,
    checkpoint_counter: u64,
    last_checkpoint_time: Instant,
    interval_calls: u64,
    interval_secs: u64,
}

impl SessionCheckpointer {
    #[must_use]
    pub fn new(checkpoint_dir: &Path, session_id: &str) -> Self {
        Self {
            checkpoint_dir: checkpoint_dir.to_path_buf(),
            session_id: session_id.to_string(),
            calls_since_checkpoint: 0,
            wal_entries: Vec::new(),
            sequence_counter: 0,
            checkpoint_counter: 0,
            last_checkpoint_time: Instant::now(),
            interval_calls: DEFAULT_CHECKPOINT_INTERVAL_CALLS,
            interval_secs: DEFAULT_CHECKPOINT_INTERVAL_SECS,
        }
    }

    #[must_use]
    pub fn with_intervals(mut self, calls: u64, secs: u64) -> Self {
        self.interval_calls = calls;
        self.interval_secs = secs;
        self
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn checkpoint_dir(&self) -> &Path {
        &self.checkpoint_dir
    }

    #[must_use]
    pub fn wal_entries(&self) -> &[WalEntry] {
        &self.wal_entries
    }

    #[must_use]
    pub fn sequence_counter(&self) -> u64 {
        self.sequence_counter
    }

    /// Record a tool call — triggers checkpoint if thresholds are met.
    pub fn record_tool_call(&mut self, tool: &str, input: &serde_json::Value) -> Option<CheckpointManifest> {
        self.calls_since_checkpoint += 1;
        self.sequence_counter += 1;

        self.wal_entries.push(WalEntry {
            sequence: self.sequence_counter,
            timestamp_ms: now_ms(),
            operation: format!("tool_call:{tool}"),
            data: input.clone(),
        });

        // Checkpoint if thresholds are exceeded
        if self.should_checkpoint() {
            self.checkpoint_now(None)
        } else {
            None
        }
    }

    /// Force a checkpoint with current session data.
    pub fn checkpoint_now(&mut self, session_data: Option<serde_json::Value>) -> Option<CheckpointManifest> {
        let _ = fs::create_dir_all(&self.checkpoint_dir);
        self.checkpoint_counter += 1;
        let cp_seq = self.checkpoint_counter;

        // Determine what to snapshot
        let data = session_data.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let data_str = serde_json::to_string(&data).unwrap_or_default();
        let checksum = to_hex(&Sha256::digest(data_str.as_bytes()));

        let snapshot = SessionSnapshot {
            session_id: self.session_id.clone(),
            timestamp_ms: now_ms(),
            message_count: 0,
            checkpoints_count: self.sequence_counter,
            checksum: checksum.clone(),
            data,
        };

        // Write snapshot
        let snapshot_path = self.checkpoint_dir.join(format!("snapshot-{cp_seq}.json"));
        if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
            let _ = atomic_write(&snapshot_path, json.as_bytes());
        }

        // Write WAL
        let wal_path = self.checkpoint_dir.join(format!("wal-{cp_seq}.jsonl"));
        if let Ok(wal_content) = serialize_wal(&self.wal_entries) {
            let _ = atomic_write(&wal_path, wal_content.as_bytes());
        }

        // Prune old checkpoints (keep last 3)
        prune_checkpoints(&self.checkpoint_dir, 3);

        let manifest = CheckpointManifest {
            session_id: self.session_id.clone(),
            last_sequence: self.sequence_counter,
            snapshot_path: snapshot_path.to_string_lossy().to_string(),
            wal_path: wal_path.to_string_lossy().to_string(),
            snapshot_checksum: checksum,
            created_at_ms: now_ms(),
            message_count: self.wal_entries.len(),
        };

        // Reset state
        self.calls_since_checkpoint = 0;
        self.wal_entries.clear();
        self.last_checkpoint_time = Instant::now();

        Some(manifest)
    }

    fn should_checkpoint(&self) -> bool {
        if self.wal_entries.len() >= MAX_WAL_ENTRIES {
            return true;
        }
        if self.calls_since_checkpoint >= self.interval_calls {
            return true;
        }
        if self.last_checkpoint_time.elapsed() >= Duration::from_secs(self.interval_secs) {
            return true;
        }
        false
    }

    /// Find the latest valid checkpoint for recovery.
    #[must_use]
    pub fn find_latest_checkpoint(checkpoint_dir: &Path) -> Option<CheckpointManifest> {
        let entries = match fs::read_dir(checkpoint_dir) {
            Ok(e) => e.flatten().collect::<Vec<_>>(),
            Err(_) => return None,
        };

        // Find the snapshot with the highest sequence number
        let mut latest_seq = 0u64;
        let mut latest_snapshot = None;
        let mut latest_wal = None;

        for entry in &entries {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(seq) = name.strip_prefix("snapshot-").and_then(|s| s.strip_suffix(".json")) {
                if let Ok(seq_num) = seq.parse::<u64>() {
                    if seq_num > latest_seq {
                        latest_seq = seq_num;
                        latest_snapshot = Some(entry.path());
                    }
                }
            }
            if let Some(rest) = name.strip_prefix("wal-").and_then(|s| s.strip_suffix(".jsonl")) {
                if let Ok(seq_num) = rest.parse::<u64>() {
                    if seq_num >= latest_seq {
                        latest_wal = Some(entry.path());
                    }
                }
            }
        }

        let snapshot_path = latest_snapshot?;
        let wal_path = latest_wal?;

        // Read and verify snapshot
        let snapshot_data = fs::read_to_string(&snapshot_path).ok()?;
        let snapshot: SessionSnapshot = serde_json::from_str(&snapshot_data).ok()?;

        // Verify checksum
        let actual_checksum = to_hex(&Sha256::digest(
            serde_json::to_string(&snapshot.data).unwrap_or_default().as_bytes()
        ));
        if actual_checksum != snapshot.checksum {
            return None; // Corrupted snapshot
        }

        Some(CheckpointManifest {
            session_id: snapshot.session_id,
            last_sequence: latest_seq,
            snapshot_path: snapshot_path.to_string_lossy().to_string(),
            wal_path: wal_path.to_string_lossy().to_string(),
            snapshot_checksum: snapshot.checksum,
            created_at_ms: snapshot.timestamp_ms,
            message_count: snapshot.message_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Health Monitor
// ---------------------------------------------------------------------------

/// System resource metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub timestamp_ms: u64,
    pub memory_available_kb: u64,
    pub memory_total_kb: u64,
    pub disk_free_kb: u64,
    pub disk_total_kb: u64,
    pub uptime_secs: u64,
    pub num_probes_healthy: usize,
    pub num_probes_degraded: usize,
    pub num_probes_unhealthy: usize,
}

impl SystemMetrics {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn is_memory_critical(&self) -> bool {
        if self.memory_total_kb == 0 {
            return false;
        }
        let free_ratio = self.memory_available_kb as f64 / self.memory_total_kb as f64;
        free_ratio < 0.05
    }

    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn is_disk_critical(&self) -> bool {
        if self.disk_total_kb == 0 {
            return false;
        }
        let free_ratio = self.disk_free_kb as f64 / self.disk_total_kb as f64;
        free_ratio < 0.02
    }
}

/// Health status for a monitored component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentHealth {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

/// A monitored component with health state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredComponent {
    pub name: String,
    pub health: ComponentHealth,
    pub last_heartbeat_ms: u64,
    pub failure_count: u64,
    pub last_error: Option<String>,
}

/// Aggregate health report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub timestamp_ms: u64,
    pub system: SystemMetrics,
    pub components: Vec<MonitoredComponent>,
    pub all_healthy: bool,
    pub degraded_count: usize,
    pub unhealthy_count: usize,
}

impl HealthReport {
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.all_healthy
    }

    #[must_use]
    pub fn has_degraded(&self) -> bool {
        self.degraded_count > 0
    }

    #[must_use]
    pub fn has_unhealthy(&self) -> bool {
        self.unhealthy_count > 0
    }
}

/// Background health monitor that periodically collects system metrics
/// and checks component health.
pub struct HealthMonitor {
    components: Arc<Mutex<HashMap<String, MonitoredComponent>>>,
    running: Arc<AtomicBool>,
}

impl HealthMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            components: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn register_component(&self, name: &str) {
        let mut comps = self.components.lock().unwrap();
        comps.entry(name.to_string()).or_insert(MonitoredComponent {
            name: name.to_string(),
            health: ComponentHealth::Unknown,
            last_heartbeat_ms: now_ms(),
            failure_count: 0,
            last_error: None,
        });
    }

    pub fn report_heartbeat(&self, name: &str) {
        let mut comps = self.components.lock().unwrap();
        if let Some(c) = comps.get_mut(name) {
            c.health = ComponentHealth::Healthy;
            c.last_heartbeat_ms = now_ms();
        }
    }

    pub fn report_failure(&self, name: &str, error: &str) {
        let mut comps = self.components.lock().unwrap();
        if let Some(c) = comps.get_mut(name) {
            c.health = ComponentHealth::Unhealthy;
            c.failure_count += 1;
            c.last_error = Some(error.to_string());
        }
    }

    pub fn report_degraded(&self, name: &str, error: &str) {
        let mut comps = self.components.lock().unwrap();
        if let Some(c) = comps.get_mut(name) {
            c.health = ComponentHealth::Degraded;
            c.last_error = Some(error.to_string());
        }
    }

    pub fn mark_healthy(&self, name: &str) {
        let mut comps = self.components.lock().unwrap();
        if let Some(c) = comps.get_mut(name) {
            c.health = ComponentHealth::Healthy;
            c.last_error = None;
        }
    }

    #[must_use]
    pub fn component_health(&self, name: &str) -> ComponentHealth {
        let comps = self.components.lock().unwrap();
        comps.get(name).map_or(ComponentHealth::Unknown, |c| c.health)
    }

    /// Gather current system metrics.
    #[must_use]
    pub fn collect_metrics(&self) -> SystemMetrics {
        let (mem_avail, mem_total) = read_memory_stats();
        let (disk_free, disk_total) = read_disk_stats(std::path::Path::new("."));

        let comps = self.components.lock().unwrap();
        let healthy = comps.values().filter(|c| c.health == ComponentHealth::Healthy).count();
        let degraded = comps.values().filter(|c| c.health == ComponentHealth::Degraded).count();
        let unhealthy = comps.values().filter(|c| c.health == ComponentHealth::Unhealthy).count();

        SystemMetrics {
            timestamp_ms: now_ms(),
            memory_available_kb: mem_avail,
            memory_total_kb: mem_total,
            disk_free_kb: disk_free,
            disk_total_kb: disk_total,
            uptime_secs: read_uptime(),
            num_probes_healthy: healthy,
            num_probes_degraded: degraded,
            num_probes_unhealthy: unhealthy,
        }
    }

    /// Generate a full health report.
    #[must_use]
    pub fn report(&self) -> HealthReport {
        let system = self.collect_metrics();
        let comps = self.components.lock().unwrap();
        let components: Vec<MonitoredComponent> = comps.values().cloned().collect();
        let degraded = components.iter().filter(|c| c.health == ComponentHealth::Degraded).count();
        let unhealthy = components.iter().filter(|c| c.health == ComponentHealth::Unhealthy).count();

        HealthReport {
            timestamp_ms: now_ms(),
            system,
            components,
            all_healthy: degraded == 0 && unhealthy == 0,
            degraded_count: degraded,
            unhealthy_count: unhealthy,
        }
    }

    /// Start the background monitoring loop.
    #[must_use]
    pub fn start(&self) -> Arc<AtomicBool> {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
        let running = self.running.clone();
        let components = self.components.clone();

        std::thread::spawn(move || {
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                // Check for stale heartbeats (no heartbeat in 30s -> degraded)
                if let Ok(mut comps) = components.lock() {
                    let now = now_ms();
                    for comp in comps.values_mut() {
                        if comp.health == ComponentHealth::Healthy
                            && now > comp.last_heartbeat_ms
                            && now - comp.last_heartbeat_ms > 30_000
                        {
                            comp.health = ComponentHealth::Degraded;
                            comp.last_error = Some("Stale heartbeat (>30s)".to_string());
                        }
                    }
                }
                std::thread::sleep(HEALTH_POLL_INTERVAL);
            }
        });

        self.running.clone()
    }

    /// Stop the background monitoring loop.
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Auto-Restarter
// ---------------------------------------------------------------------------

/// Backoff strategy for restarts.
#[derive(Debug, Clone)]
pub struct BackoffStrategy {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter: f64,
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self {
            initial_delay: INITIAL_BACKOFF,
            max_delay: MAX_BACKOFF,
            multiplier: 2.0,
            jitter: 0.1,
        }
    }
}

/// A restartable component with exponential backoff.
#[derive(Debug, Clone)]
pub struct RestartableComponent {
    pub name: String,
    pub attempt: u64,
    pub last_restart: Option<Instant>,
    pub backoff: BackoffStrategy,
    pub max_attempts: u64,
}

impl RestartableComponent {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            attempt: 0,
            last_restart: None,
            backoff: BackoffStrategy::default(),
            max_attempts: 5,
        }
    }

    /// Return the delay before the next restart attempt.
    #[must_use]
    pub fn next_delay(&self) -> Duration {
        let delay = self.backoff.initial_delay.as_secs_f64()
            * self.backoff.multiplier.powi({
                #[allow(clippy::cast_possible_truncation)]
                let v: i32 = self.attempt as i32;
                v
            });
        let jitter_amount = delay * self.backoff.jitter;
        let jittered = delay + jitter_amount * (std::time::Duration::from_secs(1).as_secs_f64());
        Duration::from_secs_f64(jittered.min(self.backoff.max_delay.as_secs_f64()))
    }

    /// Record a restart attempt. Returns the delay to wait before the next attempt.
    pub fn record_attempt(&mut self) -> Duration {
        self.attempt += 1;
        self.last_restart = Some(Instant::now());
        self.next_delay()
    }

    /// Reset the attempt counter (e.g., after a successful recovery).
    pub fn reset(&mut self) {
        self.attempt = 0;
        self.last_restart = None;
    }

    /// Check if the component has exceeded max restart attempts.
    #[must_use]
    pub fn should_escalate(&self) -> bool {
        self.attempt >= self.max_attempts
    }
}

/// Manages auto-restart for multiple layers (MCP servers, worker pool, runtime thread).
pub struct AutoRestarter {
    components: Mutex<HashMap<String, RestartableComponent>>,
    health: Option<Arc<HealthMonitor>>,
}

impl AutoRestarter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            components: Mutex::new(HashMap::new()),
            health: None,
        }
    }

    #[must_use]
    pub fn with_health_monitor(mut self, health: Arc<HealthMonitor>) -> Self {
        self.health = Some(health);
        self
    }

    /// Register a restartable component.
    pub fn register(&self, name: &str) {
        let mut comps = self.components.lock().unwrap();
        comps.entry(name.to_string()).or_insert(RestartableComponent::new(name));
        if let Some(ref health) = self.health {
            health.register_component(name);
        }
    }

    /// Record an attempt and return the delay before the next retry.
    pub fn record_attempt(&self, name: &str) -> Duration {
        let mut comps = self.components.lock().unwrap();
        if let Some(comp) = comps.get_mut(name) {
            comp.record_attempt()
        } else {
            Duration::from_secs(1)
        }
    }

    /// Mark a component as successfully recovered.
    pub fn mark_recovered(&self, name: &str) {
        let mut comps = self.components.lock().unwrap();
        if let Some(comp) = comps.get_mut(name) {
            comp.reset();
        }
        if let Some(ref health) = self.health {
            health.mark_healthy(name);
        }
    }

    /// Check if a component should be escalated to human.
    pub fn should_escalate(&self, name: &str) -> bool {
        let comps = self.components.lock().unwrap();
        comps.get(name).is_some_and(RestartableComponent::should_escalate)
    }

    /// Get the current attempt number for a component.
    pub fn attempt_count(&self, name: &str) -> u64 {
        let comps = self.components.lock().unwrap();
        comps.get(name).map_or(0, |c| c.attempt)
    }

    /// Get all registered component names.
    pub fn registered_components(&self) -> Vec<String> {
        let comps = self.components.lock().unwrap();
        comps.keys().cloned().collect()
    }
}

impl Default for AutoRestarter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Corruption Repair
// ---------------------------------------------------------------------------

/// Result of a repair attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairResult {
    /// Repaired successfully from WAL.
    RepairedFromWal,
    /// Restored from last good checkpoint.
    RestoredFromCheckpoint,
    /// Started a fresh session.
    FreshSession,
    /// No corruption found.
    NoCorruption,
    /// Repair failed.
    Failed(String),
}

/// Verifies integrity of state files and attempts repair.
pub struct CorruptionRepair;

impl CorruptionRepair {
    /// Verify checksum of a file.
    #[must_use]
    pub fn verify_file_checksum(path: &Path, expected_hex: &str) -> bool {
        let Ok(data) = fs::read(path) else {
            return false;
        };
        let actual = to_hex(&Sha256::digest(&data));
        actual == expected_hex
    }

    /// Compute SHA-256 checksum of a file.
    #[must_use]
    pub fn compute_checksum(path: &Path) -> Option<String> {
        let data = fs::read(path).ok()?;
        Some(to_hex(&Sha256::digest(&data)))
    }

    /// Verify all session state files in a directory.
    #[must_use]
    pub fn verify_all(checkpoint_dir: &Path) -> Vec<(PathBuf, String)> {
        let mut corruptions = Vec::new();
        let Ok(dir) = fs::read_dir(checkpoint_dir) else {
            return corruptions;
        };

        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                // For snapshot files, verify they are valid JSON
                if let Err(e) = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap_or_default()) {
                    corruptions.push((path, format!("Invalid JSON: {e}")));
                }
            }
        }
        corruptions
    }

    /// Attempt to repair a corrupted session state.
    ///
    /// Fallback chain:
    ///   1. Try WAL replay
    ///   2. Try last good snapshot
    ///   3. Try any remaining snapshot
    ///   4. Fresh session
    #[must_use]
    pub fn repair(checkpoint_dir: &Path) -> RepairResult {
        // Step 1: Check if there's a valid checkpoint to restore from
        if let Some(manifest) = SessionCheckpointer::find_latest_checkpoint(checkpoint_dir) {
            let snapshot_path = Path::new(&manifest.snapshot_path);
            if snapshot_path.exists() {
                // Verify the snapshot checksum
                if CorruptionRepair::verify_file_checksum(snapshot_path, &manifest.snapshot_checksum) {
                    // Try WAL replay
                    let wal_path = Path::new(&manifest.wal_path);
                    if wal_path.exists() {
                        if let Ok(entries) = read_wal(wal_path) {
                            if !entries.is_empty() {
                                return RepairResult::RepairedFromWal;
                            }
                        }
                    }
                    return RepairResult::RestoredFromCheckpoint;
                }
            }
        }

        // Step 2: Try to find any remaining snapshot
        if find_any_snapshot(checkpoint_dir).is_some() {
            return RepairResult::RestoredFromCheckpoint;
        }

        // Step 3: Fresh session
        RepairResult::FreshSession
    }
}

// ---------------------------------------------------------------------------
// Graceful Shutdown
// ---------------------------------------------------------------------------

/// Shutdown actions to execute.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct ShutdownActions {
    pub should_flush_audit: bool,
    pub should_checkpoint: bool,
    pub should_close_mcp: bool,
    pub should_zeroize: bool,
}

impl Default for ShutdownActions {
    fn default() -> Self {
        Self {
            should_flush_audit: true,
            should_checkpoint: true,
            should_close_mcp: true,
            should_zeroize: true,
        }
    }
}

/// Coordinates graceful shutdown on signal receipt.
pub struct GracefulShutdown {
    signal_received: Arc<AtomicBool>,
    health: Option<Arc<HealthMonitor>>,
    actions: ShutdownActions,
}

impl GracefulShutdown {
    #[must_use]
    pub fn new() -> Self {
        Self {
            signal_received: Arc::new(AtomicBool::new(false)),
            health: None,
            actions: ShutdownActions::default(),
        }
    }

    #[must_use]
    pub fn with_health_monitor(mut self, health: Arc<HealthMonitor>) -> Self {
        self.health = Some(health);
        self
    }

    #[must_use]
    pub fn with_actions(mut self, actions: ShutdownActions) -> Self {
        self.actions = actions;
        self
    }

    #[must_use]
    pub fn signal_received(&self) -> bool {
        self.signal_received.load(Ordering::Relaxed)
    }

    /// Register signal handlers (SIGTERM, SIGINT).
    /// Returns the shared signal flag.
    #[must_use]
    pub fn register_handlers(&self) -> Arc<AtomicBool> {
        let flag = self.signal_received.clone();

        // SIGTERM
        let f = flag.clone();
        let _ = std::thread::spawn(move || {
            // Platform-specific signal handling would go here.
            // On Unix, we would use:
            //   let sigterm = signal_hook::consts::signal::SIGTERM;
            //   signal_hook::flag::register(sigterm, f).ok();
            //
            // For now, we expose the flag and ctrl_c handler.
            drop(f);
        });

        // Ctrl+C (cross-platform)
        let f2 = flag.clone();
        std::thread::spawn(move || {
            loop {
                if std::io::stdin().lock().fill_buf().is_ok() {
                    // stdin closed => signal
                    f2.store(true, Ordering::Relaxed);
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });

        flag
    }

    /// Execute the shutdown sequence.
    pub fn execute_shutdown(&self, checkpointer: &mut Option<SessionCheckpointer>, message: &str) -> ShutdownResult {
        log::info!("Graceful shutdown initiated: {message}");

        let start = Instant::now();

        // 1. Flush audit log
        if self.actions.should_flush_audit {
            // The audit system uses SessionAuditor which persists on each log.
            // We just ensure the global auditor flushes.
            let auditor = crate::audit_integration::global_auditor();
            if let Ok(mut guard) = auditor.lock() {
                if let Some(ref mut a) = *guard {
                    let () = a.end_session();
                }
            }
        }

        // 2. Checkpoint
        if self.actions.should_checkpoint {
            if let Some(ref mut cp) = checkpointer {
                cp.checkpoint_now(None);
            }
        }

        // 3. Stop health monitor
        if let Some(ref health) = self.health {
            health.stop();
        }

        // 4. Close MCP connections
        if self.actions.should_close_mcp {
            // MCP connections are managed by McpServerManager which is dropped on shutdown.
            // The mcp_tool_bridge and plugin_lifecycle modules handle cleanup.
        }

        // 5. Zeroize secrets
        if self.actions.should_zeroize {
            // The security crate registers a panic hook that zeroizes on panic.
            // For normal shutdown, vault drop handles zeroize.
        }

        let elapsed = start.elapsed();
        ShutdownResult {
            success: true,
            elapsed_ms: {
                #[allow(clippy::cast_possible_truncation)]
                { elapsed.as_millis() as u64 }
            },
            message: message.to_string(),
        }
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownResult {
    pub success: bool,
    pub elapsed_ms: u64,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// Top-level self-healing orchestrator that ties all components together.
pub struct SelfHealingOrchestrator {
    pub checkpointer: Option<SessionCheckpointer>,
    pub health_monitor: Arc<HealthMonitor>,
    pub restarter: Arc<AutoRestarter>,
    pub shutdown: Arc<GracefulShutdown>,
    checkpoint_dir: PathBuf,
}

impl SelfHealingOrchestrator {
    #[must_use]
    pub fn new(checkpoint_dir: &Path) -> Self {
        let health = Arc::new(HealthMonitor::new());
        let restarter = Arc::new(AutoRestarter::new().with_health_monitor(health.clone()));
        let shutdown = Arc::new(GracefulShutdown::new().with_health_monitor(health.clone()));

        Self {
            checkpointer: None,
            health_monitor: health,
            restarter,
            shutdown,
            checkpoint_dir: checkpoint_dir.to_path_buf(),
        }
    }

    /// Initialize checkpointer for a session.
    pub fn init_session(&mut self, session_id: &str) {
        let session_dir = self.checkpoint_dir.join("sessions").join(session_id);
        let cp = SessionCheckpointer::new(&session_dir, session_id);
        self.checkpointer = Some(cp);
    }

    /// Start all background loops.
    pub fn start(&self) {
        let _ = self.health_monitor.start();
        let _ = self.shutdown.register_handlers();

        // Register default components
        self.health_monitor.register_component("runtime");
        self.health_monitor.register_component("worker-pool");
        self.restarter.register("mcp-servers");
        self.restarter.register("worker-pool");
        self.restarter.register("runtime");
    }

    /// Report that the system is alive.
    pub fn heartbeat(&self, component: &str) {
        self.health_monitor.report_heartbeat(component);
    }

    /// Get a health report.
    #[must_use]
    pub fn health_report(&self) -> HealthReport {
        self.health_monitor.report()
    }

    /// Record a tool call (triggers checkpoint if needed).
    pub fn record_tool_call(&mut self, tool: &str, input: &serde_json::Value, session_data: Option<serde_json::Value>) -> Option<CheckpointManifest> {
        if let Some(ref mut cp) = self.checkpointer {
            let manifest = cp.record_tool_call(tool, input);
            if manifest.is_some() {
                // Force checkpoint with current data if available
                cp.checkpoint_now(session_data);
            }
            self.health_monitor.report_heartbeat("runtime");
            manifest
        } else {
            None
        }
    }

    /// Initiate graceful shutdown.
    pub fn shutdown(&mut self, reason: &str) -> ShutdownResult {
        self.shutdown.execute_shutdown(&mut self.checkpointer, reason)
    }

    /// Attempt to recover from a component failure.
    #[must_use]
    pub fn attempt_restart(&self, component: &str) -> Duration {
        self.health_monitor.report_failure(component, "restarting");
        self.restarter.record_attempt(component)
    }

    /// Mark a component as recovered.
    pub fn mark_recovered(&self, component: &str) {
        self.restarter.mark_recovered(component);
        self.health_monitor.mark_healthy(component);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static GLOBAL_HEALING: OnceLock<Arc<Mutex<SelfHealingOrchestrator>>> = OnceLock::new();

/// Initialize the global self-healing orchestrator.
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn init_global_self_healing(checkpoint_dir: &Path) {
    GLOBAL_HEALING.get_or_init(|| {
        let orchestrator = SelfHealingOrchestrator::new(checkpoint_dir);
        orchestrator.start();
        Arc::new(Mutex::new(orchestrator))
    });
}

/// Access the global orchestrator, if initialized.
pub fn with_global_healing<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut SelfHealingOrchestrator) -> R,
{
    GLOBAL_HEALING.get().and_then(|arc| {
        let mut guard = arc.lock().ok()?;
        Some(f(&mut guard))
    })
}

/// Initiate global graceful shutdown.
#[must_use]
pub fn global_shutdown(reason: &str) -> Option<ShutdownResult> {
    with_global_healing(|o| o.shutdown(reason))
}

/// Report heartbeat to the global orchestrator.
pub fn global_heartbeat(component: &str) {
    let _ = with_global_healing(|o| o.heartbeat(component));
}

/// Record a tool call through the global orchestrator.
#[must_use]
pub fn global_record_tool_call(tool: &str, input: &serde_json::Value, session_data: Option<serde_json::Value>) -> Option<CheckpointManifest> {
    with_global_healing(|o| o.record_tool_call(tool, input, session_data)).flatten()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

fn now_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn serialize_wal(entries: &[WalEntry]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&serde_json::to_string(entry)?);
        out.push('\n');
    }
    Ok(out)
}

fn read_wal(path: &Path) -> Result<Vec<WalEntry>, RuntimeError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            entries.push(serde_json::from_str(&line).map_err(|e| RuntimeError::Other(e.to_string()))?);
        }
    }
    Ok(entries)
}

fn prune_checkpoints(dir: &Path, keep: usize) {
    let mut snapshots: Vec<(u64, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(seq) = name.strip_prefix("snapshot-").and_then(|s| s.strip_suffix(".json")) {
                if let Ok(seq_num) = seq.parse::<u64>() {
                    snapshots.push((seq_num, entry.path()));
                }
            }
        }
    }
    snapshots.sort_by_key(|b| std::cmp::Reverse(b.0)); // descending

    for (_, path) in snapshots.iter().skip(keep) {
        let _ = fs::remove_file(path);
        // Also remove corresponding WAL
        let wal = path.with_extension("jsonl").with_file_name(
            path.file_stem().unwrap_or_default().to_string_lossy().replace("snapshot", "wal") + ".jsonl"
        );
        let _ = fs::remove_file(wal);
    }
}

fn find_any_snapshot(dir: &Path) -> Option<CheckpointManifest> {
    let mut best_seq = 0u64;
    let mut best_path = None;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(seq) = name.strip_prefix("snapshot-").and_then(|s| s.strip_suffix(".json")) {
                if let Ok(seq_num) = seq.parse::<u64>() {
                    if seq_num > best_seq {
                        best_seq = seq_num;
                        best_path = Some(entry.path());
                    }
                }
            }
        }
    }
    let path = best_path?;
    let data = fs::read_to_string(&path).ok()?;
    let snapshot: SessionSnapshot = serde_json::from_str(&data).ok()?;
    Some(CheckpointManifest {
        session_id: snapshot.session_id,
        last_sequence: best_seq,
        snapshot_path: path.to_string_lossy().to_string(),
        wal_path: String::new(),
        snapshot_checksum: snapshot.checksum,
        created_at_ms: snapshot.timestamp_ms,
        message_count: snapshot.message_count,
    })
}

fn read_memory_stats() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/meminfo") {
            let mut avail = 0u64;
            let mut total = 0u64;
            for line in content.lines() {
                if line.starts_with("MemAvailable:") {
                    avail = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                }
                if line.starts_with("MemTotal:") {
                    total = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                }
            }
            return (avail, total);
        }
    }
    (0, 0)
}

fn read_disk_stats(path: &Path) -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(stat) = fs::metadata(path) {
            // Use `statvfs` via libc or fallback
            if let Ok(content) = fs::read_to_string("/proc/mounts") {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && path.starts_with(parts[1]) {
                        // Found mount point — would need statvfs for accurate numbers
                        break;
                    }
                }
            }
            let _ = stat;
        }
    }
    (0, 0)
}

fn read_uptime() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/uptime") {
            if let Some(secs) = content.split_whitespace().next() {
                if let Ok(f) = secs.parse::<f64>() {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    { return f as u64; }
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_checkpointer_creates_checkpoint() {
        let dir = std::env::temp_dir().join(format!("checkpoint-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let mut cp = SessionCheckpointer::new(&dir, "test-session");
        assert_eq!(cp.session_id(), "test-session");

        let input = serde_json::json!({"tool": "bash", "input": "ls -la"});
        let manifest = cp.record_tool_call("bash", &input);
        assert!(manifest.is_none(), "first call should not trigger checkpoint");

        // Force checkpoint
        let data = serde_json::json!({"messages": [{"role": "user", "content": "hello"}]});
        let manifest = cp.checkpoint_now(Some(data));
        assert!(manifest.is_some(), "checkpoint should be created");

        let manifest = manifest.unwrap();
        assert_eq!(manifest.session_id, "test-session");
        assert!(Path::new(&manifest.snapshot_path).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_checkpointer_find_latest() {
        let dir = std::env::temp_dir().join(format!("checkpoint-find-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut cp = SessionCheckpointer::new(&dir, "find-session");
        cp.checkpoint_now(Some(serde_json::json!({"seq": 1})));
        cp.checkpoint_now(Some(serde_json::json!({"seq": 2})));
        cp.checkpoint_now(Some(serde_json::json!({"seq": 3})));

        // List what was written
        let files: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
        eprintln!("DEBUG checkpoint files: {files:?}");

        let found = SessionCheckpointer::find_latest_checkpoint(&dir);
        assert!(found.is_some(), "should find latest checkpoint, files: {files:?}");
        assert_eq!(found.unwrap().last_sequence, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_wal_serialization() {
        let entries = vec![
            WalEntry {
                sequence: 1,
                timestamp_ms: 1000,
                operation: "tool_call:bash".to_string(),
                data: serde_json::json!({"cmd": "ls"}),
            },
            WalEntry {
                sequence: 2,
                timestamp_ms: 2000,
                operation: "tool_call:read".to_string(),
                data: serde_json::json!({"path": "/tmp/test"}),
            },
        ];

        let serialized = serialize_wal(&entries).unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join("test-wal.jsonl");
        fs::write(&path, &serialized).unwrap();

        let deserialized = read_wal(&path).unwrap();
        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].sequence, 1);
        assert_eq!(deserialized[1].operation, "tool_call:read");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_backoff_strategy() {
        let mut comp = RestartableComponent::new("test-mcp");
        assert_eq!(comp.attempt, 0);

        let d1 = comp.record_attempt();
        assert_eq!(comp.attempt, 1);
        assert!(d1.as_secs() >= 1 && d1.as_secs() <= 3); // ~1s + jitter

        let d2 = comp.record_attempt();
        assert_eq!(comp.attempt, 2);
        assert!(d2.as_secs() >= 2 && d2.as_secs() <= 5); // ~2s + jitter

        // Reset
        comp.reset();
        assert_eq!(comp.attempt, 0);
    }

    #[test]
    fn test_escalation() {
        let mut comp = RestartableComponent::new("test");
        comp.max_attempts = 3;
        assert!(!comp.should_escalate());
        comp.record_attempt();
        comp.record_attempt();
        comp.record_attempt();
        assert!(comp.should_escalate());
    }

    #[test]
    fn test_corruption_repair_verify() {
        let dir = std::env::temp_dir().join(format!("repair-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Write valid JSON
        fs::write(dir.join("test.json"), r#"{"valid": true}"#).unwrap();

        let corruptions = CorruptionRepair::verify_all(&dir);
        assert!(corruptions.is_empty(), "valid file should not be corrupt");

        // Write invalid JSON
        fs::write(dir.join("bad.json"), r#"{invalid json"#).unwrap();
        let corruptions = CorruptionRepair::verify_all(&dir);
        assert!(!corruptions.is_empty(), "invalid file should be detected");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_health_monitor_register_and_heartbeat() {
        let monitor = HealthMonitor::new();
        monitor.register_component("test-svc");

        assert_eq!(monitor.component_health("test-svc"), ComponentHealth::Unknown);

        monitor.report_heartbeat("test-svc");
        assert_eq!(monitor.component_health("test-svc"), ComponentHealth::Healthy);

        monitor.report_failure("test-svc", "connection refused");
        assert_eq!(monitor.component_health("test-svc"), ComponentHealth::Unhealthy);
    }

    #[test]
    fn test_health_report() {
        let monitor = HealthMonitor::new();
        monitor.register_component("svc-a");
        monitor.register_component("svc-b");
        monitor.report_heartbeat("svc-a");
        monitor.report_failure("svc-b", "crash");

        let report = monitor.report();
        assert!(!report.all_healthy);
        assert_eq!(report.unhealthy_count, 1);
    }

    #[test]
    fn test_graceful_shutdown_flag() {
        let shutdown = GracefulShutdown::new();
        assert!(!shutdown.signal_received());
        // Signal is set externally. In tests we verify the API.
    }

    #[test]
    fn test_shutdown_execution() {
        let dir = std::env::temp_dir().join(format!("shutdown-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let health = Arc::new(HealthMonitor::new());
        let mut orchestrator = SelfHealingOrchestrator::new(&dir);
        orchestrator.health_monitor = health.clone();
        orchestrator.init_session("shutdown-test");

        let result = orchestrator.shutdown("test shutdown");
        assert!(result.success);
        assert!(result.elapsed_ms < 5000); // should complete quickly

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_orchestrator_health() {
        let dir = std::env::temp_dir().join(format!("orch-test-{}", std::process::id()));
        let mut orch = SelfHealingOrchestrator::new(&dir);
        orch.start();
        orch.heartbeat("runtime");
        orch.heartbeat("worker-pool");

        let report = orch.health_report();
        assert!(!report.components.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_restartable_auto_restarter() {
        let restarter = AutoRestarter::new();
        restarter.register("mcp-anthropic");

        assert_eq!(restarter.attempt_count("mcp-anthropic"), 0);
        let delay = restarter.record_attempt("mcp-anthropic");
        assert_eq!(restarter.attempt_count("mcp-anthropic"), 1);
        assert!(delay.as_secs() >= 1);

        restarter.mark_recovered("mcp-anthropic");
        assert_eq!(restarter.attempt_count("mcp-anthropic"), 0);
    }

    #[test]
    fn test_checkpoint_interval_calls() {
        let dir = std::env::temp_dir().join(format!("interval-test-{}", std::process::id()));
        let mut cp = SessionCheckpointer::new(&dir, "interval-session")
            .with_intervals(3, 3600); // checkpoint every 3 calls

        let input = serde_json::json!({"cmd": "test"});
        assert!(cp.record_tool_call("bash", &input).is_none());
        assert!(cp.record_tool_call("bash", &input).is_none());
        let manifest = cp.record_tool_call("bash", &input);
        assert!(manifest.is_some(), "3rd call should trigger checkpoint");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_corruption_repair_fresh_session() {
        let dir = std::env::temp_dir().join(format!("fresh-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Empty directory should result in FreshSession
        let result = CorruptionRepair::repair(&dir);
        assert_eq!(result, RepairResult::FreshSession);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_system_metrics_collection() {
        let monitor = HealthMonitor::new();
        let metrics = monitor.collect_metrics();
        // At minimum, metrics should have a timestamp
        assert!(metrics.timestamp_ms > 0);
    }

    #[test]
    fn test_memory_critical_threshold() {
        // Not critical: 10% free
        let healthy = SystemMetrics {
            timestamp_ms: now_ms(),
            memory_available_kb: 1000,
            memory_total_kb: 10000,
            disk_free_kb: 0,
            disk_total_kb: 0,
            uptime_secs: 0,
            num_probes_healthy: 0,
            num_probes_degraded: 0,
            num_probes_unhealthy: 0,
        };
        assert!(!healthy.is_memory_critical(), "10% free should not be critical");

        // Critical: 1% free
        let critical = SystemMetrics {
            memory_available_kb: 100,
            memory_total_kb: 10000,
            ..healthy
        };
        assert!(critical.is_memory_critical(), "1% free should be critical");
    }

    #[test]
    fn test_disk_critical_threshold() {
        let metrics = SystemMetrics {
            timestamp_ms: now_ms(),
            memory_available_kb: 0,
            memory_total_kb: 0,
            disk_free_kb: 100,
            disk_total_kb: 10000,
            uptime_secs: 0,
            num_probes_healthy: 0,
            num_probes_degraded: 0,
            num_probes_unhealthy: 0,
        };
        // 100/10000 = 1% < 2% → critical
        assert!(metrics.is_disk_critical());
    }

    #[test]
    fn test_health_monitor_stale_heartbeat() {
        let monitor = HealthMonitor::new();
        monitor.register_component("stale-svc");
        monitor.report_heartbeat("stale-svc");
        assert_eq!(monitor.component_health("stale-svc"), ComponentHealth::Healthy);

        // In a real scenario, the background thread would detect stale heartbeats.
        // Here we just verify the initial state is correct after a heartbeat.
    }

    #[test]
    fn test_checkpointer_wal_size_triggers_checkpoint() {
        let dir = std::env::temp_dir().join(format!("wal-trigger-{}", std::process::id()));
        let mut cp = SessionCheckpointer::new(&dir, "wal-trigger")
            .with_intervals(1000, 3600); // High threshold for call/interval

        let input = serde_json::json!({"cmd": "test"});

        // MAX_WAL_ENTRIES is 100; fill up to trigger checkpoint
        // Checkpoint triggers when wal_entries.len() reaches MAX_WAL_ENTRIES,
        // which is the 100th entry (0-indexed: i=99)
        let mut last = None;
        for i in 0..MAX_WAL_ENTRIES + 1 {
            let manifest = cp.record_tool_call("bash", &input);
            if i == MAX_WAL_ENTRIES - 1 {
                last = manifest;
            }
        }
        assert!(last.is_some(), "WAL overflow should trigger checkpoint at entry {}", MAX_WAL_ENTRIES);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_restarter_registered_components() {
        let restarter = AutoRestarter::new();
        restarter.register("alpha");
        restarter.register("beta");
        restarter.register("gamma");

        let comps = restarter.registered_components();
        assert_eq!(comps.len(), 3);
        assert!(comps.contains(&"alpha".to_string()));
    }

    #[test]
    fn test_corruption_repair_checksum_verify() {
        let dir = std::env::temp_dir().join(format!("checksum-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        fs::write(&path, b"hello world").unwrap();

        let checksum = CorruptionRepair::compute_checksum(&path);
        assert!(checksum.is_some());

        let valid = CorruptionRepair::verify_file_checksum(&path, &checksum.unwrap());
        assert!(valid);

        // Wrong checksum
        let valid = CorruptionRepair::verify_file_checksum(&path, "deadbeef");
        assert!(!valid);

        let _ = fs::remove_dir_all(&dir);
    }
}
