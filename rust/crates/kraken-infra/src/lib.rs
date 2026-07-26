//! Infrastructure utilities extracted from the `runtime` god crate.
//!
//! This crate provides circuit breaking, health probing, rate limiting,
//! concurrency management, file operations, path safety, sandboxing,
//! forensics, fingerprinting, budgeting, summary compression, and bootstrapping.

pub mod bootstrap;
pub mod circuit_breaker;
pub mod concurrency;
pub mod error;
pub mod file_ops;
pub mod forensic;
pub mod fingerprint;
pub mod health_probe;
pub mod path_traversal;
pub mod rate_limiter;
pub mod sandbox;
pub mod sanitizer;
pub mod size_budget;
pub mod summary_compression;

#[cfg(target_os = "linux")]
pub mod sandbox_seccomp;
#[cfg(target_os = "linux")]
pub mod sandbox_landlock;
#[cfg(target_os = "linux")]
pub mod sandbox_namespace;
#[cfg(target_os = "linux")]
pub mod sandbox_resource;

pub use bootstrap::{BootstrapPhase, BootstrapPlan};
pub use circuit_breaker::{
    global_circuit_forest, init_circuit_forest, CircuitForest, CircuitLevel, CircuitNode, CircuitState,
};
pub use concurrency::{
    global_concurrency_manager, ConcurrencyCategory, ConcurrencyGuard, ConcurrencyManager,
    ConcurrencyStatus,
};
pub use file_ops::{
    edit_file, glob_search, grep_search, read_file, write_file, EditFileOutput, GlobSearchOutput,
    GrepSearchInput, GrepSearchOutput, ReadFileOutput, StructuredPatchHunk, TextFilePayload,
    WriteFileOutput,
};
pub use forensic::{global_forensic, ForensicEntry, ForensicRecorder};
pub use fingerprint::{hash_arguments, ToolCallDigest, ToolCallFingerprinter};
pub use health_probe::{
    global_health_registry, HealthProbeRegistry, HealthStatus, LatencyWindow, ProbeReport,
    ProbeTarget,
};
pub use path_traversal::{detect_traversal, validate_path_safety, TraversalDetection, TraversalKind};
pub use rate_limiter::{
    global_rate_limiter, AdaptiveTokenBucket, TokenBucketRegistry,
};
pub use sandbox::{
    build_linux_sandbox_command, detect_container_environment, detect_container_environment_from,
    resolve_sandbox_status, resolve_sandbox_status_for_request, ContainerEnvironment,
    FilesystemIsolationMode, LinuxSandboxCommand, SandboxConfig, SandboxDetectionInputs,
    SandboxRequest, SandboxStatus, ToolSandbox,
};
pub use sanitizer::{
    file_op_count, track_file_operation, Sanitizer, SanitizerConfig, SanitizerIssue,
    SanitizerResult, SanitizerStage,
};
pub use size_budget::{BudgetExceeded, SessionStats, SizeBudgeter, ToolBudget, ToolKind};
pub use summary_compression::{
    compress_summary, compress_summary_text, SummaryCompressionBudget, SummaryCompressionResult,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infra_reexports_work() {
        let _ = BootstrapPlan::claude_code_default();
        let _ = CircuitNode::new("test", CircuitLevel::Tool, 3, std::time::Duration::from_secs(30));
        let _ = ConcurrencyManager::new();
        let _ = SizeBudgeter::new();
        let _ = ToolCallFingerprinter::new(10);
        let _ = Sanitizer::with_defaults();
        let _ = SummaryCompressionBudget::default();
    }
}
