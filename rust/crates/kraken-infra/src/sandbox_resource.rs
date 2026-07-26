//! Resource limits (rlimit) wrapper.
//!
//! Applies POSIX resource limits via `setrlimit` to sandboxed processes:
//! CPU time, address space, file size, open file count, number of processes.

use kraken_errors::SandboxError;
use nix::sys::resource::{setrlimit, Resource};

#[derive(Debug, Clone, Copy)]
pub struct ResourceLimits {
    pub cpu_time_secs: u64,
    pub address_space_bytes: u64,
    pub file_size_bytes: u64,
    pub open_files: u64,
    pub processes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_time_secs: 60,
            address_space_bytes: 1_073_741_824,
            file_size_bytes: 104_857_600,
            open_files: 256,
            processes: 16,
        }
    }
}

impl ResourceLimits {
    pub const fn strict() -> Self {
        Self {
            cpu_time_secs: 60,
            address_space_bytes: 1_073_741_824,
            file_size_bytes: 104_857_600,
            open_files: 256,
            processes: 16,
        }
    }

    pub fn apply(&self) -> Result<(), SandboxError> {
        setrlimit(
            Resource::RLIMIT_CPU,
            self.cpu_time_secs,
            self.cpu_time_secs.saturating_add(30),
        )
        .map_err(|e| SandboxError::Rlimit(format!("RLIMIT_CPU: {e}")))?;

        setrlimit(
            Resource::RLIMIT_AS,
            self.address_space_bytes,
            self.address_space_bytes,
        )
        .map_err(|e| SandboxError::Rlimit(format!("RLIMIT_AS: {e}")))?;

        setrlimit(
            Resource::RLIMIT_FSIZE,
            self.file_size_bytes,
            self.file_size_bytes,
        )
        .map_err(|e| SandboxError::Rlimit(format!("RLIMIT_FSIZE: {e}")))?;

        setrlimit(
            Resource::RLIMIT_NOFILE,
            self.open_files,
            self.open_files,
        )
        .map_err(|e| SandboxError::Rlimit(format!("RLIMIT_NOFILE: {e}")))?;

        setrlimit(
            Resource::RLIMIT_NPROC,
            self.processes,
            self.processes,
        )
        .map_err(|e| SandboxError::Rlimit(format!("RLIMIT_NPROC: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.cpu_time_secs, 60);
        assert_eq!(limits.address_space_bytes, 1_073_741_824);
        assert_eq!(limits.file_size_bytes, 104_857_600);
        assert_eq!(limits.open_files, 256);
        assert_eq!(limits.processes, 16);
    }

    #[test]
    fn test_strict_limits() {
        let limits = ResourceLimits::strict();
        assert_eq!(limits.cpu_time_secs, 60);
        assert_eq!(limits.processes, 16);
    }

    #[test]
    fn test_apply_rlimits_construction() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.cpu_time_secs, 60);
        assert_eq!(limits.address_space_bytes, 1_073_741_824);
        assert_eq!(limits.processes, 16);
    }
}
