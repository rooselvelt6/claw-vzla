//! Linux Namespace Isolation — Unshare-based process isolation.
//!
//! Wraps the `unshare(2)` syscall to create isolated namespaces:
//! - PID namespace (process tree isolation)
//! - Mount namespace (filesystem mount isolation)
//! - Network namespace (network stack isolation)
//! - UTS namespace (hostname isolation)
//! - IPC namespace (System V IPC isolation)
//! - User namespace (UID/GID mapping)

use kraken_errors::SandboxError;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    User,
    Mount,
    Pid,
    Net,
    Ipc,
    Uts,
    Cgroup,
    Time,
}

#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub isolate_user: bool,
    pub isolate_mount: bool,
    pub isolate_pid: bool,
    pub isolate_net: bool,
    pub isolate_ipc: bool,
    pub isolate_uts: bool,
    pub isolate_cgroup: bool,
    pub isolate_time: bool,
    pub map_root_user: bool,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        Self {
            isolate_user: true,
            isolate_mount: false,
            isolate_pid: false,
            isolate_net: true,
            isolate_ipc: true,
            isolate_uts: true,
            isolate_cgroup: false,
            isolate_time: false,
            map_root_user: true,
        }
    }
}

impl NamespaceConfig {
    pub fn minimal() -> Self {
        Self {
            isolate_user: true,
            isolate_net: true,
            ..Default::default()
        }
    }

    pub fn full() -> Self {
        Self {
            isolate_user: true,
            isolate_mount: true,
            isolate_pid: true,
            isolate_net: true,
            isolate_ipc: true,
            isolate_uts: true,
            isolate_cgroup: true,
            isolate_time: true,
            map_root_user: true,
        }
    }

    /// Compute the CLONE_NEW* flags for unshare(2).
    pub fn unshare_flags(&self) -> i32 {
        let mut flags = 0i32;
        if self.isolate_user {
            flags |= nix::sched::CloneFlags::CLONE_NEWUSER.bits();
        }
        if self.isolate_mount {
            flags |= nix::sched::CloneFlags::CLONE_NEWNS.bits();
        }
        if self.isolate_pid {
            flags |= nix::sched::CloneFlags::CLONE_NEWPID.bits();
        }
        if self.isolate_net {
            flags |= nix::sched::CloneFlags::CLONE_NEWNET.bits();
        }
        if self.isolate_ipc {
            flags |= nix::sched::CloneFlags::CLONE_NEWIPC.bits();
        }
        if self.isolate_uts {
            flags |= nix::sched::CloneFlags::CLONE_NEWUTS.bits();
        }
        if self.isolate_cgroup {
            flags |= nix::sched::CloneFlags::CLONE_NEWCGROUP.bits();
        }
        if self.isolate_time {
            // CLONE_NEWTIME (Linux 5.6+) — raw constant
            flags |= 0x20000000;
        }
        flags
    }

    /// Apply namespace isolation via unshare(2).
    /// Must be called BEFORE spawning the sandboxed process.
    pub fn apply(&self) -> Result<(), SandboxError> {
        let flags = self.unshare_flags();
        if flags == 0 {
            return Ok(());
        }

        // Use libc::unshare directly (nix 0.29 removed its wrapper)
        let ret = unsafe { libc::unshare(flags) };
        if ret != 0 {
            return Err(SandboxError::Namespace(format!(
                "unshare({flags:#x}): {}",
                std::io::Error::last_os_error()
            )));
        }

        if self.isolate_user && self.map_root_user {
            Self::map_root_uid_gid()?;
        }

        Ok(())
    }

    /// Map UID 0 and GID 0 inside the new user namespace to the outside UID/GID.
    fn map_root_uid_gid() -> Result<(), SandboxError> {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        let uid_map = format!("0 {uid} 1\n");
        std::fs::write("/proc/self/uid_map", uid_map.as_bytes())
            .map_err(|e| SandboxError::Namespace(format!("uid_map write: {e}")))?;

        std::fs::write("/proc/self/setgroups", b"deny")
            .map_err(|e| SandboxError::Namespace(format!("setgroups write: {e}")))?;

        let gid_map = format!("0 {gid} 1\n");
        std::fs::write("/proc/self/gid_map", gid_map.as_bytes())
            .map_err(|e| SandboxError::Namespace(format!("gid_map write: {e}")))?;

        Ok(())
    }

    /// Check if user namespaces are available on this system.
    pub fn user_namespace_available() -> bool {
        let ret = unsafe { libc::unshare(nix::sched::CloneFlags::CLONE_NEWUSER.bits()) };
        ret == 0
    }
}

/// Check namespace availability by trying an unshare with just user namespace.
pub fn namespace_supported() -> bool {
    let has_unshare = std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|p| p.join("unshare").exists())
    });
    if !has_unshare {
        return false;
    }

    std::process::Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Check if a specific namespace type is available.
pub fn namespace_type_available(ns: NamespaceType) -> bool {
    let file = match ns {
        NamespaceType::User => "/proc/self/ns/user",
        NamespaceType::Mount => "/proc/self/ns/mnt",
        NamespaceType::Pid => "/proc/self/ns/pid",
        NamespaceType::Net => "/proc/self/ns/net",
        NamespaceType::Ipc => "/proc/self/ns/ipc",
        NamespaceType::Uts => "/proc/self/ns/uts",
        NamespaceType::Cgroup => "/proc/self/ns/cgroup",
        NamespaceType::Time => "/proc/self/ns/time",
    };
    Path::new(file).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_config_default() {
        let config = NamespaceConfig::default();
        assert!(config.isolate_user);
        assert!(config.isolate_net);
        assert!(config.map_root_user);
    }

    #[test]
    fn test_namespace_config_minimal() {
        let config = NamespaceConfig::minimal();
        assert!(config.isolate_user);
        assert!(!config.isolate_mount);
        assert!(!config.isolate_pid);
    }

    #[test]
    fn test_namespace_config_full() {
        let config = NamespaceConfig::full();
        assert!(config.isolate_user);
        assert!(config.isolate_mount);
        assert!(config.isolate_pid);
        assert!(config.isolate_net);
        assert!(config.isolate_ipc);
        assert!(config.isolate_uts);
        assert!(config.isolate_cgroup);
        assert!(config.isolate_time);
    }

    #[test]
    fn test_unshare_flags() {
        let config = NamespaceConfig::full();
        let flags = config.unshare_flags();
        assert_ne!(flags, 0);
        assert!(flags & 0x10000000 != 0, "CLONE_NEWUSER flag missing");
    }

    #[test]
    fn test_unshare_flags_minimal() {
        let config = NamespaceConfig::minimal();
        let flags = config.unshare_flags();
        assert_ne!(flags, 0);
        assert!(flags & 0x10000000 != 0);
    }

    #[test]
    fn test_namespace_supported() {
        let _supported = namespace_supported();
    }

    #[test]
    fn test_ns_type_available() {
        let has_user = namespace_type_available(NamespaceType::User);
        eprintln!("User namespace available: {has_user}");

        if cfg!(target_os = "linux") {
            assert!(namespace_type_available(NamespaceType::User));
        }
    }

    #[test]
    fn test_user_namespace_available() {
        let available = NamespaceConfig::user_namespace_available();
        eprintln!("User namespaces available: {available}");
    }
}
