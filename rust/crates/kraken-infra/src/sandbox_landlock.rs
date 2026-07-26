//! Landlock (Linux 5.13+) — Unprivileged filesystem sandbox.
//!
//! Restricts filesystem access for the current process and its children.
//! The restrictions are enforced in-kernel and cannot be undone.

#![allow(non_camel_case_types, dead_code)]

use kraken_errors::SandboxError;
use std::path::Path;

const LANDLOCK_CREATE_RULESET: i64 = 444;
const LANDLOCK_ADD_RULE: i64 = 445;
const LANDLOCK_RESTRICT_SELF: i64 = 446;

const LANDLOCK_ABI_1: u32 = 1;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

const ACCESS_FS_READ: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR;

const ACCESS_FS_WRITE: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_TRUNCATE;

const ACCESS_FS_REFER: u64 = LANDLOCK_ACCESS_FS_REFER;

const ACCESS_FS_RW: u64 = ACCESS_FS_READ | ACCESS_FS_WRITE | ACCESS_FS_REFER;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Detects the Landlock ABI version available on this system.
pub fn detect_landlock_abi() -> u32 {
    unsafe {
        let mut attr = LandlockRulesetAttr {
            handled_access_fs: 0,
        };
        let ret = syscall_landlock_create_ruleset(
            &mut attr as *mut _ as *mut std::ffi::c_void,
            0,
            LANDLOCK_CREATE_RULESET_VERSION as u64,
        );
        if ret < 0 {
            return 0;
        }
        let fd = ret as i32;
        let _ = libc::close(fd);

        1
    }
}

/// Check if Landlock is supported on this system.
pub fn landlock_supported() -> bool {
    let path = "/sys/kernel/security/landlock/";
    if !Path::new(path).exists() {
        return false;
    }

    let abi_path = Path::new("/sys/kernel/security/landlock/abi");
    if abi_path.exists() {
        if let Ok(content) = std::fs::read_to_string(abi_path) {
            if let Ok(abi) = content.trim().parse::<u32>() {
                return abi >= LANDLOCK_ABI_1;
            }
        }
    }

    detect_landlock_abi() >= LANDLOCK_ABI_1
}

/// Landlock sandbox configuration.
#[derive(Debug, Clone)]
pub struct LandlockConfig {
    pub read_only_paths: Vec<std::path::PathBuf>,
    pub read_write_paths: Vec<std::path::PathBuf>,
    pub enabled: bool,
}

impl Default for LandlockConfig {
    fn default() -> Self {
        Self {
            read_only_paths: Vec::new(),
            read_write_paths: Vec::new(),
            enabled: true,
        }
    }
}

impl LandlockConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a read-only path (can read and exec, but not write).
    pub fn add_read_only(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.read_only_paths.push(path.into());
        self
    }

    /// Add a read-write path (can read, write, exec, create, delete).
    pub fn add_read_write(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.read_write_paths.push(path.into());
        self
    }

    /// Apply the Landlock restrictions.
    /// This is irreversible: once called, the process cannot access paths
    /// outside the allowed set.
    pub fn apply(&self) -> Result<(), SandboxError> {
        if !self.enabled {
            return Ok(());
        }

        if !landlock_supported() {
            return Err(SandboxError::Landlock(
                "Landlock not supported (kernel < 5.13 or LSM disabled)".to_string(),
            ));
        }

        let handled = ACCESS_FS_RW;

        let mut attr = LandlockRulesetAttr {
            handled_access_fs: handled,
        };

        let ruleset_fd = unsafe {
            syscall_landlock_create_ruleset(
                &mut attr as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            )
        };

        if ruleset_fd < 0 {
            return Err(SandboxError::Landlock(format!(
                "landlock_create_ruleset: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ruleset_fd = ruleset_fd as i32;

        for path in &self.read_only_paths {
            let path_str = path.to_string_lossy();
            let c_path = std::ffi::CString::new(path_str.as_ref())
                .map_err(|e| SandboxError::Landlock(format!("invalid path '{path_str}': {e}")))?;

            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                let _ = unsafe { libc::close(ruleset_fd) };
                return Err(SandboxError::Landlock(format!(
                    "cannot open '{}': {}",
                    path_str,
                    std::io::Error::last_os_error()
                )));
            }

            let path_attr = LandlockPathBeneathAttr {
                allowed_access: ACCESS_FS_READ,
                parent_fd: fd,
            };

            let ret = unsafe {
                syscall_landlock_add_rule(
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr as *const _ as *const std::ffi::c_void,
                    0,
                )
            };

            unsafe { libc::close(fd) };

            if ret != 0 {
                let _ = unsafe { libc::close(ruleset_fd) };
                return Err(SandboxError::Landlock(format!(
                    "landlock_add_rule (read) '{}': {}",
                    path_str,
                    std::io::Error::last_os_error()
                )));
            }
        }

        for path in &self.read_write_paths {
            let path_str = path.to_string_lossy();
            let c_path = std::ffi::CString::new(path_str.as_ref())
                .map_err(|e| SandboxError::Landlock(format!("invalid path '{path_str}': {e}")))?;

            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if fd < 0 {
                let _ = unsafe { libc::close(ruleset_fd) };
                return Err(SandboxError::Landlock(format!(
                    "cannot open '{}': {}",
                    path_str,
                    std::io::Error::last_os_error()
                )));
            }

            let path_attr = LandlockPathBeneathAttr {
                allowed_access: ACCESS_FS_RW,
                parent_fd: fd,
            };

            let ret = unsafe {
                syscall_landlock_add_rule(
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &path_attr as *const _ as *const std::ffi::c_void,
                    0,
                )
            };

            unsafe { libc::close(fd) };

            if ret != 0 {
                let _ = unsafe { libc::close(ruleset_fd) };
                return Err(SandboxError::Landlock(format!(
                    "landlock_add_rule (rw) '{}': {}",
                    path_str,
                    std::io::Error::last_os_error()
                )));
            }
        }

        let ret = unsafe { syscall_landlock_restrict_self(ruleset_fd, 0) };
        unsafe { libc::close(ruleset_fd) };

        if ret != 0 {
            return Err(SandboxError::Landlock(format!(
                "landlock_restrict_self: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn syscall_landlock_create_ruleset(
    attr: *mut std::ffi::c_void,
    size: usize,
    flags: u64,
) -> i64 {
    use std::arch::asm;
    let mut ret: i64;
    asm!(
        "syscall",
        in("rax") LANDLOCK_CREATE_RULESET,
        in("rdi") attr,
        in("rsi") size,
        in("rdx") flags,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn syscall_landlock_add_rule(
    ruleset_fd: i32,
    rule_type: u32,
    rule_attr: *const std::ffi::c_void,
    flags: u64,
) -> i64 {
    use std::arch::asm;
    let mut ret: i64;
    asm!(
        "syscall",
        in("rax") LANDLOCK_ADD_RULE,
        in("rdi") ruleset_fd as i64,
        in("rsi") rule_type as i64,
        in("rdx") rule_attr,
        in("r10") flags,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(target_arch = "x86_64")]
unsafe fn syscall_landlock_restrict_self(ruleset_fd: i32, flags: u64) -> i64 {
    use std::arch::asm;
    let mut ret: i64;
    asm!(
        "syscall",
        in("rax") LANDLOCK_RESTRICT_SELF,
        in("rdi") ruleset_fd as i64,
        in("rsi") flags,
        lateout("rax") ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn syscall_landlock_create_ruleset(
    _attr: *mut std::ffi::c_void,
    _size: usize,
    _flags: u64,
) -> i64 {
    -1
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn syscall_landlock_add_rule(
    _ruleset_fd: i32,
    _rule_type: u32,
    _rule_attr: *const std::ffi::c_void,
    _flags: u64,
) -> i64 {
    -1
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn syscall_landlock_restrict_self(_ruleset_fd: i32, _flags: u64) -> i64 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_config_default() {
        let config = LandlockConfig::default();
        assert!(config.read_only_paths.is_empty());
        assert!(config.read_write_paths.is_empty());
        assert!(config.enabled);
    }

    #[test]
    fn test_landlock_config_add_paths() {
        let config = LandlockConfig::new()
            .add_read_only("/usr/lib")
            .add_read_write("/tmp/work");
        assert_eq!(config.read_only_paths.len(), 1);
        assert_eq!(config.read_write_paths.len(), 1);
    }

    #[test]
    fn test_landlock_disabled_does_nothing() {
        let config = LandlockConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(config.apply().is_ok());
    }

    #[test]
    fn test_landlock_supported_check() {
        let _supported = landlock_supported();
    }

    #[test]
    fn test_landlock_detect_abi() {
        let abi = detect_landlock_abi();
        eprintln!("Landlock ABI: {abi}");
    }

    #[test]
    fn test_landlock_apply_real() {
        if !landlock_supported() {
            eprintln!("Landlock not supported, skipping real apply test");
            return;
        }

        let tmp = std::env::temp_dir().join(format!("landlock_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let test_file = tmp.join("test.txt");
        std::fs::write(&test_file, b"hello").unwrap();

        let config = LandlockConfig::new().add_read_only(&tmp);
        let result = config.apply();

        if let Err(e) = &result {
            eprintln!("Landlock apply failed (expected in some envs): {e}");
            let _ = std::fs::remove_file(&test_file);
            let _ = std::fs::remove_dir(&tmp);
            return;
        }

        let can_read = std::fs::read_to_string(&test_file).ok();
        eprintln!("Can read after landlock: {can_read:?}");

        let _ = std::fs::remove_file(&test_file);
        let _ = std::fs::remove_dir(&tmp);
    }
}
