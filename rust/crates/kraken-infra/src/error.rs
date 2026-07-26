use thiserror::Error;

#[derive(Error, Debug)]
pub enum InfraError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

impl From<InfraError> for String {
    fn from(e: InfraError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infra_error_display() {
        let err = InfraError::PathTraversal("symlink escape".to_string());
        assert!(err.to_string().contains("symlink escape"));
    }

    #[test]
    fn test_infra_error_into_string() {
        let err = InfraError::PermissionDenied("access denied".to_string());
        let msg: String = err.into();
        assert!(msg.contains("access denied"));
    }
}
