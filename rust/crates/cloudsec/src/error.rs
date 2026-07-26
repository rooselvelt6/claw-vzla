use thiserror::Error;

#[derive(Error, Debug)]
pub enum CloudSecError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<CloudSecError> for String {
    fn from(e: CloudSecError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudsec_error_display() {
        let err = CloudSecError::Http("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_cloudsec_error_into_string() {
        let err = CloudSecError::Parse("invalid json".to_string());
        let msg: String = err.into();
        assert!(msg.contains("invalid json"));
    }
}
