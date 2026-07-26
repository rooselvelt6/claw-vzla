use thiserror::Error;

#[derive(Error, Debug)]
pub enum OsintError {
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("Whois lookup failed: {0}")]
    Whois(String),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<OsintError> for String {
    fn from(e: OsintError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_osint_error_display() {
        let err = OsintError::Dns("resolution failed".to_string());
        assert!(err.to_string().contains("resolution failed"));
    }

    #[test]
    fn test_osint_error_into_string() {
        let err = OsintError::Http("timeout".to_string());
        let msg: String = err.into();
        assert!(msg.contains("timeout"));
    }
}
