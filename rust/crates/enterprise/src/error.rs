use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnterpriseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Authentication failed: {0}")]
    Auth(String),
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl From<EnterpriseError> for String {
    fn from(e: EnterpriseError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enterprise_error_display() {
        let err = EnterpriseError::Auth("invalid token".to_string());
        assert!(err.to_string().contains("invalid token"));
    }

    #[test]
    fn test_enterprise_error_into_string() {
        let err = EnterpriseError::Config("missing key".to_string());
        let msg: String = err.into();
        assert!(msg.contains("missing key"));
    }
}
