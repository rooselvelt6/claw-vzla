use thiserror::Error;

#[derive(Error, Debug)]
pub enum SocialEngError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("Template error: {0}")]
    Template(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<SocialEngError> for String {
    fn from(e: SocialEngError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socialeng_error_display() {
        let err = SocialEngError::Http("connection timeout".to_string());
        assert!(err.to_string().contains("connection timeout"));
    }

    #[test]
    fn test_socialeng_error_into_string() {
        let err = SocialEngError::Template("render failed".to_string());
        let msg: String = err.into();
        assert!(msg.contains("render failed"));
    }
}
