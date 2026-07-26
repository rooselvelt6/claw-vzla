use thiserror::Error;

#[derive(Error, Debug)]
pub enum MobileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Invalid file format: {0}")]
    InvalidFormat(String),
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
}

impl From<MobileError> for String {
    fn from(e: MobileError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_error_display() {
        let err = MobileError::Parse("invalid dex".to_string());
        assert!(err.to_string().contains("invalid dex"));
    }

    #[test]
    fn test_mobile_error_into_string() {
        let err = MobileError::InvalidFormat("not an apk".to_string());
        let msg: String = err.into();
        assert!(msg.contains("not an apk"));
    }
}
