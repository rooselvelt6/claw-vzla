use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportingError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Template error: {0}")]
    Template(String),
    #[error("Generation failed: {0}")]
    GenerationFailed(String),
}

impl From<ReportingError> for String {
    fn from(e: ReportingError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reporting_error_display() {
        let err = ReportingError::Serialization("invalid json".to_string());
        assert!(err.to_string().contains("invalid json"));
    }

    #[test]
    fn test_reporting_error_into_string() {
        let err = ReportingError::GenerationFailed("render failed".to_string());
        let msg: String = err.into();
        assert!(msg.contains("render failed"));
    }
}
