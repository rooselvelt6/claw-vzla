use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReverseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("Tool execution failed: {0}")]
    ToolExecution(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<ReverseError> for String {
    fn from(e: ReverseError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_error_display() {
        let err = ReverseError::Parse("invalid binary".to_string());
        assert!(err.to_string().contains("invalid binary"));
    }

    #[test]
    fn test_reverse_error_into_string() {
        let err = ReverseError::UnsupportedFormat("unknown".to_string());
        let msg: String = err.into();
        assert!(msg.contains("unknown"));
    }
}
