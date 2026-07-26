use thiserror::Error;

#[derive(Error, Debug)]
pub enum LocalModelsError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Model error: {0}")]
    Model(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Training failed: {0}")]
    TrainingFailed(String),
}

impl From<LocalModelsError> for String {
    fn from(e: LocalModelsError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_localmodels_error_display() {
        let err = LocalModelsError::Model("load failed".to_string());
        assert!(err.to_string().contains("load failed"));
    }

    #[test]
    fn test_localmodels_error_into_string() {
        let err = LocalModelsError::InvalidInput("empty data".to_string());
        let msg: String = err.into();
        assert!(msg.contains("empty data"));
    }
}
