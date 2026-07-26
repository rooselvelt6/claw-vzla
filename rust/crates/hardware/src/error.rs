use thiserror::Error;

#[derive(Error, Debug)]
pub enum HardwareError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Tool execution failed: {0}")]
    ToolExecution(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl From<HardwareError> for String {
    fn from(e: HardwareError) -> Self {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_error_display() {
        let err = HardwareError::DeviceNotFound("UART not found".to_string());
        assert!(err.to_string().contains("UART not found"));
    }

    #[test]
    fn test_hardware_error_into_string() {
        let err = HardwareError::ToolExecution("flash read failed".to_string());
        let msg: String = err.into();
        assert!(msg.contains("flash read failed"));
    }
}
