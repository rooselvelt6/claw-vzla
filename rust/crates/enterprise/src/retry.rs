/// Retry logic with exponential backoff and jitter
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    pub fn new(max_retries: u32, initial_delay_ms: u64) -> Self {
        Self {
            max_retries,
            initial_delay_ms,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }

    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.initial_delay_ms as f64 * self.backoff_multiplier.powf(attempt as f64);
        let delay_ms = base.min(self.max_delay_ms as f64) as u64;

        if self.jitter {
            let mut rng = rand::rng();
            let jitter_range = 0.5 + rng.random::<f64>() * 0.5;
            let jittered = (delay_ms as f64 * jitter_range) as u64;
            Duration::from_millis(jittered.max(1))
        } else {
            Duration::from_millis(delay_ms)
        }
    }

    pub fn should_retry(&self, attempt: u32, error: &str) -> bool {
        if attempt >= self.max_retries {
            return false;
        }

        let retryable_errors = [
            "timeout",
            "connection",
            "network",
            "rate_limit",
            "429",
            "503",
            "502",
            "504",
        ];

        let error_lower = error.to_lowercase();
        retryable_errors.iter().any(|e| error_lower.contains(e))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RetryStrategy {
    #[default]
    None,
    ExponentialBackoff,
    Linear,
    Constant,
}

// Note: retry_async is simplified - see ROADMAP-ENTERPRISE.md for full implementation
pub async fn retry_async<T, E, F, Fut>(config: &RetryConfig, mut operation: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt = 0u32;

    loop {
        match operation(attempt).await {
            Ok(result) => return Ok(result),
            Err(_) => {
                attempt += 1;

                if attempt >= config.max_retries {
                    break;
                }

                let delay = config.delay(attempt);
                tokio::time::sleep(delay).await;
            }
        }
    }

    Err(operation(attempt).await.err().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_retry_delay_calculation() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: false,
        };

        let delay1 = config.delay(0);
        let delay2 = config.delay(1);
        let delay3 = config.delay(2);

        assert!(delay1.as_millis() >= 1000);
        assert!(delay2.as_millis() >= 2000);
        assert!(delay3.as_millis() >= 4000);
    }

    #[test]
    fn test_should_retry() {
        let config = RetryConfig::default();

        assert!(config.should_retry(0, "timeout error"));
        assert!(config.should_retry(0, "rate_limit"));
        assert!(!config.should_retry(0, "invalid_api_key"));
        assert!(!config.should_retry(100, "timeout"));
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.jitter);
    }

    #[test]
    fn test_retry_config_new() {
        let config = RetryConfig::new(5, 500);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay_ms, 500);
        assert_eq!(config.max_delay_ms, 30000);
        assert_eq!(config.backoff_multiplier, 2.0);
        assert!(config.jitter);
    }

    #[test]
    fn test_retry_delay_exponential_backoff_no_jitter() {
        let config = RetryConfig {
            max_retries: 10,
            initial_delay_ms: 100,
            max_delay_ms: 60000,
            backoff_multiplier: 2.0,
            jitter: false,
        };

        // attempt 0: 100 * 2^0 = 100
        assert_eq!(config.delay(0).as_millis(), 100);
        // attempt 1: 100 * 2^1 = 200
        assert_eq!(config.delay(1).as_millis(), 200);
        // attempt 2: 100 * 2^2 = 400
        assert_eq!(config.delay(2).as_millis(), 400);
        // attempt 3: 100 * 2^3 = 800
        assert_eq!(config.delay(3).as_millis(), 800);
    }

    #[test]
    fn test_retry_delay_max_cap() {
        let config = RetryConfig {
            max_retries: 20,
            initial_delay_ms: 1000,
            max_delay_ms: 5000,
            backoff_multiplier: 2.0,
            jitter: false,
        };

        // attempt 10: 1000 * 2^10 = 1024000 -> capped at 5000
        let delay = config.delay(10);
        assert_eq!(delay.as_millis(), 5000);
    }

    #[test]
    fn test_retry_delay_with_jitter() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 30000,
            backoff_multiplier: 2.0,
            jitter: true,
        };

        // With jitter, delay should be between 50%-100% of base
        // For attempt 0, base = 1000ms, so jittered = 500..=1000
        let delay = config.delay(0);
        assert!(delay.as_millis() >= 500 && delay.as_millis() <= 1000);
    }

    #[test]
    fn test_should_retry_various_errors() {
        let config = RetryConfig::default();

        assert!(config.should_retry(0, "connection refused"));
        assert!(config.should_retry(0, "network error"));
        assert!(config.should_retry(0, "rate_limit exceeded"));
        assert!(config.should_retry(0, "HTTP 429"));
        assert!(config.should_retry(0, "HTTP 503"));
        assert!(config.should_retry(0, "HTTP 502"));
        assert!(config.should_retry(0, "HTTP 504"));
        assert!(config.should_retry(0, "timeout"));
    }

    #[test]
    fn test_should_retry_non_retryable() {
        let config = RetryConfig::default();

        assert!(!config.should_retry(0, "invalid_api_key"));
        assert!(!config.should_retry(0, "permission denied"));
        assert!(!config.should_retry(0, "not found"));
        assert!(!config.should_retry(0, "bad request"));
        assert!(!config.should_retry(0, ""));
    }

    #[test]
    fn test_should_retry_exhausted() {
        let config = RetryConfig::new(3, 100);
        assert!(!config.should_retry(3, "timeout"));
        assert!(!config.should_retry(100, "timeout"));
        assert!(!config.should_retry(u32::MAX, "timeout"));
    }

    #[test]
    fn test_should_retry_at_boundary() {
        let config = RetryConfig::new(5, 100);
        assert!(config.should_retry(4, "timeout")); // 4 < 5
        assert!(!config.should_retry(5, "timeout")); // 5 >= 5
    }

    #[test]
    fn test_should_retry_case_insensitive() {
        let config = RetryConfig::default();
        assert!(config.should_retry(0, "TIMEOUT"));
        assert!(config.should_retry(0, "Connection"));
        assert!(config.should_retry(0, "NETWORK"));
    }

    #[test]
    fn test_retry_strategy_default() {
        let strategy = RetryStrategy::default();
        assert_eq!(strategy, RetryStrategy::None);
    }

    #[test]
    fn test_retry_strategy_variants() {
        let strategies = [
            RetryStrategy::None,
            RetryStrategy::ExponentialBackoff,
            RetryStrategy::Linear,
            RetryStrategy::Constant,
        ];

        for s in &strategies {
            let json = serde_json::to_string(s).unwrap();
            let deserialized: RetryStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, deserialized);
        }
    }

    #[test]
    fn test_retry_config_serialization() {
        let config = RetryConfig::new(5, 200);
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.max_retries, 5);
        assert_eq!(deserialized.initial_delay_ms, 200);
        assert_eq!(deserialized.max_delay_ms, 30000);
        assert_eq!(deserialized.backoff_multiplier, 2.0);
        assert!(deserialized.jitter);
    }

    #[test]
    fn test_retry_config_clone() {
        let config = RetryConfig::new(7, 300);
        let cloned = config.clone();
        assert_eq!(cloned.max_retries, 7);
        assert_eq!(cloned.initial_delay_ms, 300);
    }

    #[test]
    fn test_retry_delay_multiplier_one() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 100,
            max_delay_ms: 10000,
            backoff_multiplier: 1.0,
            jitter: false,
        };

        // With multiplier 1.0, all delays should be the same
        assert_eq!(config.delay(0).as_millis(), 100);
        assert_eq!(config.delay(1).as_millis(), 100);
        assert_eq!(config.delay(5).as_millis(), 100);
    }

    #[test]
    fn test_retry_delay_zero_initial() {
        let config = RetryConfig {
            max_retries: 3,
            initial_delay_ms: 0,
            max_delay_ms: 1000,
            backoff_multiplier: 2.0,
            jitter: false,
        };
        // 0 * 2^anything = 0
        assert_eq!(config.delay(0).as_millis(), 0);
        assert_eq!(config.delay(5).as_millis(), 0);
    }

    #[tokio::test]
    async fn test_retry_async_success_first_try() {
        let config = RetryConfig::new(3, 10);
        let result = retry_async(&config, |_attempt| async { Ok::<_, String>("ok") }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ok");
    }

    #[tokio::test]
    async fn test_retry_async_success_after_retries() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay_ms: 1,
            max_delay_ms: 10,
            backoff_multiplier: 1.0,
            jitter: false,
        };

        let counter = Arc::new(Mutex::new(0u32));
        let counter_clone = counter.clone();

        let result = retry_async(&config, move |attempt| {
            let counter = counter_clone.clone();
            async move {
                let mut count = counter.lock().unwrap();
                *count += 1;
                if attempt < 2 {
                    Err("transient".to_string())
                } else {
                    Ok("success".to_string())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[tokio::test]
    async fn test_retry_async_failure_exhausted() {
        let config = RetryConfig {
            max_retries: 2,
            initial_delay_ms: 1,
            max_delay_ms: 10,
            backoff_multiplier: 1.0,
            jitter: false,
        };

        let result: Result<String, String> = retry_async(&config, |_attempt| async {
            Err("permanent".to_string())
        })
        .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "permanent");
    }
}
