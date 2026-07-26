use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_per_window: u64,
    window_secs: u64,
    counts: std::sync::Arc<std::sync::Mutex<Vec<(Instant, u64)>>>,
}

impl RateLimiter {
    pub fn new(max_per_window: u64, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            counts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn allow(&self) -> bool {
        let now = Instant::now();
        let mut counts = self.counts.lock().unwrap();
        counts.retain(|(t, _)| now.duration_since(*t).as_secs() < self.window_secs);
        if counts.len() < self.max_per_window as usize {
            counts.push((now, 1));
            true
        } else {
            false
        }
    }

    pub fn wait_if_needed(&self) {
        loop {
            if self.allow() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[derive(Debug, Clone)]
pub struct SemaphoreLimiter {
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
}

impl SemaphoreLimiter {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent)),
        }
    }

    pub async fn acquire(&self) -> tokio::sync::OwnedSemaphorePermit {
        match self.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => self.semaphore.clone().acquire_owned().await.unwrap(),
        }
    }

    pub fn try_acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }
}

pub fn backoff_delay(attempt: u32, base_ms: u64) -> Duration {
    let ms = (base_ms * 2u64.pow(attempt)).min(30_000);
    Duration::from_millis(ms)
}

pub fn jitter(dur: Duration) -> Duration {
    use rand::RngExt;
    let jitter_ms: u64 = rand::rng().random_range(0..=dur.as_millis() as u64);
    Duration::from_millis(jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_allows_within_window() {
        let limiter = RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(limiter.allow());
        }
    }

    #[test]
    fn rate_limiter_blocks_after_limit() {
        let limiter = RateLimiter::new(2, 60);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn backoff_increases_exponentially() {
        let d1 = backoff_delay(0, 100);
        assert_eq!(d1.as_millis(), 100);
        let d2 = backoff_delay(1, 100);
        assert_eq!(d2.as_millis(), 200);
        let d3 = backoff_delay(2, 100);
        assert_eq!(d3.as_millis(), 400);
    }

    #[test]
    fn backoff_caps_at_30s() {
        let d = backoff_delay(10, 100);
        assert_eq!(d.as_secs(), 30);
    }

    #[test]
    fn semaphore_acquire_release() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = SemaphoreLimiter::new(2);
            let p1 = limiter.acquire().await;
            let p2 = limiter.acquire().await;
            let attempt = limiter.try_acquire();
            assert!(attempt.is_none());
            drop(p1);
            let p3 = limiter.try_acquire();
            assert!(p3.is_some());
            drop(p2);
            drop(p3);
        });
    }

    #[test]
    fn rate_limiter_one_per_window() {
        let limiter = RateLimiter::new(1, 1);
        assert!(limiter.allow());
        assert!(!limiter.allow());
    }

    #[test]
    fn backoff_base_zero() {
        let d = backoff_delay(0, 0);
        assert_eq!(d.as_millis(), 0);
    }

    #[test]
    fn backoff_exponential_growth() {
        let d1 = backoff_delay(0, 100);
        let d2 = backoff_delay(1, 100);
        let d3 = backoff_delay(2, 100);
        let d4 = backoff_delay(3, 100);
        assert!(d1 < d2);
        assert!(d2 < d3);
        assert!(d3 < d4);
    }

    #[test]
    fn jitter_within_bounds() {
        let dur = Duration::from_millis(1000);
        let j = jitter(dur);
        assert!(j.as_millis() <= 1000);
    }

    #[test]
    fn jitter_zero_duration() {
        let j = jitter(Duration::from_millis(0));
        assert_eq!(j.as_millis(), 0);
    }

    #[test]
    fn semaphore_try_acquire_single() {
        let limiter = SemaphoreLimiter::new(1);
        let p1 = limiter.try_acquire();
        assert!(p1.is_some());
        let p2 = limiter.try_acquire();
        assert!(p2.is_none());
        drop(p1);
        let p3 = limiter.try_acquire();
        assert!(p3.is_some());
    }

    #[test]
    fn rate_limiter_new_struct() {
        let limiter = RateLimiter::new(10, 30);
        for _ in 0..10 {
            assert!(limiter.allow());
        }
        assert!(!limiter.allow());
    }
}
