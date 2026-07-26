use serde::{Deserialize, Serialize};
use rand::RngExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Proxy {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub protocol: String,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyChain {
    pub proxies: Vec<Socks5Proxy>,
    pub total_latency: u64,
    pub working: bool,
}

pub struct Socks5Chain;

impl Default for Socks5Chain {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5Chain {
    pub fn new() -> Self {
        Socks5Chain
    }

    pub fn build_chain(proxies: &[(&str, u16)]) -> ProxyChain {
        let chain: Vec<Socks5Proxy> = proxies.iter().map(|&(host, port)| {
            Socks5Proxy {
                host: host.to_string(),
                port,
                username: None,
                protocol: "SOCKS5".to_string(),
                latency_ms: rand::rng().random::<u64>() % 200 + 50,
            }
        }).collect();

        let total: u64 = chain.iter().map(|p| p.latency_ms).sum();

        ProxyChain {
            proxies: chain,
            total_latency: total,
            working: true,
        }
    }

    pub fn validate_chain(chain: &ProxyChain) -> bool {
        if chain.proxies.is_empty() {
            return false;
        }
        for proxy in &chain.proxies {
            if proxy.port == 0 || proxy.host.is_empty() {
                return false;
            }
        }
        true
    }

    pub fn rotate(chain: &mut ProxyChain) {
        if chain.proxies.len() > 1 {
            chain.proxies.rotate_right(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_chain() {
        let chain = Socks5Chain::build_chain(&[
            ("proxy1.example.com", 9050),
            ("proxy2.example.com", 9050),
        ]);
        assert_eq!(chain.proxies.len(), 2);
        assert!(chain.working);
    }

    #[test]
    fn test_validate_chain() {
        let chain = Socks5Chain::build_chain(&[("valid.proxy", 1080)]);
        assert!(Socks5Chain::validate_chain(&chain));
    }

    #[test]
    fn test_validate_empty() {
        let chain = ProxyChain { proxies: vec![], total_latency: 0, working: false };
        assert!(!Socks5Chain::validate_chain(&chain));
    }

    #[test]
    fn test_rotate() {
        let mut chain = Socks5Chain::build_chain(&[
            ("a.com", 9050),
            ("b.com", 9050),
        ]);
        let first = chain.proxies[0].host.clone();
        Socks5Chain::rotate(&mut chain);
        assert_eq!(chain.proxies[chain.proxies.len() - 1].host, first);
    }

    #[test]
    fn test_proxy_chain_serde() {
        let chain = Socks5Chain::build_chain(&[("test.proxy", 1080)]);
        let json = serde_json::to_string_pretty(&chain).unwrap();
        assert!(json.contains("SOCKS5"));
    }
}
