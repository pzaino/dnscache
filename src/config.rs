use serde::Deserialize;
use std::env;
use std::fs;
use std::time::Duration;

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    pub bind: Option<String>,
    pub upstreams: Option<Vec<String>>,
    pub threads: Option<usize>,
    pub upstream_timeout_secs: Option<u64>,
    pub max_cache_ttl_secs: Option<u32>,
    pub cleanup_interval_secs: Option<u64>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&content)?;
        Ok(cfg)
    }

    fn env_string(key: &str) -> Option<String> {
        env::var(key).ok().filter(|v| !v.is_empty())
    }

    fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
        env::var(key).ok()?.parse::<T>().ok()
    }

    pub fn bind_addr(&self) -> String {
        self.bind
            .clone()
            .or_else(|| Self::env_string("DNS_BIND"))
            .unwrap_or_else(|| "127.0.0.1:5353".to_string())
    }

    /// Returns the primary upstream resolver. If no upstreams are configured, returns a default of Google's public DNS.
    pub fn primary_upstream(&self) -> String {
        self.upstreams
            .as_ref()
            .and_then(|u| u.get(0).cloned())
            .or_else(|| Self::env_string("DNS_UPSTREAM"))
            .unwrap_or_else(|| "8.8.8.8:53".to_string())
    }

    /// Returns the list of upstreams, with the primary one first. If no upstreams are configured, returns a default list with Google's public DNS.
    pub fn upstreams(&self) -> Vec<String> {
        self.upstreams
            .clone()
            .or_else(|| Self::env_string("DNS_UPSTREAM").map(|u| vec![u]))
            .unwrap_or_else(|| vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()])
    }

    pub fn threads(&self) -> usize {
        let configured = self
            .threads
            .or_else(|| Self::env_parse("DNS_THREADS"))
            .unwrap_or_else(num_cpus::get);

        // Safety: prevent 0 threads
        if configured == 0 { 1 } else { configured }
    }

    pub fn upstream_timeout(&self) -> Duration {
        let secs = self
            .upstream_timeout_secs
            .or_else(|| Self::env_parse("DNS_UPSTREAM_TIMEOUT"))
            .unwrap_or(3);

        Duration::from_secs(secs)
    }

    pub fn max_cache_ttl(&self) -> u32 {
        self.max_cache_ttl_secs
            .or_else(|| Self::env_parse("DNS_MAX_CACHE_TTL"))
            .unwrap_or(86400)
    }

    pub fn cleanup_interval(&self) -> Duration {
        let secs = self
            .cleanup_interval_secs
            .or_else(|| Self::env_parse("DNS_CLEANUP_INTERVAL"))
            .unwrap_or(30); // default 30 seconds

        Duration::from_secs(secs)
    }
}
