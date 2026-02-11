use dashmap::DashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::dns;

pub const MAX_PACKET_SIZE: usize = 512;
pub const DEFAULT_TTL_SECS: u32 = 300;
pub const MAX_CACHE_TTL_SECS: u32 = 86400;

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires: Instant,
}

struct InFlight {
    done: Mutex<bool>,
    cvar: Condvar,
}

pub struct DnsCacheServer {
    cache: DashMap<Vec<u8>, CacheEntry>,
    inflight: DashMap<Vec<u8>, Arc<InFlight>>,
    upstream: String,
    upstream_timeout: Duration,
    max_cache_ttl: u32,
}

impl DnsCacheServer {
    pub fn new(upstream: String) -> Self {
        Self {
            cache: DashMap::new(),
            inflight: DashMap::new(),
            upstream,
            upstream_timeout: Duration::from_secs(3),
            max_cache_ttl: MAX_CACHE_TTL_SECS,
        }
    }

    /// Allow tests (or production) to tune timeouts and caps.
    #[allow(dead_code)]
    pub fn with_timeouts(mut self, upstream_timeout: Duration, max_cache_ttl: u32) -> Self {
        self.upstream_timeout = upstream_timeout;
        self.max_cache_ttl = max_cache_ttl;
        self
    }

    /// Main handler for a single UDP request.
    /// This is what we test. No copied logic.
    pub fn handle_request(&self, listen_socket: &UdpSocket, request: &[u8], src: SocketAddr) {
        if request.len() < dns::DNS_HEADER_LEN {
            return;
        }

        let txid = [request[0], request[1]];
        let key = match dns::cache_key_from_request(request) {
            Some(k) => k,
            None => return,
        };

        let now = Instant::now();

        // Fast path: cache hit
        if let Some(entry) = self.cache.get(&key) {
            if now < entry.expires {
                let mut resp = entry.response.clone();
                dns::set_txid(&mut resp, txid);
                let _ = listen_socket.send_to(&resp, src);
                return;
            }
        }

        // In-flight dedup
        let inflight_entry = self
            .inflight
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(InFlight {
                    done: Mutex::new(false),
                    cvar: Condvar::new(),
                })
            })
            .clone();

        // Leader does upstream query, followers wait
        let leader = Arc::ptr_eq(
            &inflight_entry,
            self.inflight
                .get(&key)
                .map(|v| v.clone())
                .as_ref()
                .unwrap_or(&inflight_entry),
        );

        if leader {
            // Do upstream work outside any locks
            if let Ok(response) = self.forward_to_upstream(request) {
                let ttl = dns::extract_min_ttl(&response)
                    .unwrap_or(DEFAULT_TTL_SECS)
                    .min(self.max_cache_ttl);

                self.cache.insert(key.clone(), CacheEntry {
                    response: response.clone(),
                    expires: Instant::now() + Duration::from_secs(ttl as u64),
                });

                let mut resp = response;
                dns::set_txid(&mut resp, txid);
                let _ = listen_socket.send_to(&resp, src);
            }

            // Wake followers
            {
                let mut done = inflight_entry.done.lock().unwrap();
                *done = true;
                inflight_entry.cvar.notify_all();
            }
            self.inflight.remove(&key);
        } else {
            // Follower: wait for leader
            let mut done = inflight_entry.done.lock().unwrap();
            while !*done {
                done = inflight_entry.cvar.wait(done).unwrap();
            }

            if let Some(entry) = self.cache.get(&key) {
                let mut resp = entry.response.clone();
                dns::set_txid(&mut resp, txid);
                let _ = listen_socket.send_to(&resp, src);
            }
        }
    }

    /// Real upstream forwarding used by production.
    /// Tests will exercise it by pointing upstream to a mock UDP DNS server.
    pub fn forward_to_upstream(&self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(self.upstream_timeout))?;
        sock.send_to(request, &self.upstream)?;

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (size, _) = sock.recv_from(&mut buf)?;
        Ok(buf[..size].to_vec())
    }
}
