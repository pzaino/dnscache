use dashmap::DashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::dns;

pub const MAX_PACKET_SIZE: usize = 4096;
pub const DEFAULT_TTL_SECS: u32 = 300;
pub const MAX_CACHE_TTL_SECS: u32 = 86400;

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    original_ttl: u32,
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
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub upstream_queries: AtomicU64,
}

impl DnsCacheServer {
    /// Create a new server instance with the given upstream. In production, this is called once at startup.
    pub fn new(upstream: String) -> Self {
        Self {
            cache: DashMap::new(),
            inflight: DashMap::new(),
            upstream,
            upstream_timeout: Duration::from_secs(3),
            max_cache_ttl: MAX_CACHE_TTL_SECS,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
        }
    }

    /// Periodically clean expired cache entries. In production, this runs in a background thread.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) {
        let cache = self.cache.clone();

        thread::spawn(move || {
            loop {
                thread::sleep(interval);

                let now = Instant::now();
                let mut removed = 0usize;

                for entry in cache.iter() {
                    //if now >= entry.expires {
                    let elapsed = now.duration_since(entry.stored_at).as_secs();
                    if elapsed >= entry.original_ttl as u64 {
                        cache.remove(entry.key());
                        removed += 1;
                    }
                }

                if removed > 0 {
                    println!("Cleanup removed {} expired entries", removed);
                }
            }
        });
    }

    /// Periodically print stats. In production, this could be a /metrics endpoint or similar.
    pub fn start_stats_task(self: &Arc<Self>) {
        let srv = self.clone();

        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(10));

                let hits = srv.cache_hits.load(Ordering::Relaxed);
                let misses = srv.cache_misses.load(Ordering::Relaxed);
                let upstream = srv.upstream_queries.load(Ordering::Relaxed);

                println!(
                    "Stats | hits: {} | misses: {} | upstream: {} | hit ratio: {:.2}%",
                    hits,
                    misses,
                    upstream,
                    if hits + misses > 0 {
                        (hits as f64 / (hits + misses) as f64) * 100.0
                    } else {
                        0.0
                    }
                );
            }
        });
    }

    /// Allow tests (or production) to tune timeouts and caps.
    #[allow(dead_code)]
    pub fn with_timeouts(mut self, upstream_timeout: Duration, max_cache_ttl: u32) -> Self {
        self.upstream_timeout = upstream_timeout;
        self.max_cache_ttl = max_cache_ttl;
        self
    }

    /// Core logic to process a DNS query. This is called by both UDP and TCP handlers, and can also be called directly in tests.
    pub fn process_dns_query(&self, request: &[u8]) -> Option<Vec<u8>> {
        if request.len() < dns::DNS_HEADER_LEN {
            return None;
        }

        let txid = [request[0], request[1]];
        let key = dns::cache_key_from_request(request)?;

        let now = Instant::now();

        // -------- Cache Fast Path --------
        if let Some(entry) = self.cache.get(&key) {
            let elapsed = now.duration_since(entry.stored_at).as_secs();

            if elapsed < entry.original_ttl as u64 {
                let mut resp = entry.response.clone();

                let remaining = entry.original_ttl.saturating_sub(elapsed as u32);

                dns::rewrite_ttl(&mut resp, remaining);
                dns::set_txid(&mut resp, txid);

                self.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Some(resp);
            }
        }

        // -------- In-flight Dedup --------
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

        let leader = Arc::ptr_eq(
            &inflight_entry,
            self.inflight
                .get(&key)
                .map(|v| v.clone())
                .as_ref()
                .unwrap_or(&inflight_entry),
        );

        if leader {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);

            let response = self.forward_to_upstream(request).ok()?;

            let rcode = response[3] & 0x0F;
            let ancount = u16::from_be_bytes([response[6], response[7]]);

            let ttl = if rcode == 3 {
                dns::extract_negative_ttl(&response).unwrap_or(60)
            } else if rcode == 0 && ancount == 0 {
                dns::extract_negative_ttl(&response).unwrap_or(60)
            } else {
                dns::extract_min_ttl(&response).unwrap_or(DEFAULT_TTL_SECS)
            }
            .min(self.max_cache_ttl);

            self.cache.insert(key.clone(), CacheEntry {
                response: response.clone(),
                stored_at: Instant::now(),
                original_ttl: ttl,
            });

            // Wake followers
            {
                let mut done = inflight_entry.done.lock().unwrap();
                *done = true;
                inflight_entry.cvar.notify_all();
            }
            self.inflight.remove(&key);

            let mut resp = response;
            dns::set_txid(&mut resp, txid);
            return Some(resp);
        }

        // -------- Follower Path --------
        let mut done = inflight_entry.done.lock().unwrap();
        while !*done {
            done = inflight_entry.cvar.wait(done).unwrap();
        }

        if let Some(entry) = self.cache.get(&key) {
            let mut resp = entry.response.clone();
            dns::set_txid(&mut resp, txid);
            return Some(resp);
        }

        None
    }

    /// Handles all UDP requests. In production, this is called from the main loop for each received packet.
    pub fn handle_udp_request(&self, listen_socket: &UdpSocket, request: &[u8], src: SocketAddr) {
        if let Some(response) = self.process_dns_query(request) {
            let _ = listen_socket.send_to(&response, src);
        }
    }

    /// Handles all TCP requests. In production, this is called from a thread pool worker for each accepted connection.
    /// Note: this does handle multiple queries per request, but it does not handle pipelining or interleaving. It processes queries sequentially until the client disconnects.
    pub fn handle_tcp_request(&self, mut stream: TcpStream) {
        stream.set_read_timeout(Some(self.upstream_timeout)).ok();
        stream.set_write_timeout(Some(self.upstream_timeout)).ok();

        loop {
            let mut len_buf = [0u8; 2];

            if stream.read_exact(&mut len_buf).is_err() {
                break;
            }

            let msg_len = u16::from_be_bytes(len_buf) as usize;

            if msg_len == 0 || msg_len > 4096 {
                break;
            }

            let mut buffer = vec![0u8; msg_len];

            if stream.read_exact(&mut buffer).is_err() {
                break;
            }

            if let Some(response) = self.process_dns_query(&buffer) {
                let resp_len = (response.len() as u16).to_be_bytes();

                if stream.write_all(&resp_len).is_err() {
                    break;
                }

                if stream.write_all(&response).is_err() {
                    break;
                }
            }
        }
    }

    /// Upstream forwarding used by production.
    /// In tests, this can be mocked or called directly.
    pub fn forward_to_upstream(&self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        // ---- First try UDP ----
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(self.upstream_timeout))?;
        sock.send_to(request, &self.upstream)?;

        self.upstream_queries.fetch_add(1, Ordering::Relaxed);

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (size, _) = sock.recv_from(&mut buf)?;
        let response = buf[..size].to_vec();

        // ---- If not truncated, return immediately ----
        if response.len() >= 3 && (response[2] & 0x02) == 0 {
            return Ok(response);
        }

        // ---- TC bit set → retry via TCP ----
        println!("Upstream response truncated, retrying over TCP");

        self.upstream_queries.fetch_add(1, Ordering::Relaxed);

        let mut stream = TcpStream::connect(&self.upstream)?;
        stream.set_read_timeout(Some(self.upstream_timeout))?;
        stream.set_write_timeout(Some(self.upstream_timeout))?;

        // Send length-prefixed DNS message
        let len = (request.len() as u16).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(request)?;

        // Read response length
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf)?;
        let msg_len = u16::from_be_bytes(len_buf) as usize;

        let mut tcp_buf = vec![0u8; msg_len];
        stream.read_exact(&mut tcp_buf)?;

        Ok(tcp_buf)
    }
}
