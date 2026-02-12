use dashmap::DashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;

use std::net::IpAddr;

use crate::config::Config;
use crate::dns;

pub const MAX_PACKET_SIZE: usize = 4096;
pub const DEFAULT_TTL_SECS: u32 = 300;
pub const MAX_CACHE_TTL_SECS: u32 = 86400;

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone)]
struct RateLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
    capacity: f64,
    refill_rate: f64, // tokens per second
}

#[derive(Clone)]
struct CacheEntry {
    response: Vec<u8>,
    stored_at: Instant,
    original_ttl: u32,
    expires_at: Instant,
}

struct InFlight {
    done: Mutex<bool>,
    cvar: Condvar,
}

pub struct DnsCacheServer {
    cache: DashMap<Vec<u8>, CacheEntry>,
    inflight: DashMap<Vec<u8>, Arc<InFlight>>,
    upstreams: Vec<String>,
    upstream_timeout: Duration,
    max_cache_ttl: u32,

    max_cache_entries: usize,
    evict_queue: Mutex<VecDeque<Vec<u8>>>,
    shutdown: AtomicBool,

    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub upstream_queries: AtomicU64,

    rate_limiter: RateLimiter,
}

impl DnsCacheServer {
    /// Create a new server instance with the given upstream. In production, this is called once at startup.
    pub fn new(cfg: &Config) -> Self {
        let max = cfg.max_requests() as f64;
        let window_secs = cfg.rate_limit_window().as_secs_f64();

        Self {
            cache: DashMap::new(),
            inflight: DashMap::new(),
            upstreams: cfg.upstreams(),
            upstream_timeout: cfg.upstream_timeout(),
            max_cache_ttl: cfg.max_cache_ttl(),

            max_cache_entries: cfg.max_cache_entries(),
            evict_queue: Mutex::new(VecDeque::new()),
            shutdown: AtomicBool::new(false),

            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),

            rate_limiter: RateLimiter {
                buckets: DashMap::new(),
                capacity: max,
                refill_rate: max / window_secs,
            },
        }
    }

    /// Periodically clean expired cache entries. In production, this runs in a background thread.
    pub fn start_cleanup_task(self: &Arc<Self>, interval: Duration) {
        let cache = self.cache.clone();
        let srv = self.clone();

        let buckets = self.rate_limiter.buckets.clone();

        thread::spawn(move || {
            loop {
                if srv.should_shutdown() {
                    break;
                }
                thread::sleep(interval);
                if srv.should_shutdown() {
                    break;
                }

                let now = Instant::now();

                let ttl = Duration::from_secs(300);

                buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < ttl);

                let mut removed = 0usize;

                let keys_to_remove: Vec<Vec<u8>> = cache
                    .iter()
                    .filter(|entry| entry.expires_at <= now)
                    .map(|entry| entry.key().clone())
                    .collect();

                for key in keys_to_remove {
                    cache.remove(&key);
                    removed += 1;
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
                if srv.should_shutdown() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(15));
                if srv.should_shutdown() {
                    break;
                }

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

        // Enforce exactly one question
        let qdcount = u16::from_be_bytes([request[4], request[5]]);
        if qdcount != 1 {
            let mut resp = self.synthesize_servfail(request);
            dns::set_txid(&mut resp, txid);
            return Some(resp);
        }

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
        let (inflight_entry, is_leader) = {
            let entry = self.inflight.entry(key.clone());

            match entry {
                dashmap::mapref::entry::Entry::Occupied(e) => (e.get().clone(), false),
                dashmap::mapref::entry::Entry::Vacant(v) => {
                    let new = Arc::new(InFlight {
                        done: Mutex::new(false),
                        cvar: Condvar::new(),
                    });
                    v.insert(new.clone());
                    (new, true)
                }
            }
        };

        if is_leader {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);

            let response = match self.forward_to_upstream(request) {
                Ok(r) => r,
                Err(_) => {
                    // Wake followers even on failure
                    {
                        let mut done = inflight_entry.done.lock().unwrap();
                        *done = true;
                        inflight_entry.cvar.notify_all();
                    }
                    self.inflight.remove(&key);

                    // Synthesize SERVFAIL
                    let mut resp = self.synthesize_servfail(request);
                    dns::set_txid(&mut resp, txid);
                    return Some(resp);
                }
            };

            let rcode = response[3] & 0x0F;
            let ancount = u16::from_be_bytes([response[6], response[7]]);

            // Do not cache SERVFAIL, REFUSED, FORMERR, etc.
            if rcode != 0 && rcode != 3 {
                let mut resp = response;
                dns::set_txid(&mut resp, txid);

                // Wake followers
                {
                    let mut done = inflight_entry.done.lock().unwrap();
                    *done = true;
                    inflight_entry.cvar.notify_all();
                }
                self.inflight.remove(&key);

                return Some(resp);
            }

            let ttl = if rcode == 3 {
                dns::extract_negative_ttl(&response).unwrap_or(60)
            } else if rcode == 0 && ancount == 0 {
                dns::extract_negative_ttl(&response).unwrap_or(60)
            } else {
                dns::extract_min_ttl(&response).unwrap_or(DEFAULT_TTL_SECS)
            }
            .min(self.max_cache_ttl);

            // Do not cache zero-TTL responses
            if ttl > 0 {
                let now = Instant::now();
                self.cache.insert(key.clone(), CacheEntry {
                    response: response.clone(),
                    stored_at: now,
                    original_ttl: ttl,
                    expires_at: now + Duration::from_secs(ttl as u64),
                });
                self.record_and_evict_if_needed(&key);
            }

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
            let (guard, timeout) = inflight_entry
                .cvar
                .wait_timeout(done, self.upstream_timeout)
                .unwrap();
            done = guard;
            if timeout.timed_out() {
                break;
            }
        }

        if let Some(entry) = self.cache.get(&key) {
            let mut resp = entry.response.clone();

            let now = Instant::now();
            let elapsed = now.duration_since(entry.stored_at).as_secs();
            let remaining = entry.original_ttl.saturating_sub(elapsed as u32);

            dns::rewrite_ttl(&mut resp, remaining);
            dns::set_txid(&mut resp, txid);

            return Some(resp);
        }

        // leader failed and did not cache
        let mut resp = self.synthesize_servfail(request);
        dns::set_txid(&mut resp, txid);
        return Some(resp);
    }

    /// Handles all UDP requests. In production, this is called from the main loop for each received packet.
    pub fn handle_udp_request(&self, listen_socket: &UdpSocket, request: &[u8], src: SocketAddr) {
        if !self.allow_request(src) {
            return; // silently drop
        }

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

            if !self.allow_request(
                stream
                    .peer_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
            ) {
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

    /// Simple rate limiter that allows up to `max_requests` per `window` duration for each client IP. This is called at the start of request processing, and if it returns false, the request should be dropped immediately without processing.
    fn allow_request(&self, addr: SocketAddr) -> bool {
        let ip = addr.ip();
        let now = Instant::now();

        let mut entry = self
            .rate_limiter
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket {
                tokens: self.rate_limiter.capacity,
                last_refill: now,
            });

        let elapsed = now
            .checked_duration_since(entry.last_refill)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        // Refill tokens
        let new_tokens = elapsed * self.rate_limiter.refill_rate;
        entry.tokens = (entry.tokens + new_tokens).min(self.rate_limiter.capacity);
        entry.last_refill = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn forward_to_upstream(&self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        for upstream in &self.upstreams {
            if let Ok(resp) = self.forward_single_upstream(request, upstream) {
                return Ok(resp);
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "All upstream resolvers failed",
        ))
    }

    /// Upstream forwarding (one server at the time).
    /// In tests, this can be mocked or called directly.
    pub fn forward_single_upstream(
        &self,
        request: &[u8],
        upstream: &String,
    ) -> std::io::Result<Vec<u8>> {
        // ---- First try UDP ----
        let udp_result = (|| -> std::io::Result<Vec<u8>> {
            let sock = UdpSocket::bind("0.0.0.0:0")?;
            sock.set_read_timeout(Some(self.upstream_timeout))?;
            sock.send_to(request, upstream)?;

            self.upstream_queries.fetch_add(1, Ordering::Relaxed);

            let mut buf = [0u8; MAX_PACKET_SIZE];
            let (size, _) = sock.recv_from(&mut buf)?;

            let response = buf[..size].to_vec();

            if response.len() < dns::DNS_HEADER_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Malformed upstream DNS response",
                ));
            }

            // Validate TXID matches
            if response.len() >= 2 {
                if response[0] != request[0] || response[1] != request[1] {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Upstream TXID mismatch",
                    ));
                }
            }

            self.validate_upstream_response(request, &response)?;
            Ok(response)
        })();

        match udp_result {
            Ok(response) => {
                // If not truncated, return immediately
                if response.len() >= 3 && (response[2] & 0x02) == 0 {
                    return Ok(response);
                }

                // TC bit set → retry over TCP
                self.upstream_queries.fetch_add(1, Ordering::Relaxed);
                return self.forward_via_tcp(request, upstream);
            }

            Err(_) => {
                // UDP failed (timeout or network error)
                // Retry once over TCP for resilience
                self.upstream_queries.fetch_add(1, Ordering::Relaxed);
                return self.forward_via_tcp(request, upstream);
            }
        }
    }

    fn forward_via_tcp(&self, request: &[u8], upstream: &String) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect(upstream)?;
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

        if msg_len == 0 || msg_len > MAX_PACKET_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid upstream TCP response length",
            ));
        }

        let mut tcp_buf = vec![0u8; msg_len];
        stream.read_exact(&mut tcp_buf)?;

        if tcp_buf.len() < dns::DNS_HEADER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed upstream TCP DNS response",
            ));
        }

        // Validate TXID matches
        if tcp_buf.len() >= 2 {
            if tcp_buf[0] != request[0] || tcp_buf[1] != request[1] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Upstream TCP TXID mismatch",
                ));
            }
        }

        self.validate_upstream_response(request, &tcp_buf)?;
        Ok(tcp_buf)
    }

    /// Synthesize a SERVFAIL response based on the request. This is used when upstream resolution fails, and we want to return a valid DNS response indicating failure instead of just dropping the packet.
    fn synthesize_servfail(&self, request: &[u8]) -> Vec<u8> {
        let mut resp = request.to_vec();

        if resp.len() < dns::DNS_HEADER_LEN {
            return resp;
        }

        // QR = 1 (response)
        resp[2] |= 0x80;

        // Preserve RD automatically (copied from request)

        // RA = 1 (recursion available)
        resp[3] |= 0x80;

        // Clear RCODE bits
        resp[3] &= 0xF0;

        // Set RCODE = 2 (SERVFAIL)
        resp[3] |= 0x02;

        // Zero ANCOUNT, NSCOUNT, ARCOUNT
        resp[6] = 0;
        resp[7] = 0;
        resp[8] = 0;
        resp[9] = 0;
        resp[10] = 0;
        resp[11] = 0;

        resp
    }

    fn record_and_evict_if_needed(&self, key: &Vec<u8>) {
        if self.max_cache_entries == 0 {
            return;
        }

        let mut q = self.evict_queue.lock().unwrap();
        q.push_back(key.clone());

        // Evict until size is under cap. (We may pop keys that were already removed.)
        while self.cache.len() > self.max_cache_entries {
            if let Some(old_key) = q.pop_front() {
                self.cache.remove(&old_key);
            } else {
                break;
            }
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn validate_upstream_response(&self, request: &[u8], response: &[u8]) -> std::io::Result<()> {
        if response.len() < dns::DNS_HEADER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream response too short",
            ));
        }

        // 1️ Validate QR bit (must be response)
        if response[2] & 0x80 == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream packet is not a DNS response (QR=0)",
            ));
        }

        // Validate OPCODE matches request
        if (response[2] & 0x78) != (request[2] & 0x78) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream OPCODE mismatch",
            ));
        }

        // Validate RD flag matches request
        if (response[2] & 0x01) != (request[2] & 0x01) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream RD flag mismatch",
            ));
        }

        // 2️ Validate Question Count (must match request)
        let req_qdcount = u16::from_be_bytes([request[4], request[5]]);
        let resp_qdcount = u16::from_be_bytes([response[4], response[5]]);

        if req_qdcount != resp_qdcount {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream QDCOUNT mismatch",
            ));
        }

        // 3️ Validate Question Section matches exactly
        let req_question_end = dns::find_question_end(request).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed request question section",
            )
        })?;

        let resp_question_end = dns::find_question_end(response).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Malformed upstream question section",
            )
        })?;

        if request[dns::DNS_HEADER_LEN..req_question_end]
            != response[dns::DNS_HEADER_LEN..resp_question_end]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Upstream question section mismatch",
            ));
        }

        self.validate_dns_sections(response)?;
        Ok(())
    }

    fn validate_dns_sections(&self, packet: &[u8]) -> std::io::Result<()> {
        if packet.len() < dns::DNS_HEADER_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Packet too short",
            ));
        }

        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        let ancount = u16::from_be_bytes([packet[6], packet[7]]);
        let nscount = u16::from_be_bytes([packet[8], packet[9]]);
        let arcount = u16::from_be_bytes([packet[10], packet[11]]);

        let mut offset = dns::DNS_HEADER_LEN;

        // ---- Walk Question Section ----
        for _ in 0..qdcount {
            offset = dns::skip_name(packet, offset).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid question name")
            })?;

            if offset + 4 > packet.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Question truncated",
                ));
            }

            offset += 4; // QTYPE + QCLASS
        }

        // ---- Walk Resource Records ----
        let total_rr = ancount as usize + nscount as usize + arcount as usize;

        for _ in 0..total_rr {
            offset = dns::skip_name(packet, offset).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid RR name")
            })?;

            if offset + 10 > packet.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "RR header truncated",
                ));
            }

            let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > packet.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "RR data truncated",
                ));
            }

            offset += rdlength;
        }

        if offset != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Extra trailing bytes in DNS packet",
            ));
        }

        Ok(())
    }
}
