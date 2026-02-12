use dnscache::server::DnsCacheServer;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::Duration;

// Build a minimal DNS query for "example.com" A record.
// This is test data, not a copy of server logic.
fn build_query(txid: [u8; 2]) -> Vec<u8> {
    let mut p = vec![
        txid[0], txid[1], // TXID
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];

    // QNAME example.com
    p.extend([
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ]);

    // QTYPE A, QCLASS IN
    p.extend([0x00, 0x01, 0x00, 0x01]);
    p
}

// Minimal DNS response for same question, 1 answer, TTL param.
fn build_response_for_query(query: &[u8], ttl: u32) -> Vec<u8> {
    let txid0 = query[0];
    let txid1 = query[1];

    // Copy question section from query so the server key matches.
    let question = &query[12..];

    let mut p = vec![
        txid0, txid1, 0x81, 0x80, // response, no error
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    p.extend_from_slice(question);

    // Answer: NAME pointer to 0x0c
    p.extend([0xC0, 0x0C]);
    // TYPE A, CLASS IN
    p.extend([0x00, 0x01, 0x00, 0x01]);
    // TTL
    p.extend_from_slice(&ttl.to_be_bytes());
    // RDLEN and RDATA
    p.extend([0x00, 0x04, 1, 2, 3, 4]);

    p
}

fn start_mock_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = hits.clone();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => continue,
            };
            hits2.fetch_add(1, Ordering::SeqCst);

            let query = &buf[..n];
            let resp = build_response_for_query(query, 60);
            let _ = sock.send_to(&resp, src);
        }
    });

    (addr, hits)
}

#[test]
fn cache_hit_avoids_upstream() {
    let (upstream_addr, hits) = start_mock_upstream();

    let vec_upstreams = vec![upstream_addr.to_string()];

    let server = DnsCacheServer::new(vec_upstreams).with_timeouts(Duration::from_secs(1), 3600);

    let listen = UdpSocket::bind("127.0.0.1:0").unwrap();
    listen
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let listen_addr = listen.local_addr().unwrap();

    // Client socket
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();

    // Run server loop in background (single-thread is fine for this test)
    let server_arc = Arc::new(server);
    let listen_arc = Arc::new(listen);

    {
        let srv = server_arc.clone();
        let sock = listen_arc.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let (n, src) = sock.recv_from(&mut buf).unwrap();
                srv.handle_udp_request(&sock, &buf[..n], src);
            }
        });
    }

    // First query: miss, hits upstream
    let q1 = build_query([0x10, 0x01]);
    client.send_to(&q1, listen_addr).unwrap();

    let mut rbuf = [0u8; 512];
    let (rn, _) = client.recv_from(&mut rbuf).unwrap();
    assert!(rn > 0);

    // Second query: same question different txid, should hit cache
    let q2 = build_query([0x10, 0x02]);
    client.send_to(&q2, listen_addr).unwrap();

    let (rn2, _) = client.recv_from(&mut rbuf).unwrap();
    assert!(rn2 > 0);

    // Upstream should have been hit only once
    let count = hits.load(Ordering::SeqCst);
    assert_eq!(count, 1);
}

#[test]
fn inflight_dedup_under_concurrency() {
    let (upstream_addr, hits) = start_mock_upstream();

    let vec_upstreams = vec![upstream_addr.to_string()];

    let server =
        Arc::new(DnsCacheServer::new(vec_upstreams).with_timeouts(Duration::from_secs(1), 3600));

    let listen = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    listen
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let listen_addr = listen.local_addr().unwrap();

    // Background server thread that services packets
    {
        let srv = server.clone();
        let sock = listen.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            loop {
                let (n, src) = sock.recv_from(&mut buf).unwrap();
                srv.handle_udp_request(&sock, &buf[..n], src);
            }
        });
    }

    let threads = 20;
    let mut handles = Vec::new();

    for i in 0..threads {
        let addr = listen_addr;
        handles.push(thread::spawn(move || {
            let c = UdpSocket::bind("127.0.0.1:0").unwrap();
            c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

            let q = build_query([0x20, i as u8]);
            c.send_to(&q, addr).unwrap();

            let mut rbuf = [0u8; 512];
            let (rn, _) = c.recv_from(&mut rbuf).unwrap();
            assert!(rn > 0);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // All concurrent requests for same key should result in one upstream hit
    let count = hits.load(Ordering::SeqCst);
    assert_eq!(count, 1);
}
