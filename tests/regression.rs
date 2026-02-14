use dnscache::config::Config;
use dnscache::server::DnsCacheServer;
use std::time::Duration;

#[test]
fn regression_case_001_no_panic() {
    // This input previously triggered a panic during fuzzing.
    // It must never crash again.

    let data: &[u8] = &[
        0x12, 0x34, // TXID
        0x01, 0x00, // flags
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // QNAME: a.com
        0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
        // Answer (malformed on purpose)
        0xC0, 0x0C, // pointer to name
        0x00, 0x01, // TYPE A
        0x00, 0x01, // CLASS IN
        0x00, 0x00, 0x00, 0x3C, // TTL
        0x00, 0x04, // RDLEN
        0x7F, 0x00, 0x00, // ← truncated (missing 1 byte)
    ];

    let cfg = Config::default();
    let server = DnsCacheServer::new(&cfg).with_timeouts(Duration::from_millis(10), 300);

    // The test passes if this does NOT panic.
    let _ = server.process_dns_query(data);
}
