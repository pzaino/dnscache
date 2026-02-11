use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;

use dnscache::server::DnsCacheServer;

fn main() -> std::io::Result<()> {
    let upstream = std::env::var("DNS_UPSTREAM").unwrap_or_else(|_| "8.8.8.8:53".to_string());

    // On macOS for dev: bind to 127.0.0.1:5353, since 53 is usually owned by mDNSResponder.
    let bind_addr = std::env::var("DNS_BIND").unwrap_or_else(|_| "0.0.0.0:53".to_string());

    let socket = Arc::new(UdpSocket::bind(&bind_addr)?);
    let srv = Arc::new(DnsCacheServer::new(upstream));

    let threads = num_cpus::get().max(1);

    for _ in 0..threads {
        let sock = socket.clone();
        let srv = srv.clone();

        thread::spawn(move || {
            let mut buf = [0u8; dnscache::server::MAX_PACKET_SIZE];
            loop {
                let (size, src) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                srv.handle_request(&sock, &buf[..size], src);
            }
        });
    }

    loop {
        thread::park();
    }
}
