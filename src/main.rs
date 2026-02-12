use dnscache::config::Config;
use dnscache::server::DnsCacheServer;

use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::thread;

fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dnscache.toml".to_string());

    let config = Config::load(&config_path).unwrap_or_default();

    println!("Loaded config: {:?}", config);

    // ---- Bind UDP ----
    let udp_socket = Arc::new(UdpSocket::bind(config.bind_addr())?);

    // ---- Bind TCP ----
    let tcp_listener = TcpListener::bind(config.bind_addr())?;

    let server = Arc::new(
        DnsCacheServer::new(config.upstream())
            .with_timeouts(config.upstream_timeout(), config.max_cache_ttl()),
    );

    server.start_cleanup_task(config.cleanup_interval());
    server.start_stats_task();

    let threads = config.threads().max(1);
    println!("Starting dnscache with {} UDP worker threads", threads);

    // ---- UDP Workers ----
    for _ in 0..threads {
        let sock = udp_socket.clone();
        let srv = server.clone();

        thread::spawn(move || {
            let mut buf = [0u8; dnscache::server::MAX_PACKET_SIZE];

            loop {
                let (size, src) = match sock.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                srv.handle_udp_request(&sock, &buf[..size], src);
            }
        });
    }

    // ---- TCP Accept Loop ----
    {
        let srv = server.clone();
        thread::spawn(move || {
            for stream in tcp_listener.incoming() {
                if let Ok(stream) = stream {
                    let srv_clone = srv.clone();

                    thread::spawn(move || {
                        srv_clone.handle_tcp_request(stream);
                    });
                }
            }
        });
    }

    // Keep main alive
    loop {
        thread::park();
    }
}
