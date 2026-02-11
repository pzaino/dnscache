use dnscache::config::Config;
use dnscache::server::DnsCacheServer;

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;

fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "dnscache.toml".to_string());

    let config = Config::load(&config_path).unwrap_or_default();

    println!("Loaded config: {:?}", config);

    let socket = Arc::new(UdpSocket::bind(config.bind_addr())?);

    let server = Arc::new(
        DnsCacheServer::new(config.upstream())
            .with_timeouts(config.upstream_timeout(), config.max_cache_ttl()),
    );

    // Start cleanup thread
    server.start_cleanup_task(config.cleanup_interval());

    // Start stats thread
    server.start_stats_task();

    let threads = config.threads().max(1);

    println!("Starting dnscache with {} threads", threads);

    for _ in 0..threads {
        let sock = socket.clone();
        let srv = server.clone();

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
