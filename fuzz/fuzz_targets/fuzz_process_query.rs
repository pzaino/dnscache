#![no_main]

use dnscache::config::Config;
use dnscache::server::DnsCacheServer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cfg = Config::default();
    let server = DnsCacheServer::new(&cfg);

    let _ = server.process_dns_query(data);
});
