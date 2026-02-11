#![no_main]

use libfuzzer_sys::fuzz_target;

use dnscache::dns::{cache_key_from_request, extract_min_ttl};

fuzz_target!(|data: &[u8]| {
    let _ = cache_key_from_request(data);
    let _ = extract_min_ttl(data);
});
