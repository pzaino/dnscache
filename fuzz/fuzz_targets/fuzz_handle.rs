#![no_main]

use dnscache::dns::cache_key_from_request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = cache_key_from_request(data);
});
