#![no_main]

use libfuzzer_sys::fuzz_target;

use dnscache::dns::extract_min_ttl;

fuzz_target!(|data: &[u8]| {
    // We do not care about output.
    // We only care that it never panics.
    let _ = extract_min_ttl(data);
});
