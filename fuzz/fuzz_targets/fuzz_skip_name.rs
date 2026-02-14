#![no_main]

use dnscache::dns::skip_name;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for offset in 0..data.len() {
        let _ = skip_name(data, offset);
    }
});
