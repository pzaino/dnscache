#!/bin/bash

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_handle -- -max_total_time=300

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_cache_key -- -max_total_time=300
