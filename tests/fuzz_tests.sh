#!/bin/bash

RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300

RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run fuzz_handle -- -max_total_time=300

RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run fuzz_combined_parsing -- -max_total_time=300
