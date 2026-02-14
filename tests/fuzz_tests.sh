#!/bin/bash

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300 -print_final_stats=1

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_handle -- -max_total_time=300 -print_final_stats=1

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_cache_key -- -max_total_time=300 -print_final_stats=1

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_process_query -- -max_total_time=300 -print_final_stats=1

RUSTFLAGS="-Zsanitizer=address -C opt-level=1 -C debuginfo=1" cargo +nightly fuzz run fuzz_skip_name -- -max_total_time=300 -print_final_stats=1
