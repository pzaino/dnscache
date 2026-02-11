# Simple DNS Cache in Rust

This tool is a simple DNS Cache system that can be used when you have a lot of DNS queries and want to reduce the latency by caching the results. It is implemented in Rust for performance and safety.

## Features

- Caches DNS query results for a specified duration.
- Supports both IPv4 and IPv6 addresses.
- Provides a simple command-line interface for querying and managing the cache.
- Uses a HashMap to store the cached results with expiration times.
- Provides Cache auto clean up to remove expired entries.
- Provides stats to check the number of cached entries and cache hit/miss ratio.

## Usage

1. Clone the repository and navigate to the project directory:

```bash
git clone https://github.com/pzaino/dnscache
cd dnscache
```

2. Build the project using Cargo:

```bash
cargo build --release
```

3. Edit the configuration file `dnscache.toml` to set the cache duration and other parameters:

```toml
bind = "127.0.0.1:6363"
upstream = "8.8.8.8:53"
threads = 20
upstream_timeout_secs = 2
max_cache_ttl_secs = 3600
cleanup_interval_secs = 120
```

4. Run the DNS Cache server:

```bash
./target/release/dnscache
```

5. You can query the DNS Cache using `dig` or any DNS client:

```bash
dig @localhost -p 6363 example.com
```

## License

This project is copyright (c) 2026 by Paolo Zaino, all rights reserved. It is licensed under the MPL 2.0 License. See the [LICENSE](LICENSE) file for more details.

## Contributing

Contributions are welcome! If you have any ideas for improvements or want to report a bug, please open an issue or submit a pull request.
