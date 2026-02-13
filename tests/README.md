# Tests

This directory contains system, fuzz, performance and integration tests for the project. 

## Running integration tests

To run the integration tests, you can use the following command:

```bash
cargo test --test integration_tests
```

This will execute the tests defined in the `integration_tests.rs` file. Make sure you have the necessary environment set up for the tests to run successfully.

## Running performance tests

To run the performance tests, you can use the following command:

```bash
./tests/system_test.sh
```

or

```bash
dnsperf -s 127.0.0.1 -p 53 -d ./tests/queries.txt -l 30 -Q 20000
```

This will execute the performance tests defined in the `system_tests.sh` script or using the `dnsperf` tool. Make sure you have the necessary environment set up for the tests to run successfully.

## Running fuzz tests

To run the fuzz tests, you can use the following command:

```bash
./tests/fuzz_tests.sh
```
