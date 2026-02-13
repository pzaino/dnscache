# Security Policy

## Reporting a Vulnerability

We take the security of our project seriously and appreciate your efforts to responsibly disclose vulnerabilities. If you believe you have found a security vulnerability in the **DNSCache** project, please report it by following the steps below.

### What Constitutes a Vulnerability

A security vulnerability in **DNSCache** is any flaw that could allow an attacker to compromise the integrity, availability, or confidentiality of DNS resolution, cached data, or the host system.

This includes, but is not limited to:

#### DNS Protocol & Resolution Integrity

- Cache poisoning or injection of forged DNS records
- Acceptance of spoofed responses (e.g., mismatched transaction IDs, source ports, or query names)
- Failure to validate response authenticity when DNSSEC validation is enabled
- Improper handling of TTL values leading to stale or malicious cache persistence
- Incorrect CNAME/DNAME resolution that could redirect queries to attacker-controlled domains

#### Network & Input Handling

- Malformed DNS packet parsing that causes panics, crashes, or undefined behaviour
- Integer overflows or truncation during packet parsing or size calculations
- Improper bounds checking when processing DNS labels or resource records
- Acceptance of oversized or fragmented packets that can trigger resource exhaustion

#### Availability & Resource Exhaustion

- Denial of Service (DoS) via crafted queries causing excessive CPU, memory, or file descriptor usage
- Cache flooding attacks that exhaust memory or degrade lookup performance
- Unbounded growth of internal data structures
- Deadlocks or starvation caused by concurrency issues

#### Concurrency & Memory Safety

- Race conditions leading to cache corruption or inconsistent responses
- Unsafe use of `unsafe` Rust blocks that could lead to memory unsafety
- Data races across threads affecting cache integrity or resolver state
- Improper synchronization leading to stale or inconsistent records

#### System & Privilege Boundaries

- Running with elevated privileges when not required
- Improper handling of local configuration files leading to privilege escalation
- Insecure interaction with the operating system (e.g., unsafe FFI, improper file permissions)

#### Cryptography & DNSSEC (if applicable)

- Use of weak or deprecated cryptographic algorithms
- Incorrect DNSSEC validation logic
- Acceptance of invalid signatures or trust chains

#### Configuration & Operational Security

- Insecure default configurations that expose the resolver to external networks unintentionally
- Failure to restrict recursion or query sources when configured for local-only use
- Logging of sensitive information that may expose internal network details

### How to Report

Please report vulnerabilities by opening a private issue on our GitHub repository:

1. **GitHub Issue Tracker:** Open a private issue [using the link here](https://github.com/pzaino/thecrowler/issues). Make sure the issue is marked as confidential and contains detailed information about the vulnerability and steps to reproduce it.

### Coordinated Vulnerability Disclosure Guidelines

- **Initial Acknowledgment:** We will acknowledge receipt of your report within 2 business days.
- **Assessment:** We will assess the vulnerability and determine its impact. This process may take up to 5 business days.
- **Mitigation:** If the vulnerability is confirmed, we will work on a mitigation plan and provide an estimated timeline for the fix. This typically takes between 15 and 30 days.
- **Disclosure:** We will notify you when the vulnerability is fixed and coordinate a public disclosure, ensuring you receive credit for the discovery if you wish.

## Security Contacts

- **GitHub Issue Tracker:** [Report an issue](https://github.com/pzaino/dnscache/issues)

## Supported Versions

Use this section to verify if the version of **DNSCache** you are using is currently supported and eligible for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.y   | :white_check_mark: |
| 0.x.y   | :x:                |
