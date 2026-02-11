pub const DNS_HEADER_LEN: usize = 12;

/// Replace transaction ID in a DNS response buffer.
pub fn set_txid(resp: &mut [u8], txid: [u8; 2]) {
    if resp.len() >= 2 {
        resp[0] = txid[0];
        resp[1] = txid[1];
    }
}

/// Creates a cache key for a request. For now: everything after the DNS header.
/// This matches what the original code did, but now it is explicit and testable.
pub fn cache_key_from_request(req: &[u8]) -> Option<Vec<u8>> {
    if req.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(req[DNS_HEADER_LEN..].to_vec())
}

/// Extract the minimum TTL from the answer section.
/// This is the real function used by the server, and it is what we will test.
pub fn extract_min_ttl(response: &[u8]) -> Option<u32> {
    if response.len() < DNS_HEADER_LEN {
        return None;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;

    // Skip QNAME in question section
    while pos < response.len() && response[pos] != 0 {
        let label_len = response[pos] as usize;
        pos = pos.checked_add(1 + label_len)?;
    }

    // Skip null terminator + QTYPE + QCLASS
    pos = pos.checked_add(1 + 2 + 2)?;

    let mut min_ttl = u32::MAX;

    for _ in 0..ancount {
        // NAME: pointer or labels
        if pos >= response.len() {
            return None;
        }

        if (response[pos] & 0xC0) == 0xC0 {
            pos = pos.checked_add(2)?;
        } else {
            while pos < response.len() && response[pos] != 0 {
                let label_len = response[pos] as usize;
                pos = pos.checked_add(1 + label_len)?;
            }
            pos = pos.checked_add(1)?;
        }

        // TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2)
        if pos + 10 > response.len() {
            return None;
        }

        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        min_ttl = min_ttl.min(ttl);

        let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        pos = pos.checked_add(10 + rdlen)?;
    }

    if min_ttl == u32::MAX {
        None
    } else {
        Some(min_ttl)
    }
}
