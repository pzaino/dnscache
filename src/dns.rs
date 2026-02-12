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

/// Extract the negative TTL from the authority section's SOA record.
pub fn extract_negative_ttl(response: &[u8]) -> Option<u32> {
    if response.len() < 12 {
        return None;
    }

    let nscount = u16::from_be_bytes([response[8], response[9]]) as usize;
    if nscount == 0 {
        return None;
    }

    let mut pos = 12;

    // Skip question
    while pos < response.len() && response[pos] != 0 {
        let len = response[pos] as usize;
        pos += 1 + len;
    }
    pos += 1 + 2 + 2;

    for _ in 0..nscount {
        if pos >= response.len() {
            return None;
        }

        // Skip NAME
        if response[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < response.len() && response[pos] != 0 {
                let len = response[pos] as usize;
                pos += 1 + len;
            }
            pos += 1;
        }

        if pos + 10 > response.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let ttl = u32::from_be_bytes([
            response[pos + 4],
            response[pos + 5],
            response[pos + 6],
            response[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;

        pos += 10;

        if rr_type == 6 {
            // SOA record
            let mut rpos = pos;

            // Skip MNAME
            while rpos < response.len() && response[rpos] != 0 {
                let len = response[rpos] as usize;
                rpos += 1 + len;
            }
            rpos += 1;

            // Skip RNAME
            while rpos < response.len() && response[rpos] != 0 {
                let len = response[rpos] as usize;
                rpos += 1 + len;
            }
            rpos += 1;

            if rpos + 20 > response.len() {
                return None;
            }

            // Skip SERIAL(4), REFRESH(4), RETRY(4), EXPIRE(4)
            rpos += 16;

            // MINIMUM field
            let minimum = u32::from_be_bytes([
                response[rpos],
                response[rpos + 1],
                response[rpos + 2],
                response[rpos + 3],
            ]);

            return Some(minimum.min(ttl));
        }

        pos += rdlen;
    }

    None
}

/// Rewrite TTLs in all answer RRs to new_ttl.
pub fn rewrite_ttl(response: &mut [u8], new_ttl: u32) {
    if response.len() < 12 {
        return;
    }

    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
    if ancount == 0 {
        return;
    }

    let mut pos = 12;

    // Skip question
    while pos < response.len() && response[pos] != 0 {
        let len = response[pos] as usize;
        pos += 1 + len;
    }
    pos += 1 + 2 + 2;

    for _ in 0..ancount {
        if pos >= response.len() {
            return;
        }

        if response[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < response.len() && response[pos] != 0 {
                let len = response[pos] as usize;
                pos += 1 + len;
            }
            pos += 1;
        }

        if pos + 10 > response.len() {
            return;
        }

        // Overwrite TTL field
        response[pos + 4..pos + 8].copy_from_slice(&new_ttl.to_be_bytes());

        let rdlen = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;

        pos += 10 + rdlen;
    }
}

/// Finds the end offset of the question section in a DNS packet.
pub fn find_question_end(packet: &[u8]) -> Option<usize> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;

    // Walk QNAME labels
    loop {
        if pos >= packet.len() {
            return None;
        }

        let len = packet[pos] as usize;
        pos += 1;

        if len == 0 {
            break;
        }

        pos += len;

        if pos > packet.len() {
            return None;
        }
    }

    // QTYPE (2 bytes) + QCLASS (2 bytes)
    if pos + 4 > packet.len() {
        return None;
    }

    Some(pos + 4)
}

/// Skips a DNS name (labels + compression).
/// Returns the offset immediately after the name.
///
/// This does NOT expand the name. It only walks it safely.
///
/// RFC 1035 compression supported.
/// Safe against pointer loops and out-of-bounds.
pub fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    if offset >= packet.len() {
        return None;
    }

    let mut jumped = false;
    let mut jump_limit = 0;
    let mut original_offset = offset;

    loop {
        if offset >= packet.len() {
            return None;
        }

        let len = packet[offset];

        // Compression pointer: 11xxxxxx xxxxxxxx
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }

            let pointer = (((len & 0x3F) as usize) << 8) | packet[offset + 1] as usize;

            if pointer >= packet.len() {
                return None;
            }

            if jump_limit > 10 {
                // Prevent pointer loop abuse
                return None;
            }

            jump_limit += 1;

            offset = pointer;
            jumped = true;
            continue;
        }

        // End of name
        if len == 0 {
            if jumped {
                return Some(original_offset + 2);
            } else {
                return Some(offset + 1);
            }
        }

        // Normal label
        let label_len = len as usize;

        // Label length must be <= 63
        if label_len > 63 {
            return None;
        }

        offset += 1;

        if offset + label_len > packet.len() {
            return None;
        }

        offset += label_len;

        if !jumped {
            original_offset = offset;
        }
    }
}

// ---- Unit Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------
    // Helpers
    // -------------------------

    fn build_basic_query() -> Vec<u8> {
        let mut p = vec![
            0x12, 0x34, // TXID
            0x01, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        // example.com
        p.extend([
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);

        // QTYPE A, QCLASS IN
        p.extend([0x00, 0x01, 0x00, 0x01]);

        p
    }

    fn build_basic_response(ttl: u32) -> Vec<u8> {
        let mut q = build_basic_query();
        q[2] = 0x81;
        q[3] = 0x80;
        q[6] = 0x00;
        q[7] = 0x01; // ANCOUNT = 1

        // Answer
        q.extend([0xC0, 0x0C]); // pointer to question
        q.extend([0x00, 0x01, 0x00, 0x01]); // TYPE A, CLASS IN
        q.extend_from_slice(&ttl.to_be_bytes());
        q.extend([0x00, 0x04, 1, 2, 3, 4]);

        q
    }

    // -------------------------
    // set_txid
    // -------------------------

    #[test]
    fn test_set_txid() {
        let mut packet = vec![0, 0, 1, 2, 3];
        set_txid(&mut packet, [0xAA, 0xBB]);
        assert_eq!(packet[0], 0xAA);
        assert_eq!(packet[1], 0xBB);
    }

    // -------------------------
    // cache_key_from_request
    // -------------------------

    #[test]
    fn test_cache_key_from_request() {
        let q = build_basic_query();
        let key = cache_key_from_request(&q).unwrap();
        assert_eq!(key, q[DNS_HEADER_LEN..]);
    }

    #[test]
    fn test_cache_key_too_short() {
        assert!(cache_key_from_request(&[1, 2, 3]).is_none());
    }

    // -------------------------
    // extract_min_ttl
    // -------------------------

    #[test]
    fn test_extract_min_ttl_single_answer() {
        let resp = build_basic_response(123);
        assert_eq!(extract_min_ttl(&resp), Some(123));
    }

    #[test]
    fn test_extract_min_ttl_multiple_answers() {
        let mut resp = build_basic_response(300);

        // second answer with lower TTL
        resp.extend([0xC0, 0x0C]);
        resp.extend([0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&50u32.to_be_bytes());
        resp.extend([0x00, 0x04, 5, 6, 7, 8]);

        resp[7] = 0x02; // ANCOUNT = 2

        assert_eq!(extract_min_ttl(&resp), Some(50));
    }

    // -------------------------
    // rewrite_ttl
    // -------------------------

    #[test]
    fn test_rewrite_ttl() {
        let mut resp = build_basic_response(100);
        rewrite_ttl(&mut resp, 999);

        assert_eq!(extract_min_ttl(&resp), Some(999));
    }

    // -------------------------
    // find_question_end
    // -------------------------

    #[test]
    fn test_find_question_end() {
        let q = build_basic_query();
        let end = find_question_end(&q).unwrap();
        assert_eq!(end, q.len());
    }

    #[test]
    fn test_find_question_end_malformed() {
        let mut q = build_basic_query();
        q.pop(); // truncate
        assert!(find_question_end(&q).is_none());
    }

    // -------------------------
    // skip_name
    // -------------------------

    #[test]
    fn test_skip_name_plain() {
        let q = build_basic_query();
        let offset = DNS_HEADER_LEN;
        let end = skip_name(&q, offset).unwrap();

        // Should land on QTYPE
        assert_eq!(end, q.len() - 4);
    }

    #[test]
    fn test_skip_name_pointer() {
        let resp = build_basic_response(60);

        // answer name starts after question
        let q_end = find_question_end(&resp).unwrap();
        let name_offset = q_end;

        let end = skip_name(&resp, name_offset).unwrap();
        assert_eq!(end, name_offset + 2);
    }

    #[test]
    fn test_skip_name_invalid_label_length() {
        let mut packet = build_basic_query();
        packet[DNS_HEADER_LEN] = 70; // invalid label >63
        assert!(skip_name(&packet, DNS_HEADER_LEN).is_none());
    }

    #[test]
    fn test_skip_name_pointer_loop_protection() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0xC0;
        packet[1] = 0x00; // pointer to itself

        assert!(skip_name(&packet, 0).is_none());
    }

    // -------------------------
    // extract_negative_ttl
    // -------------------------

    #[test]
    fn test_extract_negative_ttl_soa() {
        let mut packet = build_basic_query();

        packet[8] = 0x00;
        packet[9] = 0x01; // NSCOUNT = 1

        // SOA record
        packet.extend([0xC0, 0x0C]); // NAME
        packet.extend([0x00, 0x06]); // TYPE = SOA
        packet.extend([0x00, 0x01]); // CLASS IN
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend([0x00, 0x16]); // RDLEN 22

        // MNAME
        packet.extend([0]);
        // RNAME
        packet.extend([0]);

        // SERIAL, REFRESH, RETRY, EXPIRE
        packet.extend([0, 0, 0, 1]);
        packet.extend([0, 0, 0, 2]);
        packet.extend([0, 0, 0, 3]);
        packet.extend([0, 0, 0, 4]);

        // MINIMUM
        packet.extend([0, 0, 0, 10]);

        assert_eq!(extract_negative_ttl(&packet), Some(10));
    }
}
