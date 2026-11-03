//! DNS messages on the wire (RFC 1035): one question out, the addresses of the answer in.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;

/// The useful part of an answer.
#[derive(Debug, PartialEq)]
pub enum Answer {
    /// The addresses of the asked type and the smallest TTL among them, in seconds.
    Addresses(Vec<IpAddr>, u32),
    /// The name does not exist.
    NoSuchName,
}

/// A query for `host`, recursion desired.
pub fn query(id: u16, host: &str, qtype: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(18 + host.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    msg.get(pos..pos + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(msg: &[u8], pos: usize) -> Option<u32> {
    msg.get(pos..pos + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// The position after the (possibly compressed) name at `pos`.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        match *msg.get(pos)? {
            0 => return Some(pos + 1),
            len if len & 0xC0 == 0xC0 => return Some(pos + 2),
            len => pos += 1 + len as usize,
        }
    }
}

/// Parses the reply to the query with `id`; None for a malformed or foreign message.
/// CNAME records are skipped: the server puts the target's addresses in the same answer.
pub fn parse(id: u16, qtype: u16, msg: &[u8]) -> Option<Answer> {
    if u16_at(msg, 0)? != id {
        return None;
    }
    let rcode = u16_at(msg, 2)? & 0x000F;
    if rcode == RCODE_NXDOMAIN {
        return Some(Answer::NoSuchName);
    }
    if rcode != 0 {
        return None;
    }
    let mut pos = 12;
    for _ in 0..u16_at(msg, 4)? {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut addrs = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..u16_at(msg, 6)? {
        pos = skip_name(msg, pos)?;
        let rtype = u16_at(msg, pos)?;
        let rttl = u32_at(msg, pos + 4)?;
        let rdlen = u16_at(msg, pos + 8)? as usize;
        pos += 10;
        let data = msg.get(pos..pos + rdlen)?;
        let addr = match (rtype, qtype, rdlen) {
            (TYPE_A, TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (TYPE_AAAA, TYPE_AAAA, 16) => {
                Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)))
            }
            _ => None,
        };
        if let Some(addr) = addr {
            addrs.push(addr);
            ttl = ttl.min(rttl);
        }
        pos += rdlen;
    }
    Some(Answer::Addresses(addrs, if ttl == u32::MAX { 0 } else { ttl }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_layout() {
        let q = query(0x1234, "a.bc", TYPE_A);
        assert_eq!(q, [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
    }

    #[test]
    fn answer_with_cname() {
        let mut msg = query(7, "a.bc", TYPE_A);
        msg[2] = 0x81; // response
        msg[3] = 0x80;
        msg[7] = 2; // two answers
        // CNAME a.bc -> x.bc (pointer to the question name for the owner)
        msg.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'x', 0xC0, 14]);
        // A x.bc 1.2.3.4, TTL 30
        msg.extend_from_slice(&[0xC0, 34, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse(7, TYPE_A, &msg),
            Some(Answer::Addresses(vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))], 30))
        );
        assert_eq!(parse(8, TYPE_A, &msg), None);
    }

    #[test]
    fn nxdomain() {
        let mut msg = query(9, "nope.example", TYPE_A);
        msg[2] = 0x81;
        msg[3] = 0x83;
        assert_eq!(parse(9, TYPE_A, &msg), Some(Answer::NoSuchName));
    }
}
