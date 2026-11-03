//! The dnsproxyd protocol as libnetd_client.so speaks it.
//!
//! Requests: one NUL-terminated line.
//! - `getaddrinfo <host> <service> <flags> <family> <socktype> <protocol> <netid>`, `^` for
//!   a missing host or service (bionic libc/dns/net/getaddrinfo.c).
//! - `gethostbyname <netid> <host> <family>` (bionic libc/dns/net/gethnamaddr.c; toybox
//!   ping uses it).
//!
//! Reply (packages/modules/DnsResolver/DnsProxyListener.cpp): a three-digit code as four
//! bytes ("222\0"), then per address a big-endian 1, flags, family, socktype, protocol,
//! address length, the sockaddr, the canonical name length (with its NUL) and the name;
//! a big-endian 0 ends the list. For gethostbyname a serialized hostent instead:
//! name, aliases, address type, address length, addresses, each list ended by a 0 (see
//! android_read_hostent). On failure: "401\0", a big-endian length 4 and the error code.

use std::net::IpAddr;

/// `DnsProxyQueryResult`.
const CODE_OK: &[u8; 4] = b"222\0";
/// `DnsProxyOperationFailed`.
const CODE_FAILED: &[u8; 4] = b"401\0";

/// getaddrinfo() error codes (bionic netdb.h).
pub const EAI_FAIL: i32 = 4;
pub const EAI_NODATA: i32 = 7;
pub const EAI_SERVICE: i32 = 9;

pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// A parsed client request.
#[derive(Debug, PartialEq)]
pub enum Request {
    GetAddrInfo(Query),
    GetHostByName { host: String, family: i32 },
}

/// The arguments of one getaddrinfo() call.
#[derive(Debug, PartialEq)]
pub struct Query {
    pub host: String,
    pub service: Option<String>,
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
}

/// One addrinfo entry of a reply.
#[derive(Debug, PartialEq)]
pub struct Entry {
    pub addr: IpAddr,
    pub port: u16,
    pub socktype: i32,
    pub protocol: i32,
}

impl Request {
    pub fn parse(line: &str) -> Option<Request> {
        let args: Vec<&str> = line.split_whitespace().collect();
        match args.as_slice() {
            ["getaddrinfo", host, service, _flags, family, socktype, protocol, _netid] => {
                // A NULL host never reaches the proxy: bionic answers it itself.
                let number = |s: &str| s.parse::<i32>().ok().filter(|n| *n >= 0).unwrap_or(0);
                Some(Request::GetAddrInfo(Query {
                    host: host.to_string(),
                    service: (*service != "^").then(|| service.to_string()),
                    family: number(family),
                    socktype: number(socktype),
                    protocol: number(protocol),
                }))
            }
            ["gethostbyname", _netid, host, family] => Some(Request::GetHostByName {
                host: host.to_string(),
                family: family.parse().unwrap_or(AF_INET),
            }),
            _ => None,
        }
    }
}

/// The port of a service: a number, or one of the few names worth knowing on this
/// device (there is no /etc/services).
pub fn port(service: Option<&str>) -> Result<u16, i32> {
    match service {
        None => Ok(0),
        Some(s) => s.parse().or(match s {
            "domain" => Ok(53),
            "http" => Ok(80),
            "ntp" => Ok(123),
            "https" => Ok(443),
            _ => Err(EAI_SERVICE),
        }),
    }
}

/// The (socktype, protocol) pairs to return, as getaddrinfo() does for a hint of 0.
pub fn socket_kinds(socktype: i32, protocol: i32) -> Vec<(i32, i32)> {
    match (socktype, protocol) {
        (0, 0) => vec![(SOCK_STREAM, IPPROTO_TCP), (SOCK_DGRAM, IPPROTO_UDP)],
        (0, IPPROTO_TCP) | (SOCK_STREAM, 0) => vec![(SOCK_STREAM, IPPROTO_TCP)],
        (0, IPPROTO_UDP) | (SOCK_DGRAM, 0) => vec![(SOCK_DGRAM, IPPROTO_UDP)],
        (socktype, protocol) => vec![(socktype, protocol)],
    }
}

fn be32(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// struct sockaddr_in / sockaddr_in6: family in host order, port big-endian.
fn sockaddr(addr: &IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    match addr {
        IpAddr::V4(v4) => {
            out.extend_from_slice(&(AF_INET as u16).to_ne_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&v4.octets());
            out.extend_from_slice(&[0; 8]);
        }
        IpAddr::V6(v6) => {
            out.extend_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&[0; 4]); // flowinfo
            out.extend_from_slice(&v6.octets());
            out.extend_from_slice(&[0; 4]); // scope id
        }
    }
    out
}

pub fn addrinfo_reply(entries: &[Entry]) -> Vec<u8> {
    let mut out = CODE_OK.to_vec();
    for entry in entries {
        let addr = sockaddr(&entry.addr, entry.port);
        be32(&mut out, 1);
        be32(&mut out, 0); // ai_flags
        be32(&mut out, if entry.addr.is_ipv4() { AF_INET } else { AF_INET6 });
        be32(&mut out, entry.socktype);
        be32(&mut out, entry.protocol);
        be32(&mut out, addr.len() as i32);
        out.extend_from_slice(&addr);
        be32(&mut out, 0); // no canonical name
    }
    be32(&mut out, 0);
    out
}

/// A string as android_read_hostent reads it: length with the NUL, then the bytes.
fn string(out: &mut Vec<u8>, s: &str) {
    be32(out, s.len() as i32 + 1);
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}

/// A hostent with `addrs`, all of `family`.
pub fn hostent_reply(name: &str, family: i32, addrs: &[IpAddr]) -> Vec<u8> {
    let mut out = CODE_OK.to_vec();
    string(&mut out, name);
    be32(&mut out, 0); // no aliases
    be32(&mut out, family);
    be32(&mut out, if family == AF_INET6 { 16 } else { 4 });
    for addr in addrs {
        let bytes = match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        be32(&mut out, bytes.len() as i32);
        out.extend_from_slice(&bytes);
    }
    be32(&mut out, 0);
    out
}

pub fn error_reply(code: i32) -> Vec<u8> {
    let mut out = CODE_FAILED.to_vec();
    be32(&mut out, 4);
    out.extend_from_slice(&code.to_ne_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_bionic_request() {
        let req = Request::parse("getaddrinfo api.open-meteo.com ^ 1024 0 1 0 0");
        assert_eq!(
            req,
            Some(Request::GetAddrInfo(Query {
                host: "api.open-meteo.com".into(),
                service: None,
                family: AF_UNSPEC,
                socktype: SOCK_STREAM,
                protocol: 0,
            }))
        );
        assert_eq!(
            Request::parse("gethostbyname 0 example.com 2"),
            Some(Request::GetHostByName { host: "example.com".into(), family: AF_INET })
        );
        assert_eq!(Request::parse("resnsend 0 0 AAAA"), None);
    }

    #[test]
    fn encodes_ipv4_entry() {
        let entry = Entry {
            addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 443,
            socktype: SOCK_STREAM,
            protocol: IPPROTO_TCP,
        };
        let reply = addrinfo_reply(&[entry]);
        assert_eq!(&reply[..4], b"222\0");
        // more=1, flags, family, socktype, protocol, addrlen=16
        assert_eq!(&reply[4..28], &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0, 16]);
        assert_eq!(&reply[30..36], &[1, 187, 1, 2, 3, 4]); // port 443, address
        assert_eq!(&reply[reply.len() - 8..], &[0; 8]); // no name, end of list
        assert_eq!(reply.len(), 4 + 24 + 16 + 4 + 4);
    }

    #[test]
    fn encodes_hostent() {
        let reply = hostent_reply("a.b", AF_INET, &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        let mut expected = b"222\0".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 4, b'a', b'.', b'b', 0]); // name
        expected.extend_from_slice(&[0, 0, 0, 0]); // aliases
        expected.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 4]); // AF_INET, length 4
        expected.extend_from_slice(&[0, 0, 0, 4, 1, 2, 3, 4, 0, 0, 0, 0]); // addresses
        assert_eq!(reply, expected);
    }

    #[test]
    fn services_and_kinds() {
        assert_eq!(port(Some("https")), Ok(443));
        assert_eq!(port(Some("8080")), Ok(8080));
        assert_eq!(port(Some("gopher")), Err(EAI_SERVICE));
        assert_eq!(socket_kinds(0, 0).len(), 2);
        assert_eq!(socket_kinds(SOCK_STREAM, 0), vec![(SOCK_STREAM, IPPROTO_TCP)]);
    }
}
