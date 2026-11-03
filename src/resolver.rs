//! Resolution: /system/etc/hosts first, then the DNS servers of the current DHCP lease,
//! with a small cache.

use crate::protocol::{self, Entry, Query, AF_INET, AF_INET6, AF_UNSPEC, EAI_FAIL, EAI_NODATA};
use crate::wire::{self, Answer, TYPE_A, TYPE_AAAA};
use log::{info, warn};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HOSTS: &str = "/system/etc/hosts";
/// Written by the board's DHCP hook (`nameserver <ip>` lines). On the RB3 that is
/// device/rb3/sdv_media_db845c/net/net_dhcp_hook.sh.
const RESOLV_CONF: &str = "/data/vendor/net/resolv.conf";
const TIMEOUT: Duration = Duration::from_secs(2);
const ATTEMPTS: usize = 2;
/// Upper bound for cached answers, so a changed lease is picked up soon.
const MAX_TTL: Duration = Duration::from_secs(300);
/// Negative answers are cached briefly.
const NEGATIVE_TTL: Duration = Duration::from_secs(30);

type Key = (String, u16);

pub struct Resolver {
    cache: Mutex<HashMap<Key, (Vec<IpAddr>, Instant)>>,
}

impl Resolver {
    pub fn new() -> Resolver {
        Resolver { cache: Mutex::new(HashMap::new()) }
    }

    pub fn getaddrinfo(&self, query: &Query) -> Result<Vec<Entry>, i32> {
        let port = protocol::port(query.service.as_deref())?;
        let addrs = self.addresses(&query.host.to_ascii_lowercase(), query.family)?;
        let kinds = protocol::socket_kinds(query.socktype, query.protocol);
        Ok(addrs
            .iter()
            .flat_map(|addr| {
                kinds.iter().map(move |&(socktype, protocol)| Entry { addr: *addr, port, socktype, protocol })
            })
            .collect())
    }

    /// The addresses of `host` for gethostbyname: one family only, AF_INET unless asked.
    pub fn gethostbyname(&self, host: &str, family: i32) -> Result<Vec<IpAddr>, i32> {
        let family = if family == AF_INET6 { AF_INET6 } else { AF_INET };
        self.addresses(&host.to_ascii_lowercase(), family)
    }

    /// The addresses of `host`. For AF_UNSPEC IPv4 comes first and IPv6 only when there is
    /// no IPv4 address: the devices get IPv4 leases, an IPv6 address first would make every
    /// client wait for a connect that cannot work.
    fn addresses(&self, host: &str, family: i32) -> Result<Vec<IpAddr>, i32> {
        let hosts = from_hosts(host, family);
        if !hosts.is_empty() {
            return Ok(hosts);
        }
        let addrs = match family {
            AF_INET => self.lookup(host, TYPE_A)?,
            AF_INET6 => self.lookup(host, TYPE_AAAA)?,
            AF_UNSPEC => match self.lookup(host, TYPE_A)? {
                v4 if v4.is_empty() => self.lookup(host, TYPE_AAAA)?,
                v4 => v4,
            },
            _ => return Err(EAI_FAIL),
        };
        if addrs.is_empty() {
            return Err(EAI_NODATA);
        }
        Ok(addrs)
    }

    fn lookup(&self, host: &str, qtype: u16) -> Result<Vec<IpAddr>, i32> {
        let key = (host.to_string(), qtype);
        if let Some((addrs, expiry)) = self.cache.lock().unwrap().get(&key) {
            if Instant::now() < *expiry {
                return Ok(addrs.clone());
            }
        }
        let (addrs, ttl) = match ask_servers(host, qtype) {
            Some(Answer::Addresses(addrs, ttl)) if !addrs.is_empty() => {
                (addrs, Duration::from_secs(ttl.into()).min(MAX_TTL))
            }
            Some(_) => (Vec::new(), NEGATIVE_TTL),
            None => return Err(EAI_FAIL),
        };
        info!("{host} type {qtype}: {addrs:?}");
        self.cache.lock().unwrap().insert(key, (addrs.clone(), Instant::now() + ttl));
        Ok(addrs)
    }
}

fn from_hosts(host: &str, family: i32) -> Vec<IpAddr> {
    let text = fs::read_to_string(HOSTS).unwrap_or_default();
    hosts_lookup(&text, host, family)
}

fn hosts_lookup(text: &str, host: &str, family: i32) -> Vec<IpAddr> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or(""))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let addr: IpAddr = fields.next()?.parse().ok()?;
            fields.any(|name| name.eq_ignore_ascii_case(host)).then_some(addr)
        })
        .filter(|addr| match family {
            AF_INET => addr.is_ipv4(),
            AF_INET6 => addr.is_ipv6(),
            _ => true,
        })
        .collect()
}

fn nameservers() -> Vec<IpAddr> {
    fs::read_to_string(RESOLV_CONF)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|addr| addr.trim().parse().ok())
        .collect()
}

/// Asks each server in turn; None when no server gave a usable answer.
fn ask_servers(host: &str, qtype: u16) -> Option<Answer> {
    let servers = nameservers();
    if servers.is_empty() {
        warn!("no DNS servers in {RESOLV_CONF}");
        return None;
    }
    for _ in 0..ATTEMPTS {
        for server in &servers {
            match ask(host, qtype, *server) {
                Ok(Some(answer)) => return Some(answer),
                Ok(None) => warn!("{server}: malformed answer for {host}"),
                Err(err) => warn!("{server}: {err}"),
            }
        }
    }
    None
}

fn ask(host: &str, qtype: u16, server: IpAddr) -> std::io::Result<Option<Answer>> {
    let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as u16;
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.connect(SocketAddr::new(server, 53))?;
    socket.send(&wire::query(id, host, qtype))?;
    let mut buf = [0u8; 1500];
    let len = socket.recv(&mut buf)?;
    Ok(wire::parse(id, qtype, &buf[..len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_file() {
        let text = "127.0.0.1 localhost\n::1 ip6-localhost localhost # loopback\n";
        assert_eq!(hosts_lookup(text, "localhost", AF_INET), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(hosts_lookup(text, "localhost", AF_UNSPEC).len(), 2);
        assert!(hosts_lookup(text, "example.com", AF_UNSPEC).is_empty());
    }
}
