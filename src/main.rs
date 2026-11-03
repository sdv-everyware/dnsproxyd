//! dnsproxyd: name resolution for an Android device without netd.
//!
//! bionic's getaddrinfo() does not resolve names itself: libnetd_client.so sends the query
//! to netd over /dev/socket/dnsproxyd, and the DNS servers live in netd's resolver
//! (com.android.resolv), set by ConnectivityService. SDV Media has none of these. This
//! daemon answers on the same socket with the same protocol, so getaddrinfo() works again
//! in every process, unchanged.

mod protocol;
mod resolver;
mod wire;

use log::{error, info, warn};
use protocol::Request;
use resolver::Resolver;
use rustutils::android::sockets::android_get_control_socket;
use std::io::{BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SOCKET: &str = "dnsproxyd";
/// A request is one short line; a client that sends nothing is dropped.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST: usize = 1024;
/// netd's FrameworkListener uses 4; a few more for bursts at boot.
const BACKLOG: i32 = 16;
/// After a failed accept(), so an error does not turn into a busy loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

fn main() {
    // SAFETY: first thing in main, before anything takes ownership of a file descriptor.
    // rustutils hands out init's socket only through this registry.
    if let Err(err) = unsafe { rustutils::inherited_fd::init_once() } {
        eprintln!("inherited_fd::init_once: {err}");
        std::process::exit(1);
    }
    android_logger::init_once(
        android_logger::Config::default().with_tag("dnsproxyd").with_max_level(log::LevelFilter::Info),
    );
    let fd = match android_get_control_socket(SOCKET) {
        Ok(fd) => fd,
        Err(err) => {
            error!("no init socket {SOCKET}: {err:?}");
            std::process::exit(1);
        }
    };
    // init only creates and binds the socket; netd's FrameworkListener calls listen() itself.
    // SAFETY: fd is a valid socket and stays open for the call.
    if unsafe { libc::listen(fd.as_raw_fd(), BACKLOG) } != 0 {
        error!("listen: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    let listener = UnixListener::from(fd);
    let resolver = Arc::new(Resolver::new());
    info!("listening");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let resolver = resolver.clone();
                thread::spawn(move || {
                    if let Err(err) = serve(stream, &resolver) {
                        warn!("client: {err}");
                    }
                });
            }
            Err(err) => {
                warn!("accept: {err}");
                thread::sleep(ACCEPT_BACKOFF);
            }
        }
    }
}

/// One connection carries one request (libnetd_client opens a new one per call).
fn serve(stream: UnixStream, resolver: &Resolver) -> std::io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let mut line = Vec::new();
    for byte in BufReader::new(&stream).bytes() {
        match byte? {
            0 => break,
            b if line.len() < MAX_REQUEST => line.push(b),
            _ => break,
        }
    }
    let reply = match Request::parse(&String::from_utf8_lossy(&line)) {
        Some(Request::GetAddrInfo(query)) => match resolver.getaddrinfo(&query) {
            Ok(entries) => protocol::addrinfo_reply(&entries),
            Err(code) => protocol::error_reply(code),
        },
        Some(Request::GetHostByName { host, family }) => match resolver.gethostbyname(&host, family) {
            Ok(addrs) => protocol::hostent_reply(&host, if family == protocol::AF_INET6 { family } else { protocol::AF_INET }, &addrs),
            // h_errno HOST_NOT_FOUND; bionic sets it itself on any failure code.
            Err(_) => protocol::error_reply(1),
        },
        None => {
            warn!("unsupported request: {}", String::from_utf8_lossy(&line));
            protocol::error_reply(protocol::EAI_FAIL)
        }
    };
    (&stream).write_all(&reply)
}
