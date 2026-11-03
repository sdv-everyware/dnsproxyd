# dnsproxyd

Name resolution for an Android device without netd, such as SDV Media.

## Why

On Android, `getaddrinfo()` does not resolve names in the calling process. bionic's
`libnetd_client.so` sends every query to netd over `/dev/socket/dnsproxyd`; netd hands it
to DnsResolver (APEX `com.android.resolv`), whose DNS servers are set by
ConnectivityService after DHCP. `/etc/resolv.conf` is ignored on purpose
(`bionic/libc/dns/resolv/res_init.c`).

SDV Media ships none of this: no netd, no `com.android.resolv`, no framework. The
socket is missing and every `getaddrinfo()` for a name fails.

dnsproxyd listens on that socket and speaks netd's protocol, so bionic, and every program
on top of it, resolves names again without a change.

```
process ──getaddrinfo()──► libnetd_client.so ──/dev/socket/dnsproxyd──► dnsproxyd
                                                                          │ /system/etc/hosts
                                                                          │ cache (TTL, max 5 min)
                                                                          ▼
                                     DNS servers of the DHCP lease (/data/vendor/net/resolv.conf)
```

## What it does and does not do

| Request | |
|---|---|
| `getaddrinfo` | yes: hosts file, then A (and AAAA when there is no A) from the lease's servers |
| `gethostbyname` | yes, one address family (toybox `ping` uses it) |
| `gethostbyaddr`, `resnsend`, `getdnsnetid` | answered with a failure |

No DNS-over-TLS, no per-network or per-app DNS, no search domains, no DNSSEC.

## Traps found on the way

Three things that are done for netd by the rest of Android and that dnsproxyd has to do
itself. Each one was found on the RB3.

### 1. The init socket is only handed out through a registry

```
init:      socket dnsproxyd stream 0666 → creates /dev/socket/dnsproxyd, fd in
           the environment (ANDROID_SOCKET_dnsproxyd)
dnsproxyd: android_get_control_socket("dnsproxyd")
           → OwnershipFailed(NotInitialized), exit 1, init restarts it every 5 s
```

Problem: rustutils does not take an fd it was not told about. Inherited fds go through
`rustutils::inherited_fd`, which must be initialized before anything else in the process
takes an fd.

Fix: `inherited_fd::init_once()` is the first call in `main`.

### 2. init creates and binds the socket but does not listen

```
init:      socket() + bind() + chmod/chown           (no listen)
netd:      FrameworkListener::startListener → listen()
dnsproxyd: accept() on a socket nobody listens on → EINVAL, in a loop
```

Problem: `accept()` fails with `EINVAL` on a socket that is not listening. netd calls
`listen()` itself in `FrameworkListener`, so init never does. The loop also logged a warning
per iteration and flooded logcat.

Fix: `listen(fd, 16)` after the socket is taken; a failed `accept()` waits 100 ms before the
next one.

### 3. bionic has two resolver entry points on the same socket

```
nc, Rust std, curl  → getaddrinfo()   → "getaddrinfo <host> ..."   → addrinfo list
toybox ping         → gethostbyname() → "gethostbyname <netid> <host> <af>" → hostent
```

Problem: with only `getaddrinfo` implemented, `nc api.open-meteo.com 443` worked and
`ping api.open-meteo.com` said "unknown host"; dnsproxyd logged
`unsupported request: gethostbyname 0 api.open-meteo.com 2`.

Fix: `gethostbyname` is served too. The reply is a serialized `hostent` (name, aliases,
address type and length, addresses), in the order bionic's `android_read_hostent` reads it.

## Files

| | |
|---|---|
| `src/main.rs` | the init socket, one thread per connection |
| `src/protocol.rs` | the request line and the binary reply, as in bionic and DnsResolver |
| `src/resolver.rs` | hosts file, DNS servers, cache |
| `src/wire.rs` | DNS messages (RFC 1035) |
| `dnsproxyd.rc` | the service and the socket (`0666`, so service bundles can connect) |
| `sepolicy/private/` | domain `sdv_dnsproxyd`, permissive for now |
| `dnsproxyd.mk` | what a product inherits |

## Add it to a product

```make
$(call inherit-product, vendor/sdv-everyware/dnsproxyd/dnsproxyd.mk)
```

and in the product's root init (SDV init only parses what is imported):

```
import /product/etc/init/dnsproxyd.rc
```

The board writes the servers of its DHCP lease as `nameserver <ip>` lines to
`/data/vendor/net/resolv.conf`.

## Check

```bash
adb logcat -s dnsproxyd
adb shell ping -c1 api.open-meteo.com
```
