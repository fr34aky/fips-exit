//! fips-exitd: the data plane of a fips exit node.
//!
//! Clients send their internet traffic to this node as plain IP-in-IPv6 over
//! the mesh (RFC 2473): the client's packet is the payload of a mesh packet
//! with next-header 4 (IPv4) or 41 (IPv6). This daemon is the tunnel's end:
//!
//! ```text
//!   mesh (fips0)  ⇄  raw sockets, protocol 4 and 41  ⇄  TUN (fipsexit0)  ⇄  kernel NAT ⇄ uplink
//! ```
//!
//! It replaces the kernel's `ip6tnl` for one reason. A mesh packet is 1280
//! bytes, so an inner packet over 1240 bytes has to travel as fragments of
//! the OUTER packet (RFC 2473 section 7.1) — IPv6 promises every host 1280
//! bytes and has no in-path fragmentation. Linux's `ip6tnl` does not do
//! that; a raw socket does, and reassembles what the clients send the same
//! way. So nothing here fragments or reassembles: the kernel does both, on
//! the sockets.
//!
//! What the daemon decides is who may use the tunnel and as whom:
//!
//! - a packet from the mesh is accepted only from a listed client, and only
//!   if its inner source is that client's own address — its fips address
//!   for IPv6, [`inner_ipv4`] of it for IPv4;
//! - a packet from the TUN goes to the client its destination belongs to,
//!   and nowhere if it belongs to none.
//!
//! Everything else (the TUN's routes, NAT, the firewall) is `fips-exit up`.
//!
//! It also answers its clients' DNS. A fips2go phone sends every lookup to
//! UDP port 53 on its exit's fips address, over the mesh and outside the
//! tunnel, so that no name leaves through the phone's own network. Without
//! an answer there the exit carries packets nobody can address. The daemon
//! forwards a listed client's query to the host's resolvers and returns the
//! answer; it does not parse names and caches nothing ([`serve_dns`]).
//! The client list is re-read on SIGHUP.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// Issue an ioctl with a platform-correct request argument.
///
/// `libc::ioctl`'s request parameter is `c_ulong` on glibc and `c_int` on musl,
/// while the consts (`TUNSETIFF`, `SIOCSIFMTU`, …) are unsigned. Casting at each
/// call site either truncates on musl or fails to compile on glibc, so every
/// call goes through here and this is the only place that knows the difference.
#[cfg(target_env = "musl")]
#[inline]
fn ioctl_req(request: libc::c_ulong) -> libc::c_int {
    request as libc::c_int
}

#[cfg(not(target_env = "musl"))]
#[inline]
fn ioctl_req(request: libc::c_ulong) -> libc::c_ulong {
    request
}

const PROTO_IPV4: i32 = 4; // IPPROTO_IPIP
const PROTO_IPV6: i32 = 41; // IPPROTO_IPV6

/// The largest inner packet: the TUN's MTU, and the IPv6 minimum.
const TUN_MTU: i32 = 1280;

/// The IPv4 address a client has inside the tunnel: `100.64.0.0/10` with
/// the low 22 bits of the three bytes after the `fd` of its fips address.
/// The client derives the same; this is the contract with fips2go
/// (`shim/src/exit.rs`, `inner_ipv4`) and its exit container, and must not
/// change on one side only.
///
/// ```text
/// inner = 0x64400000 | ((a[1] << 16 | a[2] << 8 | a[3]) & 0x3fffff)
/// ```
///
/// Carrier-grade NAT space rather than `10/8`: a client's address must not
/// fall inside a LAN the exit or the client is on, and `10/8` is the range
/// most LANs use.
fn inner_ipv4(fips_addr: &[u8; 16]) -> [u8; 4] {
    let bits = (u32::from(fips_addr[1]) << 16
        | u32::from(fips_addr[2]) << 8
        | u32::from(fips_addr[3]))
        & 0x003f_ffff;
    (0x6440_0000 | bits).to_be_bytes()
}

/// The allowed clients, by both of their inner addresses.
#[derive(Default)]
struct Clients {
    /// fips address → present (the inner IPv6 address is the same).
    by_v6: HashMap<[u8; 16], ()>,
    /// Inner IPv4 address → fips address.
    by_v4: HashMap<[u8; 4], [u8; 16]>,
}

impl Clients {
    /// `<fips address> [name]` per line, `#` comments; a line that is not a
    /// fips address is skipped with a message, never fatal.
    fn parse(text: &str) -> Self {
        let mut clients = Self::default();
        for line in text.lines() {
            let Some(field) = line.split('#').next().and_then(|l| l.split_whitespace().next())
            else {
                continue;
            };
            match field.parse::<Ipv6Addr>() {
                Ok(addr) if addr.octets()[0] == 0xfd => {
                    let addr = addr.octets();
                    // 22 bits, so two clients can derive one address. Their
                    // replies could not be told apart: the first keeps it.
                    // (`fips-exit add` refuses the second; this is for a
                    // list edited by hand.)
                    match clients.by_v4.get(&inner_ipv4(&addr)) {
                        Some(other) if *other != addr => {
                            eprintln!(
                                "fips-exitd: {field} has the same inner IPv4 address as {}, skipped",
                                Ipv6Addr::from(*other)
                            );
                        }
                        _ => {
                            clients.by_v6.insert(addr, ());
                            clients.by_v4.insert(inner_ipv4(&addr), addr);
                        }
                    }
                }
                _ => eprintln!("fips-exitd: not a fips address, skipped: {field}"),
            }
        }
        clients
    }

    fn len(&self) -> usize {
        self.by_v6.len()
    }

    /// May `inner`, received from `src` under next-header `proto`, enter
    /// the TUN? Only a listed client's packet of the family its outer
    /// header names, whole, and sent from that client's own inner address.
    fn admits(&self, proto: i32, src: &[u8; 16], inner: &[u8]) -> bool {
        if !self.by_v6.contains_key(src) {
            return false;
        }
        match proto {
            PROTO_IPV4 => {
                inner.len() >= 20
                    && inner[0] >> 4 == 4
                    && usize::from(u16::from_be_bytes([inner[2], inner[3]])) == inner.len()
                    && inner[12..16] == inner_ipv4(src)
            }
            _ => {
                inner.len() >= 40
                    && inner[0] >> 4 == 6
                    && usize::from(u16::from_be_bytes([inner[4], inner[5]])) + 40 == inner.len()
                    && inner[8..24] == src[..]
            }
        }
    }

    /// Where a packet read from the TUN goes: the next-header to send it
    /// under and the client its destination address belongs to.
    fn route(&self, inner: &[u8]) -> Option<(i32, [u8; 16])> {
        match inner.first()? >> 4 {
            4 if inner.len() >= 20 => {
                let dst: [u8; 4] = inner[16..20].try_into().unwrap();
                self.by_v4.get(&dst).map(|client| (PROTO_IPV4, *client))
            }
            6 if inner.len() >= 40 => {
                let dst: [u8; 16] = inner[24..40].try_into().unwrap();
                self.by_v6.contains_key(&dst).then_some((PROTO_IPV6, dst))
            }
            _ => None,
        }
    }
}

fn last_error(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    /// The union: flags (i16) or MTU (i32) in its first bytes.
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
        }
        let mut req = Self { name: [0; libc::IFNAMSIZ], data: [0; 24] };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(req)
    }
}

/// Create the TUN device (no packet-info header), set its MTU, bring it up.
fn open_tun(name: &str) -> io::Result<OwnedFd> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_error("open /dev/net/tun"));
    }
    let tun = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut req = IfReq::new(name)?;
    let flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    req.data[..2].copy_from_slice(&flags.to_ne_bytes());
    if unsafe { libc::ioctl(tun.as_raw_fd(), ioctl_req(TUNSETIFF), &req) } < 0 {
        return Err(last_error("create TUN device"));
    }

    let ctl = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if ctl < 0 {
        return Err(last_error("control socket"));
    }
    let ctl = unsafe { OwnedFd::from_raw_fd(ctl) };
    let mut req = IfReq::new(name)?;
    req.data[..4].copy_from_slice(&TUN_MTU.to_ne_bytes());
    if unsafe { libc::ioctl(ctl.as_raw_fd(), ioctl_req(libc::SIOCSIFMTU), &req) } < 0 {
        return Err(last_error("set TUN MTU"));
    }
    let mut req = IfReq::new(name)?;
    if unsafe { libc::ioctl(ctl.as_raw_fd(), ioctl_req(libc::SIOCGIFFLAGS), &mut req) } < 0 {
        return Err(last_error("read TUN flags"));
    }
    let flags = i16::from_ne_bytes([req.data[0], req.data[1]]) | libc::IFF_UP as i16;
    req.data[..2].copy_from_slice(&flags.to_ne_bytes());
    if unsafe { libc::ioctl(ctl.as_raw_fd(), ioctl_req(libc::SIOCSIFFLAGS), &req) } < 0 {
        return Err(last_error("bring TUN up"));
    }
    Ok(tun)
}

/// The fips address (`fd…`) of interface `name`, if it has one yet.
fn mesh_address(name: &str) -> Option<[u8; 16]> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut at = list;
    while !at.is_null() {
        let entry = unsafe { &*at };
        at = entry.ifa_next;
        if entry.ifa_addr.is_null()
            || unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_bytes() != name.as_bytes()
            || i32::from(unsafe { (*entry.ifa_addr).sa_family }) != libc::AF_INET6
        {
            continue;
        }
        let addr = unsafe { (*(entry.ifa_addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr };
        if addr[0] == 0xfd {
            found = Some(addr);
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

fn sockaddr(addr: &[u8; 16]) -> libc::sockaddr_in6 {
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr.s6_addr = *addr;
    sa
}

/// A raw IPv6 socket for one next-header value, bound to this node's fips
/// address: it receives only what the mesh delivers to that address, each
/// datagram whole (the kernel reassembles), and what it sends is fragmented
/// by the kernel when it exceeds the mesh's MTU.
fn raw_socket(proto: i32, local: &[u8; 16]) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
    if fd < 0 {
        return Err(last_error("raw socket"));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let sa = sockaddr(local);
    let len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    if unsafe { libc::bind(fd, (&raw const sa).cast(), len) } < 0 {
        return Err(last_error("bind raw socket to the mesh address"));
    }
    // Room for a burst: the default is a few hundred packets.
    let size: libc::c_int = 4 << 20;
    for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    Ok(socket)
}

#[derive(Default)]
struct Counters {
    to_internet: AtomicU64,
    to_clients: AtomicU64,
    refused: AtomicU64,
    unrouted: AtomicU64,
    send_failed: AtomicU64,
    dns_answered: AtomicU64,
    dns_refused: AtomicU64,
    dns_failed: AtomicU64,
}

static RELOAD: AtomicBool = AtomicBool::new(false);

/// Replace the report atomically: a reader (a TollGate gate polling this
/// file) must never observe a half-written one. Same temp+rename discipline
/// the module uses for its config, for the same reason.
fn write_report(path: &Path, json: &str) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// How often the report thread wakes. A minute unless
/// `USAGE_REPORT_INTERVAL_MS` overrides it, which the test harness uses to
/// see the report without waiting for the minute. A value of zero would make
/// the loop spin and a value that is not a number is no interval at all, so
/// both keep the default; the default is what an unset variable means.
fn report_interval(setting: Option<&str>) -> Duration {
    const DEFAULT: Duration = Duration::from_secs(60);
    let Some(text) = setting else { return DEFAULT };
    let text = text.trim();
    match text.parse::<u64>() {
        Ok(ms) if ms > 0 => match u32::try_from(ms) {
            Ok(ms) => Duration::from_millis(u64::from(ms)),
            Err(_) => {
                eprintln!(
                    "fips-exitd: USAGE_REPORT_INTERVAL_MS={text} is out of range; \
                     reporting every {}s",
                    DEFAULT.as_secs()
                );
                DEFAULT
            }
        },
        _ => {
            eprintln!(
                "fips-exitd: USAGE_REPORT_INTERVAL_MS={text:?} is not a positive number of \
                 milliseconds; reporting every {}s",
                DEFAULT.as_secs()
            );
            DEFAULT
        }
    }
}

/// Which way a packet crossed the exit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// A client's packet leaving for the internet (mesh → TUN).
    FromClient,
    /// An internet reply on its way back to a client (TUN → mesh).
    ToClient,
}

/// What each client has moved since the daemon started.
///
/// Kept apart from `Clients` on purpose: dropping a client from the
/// allow-list ends admission and must not erase the record of what it
/// already moved, and re-reading the list on SIGHUP must not zero it.
#[derive(Default)]
struct Usage {
    rows: Mutex<HashMap<[u8; 16], Row>>,
}

#[derive(Default, Clone, Copy)]
struct Row {
    from_client: u64,
    to_client: u64,
    packets: u64,
}

impl Usage {
    fn record(&self, client: [u8; 16], bytes: u64, direction: Direction) {
        let mut rows = self.rows.lock().unwrap();
        let row = rows.entry(client).or_default();
        match direction {
            Direction::FromClient => row.from_client = row.from_client.saturating_add(bytes),
            Direction::ToClient => row.to_client = row.to_client.saturating_add(bytes),
        }
        row.packets = row.packets.saturating_add(1);
    }

    /// One row per client ever seen, ordered by address so the output is
    /// stable between reads. `(client, from_client_bytes, to_client_bytes,
    /// packets)`.
    fn snapshot(&self) -> Vec<(Ipv6Addr, u64, u64, u64)> {
        let rows = self.rows.lock().unwrap();
        let mut out: Vec<_> = rows
            .iter()
            .map(|(client, row)| {
                (Ipv6Addr::from(*client), row.from_client, row.to_client, row.packets)
            })
            .collect();
        out.sort_by_key(|row| row.0);
        out
    }

    /// The same rows as a JSON array, written where a TollGate gate can read
    /// them. Bytes rather than packets because that is what a purchase is
    /// denominated in.
    fn to_json(&self) -> String {
        let mut out = String::from("[");
        for (i, (client, from_client, to_client, packets)) in self.snapshot().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "{{\"client\":\"{client}\",\"from_client_bytes\":{from_client},\
                 \"to_client_bytes\":{to_client},\"packets\":{packets}}}"
            ));
        }
        out.push(']');
        out
    }
}

extern "C" fn on_hangup(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

struct State {
    clients_path: String,
    clients: RwLock<Clients>,
    counters: Counters,
    usage: Usage,
}

impl State {
    /// Re-read the client list if a SIGHUP asked for it. A list that cannot
    /// be read leaves the current one in place.
    fn reload_if_asked(&self) {
        if !RELOAD.swap(false, Ordering::Relaxed) {
            return;
        }
        match std::fs::read_to_string(&self.clients_path) {
            Ok(text) => {
                let clients = Clients::parse(&text);
                eprintln!("fips-exitd: client list reloaded, {} client(s)", clients.len());
                *self.clients.write().unwrap() = clients;
            }
            Err(e) => eprintln!("fips-exitd: {}: {e}; keeping the current list", self.clients_path),
        }
    }
}

/// Mesh → TUN, for one next-header value. Returns only on a socket error.
fn from_mesh(state: &State, socket: RawFd, proto: i32, tun: RawFd) -> io::Error {
    let mut buf = vec![0u8; 65536];
    loop {
        let mut from: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(socket, buf.as_mut_ptr().cast(), buf.len(), 0, (&raw mut from).cast(), &mut len)
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return e;
        }
        state.reload_if_asked();
        let inner = &buf[..n as usize];
        let client = from.sin6_addr.s6_addr;
        if !state.clients.read().unwrap().admits(proto, &client, inner) {
            state.counters.refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // A failed write is that packet's loss (the TUN's queue is full).
        let written = unsafe { libc::write(tun, inner.as_ptr().cast(), inner.len()) };
        if written >= 0 {
            state.counters.to_internet.fetch_add(1, Ordering::Relaxed);
            state
                .usage
                .record(client, inner.len() as u64, Direction::FromClient);
        }
    }
}

/// TUN → mesh. Returns only on a TUN error.
fn from_tun(state: &State, tun: RawFd, socket4: RawFd, socket6: RawFd) -> io::Error {
    let mut buf = vec![0u8; 65536];
    loop {
        let n = unsafe { libc::read(tun, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return e;
        }
        state.reload_if_asked();
        let inner = &buf[..n as usize];
        let Some((proto, client)) = state.clients.read().unwrap().route(inner) else {
            state.counters.unrouted.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let to = sockaddr(&client);
        let socket = if proto == PROTO_IPV4 { socket4 } else { socket6 };
        // Larger than the mesh's MTU beside the outer header: the kernel
        // sends it as fragments, which the client reassembles.
        let sent = unsafe {
            libc::sendto(
                socket,
                inner.as_ptr().cast(),
                inner.len(),
                0,
                (&raw const to).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            // That packet's loss; said once per kind of failure, since a
            // cause that persists would otherwise fill the journal.
            let e = io::Error::last_os_error();
            if state.counters.send_failed.fetch_add(1, Ordering::Relaxed) == 0 {
                eprintln!("fips-exitd: send to a client failed (reported once): {e}");
            }
            continue;
        }
        state.counters.to_clients.fetch_add(1, Ordering::Relaxed);
        state
            .usage
            .record(client, inner.len() as u64, Direction::ToClient);
    }
}

// ---- DNS for the clients ---------------------------------------------------

const DNS_PORT: u16 = 53;
/// The largest query read and the largest answer taken from an upstream.
const DNS_BUFFER: usize = 4096;
/// The largest answer sent to a client in one piece. A mesh packet is 1280
/// bytes; an answer that would not fit one is replaced by a truncated one
/// ([`dns_reply`]) rather than sent as fragments, which a client's small
/// in-process stack may not put together again.
const DNS_MAX_REPLY: usize = 1232;
/// How long one upstream is waited for.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// Queries being forwarded at once. Each is a thread waiting on a socket;
/// beyond this a query is dropped and the client's resolver asks again.
const DNS_IN_FLIGHT: usize = 64;

/// The resolvers to forward to, from `DNS_UPSTREAMS` (IP addresses, spaces
/// or commas between them) or, when that is unset, the host's
/// `/etc/resolv.conf`. `Ok(None)`: `DNS_UPSTREAMS=off`, no resolver is run.
fn dns_upstreams(setting: Option<&str>, resolv_conf: &str) -> Result<Option<Vec<SocketAddr>>, String> {
    // As systemd hands it over from the config file: possibly quoted, and
    // with whatever followed a `#` on the line.
    let setting = setting
        .map(|s| s.split('#').next().unwrap_or("").trim().trim_matches('"').trim())
        .unwrap_or("");
    if setting == "off" {
        return Ok(None);
    }
    let named: Vec<&str> = if setting.is_empty() {
        // `nameserver <address>` lines; a zone index (fe80::1%eth0) is cut.
        resolv_conf
            .lines()
            .filter_map(|l| l.split('#').next()?.trim().strip_prefix("nameserver"))
            .filter_map(|rest| rest.split_whitespace().next())
            .map(|a| a.split('%').next().unwrap_or(a))
            .collect()
    } else {
        setting.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).collect()
    };
    let mut upstreams = Vec::new();
    for text in named {
        let ip: IpAddr =
            text.parse().map_err(|_| format!("DNS upstream is not an IP address: {text}"))?;
        let addr = SocketAddr::new(ip, DNS_PORT);
        if !upstreams.contains(&addr) {
            upstreams.push(addr);
        }
    }
    if upstreams.is_empty() {
        return Err("no DNS upstream: set DNS_UPSTREAMS, or DNS_UPSTREAMS=off".into());
    }
    upstreams.truncate(4);
    Ok(Some(upstreams))
}

/// Where the question section of a DNS message with exactly one question
/// ends, or `None` for anything else. The only place a query is looked
/// into, and the bytes are a client's: every step is bounds-checked.
fn question_end(message: &[u8]) -> Option<usize> {
    if message.len() < 12 || message[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12;
    loop {
        let len = usize::from(*message.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        // A label, not a compression pointer: a question has none.
        if len > 63 {
            return None;
        }
        at += 1 + len;
        if at > 12 + 255 {
            return None;
        }
    }
    // QTYPE and QCLASS.
    (at + 4 <= message.len()).then_some(at + 4)
}

/// An answer with no records for `query`: its header and question with the
/// response bit set, the truncated bit if `truncated`, and `rcode`. `None`
/// for a query that is not exactly one question, which gets no answer.
fn dns_reply(query: &[u8], truncated: bool, rcode: u8) -> Option<Vec<u8>> {
    let end = question_end(query)?;
    let mut reply = query[..end].to_vec();
    // QR, the query's opcode and RD, and TC when asked for.
    reply[2] = 0x80 | (query[2] & 0x79) | if truncated { 0x02 } else { 0 };
    // RA, and the code.
    reply[3] = 0x80 | (rcode & 0x0f);
    // One question; no answer, authority or additional records.
    reply[6..12].fill(0);
    Some(reply)
}

/// Ask the upstreams in turn; the first answer to this query wins.
fn dns_forward(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; DNS_BUFFER];
    for upstream in upstreams {
        let bind: SocketAddr = match upstream {
            SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
            SocketAddr::V6(_) => ([0u16; 8], 0).into(),
        };
        let Ok(socket) = UdpSocket::bind(bind) else { continue };
        // Connected: the kernel drops datagrams from anyone else.
        if socket.connect(upstream).is_err()
            || socket.set_read_timeout(Some(DNS_TIMEOUT)).is_err()
            || socket.send(query).is_err()
        {
            continue;
        }
        let deadline = std::time::Instant::now() + DNS_TIMEOUT;
        while std::time::Instant::now() < deadline {
            match socket.recv(&mut buf) {
                // The same id, and a response.
                Ok(n) if n >= 12 && buf[..2] == query[..2] && buf[2] & 0x80 != 0 => {
                    return Some(buf[..n].to_vec());
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
    None
}

/// The resolver: UDP port 53 on this node's fips address. Answers listed
/// clients only (the source of a packet on the mesh is its sender's fips
/// address: fips authenticates it), so this is not an open resolver for the
/// mesh. Returns only if the socket fails.
fn serve_dns(state: Arc<State>, socket: UdpSocket, upstreams: Vec<SocketAddr>) -> io::Error {
    let socket = Arc::new(socket);
    let upstreams = Arc::new(upstreams);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let mut buf = [0u8; DNS_BUFFER];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return e,
        };
        state.reload_if_asked();
        let IpAddr::V6(source) = peer.ip() else { continue };
        let listed = state.clients.read().unwrap().by_v6.contains_key(&source.octets());
        // A response bit set is not a query: never answer an answer.
        if !listed || n < 12 || buf[2] & 0x80 != 0 {
            state.counters.dns_refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if in_flight.fetch_add(1, Ordering::Relaxed) >= DNS_IN_FLIGHT {
            in_flight.fetch_sub(1, Ordering::Relaxed);
            state.counters.dns_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let query = buf[..n].to_vec();
        let (state, socket, upstreams, in_flight) =
            (state.clone(), socket.clone(), upstreams.clone(), in_flight.clone());
        std::thread::spawn(move || {
            let reply = match dns_forward(&query, &upstreams) {
                Some(answer) if answer.len() <= DNS_MAX_REPLY => {
                    state.counters.dns_answered.fetch_add(1, Ordering::Relaxed);
                    Some(answer)
                }
                // Too large for one mesh packet: tell the client so.
                Some(_) => {
                    state.counters.dns_answered.fetch_add(1, Ordering::Relaxed);
                    dns_reply(&query, true, 0)
                }
                // No upstream answered: SERVFAIL now, not a timeout later.
                None => {
                    state.counters.dns_failed.fetch_add(1, Ordering::Relaxed);
                    dns_reply(&query, false, 2)
                }
            };
            if let Some(reply) = reply {
                let _ = socket.send_to(&reply, peer);
            }
            in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

struct Args {
    clients: String,
    mesh_if: String,
    tun: String,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        clients: "/etc/fips-exit/clients".into(),
        mesh_if: "fips0".into(),
        tun: "fipsexit0".into(),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let slot = match flag.as_str() {
            "--clients" => &mut args.clients,
            "--mesh-if" => &mut args.mesh_if,
            "--tun" => &mut args.tun,
            other => {
                return Err(format!(
                    "unknown argument {other}\nusage: fips-exitd [--clients FILE] [--mesh-if IF] [--tun NAME]"
                ));
            }
        };
        *slot = argv.next().ok_or_else(|| format!("{flag} needs a value"))?;
    }
    Ok(args)
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    // fips brings its interface up a moment after it starts.
    let local = (0..60)
        .find_map(|i| {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }
            mesh_address(&args.mesh_if)
        })
        .ok_or_else(|| format!("{} has no fips address: is fips running?", args.mesh_if))?;

    let socket4 = raw_socket(PROTO_IPV4, &local).map_err(|e| e.to_string())?;
    let socket6 = raw_socket(PROTO_IPV6, &local).map_err(|e| e.to_string())?;
    let tun = open_tun(&args.tun).map_err(|e| e.to_string())?;

    let clients = match std::fs::read_to_string(&args.clients) {
        Ok(text) => Clients::parse(&text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Clients::default(),
        Err(e) => return Err(format!("{}: {e}", args.clients)),
    };
    unsafe { libc::signal(libc::SIGHUP, on_hangup as extern "C" fn(libc::c_int) as libc::sighandler_t) };
    eprintln!(
        "fips-exitd: {} ⇄ {} as {}, {} client(s)",
        args.mesh_if,
        args.tun,
        Ipv6Addr::from(local),
        clients.len()
    );
    let state = Arc::new(State {
        clients_path: args.clients,
        clients: RwLock::new(clients),
        counters: Counters::default(),
        usage: Usage::default(),
    });

    for (socket, proto) in [(socket4.as_raw_fd(), PROTO_IPV4), (socket6.as_raw_fd(), PROTO_IPV6)] {
        let (state, tun) = (state.clone(), tun.as_raw_fd());
        std::thread::spawn(move || {
            let e = from_mesh(&state, socket, proto, tun);
            eprintln!("fips-exitd: mesh socket (protocol {proto}): {e}");
            std::process::exit(1);
        });
    }
    // DNS for the clients. A resolver that cannot start is said loudly and is
    // not fatal: the tunnel works without it for anyone who brings their own.
    let resolv_conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    match dns_upstreams(std::env::var("DNS_UPSTREAMS").ok().as_deref(), &resolv_conf) {
        Ok(None) => eprintln!("fips-exitd: DNS_UPSTREAMS=off: no DNS for clients"),
        Err(e) => eprintln!("fips-exitd: NO DNS FOR CLIENTS: {e}"),
        Ok(Some(upstreams)) => {
            match UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(local)), DNS_PORT)) {
                Ok(socket) => {
                    let list: Vec<String> = upstreams.iter().map(|u| u.ip().to_string()).collect();
                    eprintln!("fips-exitd: DNS for clients on port {DNS_PORT}, forwarding to {}", list.join(", "));
                    let state = state.clone();
                    std::thread::spawn(move || {
                        let e = serve_dns(state, socket, upstreams);
                        eprintln!("fips-exitd: DNS socket: {e}");
                        std::process::exit(1);
                    });
                }
                Err(e) => eprintln!(
                    "fips-exitd: NO DNS FOR CLIENTS: cannot listen on [{}]:{DNS_PORT}: {e}",
                    Ipv6Addr::from(local)
                ),
            }
        }
    }
    {
        // Once a minute, and only if something moved: a line for the journal,
        // plus the per-client report a TollGate gate reads.
        let state = state.clone();
        std::thread::spawn(move || {
            let mut last = (0, 0, 0, 0, 0, 0, 0);
            let mut last_usage = String::new();
            let interval = report_interval(std::env::var("USAGE_REPORT_INTERVAL_MS").ok().as_deref());
            loop {
                std::thread::sleep(interval);
                state.reload_if_asked();
                if let Some(path) = std::env::var_os("USAGE_REPORT") {
                    let json = state.usage.to_json();
                    if json != last_usage {
                        if let Err(e) = write_report(Path::new(&path), &json) {
                            eprintln!(
                                "fips-exitd: usage report {}: {e}",
                                Path::new(&path).display()
                            );
                        } else {
                            last_usage = json;
                        }
                    }
                }
                let c = &state.counters;
                let now = (
                    c.to_internet.load(Ordering::Relaxed),
                    c.to_clients.load(Ordering::Relaxed),
                    c.refused.load(Ordering::Relaxed),
                    c.unrouted.load(Ordering::Relaxed),
                    c.dns_answered.load(Ordering::Relaxed),
                    c.dns_refused.load(Ordering::Relaxed),
                    c.dns_failed.load(Ordering::Relaxed),
                );
                if now != last {
                    eprintln!(
                        "fips-exitd: packets to internet {}, to clients {}, refused {}, unrouted {}; \
                         DNS answered {}, refused {}, failed {}",
                        now.0, now.1, now.2, now.3, now.4, now.5, now.6
                    );
                    last = now;
                }
            }
        });
    }
    let e = from_tun(&state, tun.as_raw_fd(), socket4.as_raw_fd(), socket6.as_raw_fd());
    Err(format!("TUN: {e}"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("fips-exitd: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "fd11:2233:4455:6677::1";
    const B: &str = "fd99:8877:6655:4433::2";

    fn addr(text: &str) -> [u8; 16] {
        text.parse::<Ipv6Addr>().unwrap().octets()
    }

    fn clients() -> Clients {
        Clients::parse(&format!("# clients\n{A} alice-phone\n\n{B}   # bob\nnot-an-address x\n2001:db8::1\n"))
    }

    fn v4(src: [u8; 4], dst: [u8; 4], len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    fn v6(src: [u8; 16], dst: [u8; 16], len: usize) -> Vec<u8> {
        let mut p = vec![0u8; len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        p[8..24].copy_from_slice(&src);
        p[24..40].copy_from_slice(&dst);
        p
    }

    #[test]
    fn the_list_takes_fips_addresses_and_skips_the_rest() {
        let c = clients();
        assert_eq!(c.len(), 2);
        assert_eq!(c.by_v4.get(&[100, 0x51, 0x22, 0x33]), Some(&addr(A)));
    }

    /// The same vectors as fips2go's `exit::tests` and its exit container's
    /// `test_exitctl.py`: all three derive one address for one client.
    #[test]
    fn the_usage_report_is_json_a_gate_can_read() {
        let usage = Usage::default();
        let a = addr(A);
        usage.record(a, 1024, Direction::FromClient);
        usage.record(a, 64, Direction::ToClient);
        let json = usage.to_json();
        assert_eq!(
            json,
            format!(
                "[{{\"client\":\"{}\",\"from_client_bytes\":1024,\
                 \"to_client_bytes\":64,\"packets\":2}}]",
                Ipv6Addr::from(a)
            )
        );
        assert_eq!(Usage::default().to_json(), "[]");
    }

    /// The report interval is a minute unless `USAGE_REPORT_INTERVAL_MS` says
    /// otherwise, and a value that is not a positive number of milliseconds is
    /// not allowed to turn the loop into a spin: it falls back to the minute.
    #[test]
    fn the_report_interval_is_a_minute_unless_overridden_with_a_real_number() {
        let minute = Duration::from_secs(60);
        assert_eq!(report_interval(None), minute);
        assert_eq!(report_interval(Some("200")), Duration::from_millis(200));
        assert_eq!(report_interval(Some(" 2500 ")), Duration::from_millis(2500));
        // Zero would busy-loop the report thread; not a number, not a duration.
        assert_eq!(report_interval(Some("0")), minute);
        assert_eq!(report_interval(Some("")), minute);
        assert_eq!(report_interval(Some("-5")), minute);
        assert_eq!(report_interval(Some("soon")), minute);
        assert_eq!(report_interval(Some("1.5")), minute);
        // A number too large for a Duration is a bad value too, not a panic.
        assert_eq!(report_interval(Some("999999999999999999999")), minute);
    }

    #[test]
    fn a_written_report_leaves_no_partial_file() {
        let dir = std::env::temp_dir().join(format!("fips-exit-usage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("usage.json");
        let usage = Usage::default();
        usage.record(addr(A), 7, Direction::FromClient);
        write_report(&path, &usage.to_json()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), usage.to_json());
        // A stale reader never sees a truncated file: the write renames.
        assert!(!dir.join("usage.json.tmp").exists());
        // An existing report is replaced, not appended to.
        usage.record(addr(A), 3, Direction::FromClient);
        write_report(&path, &usage.to_json()).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), usage.to_json());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn usage_is_counted_per_client_and_survives_a_list_reload() {
        let usage = Usage::default();
        let (a, b) = (addr(A), addr(B));
        usage.record(a, 100, Direction::FromClient);
        usage.record(a, 250, Direction::ToClient);
        usage.record(b, 40, Direction::FromClient);
        let snap = usage.snapshot();
        // Sorted by address, one row per client, both directions in bytes.
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].0, Ipv6Addr::from(a));
        assert_eq!((snap[0].1, snap[0].2, snap[0].3), (100, 250, 2));
        assert_eq!((snap[1].1, snap[1].2, snap[1].3), (40, 0, 1));

        // A second SIGHUP-driven list reload must not silently zero billing
        // state: the daemon keeps usage in its own map for exactly this reason.
        let state = State {
            clients_path: "/nonexistent".into(),
            clients: RwLock::new(Clients::default()),
            counters: Counters::default(),
            usage,
        };
        assert_eq!(state.usage.snapshot(), snap);
    }

    #[test]
    fn usage_of_a_removed_client_is_still_reportable() {
        let usage = Usage::default();
        let a = addr(A);
        usage.record(a, 10, Direction::FromClient);
        // Dropping the client from the allow-list ends admission, not the
        // record of what it already moved.
        usage.record(addr(B), 5, Direction::FromClient);
        let snap = usage.snapshot();
        assert!(
            snap.iter()
                .any(|row| row.0 == Ipv6Addr::from(a) && row.1 == 10)
        );
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn the_inner_address_follows_the_shared_formula() {
        let inner = |b1, b2, b3| {
            let mut a = [0u8; 16];
            a[0] = 0xfd;
            a[1..4].copy_from_slice(&[b1, b2, b3]);
            inner_ipv4(&a)
        };
        assert_eq!(inner(0xab, 0xcd, 0xef), [100, 107, 205, 239]);
        assert_eq!(inner(0xff, 0xff, 0xff), [100, 127, 255, 255]);
        assert_eq!(inner(0, 0, 0), [100, 64, 0, 0]);
    }

    /// Two addresses that differ only above the 22 bits derive one inner
    /// address. The first on the list keeps it; the second is not a client.
    #[test]
    fn a_second_client_with_the_same_inner_address_is_skipped() {
        let c = Clients::parse("fd11:2233::1 first\nfd51:2233::2 second\n");
        assert_eq!(c.len(), 1);
        let first: [u8; 16] = "fd11:2233::1".parse::<Ipv6Addr>().unwrap().octets();
        let second: [u8; 16] = "fd51:2233::2".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(inner_ipv4(&first), inner_ipv4(&second));
        assert_eq!(c.by_v4.get(&inner_ipv4(&first)), Some(&first));
        assert!(!c.by_v6.contains_key(&second));
        // The same line twice is one client, not a clash.
        assert_eq!(Clients::parse("fd11:2233::1\nfd11:2233::1\n").len(), 1);
    }

    #[test]
    fn a_client_sends_only_as_itself() {
        let c = clients();
        let (a, b) = (addr(A), addr(B));
        let internet4 = [1, 1, 1, 1];
        let internet6 = [0x20; 16];
        // Its own addresses, the family the outer header names.
        assert!(c.admits(PROTO_IPV4, &a, &v4(inner_ipv4(&a), internet4, 60)));
        assert!(c.admits(PROTO_IPV6, &a, &v6(a, internet6, 60)));
        // Another client's address, in either family.
        assert!(!c.admits(PROTO_IPV4, &a, &v4(inner_ipv4(&b), internet4, 60)));
        assert!(!c.admits(PROTO_IPV6, &a, &v6(b, internet6, 60)));
        // An address that is nobody's.
        assert!(!c.admits(PROTO_IPV4, &a, &v4([192, 168, 1, 5], internet4, 60)));
        // The wrong family for the next-header, and a length that lies.
        assert!(!c.admits(PROTO_IPV6, &a, &v4(inner_ipv4(&a), internet4, 60)));
        assert!(!c.admits(PROTO_IPV4, &a, &v6(a, internet6, 60)));
        let mut short = v4(inner_ipv4(&a), internet4, 60);
        short.truncate(40);
        assert!(!c.admits(PROTO_IPV4, &a, &short));
        // A node that is not a client, even with a plausible packet.
        let stranger = addr("fd77::7");
        assert!(!c.admits(PROTO_IPV4, &stranger, &v4(inner_ipv4(&stranger), internet4, 60)));
        assert!(!c.admits(PROTO_IPV6, &stranger, &v6(stranger, internet6, 60)));
    }

    #[test]
    fn a_reply_goes_to_the_client_its_destination_belongs_to() {
        let c = clients();
        let (a, b) = (addr(A), addr(B));
        assert_eq!(c.route(&v4([1, 1, 1, 1], inner_ipv4(&b), 60)), Some((PROTO_IPV4, b)));
        assert_eq!(c.route(&v6([0x20; 16], a, 60)), Some((PROTO_IPV6, a)));
        // Nobody's address, too short, not IP.
        assert_eq!(c.route(&v4([1, 1, 1, 1], [100, 64, 9, 9], 60)), None);
        assert_eq!(c.route(&v6([0x20; 16], addr("fd77::7"), 60)), None);
        assert_eq!(c.route(&[0x45; 10]), None);
        assert_eq!(c.route(&[]), None);
    }
    #[test]
    fn upstreams_come_from_the_setting_or_the_hosts_resolv_conf() {
        let at = |text: &str| SocketAddr::new(text.parse().unwrap(), 53);
        let conf = "# resolv.conf\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\noptions edns0\nsearch lan\n";
        assert_eq!(dns_upstreams(None, conf), Ok(Some(vec![at("127.0.0.53"), at("fe80::1")])));
        assert_eq!(dns_upstreams(Some(""), conf), Ok(Some(vec![at("127.0.0.53"), at("fe80::1")])));
        // The setting replaces the file, and is trimmed like the script's values.
        assert_eq!(
            dns_upstreams(Some("\"9.9.9.9, 2620:fe::fe 9.9.9.9\""), conf),
            Ok(Some(vec![at("9.9.9.9"), at("2620:fe::fe")]))
        );
        assert_eq!(dns_upstreams(Some("off"), conf), Ok(None));
        // A comment after the value arrives with it from the unit's environment.
        assert_eq!(dns_upstreams(Some("9.9.9.9  # quad9"), conf), Ok(Some(vec![at("9.9.9.9")])));
        assert_eq!(dns_upstreams(Some("off # for now"), conf), Ok(None));
        assert!(dns_upstreams(Some("dns.example.org"), conf).is_err(), "a name is not an address");
        assert!(dns_upstreams(None, "search lan\n").is_err(), "nothing to forward to");
        // No more than four are asked.
        let many = "1.1.1.1 1.0.0.1 9.9.9.9 8.8.8.8 8.8.4.4";
        assert_eq!(dns_upstreams(Some(many), "").unwrap().unwrap().len(), 4);
    }

    /// `example.com A IN`, id abcd, recursion desired.
    fn query() -> Vec<u8> {
        let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        q
    }

    #[test]
    fn the_question_is_found_or_the_query_is_left_alone() {
        let q = query();
        assert_eq!(question_end(&q), Some(q.len()));
        // With an EDNS record after it, the question still ends where it ends.
        let mut edns = q.clone();
        edns[11] = 1;
        edns.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(question_end(&edns), Some(q.len()));
        // Truncated anywhere, two questions, a pointer, an endless name: none.
        for cut in 0..q.len() {
            assert_eq!(question_end(&q[..cut]), None, "cut at {cut}");
        }
        let mut two = q.clone();
        two[5] = 2;
        assert_eq!(question_end(&two), None);
        let mut pointer = q.clone();
        pointer[12] = 0xc0;
        assert_eq!(question_end(&pointer), None);
        let mut long = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for _ in 0..10 {
            long.push(63);
            long.extend_from_slice(&[b'a'; 63]);
        }
        long.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(question_end(&long), None, "a name over 255 bytes");
    }

    #[test]
    fn an_empty_answer_keeps_the_id_and_the_question() {
        let q = query();
        let fail = dns_reply(&q, false, 2).unwrap();
        assert_eq!(fail[..2], q[..2], "the id");
        assert_eq!(fail[2], 0x81, "a response, recursion desired as asked");
        assert_eq!(fail[3], 0x82, "recursion available, SERVFAIL");
        assert_eq!(fail[4..12], [0, 1, 0, 0, 0, 0, 0, 0], "one question, no records");
        assert_eq!(fail[12..], q[12..], "the question as asked");
        let cut = dns_reply(&q, true, 0).unwrap();
        assert_eq!(cut[2], 0x83, "truncated");
        assert_eq!(cut[3], 0x80);
        // The EDNS record of a query is not echoed: the count says none.
        let mut edns = q.clone();
        edns[11] = 1;
        edns.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(dns_reply(&edns, false, 2).unwrap(), fail);
        assert_eq!(dns_reply(&q[..14], false, 2), None, "no answer to what is not a question");
    }

}
