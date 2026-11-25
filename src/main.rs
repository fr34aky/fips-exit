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
//! The client list is re-read on SIGHUP.

use std::collections::HashMap;
use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

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
    if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &req) } < 0 {
        return Err(last_error("create TUN device"));
    }

    let ctl = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if ctl < 0 {
        return Err(last_error("control socket"));
    }
    let ctl = unsafe { OwnedFd::from_raw_fd(ctl) };
    let mut req = IfReq::new(name)?;
    req.data[..4].copy_from_slice(&TUN_MTU.to_ne_bytes());
    if unsafe { libc::ioctl(ctl.as_raw_fd(), libc::SIOCSIFMTU, &req) } < 0 {
        return Err(last_error("set TUN MTU"));
    }
    let mut req = IfReq::new(name)?;
    if unsafe { libc::ioctl(ctl.as_raw_fd(), libc::SIOCGIFFLAGS, &mut req) } < 0 {
        return Err(last_error("read TUN flags"));
    }
    let flags = i16::from_ne_bytes([req.data[0], req.data[1]]) | libc::IFF_UP as i16;
    req.data[..2].copy_from_slice(&flags.to_ne_bytes());
    if unsafe { libc::ioctl(ctl.as_raw_fd(), libc::SIOCSIFFLAGS, &req) } < 0 {
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
}

static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hangup(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

struct State {
    clients_path: String,
    clients: RwLock<Clients>,
    counters: Counters,
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
        if !state.clients.read().unwrap().admits(proto, &from.sin6_addr.s6_addr, inner) {
            state.counters.refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // A failed write is that packet's loss (the TUN's queue is full).
        unsafe { libc::write(tun, inner.as_ptr().cast(), inner.len()) };
        state.counters.to_internet.fetch_add(1, Ordering::Relaxed);
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
    });

    for (socket, proto) in [(socket4.as_raw_fd(), PROTO_IPV4), (socket6.as_raw_fd(), PROTO_IPV6)] {
        let (state, tun) = (state.clone(), tun.as_raw_fd());
        std::thread::spawn(move || {
            let e = from_mesh(&state, socket, proto, tun);
            eprintln!("fips-exitd: mesh socket (protocol {proto}): {e}");
            std::process::exit(1);
        });
    }
    {
        // Once a minute, and only if something moved: a line for the journal.
        let state = state.clone();
        std::thread::spawn(move || {
            let mut last = (0, 0, 0, 0);
            loop {
                std::thread::sleep(Duration::from_secs(60));
                state.reload_if_asked();
                let c = &state.counters;
                let now = (
                    c.to_internet.load(Ordering::Relaxed),
                    c.to_clients.load(Ordering::Relaxed),
                    c.refused.load(Ordering::Relaxed),
                    c.unrouted.load(Ordering::Relaxed),
                );
                if now != last {
                    eprintln!(
                        "fips-exitd: packets to internet {}, to clients {}, refused {}, unrouted {}",
                        now.0, now.1, now.2, now.3
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
}
