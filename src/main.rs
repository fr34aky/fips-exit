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
//! Who is a client: an address on the operator's list, carried without a
//! count; or a member of an *account*, carried while the account has bytes
//! left ([`Account`]). Accounts are not this daemon's idea: something else
//! (a payment service) makes them over the control socket ([`serve_control`],
//! `--control PATH`), and without that option there are none. The daemon
//! counts and stops; it knows nothing about money.
//!
//! It also answers its clients' DNS. A fips2go phone sends every lookup to
//! UDP port 53 on its exit's fips address, over the mesh and outside the
//! tunnel, so that no name leaves through the phone's own network. Without
//! an answer there the exit carries packets nobody can address. The daemon
//! forwards a listed client's query to the host's resolvers and returns the
//! answer; it does not parse names and caches nothing ([`serve_dns`]).
//! The client list is re-read on SIGHUP.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// What an account may use and what it has used. An account is how
/// something outside this daemon lets addresses that are not on the
/// operator's list use the exit, for a number of bytes. The three numbers
/// only ever grow: nothing is subtracted, so no arithmetic here can wrap
/// round to "unlimited" ([`MAX_NUMBER`] keeps what is put in far from the
/// top).
#[derive(Default)]
struct Account {
    /// Bytes the account may use in all, both directions together.
    granted: AtomicU64,
    /// Bytes carried from its members towards the internet.
    used_in: AtomicU64,
    /// Bytes carried towards its members.
    used_out: AtomicU64,
}

impl Account {
    /// May another packet be carried? The packet that crosses the line was:
    /// the overdraft is one packet for each thread that carries packets.
    fn funded(&self) -> bool {
        let used = self.used_in.load(Ordering::Relaxed).saturating_add(self.used_out.load(Ordering::Relaxed));
        used < self.granted.load(Ordering::Relaxed)
    }

    /// Bring each number up to the given one. Never down: a command that
    /// arrives twice, or late, takes nothing back and gives nothing twice.
    fn raise(&self, granted: u64, used_in: u64, used_out: u64) {
        self.granted.fetch_max(granted, Ordering::Relaxed);
        self.used_in.fetch_max(used_in, Ordering::Relaxed);
        self.used_out.fetch_max(used_out, Ordering::Relaxed);
    }
}

/// Who an address in the table is.
enum Client {
    /// On the operator's list: carried, and not counted.
    Static,
    /// A member of an account: carried while the account has bytes left.
    Member(Arc<Account>),
}

/// What is to happen to a packet. `Carry` names the account to count it
/// against once it has really been passed on; `None` is a client on the
/// operator's list.
enum Verdict<T> {
    /// Not a client's packet, or not a packet.
    Refused,
    /// A member's, whose account has no bytes left.
    Exhausted,
    Carry(T, Option<Arc<Account>>),
}

impl<T> Verdict<T> {
    #[cfg(test)]
    fn carried(self) -> Option<T> {
        match self {
            Verdict::Carry(what, _) => Some(what),
            _ => None,
        }
    }
}

/// How a member sits in the table: what `put` and `members` answer for each.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Seat {
    /// Carried in both families.
    V4,
    /// Carried for IPv6 only: its inner IPv4 address is another client's.
    No4,
    /// On the operator's list as well, which wins: carried, not counted.
    Static,
}

impl Seat {
    fn word(self) -> &'static str {
        match self {
            Seat::V4 => "v4",
            Seat::No4 => "no4",
            Seat::Static => "static",
        }
    }
}

/// How each member of an account sits, in the order they were given.
type Seats = Vec<([u8; 16], Seat)>;

/// An account and the addresses that share it, as they were given: a member
/// is listed here whether or not it could be seated.
struct Entry {
    account: Arc<Account>,
    members: Vec<[u8; 16]>,
}

/// The most accounts, and the most members of one. Both are a peer's on the
/// control socket to choose, so both have an end.
const MAX_ACCOUNTS: usize = 16384;
const MAX_MEMBERS: usize = 32;
/// How long an inner IPv4 address that was given up is kept from everyone
/// but its last holder. Replies are routed by their destination alone
/// ([`Clients::route`]): handed on at once, the address would bring its new
/// holder what was still on its way to the old one.
const HOLD_DOWN: Duration = Duration::from_secs(300);

/// The clients, by both of their inner addresses.
#[derive(Default)]
struct Clients {
    /// fips address → who it is (the inner IPv6 address is the same).
    by_v6: HashMap<[u8; 16], Client>,
    /// Inner IPv4 address → the fips address that holds it. Whoever is here
    /// is in `by_v6` too.
    by_v4: HashMap<[u8; 4], [u8; 16]>,
    /// How many of `by_v6` are the operator's.
    listed: usize,
    /// The accounts, by name.
    accounts: BTreeMap<String, Entry>,
    /// Member → the name of its account. An address is in one account.
    member_of: HashMap<[u8; 16], String>,
    /// Inner IPv4 addresses given up: the last holder, and until when only
    /// that holder may have the address back.
    held: HashMap<[u8; 4], ([u8; 16], Instant)>,
}

/// The operator's list: `<fips address> [name]` per line, `#` comments. A
/// line that is not a fips address is skipped with a message, never fatal,
/// and so is an address whose inner IPv4 address an earlier line has.
fn parse_list(text: &str) -> Vec<[u8; 16]> {
    let mut list = Vec::new();
    let mut by_v4: HashMap<[u8; 4], [u8; 16]> = HashMap::new();
    for line in text.lines() {
        let Some(field) = line.split('#').next().and_then(|l| l.split_whitespace().next()) else {
            continue;
        };
        match field.parse::<Ipv6Addr>() {
            Ok(addr) if addr.octets()[0] == 0xfd => {
                let addr = addr.octets();
                // 22 bits, so two clients can derive one address. Their
                // replies could not be told apart: the first keeps it.
                // (`fips-exit add` refuses the second; this is for a list
                // edited by hand.)
                match by_v4.get(&inner_ipv4(&addr)) {
                    Some(other) if *other != addr => {
                        eprintln!(
                            "fips-exitd: {field} has the same inner IPv4 address as {}, skipped",
                            Ipv6Addr::from(*other)
                        );
                    }
                    // The same line twice is one client.
                    Some(_) => {}
                    None => {
                        by_v4.insert(inner_ipv4(&addr), addr);
                        list.push(addr);
                    }
                }
            }
            _ => eprintln!("fips-exitd: not a fips address, skipped: {field}"),
        }
    }
    list
}

impl Clients {
    #[cfg(test)]
    fn parse(text: &str) -> Self {
        let mut clients = Self::default();
        clients.set_list(parse_list(text), Instant::now());
        clients
    }

    /// The clients on the operator's list.
    fn len(&self) -> usize {
        self.listed
    }

    /// Replace the operator's list and leave the accounts as they are. A
    /// client on the list wins over a member: it takes the member's place
    /// when it is the same address, and the inner IPv4 address when that is
    /// what they share. A member that a removed line was in front of is
    /// seated again.
    fn set_list(&mut self, list: Vec<[u8; 16]>, now: Instant) {
        self.held.retain(|_, (_, until)| now < *until);
        let old: Vec<[u8; 16]> =
            self.by_v6.iter().filter(|(_, client)| matches!(client, Client::Static)).map(|(addr, _)| *addr).collect();
        for addr in &old {
            self.unseat(addr, now);
        }
        for addr in &list {
            self.by_v6.insert(*addr, Client::Static);
            self.by_v4.insert(inner_ipv4(addr), *addr);
            self.held.remove(&inner_ipv4(addr));
        }
        self.listed = list.len();
        let names: Vec<String> = self.accounts.keys().cloned().collect();
        for name in names {
            self.seat(&name, now);
        }
    }

    /// Take `addr` out of the tables. An inner IPv4 address it held is kept
    /// for it for [`HOLD_DOWN`].
    fn unseat(&mut self, addr: &[u8; 16], now: Instant) {
        self.by_v6.remove(addr);
        let inner = inner_ipv4(addr);
        if self.by_v4.get(&inner) == Some(addr) {
            self.by_v4.remove(&inner);
            self.held.insert(inner, (*addr, now + HOLD_DOWN));
        }
    }

    /// Put an account's members into the tables, as far as each can be, and
    /// say how each sits. A member that already sits keeps what it has; one
    /// without its inner IPv4 address gets it if it has become free.
    fn seat(&mut self, name: &str, now: Instant) -> Seats {
        let Some(entry) = self.accounts.get(name) else {
            return Vec::new();
        };
        let (account, members) = (entry.account.clone(), entry.members.clone());
        let mut seats = Vec::with_capacity(members.len());
        for addr in members {
            let client = self.by_v6.entry(addr).or_insert_with(|| Client::Member(account.clone()));
            if matches!(client, Client::Static) {
                seats.push((addr, Seat::Static));
                continue;
            }
            let inner = inner_ipv4(&addr);
            let kept_for_another =
                matches!(self.held.get(&inner), Some((last, until)) if *last != addr && now < *until);
            let has_v4 = match self.by_v4.get(&inner) {
                // The first holder keeps it.
                Some(holder) => *holder == addr,
                None if kept_for_another => false,
                None => {
                    self.by_v4.insert(inner, addr);
                    self.held.remove(&inner);
                    true
                }
            };
            seats.push((addr, if has_v4 { Seat::V4 } else { Seat::No4 }));
        }
        seats
    }

    /// An address is in one account: `members` may all join `name`, or the
    /// first that is somewhere else is named.
    fn may_join(&self, name: &str, members: &[[u8; 16]]) -> Result<(), String> {
        for addr in members {
            if self.member_of.get(addr).is_some_and(|other| other != name) {
                return Err(format!("elsewhere {}", Ipv6Addr::from(*addr)));
            }
        }
        Ok(())
    }

    /// Replace an account's members: all of it, or on an error none of it.
    fn set_members(&mut self, name: &str, members: Vec<[u8; 16]>, now: Instant) -> Result<Seats, String> {
        if !self.accounts.contains_key(name) {
            return Err("no-account".into());
        }
        self.may_join(name, &members)?;
        self.held.retain(|_, (_, until)| now < *until);
        let Some(entry) = self.accounts.get_mut(name) else {
            return Err("no-account".into());
        };
        let old = std::mem::replace(&mut entry.members, members.clone());
        for addr in old.iter().filter(|addr| !members.contains(addr)) {
            self.member_of.remove(addr);
            // Its seat, unless a client on the operator's list has it.
            if matches!(self.by_v6.get(addr), Some(Client::Member(_))) {
                self.unseat(addr, now);
            }
        }
        for addr in &members {
            self.member_of.insert(*addr, name.to_string());
        }
        Ok(self.seat(name, now))
    }

    /// Make the account, or bring it up to these numbers ([`Account::raise`]),
    /// and replace its members. What the payment service sends for every
    /// account after this daemon has started with an empty table.
    fn put(
        &mut self,
        name: &str,
        numbers: [u64; 3],
        members: Vec<[u8; 16]>,
        now: Instant,
    ) -> Result<Seats, String> {
        self.may_join(name, &members)?;
        if !self.accounts.contains_key(name) {
            if self.accounts.len() >= MAX_ACCOUNTS {
                return Err("too-many-accounts".into());
            }
            self.accounts.insert(name.to_string(), Entry { account: Arc::default(), members: Vec::new() });
        }
        if let Some(entry) = self.accounts.get(name) {
            entry.account.raise(numbers[0], numbers[1], numbers[2]);
        }
        self.set_members(name, members, now)
    }

    /// Remove an account and unseat its members.
    fn drop_account(&mut self, name: &str, now: Instant) -> bool {
        self.set_members(name, Vec::new(), now).is_ok() && self.accounts.remove(name).is_some()
    }

    /// Raise an account's grant to `granted` in all.
    fn grant(&self, name: &str, granted: u64) -> bool {
        match self.accounts.get(name) {
            Some(entry) => {
                entry.account.granted.fetch_max(granted, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// What `addr` is here: on the operator's list; a member, with its inner
    /// IPv4 address or without; or free to join, and whether it would get
    /// that address if it joined now.
    fn check(&self, addr: &[u8; 16], now: Instant) -> String {
        let inner = inner_ipv4(addr);
        let word = |has_v4: bool| if has_v4 { Seat::V4.word() } else { Seat::No4.word() };
        let holds = self.by_v4.get(&inner) == Some(addr);
        let kept_for_another = matches!(self.held.get(&inner), Some((last, until)) if last != addr && now < *until);
        match (self.by_v6.get(addr), self.member_of.get(addr)) {
            (Some(Client::Static), _) => "static".into(),
            (_, Some(name)) => format!("member {name} {}", word(holds)),
            _ => format!("free {}", word(!self.by_v4.contains_key(&inner) && !kept_for_another)),
        }
    }

    /// One line for each account, or for the one named: its name and its
    /// three numbers.
    fn usage(&self, name: Option<&str>) -> Vec<String> {
        self.accounts
            .iter()
            .filter(|(account, _)| name.is_none_or(|wanted| wanted == account.as_str()))
            .map(|(account, entry)| {
                format!(
                    "account {account} {} {} {}",
                    entry.account.granted.load(Ordering::Relaxed),
                    entry.account.used_in.load(Ordering::Relaxed),
                    entry.account.used_out.load(Ordering::Relaxed)
                )
            })
            .collect()
    }

    /// Is `addr` someone the resolver answers: a client on the operator's
    /// list, or a member whose account has bytes left?
    fn resolves_for(&self, addr: &[u8; 16]) -> bool {
        match self.by_v6.get(addr) {
            Some(Client::Static) => true,
            Some(Client::Member(account)) => account.funded(),
            None => false,
        }
    }

    /// May `inner`, received from `src` under next-header `proto`, enter
    /// the TUN? Only a client's packet of the family its outer header
    /// names, whole, and sent from that client's own inner address.
    fn admits(&self, proto: i32, src: &[u8; 16], inner: &[u8]) -> Verdict<()> {
        let Some(client) = self.by_v6.get(src) else {
            return Verdict::Refused;
        };
        let its_own = match proto {
            PROTO_IPV4 => {
                inner.len() >= 20
                    && inner[0] >> 4 == 4
                    && usize::from(u16::from_be_bytes([inner[2], inner[3]])) == inner.len()
                    && inner[12..16] == inner_ipv4(src)
                    // Derived from its address, and held by it: a member
                    // admitted for IPv6 only derives the address of the
                    // client that holds it.
                    && self.by_v4.get(&inner_ipv4(src)) == Some(src)
            }
            _ => {
                inner.len() >= 40
                    && inner[0] >> 4 == 6
                    && usize::from(u16::from_be_bytes([inner[4], inner[5]])) + 40 == inner.len()
                    && inner[8..24] == src[..]
            }
        };
        if !its_own {
            return Verdict::Refused;
        }
        match client {
            Client::Static => Verdict::Carry((), None),
            Client::Member(account) if account.funded() => Verdict::Carry((), Some(account.clone())),
            Client::Member(_) => Verdict::Exhausted,
        }
    }

    /// Where a packet read from the TUN goes: the next-header to send it
    /// under and the client its destination address belongs to.
    fn route(&self, inner: &[u8]) -> Verdict<(i32, [u8; 16])> {
        let to = match inner.first().map(|byte| byte >> 4) {
            Some(4) if inner.len() >= 20 => {
                let dst: [u8; 4] = inner[16..20].try_into().unwrap();
                self.by_v4.get(&dst).map(|client| (PROTO_IPV4, *client))
            }
            Some(6) if inner.len() >= 40 => {
                let dst: [u8; 16] = inner[24..40].try_into().unwrap();
                Some((PROTO_IPV6, dst))
            }
            _ => None,
        };
        let Some((proto, client)) = to else {
            return Verdict::Refused;
        };
        match self.by_v6.get(&client) {
            Some(Client::Static) => Verdict::Carry((proto, client), None),
            Some(Client::Member(account)) if account.funded() => Verdict::Carry((proto, client), Some(account.clone())),
            Some(Client::Member(_)) => Verdict::Exhausted,
            None => Verdict::Refused,
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
    /// Packets of members whose account had no bytes left, either way.
    exhausted: AtomicU64,
    unrouted: AtomicU64,
    send_failed: AtomicU64,
    dns_answered: AtomicU64,
    dns_refused: AtomicU64,
    dns_failed: AtomicU64,
}

static RELOAD: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hangup(_: libc::c_int) {
    RELOAD.store(true, Ordering::Relaxed);
}

struct State {
    clients_path: String,
    clients: RwLock<Clients>,
    counters: Counters,
    /// When this daemon started, in nanoseconds: a different number after
    /// every start. Whoever keeps accounts here reads it (`stat`) to know
    /// that the table is empty again.
    epoch: u64,
    /// Whether the resolver is answering.
    resolver: AtomicBool,
}

impl State {
    /// The table, for reading. A thread that panicked while it held the lock
    /// must not take the packet threads with it: the table is still a table.
    fn clients(&self) -> RwLockReadGuard<'_, Clients> {
        self.clients.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn clients_mut(&self) -> RwLockWriteGuard<'_, Clients> {
        self.clients.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Re-read the client list if a SIGHUP asked for it. A list that cannot
    /// be read leaves the current one in place. The accounts stay as they
    /// are either way: `fips-exit add` and `remove` send this signal.
    fn reload_if_asked(&self) {
        if !RELOAD.swap(false, Ordering::Relaxed) {
            return;
        }
        match std::fs::read_to_string(&self.clients_path) {
            Ok(text) => {
                let list = parse_list(&text);
                eprintln!("fips-exitd: client list reloaded, {} client(s)", list.len());
                self.clients_mut().set_list(list, Instant::now());
            }
            Err(e) => eprintln!("fips-exitd: {}: {e}; keeping the current list", self.clients_path),
        }
    }
}

/// Count a packet that was passed on against the account that pays for it.
fn bill(counter: &AtomicU64, bytes: usize) {
    counter.fetch_add(bytes as u64, Ordering::Relaxed);
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
        // The lock is given back before the write: it never spans a syscall.
        let verdict = state.clients().admits(proto, &from.sin6_addr.s6_addr, inner);
        let payer = match verdict {
            Verdict::Carry((), payer) => payer,
            Verdict::Exhausted => {
                state.counters.exhausted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Verdict::Refused => {
                state.counters.refused.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        // A failed write is that packet's loss (the TUN's queue is full),
        // and nobody's bill: only what was passed on is counted.
        if unsafe { libc::write(tun, inner.as_ptr().cast(), inner.len()) } != inner.len() as isize {
            continue;
        }
        state.counters.to_internet.fetch_add(1, Ordering::Relaxed);
        if let Some(account) = payer {
            bill(&account.used_in, inner.len());
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
        let verdict = state.clients().route(inner);
        let (proto, client, payer) = match verdict {
            Verdict::Carry((proto, client), payer) => (proto, client, payer),
            Verdict::Exhausted => {
                state.counters.exhausted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Verdict::Refused => {
                state.counters.unrouted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
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
        if let Some(account) = payer {
            bill(&account.used_out, inner.len());
        }
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
/// And of those, the most for one client. A query whose upstreams are all
/// silent holds its place for their timeouts together; without this, one
/// client asking fast enough has every place and nobody else gets a name.
const DNS_IN_FLIGHT_PER_CLIENT: usize = 16;

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

/// The queries being forwarded: how many in all, and how many for each
/// client.
#[derive(Default)]
struct InFlight(Mutex<(usize, HashMap<[u8; 16], usize>)>);

impl InFlight {
    /// Take a place for a query of `client`'s, if there is one left in all
    /// and one left of its own.
    fn enter(&self, client: [u8; 16]) -> bool {
        let mut places = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (all, each) = &mut *places;
        let its = each.entry(client).or_insert(0);
        if *all >= DNS_IN_FLIGHT || *its >= DNS_IN_FLIGHT_PER_CLIENT {
            if *its == 0 {
                each.remove(&client);
            }
            return false;
        }
        *all += 1;
        *its += 1;
        true
    }

    /// Give the place back.
    fn leave(&self, client: &[u8; 16]) {
        let mut places = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let (all, each) = &mut *places;
        *all = all.saturating_sub(1);
        if let Some(its) = each.get_mut(client) {
            *its = its.saturating_sub(1);
            if *its == 0 {
                each.remove(client);
            }
        }
    }
}

/// The resolver: UDP port 53 on this node's fips address. Answers clients
/// only — the operator's list, and members of an account that has bytes left
/// (the source of a packet on the mesh is its sender's fips address: fips
/// authenticates it) — so this is not an open resolver for the mesh. A
/// query is not counted against an account. Returns only if the socket
/// fails.
fn serve_dns(state: Arc<State>, socket: UdpSocket, upstreams: Vec<SocketAddr>) -> io::Error {
    let socket = Arc::new(socket);
    let upstreams = Arc::new(upstreams);
    let in_flight: Arc<InFlight> = Arc::default();
    let mut buf = [0u8; DNS_BUFFER];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return e,
        };
        state.reload_if_asked();
        let IpAddr::V6(source) = peer.ip() else { continue };
        let source = source.octets();
        let listed = state.clients().resolves_for(&source);
        // A response bit set is not a query: never answer an answer.
        if !listed || n < 12 || buf[2] & 0x80 != 0 {
            state.counters.dns_refused.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if !in_flight.enter(source) {
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
            in_flight.leave(&source);
        });
    }
}

// ---- The control socket -----------------------------------------------------
//
// How accounts come to be: a Unix socket for whatever sells access. One
// command a line, words with spaces between them, and every answer ends in a
// line that begins `ok` or `err`. Every number is a total and never a
// difference, so a command sent again because its answer was lost changes
// nothing.
//
//   put <account> <granted> <used_in> <used_out> <address,…|->
//   grant <account> <granted>
//   members <account> <address,…|->
//   drop <account>
//   usage [account]
//   check <address>
//   stat
//
// Whoever may connect decides who uses the exit and for how much; it cannot
// touch the operator's list, name a file, or run anything.

/// The longest line read.
const CONTROL_MAX_LINE: usize = 4096;
/// Connections served at once; one more is closed at once.
const CONTROL_CONNECTIONS: usize = 4;
/// How long a peer may be silent, and how long one line may take to arrive.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest number taken. Far above any real count of bytes, and far
/// enough below the top of a u64 that adding real traffic to it cannot wrap.
const MAX_NUMBER: u64 = u64::MAX / 4;

#[derive(Debug, PartialEq)]
enum Command {
    Put { name: String, numbers: [u64; 3], members: Vec<[u8; 16]> },
    Grant { name: String, granted: u64 },
    Members { name: String, members: Vec<[u8; 16]> },
    Drop { name: String },
    Usage { name: Option<String> },
    Check { addr: [u8; 16] },
    Stat,
}

/// An account's name: 1 to 64 of `A-Z a-z 0-9 . _ -`.
fn account_name(word: &str) -> Result<String, String> {
    let fits = (1..=64).contains(&word.len())
        && word.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if fits { Ok(word.to_string()) } else { Err("name".into()) }
}

/// A count of bytes: digits only, at most [`MAX_NUMBER`].
fn number(word: &str) -> Result<u64, String> {
    if word.is_empty() || word.len() > 20 || !word.bytes().all(|b| b.is_ascii_digit()) {
        return Err("number".into());
    }
    match word.parse::<u64>() {
        Ok(value) if value <= MAX_NUMBER => Ok(value),
        _ => Err("number".into()),
    }
}

/// A fips address.
fn address(word: &str) -> Result<[u8; 16], String> {
    match word.parse::<Ipv6Addr>() {
        Ok(addr) if addr.octets()[0] == 0xfd => Ok(addr.octets()),
        _ => Err("address".into()),
    }
}

/// An account's members: fips addresses with commas between them, or `-`
/// for none. No address twice, and no more than [`MAX_MEMBERS`].
fn member_list(word: &str) -> Result<Vec<[u8; 16]>, String> {
    let mut members = Vec::new();
    if word == "-" {
        return Ok(members);
    }
    for part in word.split(',') {
        let addr = address(part)?;
        if members.contains(&addr) {
            return Err("duplicate".into());
        }
        if members.len() >= MAX_MEMBERS {
            return Err("too-many-members".into());
        }
        members.push(addr);
    }
    Ok(members)
}

/// One line as a command. The bytes are a peer's: anything that is not
/// exactly a command is an error, and nothing here can panic on them.
fn parse_command(line: &[u8]) -> Result<Command, String> {
    let Ok(line) = std::str::from_utf8(line) else {
        return Err("syntax".into());
    };
    if !line.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
        return Err("syntax".into());
    }
    let words: Vec<&str> = line.split(' ').filter(|word| !word.is_empty()).collect();
    match words.as_slice() {
        ["put", name, granted, used_in, used_out, members] => Ok(Command::Put {
            name: account_name(name)?,
            numbers: [number(granted)?, number(used_in)?, number(used_out)?],
            members: member_list(members)?,
        }),
        ["grant", name, granted] => Ok(Command::Grant { name: account_name(name)?, granted: number(granted)? }),
        ["members", name, members] => {
            Ok(Command::Members { name: account_name(name)?, members: member_list(members)? })
        }
        ["drop", name] => Ok(Command::Drop { name: account_name(name)? }),
        ["usage"] => Ok(Command::Usage { name: None }),
        ["usage", name] => Ok(Command::Usage { name: Some(account_name(name)?) }),
        ["check", addr] => Ok(Command::Check { addr: address(addr)? }),
        ["stat"] => Ok(Command::Stat),
        [] => Err("syntax".into()),
        [
            "put" | "grant" | "members" | "drop" | "usage" | "check" | "stat",
            ..,
        ] => Err("arguments".into()),
        _ => Err("command".into()),
    }
}

/// How each member sits, for the answer to `put` and `members`.
fn seats_line(seats: &Seats) -> String {
    let mut line = String::from("ok");
    for (addr, seat) in seats {
        line.push_str(&format!(" {}={}", Ipv6Addr::from(*addr), seat.word()));
    }
    line.push('\n');
    line
}

/// Do what one line asks and give the answer, its last line beginning `ok`
/// or `err`. A line that is not a command changes nothing.
fn control_reply(state: &State, line: &[u8], now: Instant) -> String {
    let command = match parse_command(line) {
        Ok(command) => command,
        Err(reason) => return format!("err {reason}\n"),
    };
    let done = match command {
        Command::Put { name, numbers, members } => {
            state.clients_mut().put(&name, numbers, members, now).map(|seats| seats_line(&seats))
        }
        Command::Members { name, members } => {
            state.clients_mut().set_members(&name, members, now).map(|seats| seats_line(&seats))
        }
        Command::Grant { name, granted } => {
            if state.clients().grant(&name, granted) { Ok("ok\n".into()) } else { Err("no-account".into()) }
        }
        Command::Drop { name } => {
            if state.clients_mut().drop_account(&name, now) { Ok("ok\n".into()) } else { Err("no-account".into()) }
        }
        Command::Usage { name } => {
            let lines = state.clients().usage(name.as_deref());
            if name.is_some() && lines.is_empty() {
                Err("no-account".into())
            } else {
                let mut reply: String = lines.iter().map(|line| format!("{line}\n")).collect();
                reply.push_str(&format!("ok {}\n", lines.len()));
                Ok(reply)
            }
        }
        Command::Check { addr } => Ok(format!("ok {}\n", state.clients().check(&addr, now))),
        Command::Stat => Ok(format!(
            "ok epoch={} accounts={} resolver={}\n",
            state.epoch,
            state.clients().accounts.len(),
            u8::from(state.resolver.load(Ordering::Relaxed))
        )),
    };
    done.unwrap_or_else(|reason: String| format!("err {reason}\n"))
}

/// Listen at `path`, for root alone. A socket an earlier run left there is
/// replaced; anything else at that path is not this daemon's to remove.
fn control_listener(path: &str) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists and is not a socket")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // The mode comes from the umask, so the socket is never there with a
    // wider one, not even for a moment.
    let before = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(path);
    unsafe { libc::umask(before) };
    listener
}

enum Line {
    Read,
    TooLong,
    /// The peer closed, was silent for too long, or took too long over a line.
    Over,
}

/// Read one line into `line`, without its end: at most [`CONTROL_MAX_LINE`]
/// bytes, and all of it within [`CONTROL_TIMEOUT`].
fn read_line(reader: &mut BufReader<&UnixStream>, line: &mut Vec<u8>) -> Line {
    line.clear();
    let deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Line::Over,
        };
        if available.is_empty() {
            return Line::Over;
        }
        let (take, ended) = match available.iter().position(|byte| *byte == b'\n') {
            Some(at) => (at, true),
            None => (available.len(), false),
        };
        if line.len() + take > CONTROL_MAX_LINE {
            return Line::TooLong;
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(ended));
        if ended {
            return Line::Read;
        }
        if Instant::now() >= deadline {
            return Line::Over;
        }
    }
}

/// One peer, until it closes or goes silent. A line that is not a command
/// gets an error and the next line is read; a line without an end within
/// the limit ends the session, since nothing after it can be told apart.
fn control_session(state: &State, stream: &UnixStream) {
    let _ = stream.set_read_timeout(Some(CONTROL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONTROL_TIMEOUT));
    let mut reader = BufReader::new(stream);
    let mut writer = stream;
    let mut line = Vec::new();
    loop {
        match read_line(&mut reader, &mut line) {
            Line::Read => {}
            Line::TooLong => {
                let _ = writer.write_all(b"err line\n");
                return;
            }
            Line::Over => return,
        }
        state.reload_if_asked();
        if writer.write_all(control_reply(state, &line, Instant::now()).as_bytes()).is_err() {
            return;
        }
    }
}

/// One of the [`CONTROL_CONNECTIONS`] places, given back when it is dropped.
struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The control socket: a thread for each peer, [`CONTROL_CONNECTIONS`] at
/// most. Returns only if the socket fails.
fn serve_control(state: Arc<State>, listener: UnixListener) -> io::Error {
    let open = Arc::new(AtomicUsize::new(0));
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return e,
        };
        // Counted down when the session ends, however it ends.
        let place = Place(open.clone());
        if open.fetch_add(1, Ordering::Relaxed) >= CONTROL_CONNECTIONS {
            continue;
        }
        let state = state.clone();
        std::thread::spawn(move || {
            let _place = place;
            control_session(&state, &stream);
        });
    }
}

struct Args {
    clients: String,
    mesh_if: String,
    tun: String,
    /// Where the control socket is; empty for none.
    control: String,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        clients: "/etc/fips-exit/clients".into(),
        mesh_if: "fips0".into(),
        tun: "fipsexit0".into(),
        control: String::new(),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let slot = match flag.as_str() {
            "--clients" => &mut args.clients,
            "--mesh-if" => &mut args.mesh_if,
            "--tun" => &mut args.tun,
            "--control" => &mut args.control,
            other => {
                return Err(format!(
                    "unknown argument {other}\n\
                     usage: fips-exitd [--clients FILE] [--mesh-if IF] [--tun NAME] [--control SOCKET]"
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

    let mut clients = Clients::default();
    match std::fs::read_to_string(&args.clients) {
        Ok(text) => clients.set_list(parse_list(&text), Instant::now()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", args.clients)),
    }
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
        epoch: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_nanos() as u64),
        resolver: AtomicBool::new(false),
    });

    // Accounts, for whatever sells access. After the TUN, which a second
    // daemon could not have opened: the socket of a running one is never
    // replaced. A socket that cannot be made is said loudly and is not
    // fatal: the clients on the operator's list are carried without it, and
    // nobody else is.
    if !args.control.is_empty() {
        match control_listener(&args.control) {
            Ok(listener) => {
                eprintln!("fips-exitd: accounts over {}", args.control);
                let state = state.clone();
                std::thread::spawn(move || {
                    let e = serve_control(state, listener);
                    eprintln!("fips-exitd: NO ACCOUNTS: control socket: {e}");
                });
            }
            Err(e) => eprintln!("fips-exitd: NO ACCOUNTS: {}: {e}", args.control),
        }
    }

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
                    state.resolver.store(true, Ordering::Relaxed);
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
        // Once a minute, and only if something moved: a line for the journal.
        let state = state.clone();
        std::thread::spawn(move || {
            let mut last = (0, 0, 0, 0, 0, 0, 0, 0);
            loop {
                std::thread::sleep(Duration::from_secs(60));
                state.reload_if_asked();
                let c = &state.counters;
                let now = (
                    c.to_internet.load(Ordering::Relaxed),
                    c.to_clients.load(Ordering::Relaxed),
                    c.refused.load(Ordering::Relaxed),
                    c.exhausted.load(Ordering::Relaxed),
                    c.unrouted.load(Ordering::Relaxed),
                    c.dns_answered.load(Ordering::Relaxed),
                    c.dns_refused.load(Ordering::Relaxed),
                    c.dns_failed.load(Ordering::Relaxed),
                );
                if now != last {
                    eprintln!(
                        "fips-exitd: packets to internet {}, to clients {}, refused {}, out of bytes {}, \
                         unrouted {}; DNS answered {}, refused {}, failed {}",
                        now.0, now.1, now.2, now.3, now.4, now.5, now.6, now.7
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
        // The same list as it is read at a reload.
        assert_eq!(parse_list(&format!("{A}\n{A} again\nnot-an-address\n")), vec![addr(A)]);
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
        assert!(c.admits(PROTO_IPV4, &a, &v4(inner_ipv4(&a), internet4, 60)).carried().is_some());
        assert!(c.admits(PROTO_IPV6, &a, &v6(a, internet6, 60)).carried().is_some());
        // Another client's address, in either family.
        assert!(c.admits(PROTO_IPV4, &a, &v4(inner_ipv4(&b), internet4, 60)).carried().is_none());
        assert!(c.admits(PROTO_IPV6, &a, &v6(b, internet6, 60)).carried().is_none());
        // An address that is nobody's.
        assert!(c.admits(PROTO_IPV4, &a, &v4([192, 168, 1, 5], internet4, 60)).carried().is_none());
        // The wrong family for the next-header, and a length that lies.
        assert!(c.admits(PROTO_IPV6, &a, &v4(inner_ipv4(&a), internet4, 60)).carried().is_none());
        assert!(c.admits(PROTO_IPV4, &a, &v6(a, internet6, 60)).carried().is_none());
        let mut short = v4(inner_ipv4(&a), internet4, 60);
        short.truncate(40);
        assert!(c.admits(PROTO_IPV4, &a, &short).carried().is_none());
        // A node that is not a client, even with a plausible packet.
        let stranger = addr("fd77::7");
        assert!(c.admits(PROTO_IPV4, &stranger, &v4(inner_ipv4(&stranger), internet4, 60)).carried().is_none());
        assert!(c.admits(PROTO_IPV6, &stranger, &v6(stranger, internet6, 60)).carried().is_none());
    }

    #[test]
    fn a_reply_goes_to_the_client_its_destination_belongs_to() {
        let c = clients();
        let (a, b) = (addr(A), addr(B));
        assert_eq!(c.route(&v4([1, 1, 1, 1], inner_ipv4(&b), 60)).carried(), Some((PROTO_IPV4, b)));
        assert_eq!(c.route(&v6([0x20; 16], a, 60)).carried(), Some((PROTO_IPV6, a)));
        // Nobody's address, too short, not IP.
        assert_eq!(c.route(&v4([1, 1, 1, 1], [100, 64, 9, 9], 60)).carried(), None);
        assert_eq!(c.route(&v6([0x20; 16], addr("fd77::7"), 60)).carried(), None);
        assert_eq!(c.route(&[0x45; 10]).carried(), None);
        assert_eq!(c.route(&[]).carried(), None);
    }

    // ---- accounts ---------------------------------------------------------------

    const C: &str = "fd55:aaaa:bbbb:cccc::3";
    const D: &str = "fd66:1234:5678:9abc::4";

    fn at(clients: &mut Clients, line: &str, now: Instant) -> String {
        let state = State {
            clients_path: String::new(),
            clients: RwLock::new(std::mem::take(clients)),
            counters: Counters::default(),
            epoch: 7,
            resolver: AtomicBool::new(true),
        };
        let reply = control_reply(&state, line.as_bytes(), now);
        *clients = std::mem::take(&mut *state.clients_mut());
        reply
    }

    fn ctl(clients: &mut Clients, line: &str) -> String {
        at(clients, line, Instant::now())
    }

    /// Carry a packet as the daemon's loops do: ask, and count it if carried.
    fn send(c: &Clients, from: [u8; 16], len: usize) -> bool {
        match c.admits(PROTO_IPV6, &from, &v6(from, [0x20; 16], len)) {
            Verdict::Carry((), payer) => {
                if let Some(account) = payer {
                    bill(&account.used_in, len);
                }
                true
            }
            _ => false,
        }
    }

    fn reply_to(c: &Clients, to: [u8; 16], len: usize) -> bool {
        match c.route(&v6([0x20; 16], to, len)) {
            Verdict::Carry(_, payer) => {
                if let Some(account) = payer {
                    bill(&account.used_out, len);
                }
                true
            }
            _ => false,
        }
    }

    #[test]
    fn a_member_is_carried_while_its_account_has_bytes() {
        let mut c = clients();
        let m = addr(C);
        // Not a client at all.
        assert!(!send(&c, m, 100));
        // A member of an account with nothing granted: known, and not carried.
        assert_eq!(ctl(&mut c, &format!("put pkg 0 0 0 {C}")), format!("ok {C}=v4\n"));
        assert!(matches!(c.admits(PROTO_IPV6, &m, &v6(m, [0x20; 16], 100)), Verdict::Exhausted));
        assert!(matches!(c.route(&v6([0x20; 16], m, 100)), Verdict::Exhausted));
        assert!(!c.resolves_for(&m), "no names for an account without bytes");
        // Granted 250 bytes: 100 out, 100 back, and the packet that crosses
        // the line is the last one carried, in either direction.
        assert_eq!(ctl(&mut c, "grant pkg 250"), "ok\n");
        assert!(c.resolves_for(&m));
        assert!(send(&c, m, 100));
        assert!(reply_to(&c, m, 100));
        assert!(send(&c, m, 100), "200 of 250 used: the next packet is carried");
        assert!(!send(&c, m, 100), "300 of 250 used");
        assert!(!reply_to(&c, m, 100));
        assert!(!c.resolves_for(&m));
        assert_eq!(ctl(&mut c, "usage pkg"), "account pkg 250 200 100\nok 1\n");
        // More is granted: it is carried again, from where it stood.
        assert_eq!(ctl(&mut c, "grant pkg 1000"), "ok\n");
        assert!(send(&c, m, 100));
        assert_eq!(ctl(&mut c, "usage"), "account pkg 1000 300 100\nok 1\n");
        // IPv4 too, from its own derived address.
        assert!(c.admits(PROTO_IPV4, &m, &v4(inner_ipv4(&m), [1, 1, 1, 1], 60)).carried().is_some());
        assert_eq!(c.route(&v4([1, 1, 1, 1], inner_ipv4(&m), 60)).carried(), Some((PROTO_IPV4, m)));
        // A client on the operator's list is carried and never counted.
        assert!(send(&c, addr(A), 1280));
        assert_eq!(ctl(&mut c, "usage"), "account pkg 1000 300 100\nok 1\n");
    }

    #[test]
    fn members_of_one_account_share_its_bytes() {
        let mut c = Clients::default();
        assert_eq!(ctl(&mut c, &format!("put shared 300 0 0 {C},{D}")), format!("ok {C}=v4 {D}=v4\n"));
        assert!(send(&c, addr(C), 200));
        assert!(send(&c, addr(D), 200), "200 of 300 used: carried");
        assert!(!send(&c, addr(C), 60), "what one used the other has not");
        assert!(!send(&c, addr(D), 60));
        // An address is in one account.
        assert_eq!(ctl(&mut c, &format!("put other 100 0 0 {D}")), format!("err elsewhere {D}\n"));
        assert_eq!(ctl(&mut c, "usage other"), "err no-account\n", "a refused put makes nothing");
        // Taken out of the first, it can join the second, and is carried on that one's bytes.
        assert_eq!(ctl(&mut c, &format!("members shared {C}")), format!("ok {C}=v4\n"));
        assert_eq!(ctl(&mut c, &format!("put other 100 0 0 {D}")), format!("ok {D}=v4\n"));
        assert!(send(&c, addr(D), 60));
        assert!(!send(&c, addr(C), 60));
        // Dropped: its member is nobody.
        assert_eq!(ctl(&mut c, "drop other"), "ok\n");
        assert!(matches!(c.admits(PROTO_IPV6, &addr(D), &v6(addr(D), [0x20; 16], 60)), Verdict::Refused));
        assert_eq!(ctl(&mut c, "drop other"), "err no-account\n");
    }

    /// Every number is a total. A command that arrives again, or after a
    /// later one, takes nothing back and gives nothing twice.
    #[test]
    fn a_command_sent_twice_changes_nothing() {
        let mut c = Clients::default();
        let put = format!("put pkg 1000 400 100 {C}");
        assert_eq!(ctl(&mut c, &put), format!("ok {C}=v4\n"));
        assert!(send(&c, addr(C), 50));
        assert_eq!(ctl(&mut c, "usage"), "account pkg 1000 450 100\nok 1\n");
        // The same put again, and an older grant: the counts stay.
        assert_eq!(ctl(&mut c, &put), format!("ok {C}=v4\n"));
        assert_eq!(ctl(&mut c, "grant pkg 500"), "ok\n");
        assert_eq!(ctl(&mut c, "grant pkg 1000"), "ok\n");
        assert_eq!(ctl(&mut c, "usage"), "account pkg 1000 450 100\nok 1\n");
        assert_eq!(ctl(&mut c, "grant nobody 5"), "err no-account\n");
    }

    #[test]
    fn the_operators_list_wins_over_a_member() {
        let mut c = clients();
        // A is on the list: as a member it is carried as before, and not counted.
        assert_eq!(ctl(&mut c, &format!("put pkg 0 0 0 {A},{C}")), format!("ok {A}=static {C}=v4\n"));
        assert!(send(&c, addr(A), 100));
        assert!(!send(&c, addr(C), 100));
        assert_eq!(ctl(&mut c, "usage"), "account pkg 0 0 0\nok 1\n");
        assert_eq!(ctl(&mut c, &format!("check {A}")), "ok static\n");
        // The list is read again without A, and with a new client that has
        // C's inner IPv4 address. The account is still there; A is now only
        // a member; the new client takes the IPv4 address from C.
        let rival = "fd95:aaaa::9";
        assert_eq!(inner_ipv4(&addr(rival)), inner_ipv4(&addr(C)));
        c.set_list(parse_list(&format!("{B}\n{rival}\n")), Instant::now());
        assert_eq!(c.len(), 2);
        assert!(!send(&c, addr(A), 100), "a member now, of an account without bytes");
        assert_eq!(ctl(&mut c, "grant pkg 10000"), "ok\n");
        assert!(send(&c, addr(A), 100));
        assert_eq!(ctl(&mut c, &format!("check {C}")), "ok member pkg no4\n");
        assert_eq!(c.route(&v4([1, 1, 1, 1], inner_ipv4(&addr(C)), 60)).carried(), Some((PROTO_IPV4, addr(rival))));
        assert_eq!(ctl(&mut c, "usage"), "account pkg 10000 100 0\nok 1\n");
    }

    /// Two addresses that derive one inner IPv4 address: the first keeps it,
    /// and the second, admitted for IPv6 only, cannot send as the first.
    #[test]
    fn a_member_without_its_ipv4_address_cannot_send_as_its_holder() {
        let mut c = Clients::default();
        let (first, second) = (addr(C), addr("fd95:aaaa::9"));
        assert_eq!(inner_ipv4(&first), inner_ipv4(&second));
        assert_eq!(ctl(&mut c, &format!("check {C}")), "ok free v4\n");
        assert_eq!(ctl(&mut c, &format!("put one 10000 0 0 {C}")), format!("ok {C}=v4\n"));
        assert_eq!(ctl(&mut c, "check fd95:aaaa::9"), "ok free no4\n");
        assert_eq!(ctl(&mut c, "put two 10000 0 0 fd95:aaaa::9"), "ok fd95:aaaa::9=no4\n");
        // IPv6 for both, each as itself.
        assert!(send(&c, first, 60));
        assert!(send(&c, second, 60));
        // IPv4 from the address both derive: the holder's packet only.
        let packet = v4(inner_ipv4(&first), [1, 1, 1, 1], 60);
        assert!(c.admits(PROTO_IPV4, &first, &packet).carried().is_some());
        assert!(matches!(c.admits(PROTO_IPV4, &second, &packet), Verdict::Refused));
        assert_eq!(c.route(&v4([1, 1, 1, 1], inner_ipv4(&first), 60)).carried(), Some((PROTO_IPV4, first)));
    }

    /// An inner IPv4 address that was given up is its last holder's alone
    /// for a while, and then anybody's.
    #[test]
    fn an_ipv4_address_given_up_is_not_handed_on_at_once() {
        let mut c = Clients::default();
        let t0 = Instant::now();
        let rival = "fd95:aaaa::9";
        assert_eq!(at(&mut c, &format!("put one 100 0 0 {C}"), t0), format!("ok {C}=v4\n"));
        assert_eq!(at(&mut c, "drop one", t0), "ok\n");
        assert_eq!(at(&mut c, &format!("check {rival}"), t0), "ok free no4\n");
        assert_eq!(at(&mut c, &format!("put two 100 0 0 {rival}"), t0), format!("ok {rival}=no4\n"));
        // The last holder may have it back at once.
        assert_eq!(at(&mut c, &format!("check {C}"), t0), "ok free v4\n");
        // After the wait the other gets it, the next time its account is put.
        let later = t0 + HOLD_DOWN + Duration::from_secs(1);
        assert_eq!(at(&mut c, &format!("check {rival}"), later), "ok member two no4\n");
        assert_eq!(at(&mut c, &format!("put two 100 0 0 {rival}"), later), format!("ok {rival}=v4\n"));
        assert_eq!(at(&mut c, &format!("put one 100 0 0 {C}"), later), format!("ok {C}=no4\n"));
    }

    #[test]
    fn a_reload_of_the_list_leaves_the_accounts() {
        let mut c = clients();
        assert_eq!(ctl(&mut c, &format!("put pkg 500 0 0 {C}")), format!("ok {C}=v4\n"));
        assert!(send(&c, addr(C), 100));
        for list in [format!("{A}\n"), String::new(), format!("{A}\n{B}\n")] {
            c.set_list(parse_list(&list), Instant::now());
            assert!(send(&c, addr(C), 100), "after a reload to {list:?}");
        }
        assert_eq!(ctl(&mut c, "usage"), "account pkg 500 400 0\nok 1\n");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn the_limits_on_accounts_and_members_hold() {
        let mut c = Clients::default();
        let many: Vec<String> = (0..=MAX_MEMBERS).map(|i| format!("fd00:{i:x}::1")).collect();
        assert_eq!(ctl(&mut c, &format!("put pkg 1 0 0 {}", many.join(","))), "err too-many-members\n");
        assert!(ctl(&mut c, &format!("put pkg 1 0 0 {}", many[..MAX_MEMBERS].join(","))).starts_with("ok "));
        assert_eq!(ctl(&mut c, &format!("put pkg 1 0 0 {C},{C}")), "err duplicate\n");
        for i in 1..MAX_ACCOUNTS {
            assert_eq!(ctl(&mut c, &format!("put a{i} 1 0 0 -")), "ok\n");
        }
        assert_eq!(ctl(&mut c, "put one-too-many 1 0 0 -"), "err too-many-accounts\n");
        assert_eq!(ctl(&mut c, "put a1 2 0 0 -"), "ok\n", "an account that exists can still be put");
        assert!(ctl(&mut c, "stat").starts_with(&format!("ok epoch=7 accounts={MAX_ACCOUNTS} resolver=1")));
    }

    #[test]
    fn a_line_is_a_command_or_an_error() {
        let fd = |text: &str| addr(text);
        assert_eq!(
            parse_command(b"put pkg-1.a_B 10 2 3 fd11::1,fd22::2"),
            Ok(Command::Put {
                name: "pkg-1.a_B".into(),
                numbers: [10, 2, 3],
                members: vec![fd("fd11::1"), fd("fd22::2")]
            })
        );
        assert_eq!(parse_command(b"  stat  "), Ok(Command::Stat));
        assert_eq!(parse_command(b"usage"), Ok(Command::Usage { name: None }));
        assert_eq!(parse_command(b"members x -"), Ok(Command::Members { name: "x".into(), members: vec![] }));
        let bad = |line: &[u8], why: &str| assert_eq!(parse_command(line), Err(why.to_string()), "{:?}", line);
        bad(b"", "syntax");
        bad(b"   ", "syntax");
        bad(b"stat\t", "syntax");
        bad(b"stat\0", "syntax");
        bad("stät".as_bytes(), "syntax");
        bad(&[0xff, 0xfe, b' ', 0x80], "syntax");
        bad(b"reboot now", "command");
        bad(b"PUT a 1 0 0 -", "command");
        bad(b"stat please", "arguments");
        bad(b"put pkg 10 2 3", "arguments");
        bad(b"grant pkg", "arguments");
        bad(b"grant a/b 1", "name");
        bad(b"grant ../../etc/passwd 1", "name");
        bad(format!("grant {} 1", "a".repeat(65)).as_bytes(), "name");
        bad(b"grant pkg -1", "number");
        bad(b"grant pkg +1", "number");
        bad(b"grant pkg 1e3", "number");
        bad(b"grant pkg 0x10", "number");
        bad(b"grant pkg 18446744073709551615", "number");
        bad(b"grant pkg 99999999999999999999999", "number");
        bad(format!("grant pkg {}", MAX_NUMBER as u128 + 1).as_bytes(), "number");
        assert!(parse_command(format!("grant pkg {MAX_NUMBER}").as_bytes()).is_ok());
        bad(b"check 2001:db8::1", "address");
        bad(b"check fd11::1%eth0", "address");
        bad(b"check 10.0.0.1", "address");
        bad(b"members x fd11::1,", "address");
        bad(b"members x ,", "address");
        bad(b"members x fd11::1,fd11:0::1", "duplicate");
    }

    /// The parser reads bytes anyone on the socket chose. Whatever they are,
    /// it answers, and the table is as it was.
    #[test]
    fn no_line_makes_the_parser_panic_or_the_table_change() {
        let mut c = Clients::default();
        assert_eq!(ctl(&mut c, &format!("put pkg 500 1 2 {C}")), format!("ok {C}=v4\n"));
        let words: [&[u8]; 14] = [
            b"put", b"grant", b"members", b"drop", b"usage", b"check", b"stat", b"pkg", b"-", b"1",
            b"fd55:aaaa:bbbb:cccc::3", b",", b"\xff", b"99999999999999999999",
        ];
        // A fixed sequence, not a random one: the same lines every run.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let mut line = Vec::new();
            for _ in 0..next() % 9 {
                match next() % 4 {
                    0 => line.push((next() % 256) as u8),
                    1 => line.push(b' '),
                    _ => line.extend_from_slice(words[(next() % words.len() as u64) as usize]),
                }
            }
            // Anything that would change the account is left out; the rest
            // must be answered and must leave it alone.
            let changes = matches!(
                parse_command(&line),
                Ok(Command::Put { .. } | Command::Grant { .. } | Command::Members { .. } | Command::Drop { .. })
            );
            if changes {
                continue;
            }
            let reply = at(&mut c, &String::from_utf8_lossy(&line), Instant::now());
            assert!(reply.ends_with('\n') && !reply.is_empty());
            let last = reply.trim_end().lines().last().unwrap_or("");
            assert!(last.starts_with("ok") || last.starts_with("err "), "{line:?} -> {reply:?}");
        }
        assert_eq!(ctl(&mut c, "usage"), "account pkg 500 1 2\nok 1\n");
    }

    /// The socket itself: root's alone, a line too long ends the session,
    /// and a line that is not a command does not.
    #[test]
    fn the_socket_answers_a_line_at_a_time() {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fips-exitd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let path = path.to_str().unwrap();
        // Something that is not a socket is left alone.
        std::fs::write(path, "not a socket").unwrap();
        assert!(control_listener(path).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "not a socket");
        std::fs::remove_file(path).unwrap();
        // A socket from an earlier run is replaced.
        drop(control_listener(path).unwrap());
        let listener = control_listener(path).unwrap();
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);

        let state = Arc::new(State {
            clients_path: String::new(),
            clients: RwLock::new(Clients::default()),
            counters: Counters::default(),
            epoch: 42,
            resolver: AtomicBool::new(false),
        });
        std::thread::spawn(move || serve_control(state, listener));

        let talk = |lines: &[u8]| {
            let mut stream = UnixStream::connect(path).unwrap();
            stream.write_all(lines).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            reply
        };
        assert_eq!(talk(b"stat\n"), "ok epoch=42 accounts=0 resolver=0\n");
        let mut lines = b"nonsense\n\xff\xfe\n".to_vec();
        lines.extend_from_slice(format!("put pkg 9 0 0 {C}\nusage\n").as_bytes());
        assert_eq!(talk(&lines), format!("err command\nerr syntax\nok {C}=v4\naccount pkg 9 0 0\nok 1\n"));
        // The account outlives the connection that made it.
        assert_eq!(talk(b"usage pkg\n"), "account pkg 9 0 0\nok 1\n");
        // A line with no end within the limit: one answer, and nothing after
        // it is read as a command.
        let mut long = vec![b'x'; CONTROL_MAX_LINE + 1];
        long.extend_from_slice(b"\ndrop pkg\n");
        assert_eq!(talk(&long), "err line\n");
        assert_eq!(talk(b"usage pkg\n"), "account pkg 9 0 0\nok 1\n");
        // A line of exactly the limit is still a line.
        let mut full = vec![b' '; CONTROL_MAX_LINE - 4];
        full.extend_from_slice(b"stat\n");
        assert_eq!(talk(&full), "ok epoch=42 accounts=1 resolver=0\n");
        std::fs::remove_dir_all(&dir).unwrap();
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

    /// One client cannot have every place among the queries in flight.
    #[test]
    fn a_client_has_its_own_limit_of_queries_in_flight() {
        let queries = InFlight::default();
        let (a, b) = (addr(A), addr(B));
        for _ in 0..DNS_IN_FLIGHT_PER_CLIENT {
            assert!(queries.enter(a));
        }
        assert!(!queries.enter(a), "one more than its own");
        assert!(queries.enter(b), "another client is not kept out by it");
        queries.leave(&a);
        assert!(queries.enter(a), "a place given back is a place");
        // In all: clients that each stay within their own limit fill it.
        let queries = InFlight::default();
        let mut taken = 0;
        for client in 0..=u8::MAX {
            let mut address = [0xfd; 16];
            address[15] = client;
            while taken < DNS_IN_FLIGHT + 5 && queries.enter(address) {
                taken += 1;
            }
        }
        assert_eq!(taken, DNS_IN_FLIGHT);
        // Nothing is left behind for a client that was refused or has left.
        for client in 0..=u8::MAX {
            let mut address = [0xfd; 16];
            address[15] = client;
            for _ in 0..DNS_IN_FLIGHT_PER_CLIENT {
                queries.leave(&address);
            }
        }
        let places = queries.0.lock().unwrap();
        assert_eq!((places.0, places.1.len()), (0, 0));
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
