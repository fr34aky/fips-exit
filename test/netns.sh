#!/bin/sh
# End-to-end test of fips-exit against the real kernel, without fips and
# without root: network namespaces stand in for a client, the exit and the
# internet, and a 1280-byte veth stands in for the mesh (fips0).
#
#   client c1 ─┐
#              ├─ bridge "fips0" (exit, fd00::/8, MTU 1280) ── exit ── "wan" ── inet
#   client c2 ─┘
#
# The clients use the kernel's own ip6tnl, i.e. the same wire format the
# phone speaks. Needs the daemon built (cargo build --release).
# Run as: unshare -Urnm test/netns.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
export FIPS_EXIT_DIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$FIPS_EXIT_DIR"' EXIT
mount -t tmpfs tmpfs /run

E=fd0e::1 C1=fd11:2233:4455:6677::1 C2=fd99:8877:6655:4433::2
C1V4=100.81.34.51 C2V4=100.89.136.119
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok: $*"; }

ip link set lo up
ip link add fips0 type bridge
ip link set fips0 mtu 1280 up
ip -6 addr add $E/128 dev fips0 nodad
ip -6 route add fd00::/8 dev fips0
ip link add wan type veth peer name eth0
ip link set wan up
ip addr add 8.8.8.1/24 dev wan
ip -6 addr add 2001:4860:1::1/64 dev wan nodad
# The uplink is also the operator's LAN, as on most home networks, and has
# a second public network the operator chose to block (BLOCK_CIDRS).
ip addr add 192.168.77.1/24 dev wan
ip -6 addr add fc00:77::1/64 dev wan nodad
ip addr add 9.9.9.1/24 dev wan

ip netns add inet
ip link set eth0 netns inet
ip -n inet link set lo up
ip -n inet link set eth0 up
ip -n inet addr add 8.8.8.2/24 dev eth0
ip -n inet -6 addr add 2001:4860:1::2/64 dev eth0 nodad
ip -n inet addr add 192.168.77.2/24 dev eth0
ip -n inet -6 addr add fc00:77::2/64 dev eth0 nodad
ip -n inet addr add 9.9.9.2/24 dev eth0
# No route back to anything but the exit's own uplink addresses: a reply
# only arrives if the exit masqueraded.

# Turn off transmit checksum offload on a device. Between namespaces a veth
# leaves checksums unfilled, which nothing notices while the kernel carries
# the packet end to end; here the daemon receives the tunnelled packet as
# bytes, as it does from a real mesh, and those bytes must be complete.
no_offload() { # netns device...
  ns=$1; shift
  ip netns exec "$ns" python3 -c '
import array, fcntl, socket, struct, sys
s = socket.socket()
for dev in sys.argv[1:]:
    for command in (0x17, 0x19, 0x1f):  # ETHTOOL_STXCSUM, _SSG, _STSO
        value = array.array("B", struct.pack("II", command, 0))
        try: fcntl.ioctl(s, 0x8946, struct.pack("16sP", dev.encode(), value.buffer_info()[0]))
        except OSError: pass' "$@"
}

client() { # name address ipv4
  ip netns add "$1"
  ip link add "v$1" type veth peer name fips0 netns "$1"
  ip link set "v$1" mtu 1280 master fips0 up
  ip -n "$1" link set lo up
  ip -n "$1" link set fips0 mtu 1280 up
  ip -n "$1" -6 addr add "$2/128" dev fips0 nodad
  ip -n "$1" -6 route add fd00::/8 dev fips0
  ip -n "$1" link add tun0 type ip6tnl mode any local "$2" remote $E encaplimit none
  ip -n "$1" link set tun0 mtu 1280 up
  ip -n "$1" addr add "$3/32" dev tun0
  ip -n "$1" route add default dev tun0
  ip -n "$1" -6 route add default dev tun0 src "$2"
  no_offload "$1" fips0 tun0
}
client c1 $C1 $C1V4
client c2 $C2 $C2V4
printf "WAN=wan\nFIPS_FIREWALL=\nBLOCK_CIDRS=9.9.9.0/24\n" > "$FIPS_EXIT_DIR/config"
daemon="$here/target/release/fips-exitd"
[ -x "$daemon" ] || fail "build the daemon first: cargo build --release"

# --- without the daemon, the script says so and applies nothing ----------------
"$here/fips-exit" up 2>&1 | grep -q "fips-exitd is not running" || fail "up without the daemon"
ok "up without the daemon is refused"
DNS_UPSTREAMS=8.8.8.2 "$daemon" --clients "$FIPS_EXIT_DIR/clients" --mesh-if fips0 --tun fipsexit0 2>"$FIPS_EXIT_DIR/daemon.log" &
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 && break; sleep 0.2; done
ip link show fipsexit0 >/dev/null 2>&1 || fail "the daemon did not create its TUN: $(cat "$FIPS_EXIT_DIR/daemon.log")"

# A server that answers a request "<n>" with n bytes, DF set on IPv4: what a
# QUIC server does to a client that sent a small packet.
cat > "$FIPS_EXIT_DIR/server.py" <<'PY'
import socket, sys, select
s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s4.bind(("0.0.0.0", 4444))
s4.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER = IP_PMTUDISC_DO
s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1); s6.bind(("::", 4444))
log = open(sys.argv[1], "w")
while True:
    for s in select.select([s4, s6], [], [])[0]:
        data, peer = s.recvfrom(4096)
        log.write(peer[0] + "\n"); log.flush()
        try: s.sendto(b"x" * int(data), peer)
        except OSError as e: log.write("send failed: %s\n" % e); log.flush()
PY
ip netns exec inet python3 "$FIPS_EXIT_DIR/server.py" "$FIPS_EXIT_DIR/peers" &
ask() { # netns family address size -> prints bytes received
  ip netns exec "$1" python3 -c '
import socket, sys
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM); s.settimeout(2)
for _ in range(3):
    s.sendto(sys.argv[3].encode(), (sys.argv[2], 4444))
    try: print(len(s.recv(4096))); break
    except socket.timeout: pass
else: print("timeout")' "$2" "$3" "$4"
}

# The upstream resolver the daemon forwards its clients' DNS to: answers any
# question with one A record, and a name starting "big" with far more than
# fits one mesh packet.
cat > "$FIPS_EXIT_DIR/dns.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("8.8.8.2", 53))
while True:
    q, peer = s.recvfrom(4096)
    head = q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    end = 12
    while q[end]: end += 1 + q[end]
    question = q[12:end + 5]
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
    if question[1:4] == b"big": answer += b"\x00" * 1500
    s.sendto(head + question + answer, peer)
PY
ip netns exec inet python3 "$FIPS_EXIT_DIR/dns.py" &
dns_pid=$!
resolve() { # netns name -> "answers=<n> rcode=<n> tc=<0|1>" or "timeout"
  ip netns exec "$1" python3 -c '
import socket, sys
me, exit_, name = sys.argv[1:4]
q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
for label in name.split("."): q += bytes([len(label)]) + label.encode()
q += b"\x00\x00\x01\x00\x01"
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind((me, 0)); s.settimeout(5)
s.sendto(q, (exit_, 53))
try: r = s.recv(4096)
except socket.timeout: print("timeout"); sys.exit()
assert r[:2] == q[:2] and r[2] & 0x80
print("answers=%d rcode=%d tc=%d size=%d" % (int.from_bytes(r[6:8], "big"), r[3] & 15, (r[2] >> 1) & 1, len(r)))' "$2" $E "$3"
}

# --- what a version before the daemon left behind is cleared away ---------------
# One ip6tnl device per client, named fx…. The script lists them by type,
# and on a host where the ip6_tunnel module is not loaded (any host that
# never ran that version) the kernel cannot filter by a type it does not
# know: ip filters instead and prints an empty object for each link it
# drops. Here the module is loaded, the clients use it, so a stand-in ip
# adds the empty objects.
legacy() { ip link add "$1" type ip6tnl mode any local $E remote "$2" encaplimit none; }
mkdir "$FIPS_EXIT_DIR/bin"
cat > "$FIPS_EXIT_DIR/bin/ip" <<IP
#!/bin/sh
if [ "\$*" = "-j link show type ip6tnl" ]; then
  $(command -v ip) "\$@" | sed 's/^\[/[{},/; s/\]\$/,{}]/'
else
  exec $(command -v ip) "\$@"
fi
IP
chmod +x "$FIPS_EXIT_DIR/bin/ip"
legacy fx11223344 $C1

# --- before any client is added: nothing passes -------------------------------
PATH="$FIPS_EXIT_DIR/bin:$PATH" "$here/fips-exit" up >/dev/null || fail "up with empty objects in ip's list of links"
ip link show fx11223344 >/dev/null 2>&1 && fail "up left an old fx tunnel device"
ok "up removes a tunnel device of the version before the daemon"
[ "$(ask c1 4 8.8.8.2 100)" = timeout ] || fail "traffic passed without a client entry"
[ "$(resolve c1 $C1 example.com)" = timeout ] || fail "DNS answered without a client entry"
ok "no client entry, no traffic and no DNS"

"$here/fips-exit" add $C1 phone-one >/dev/null
"$here/fips-exit" list | grep -q "$C1  $C1V4  phone-one" || fail "list: $("$here/fips-exit" list)"
ok "client added: $("$here/fips-exit" list)"

# --- both families, masqueraded -----------------------------------------------
[ "$(ask c1 4 8.8.8.2 100)" = 100 ] || fail "IPv4 through the exit"
[ "$(ask c1 6 2001:4860:1::2 100)" = 100 ] || fail "IPv6 through the exit"
grep -qx 8.8.8.1 "$FIPS_EXIT_DIR/peers" || fail "IPv4 not masqueraded: $(cat "$FIPS_EXIT_DIR/peers")"
grep -qx 2001:4860:1::1 "$FIPS_EXIT_DIR/peers" || fail "IPv6 not masqueraded: $(cat "$FIPS_EXIT_DIR/peers")"
ok "IPv4 and IPv6 reach the internet from the exit's addresses"

# --- full-size packets towards the client --------------------------------------
# 1280 bytes is the tunnel's MTU: IPv4 payload 1252 (DF set, as QUIC does),
# IPv6 payload 1232. Neither fits one mesh packet beside the outer header, so
# the exit sends two fragments of the outer packet and the client reassembles.
[ "$(ask c1 4 8.8.8.2 1252)" = 1252 ] || fail "1280-byte IPv4 packet (DF) towards the client"
[ "$(ask c1 6 2001:4860:1::2 1232)" = 1232 ] || fail "1280-byte IPv6 packet towards the client"
ok "1280-byte packets arrive in both families (outer fragments)"

# --- a 1280-byte IPv6 packet from the client ----------------------------------
# The phone sends it as two fragments of the OUTER packet; the exit's kernel
# must reassemble them before the tunnel sees the packet.
ip netns exec c1 python3 -c '
import socket, struct, sys, ipaddress
src, exit_, dst = (ipaddress.IPv6Address(a).packed for a in sys.argv[1:4])
payload = b"100".ljust(1232)
udp = struct.pack("!HHHH", 5555, 4444, 8 + len(payload), 0) + payload
pseudo = src + dst + struct.pack("!IHBB", len(udp), 0, 0, 17)
total = sum(struct.unpack("!%dH" % ((len(pseudo) + len(udp)) // 2), pseudo + udp))
while total >> 16: total = (total & 0xffff) + (total >> 16)
udp = udp[:6] + struct.pack("!H", ~total & 0xffff) + udp[8:]
inner = struct.pack("!IHBB", 0x60000000, len(udp), 17, 64) + src + dst + udp
assert len(inner) == 1280
reply = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); reply.bind((sys.argv[1], 5555)); reply.settimeout(3)
raw = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
for offset in (0, 1232):
    data = inner[offset:offset + 1232]
    frag = struct.pack("!BBHI", 41, 0, offset | (offset + len(data) < len(inner)), 0xf1b5) + data
    raw.sendto(struct.pack("!IHBB", 0x60000000, len(frag), 44, 64) + src + exit_ + frag, (sys.argv[2], 0))
print(len(reply.recv(4096)))' $C1 $E 2001:4860:1::2 | grep -qx 100 || fail "fragmented 1280-byte IPv6 packet from the client"
ok "a 1280-byte IPv6 packet sent as two outer fragments is reassembled by the exit"

# --- TCP MSS ------------------------------------------------------------------
ip netns exec inet python3 -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", 4445)); s.listen(4)
while True:
    c, _ = s.accept(); c.sendall(b"y" * 200000); c.close()' &
sleep 0.5
fetch() { ip netns exec c1 python3 -c '
import socket, sys
s = socket.create_connection((sys.argv[1], 4445), timeout=5); n = 0
while True:
    d = s.recv(65536)
    if not d: break
    n += len(d)
print(n)' "$1"; }
[ "$(fetch 8.8.8.2)" = 200000 ] || fail "TCP over IPv4"
[ "$(fetch 2001:4860:1::2)" = 200000 ] || fail "TCP over IPv6"
ok "TCP transfers complete in both families"

# --- DNS for the clients, and only for them ------------------------------------
# A phone sends its lookups to port 53 on the exit's fips address, over the
# mesh and outside the tunnel.
r=$(resolve c1 $C1 example.com)
[ "${r% size=*}" = "answers=1 rcode=0 tc=0" ] || fail "a client's DNS query: $r"
[ "$(resolve c2 $C2 example.com)" = timeout ] || fail "A NODE THAT IS NOT A CLIENT GOT DNS"
# An answer too large for one mesh packet comes back truncated, not in
# fragments.
r=$(resolve c1 $C1 big.example.com)
[ "${r% size=*}" = "answers=0 rcode=0 tc=1" ] || fail "an oversized DNS answer: $r"
[ "${r#*size=}" -le 1232 ] || fail "an oversized DNS answer was sent whole: $r"
ok "a client resolves names through the exit, a stranger does not, and a large answer is truncated"

# --- a client is bound to its own addresses -----------------------------------
"$here/fips-exit" add $C2 phone-two >/dev/null
[ "$(ask c2 4 8.8.8.2 100)" = 100 ] || fail "second client"
ip -n c2 addr add $C1V4/32 dev tun0
ip netns exec c2 python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("'$C1V4'", 0)); s.settimeout(1.5)
s.sendto(b"100", ("8.8.8.2", 4444))
try: s.recv(4096); print("SPOOFED")
except socket.timeout: print("dropped")' | grep -qx dropped || fail "client two sent as client one"
ok "a client cannot send from another client's address"

# --- clients do not reach the exit host or each other -------------------------
ip netns exec c1 ping -c 1 -W 1 -q 8.8.8.1 >/dev/null 2>&1 && fail "client reached the exit host through the tunnel"
ip netns exec c1 ping -c 1 -W 1 -q $C2V4 >/dev/null 2>&1 && fail "client reached another client"
ok "the exit host and other clients are not reachable through the tunnel"

# --- the internet only: not the uplink's own LAN -------------------------------
# The host on the LAN answers the exit itself, so it is up; a client's packet
# to it would leave by the uplink interface like any other. The destination
# is what stops it.
ip netns exec inet ping -c 1 -W 1 -q 192.168.77.1 >/dev/null 2>&1 || fail "test setup: the LAN host does not reach the exit"
[ "$(ask c1 4 192.168.77.2 100)" = timeout ] || fail "CLIENT REACHED A PRIVATE ADDRESS ON THE UPLINK'S LAN"
[ "$(ask c1 6 fc00:77::2 100)" = timeout ] || fail "CLIENT REACHED A UNIQUE-LOCAL ADDRESS ON THE UPLINK'S LAN"
[ "$(ask c1 4 9.9.9.2 100)" = timeout ] || fail "CLIENT REACHED A NETWORK IN BLOCK_CIDRS"
[ "$(ask c1 4 8.8.8.2 100)" = 100 ] || fail "the blocks broke the internet"
ok "private, unique-local and BLOCK_CIDRS destinations are not reachable through the tunnel"

# A BLOCK_CIDRS entry that is not a network stops the script.
printf "WAN=wan\nFIPS_FIREWALL=\nBLOCK_CIDRS=not-a-network\n" > "$FIPS_EXIT_DIR/config"
"$here/fips-exit" up >/dev/null 2>&1 && fail "up accepted a bad BLOCK_CIDRS"
printf "WAN=wan\nFIPS_FIREWALL=\nBLOCK_CIDRS=9.9.9.0/24\n" > "$FIPS_EXIT_DIR/config"
"$here/fips-exit" up >/dev/null
ok "a bad BLOCK_CIDRS entry is refused"

# --- no upstream answers: the client is told at once ---------------------------
kill $dns_pid
r=$(resolve c2 $C2 example.com)
[ "${r% size=*}" = "answers=0 rcode=2 tc=0" ] || fail "DNS with the upstream down: $r"
ok "with no upstream answering, a client gets SERVFAIL instead of silence"

# --- removal and teardown -----------------------------------------------------
"$here/fips-exit" remove phone-one >/dev/null
[ "$(ask c1 4 8.8.8.2 100)" = timeout ] || fail "removed client still passes"
[ "$(ask c2 4 8.8.8.2 100)" = 100 ] || fail "remaining client broke on removal"
ok "removing a client cuts it off and leaves the others"
legacy fx55667788 $C2
PATH="$FIPS_EXIT_DIR/bin:$PATH" "$here/fips-exit" down >/dev/null || fail "down with empty objects in ip's list of links"
ip link show fx55667788 >/dev/null 2>&1 && fail "down left an old fx tunnel device"
ip route show dev fipsexit0 | grep -q . && fail "routes left after down"
ip -6 rule show | grep -q "lookup 5170" && fail "rule left after down"
nft list table inet fips_exit >/dev/null 2>&1 && fail "table left after down"
ok "down removes everything"
echo PASS
