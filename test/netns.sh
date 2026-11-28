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
# First the exit as it is by default, for the clients on its list; then the
# same exit with ACCESS=paid, where it also carries the members of accounts.
# Run as: unshare -Urnm test/netns.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
export FIPS_EXIT_DIR=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$FIPS_EXIT_DIR"' EXIT
mount -t tmpfs tmpfs /run

# The exit is a node with a key: its npub is its name on the mesh, and its
# address is the one fips derives from it (fd and SHA-256 of the key).
NPUB=$(python3 -c '
import hashlib
key = hashlib.sha256(b"fips-exit test exit").digest()
A = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(values):
    c = 1
    for v in values:
        top = c >> 25; c = (c & 0x1ffffff) << 5 ^ v
        for i, g in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            c ^= g if top >> i & 1 else 0
    return c
acc = bits = 0; data = []
for b in key:
    acc, bits = acc << 8 | b, bits + 8
    while bits >= 5: bits -= 5; data.append(acc >> bits & 31)
if bits: data.append(acc << (5 - bits) & 31)
hrp = [ord(c) >> 5 for c in "npub"] + [0] + [ord(c) & 31 for c in "npub"]
check = polymod(hrp + data + [0] * 6) ^ 1
print("npub1" + "".join(A[v] for v in data + [check >> 5 * (5 - i) & 31 for i in range(6)]))')
E=$(python3 -c '
import hashlib, ipaddress
print(ipaddress.IPv6Address(b"\xfd" + hashlib.sha256(hashlib.sha256(b"fips-exit test exit").digest()).digest()[:15]))')
C1=fd11:2233:4455:6677::1 C2=fd99:8877:6655:4433::2 C3=fd55:aaaa:bbbb:cccc::3
C1V4=100.81.34.51 C2V4=100.89.136.119 C3V4=100.85.170.170
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok: $*"; }

ip link set lo up
ip link add fips0 type bridge
# Its own address, set before any client is attached. Left alone, a bridge
# takes the lowest address among its ports, so it changes as clients are
# added, after an earlier client has learned it: that client then sends to
# an address the exit no longer answers to, for the eight seconds its
# neighbour entry takes to notice.
ip link set fips0 address 02:00:00:00:0e:01
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
client c3 $C3 $C3V4
printf "WAN=wan\nFIPS_FIREWALL=\nBLOCK_CIDRS=9.9.9.0/24\n" > "$FIPS_EXIT_DIR/config"
daemon="$here/target/release/fips-exitd"
payd="$here/payd/target/release/fips-exit-payd"
[ -x "$payd" ] || fail "build the payment service first: cargo build --release --manifest-path payd/Cargo.toml"
[ -x "$daemon" ] || fail "build the daemon first: cargo build --release"

# --- without the daemon, the script says so and applies nothing ----------------
"$here/fips-exit" up 2>&1 | grep -q "fips-exitd is not running" || fail "up without the daemon"
ok "up without the daemon is refused"
sock="$FIPS_EXIT_DIR/control.sock"
# CLIENT_COUNTS=on: the clients on the list are counted, which an exit does
# only when its operator asks for it. The second half runs without.
CLIENT_COUNTS=on DNS_UPSTREAMS=8.8.8.2 "$daemon" --clients "$FIPS_EXIT_DIR/clients" --mesh-if fips0 --tun fipsexit0 --control "$sock" 2>"$FIPS_EXIT_DIR/daemon.log" &
daemon_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 && [ -S "$sock" ] && break; sleep 0.2; done
ip link show fipsexit0 >/dev/null 2>&1 || fail "the daemon did not create its TUN: $(cat "$FIPS_EXIT_DIR/daemon.log")"

# --- the control socket: root's alone, and no peer on it stops anything ---------
# Accounts are made over it (in the second half, ACCESS=paid). It is there
# through this half too, with a peer that says nothing and after one that
# sent no command.
ctl() { # bytes to send, as Python would write them -> the daemon's answer
  python3 -c '
import ast, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(8); s.connect(sys.argv[1])
s.sendall(ast.literal_eval("b\"" + sys.argv[2] + "\\n\"")); s.shutdown(socket.SHUT_WR)
answer = b""
while True:
    data = s.recv(65536)
    if not data: break
    answer += data
sys.stdout.write(answer.decode())' "$sock" "$1"
}
[ -S "$sock" ] || fail "no control socket: $(cat "$FIPS_EXIT_DIR/daemon.log")"
[ "$(stat -c %a "$sock")" = 600 ] || fail "the control socket has mode $(stat -c %a "$sock")"
case "$(ctl stat)" in "ok epoch="*" accounts=0 resolver="?" counts=1") ;; *) fail "stat: $(ctl stat)" ;; esac
python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); time.sleep(600)' "$sock" &
# Bytes that are no text, then a line with no end within the limit: an error
# each, and what follows the second is not read as a command.
[ "$(ctl '\xff\xfe\x00 put\n'"$(printf 'x%.0s' $(seq 5000))"'\nput pkg 999999 0 0 '$C1)" = "$(printf 'err syntax\nerr line')" ] \
  || fail "what is not a command was not refused"
[ "$(ctl usage)" = "ok 0" ] || fail "an account came out of what was not a command: $(ctl usage)"
ok "the control socket is root's, and answers what is not a command with an error"

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

# --- the count of a client on the list, since the operator asked for it ---------
# One exchange, sent once (ask sends again when an answer is slow, and what
# is sent twice is counted twice): 31 bytes from the client (20 + 8 + "100")
# and 128 to it, on top of whatever it had.
count() { ctl clients | awk -v c="$1" '$2 == c { print $3, $4 }'; }
before=$(count $C1)
ip netns exec c1 python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
s.sendto(b"100", ("8.8.8.2", 4444)); print(len(s.recv(4096)))' | grep -qx 100 || fail "the one exchange to be counted"
after=$(count $C1)
[ "$(( ${after% *} - ${before% *} )) $(( ${after#* } - ${before#* } ))" = "31 128" ] \
  || fail "the count of a listed client went from '$before' to '$after'"
# `status` shows it, and says so when the config and the daemon differ.
status() { FIPS_EXIT_CONTROL="$sock" "$here/fips-exit" status; }
conf1() { printf "WAN=wan\nFIPS_FIREWALL=\nBLOCK_CIDRS=9.9.9.0/24\n$1" > "$FIPS_EXIT_DIR/config"; }
conf1 "CLIENT_COUNTS='on'\n"
status | grep -Eq "^  $C1 phone-one +${after% *} bytes from it, +${after#* } to it$" || fail "status: $(status)"
status | grep -q "STILL COUNTING" && fail "status complained though the config asks for the count"
conf1 ""
status | grep -q "THE DAEMON IS STILL COUNTING" || fail "status did not say that the daemon counts unasked: $(status)"
conf1 "CLIENT_COUNTS=yes\n"
"$here/fips-exit" up >/dev/null 2>&1 && fail "up accepted a CLIENT_COUNTS that is neither word"
conf1 ""
"$here/fips-exit" up >/dev/null
ok "a client on the list is counted to the byte when the operator asks, and status says what the daemon does"

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
for port in 4445 25; do   # 25 for the second half: mail is not for members
  ip netns exec inet python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0); s.bind(("::", int(sys.argv[1]))); s.listen(4)
while True:
    c, _ = s.accept(); c.sendall(b"y" * 200000); c.close()' $port &
done
sleep 0.5
fetch() { # netns address [port] -> bytes received, or nothing
  ip netns exec "$1" python3 -c '
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5); n = 0
while True:
    d = s.recv(65536)
    if not d: break
    n += len(d)
print(n)' "$2" "${3:-4445}" 2>/dev/null || true; }
[ "$(fetch c1 8.8.8.2)" = 200000 ] || fail "TCP over IPv4"
[ "$(fetch c1 2001:4860:1::2)" = 200000 ] || fail "TCP over IPv6"
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
# Its count went with it; the other client's is still there. And a client
# that is removed and put back at once starts at nothing: the daemon reads
# the list when it changes, not when the next packet comes.
ctl clients | grep -q "^client $C1 " && fail "A REMOVED CLIENT'S COUNT WAS KEPT: $(ctl clients)"
ctl clients | grep -q "^client $C2 [1-9]" || fail "the remaining client's count: $(ctl clients)"
"$here/fips-exit" remove phone-two >/dev/null
"$here/fips-exit" add $C2 phone-two >/dev/null
[ "$(ctl clients)" = "$(printf 'client %s 0 0\nok 1' $C2)" ] || fail "A CLIENT PUT BACK KEPT ITS OLD COUNT: $(ctl clients)"
legacy fx55667788 $C2
PATH="$FIPS_EXIT_DIR/bin:$PATH" "$here/fips-exit" down >/dev/null || fail "down with empty objects in ip's list of links"
ip link show fx55667788 >/dev/null 2>&1 && fail "down left an old fx tunnel device"
ip route show dev fipsexit0 | grep -q . && fail "routes left after down"
ip -6 rule show | grep -q "lookup 5170" && fail "rule left after down"
nft list table inet fips_exit >/dev/null 2>&1 && fail "table left after down"
ok "down removes everything"

# ================================ ACCESS=paid ==================================
# The same exit as a paid one: besides the clients on the list it carries the
# members of accounts, each for the bytes its account was granted. Nothing
# here sells anything; the accounts are made over the socket as a payment
# service would make them.
#
# This half also has fips's own firewall in front of the daemon, as fips
# ships it (packaging/common/fips.nft): what arrives on the mesh interface is
# dropped unless a drop-in admits it. A stand-in with the same rules, and
# neighbour discovery let through, because this "mesh" is a bridge. The
# script writes its drop-in beside it. The first half has no firewall at
# all, so that what is refused there is refused by the daemon.
fw="$FIPS_EXIT_DIR/fips"
mkdir -p "$fw/fips.d"
cat > "$fw/fips.nft" <<NFT
add table inet fips
flush table inet fips
table inet fips {
    chain inbound {
        type filter hook input priority 0; policy accept;
        iifname != "fips0" return
        ct state established,related accept
        meta nfproto ipv6 icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
        include "$fw/fips.d/*.nft"
        counter drop
    }
}
NFT
nft -f "$fw/fips.nft"
conf() { printf "WAN=wan\nFIPS_FIREWALL=$fw/fips.nft\nBLOCK_CIDRS=9.9.9.0/24\n$1" > "$FIPS_EXIT_DIR/config"; }
conf "ACCESS=nonsense\n"
"$here/fips-exit" up >/dev/null 2>&1 && fail "up accepted an ACCESS that is neither word"
"$here/fips-exit" down >/dev/null || fail "down was stopped by a config that up refuses"
conf "ACCESS=paid\n"
# The daemon reads ACCESS when it starts. This one was started without it and
# has no socket where the script looks: nothing may be opened for it.
out=$("$here/fips-exit" up 2>&1) && fail "up in paid mode went ahead without the daemon's socket"
case "$out" in *"does not answer on /run/fips-exit/control.sock"*) ;; *) fail "up without the socket said: $out" ;; esac
nft list table inet fips_exit >/dev/null 2>&1 && fail "a table was made for a daemon without a socket"
ok "paid mode is refused while the daemon was not started for it"

# As the unit starts it: the config as its environment, the socket in /run.
kill $daemon_pid
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 || break; sleep 0.2; done
mkdir -m 750 /run/fips-exit
sock=/run/fips-exit/control.sock
ACCESS=paid DNS_UPSTREAMS=8.8.8.2 "$daemon" --clients "$FIPS_EXIT_DIR/clients" --mesh-if fips0 --tun fipsexit0 2>>"$FIPS_EXIT_DIR/daemon.log" &
daemon_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 && break; sleep 0.2; done
ip netns exec inet python3 "$FIPS_EXIT_DIR/dns.py" &

# A host that is in the clients' range itself cannot route all of it to them.
ip addr add 100.70.0.1/24 dev wan
out=$("$here/fips-exit" up 2>&1) && fail "up in paid mode on a host inside 100.64.0.0/10"
case "$out" in *"100.70.0.1 on wan"*) ;; *) fail "up on such a host said: $out" ;; esac
ip addr del 100.70.0.1/24 dev wan
"$here/fips-exit" up >/dev/null
ip route show dev fipsexit0 | grep -q "^100.64.0.0/10 " || fail "routes in paid mode: $(ip route show dev fipsexit0)"
ip -6 rule show | grep "lookup 5170" | grep -q "fwmark 0x8000000/0x8000000" || fail "rule in paid mode: $(ip -6 rule show | grep 5170)"
case "$(ctl stat)" in "ok epoch="*" accounts=0 resolver=1 counts=0") ;; *) fail "stat: $(ctl stat)" ;; esac
[ "$(ctl clients)" = "ok 0" ] || fail "clients were counted without CLIENT_COUNTS: $(ctl clients)"
# What it opened in fips's firewall: the tunnel and the resolver, to this
# node's own address, from anyone. Admission is the daemon's alone now.
grep -qx "ip6 daddr $E ip6 nexthdr { 4, 41, 44 } accept" "$fw/fips.d/fips-exit.nft" || fail "drop-in: $(cat "$fw/fips.d/fips-exit.nft")"
grep -qx "ip6 daddr $E udp dport 53 accept" "$fw/fips.d/fips-exit.nft" || fail "drop-in: $(cat "$fw/fips.d/fips-exit.nft")"
ok "paid mode starts where the clients' range is free, and not where the host uses it"

# --- nobody is carried for being on the mesh ------------------------------------
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A NODE WITHOUT AN ACCOUNT WAS CARRIED"
[ "$(resolve c3 $C3 example.com)" = timeout ] || fail "a node without an account got DNS"
[ "$(ask c2 4 8.8.8.2 100)" = 100 ] || fail "a client on the list, in paid mode"
# A member of an account with nothing granted is known, and not carried.
[ "$(ctl "put empty 0 0 0 $C3")" = "ok $C3=v4" ] || fail "put: $(ctl "check $C3")"
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A MEMBER WAS CARRIED WITHOUT A GRANT"
[ "$(ctl "drop empty")" = ok ] || fail "drop"
[ "$(ctl "check $C3")" = "ok free v4" ] || fail "after drop: $(ctl "check $C3")"
ok "paid mode carries the clients on the list, and no node that has no account or no grant"

# --- the payment service: what the exit costs, for anyone on the mesh -----------
# It reads the same config, finds the exit's fips address itself, and answers
# there; the script has opened its port in fips's firewall, to that address.
# A node that is no client at all asks, and is told who it is.
http_get() { # netns path [Host header] -> status, then the body
  ip netns exec "$1" python3 -c '
import http.client, sys
c = http.client.HTTPConnection(sys.argv[1], 5170, timeout=4)
try:
    c.request("GET", sys.argv[2], headers={"Host": sys.argv[3]})
    r = c.getresponse(); print(r.status); sys.stdout.write(r.read().decode())
except OSError: print("unreachable")' $E "$2" "${3:-$NPUB.fips:5170}"
}
conf "ACCESS=nonsense\n"
"$payd" --config "$FIPS_EXIT_DIR/config" 2>&1 | grep -q "nothing to sell" || fail "the payment service on an exit that sells nothing"
conf "ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\nPACKAGES=\"1gb:1GB:1500:30 5gb:5GB:6000:90\"\nCOUNTRY=CH\nADVERT_NAME=\"An exit\"\n"
# Nothing listens on the port yet, so it is not opened: whatever else might
# listen there is not for the mesh.
grep -q "dport 5170" "$fw/fips.d/fips-exit.nft" && fail "THE PAYMENT PORT WAS OPENED WITH NO SERVICE BEHIND IT"
nc_listener() { python3 -c 'import socket,time; s=socket.socket(socket.AF_INET6); s.bind(("::",5170)); s.listen(1); time.sleep(30)' & }
nc_listener; other=$!
sleep 0.3
"$here/fips-exit" up >/dev/null
grep -q "dport 5170" "$fw/fips.d/fips-exit.nft" && fail "THE PAYMENT PORT WAS OPENED FOR SOMETHING THAT IS NOT THE SERVICE"
kill $other; wait $other 2>/dev/null || true
mkdir -p /run/fips-exit-payd "$FIPS_EXIT_DIR/state"
echo $NPUB > "$FIPS_EXIT_DIR/fips.pub"
# Without the node's npub, or with another node's, the service does not start:
# the npub is the way to it.
"$payd" --config "$FIPS_EXIT_DIR/config" --pub "$FIPS_EXIT_DIR/none.pub" --state "$FIPS_EXIT_DIR/state" 2>&1 \
  | grep -q "has no npub" || fail "the payment service started without the node's npub"
echo npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl > "$FIPS_EXIT_DIR/other.pub"
"$payd" --config "$FIPS_EXIT_DIR/config" --pub "$FIPS_EXIT_DIR/other.pub" --state "$FIPS_EXIT_DIR/state" 2>&1 \
  | grep -q "is not this node" || fail "the payment service started with another node's npub"
start_payd() {
  "$payd" --config "$FIPS_EXIT_DIR/config" --pub "$FIPS_EXIT_DIR/fips.pub" --state "$FIPS_EXIT_DIR/state" \
    2>>"$FIPS_EXIT_DIR/payd.log" &
  payd_pid=$!
}
start_payd
# As the service's unit does when it has started: `up`, which waits for it to listen.
"$here/fips-exit" up >/dev/null
grep -qx "ip6 daddr $E tcp dport 5170 accept" "$fw/fips.d/fips-exit.nft" || fail "the payment port in fips's firewall: $(cat "$fw/fips.d/fips-exit.nft")"
"$here/fips-exit" status | grep -q "payment service fips-exit-payd: answering on port 5170" || fail "status: $("$here/fips-exit" status)"
r=$(http_get c3 /v1/terms)
[ "${r%%
*}" = 200 ] || fail "the terms from the mesh: $r $(cat "$FIPS_EXIT_DIR/payd.log")"
printf '%s' "${r#*
}" | python3 -c '
import json, sys
t = json.load(sys.stdin)
assert t["version"] == 1, t
assert t["you"] == {"address": sys.argv[1], "package": None}, t["you"]
assert t["exit"] == {"npub": sys.argv[3], "address": sys.argv[2], "name": "An exit", "about": "", "country": "CH"}, t["exit"]
assert t["price_msat_per_gb"] == 2000000 and t["methods"] == [] and t["mints"] == [], t
assert [p["id"] for p in t["packages"]] == ["1gb", "5gb"] and t["packages"][1]["bytes"] == 5000000000, t' $C3 $E $NPUB \
  || fail "the terms said: ${r#*
}"
r=$(http_get c3 /)
case "$r" in "200
"*"<title>An exit</title>"*"5 GB"*"You are <code>$C3</code>"*) ;; *) fail "the page: $r" ;; esac
[ "$(http_get c3 /v1/terms "evil.example")" = "421
not this exit's name" ] || fail "a request for another name: $(http_get c3 /v1/terms evil.example)"
# Nor its bare address: that is reached only by way of the npub.
[ "$(http_get c3 /v1/terms "[$E]:5170" | head -1)" = 421 ] || fail "a request by the bare address was answered"
ok "the payment service tells any node on the mesh what the exit costs, and who it is"

# --- a package the operator gives away, kept by the payment service -------------
# The service keeps it, and keeps the daemon's account for it as it says:
# the member is carried, counted, cut off when it is used up, carried again
# when it is topped up, and nothing is lost when the daemon or the service
# starts again.
account_of() { ctl usage | awk -v p="$1" '$2 == p { print $3, $4, $5 }'; }
wait_for() { # a shell condition, for up to ten seconds
  for i in $(seq 40); do eval "$1" && return 0; sleep 0.25; done; return 1
}
out=$("$here/fips-exit" grant 400 0 $C3 a test package) || fail "grant: $out"
package=$(printf '%s\n' "$out" | awk '$1 == "package" { print $2 }')
key=$(printf '%s\n' "$out" | awk '$1 == "key" { print $2 }')
[ ${#key} = 64 ] || fail "grant said: $out"
wait_for '[ -n "$(account_of $package)" ]' || fail "the package was not put in the daemon: $(ctl usage) $(tail -3 "$FIPS_EXIT_DIR/payd.log")"
for i in 1 2 3; do
  [ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "exchange $i of a package's member"
done
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A PACKAGE'S MEMBER WAS CARRIED PAST ITS BYTES"
wait_for '"$here/fips-exit" packages | grep -q "^$package  *used-up"' || fail "packages: $("$here/fips-exit" packages)"
wait_for '[ -z "$(account_of $package)" ]' || fail "a used-up package was not dropped from the daemon"
r=$(http_get c3 /v1/terms)
printf '%s' "${r#*
}" | python3 -c '
import json, sys
p = json.load(sys.stdin)["you"]["package"]
assert p["id"] == sys.argv[1] and p["standing"] == "used-up" and p["bytes_left"] == 0 and p["members"] == 1, p' $package \
  || fail "the terms for a member: ${r#*
}"
"$here/fips-exit" top-up $package 10000 >/dev/null || fail "top-up"
wait_for '[ -n "$(account_of $package)" ]' || fail "a topped-up package was not put again"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member after a top-up"
ok "a package given away is carried, counted, cut off when used up, and carried again when topped up"

# The daemon starts again, empty: the service puts the package back, with
# what it had used when it last asked, every two seconds. (What was used
# after that and before the daemon stopped is forgiven: a few seconds.)
sleep 3
used_before=$(account_of $package | awk '{ print $2 + $3 }')
kill $daemon_pid; wait $daemon_pid 2>/dev/null || true
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 || break; sleep 0.2; done
ACCESS=paid DNS_UPSTREAMS=8.8.8.2 "$daemon" --clients "$FIPS_EXIT_DIR/clients" --mesh-if fips0 --tun fipsexit0 2>>"$FIPS_EXIT_DIR/daemon.log" &
daemon_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 && break; sleep 0.2; done
"$here/fips-exit" up >/dev/null
wait_for '[ -n "$(account_of $package)" ]' || fail "THE PACKAGE WAS NOT PUT BACK AFTER THE DAEMON STARTED AGAIN"
used_after=$(account_of $package | awk '{ print $2 + $3 }')
[ "$used_after" -ge "$used_before" ] || fail "what the package had used was lost: $used_before, then $used_after"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member after the daemon started again"
# The service starts again: its packages are kept.
kill $payd_pid; wait $payd_pid 2>/dev/null || true
start_payd
"$here/fips-exit" up >/dev/null
wait_for '"$here/fips-exit" packages 2>/dev/null | grep -q "^$package  *live .*a test package"' \
  || fail "the package after the service started again: $("$here/fips-exit" packages 2>&1)"
ok "nothing is lost when the daemon or the payment service starts again"

# --- a package managed with its key, over the mesh --------------------------------
# Whoever holds the key sees the package and takes members out of it; a
# device is put in by itself alone, with the key, and can always take itself
# out.
http_post() { # netns path json -> status, then the body
  ip netns exec "$1" python3 -c '
import http.client, sys
c = http.client.HTTPConnection(sys.argv[1], 5170, timeout=4)
try:
    c.request("POST", sys.argv[2], body=sys.argv[3], headers={"Host": sys.argv[4], "Content-Type": "application/json"})
    r = c.getresponse(); print(r.status); sys.stdout.write(r.read().decode())
except OSError: print("unreachable")' $E "$2" "$3" "$NPUB.fips:5170"
}
status_of() { printf '%s\n' "$1" | head -1; }
r=$(http_post c1 /v1/package "{\"key\": \"$key\"}")
[ "$(status_of "$r")" = 200 ] || fail "the package by its key: $r"
printf '%s' "$r" | tail -n +2 | grep -q "\"name\":\"$C3\"" || fail "the package's members: $r"
[ "$(status_of "$(http_post c1 /v1/package "{\"key\": \"$(printf '0%.0s' $(seq 64))\"}")")" = 403 ] || fail "a wrong key was not refused"
# c1, which is nobody's, puts itself in with the key: carried.
r=$(http_post c1 /v1/package/members "{\"key\": \"$key\", \"add\": [\"$C1\"]}")
[ "$(status_of "$r")" = 200 ] || fail "c1 adding itself: $r"
wait_for '[ "$(ask c1 4 8.8.8.2 100)" = 100 ]' || fail "a member added with the key is not carried"
# Another package, whose holder would put c1 in it: refused, since only c1
# puts itself anywhere; c1 itself, with that key, moves.
out=$("$here/fips-exit" grant 1MB 0 $C2 another) || fail "grant: $out"
other_key=$(printf '%s\n' "$out" | awk '$1 == "key" { print $2 }')
other_package=$(printf '%s\n' "$out" | awk '$1 == "package" { print $2 }')
r=$(http_post c2 /v1/package/members "{\"key\": \"$other_key\", \"add\": [\"$C1\"]}")
[ "$(status_of "$r")" = 403 ] || fail "A KEY HOLDER PUT ANOTHER DEVICE IN ITS PACKAGE: $r"
r=$(http_post c1 /v1/package/members "{\"key\": \"$other_key\", \"add\": [\"$C1\"]}")
[ "$(status_of "$r")" = 200 ] || fail "c1 moving itself: $r"
# And out, with no key at all: not carried.
r=$(http_post c1 /v1/leave "{}")
[ "$(status_of "$r")" = 200 ] && printf '%s' "$r" | grep -q '"left":"p' || fail "leave: $r"
wait_for '[ "$(ctl "check $C1")" = "ok free v4" ]' || fail "after leave: $(ctl "check $C1")"
[ "$(ask c1 4 8.8.8.2 100)" = timeout ] || fail "A DEVICE THAT LEFT ITS PACKAGE WAS CARRIED"
# What another site's page would send: refused.
ip netns exec c1 python3 -c '
import http.client, sys
c = http.client.HTTPConnection(sys.argv[1], 5170, timeout=4)
c.request("POST", "/leave", body="", headers={"Host": sys.argv[2], "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://evil.example"})
print(c.getresponse().status)' $E "$NPUB.fips:5170" | grep -qx 403 || fail "a form from another site was taken"
"$here/fips-exit" revoke $other_package >/dev/null || fail "revoke the other package"
ok "a package's key shows who is in it; a device puts itself in, or leaves, and nobody else moves it"

"$here/fips-exit" revoke $package >/dev/null || fail "revoke"
wait_for '[ -z "$(account_of $package)" ]' || fail "a revoked package was not dropped"
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A REVOKED PACKAGE'S MEMBER WAS CARRIED"
[ "$(ctl "check $C3")" = "ok free v4" ] || fail "after revoke: $(ctl "check $C3")"
"$here/fips-exit" grant 1GB 0 2001:db8::1 >/dev/null 2>&1 && fail "a package for an address that is not a fips address"
ok "a revoked package's member is not carried"

# --- a package bought with a token, over the mesh -----------------------------------
# A real Cashu mint in the exit's namespace, with a Lightning backend that
# pays itself. The exit names it, and tokens of it arrive in the service's
# wallet: a node that is nobody's pays, and is carried.
mint="$here/payd/target/debug/fips-exit-test-mint"
[ -x "$mint" ] || fail "build the test mint first: cargo build --manifest-path payd/Cargo.toml -p fips-exit-test-mint"
MINT=http://127.0.0.1:3338
"$mint" serve 127.0.0.1:3338 > "$FIPS_EXIT_DIR/mint.out" 2>"$FIPS_EXIT_DIR/mint.log" &
mint_pid=$!
wait_for 'grep -qx "$MINT" "$FIPS_EXIT_DIR/mint.out"' || fail "the test mint did not start: $(cat "$FIPS_EXIT_DIR/mint.log")"
token() { "$mint" token $MINT "$1" || fail "no token of $1 sat from the test mint"; }
sells() { conf "ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\nPACKAGES=\"$1\"\nCOUNTRY=CH\nADVERT_NAME=\"An exit\"\n$2"; }
# What the advert would say of the exit's terms: what the script is told by
# the service, written as the advert's tags. (The advert itself is signed
# with the node's key, which this exit of a test has none of.)
advert_terms() {
  python3 -I -c '
import importlib.machinery, importlib.util, json, sys
loader = importlib.machinery.SourceFileLoader("fips_exit", sys.argv[1])
x = importlib.util.module_from_spec(importlib.util.spec_from_loader("fips_exit", loader))
loader.exec_module(x)
terms = x.offered()
advert = {"access": "paid" if terms else "allow-list", "name": "", "about": "", "expires": 1003600, "terms": terms}
print(json.dumps(x.advert_tags(advert, 1000000)))' "$here/fips-exit"
}
restart_payd() { kill $payd_pid; wait $payd_pid 2>/dev/null || true; start_payd; "$here/fips-exit" up >/dev/null; }
# Without a mint named, nothing is sold, and the advert does not say paid.
advert_terms | grep -q '\["access", "allow-list"\]' || fail "the advert of an exit that sells nothing: $(advert_terms)"
r=$(http_post c1 /v1/orders '{"package": "1gb", "token": "cashuBabc"}')
[ "$(status_of "$r")" = 503 ] || fail "an order on an exit that names no mint: $r"
sells "tiny:30000:8:1 1gb:1GB:1500:30" "MINTS=$MINT\n"
restart_payd
wait_for 'http_get c1 /v1/terms | grep -q "\"methods\":\[\"cashu\",\"bolt11\"\]"' \
  || fail "the service does not take tokens, or gives no invoices: $(http_get c1 /v1/terms) $(tail -5 "$FIPS_EXIT_DIR/payd.log")"
http_get c1 / | grep -q '<form method="post" action="/buy">' || fail "the page does not sell"
[ "$(ask c1 4 8.8.8.2 100)" = timeout ] || fail "c1 was carried before it paid"
t=$(token 8)
r=$(http_post c1 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")
[ "$(status_of "$r")" = 200 ] || fail "buying with a token: $r $(tail -5 "$FIPS_EXIT_DIR/payd.log")"
bought=$(printf '%s' "$r" | tail -n +2 | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["paid_sat"] == 8 and d["again"] is False and d["added"] is False, d
assert d["package"]["you"] is True and d["package"]["bytes_left"] == 30000 and len(d["key"]) == 64, d
print(d["package"]["id"], d["key"])') || fail "what was bought: $r"
bought_key=${bought#* }; bought=${bought% *}
wait_for '[ "$(ask c1 4 8.8.8.2 100)" = 100 ]' || fail "A NODE THAT PAID IS NOT CARRIED: $(ctl usage) $(tail -5 "$FIPS_EXIT_DIR/payd.log")"
# The token is one purchase: not a second for someone else, and for its buyer
# the same again, with a new key for the package.
[ "$(status_of "$(http_post c3 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")")" = 409 ] || fail "A TOKEN WAS TAKEN TWICE"
r=$(http_post c1 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")
[ "$(status_of "$r")" = 200 ] && printf '%s' "$r" | grep -q '"again":true' || fail "the same token from its buyer: $r"
[ "$(status_of "$(http_post c1 /v1/package "{\"key\": \"$bought_key\"}")")" = 403 ] || fail "the key before the new one still opened the package"
# A token worth less than the price is not taken, and buys nothing.
[ "$(status_of "$(http_post c3 /v1/orders "{\"package\": \"tiny\", \"token\": \"$(token 7)\"}")")" = 402 ] || fail "a token of 7 sat for 8"
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A NODE THAT DID NOT PAY WAS CARRIED"
# A client on the operator's list is carried as it is, and is sold nothing:
# the daemon says who it is. Its token is not touched, and buys for another.
t=$(token 8)
r=$(http_post c2 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")
[ "$(status_of "$r")" = 409 ] && printf '%s' "$r" | grep -q '"code":"listed"' || fail "a client on the list was sold a package: $r"
r=$(http_post c3 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")
[ "$(status_of "$r")" = 200 ] || fail "a token that was refused untouched did not buy afterwards: $r"
also=$(printf '%s' "$r" | tail -n +2 | python3 -c 'import json, sys; print(json.load(sys.stdin)["package"]["id"])')
wait_for '[ "$(ask c3 4 8.8.8.2 100)" = 100 ]' || fail "the second node that paid is not carried"
# What the operator sees of it, and what the advert says now.
"$here/fips-exit" wallet | grep -Eq "^ +16 sat +0 sat +16 sat +reached +yes +$MINT\$" || fail "wallet: $("$here/fips-exit" wallet)"
"$here/fips-exit" orders | grep -Eq "^o[0-9a-f]{16} +paid .* 8 sat +8 sat +0 +tiny +$bought +$C1\$" || fail "orders: $("$here/fips-exit" orders)"
[ "$("$here/fips-exit" orders | grep -c " paid ")" = 2 ] || fail "orders: $("$here/fips-exit" orders)"
"$here/fips-exit" packages | grep -q "^$bought  *live .*bought: tiny" || fail "packages: $("$here/fips-exit" packages)"
"$here/fips-exit" status | grep -q "tokens of $MINT: reached, holds 16 sat, and gives Lightning invoices" || fail "status: $("$here/fips-exit" status)"
advert_terms | python3 -c '
import json, sys
tags = json.load(sys.stdin)
for tag in (["access", "paid"], ["price", "2000000"], ["pay", "cashu", "bolt11"], ["port", "5170"], ["mint", sys.argv[1]],
            ["package", "tiny", "30000", "8", "1"], ["package", "1gb", "1000000000", "1500", "30"]):
    assert tag in tags, (tag, tags)' $MINT || fail "the advert of an exit that sells: $(advert_terms)"
ok "a token of the exit's mint buys a package over the mesh: once, for its price, and its buyer is carried"

# --- a package bought with Lightning, over the mesh ----------------------------------
# The mint gives the invoice, and from here on it is paid when this test says
# so. c3, which is in the package it bought with a token, asks for another.
"$mint" hold $MINT || fail "the test mint does not hold its invoices"
http_get c3 / | grep -q '<button>Pay with Lightning</button>' || fail "the page does not sell for an invoice"
r=$(http_post c3 /v1/orders '{"package": "tiny", "method": "bolt11"}')
[ "$(status_of "$r")" = 201 ] || fail "asking for an invoice: $r $(tail -5 "$FIPS_EXIT_DIR/payd.log")"
order=$(printf '%s' "$r" | tail -n +2 | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["state"] == "waiting" and d["method"] == "bolt11" and d["sat"] == 8 and d["request"].startswith("lnbc80n1"), d
assert "key" not in d and "package" not in d, d
print(d["order"], d["request"])') || fail "the order: $r"
invoice=${order#* }; order=${order% *}
# The order is its buyer's, and it waits: nothing is granted for an invoice.
[ "$(status_of "$(http_get c1 /v1/orders/$order)")" = 404 ] || fail "ANOTHER NODE SAW AN ORDER THAT IS NOT ITS OWN"
http_get c3 /v1/orders/$order | grep -q '"state":"waiting"' || fail "the order while it waits: $(http_get c3 /v1/orders/$order)"
http_get c3 /order/$order | grep -q '<svg class="qr"' || fail "the order's page shows no code to pay by"
[ "$(status_of "$(http_post c3 /v1/orders/$order/key '{}')")" = 409 ] || fail "a key was given for an order that is not paid"
"$here/fips-exit" orders | grep -Eq "^$order +open +invoice " || fail "orders: $("$here/fips-exit" orders)"
[ "$(ctl "check $C3")" = "ok member $also v4" ] || fail "c3 before it paid the invoice: $(ctl "check $C3")"
# Somebody pays it: the mint is asked, the wallet mints, the package is there.
"$mint" pay $MINT "$invoice" || fail "the test mint did not take the payment"
wait_for 'http_get c3 /v1/orders/$order | grep -q "\"state\":\"paid\""' \
  || fail "AN INVOICE THAT WAS PAID BOUGHT NOTHING: $(http_get c3 /v1/orders/$order) $(tail -5 "$FIPS_EXIT_DIR/payd.log")"
via=$(http_get c3 /v1/orders/$order | tail -n +2 | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["paid_sat"] == 8 and d["added"] is False and "request" not in d, d
print(d["package"]["id"])') || fail "the order once it is paid: $(http_get c3 /v1/orders/$order)"
wait_for '[ "$(ctl "check $C3")" = "ok member $via v4" ]' || fail "who paid an invoice is not in its package: $(ctl "check $C3")"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "A NODE THAT PAID AN INVOICE IS NOT CARRIED"
http_get c3 /order/$order | grep -q "Paid: 8 sat arrived, and tiny is package $via" || fail "the order's page once it is paid"
# Nobody was shown the package's key: its buyer asks for one, and nobody else.
[ "$(status_of "$(http_post c1 /v1/orders/$order/key '{}')")" = 404 ] || fail "ANOTHER NODE WAS GIVEN A KEY"
r=$(http_post c3 /v1/orders/$order/key '{}')
[ "$(status_of "$r")" = 200 ] || fail "a key for what an invoice bought: $r"
via_key=$(printf '%s' "$r" | tail -n +2 | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["package"]["id"] == sys.argv[1] and d["package"]["you"] is True and len(d["key"]) == 64, d
print(d["key"])' $via) || fail "the key: $r"
[ "$(status_of "$(http_post c1 /v1/package "{\"key\": \"$via_key\"}")")" = 200 ] || fail "the key that was given opens nothing"
# As the page's form asks: on to the order's page. And not from another site.
ip netns exec c1 python3 -c '
import http.client, sys
def post(origin):
    c = http.client.HTTPConnection(sys.argv[1], 5170, timeout=4)
    c.request("POST", "/buy", body="package=tiny&method=bolt11",
              headers={"Host": sys.argv[2], "Content-Type": "application/x-www-form-urlencoded", "Origin": origin})
    r = c.getresponse()
    return r.status, r.getheader("Location") or ""
status, at = post("http://" + sys.argv[2])
assert status == 303 and at.startswith("/order/o"), (status, at)
assert post("http://evil.example")[0] == 403' $E "$NPUB.fips:5170" || fail "the page's form for an invoice"
"$here/fips-exit" orders | grep -Eq "^$order +paid +invoice .* 8 sat +8 sat +0 +tiny +$via +$C3\$" || fail "orders: $("$here/fips-exit" orders)"
"$here/fips-exit" wallet | grep -Eq "^ +24 sat +0 sat +24 sat +reached +yes +$MINT\$" || fail "wallet: $("$here/fips-exit" wallet)"
ok "an invoice of the exit's mint buys a package over the mesh: when it is paid, for its buyer alone"

# The wallet and what was sold are kept when the service starts again, with
# its mint away: nothing is sold then, and who paid is carried all the same.
fresh=$(token 8)
kill $mint_pid; wait $mint_pid 2>/dev/null || true
restart_payd
wait_for '"$here/fips-exit" wallet 2>/dev/null | grep -Eq "^ +24 sat +0 sat +24 sat +away +no +$MINT\$"' \
  || fail "the wallet after the service started again: $("$here/fips-exit" wallet 2>&1)"
r=$(http_post c3 /v1/orders "{\"package\": \"tiny\", \"token\": \"$fresh\"}")
[ "$(status_of "$r")" = 503 ] && printf '%s' "$r" | grep -q '"code":"mint-away"' || fail "an order while the mint is away: $r"
r=$(http_post c1 /v1/orders '{"package": "tiny", "method": "bolt11"}')
[ "$(status_of "$r")" = 503 ] && printf '%s' "$r" | grep -q '"code":"mint-away"' || fail "an invoice while the mint is away: $r"
# The invoice c1 asked for by the form was not paid: it waits for its mint,
# and is not given up while that cannot be asked.
"$here/fips-exit" orders | grep -Eq "^o[0-9a-f]{16} +open +invoice " || fail "an invoice that waits, after a restart: $("$here/fips-exit" orders)"
# A token that did buy is still answered with what became of it.
r=$(http_post c3 /v1/orders "{\"package\": \"tiny\", \"token\": \"$t\"}")
[ "$(status_of "$r")" = 200 ] && printf '%s' "$r" | grep -q '"again":true' || fail "a token that bought, sent again while the mint is away: $r"
wait_for '[ "$(ask c1 4 8.8.8.2 100)" = 100 ]' || fail "who paid is not carried after the service started again"
[ "$(stat -c %a "$FIPS_EXIT_DIR/state/seed")" = 600 ] && [ "$(wc -w < "$FIPS_EXIT_DIR/state/seed")" = 24 ] || fail "the wallet's seed"
"$here/fips-exit" revoke $bought >/dev/null && "$here/fips-exit" revoke $also >/dev/null \
  && "$here/fips-exit" revoke $via >/dev/null || fail "revoke what was bought"
wait_for '[ "$(ctl "check $C1") $(ctl "check $C3")" = "ok free v4 ok free v4" ]' || fail "after revoking what was bought: $(ctl "check $C1") $(ctl "check $C3")"
sells "1gb:1GB:1500:30 5gb:5GB:6000:90" ""
restart_payd
ok "the wallet and who paid outlive the service, and nothing is sold while its mint is away"

# --- a removed client is cut off, even when `up` then stops -------------------------
# `remove` saves the list and applies it. If applying stops at something (here:
# the host has moved into the clients' range), the client must still be gone
# from the daemon, which is what carries it.
ip addr add 100.70.0.1/24 dev wan
"$here/fips-exit" remove phone-two >/dev/null 2>&1 && fail "remove went through on a host inside 100.64.0.0/10"
[ "$(ask c2 4 8.8.8.2 100)" = timeout ] || fail "A REMOVED CLIENT WAS STILL CARRIED BECAUSE up COULD NOT RUN"
ip addr del 100.70.0.1/24 dev wan
"$here/fips-exit" add $C2 phone-two >/dev/null
[ "$(ask c2 4 8.8.8.2 100)" = 100 ] || fail "a client put back on the list"
ok "a removed client is cut off by the daemon even when the rest of up cannot run"

# --- two members share an account, to the byte -------------------------------------
# 400 bytes. A request is 31 (20 + 8 + "100") and its answer 128: two
# exchanges fit, the third crosses the line with its answer, and that was the
# last, for both members. A name is answered and not counted.
[ "$(ctl "check $C3")" = "ok free v4" ] || fail "check: $(ctl "check $C3")"
[ "$(ctl "put pkg 400 0 0 $C3,$C1,$C2")" = "ok $C3=v4 $C1=v4 $C2=static" ] || fail "put: $(ctl "check $C3")"
r=$(resolve c3 $C3 example.com)
[ "${r% size=*}" = "answers=1 rcode=0 tc=0" ] || fail "a member's DNS query: $r"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member's first exchange"
[ "$(ask c1 4 8.8.8.2 100)" = 100 ] || fail "the other member's exchange"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "the exchange that crosses the line"
[ "$(ask c1 4 8.8.8.2 100)" = timeout ] || fail "A MEMBER WAS CARRIED PAST ITS ACCOUNT'S GRANT"
[ "$(resolve c3 $C3 example.com)" = timeout ] || fail "a member without bytes left got DNS"
[ "$(ask c2 4 8.8.8.2 100)" = 100 ] || fail "a client on the list, also a member"
[ "$(ctl "usage pkg")" = "$(printf 'account pkg 400 93 384 0\nok 1')" ] || fail "usage: $(ctl usage)"
# The same put again, as after a lost answer, takes nothing back.
[ "$(ctl "put pkg 400 0 0 $C3,$C1,$C2")" = "ok $C3=v4 $C1=v4 $C2=static" ] || fail "put again"
[ "$(ctl "usage pkg")" = "$(printf 'account pkg 400 93 384 0\nok 1')" ] || fail "a repeated put changed the count: $(ctl usage)"
ok "members share their account's bytes, counted exactly, and are carried no further"

# --- what a member gets, and what it does not ---------------------------------------
[ "$(ctl "grant pkg 1000000")" = ok ] || fail "grant"
[ "$(ask c3 6 2001:4860:1::2 100)" = 100 ] || fail "a member over IPv6"
[ "$(ask c3 4 8.8.8.2 1252)" = 1252 ] || fail "a 1280-byte packet towards a member"
[ "$(fetch c3 8.8.8.2)" = 200000 ] || fail "TCP for a member"
[ "$(fetch c3 2001:4860:1::2)" = 200000 ] || fail "TCP over IPv6 for a member"
# The internet only, as for any client; and no mail between servers, which
# the clients on the list may send.
[ "$(ask c3 4 192.168.77.2 100)" = timeout ] || fail "A MEMBER REACHED A PRIVATE ADDRESS ON THE UPLINK'S LAN"
ip netns exec c3 ping -c 1 -W 1 -q $C2V4 >/dev/null 2>&1 && fail "a member reached another client"
[ -z "$(fetch c3 8.8.8.2 25)" ] || fail "A MEMBER REACHED PORT 25"
[ "$(fetch c2 8.8.8.2 25)" = 200000 ] || fail "a client on the list and port 25"
"$here/fips-exit" accounts | grep -Eq "^pkg +1000000 +[0-9]+ +[0-9]+ +[0-9]+ +-$" || fail "accounts: $("$here/fips-exit" accounts)"
ok "a member reaches the internet in both families and nothing else, and not port 25"

# --- an account may have an end ------------------------------------------------------
# Whatever is left of its bytes: from that second on its members are not
# carried. A later end, or none, carries them again.
end=$(($(date +%s) + 8))
[ "$(ctl "until pkg $end")" = ok ] || fail "until"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member before its account's end"
while [ "$(date +%s)" -lt "$end" ]; do sleep 0.5; done
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "A MEMBER WAS CARRIED AFTER ITS ACCOUNT'S END"
[ "$(resolve c3 $C3 example.com)" = timeout ] || fail "a member got DNS after its account's end"
"$here/fips-exit" accounts | grep -Eq "^pkg .* \(over\)$" || fail "accounts after the end: $("$here/fips-exit" accounts)"
[ "$(ctl "until pkg 0")" = ok ] || fail "until 0"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member whose account has no end any more"
ok "an account that has an end carries its members until then, and not after"

# --- only replies go to the tunnel -----------------------------------------------------
# All of fd00::/8 is routed to the tunnel in this mode, for the members. That
# must be for the connections that came out of the tunnel and for nothing
# else: a host that also forwards into the mesh from its uplink (a fips
# gateway for its LAN, a published port) must go on doing so. Here the
# "internet" sends to a mesh node through the exit, as such a LAN would.
ip -n inet -6 route add fd00::/8 via 2001:4860:1::1
ip netns exec c1 python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.bind((sys.argv[1], 7777)); s.settimeout(4)
try: s.recv(100); print("arrived")
except socket.timeout: print("lost")' $C1 > "$FIPS_EXIT_DIR/forwarded" &
listener=$!
sleep 0.5
ip netns exec inet python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
for _ in range(3): s.sendto(b"hello", (sys.argv[1], 7777)); time.sleep(0.3)' $C1
wait $listener
ip -n inet -6 route del fd00::/8 via 2001:4860:1::1
[ "$(cat "$FIPS_EXIT_DIR/forwarded")" = arrived ] || fail "WHAT THE UPLINK SENT TO THE MESH WENT INTO THE TUNNEL INSTEAD"
ok "only the replies to what came out of the tunnel are sent to it"

# --- the list changes, the accounts stay --------------------------------------------
before=$(ctl "usage pkg")
"$here/fips-exit" add $C1 phone-one >/dev/null
[ "$(ctl "usage pkg")" = "$before" ] || fail "THE ACCOUNT CHANGED AT A RELOAD: $(ctl usage)"
[ "$(ctl "check $C1")" = "ok static" ] || fail "check: $(ctl "check $C1")"
[ "$(ask c1 4 8.8.8.2 100)" = 100 ] || fail "a member that was put on the list"
[ "$(ctl "usage pkg")" = "$before" ] || fail "a client on the list was counted: $(ctl usage)"
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member after the list was read again"
ok "an account outlives a reload of the list, and a client on the list is not counted"

# --- back to the list alone, and away -------------------------------------------------
conf ""
"$here/fips-exit" up >/dev/null
ip route show dev fipsexit0 | grep -q "100.64.0.0/10" && fail "the clients' whole range is still routed after paid mode"
ip -6 rule show | grep "lookup 5170" | grep -q fwmark && fail "paid mode's rule is still there"
nft list chain inet fips_exit replies >/dev/null 2>&1 && fail "paid mode's marking of connections is still there"
grep -q "daddr" "$fw/fips.d/fips-exit.nft" && fail "fips's firewall is still open to the mesh: $(cat "$fw/fips.d/fips-exit.nft")"
# The payment service still runs, and the mesh no longer reaches it.
[ "$(http_get c3 /v1/terms)" = unreachable ] || fail "THE PAYMENT SERVICE WAS REACHABLE WITHOUT PAID MODE"
# In paid mode again, and the service stops: as its unit does then, `up`, and
# the port is closed.
conf "ACCESS=paid\n"
"$here/fips-exit" up >/dev/null
grep -q "dport 5170" "$fw/fips.d/fips-exit.nft" || fail "the payment port after paid mode came back"
kill $payd_pid; wait $payd_pid 2>/dev/null || true
"$here/fips-exit" up >/dev/null
grep -q "dport 5170" "$fw/fips.d/fips-exit.nft" && fail "THE PAYMENT PORT STAYED OPEN AFTER THE SERVICE STOPPED"
conf ""
"$here/fips-exit" up >/dev/null
[ "$(ask c3 4 8.8.8.2 100)" = timeout ] || fail "a member was served without paid mode"
# The daemon would still answer this member, whose account has bytes: here it
# is fips's firewall alone that keeps its query out.
[ "$(resolve c3 $C3 example.com)" = timeout ] || fail "fips's firewall let a member's query through without paid mode"
[ "$(ask c1 4 8.8.8.2 100)" = 100 ] || fail "a client on the list after paid mode, through fips's firewall"
r=$(resolve c1 $C1 example.com)
[ "${r% size=*}" = "answers=1 rcode=0 tc=0" ] || fail "a listed client's DNS through fips's firewall: $r"
conf "ACCESS=paid\n"
"$here/fips-exit" up >/dev/null
[ "$(ask c3 4 8.8.8.2 100)" = 100 ] || fail "a member after paid mode came back"
"$here/fips-exit" down >/dev/null
ip route show dev fipsexit0 | grep -q . && fail "routes left after down in paid mode"
ip -6 rule show | grep -q "lookup 5170" && fail "rule left after down in paid mode"
ip -6 route show table 5170 2>/dev/null | grep -q . && fail "IPv6 routes left after down in paid mode"
nft list table inet fips_exit >/dev/null 2>&1 && fail "table left after down in paid mode"
[ -e "$fw/fips.d/fips-exit.nft" ] && fail "the drop-in in fips's firewall was left after down"
ok "leaving paid mode, and down, remove what it made"

# --- without a resolver, port 53 stays shut --------------------------------------
# Whatever else listened there would otherwise be open to the whole mesh.
kill $daemon_pid
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 || break; sleep 0.2; done
ACCESS=paid DNS_UPSTREAMS=off "$daemon" --clients "$FIPS_EXIT_DIR/clients" --mesh-if fips0 --tun fipsexit0 2>>"$FIPS_EXIT_DIR/daemon.log" &
for i in 1 2 3 4 5 6 7 8 9 10; do ip link show fipsexit0 >/dev/null 2>&1 && break; sleep 0.2; done
"$here/fips-exit" up >/dev/null
case "$(ctl stat)" in "ok epoch="*" accounts=0 resolver=0 counts=0") ;; *) fail "stat without a resolver: $(ctl stat)" ;; esac
grep -q "nexthdr { 4, 41, 44 } accept" "$fw/fips.d/fips-exit.nft" || fail "drop-in: $(cat "$fw/fips.d/fips-exit.nft")"
grep -q "dport 53" "$fw/fips.d/fips-exit.nft" && fail "PORT 53 WAS OPENED TO THE MESH WITH NO RESOLVER BEHIND IT"
"$here/fips-exit" down >/dev/null
ok "port 53 is opened to the mesh only while the daemon's resolver runs"
echo PASS
