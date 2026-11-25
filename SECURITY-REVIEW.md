# Security review context for fips-exit

Security review here is done by hand, as part of the PR review in
`PR-REVIEW.md`. This file is the context that review needs: where this
codebase's trust boundaries are, what would be serious, which design choices
are deliberate and so not findings, and which gaps are known.

## What this is

Two programs that turn a Linux fips node into an exit node, both running as
root:

- `fips-exitd` (`src/main.rs`): the data plane. Raw sockets for IP protocols
  4 and 41 on the mesh interface, one TUN device, and the rule for who may
  use the tunnel and as whom.
- `fips-exit` (a Python script): everything around it. The client list, the
  TUN's routes, NAT to the uplink, an nftables table of its own, and the
  openings it makes in two firewalls it knows (fips's own, and ufw).

Clients are fips2go phones and other fips nodes. The wire contract is shared
with fips2go (`shim/src/exit.rs`) and its exit container
(`exit-node/exitctl.py`): plain IP-in-IPv6, next header 4 or 41, and an inner
IPv4 address derived from the client's fips address.

## Untrusted input, in rough order of exposure

1. **Packets from the mesh.** Any node on a public mesh can send IP protocol
   4, 41 or 44 to this node. The kernel reassembles outer fragments; the
   daemon then reads the inner packet's version, length and source address
   (`Clients::admits`) before anything is written to the TUN. What fips
   guarantees is the outer source: it is the session's authenticated peer.
   Everything inside is the sender's.
2. **Packets from the internet**, arriving on the TUN after NAT, routed back
   to a client by their destination (`Clients::route`).
3. **The client list**, `/etc/fips-exit/clients`. Root-owned, but written by
   hand as well as by `add`: the daemon skips a line it cannot use rather
   than stopping, and must not be led by one into admitting someone else.
4. **Operator input to the script**: an npub, an address or a name on the
   command line, and `WAN`, `MESH_IF`, `TUN` and `FIPS_FIREWALL` in
   `/etc/fips-exit/config`. These end up in nftables scripts and in
   arguments of `ip` and `sysctl`. Not hostile, but a typo there runs as
   root.

## Things that would be serious in this codebase

- **Admission bypass.** A packet reaching the TUN from a node that is not a
  listed client, or with an inner source that is not the sender's own
  address. Either lets a stranger use the exit, or lets one client send as
  another.
- **Misrouted replies.** A packet from the TUN delivered to a client other
  than the one its destination belongs to. Two clients that derive one inner
  IPv4 address (22 bits) are exactly this; the list must never hold both.
- **The address contract drifting.** `inner_ipv4` exists in the daemon, in
  the script, and in fips2go. If they disagree the exit silently refuses
  every client, or routes replies to nobody. CI checks the daemon and the
  script against the same vectors fips2go tests.
- **Firewall leaks.** A client reaching this host, another client, or
  anything that is not the public internet — the uplink interface is usually
  the LAN too, so the destination lists (`BLOCKED_V4`, `BLOCKED_V6` in the
  script, the same as fips2go's container plus IPv6) are what keeps a client
  off it, and a change that shortens them needs a reason; or the internet opening a connection to a
  client. Also: rules left behind after `down`, and rules of someone else's
  (fips's table, ufw's chains) changed beyond the tagged ones this script
  adds.
- **Injection into root's commands.** Anything from the list, the config or
  the command line reaching an nftables script or a command line without
  being parsed into an address or checked as an interface name first.
  Commands are run as argument lists, never through a shell.
- **Parsing the inner packet.** Out-of-bounds reads and length arithmetic in
  the two places that look inside a packet. A panic here is a remote
  denial of service for every client.

## Known gaps — real, not yet fixed

- **The uplink's own public address is not blocked** when the exit is
  behind a NAT router. From inside, that address is the router: its admin
  page and, through NAT loopback, every port it forwards. fips2go's exit
  container looks the address up and keeps it blocked as it changes; here
  the operator has to put it in `BLOCK_CIDRS`.
- **No DNS for clients.** A fips2go phone sends every lookup to its exit's
  port 53. Nothing answers here.
- **No limit on clients, bandwidth or destinations** beyond the list itself.
- **The config's interface names are not checked.** `WAN`, `MESH_IF` and
  `TUN` from `/etc/fips-exit/config` are placed in the nftables script as
  written. The file is root's, so this is a typo running as root rather than
  an attack, but criterion 8 of `PR-REVIEW.md` is not yet true of them.

## Deliberate design choices — not findings

- No encryption or authentication of its own: fips encrypts end to end and
  authenticates the outer source, and the daemon keys on that.
- The daemon skips a bad line in the client list instead of refusing to
  start: a typo in one line must not cut off every other client.
- `up` turns on IPv4 and IPv6 forwarding and leaves them on after `down`;
  it sets `accept_ra=2` on an uplink that had 1. Both are stated in the
  README.
- The script's own nftables chains have policy accept. They only see traffic
  to and from the TUN, and each ends in an explicit verdict.
- The exit's operator sees its clients' traffic, as any VPN endpoint does.
