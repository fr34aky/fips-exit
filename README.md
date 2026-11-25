# fips-exit

Turns a Linux [fips](https://github.com/jmcorgan/fips) node into an **exit
node**: mesh clients send it their internet traffic, IPv4 and IPv6, and it
forwards that traffic to the legacy internet from its own addresses.

The client side is in [fips2go](https://github.com/fr34aky/fips2go)
(Overview → Internet route; it sends IPv4 only for now). Any Linux fips node
can be a client too,
with the kernel's `ip6tnl` (see `test/netns.sh` for the exact commands).

## How it works

Transport only. A client's packet becomes the payload of a mesh packet to
the exit, with next-header 4 (IPv4) or 41 (IPv6) — plain IP-in-IPv6,
RFC 2473. There is no tunnel header and no second encryption: fips already
encrypts and authenticates every packet end to end, and the outer source
address *is* the client's identity.

Two parts run on the exit:

- **`fips-exitd`**, a small daemon (Rust, one dependency): raw sockets for
  the two next-header values on the mesh side, one TUN device
  (`fipsexit0`) on the other. It admits a packet only from a listed client
  and only when its inner source is that client's own address, and sends a
  reply to the client its destination belongs to. The client list is the
  allow-list: no entry, no traffic.
- **`fips-exit`**, a script: the client list, the routes to the TUN, NAT
  (masquerade) to the uplink for both families, and an nftables table that
  lets clients reach the internet only — not this host, its other networks,
  or each other — and clamps the TCP MSS.

Addresses inside the tunnel need no negotiation. A client's IPv6 source is
its fips address (`fd…`). Its IPv4 source is in `100.64.0.0/10`: that
prefix with the low 22 bits of the three bytes after the `fd` of the fips
address (`0x64400000 | ((a[1] << 16 | a[2] << 8 | a[3]) & 0x3fffff)`). Both
sides derive it, it is the same formula fips2go and its exit container use,
and `add` refuses a client whose derived address clashes with an existing
one. The range is carrier-grade NAT space, so that a client's address does
not fall inside a LAN; an exit whose own uplink is behind carrier-grade NAT,
or that also runs an overlay using the range (Tailscale does), can hold a
client's address itself and should not be used as an exit.

## Install

Needs: a running fips with its TUN (`fips0`), Python 3, iproute2, nftables,
and a Rust toolchain to build the daemon.

```sh
./install.sh
sudo systemctl enable --now fips-exit
```

## Use

```sh
sudo fips-exit add npub1…  alice-phone   # allow a client (npub or fd… address)
sudo fips-exit list
sudo fips-exit remove alice-phone
sudo fips-exit status
```

Changes apply at once; the daemon re-reads the list on SIGHUP, which the
script sends. The list is `/etc/fips-exit/clients`. `/etc/fips-exit/config`
takes `WAN=<interface>` (default: the interface of the default route),
`MESH_IF=<interface>` (default `fips0`), `TUN=<name>` (default `fipsexit0`)
and `BLOCK_CIDRS=<networks>` (IPv4 or IPv6, space separated: further
destinations no client may reach).

On the client, enter this node's npub as the exit node. A direct fips link
between client and exit (add the exit as a peer) keeps latency down; it is
not required.

## Packet sizes

A mesh packet is at most 1280 bytes at fips's default transport MTU, so 1240
bytes are left for the inner packet, while the tunnel's own MTU is 1280 —
the least IPv6 allows.

- TCP is kept to one mesh packet by its MSS, clamped in both directions
  (1200 for IPv4, 1180 for IPv6).
- Anything else between 1241 and 1280 bytes (QUIC, mostly) travels as two
  fragments of the *outer* packet, in both directions and both families:
  RFC 2473 section 7.1. The kernel does the fragmenting and the reassembly
  on the daemon's sockets.

This is why there is a daemon at all: Linux's own `ip6tnl` does not
fragment the outer packet, so a kernel-only exit loses exactly those IPv6
packets, and QUIC over IPv6 stalls. Raising fips's transport MTU to about
1400 on both ends of a direct link avoids the fragments altogether; that is
an optimisation, not a requirement.

## What the operator and the client should know

- **A client reaches the public internet and nothing else.** Not this host,
  not another client, and not the uplink's own network: private and
  unique-local ranges, link-local, carrier-grade NAT space, multicast and
  the documentation ranges are refused as destinations in both families,
  whatever interface they would leave by. On a home network the uplink is
  also the LAN, so without this a client could open the router's admin page.
  `BLOCK_CIDRS` adds to the list; nothing takes away from it. What is NOT
  blocked yet is the uplink's own *public* address when the exit sits behind
  a NAT router: from inside, that address is the router. If that matters,
  put it in `BLOCK_CIDRS`.

- The exit sees its clients' internet traffic as any VPN endpoint does, and
  the internet sees the exit's address.
- `fips-exit` adds its own nftables table and opens two firewalls it knows:
  fips's own (a drop-in `fips.d/fips-exit.nft` admitting next-header 4, 41
  and 44 from the clients' addresses; `FIPS_FIREWALL=` in the config to
  leave it alone) and ufw (runtime rules in its before-chains, tagged
  `fips-exit`; `ufw reload` drops them and `fips-exit up` restores them).
  Any other host firewall that drops by default must allow that input on
  the mesh interface and forwarding for the TUN device itself.
- `up` turns on IPv4 and IPv6 forwarding, and sets `accept_ra=2` on the
  uplink if it was 1, so an SLAAC uplink keeps its default route. `down`
  leaves forwarding as it is.
- Run a recent fips on the exit. A route through older nodes carries less
  than 1280 bytes; the exit's fips then has to split its packets for that
  route, which older versions do not do.
- fips2go also ships an exit node of its own, a Docker container
  (`exit-node/` there). It speaks the same contract and needs none of this
  repository; the two differ in what they offer, not in what a client sends.
- Other Linux fips nodes can be clients with the kernel's `ip6tnl`
  (`mode any`, `encaplimit none`, remote = the exit's fips address; the
  commands are in `test/netns.sh`). A kernel client cannot send a non-TCP
  IPv6 packet over 1240 bytes, for the reason above.

## Test

```sh
cargo test                      # the daemon's admission and routing rules
cargo build --release && unshare -Urnm test/netns.sh
```

The second runs the daemon and the script against the real kernel, without
root and without fips: network namespaces stand in for two clients, the
exit and the internet, and a 1280-byte link stands in for the mesh. It
checks both families, NAT, full-size packets in both directions, TCP, the
binding of a client to its addresses, isolation, removal and teardown.

## Contributing

Changes come as pull requests against `main`. The `checks` job has to pass:
it runs the daemon's unit tests and `test/netns.sh`. Read
[`PR-REVIEW.md`](PR-REVIEW.md) first — it is the checklist a PR is reviewed
against — and [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) for where the trust
boundaries are, what is known to be missing, and which design choices are
deliberate. Say in the PR how the change was verified, and what was not.
