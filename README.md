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
`BLOCK_CIDRS=<networks>` (IPv4 or IPv6, space separated: further
destinations no client may reach), `DNS_UPSTREAMS=<addresses>` (the
resolvers the clients' lookups are forwarded to; default: the host's
`/etc/resolv.conf`; `off` for no DNS at all) and `ACCESS=paid` (see
*Accounts* below; default `allow-list`, the list alone). The daemon reads
the last two when it starts: `sudo systemctl restart fips-exit` after
changing them.

On the client, enter this node's npub as the exit node. A direct fips link
between client and exit (add the exit as a peer) keeps latency down; it is
not required.

### Counting

`sudo fips-exit status` says how many packets and bytes the exit has carried
since it started, for all clients together. Whose they were is not kept.

With `CLIENT_COUNTS=on` in the config (and a restart, since the daemon reads
it when it starts) the daemon also counts each client on the list: the bytes
carried from it and to it. `status` then shows a line for each.

- The counts are two numbers for a client, in the daemon's memory. They are
  not written anywhere, hold no times and no destinations, and are read over
  the daemon's socket, which is root's.
- A client's count starts when it is put on the list or the daemon starts,
  and is gone when the client is removed or the daemon stops.
- The daemon counts or not as the config said when it started. `status` asks
  the daemon, and says so when the config has changed since.
- It is off unless you turn it on. An operator who counts should say so to
  the people whose devices are on the list.

### Being found

An exit says nothing about itself unless it is told to. With relays named
in the config it publishes an advert on Nostr, signed with the node's fips
key, which is what a fips2go phone's *Find exit nodes* reads:

```sh
ADVERT_RELAYS="wss://relay.example.org ws://npub1….fips"   # where to say it
ADVERT_NAME="An exit"                    # optional, up to 40 characters
ADVERT_ABOUT="In a rack in Frankfurt"    # optional, up to 200
COUNTRY=DE                               # optional: where the exit is, ISO 3166-1 alpha-2
```

A value in double quotes is taken as it is, a `#` included; outside quotes
a `#` begins a comment.

```sh
sudo fips-exit advert show                           # the event, sent nowhere
sudo fips-exit advert                                # publish it now
sudo systemctl enable --now fips-exit-advert.timer   # and every hour
```

- The advert says that this npub is an exit, the name and the note, the
  country, and `allow-list`: that it serves whom its operator put on its
  list. It says that with `ACCESS=paid` as well, for as long as nothing here
  takes a payment. Anyone can read it. The country is your claim; nobody
  checks it.
- It is valid for three hours and published again every hour. An exit that
  stops drops out of the lists within three hours; nothing takes the advert
  back sooner.
- A relay on the internet (`wss://`) also learns this host's address, as
  with any connection. A relay on the mesh is `ws://<npub>.fips`. fips2go
  looks on `wss://relay.damus.io`, `wss://nos.lol` and `wss://offchain.pub`
  unless its user changed that, and on the mesh relays its user named.
- The key is read from `/etc/fips/fips.key` (`FIPS_KEY=` in the config if it
  is elsewhere), so this runs as root, like the rest. A node that keeps no
  identity on disk cannot advertise: its npub is another one after every
  start.
- What the tags are is specified in `payd/proto`; the script and that crate
  are held to the same file of cases.

### The payment service

`fips-exit-payd` runs beside the exit, as a user of its own with no
privilege, and answers at `http://<npub>.fips:5170/`, the exit's npub being
its name on the mesh. It says what the exit costs, keeps the packages the
operator gives away, and takes no payment yet:

```sh
ACCESS=paid
PRICE_MSAT_PER_GB=2000000                   # millisatoshi a GB of 10^9 bytes: 2000 sat
PACKAGES="1gb:1GB:1500:30 5gb:5GB:6000:90"  # optional: id:size:sat:days, sizes in bytes, MB, GB or TB
MINTS="https://mint.example.org"            # optional: the Cashu mints that will be taken
PAY_PORT=5170                               # optional, the default
```

```sh
sudo systemctl enable --now fips-exit-payd
```

- `http://<npub>.fips:5170/v1/terms` is the exit's terms as JSON, and `/`
  the same as a page for a browser on the mesh: price, packages, mints, name
  and country, and who is asking, with its package if it is in one. A caller
  is known by the address its connection comes from, which fips
  authenticates. `methods` is empty: there is no way to pay yet.
- The npub is the only way to the exit: a node reaches a fips address only
  once it has resolved the npub it belongs to. The service answers requests
  for `<npub>.fips:5170` and for nothing else, not the bare address, and
  does not start without the node's npub (`/etc/fips/fips.pub`) or with one
  that is not this node's.
- In paid mode `fips-exit up` opens that port in fips's firewall and in ufw,
  to this node's address, for the whole mesh, while the service listens
  there, and only then: nothing else that listens on the port is to be
  reached. The service's unit runs `up` when it starts and stops, so the
  port follows it. `status` says whether it answers.
- The service reads the config when it starts: restart it after a change.
  With `ACCESS` other than `paid` it says so and stops.
- Only `GET`, and only so much at a time: 64 connections, 8 from one
  address, a header of 16 KiB within 5 seconds, a minute for a connection.

Packages the operator gives away, for nothing, until the service sells
them:

```sh
sudo fips-exit grant 5GB 30 npub1…,npub1… a friend   # 5 GB for 30 days (0: no end), for these devices
sudo fips-exit packages                               # each package: what is left, until when, who is in it
sudo fips-exit top-up <package> 1GB 7                 # more bytes, and more days
sudo fips-exit members <package> npub1…               # who shares it, in place of who did
sudo fips-exit revoke <package>                       # taken back
```

- A package is an account in the daemon, kept as the service says: its
  members are carried until its bytes are used up or its time is over, and
  carried again when it is topped up. A device is in one package at a time.
- `grant` prints the package's key once, and the service keeps only its
  hash. Whoever has the key manages the package: on the exit's page
  (*A package of yours*), or as JSON:

  ```text
  POST /v1/package          {"key": "…"}                                  the package, and who is in it
  POST /v1/package/members  {"key": "…", "add": ["npub1…"], "remove": []}   the same, changed
  POST /v1/leave            {}                                            this device out of its package
  ```

  The key holder sees who is in the package and can take them out. A
  device is put in by nobody but itself: it asks, from its own address,
  with the key (the page's *Add this device*), and is moved out of
  whatever package it was in. To add a phone, give the key to the phone.
  A device can always take itself out, with no key at all. So a key holder
  cannot keep a stranger's device in its package, take one out of the
  package it paid for, or learn whether one has a package here. Members
  are shown by the npub they were named by. The operator's `grant` and
  `members` can put any device in.
- A request that changes something is JSON, or a form from the exit's own
  page (its `Origin`): a page on another site cannot make a device leave
  its package.
- The service keeps its packages in `/var/lib/fips-exit-payd`, and what the
  daemon counts is written there every two seconds: a restart of the daemon
  or of the service loses at most those seconds, in the members' favour.
- The service is in the group `fips-exit`, which `install.sh` makes; the
  daemon opens its control socket to that group in paid mode. The operator's
  commands go to the service's own socket, `/run/fips-exit-payd/admin.sock`,
  which only root and the service can open.

### Accounts

With `ACCESS=paid` in the config the exit also carries addresses that are
not on the list, for a number of bytes: the *members of an account*. This is
the base for selling access, not the selling: nothing in this repository
makes an account yet. Whatever does, does it over the daemon's socket,
below.

- An account has bytes granted and bytes used. Its members share them.
- A member's packet is counted once it has been passed on: the length of the
  inner packet, in both directions. That is before the firewall decides, so
  a packet to a destination the exit refuses is counted and then dropped.
- When the count reaches the grant, the members are not carried any
  further. The packet that crosses the line still is.
- An account may have an end as well: a time from which its members are not
  carried, whatever is left of its bytes. That is how time is sold: a grant
  too large to use up, and an end. The time is this machine's clock.
- DNS is answered for a member while its account has bytes and is not over,
  and not counted.
- A client on the list is never counted, and wins over a member with the
  same address or the same derived IPv4 address, at once. A member whose
  derived IPv4 address is another client's is carried for IPv6 only, and
  gets the address within a minute of its becoming free, which is five
  minutes after its holder gave it up.
- Accounts are kept in memory. After a restart there are none.

Accounts are made over a Unix socket, `/run/fips-exit/control.sock`, which
the daemon opens only with `ACCESS=paid` or `CLIENT_COUNTS=on` (or
`--control <path>`), for root alone. Opened for the counts alone it takes
no accounts. One command a line; every answer ends in a line that begins `ok` or
`err`; every number is a total, so that a command sent twice changes
nothing.

```text
put <account> <granted> <used_in> <used_out> <address,…|-> [until]
                                                              make it, or raise its numbers; replace its members
grant <account> <granted>                                     raise what it may use, in all
until <account> <unix seconds|0>                              when it ends; 0 for no end
                                                              (put moves an end later only; this sets it)
members <account> <address,…|->                               replace its members
drop <account>
usage [account]                                               account <name> <granted> <used_in> <used_out> <until>
clients                                                       client <address> <bytes from it> <bytes to it>, with CLIENT_COUNTS=on
check <address>                                               static | member <account> v4|no4 | free v4|no4
stat                                                          epoch=<start> accounts=<n> resolver=<0|1> counts=<0|1>
```

Whoever can write to that socket decides who uses the exit and for how much.
`sudo fips-exit accounts` shows the accounts and what each has used.

What `ACCESS=paid` changes on the machine, beyond what the list alone does:

- **The firewalls are opened to the whole mesh, not to the listed clients.**
  The members are not known to the script, so fips's firewall and ufw admit
  tunnel packets (next header 4, 41 and 44) from any node of the mesh to this
  node's fips address, and DNS queries while the daemon's resolver runs. The
  daemon is then the only place where it is decided who is carried.
- **All of `100.64.0.0/10` is routed to the tunnel.** `up` refuses to start
  on a host that has an address, a route or a resolver in that range itself:
  the route would take the host's own traffic.
- **IPv6 replies are found by a mark.** A connection that comes out of the
  tunnel is marked (one bit, `0x8000000`, of the connection mark and of the
  packet mark), and only packets of such connections are routed to the
  tunnel for `fd00::/8`. Whatever else the host forwards to unique-local
  addresses goes where it went before. Other software that uses those marks
  keeps its bits, as long as it leaves this one alone.
- **A member cannot connect to TCP port 25.** A client on the list can.
- Leaving paid mode again (`ACCESS=allow-list`, restart) puts back the
  routes and openings for the listed clients alone.

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

- **The exit answers its clients' DNS.** A fips2go phone sends every lookup
  to UDP port 53 on its exit's fips address, over the mesh, so that no name
  leaves through the phone's own network. The daemon forwards a listed
  client's query to the host's resolvers and returns the answer. Only listed
  clients are answered, so it is not an open resolver for the mesh. It caches
  nothing and validates nothing: it is as good as the resolver behind it,
  which also sees the names (from the exit, not from the client). An answer
  too large for one mesh packet is returned truncated; UDP only. At most 64
  of one client's queries are being forwarded at a time, of 256 in all; one
  more is dropped, and the client's resolver asks again.

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
  the internet sees the exit's address. Its operator may also count the
  bytes each client moves (`CLIENT_COUNTS=on`, under *Counting*); by default
  that is not kept.
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

## Planned

Optional paid public exits (an advert with price and country, prepaid data
packages, pay-as-you-go) are designed in
[`docs/paid-exit.md`](docs/paid-exit.md). Its first three phases are
here: accounts and `ACCESS=paid`, the advert, and the payment service's
frame, all above. Nothing yet takes a payment, so no exit says that it is a
paid one.

## Test

```sh
cargo test                      # the daemon's admission and routing rules
cargo build --release && unshare -Urnm test/netns.sh
cargo test --manifest-path payd/Cargo.toml   # the advert's tags, the price, the payment service
python3 -I -m unittest discover -s test      # the script's advert
```

The namespace test runs the payment service too, so it needs it built:
`cargo build --release --manifest-path payd/Cargo.toml`.

The second runs the daemon and the script against the real kernel, without
root and without fips: network namespaces stand in for two clients, the
exit and the internet, and a 1280-byte link stands in for the mesh. It
checks both families, NAT, full-size packets in both directions, TCP, the
binding of a client to its addresses, isolation, removal and teardown. Then
the same exit with `ACCESS=paid`, behind a stand-in for fips's firewall: no
node without an account is carried, two members share an account counted to
the byte and are cut off at the grant, a member reaches the internet and
neither the uplink's LAN nor port 25, the payment service tells a node that
is no client what the exit costs and who it is, and leaving the mode removes
what it made, the opening for the payment service with it.

The third is `payd/`, a workspace with a lockfile of its own, so that the
daemon keeps its one dependency. `payd/proto` is a crate with no
dependencies that the exit and its clients share: what an exit's advert on
Nostr says (who it serves, where it is, and for a paid exit what it costs)
and what a number of bytes costs at a price. It is checked against
`payd/proto/vectors/advert.json`, and so is every other implementation of
the same. `payd/payd` is the payment service: its config, its terms and
page, and its HTTP server's limits, over a real socket.

The fourth is the script's side of the advert: the signature against the
vectors of BIP-340, the tags against the same file of cases, and the
publishing against a relay that runs inside the test. Nothing in the tests
talks to a relay on the internet.

## Contributing

Changes come as pull requests against `main`. The `checks` job has to pass:
it runs the daemon's unit tests and `test/netns.sh`. Read
[`PR-REVIEW.md`](PR-REVIEW.md) first — it is the checklist a PR is reviewed
against — and [`SECURITY-REVIEW.md`](SECURITY-REVIEW.md) for where the trust
boundaries are, what is known to be missing, and which design choices are
deliberate. Say in the PR how the change was verified, and what was not.
