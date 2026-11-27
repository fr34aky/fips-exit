# Paid public exits: design

**Status: phases 1 to 3 of ten are implemented, and the first half of
phase 4** (accounts in the daemon and `ACCESS=paid` in the script; the
advert, with a country; the payment service, which tells what the exit
costs and keeps the packages the operator gives away. The README's
*Accounts*, *Being found* and *The payment service* sections are what they
do now). A buyer managing its own package with its key, and everything from
taking a payment on, is design. This document says what is to
be built, in which order, and what was decided against. Each phase arrives
as its own pull request and moves the parts it implements from here into the
README and `SECURITY-REVIEW.md`; where building a phase changed the design,
the text here was changed with it.

## What this is for

Today an exit serves the clients its operator lists by hand
(`/etc/fips-exit/clients`). This design adds an **optional** second mode: a
public, paid exit.

- The exit announces itself on nostr, with its price and its country.
- Anyone on the mesh can buy access: a prepaid data package (1 GB, 5 GB, …)
  paid with Lightning, on-chain bitcoin or a Cashu token, or pay-as-you-go
  with a Cashu Spilman payment channel.
- The buyer of a package names the fips npubs that share it.
- The exit meters what each buyer uses and stops carrying when it is used up.

An exit that does not turn the mode on behaves exactly as it does now.

## Decisions

| Question | Decision |
|---|---|
| Where the shop lives | In this repository, self-contained: one node, SQLite, no separate backend. |
| The advert | fips2go's existing exit advert, extended: kind 30078, `d=fips-exit`, a new access word `paid`, and tags for price, payment methods, packages and country. |
| Lightning and on-chain | Through a Cashu mint the operator chooses. The exit runs no Lightning node and no bitcoind. |
| Pay-as-you-go | Cashu Spilman channels, including a payer in fips2go. Built last, behind a build feature that is off by default. |
| Buying on a phone | A native screen in fips2go and a web page served by the exit. Both use one API. |

### Decided against

- **Reusing fips-exit-gate as the shop.** It already sells packages (portal,
  BTCPay, phoenixd, guest npubs), but for SOCKS and WireGuard exits and with a
  Go backend and Postgres beside each exit. A public exit should be one
  install. Its data model, its idempotent settlement and its rule *never
  implement minting or blind signatures ourselves* are kept.
- **nostr-vpn's offer format** (kind 37196, `fips/paid-route-offer`).
  nostr-vpn sells exits over fips too, with nostr offers and Spilman channels,
  but its tunnel and its payment protocol are its own: its clients could list
  our exits and not use them. Its vocabulary is borrowed (price in msat per
  GB, a free allowance and a grace allowance, collect at 12 h and refund at
  24 h).
- **The fips service-record draft** (kind 37196 as a placeholder). It is not
  implemented, and nostr-vpn already uses that kind number for something else.
- **An own Lightning node on the exit** (phoenixd, BTCPay). Every paid exit
  would need that infrastructure. The mint gives an invoice instead; the
  price is that the mint holds the money until the exit sweeps it out.
- **A JSON control protocol for the daemon.** `fips-exitd` runs as root with
  one dependency; a hand-written JSON parser there is a larger surface than a
  strict line of words.
- **Channels first.** The channel specification is a draft that changed
  incompatibly in autumn 2026, and its two Rust implementations do not speak
  to each other (see *Channels*). Packages need none of it.

## What is already there

- **The payer is authenticated by the mesh.** fips rebuilds a packet's source
  address from the session's key, and the daemon already keys on that
  (`src/main.rs`, `Clients::admits`; `SECURITY-REVIEW.md`, *Untrusted input*).
  A TCP connection to the exit's mesh address therefore proves the caller's
  npub, with no login.
- **An exit advert exists, in fips2go.** `exit-node/advert.py` there publishes
  kind 30078 with `d=fips-exit`, `v=1`, `access=open|allow-list`, `name`,
  `about` and a NIP-40 `expiration`, signed with the node's fips key by a
  standard-library BIP-340 signer and WebSocket client. The phone reads it in
  `shim/src/exitfind.rs` and drops an advert whose access word it does not
  know. This repository publishes no advert yet.
- **The daemon sees every packet with its client's address**
  (`from_mesh`, `from_tun`), which is where metering belongs. Today it counts
  packets for the whole exit, not bytes per client (`Counters`).
- **fips-ui drives this repository's script.** Its helper runs
  `fips-exit add <fd-address> [name]` and `fips-exit remove <fd-address>` and
  uses their exit status; its server reads `/etc/fips-exit/clients` itself
  and expects both programs under `/usr/local/sbin`. None of that may change.

## Architecture

```text
 client (fips2go / Linux)                      exit node
 ─────────────────────────                     ──────────────────────────────────────────────
 tunnel packets ───────────── mesh ──────────▶ fips-exitd   (root, libc only)
                                                 tunnel + DNS; new: accounts = byte meter + gate
                                                 new: control socket /run/fips-exit/control.sock
                                                        ▲ grant / members / usage
 HTTP to [exit fd…]:PORT ──── mesh ──────────▶ fips-exit-payd  (new, unprivileged)
   terms, orders, members,                       packages and orders (SQLite), Cashu wallet,
   channel updates, shop page                    mint quotes; later: channels
                                                        │ HTTPS
                                                        ▼
                                                 Cashu mint(s)
 nostr relays ◀── advert, signed with fips.key ─ fips-exit advert  (root script, on a timer)
```

Three rules hold it together.

1. **The root daemon stays small and knows nothing about money.** It learns
   only "this address belongs to account A, which may use N bytes".
2. **Every way of paying ends as the same thing:** bytes granted to an
   account. A package, a channel update and an operator's manual grant all go
   through one interface.
3. **The advert is a hint; the exit is the authority.** A client reads price
   and country from nostr, then asks the exit itself for its terms over the
   mesh before it pays. Nothing but the npub is trusted from an advert.

One configuration file, `/etc/fips-exit/config`, holds the mode, the country,
the prices, the packages, the mints and the relays. The advert and the terms
are both made from it, so they cannot disagree. The names of the settings are
fixed by the pull requests that add them.

## Metering and admission

### Accounts

Besides the static client list, which stays as it is and stays unmetered, the
daemon holds **accounts**. An account has three numbers: bytes granted, bytes
used towards the internet, bytes used towards the clients. An address is a
member of at most one account; several addresses may share one, which is how
a package serves several npubs.

- A member's packet is carried while `used_in + used_out < granted`. The
  counters only grow and nothing is ever subtracted, so no arithmetic can
  wrap round to "unlimited". The packet that crosses the line is still
  carried: the overdraft is one packet per thread.
- A packet is counted after it was written to the TUN, or sent to the client,
  successfully. A packet the daemon could not pass on is not billed.
- A static client always wins over a member with the same address or the same
  inner IPv4 address.
- A reload of the static list (SIGHUP, which every `add` and `remove` sends)
  rebuilds only the static part. Today's reload replaces the whole table
  (`State::reload_if_asked`); with accounts it must leave them in place.
- Accounts live in memory. After a restart the table is empty and nobody but
  the static clients is carried, until the payment service has pushed its
  state again.

**To fix before any of this:** `Clients::admits` accepts an IPv4 packet when
its inner source equals `inner_ipv4(src)`, without checking that `src` is the
address that owns that inner address. Today this cannot be used, because a
second client with a clashing inner address is never on the list. A member
admitted for IPv6 only (below) would be exactly such a client, and could then
send as the address's real holder.

### What is billed

The length of the inner IP packet, in both directions, for every packet the
daemon passed on.

- The daemon counts before the kernel's firewall decides. A packet to a
  destination the exit refuses (`BLOCKED_V4`, `BLOCKED_V6`, port 25) is
  billed and then dropped. The README has to say so.
- Nothing arrives for a client that it did not ask for: `to_client` in the
  script's table carries only established and related traffic.
- DNS through the daemon's resolver is answered for static clients and for
  members of an account that still has bytes, and is not billed. A client
  has 64 queries in flight at most, of 256 for the exit. Before, the 64 were
  for the whole exit, so one member could have used them all.
- A gigabyte is 10⁹ bytes. The amount due for `n` bytes at a price of `p`
  millisatoshi per gigabyte is `ceil(n × p / 10⁹)` millisatoshi.

### The control socket

A Unix stream socket, `/run/fips-exit/control.sock`, made by the daemon.
One command per line, words separated by spaces, one line in reply. Every
command carries totals, never differences, so that a command sent twice
because its reply was lost changes nothing.

| Command | Does |
|---|---|
| `put <account> <granted> <used_in> <used_out> <address,…> [until]` | Makes the account or brings it up to these values: each number is raised to the given one, never lowered; the members are replaced. The last word is its end, set when the account is made and afterwards only moved later. |
| `grant <account> <granted>` | Raises the grant to this total. |
| `until <account> <unix seconds>` | Sets when the account ends, whatever is left of its bytes, later or earlier; 0 for no end. |
| `members <account> <address,…>` | Replaces the members. |
| `drop <account>` | Removes the account and its members. |
| `usage [account]` | One line per account: granted, used in, used out, and its end. |
| `clients` | One line per client on the operator's list, if the operator has them counted (`CLIENT_COUNTS=on`): the bytes from it and to it. |
| `check <address>` | Says whether this address could be a member here, and whether it would get its inner IPv4 address. |
| `stat` | The daemon's start time as an epoch, the number of accounts, whether the resolver runs, whether listed clients are counted. |

- The epoch is how the payment service notices a restart: a new epoch means
  an empty table, and it pushes everything again, each account's end with
  its `put`: an account put without one has none, and one sold as time
  would be carried again until an `until` followed. A restart is routine, since
  the unit requires `fips.service` and restarts with it.
- Bytes used between the payment service's last `usage` and a restart of the
  daemon are forgiven. That is a few seconds of traffic, in the client's
  favour.
- Limits: a line is at most 4096 bytes; an account name is 1 to 64 of
  `[A-Za-z0-9._-]`; a number is digits only and at most a quarter of what a
  u64 holds, so that adding real traffic to it cannot wrap; an account has
  at most 32 members; there are at most 16384 accounts; four connections at
  once, each with a five-second timeout.
- A line the daemon cannot use gets `err <reason>` and the connection goes
  on. A line that is too long closes it. A socket that cannot be made is
  said loudly and the tunnel keeps running, as for the resolver today.
- The socket belongs to root in the first phase. The group that lets the
  payment service in arrives with that service.

What a peer on this socket can do: admit any fips address and give it any
number of bytes, read everyone's usage, drop accounts. What it cannot do:
touch or shadow a static client, name a file or a command, change a route or
a firewall rule. The payment service is therefore part of what decides
admission; if it is taken over, the exit is open.

### The inner IPv4 address

A client's inner IPv4 address has 22 bits of its fips address. Two addresses
that clash can be found in seconds, so on a public exit a clash is something
to expect and something an attacker can arrange.

- The first holder keeps the address. A later member with the same inner
  address is admitted for IPv6 only.
- `check` lets the shop tell a buyer before any money moves. fips2go sends
  IPv4 only, so for a phone "IPv6 only" means "not on this exit".
- A member holds its address only while its account exists, so the payment
  service must drop accounts that have run out or expired; otherwise the
  smallest purchase keeps an address for ever.
- An address that was given up is not handed to a different node at once:
  replies are routed by their destination alone (`Clients::route`), and the
  new holder would receive what was still on its way to the old one. It is
  kept for five minutes, and a member that waited for it has it within a
  minute after. A client put on the operator's list does not wait.

The real remedy is a wider inner address, or one the exit assigns, in a
second version of the contract with fips2go. That is outside this design and
is listed under *Known gaps*.

## Paid mode in the script

The script builds its routes, its nftables sets and the openings in the two
firewalls from the client list (`cmd_up`, `ruleset`, `fips_firewall`, `ufw`).
Members are not known in advance, and a root script should not run for every
purchase. In paid mode those per-client entries become static rules, and the
daemon is the only place where admission is decided.

- **The firewall stops being a second lock.** Today a packet from an unlisted
  node is dropped by fips's firewall before the daemon sees it. In paid mode
  tunnel packets (next header 4, 41 and 44) from any mesh node reach the
  daemon, and fragments from any node reach the kernel's reassembly.
- **IPv4 route.** `100.64.0.0/10` goes to the TUN as one route. That would
  also take the host's own traffic to that range, so `up` refuses to start on
  a host that has an address or a route in it (an uplink behind carrier-grade
  NAT, Tailscale). Today the README only advises against such hosts.
- **IPv6 route.** One route for all of `fd00::/8` in table 5170, looked at
  only for packets of connections that came out of the tunnel. Those are
  marked there (one bit of the connection mark), and the routing rule reads
  the mark. The default mode's rule (`not iif lo`) would, with one broad
  route, capture every forwarded packet to any unique-local address; a rule
  for everything arriving on the uplink, which was the first design, still
  captured what a fips gateway forwards from its LAN into the mesh.
- **`add` and `remove` tell the daemon first.** In this mode `up` can stop
  at more things than before, and a removed client must be gone from the
  daemon's table even then.
- **Rules that need care in both modes:** the loop in `cmd_up` that removes
  stale routes must not remove the broad one; `fips_firewall` removes the
  drop-in when there are no static clients, which in paid mode would shut
  every member out; the `output` chain drops the kernel's port-unreachable
  answers only towards listed clients, and has to recognise them by the
  packet they quote instead.
- **DNS.** UDP port 53 is opened to the mesh only towards the exit's own
  address, and only while the daemon says its resolver runs. Otherwise
  whatever else listens on port 53 of the host would be exposed.
- **Mail.** TCP port 25 is refused to members, as fips2go's open exit does.
- `fips-exit accounts` shows the accounts and their usage. A command to
  grant bytes by hand comes with the payment service, which is what keeps
  usage across restarts.

## The advert

Kind 30078, `d=fips-exit`, `v=1`. The tunnel's contract does not change, so
the version does not either. A phone without the update drops an advert
whose access word is `paid`, which is right: it could not pay.

| Tag | Meaning | Limit |
|---|---|---|
| `["access","paid"]` | The new access word. | one |
| `["country","DE"]` | ISO 3166-1 alpha-2. The operator's claim. Allowed on `open` and `allow-list` exits too. | one, two capital letters |
| `["price","2000000"]` | Millisatoshi per gigabyte. | one, digits only, 1 to 10¹² |
| `["pay","bolt11","onchain","cashu","channel"]` | The ways of paying on offer. Unknown words are ignored. | one, eight words |
| `["port","5170"]` | The payment service's TCP port on the exit's mesh address. | one |
| `["mint","https://…"]` | Mints accepted. For filtering; a client never adopts a mint from an advert. | four |
| `["package",id,bytes,sat,days]` | The packages, so that a list can show a "from" price. | eight |

`name`, `about` and `expiration` stay as they are. An advert that says `paid`
and lacks a price, a port or a known way of paying is not shown. A number
is written one way: digits, no sign, no zero in front. A mint is compared
by its bytes, so one mint written in two ways is two.

`fips-exit advert` publishes it on a timer. It is a port of fips2go's
`advert.py`: root reads `/etc/fips/fips.key`, so the node's key never comes
near the payment service. Building and checking the tags is a small Rust
crate in this repository, `fips-exit-proto` (`payd/proto`), with its cases
in one JSON file. The Python publisher is tested against that file, and the
payment service and fips2go's shim are to be, as the three implementations
of `inner_ipv4` are held to one set of vectors today.

What is published so far is the advert of an exit that sells nothing: the
name, the note, the country, and `allow-list`, also with `ACCESS=paid`. The
tags of a paid exit are specified and tested on both sides, and the script
writes them once there is a payment service whose port it can name.

The country is what the operator says. A client can compare it with where
the exit's address is seen from once it is connected; nothing here does that
for it.

## The payment service

`fips-exit-payd`: Rust with tokio, in a Cargo workspace of its own under
`payd/`, with its own lockfile. `fips-exitd` keeps its one dependency and
its release profile. It runs as a fixed unprivileged user under a sandboxed
unit and listens on the exit's mesh address only.

### What a client asks it

- `GET /v1/terms`: the price, the mints, the packages, the ways of paying
  that work right now, and for the caller: whether its address can be served
  here, its packages and what is left of them.
- `POST /v1/orders` and `GET /v1/orders/{id}`: buy a package. The answer is a
  Lightning invoice, an on-chain address, or a request for a token.
- The members of a package: added and removed by whoever holds the package's
  key, which the buyer receives with the order.
- Later, `POST /v1/channel`: open a channel, send an update, close it.

The same service renders the shop page: plain HTML made on the server, no
JavaScript, no fonts or scripts from elsewhere, the invoice as a QR code
drawn as SVG.

### Packages and members

A package has a size, a price, a lifetime and a key. The key is what manages
it. The source address alone is not enough for that: any app on a phone can
reach the exit from the phone's address, and so can any web page open in a
browser that is routed into the mesh.

An address is a member of one package at a time. So that nobody can be shut
out by being added to a stranger's empty package, an npub that connects from
its own address can always remove itself, or move itself to a package whose
key it has.

A package is not refunded. What is left when it expires is gone.

### Money in

All of it arrives as ecash in the exit's own wallet, at a mint the operator
chose.

- **Lightning.** The service asks the mint for a quote (NUT-23) and shows the
  invoice. When the mint says it is paid, the service mints the ecash and
  only then grants the bytes.
- **On-chain.** The same with an on-chain quote (NUT-30), offered only when
  the mint offers it. Deposits are credited as the mint confirms them. A
  deposit that arrives after the quote has expired is lost to the buyer, so
  the page shows the expiry where it cannot be missed.
- **A token.** Accepted only from the operator's mints. Its value after the
  mint's fee is checked against the price before it is swapped; a token that
  is too small is given back untouched.

A way of paying is offered only when the mint's own description
(`/v1/info`) says it can do it.

### Money out

`fips-exit wallet` shows the balance, hands out a token, or pays a Lightning
invoice from the wallet. The service can sweep the wallet to a Lightning
address of the operator's above a threshold, and stops selling above a cap.
A wallet on a server is protected by holding little. Encrypting it with a
key on the same disk would protect nothing.

### State, and what a crash may not break

Two SQLite files, the wallet's and the service's. Nothing assumes that a
change to both happens at once.

- `orders`: one per quote at a mint.
- `credits`: one row for every receipt that was realised, with a key that
  can exist once: the quote, the hash of a token's proofs, or a channel and
  its balance.
- `packages`, `members`, later `channels`, `withdrawals`.

There is one place where an order is settled, a reconciler. It grants only
what is in the wallet. If the process dies after an invoice was paid and
before the ecash was minted, the next start mints it and grants it. The
service is the truth about accounts, and pushes them to the daemon whenever
the daemon's epoch has changed.

### What it has to hold against

- The `Host` header must be the exit's name, `<npub>.fips:<port>`: not its
  bare address, which is reached only by way of the name. Requests that change
  something must be JSON, or come from the page itself (`Origin`,
  `Sec-Fetch-Site`). The source address is ambient authority, like a cookie.
- Limits on headers and bodies, on connections for the whole service and per
  source, and a rate limit. Limits per address stop nobody who can make new
  npubs; the limits for the whole service do the work.
- If the service is taken over, the attacker has an open exit and the
  wallet. They do not have root, the node's key, or the static client list.

### Channels

A Spilman channel lets a client pay as it goes. It locks ecash at a mint so
that it can be spent by client and exit together, or by the client alone
after an expiry. The client then signs, again and again, a larger share for
the exit: a channel id, a balance and a signature, a few hundred bytes. The
exit checks each update without asking the mint and redeems the last one
before the expiry.

It is built last, for these reasons, all as of 2026-11-27.

- The specification is a draft (cashubtc/nuts pull request 296), last changed
  on 2026-11-06, and it has changed incompatibly: the way a channel id is
  derived was replaced with no migration.
- There are two Rust implementations and they do not speak to each other.
  Upstream (`SatsAndSports/cashu_spilman_channels`) needs its author's fork of
  the Cashu library, pinned by commit. nostr-vpn's (`nvpn-cdk-spilman`) pins
  an older `cashu` than the wallet library needs, and says of itself that it
  is not an upstream release.
- Whether a mint handles the locks a channel needs (both signatures before
  the expiry, the client alone after it) cannot be read from the mint's
  description. Mints have had bugs there.
- **A channel protects the payer only when the mint is not the operator's.**
  With the operator's own mint the operator can keep the money either way.

So: the code sits behind a build feature that is off by default. It is
pinned to one exact revision, which the terms name, and a client that has a
different one does not open a channel. The exit offers channels only for
mints it does not run, and only after it has opened and closed a channel of a
few satoshi with itself at that mint, both ways out, for that version of the
mint. It begins collecting at half the channel's lifetime, twelve hours at
most, and writes down the exact request before it sends it to the mint.

## The phone

fips2go changes in its own repository, in this order. The first six need no
wallet in the phone.

1. Its HTTP client for the mesh learns POST (`shim/src/meshhttp.rs` is GET
   only).
2. The container's advert gains `country`.
3. **The phone reassembles fragments of the outer packet.** This exit sends
   an inner packet of 1241 to 1280 bytes as two fragments (README, *Packet
   sizes*); the phone takes next header 4 only and drops the rest. Today that
   is lost QUIC. With metering it would be lost QUIC that was paid for.
4. `shim/src/exitfind.rs` takes adverts that say `paid`, with a limit per
   tag, and filters by country before it cuts the list to its hundred. The
   list shows country and price, marked as the operator's claim.
5. A purchase screen that talks to the exit's API: the terms, an invoice as a
   QR code and a `lightning:` link, a pasted token, the members. The browser
   is not the way: the phone's tunnel is per app, and a browser that is not a
   mesh app has no route into the mesh.
6. Its own byte counters beside the exit's figure, so that a difference
   shows.
7. A trial: the Cashu wallet library on all three Android ABIs, its size,
   its licences.
8. A wallet, behind a build feature, with a cap.
9. A channel payer.

## Who risks what

- **The buyer of a package** trusts the exit with what is not yet used.
  There is no refund. Small packages keep that small.
- **The payer in a channel** risks the grace allowance, and has ecash locked
  until the expiry if the exit disappears. This holds with a mint that is not
  the operator's.
- **The operator** trusts the mint with what is in the wallet, until it is
  swept out.
- **The operator's address** carries strangers' traffic. Port 25 is closed,
  `BLOCK_CIDRS` adds destinations, and that is all: what a stranger does
  through the exit comes back to its operator. The README will say this
  first, not last.
- **What the exit learns**, beyond what any VPN endpoint learns: which npubs
  share a package. **What the mint learns:** the amounts of the invoices,
  and a client's address if the client talks to the mint itself.

## Known gaps

- The inner IPv4 address: 22 bits, clashes and squatting (above).
- Fragments from any mesh node reach the kernel's reassembly in paid mode.
- The exit host itself can send to a member's inner address, and that is
  counted against the member.
- Paid mode uses one bit of the packet and connection marks. Other software
  on the host that sets or clears that bit breaks IPv6 for the members.
- No limit on a client's bandwidth, only on its bytes.
- The country is a claim.
- Channels rest on a draft.

## Phases

Each is a small pull request with its tests and its changes to the README
and `SECURITY-REVIEW.md`.

| # | What |
|---|---|
| 1 | **Done.** The daemon's accounts and the control socket. Then paid mode in the script. |
| 2 | **Done.** `fips-exit-proto` and its vectors; `fips-exit advert` and its timer. Free exits gain an advert and a country by this alone. |
| 3 | **Done.** The payment service's frame: configuration, terms, the page, the unit, a CI job. The schema waits for phase 4, which is the first to keep anything. |
| 4 | **Half done.** Accounts without money: the service on the socket, a grant by hand, members, usage, pushing again after a restart. To come: a buyer managing its package's members with its key, over the mesh. |
| 5 | The wallet, and payment by token. |
| 6 | Lightning. |
| 7 | Paying out and sweeping. Before on-chain: a wallet with no way out is the larger risk. |
| 8 | On-chain. |
| 9 | A command-line client for Linux nodes. |
| 10 | Channels. |

The tests for the payment phases run against a real Cashu mint started
inside the test, with a Lightning backend that pays itself. fips-exit-gate's
fake mint is a stub a real wallet cannot talk to.

## Open questions

Each has the answer this design assumes until someone says otherwise.

- **A free allowance** before a client must pay, to try an exit: none. A
  grace allowance in a channel: 256 KiB.
- **The mint for a phone.** A phone's wallet reaches the mint over the
  phone's own connection, so the mint sees the phone's address, and a phone
  with no other connection cannot pay. Assumed: the exit passes requests on
  to its accepted mints for its clients, from the wallet stage on.
- **The phone wallet's seed:** separate from the nsec, so that a new
  identity does not strand money. Releases are built without the wallet until
  it has proven itself.
- **The wallet's store.** The wallet library's SQLite store pins a version of
  `rusqlite` with an open advisory (RUSTSEC-2026-0459, a crafted WAL file
  read by a local attacker). Assumed: accepted and written down, since a
  local attacker who can write the wallet's files has the wallet.
- **A shop on the clearnet.** Not now. Off the mesh a buyer has no address
  that proves who it is.
- **Which channel revision**, decided when that phase starts.

## Sources

Read on 2026-11-27. Nothing was compiled against them.

- Spilman channels: <https://github.com/cashubtc/nuts/pull/296>,
  <https://github.com/SatsAndSports/cashu_spilman_channels>
- nostr-vpn's paid exits: <https://github.com/mmalmi/nostr-vpn>
  (`docs/protocol.md`, `crates/nostr-vpn-core/src/paid_routes/`)
- The wallet library: <https://github.com/cashubtc/cdk> (0.18.3)
- Mint quotes: NUT-23 (bolt11) and NUT-30 (on-chain),
  <https://github.com/cashubtc/nuts>
- TollGate, for comparison: <https://github.com/OpenTollGate/tollgate>
