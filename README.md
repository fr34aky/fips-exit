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
  list. An exit that sells (`ACCESS=paid`, its payment service running, a
  mint named) says `paid` instead, with what the service says it costs: the
  price, the packages, the mints, the port. Anyone can read it. The country
  is your claim; nobody checks it.
- fips2go, as released, lists exits that say `open` or `allow-list`, and
  passes over one that says `paid`: until it reads paid adverts, a paid
  exit is found by its npub, not in that list.
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
its name on the mesh. It says what the exit costs, sells packages for Cashu
tokens of the mints you name and for Lightning invoices those mints give,
and keeps the packages you give away:

```sh
ACCESS=paid
PRICE_MSAT_PER_GB=2000000                   # millisatoshi a GB of 10^9 bytes: 2000 sat
PACKAGES="1gb:1GB:1500:30 5gb:5GB:6000:90"  # optional: id:size:sat:days, sizes in bytes, MB, GB or TB
MINTS="https://mint.example.org"            # optional: the Cashu mints whose tokens are taken; none, nothing is sold
PAY_PORT=5170                               # optional, the default
WALLET_CAP=500000                           # optional, the default: the most the wallet may hold at a mint, in sat (0: any amount)
SWEEP_TO="you@example.org"                  # optional: a Lightning address of yours that the wallet is sent on to
SWEEP_ABOVE=20000                           # optional, the default: above how many sat at a mint it is sent on
```

```sh
sudo systemctl enable --now fips-exit-payd
```

- `http://<npub>.fips:5170/v1/terms` is the exit's terms as JSON, and `/`
  the same as a page for a browser on the mesh: price, packages, mints, name
  and country, and who is asking, with its package if it is in one. A caller
  is known by the address its connection comes from, which fips
  authenticates. `methods` says how one can pay right now: `cashu` while a
  mint named in `MINTS` is reached, and nothing otherwise.
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
- Only so much at a time: 64 connections, 8 from one address, a header of
  16 KiB within 5 seconds, a body of 32 KiB within 15, a minute for a
  connection.

#### A package for a token

On the exit's page a buyer picks a package and pastes a Cashu token; a
program sends the same as JSON:

```text
POST /v1/orders  {"package": "1gb", "token": "cashuB…"}                the package, and its key
POST /v1/orders  {"package": "1gb", "token": "cashuB…", "key": "…"}    added to the package that key opens
```

- The token is of a mint in `MINTS`, in sat, and worth the package's price
  after the fee its mint takes for redeeming it. One that is worth less, or
  over a tenth more, is refused, and so is one of any other mint: such a
  token is not touched, and the answer says so. What a token is worth over
  the price, up to that tenth, is kept. Nothing is given back. (A tenth of
  a price under 10 sat is nothing: such a package takes its price exactly.)
- What is bought is a package of its own, with the device that asked in it
  and its key in the answer, shown once. With the `key` of a package there
  already is, the bytes and the days are added to that one, and nobody is
  put in or taken out.
- A token is one purchase. Sent again by the device that bought with it, it
  is answered with that purchase again, and with a new key for the package
  if it made one: the answer that carried the first key may not have
  arrived. The key before it then opens nothing. Sent by anyone else, it is
  refused.
- A package is granted when its price has arrived in the wallet, and not
  before. If the mint's answer was lost, the mint is asked two things, at
  once and then every twenty seconds: what it signed for this wallet, and
  whether the token is spent. Signed and spent, the order is paid. Spent
  and not signed, someone else spent the token, and nothing is granted.
  Neither, the order stays open (`202`, and the code `not-yet`) for as long
  as the wallet's request may still arrive, ten minutes at least. Sending
  the same token again asks what became of it and takes nothing twice; a
  token that could not be taken to the mint at all is answered `503`,
  `try-again`, and is not touched.
- Not sold to: a device on the exit's own list, which is carried as it is;
  a device that another client's inner IPv4 address clashes with (below,
  under *Accounts*), which would be carried over IPv6 only; anyone while
  the exit's daemon is not running. Their tokens are not touched either.
- A mint is taken only if it says what it has signed (NUT-07 and NUT-09):
  that is what is gone by after a lost answer.
- At most 10 tokens in a burst and one more every six seconds are taken to
  a mint, for all buyers together, 8 at once and one at a time for an
  address. Past that the answer is `429`, and the token is not touched.
  (The wallet library itself asks a mint no more than 20 things at once
  and one every three seconds after that.)

#### A package for a Lightning invoice

Where a mint in `MINTS` gives invoices (it says so of itself: NUT-04, for
`bolt11` in sat), the page has a second button, "Pay with Lightning", and a
program asks the same way, without a token:

```text
POST /v1/orders              {"package": "1gb", "method": "bolt11"}               201: the order, with its invoice
POST /v1/orders              {"package": "1gb", "method": "bolt11", "key": "…"}   to be added to the package that key opens
GET  /v1/orders/<order>                                                         what became of it: waiting, checking, paid, expired
POST /v1/orders/<order>/key  {}                                                 a key for the package it made
```

- The exit runs no Lightning node. The invoice is the mint's (a quote,
  NUT-23), for the package's price exactly; it is read here before anyone
  sees it, and one that is not for that price is not shown. When it is paid
  the wallet mints ecash for it, so what is paid arrives in the wallet as a
  token's worth does. The package is granted then, and not before.
- An order is its buyer's. The device that asked sees it, by its name;
  nobody else is told that it is there. Its page shows the invoice as text,
  as a `lightning:` link and as a QR code (drawn by the service: no script,
  nothing fetched), and looks again by itself every few seconds. The same
  asked again within a minute (a form sent twice) is the same order.
- The package is there once the payment has arrived, with the device that
  asked in it, whether or not anyone is looking at the page. Nobody was
  shown its key. Its buyer asks for one (the last line above, or "Show a
  key for it" on the order's page), and each key asked for takes the place
  of the one before, so a key that did not arrive is no loss. With the
  `key` of a package there already is, the bytes and the days are added to
  that one instead.
- **What is paid after an invoice has ended is lost to whoever paid it.**
  The page says when that is, and an invoice is shown only while it can be
  paid: one that would end within a minute is not given to anyone, and once
  it has ended the order says `checking`, with nothing to pay, until the
  mint has said what became of it. The mint is asked about one invoice at a
  time, at most every three seconds: about an order whose buyer is asking,
  and every other time about whichever was not asked about for longest, so
  that those who ask do not keep the others waiting; more seldom the older
  an order is. An order is given up (`expired`) only when the mint, asked
  ten minutes after the invoice has ended, says it is not paid. One paid
  while the service was not running is found when it starts again. An
  order that was given up can be asked about for a day.
- Leave a mint in `MINTS` while `fips-exit orders` shows an invoice of it
  open. With the mint taken out, such an order cannot be asked about: it
  says `checking`, the log says so, and what is paid for it meanwhile is
  at that mint, granted only once the mint is named again.
- If the mint minted and its answer did not arrive, the mint says so of the
  quote, and that is the payment: a quote is minted for the wallet that
  knows it and holds its key (NUT-20, where the mint has it), and what was
  minted is found again from the seed. If the wallet's file is lost while
  an invoice waits, the order is enough to claim what is paid: the quote
  and its key are kept with it.
- Not sold to: whoever a token would not buy for either (above). At most 3
  invoices wait to be paid for one address. An invoice is asked of a mint
  from the same budget as a token is taken there, 10 in a burst and one
  more every six seconds for everyone together. Past either the answer is
  `429`.
- The mint asked is the first in `MINTS` that is reached and gives an
  invoice for that price. A program may name another of them
  (`"mint": "https://…"`).

```sh
sudo fips-exit wallet    # what the wallet holds at each mint, what was sold there, whether it gives invoices
sudo fips-exit orders    # what was paid, with a token or by invoice, by whom, for which package
```

**The wallet is money on this machine.** What is paid is ecash in a wallet
the service keeps in `/var/lib/fips-exit-payd` (`wallet.db`), and whoever
has its seed, 24 words in the file `seed` beside it, has all of it. Copy the
seed somewhere safe, once: with it the wallet's contents are found again at
the mints if the machine is lost, here (a start with the seed and no
`wallet.db` counts again) or in any Cashu wallet that restores from a seed.
The two belong together: the service does not start with a `wallet.db` and
no seed, and a `wallet.db` that is older than its seed's use (an old copy
put back) is found out when a mint is reached, and counts again before
anything is sold. One wallet for a seed, ever: a second one running on a
copy of it makes each ask the mint for what it signed for the other.
Ecash is the mint's promise and nothing more: a mint that goes away takes
what the wallet holds there with it, so name mints you would trust with
that, or your own.

#### Taking what was paid out of the wallet

A wallet on a server is protected by holding little. Nothing a buyer does
takes anything out of it; you do, or your config does:

```sh
sudo fips-exit wallet token 5000                 # a Cashu token of 5000 sat: its text is the money
sudo fips-exit wallet tokens                     # the tokens handed out that nobody has redeemed, with their text
sudo fips-exit wallet take-back <name>           # one of those, back into the wallet
sudo fips-exit wallet pay lnbc…                  # pay a Lightning invoice out of it: says what it takes, then asks
sudo fips-exit wallet sweep                      # send on to SWEEP_TO now, whatever is held
sudo fips-exit wallet out                        # what left the wallet, and what each cost
```

- **A token** is ecash for whoever has its text: redeem it in a wallet of
  your own, at the same mint. It is worth what you asked for to whoever
  redeems it, as near as the mint's fee for that lets it be, and that fee
  is taken out of the exit's wallet with it. The command prints the text
  alone, so that it can be piped; what else it says goes to standard error.
  Until somebody redeems it the wallet keeps its text (`wallet tokens`), and
  it can be taken back, which makes that text worthless.
- **An invoice** is paid by the mint with what the wallet holds (a melt,
  NUT-05). The mint is asked what it takes first: the amount, and the most
  the mint may keep on top for the payment's fee (what it does not use
  comes back). It is paid when you say so: `--yes` for a script. An invoice
  is paid once. If the mint has not said after a minute what became of a
  payment, it is written down as begun, counts as gone, and the mint is
  asked about it every minute until it says.
- **`SWEEP_TO`** is a Lightning address of yours (`name@host`). Once a
  minute each mint's holdings are looked at, and what is over `SWEEP_ABOVE`
  starts a payment of all that is held there, less a fiftieth and 4 sat
  left for the mint's fee: the address's host is asked for an invoice of
  that much, the wallet library checks that the invoice is for that much
  and for that address, and the mint pays it. A mint that asks for more
  than a twentieth and 20 sat for it is not paid by itself. After a failure
  nothing is sent on from that mint for a quarter of an hour, and while a
  payment is under way there, nothing else is. The service then talks to
  that host as well as to its mints, and to nobody else.
- **`WALLET_CAP`** is the most the wallet may hold at one mint: from there
  on nothing is sold at that mint, by token or by invoice (`503`, the code
  `wallet-full`), until something has left it. Half a million sat when the
  config says nothing; 0 for any amount. Invoices given before it was
  reached are still honoured, so it can end a little over. With `SWEEP_TO`,
  `SWEEP_ABOVE` has to be under it.
- **Everything that leaves is written down** before the mint is asked
  (`wallet out`), with the most it may cost, and then with what it did
  cost, or that it came to nothing. `fips-exit wallet` shows for each mint
  what it holds, what was sold there and what was paid out: the first is
  the second less the third.

The seed is still the way to everything the wallet holds, and the way of
last resort: restored in another wallet, with the service stopped for good
(two wallets on one seed get in each other's way).

Packages the operator gives away, for nothing:

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
[`docs/paid-exit.md`](docs/paid-exit.md). Its first seven phases are here:
accounts and `ACCESS=paid`, the advert, the payment service, packages and
their keys, packages sold for Cashu tokens and for Lightning invoices, and
paying out of the wallet with a limit on what it holds, all above. To come:
on-chain payments, a command-line client, and pay-as-you-go channels.

## Test

```sh
cargo test                      # the daemon's admission and routing rules
cargo build --release && unshare -Urnm test/netns.sh
cargo test --manifest-path payd/Cargo.toml   # the advert's tags, the price, the payment service
python3 -I -m unittest discover -s test      # the script's advert
```

The namespace test runs the payment service too, and a mint for it, so it
needs both built:
`cargo build --release --manifest-path payd/Cargo.toml -p fips-exit-payd` and
`cargo build --manifest-path payd/Cargo.toml -p fips-exit-test-mint`.

The tests in `payd/` and that mint need `protoc` to be built (the package
`protobuf-compiler`, or `protobuf`): the wallet library's mint side wants
it. The payment service itself does not, and neither does `install.sh`.

The second runs the daemon and the script against the real kernel, without
root and without fips: network namespaces stand in for two clients, the
exit and the internet, and a 1280-byte link stands in for the mesh. It
checks both families, NAT, full-size packets in both directions, TCP, the
binding of a client to its addresses, isolation, removal and teardown. Then
the same exit with `ACCESS=paid`, behind a stand-in for fips's firewall: no
node without an account is carried, two members share an account counted to
the byte and are cut off at the grant, a member reaches the internet and
neither the uplink's LAN nor port 25, the payment service tells a node that
is no client what the exit costs and who it is, a node that is nobody's buys
a package with a token of a mint that runs in the test and is carried,
another pays an invoice of that mint for one, a token and an invoice leave
the wallet again on the operator's word, a full wallet sells nothing, and
leaving the mode removes what it made, the opening for the payment service
with it.

The third is `payd/`, a workspace with a lockfile of its own, so that the
daemon keeps its one dependency. `payd/proto` is a crate with no
dependencies that the exit and its clients share: what an exit's advert on
Nostr says (who it serves, where it is, and for a paid exit what it costs)
and what a number of bytes costs at a price. It is checked against
`payd/proto/vectors/advert.json`, and so is every other implementation of
the same. `payd/payd` is the payment service: its config, its terms and
page, its HTTP server's limits over a real socket, its packages, and what
is paid. `payd/test-mint` is a Cashu mint for the tests, in memory, with a
Lightning backend that pays its own invoices (at once, or when a test says
so), and a way to it on which a request or an answer can be lost: the
payments are tested against it, a token spent twice, one spent elsewhere,
an invoice paid late or never, an answer that never arrived and a service
that died between a payment and its package among them. It is not
installed, and nothing it gives out is worth anything.

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
