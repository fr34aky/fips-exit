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
  use the tunnel and as whom: the clients on the operator's list, and the
  members of *accounts*, each for the bytes its account was granted. Accounts
  are made by another program over a control socket, which exists only when
  the config says `ACCESS=paid`, or `CLIENT_COUNTS=on` (then for the counts
  of the listed clients, and it takes no accounts), or the daemon is started
  with `--control`.
- `fips-exit` (a Python script): everything around it. The client list, the
  TUN's routes, NAT to the uplink, an nftables table of its own, and the
  openings it makes in two firewalls it knows (fips's own, and ufw). And,
  when the operator names relays, the exit's advert on Nostr: for that it
  reads the node's secret key and signs one event an hour with it.
- `fips-exit-payd` (`payd/payd`, Rust with tokio, hyper and SQLite): the
  payment service, for `ACCESS=paid`. Not root: a user made for it by
  systemd, with no capability and little of the machine, in the group
  `fips-exit` to which the daemon opens its control socket. It answers HTTP
  at the node's npub on the mesh, says what the exit costs, and keeps the
  packages: those the operator gives away and those it sells, for Cashu
  tokens of the mints the operator names. It makes the daemon's accounts
  for them. What is paid arrives in a wallet of its own, kept beside its
  store: it holds money, and asks those mints over the internet. The wallet
  is a library's (`cdk` 0.18.3, pinned exactly), which brings some 270
  crates into this one program, a TLS stack among them.

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
   Everything inside is the sender's. With `ACCESS=paid` the firewalls in
   front of the daemon admit these packets from every node, so the daemon
   sees all of them, and the kernel reassembles fragments from anyone.
2. **Packets from the internet**, arriving on the TUN after NAT, routed back
   to a client by their destination (`Clients::route`).
3. **DNS queries from clients, and answers from the upstream resolvers.**
   The daemon's resolver (`serve_dns`) takes a datagram on port 53 of the
   fips address from a listed client and forwards it as it is. It looks
   inside a query in one place only, `question_end`, to build an empty
   answer (SERVFAIL, or truncated) when there is no usable one. An
   upstream's answer is matched on its id and response bit, on a connected
   socket, and otherwise passed through unread; one over 1232 bytes is
   replaced by a truncated answer.
4. **The client list**, `/etc/fips-exit/clients`. Root-owned, but written by
   hand as well as by `add`: the daemon skips a line it cannot use rather
   than stopping, and must not be led by one into admitting someone else.
5. **Lines on the control socket**, when there is one. It is a Unix socket
   with mode 0600, so its peer is root today; it is meant for a payment
   service that is not. `parse_command` reads each line as bytes: one of
   nine commands with exactly its arguments, a name of 1 to 64 safe
   characters, numbers of digits only up to a quarter of a u64, fips
   addresses. Anything else is answered with an error and changes nothing. A
   line is at most 4096 bytes and has five seconds to arrive, an account has
   at most 32 members, there are at most 16384 accounts and four connections.
6. **Operator input to the script**: an npub, an address or a name on the
   command line, and `WAN`, `MESH_IF`, `TUN` and `FIPS_FIREWALL` in
   `/etc/fips-exit/config`. These end up in nftables scripts and in
   arguments of `ip` and `sysctl`. Not hostile, but a typo there runs as
   root. `ACCESS` is one of two words or the script stops: a word that is
   neither must not quietly mean the open one.

7. **What a relay answers** to `fips-exit advert`. The script is the client:
   it reads an HTTP status line and WebSocket frames from whoever is at the
   address the operator named. The header is at most 8192 bytes and a
   message 65536, in one frame or in several. A relay has ten seconds to be
   reached and ten for all of its answer, however it spaces it out; the unit
   has five minutes for all relays. The only thing acted on is an `OK` for
   the event just sent; what is not JSON, or JSON too deep to read, is
   passed over. What a relay says in words is printed, cut and with nothing
   but printable characters. Whatever one relay does, the next is still
   tried. A `wss://` relay's certificate is checked as Python checks any.
8. **Requests to the payment service.** Anyone on the mesh may connect to
   `PAY_PORT` in paid mode; the firewalls are opened for that. A peer whose
   address is not a fips address is closed at once. A request must name
   this exit in `Host`, `<npub>.fips:port` and nothing else, or it is
   answered 421: a page elsewhere must not be able to read what this one
   says to a browser on the mesh. Three paths are `GET`/`HEAD` (the terms,
   the page, its stylesheet) and eight are `POST` (a package by its key, its
   members, leave, a purchase; each as JSON and as a form). A header has 5
   seconds and 16 KiB, a body 15 seconds and 32 KiB, a connection a minute;
   there are 64 connections at once and 8 from one address.
   What changes something is JSON (`application/json`, from a program or
   this page, never with another site's `Origin` or `Sec-Fetch-Site`), or a
   form from this exit's own page: its `Origin`, or the browser's own
   `Sec-Fetch-Site: same-origin` where it hides the origin. A key that is
   not 64 hex digits is not looked for; one that is no package's is told
   nothing but that. What a member is told of its package is its own: what
   is left, until when, how many share it; not the key, and not who the
   others are. The operator's text is escaped on the pages, which have no
   script and load nothing from elsewhere.
9. **The operator's commands to the payment service**, on its socket in
   `/run/fips-exit-payd`, which only the service's user and root can open.
   Lines of words, each checked: a size, a number of days up to 3660,
   npubs or fips addresses, a label of one printable line. Not hostile, but
   a package made there carries whoever is in it.
10. **A token, from anyone on the mesh.** Text of up to 24 KiB, read by the
    wallet library (base64, then CBOR or JSON) before anything else is known
    of it. Of it the service takes, without asking a mint: which mint it
    names, which must be one of `MINTS` by its whole address; its unit; its
    proofs, 64 at most, none twice, of keys that mint has; what they add up
    to, and the mint's fee for them. Only then is a mint asked anything, and
    only the one the operator named: a token cannot make the service talk
    to an address of its sender's choosing.
11. **What a mint answers.** The operator chose it and trusts it with what
    the wallet holds, so it is not an adversary for money. Its answers are
    parsed by the wallet library all the same, and one of them decides a
    grant: what it says it has signed (NUT-09), of which only the outputs
    this wallet asked about are counted.
12. **A request for an invoice, from anyone on the mesh.** It costs its
    asker nothing, and makes the service ask a mint (for a quote) and keep
    an order until the invoice has ended. Taken from it: a package on
    offer, optionally a key and the name of a mint, which must be one of
    `MINTS` as the config writes it. Bounds: 3 invoices waiting for one
    address, 512 in all, and the budget a token is taken from; the same
    asked again within a minute is the order there is already. The invoice
    comes from the mint and is read before it is shown: a BOLT11 request
    for the price exactly that lasts a minute at least, or nothing is
    shown; and it is shown only until it ends. It goes into the order's
    page escaped, as text, as a `lightning:` link and as a QR code that is
    SVG written here (rectangles, no script, no link). An order is named by
    64 random bits and shown to the address that made it only, so asking
    for one that is another's says nothing but "no such order". Asking
    about an order changes nothing but when the mint is next asked, which
    has a bound of its own (one invoice every three seconds). The one
    request there that changes something, a new key for the package an
    order made, is a POST held to the same rules as every other change.
13. **What the payment service tells the script.** `fips-exit wallet`,
    `orders`, `status` and `advert` ask the service over its socket, and
    root prints or signs what comes back: the service is another program,
    without privilege, and its word is taken as that. What is printed is
    held to numbers and cut of anything a terminal would act on; the terms
    that go into the advert are checked for their shape, then held to the
    advert's own bounds, and an advert that is out of them is not written.

## Things that would be serious in this codebase

- **Admission bypass.** A packet reaching the TUN from a node that is
  neither a listed client nor a member of an account with bytes left, or
  with an inner source that is not the sender's own address. Either lets a
  stranger use the exit, or lets one client send as another. For IPv4 "its
  own" means two things: the address derived from the sender's, and held by
  the sender. A member admitted for IPv6 only derives the address of the
  client that holds it.
- **Carried and not counted, or counted wrong.** A member's packet passed on
  without being added to its account, counted twice, or counted when it was
  not passed on; a member carried after its account's count has reached the
  grant, beyond the one packet per thread that crosses the line; a member
  carried at or after its account's end; any arithmetic on the three numbers
  that could wrap. The counts only grow and nothing is subtracted, for that
  reason.
- **The control socket reaching further than accounts.** A command that
  changes the operator's list or takes a listed client's place or inner
  address, that names a file or runs something, or a line that makes the
  daemon panic or stop carrying. Also: the socket readable or writable by
  anyone but its owner.
- **What a client moved, kept without being asked for or for longer than
  said.** The clients on the list are counted only with `CLIENT_COUNTS=on`:
  two numbers each, in memory. Counting them by default, keeping the count
  of a client that was removed, writing counts to a file or the journal, or
  adding times or destinations to them, would each make a record of people
  that the README says is not kept. The socket they are read over is root's.
- **A reload losing the accounts.** `fips-exit add` and `remove` make the
  daemon read the list again; the accounts must be as they were afterwards.
- **Misrouted replies.** A packet from the TUN delivered to a client other
  than the one its destination belongs to. Two clients that derive one inner
  IPv4 address (22 bits) are exactly this; the list must never hold both.
- **The address contract drifting.** `inner_ipv4` exists in the daemon, in
  the script, and in fips2go. If they disagree the exit silently refuses
  every client, or routes replies to nobody. CI checks the daemon and the
  script against the same vectors fips2go tests.
- **Paid mode opening more than the tunnel.** With `ACCESS=paid` the
  script's openings in fips's firewall and in ufw are no longer for listed
  addresses but for every node of the mesh. They must stay what they are:
  next header 4, 41 and 44, and UDP port 53 only while the daemon's resolver
  runs, to this node's own fips address, and nothing else. In that mode the
  daemon is the only lock; a member must get no more through the tunnel than
  a listed client does, and not TCP port 25. And the mode must be the
  operator's choice: nothing but `ACCESS=paid` may turn it on, and leaving it
  must close what it opened.
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
- **An open resolver.** The daemon answering DNS for a node that is not a
  listed client, or answering something that is not a query. Either makes
  the exit a resolver, and a reflector, for the whole mesh.
- **The payment service reaching further than its port.** It runs without
  privilege and must stay so: a change that gives it a capability, a
  writable path outside its own, the control socket (before that is meant,
  with accounts), or the node's key. And its port must be opened in paid
  mode only, to this node's address only, and only while the service
  itself listens there (`up` asks the kernel which process does): leaving
  paid mode, or the service stopping, closes it.
- **The payment service naming another node.** It answers to
  `<npub>.fips`, and starts at all, only when that npub's fips address is
  one this node has; a stale key file is not believed.
- **The daemon's socket given away further than meant.** In paid mode the
  daemon gives the socket, and the directory systemd made for it, to the
  group `fips-exit`. Only that socket at its own place: one put anywhere
  else with `--control` stays root's, and so does its directory, which may
  be shared with others (`/run` itself).
- **The payment service making accounts it should not.** It is in the
  daemon's admission now: whatever it puts is carried. It must put a
  package's members, for the package's bytes and end, only while the
  package is live, and drop it when it is used up, over or revoked, or
  when its store does not know it; never touch an account that is not its
  own (`p` and 16 hex digits); never let one package the daemon refuses
  hold up the others (what is to be dropped is dropped first); and never
  lose what the daemon counted, which it folds into its store before it
  decides anything. A package's key is kept only as its hash.
- **An address in two packages, or held in one.** A device is in one
  package at a time, and is put in a package by nobody but itself (from
  its own address, with the key) or the operator. A key holder may take
  members out of its package and put only its own device in. Anything that
  lets a stranger put a device in a package (keeping it from the one it
  paid for, or from a grant), take it out of its own, or learn whether it
  has one, is serious.
- **A package's key going anywhere.** It is shown once, to the operator or
  to the device that bought the package, and kept as its hash. A key holder
  sees the package and its members' npubs; nothing in the terms or on the
  page of a member shows the key. A buyer that sends its token again gets a
  new key, and the one before opens nothing: that must stay with the address
  that bought, and nobody else may learn from a token whose package it paid
  for.
- **Granting what did not arrive.** The one thing the payment service is
  for. A package is made in one place (`Store::order_settle`), for an order
  written down before its token went to the mint, and only on one of two
  grounds: the wallet took the token without a hitch, or the mint says both
  that it signed what this wallet asked for in exchange (NUT-09) and that
  the token's proofs are spent (NUT-07), which one exchange does at once.
  Never on one of the two alone. Spent and not signed is a token its sender
  spent elsewhere first, which is what the wallet library's own conclusion
  after a lost answer cannot tell from a payment. Signed and not spent is
  a wallet whose file is behind its seed's use, asking for what the mint
  signed before: so the wallet's next requests are asked about at a mint
  before anything is sold there, a mint's "signed before" ends the order
  and the selling until the wallet has counted again, and an order the mint
  said that of is never paid on what is found signed later. Serious: a
  package for a token that was spent by someone else, refused by the mint,
  of another mint, worth less than the price, or counted twice (a credit's
  key can exist once); and the wallet let to finish what it began before
  what it asked the mint to sign was kept for every open order, since
  afterwards nothing can be asked.
  For an invoice the grounds are two as well: the wallet minted for the
  quote without a hitch, after the mint said the invoice is paid; or the
  mint says the quote is minted, which it does for the wallet that knows
  the quote and holds the key it is locked to. Serious: a package for an
  invoice that is not paid, for another order's quote, or twice for one
  quote (an order is one quote of one mint, and a credit's key can exist
  once); and an order given up while its invoice could still be paid, or
  without the mint's word.
- **An invoice paid, and nothing granted.** An order is written down before
  its invoice is shown to anyone; it is given up only when the mint, asked
  after the invoice's end and a while more, says it is not paid; and
  neither a restart, a lost answer, a mint that is away nor a wallet's file
  that was lost may end it otherwise (the quote and its key are kept with
  the order). A mint that refuses to mint for a paid quote as signed
  before makes the wallet count again, once for an order, and is asked
  again after. What is paid after an invoice's end is lost to the payer,
  and the page says when that is: serious would be showing an invoice
  whose end has passed, or a wrong end; and an order that waits forever
  because those who ask about theirs are always looked at first (every
  other look goes to whichever waited longest).
- **A token taken, and nothing granted.** The other way round: whatever the
  service refuses, it must refuse before the token is taken to the mint, and
  say that the token was not touched; an order whose token did reach the
  mint must stay open until the mint has said what became of it, across a
  restart, a lost answer and a closed connection. An order is forgotten only
  when the mint says the token is spent and not for this wallet; or when it
  says neither signed nor spent, ten minutes have passed, and the wallet has
  nothing of it left that it could still be asking the mint for (while it
  has, or could not finish, a request of its own may be on its way). And a
  token sent again is answered with what became of it before anything that
  is asked only of a new purchase: none of those may say "not touched" of a
  token that was taken.
- **The wallet's seed going anywhere.** The file `seed` in the state
  directory, for the service's user alone. It is what the wallet holds. It
  must never be logged, printed, put in an answer or an error, or sent; a
  seed file that holds something else is not replaced, and its contents not
  repeated; and none is made beside a wallet's file that has lost its own,
  where it would be taken for the one that is gone. The same for the
  tokens: one is not written to the log.
- **The service asking anyone but its mints.** It has the internet now, to
  reach the mints in `MINTS` and nothing else. Anything that makes it open a
  connection to an address from a request, a token or a page is serious.
- **A page on another site changing a package.** Through a browser on the
  mesh it could reach the exit; it must not be able to send a form the
  service takes (`Origin`), nor JSON (which a browser sends elsewhere only
  after asking, and the service does not answer that). A purchase comes in
  by the same two ways and no third: a page elsewhere must not be able to
  spend a token in a visitor's name.
- **The node's key going anywhere.** `fips-exit advert` reads the fips
  identity's secret key. It must never be printed, logged, put in an error
  message or sent: only the signature leaves. That includes a key file that
  holds something else, whose contents are not repeated either. Whoever has
  the key is the node, on the mesh and on Nostr.
- **An advert that is not this exit's, or says more than the exit does.**
  Signed with a key that is not the node's own (it is compared with the
  mesh interface's address first); naming an access the exit does not give;
  or tags that are not what `payd/proto` specifies, which clients would
  pass over or, worse, read differently. A paid exit's terms in the advert
  are what its payment service says of itself, so that the two cannot
  differ: the script, which holds the key, must hold them to the advert's
  bounds and sign nothing that is out of them. And an advert sent anywhere the
  operator did not name: publishing is by `ADVERT_RELAYS` alone, and the
  timer is not enabled by the installer.
- **Parsing the inner packet.** Out-of-bounds reads and length arithmetic in
  the two places that look inside a packet. A panic here is a remote
  denial of service for every client.

## Known gaps — real, not yet fixed

- **The uplink's own public address is not blocked** when the exit is
  behind a NAT router. From inside, that address is the router: its admin
  page and, through NAT loopback, every port it forwards. fips2go's exit
  container looks the address up and keeps it blocked as it changes; here
  the operator has to put it in `BLOCK_CIDRS`.
- **No limit on clients, bandwidth or destinations** beyond the list itself.
  An account limits its members' bytes, not their rate.
- **Two members that derive one inner IPv4 address.** 22 bits of the fips
  address, so a clash can be found in seconds, on purpose. The first holder
  keeps the address and the other is carried for IPv6 only; an address that
  was given up is kept from others for five minutes, and whoever waited for
  it has it within a minute after that. Whoever makes accounts
  can ask first (`check`), and has to drop accounts that are finished, or
  the smallest one holds an address for ever. The remedy is a wider inner
  address, which is a change to the contract with fips2go.
- **An advert is not taken back.** An exit that stops is listed until its
  last advert expires, three hours at most.
- **The payment service's store is SQLite from `rusqlite` 0.31**, which has
  an open advisory, RUSTSEC-2026-0459: memory disclosure on a crafted WAL
  file. Only the service's user and root can write its state directory,
  and either already holds everything in it. 0.31 because the Cashu wallet
  library pins it, and there can be one SQLite in a build.
- **Nothing pays out, and nothing limits what the wallet holds.** A wallet
  on a server is protected by holding little; this one only grows, until
  paying out and a limit are written (the next phases). Whoever takes the
  service over, or reads its state directory, has all that was paid since
  the operator last emptied it by hand, with the seed.
- **Two wallets on one seed.** A copy of the seed in a second service, or
  in another wallet while this one runs, makes each ask the mint for what
  it signed for the other. That is found out (the mint refuses, selling
  stops, the wallet counts again) and it is not safe all the same: between
  one count and the next, with an answer of the mint's lost and a sender
  who spends the token elsewhere in that moment, what the mint signed for
  the other wallet would pass for a payment. The README says one wallet for
  a seed.
- **Anyone can keep others from paying.** The mint is asked for every token
  that passes the checks made here, and a token that will be refused there
  costs its sender nothing to make; nor does asking for an invoice. So
  there is a budget for the whole service, 10 of either and one more every
  six seconds, and someone who uses it up keeps everyone from buying for as
  long as they go on. Invoices that nobody pays also take the mint's
  attention from those that are paid: each is asked about until it has
  ended, one every three seconds in all, so with many waiting a payment is
  seen later (half the looks go to orders whose buyers ask, half to
  whichever waited longest). Members are carried all the same.
- **A mint taken out of `MINTS` strands its open invoices.** The service
  keeps a wallet only for the mints it names, so an invoice of a mint that
  was removed cannot be asked about: it is not shown to be paid any more,
  the log says so, and the order is kept with what claims it. One paid in
  between is granted only when the mint is named again. A token need not carry the proof (NUT-12) that
  would let the service refuse a made-up one without asking: wallets in
  use leave it out.
- **A mint is trusted for what it holds, and for the truth.** It can keep
  what the wallet has there, and it decides what was paid: a mint that says
  it signed when it did not is believed, and so is one that says an invoice
  is paid. The invoice is the mint's too: its amount is checked here, and
  who it pays is not, so a mint could have a buyer pay someone else. That
  is what choosing a mint means.
- **What is paid after an invoice has ended is lost.** To the payer, at the
  mint; the exit does not know of it, having given the order up on the
  mint's word ten minutes after the end. A Lightning wallet does not pay an
  invoice that has ended, so this takes a payment that was under way for
  longer than that.
- **The wallet library is most of the program.** Some 270 crates, pinned by
  the lockfile and by `cdk`'s exact version, none of them read here beyond
  what the service calls. Nothing in CI looks for advisories against them.
- **A mint named by an IPv6 address in brackets is not reached**: the
  library's HTTP client does not take one. A name, or an IPv4 address.
- **An account's end is by this machine's clock.** A machine that starts
  with its clock in the past (no battery, no time yet from the network)
  carries the members of an account whose time is over, until the clock is
  right. An account that has ended is not removed: it keeps its members'
  places until whoever made it drops it.
- **Paid mode's check of the host looks at the main routing table only.**
  `up` refuses a host with an address, a route or a resolver in
  `100.64.0.0/10`. A route there that sits in another table, behind a policy
  rule, is not seen (an address on an interface is, which is how Tailscale is
  caught).
- **This host can send to a member's inner address, and it is counted.** The
  route to the tunnel is the host's too, as it is for a listed client. A
  process on the exit that sends there is carried to the member on the
  member's bytes.
- **The config's interface names are not checked.** `WAN`, `MESH_IF` and
  `TUN` from `/etc/fips-exit/config` are placed in the nftables script as
  written. The file is root's, so this is a typo running as root rather than
  an attack, but criterion 9 of `PR-REVIEW.md` is not yet true of them.

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
- With `ACCESS=paid` the firewall is not a second lock in front of the
  daemon: it cannot know the members, so it admits the tunnel from the whole
  mesh and `Clients::admits` decides alone. The clients' whole ranges are
  routed to the TUN for the same reason, and the daemon drops what it finds
  no client for. The README says what the mode opens.
- In paid mode the IPv6 route to the tunnel is for all of `fd00::/8`, and is
  looked at only for packets of connections that came out of the tunnel:
  those are marked there, with one bit of the connection mark. Looked at
  for everything forwarded, as the per-client routes of the default mode
  are, it would take every forwarded packet to a unique-local address; for
  everything from the uplink, a fips gateway's LAN traffic too. Something
  else on the host that sets or clears that bit breaks IPv6 for the members,
  or sends its own traffic to the tunnel, where it is dropped as nobody's.
- TCP port 25 is closed to members and open to listed clients, who are the
  operator's own.
- A token is taken to the mint whether or not it carries the mint's proof of
  its signature (NUT-12): what carries one is checked by the library, and
  what does not is the mint's to refuse.
- "Spent", said by the mint, is not taken as the end of an order by itself:
  the wallet's own request may be what spent the token. The mint is asked
  what it signed for this wallet, and that is the end of it either way.
- What a token is worth over the price, up to a tenth, is kept; more than
  that and it is not taken at all, so that a slip of a finger costs nobody
  a large token.
- A purchase is answered while its connection lives (a minute), with "not
  yet" if need be, and goes on by itself: a token half taken is not left
  because a connection closed.
- One thing at a time at a mint: a token taken, or what was interrupted put
  right, never both. Sales at one mint wait for each other.
- The service says "reached" of a mint only when the mint itself answered,
  not from what the wallet remembers of it; a mint that is away sells
  nothing, and its tokens are not touched.
- The exit's operator sees its clients' traffic, as any VPN endpoint does.
- The resolver forwards and nothing more: no cache, no DNSSEC validation,
  no filtering of private addresses in answers (a client could not reach
  one through the exit anyway), UDP only. It is as trustworthy as the
  host's resolver, which the operator chose.
- A resolver that cannot start (port 53 taken, no upstream) is logged and
  the daemon keeps running: the tunnel is still of use to a client that
  brings its own names.
- The advert's signature is BIP-340 as the BIP writes it, in Python, and not
  constant-time. It signs one public event an hour on the machine the key
  lives on; there is nobody to time it.
- The advert says `allow-list` whatever `ACCESS` is, until something here
  takes a payment: who is served is who the operator put there. The country
  in it is the operator's claim and is checked only for being a country.
- The advert tells the world that this npub is an exit, and tells each
  internet relay this host's address. That is its purpose, and it is the
  operator's choice: nothing is published unless `ADVERT_RELAYS` names where.
- Accounts are kept in memory and are gone after a restart, when nobody but
  the listed clients is carried until they are made again. What was used
  between the last `usage` and the restart is forgotten: the program that
  makes the accounts keeps the books, and this errs in the client's favour.
- Whoever can write to the control socket decides who uses the exit and for
  how many bytes. That is what the socket is for. It cannot touch the list.
- A client put on the list takes its place, and its inner IPv4 address, from
  a member that had either, at once and without the five minutes. The list
  is the operator's word, and what was still on its way to the member then
  reaches a client of the operator's own.
- The control socket is listened on for as long as the daemon runs. A peer
  that cannot be taken is logged once and the next one is waited for; the
  daemon does not stop, since a restart would empty the accounts.
- The control socket speaks lines of words, not JSON: a JSON parser written
  by hand has no place in a root daemon with one dependency.
- A member is counted before the firewall decides, so a packet to a
  destination the exit refuses is counted and then dropped. The README says
  so.
- An account's end is set, where its three numbers are only raised: it is a
  time somebody sold, and may be moved either way by whoever may write to the
  socket. The same command sent twice still changes nothing. A clock that
  cannot be read ends every account that has an end.
- The bytes the exit carries, for all clients together, are what the TUN
  device has counted since it was made: `status` reads them there. They are
  not in the daemon's line in the journal, which has packets: with one
  client on the list, bytes by the minute would be that client's. Per client
  bytes are counted only when the operator turns it on, and then
  `CLIENT_COUNTS=on` opens the control socket too, on an exit that sells
  nothing. That socket takes no accounts: where nothing is sold nobody is
  carried for one, and none of their lookups answered.
- The daemon reads its client list again as soon as it is told to (SIGHUP),
  in a thread that waits for that, and no longer when the next packet
  comes: a removed client is cut off then, and its count is gone before it
  can be put back.
- DNS for a member is not counted. It is answered only while the account has
  bytes, and each client has a limit on queries in flight: 64, which is what
  the whole exit had before, of 256.
- A control socket that cannot be made is logged and the daemon keeps
  running, like the resolver.
