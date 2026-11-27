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
- **The node's key going anywhere.** `fips-exit advert` reads the fips
  identity's secret key. It must never be printed, logged, put in an error
  message or sent: only the signature leaves. That includes a key file that
  holds something else, whose contents are not repeated either. Whoever has
  the key is the node, on the mesh and on Nostr.
- **An advert that is not this exit's, or says more than the exit does.**
  Signed with a key that is not the node's own (it is compared with the
  mesh interface's address first); naming an access the exit does not give;
  or tags that are not what `payd/proto` specifies, which clients would
  pass over or, worse, read differently. And an advert sent anywhere the
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
- **An account's end is by this machine's clock.** A machine that starts
  with its clock in the past (no battery, no time yet from the network)
  carries the members of an account whose time is over, until the clock is
  right. An account that has ended is not removed: it keeps its members'
  places until whoever made it drops it.
- **Nothing makes accounts yet.** `ACCESS=paid` serves the members of
  accounts; what makes the accounts, a payment service, is not written. Until
  it is, the mode is of use only to someone who writes to the socket by hand.
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
