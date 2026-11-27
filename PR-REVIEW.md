# PR Review Checklist

The criteria applied to incoming PRs on `fips-exit`. Written to be executable
by a human or a coding agent, in that order: read the context, apply the
criteria, then write prose — not a filled-in form.

This is two programs that run as root on someone's server and forward
strangers' packets to the internet. A change here can let a node that was
never allowed use the exit, hand one client's traffic to another, expose the
operator's LAN to the mesh, or leave firewall rules behind on a machine. The
criteria are weighted accordingly.

## Step 1 — Should this even be reviewed?

Skip and say so briefly:

- Closed, merged, or draft PRs.
- Dependabot PRs for actions, unless the bump crosses a major version or
  moves `actions/checkout`, which runs with the repository's contents in
  hand and is pinned for that reason.

Everything touching `src/`, `payd/`, `fips-exit`, `fips-exit.service`,
`install.sh`, `test/` or `.github/workflows/` gets a real review.
`payd/proto` and its vectors are a contract with every client: a change
there is a change for all of them.

## Step 2 — Gather context

Do this before reading a single diff hunk.

1. **PR metadata.** `gh pr view <n>` and `gh pr diff <n>`. Does the body say
   what the change does and why, or only what it touches?
2. **CI state.** `gh pr checks <n>`. The `checks` job runs the daemon's unit
   tests, `test/netns.sh`, the whole exit in network namespaces, and the
   tests of `payd/proto` against its vectors. Read why
   a check is red before believing it. There is no automated security scan:
   that review is section B below, done by a person with
   `SECURITY-REVIEW.md` open.
3. **Base freshness.** Is the branch behind `main`?
4. **Project guidance.** `README.md` says what the exit does to the machine
   it runs on; `SECURITY-REVIEW.md` maps the trust boundaries, the known
   gaps, and the deliberate choices that are not findings.
5. **The other side of the contract.** fips2go's `shim/src/exit.rs` and
   `exit-node/` (README: *What the phone sends*). A change to what goes on
   the wire here is a change there too.

## Step 3 — The criteria

### A. Structure and hygiene

1. **The body explains the why.** What was broken or missing, and what
   observable behaviour differs now.
2. **Scope matches the stated intent.** No drive-by reformatting, no second
   feature inside a fix.
3. **Commit messages carry the reasoning.** The message, not the PR body, is
   what survives.

### B. The change itself

4. **The wire contract stays in step.** The inner IPv4 formula lives in
   `src/main.rs`, in `fips-exit`, and in fips2go; the MSS values (1200 for
   IPv4, 1180 for IPv6) live here and in fips2go. A PR that changes one
   place changes all of them or explains why not. CI holds the daemon and
   the script to the same test vectors. The tags of an exit's advert and the
   price of a byte live in `payd/proto`, in the script (`advert_tags`) and
   in every client that reads an advert:
   `payd/proto/vectors/advert.json` is what they are all held to, and a
   change to the tags is a change to that file first.
5. **Untrusted input is treated as hostile.** Anything that reads a packet
   (`Clients::admits`, `Clients::route`) handles bytes a stranger chose, and
   `parse_command` handles bytes a peer on the control socket chose, and
   `publish` what a relay sent. Check
   bounds and length arithmetic, and what a truncated packet or line does. A
   panic is a denial of service for every client.
6. **Admission is still exact.** A packet enters the tunnel only from a
   listed client, or from a member of an account that has bytes left, and
   only with that client's own inner source address, which it must also
   hold. A reply goes only to the client its destination belongs to. Two
   clients may never share an inner address, in `add`, in a list edited by
   hand, or as members. The resolver answers those clients only, and only
   queries. A listed client is never displaced by a member, and a reload of
   the list leaves the accounts as they were.
7. **What a member is carried is counted, once.** After the packet was
   passed on, by its inner length, against its own account. The three
   numbers of an account only grow; nothing is carried once the count has
   reached the grant, bar the packet that crosses, and nothing from the
   second an account that has an end has ended. A client on the list is
   counted only when the operator asked for it, in memory, and not beyond
   its place on the list.
8. **The firewall still isolates.** Through the tunnel a client reaches the
   uplink and nothing else on this host, and not another client; the
   internet reaches a client only as a reply. A member of an account gets no
   more than a listed client, and not TCP port 25. With `ACCESS=paid` the
   openings in fips's firewall and ufw are for the whole mesh, so they must
   be exactly the tunnel and the resolver, to this node's own address; in
   the default mode they stay per listed client. `SECURITY-REVIEW.md` lists
   what is known to be missing here; a PR must not add to it silently.
9. **Root's commands are built from parsed values.** Addresses go through
   `ipaddress`, interface names are checked, commands are argument lists,
   never a shell string. Nothing from the client list, the config or the
   command line is pasted into an nftables script as it came.
10. **`down` removes what `up` made**, and only that: this script's table,
    its routes, its tagged rules in fips's firewall and in ufw. Other
    people's rules are not touched.
11. **What it does to the machine is said in the README.** Forwarding,
    `accept_ra`, the firewalls it opens. An operator must be able to read
    what running this changes before running it.
12. **The PR states how it was verified.** `cargo test` and
    `unshare -Urnm test/netns.sh` at least, and for anything the namespaces
    cannot show (a real uplink, ufw, fips's firewall, a phone as the
    client), what was run on a real node — or that it was not.

### C. Consequences

13. **Existing clients and installs.** Does an upgrade change a client's
    address, need a step from the operator, or leave old state behind? Say
    so in the commit message and the README.
14. **The install path still works.** `install.sh`, the unit file's start
    and stop commands, and the paths they name stay in step.

## Step 4 — Compose the review

Write prose. Open with what the PR does and whether it should land. Then the
findings that matter, most serious first, each with the concrete failure it
causes: inputs, state, resulting behaviour. "This could be spoofed" is not a
finding; "a listed client sending inner source X is admitted because the
check compares only three bytes" is. Close with the disposition and what
would change it.

## Step 5 — Filter aggressively

Do not flag:

- Style the codebase does not enforce. There is no linter here.
- Hypotheticals with no reachable path. Name the sender or the caller.
- The deliberate choices and the known gaps in `SECURITY-REVIEW.md`. Add
  new ones there, not in a review.

Three real findings beat fifteen observations.

## Step 6 — Citation discipline

Cite with full-SHA permalinks so they survive a rebase:

```
https://github.com/fr34aky/fips-exit/blob/<full-40-char-sha>/src/main.rs#L96-L110
```

## Notes

State confidence honestly: "this is wrong" and "I think this is wrong, but I
have not traced the caller" are different claims.

Green CI means the unit tests passed and the exit worked in namespaces on
one kernel. It says nothing about a real uplink, another host firewall, or a
phone. Those are the author's to state.
