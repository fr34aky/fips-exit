//! The operator's own way into the service: a Unix socket in the service's
//! runtime directory, which only the service's user and root can open, and
//! which `fips-exit grant`, `packages`, `top-up`, `members` and `revoke`
//! speak to. Packages made here are given away: nothing is paid for them.
//! `wallet` and `orders` say what was paid, and `terms` what the advert is
//! to say of this exit.
//!
//! One command a line, words with spaces between them; every answer ends in
//! a line that begins `ok` or `err`.
//!
//! ```text
//! grant <size> <days> <npub|address,…> [label…]   ok <id> <key>
//! top-up <id> <size> <days>                       ok
//! members <id> <npub|address,…|->                 ok
//! revoke <id>                                     ok
//! packages                                        package <id> <standing> <granted> <used_in> <used_out> <until> <members|-> [label], … ok <n>
//! orders                                          order <id> <paid|open> <created> <buyer> <offer> <sat> <paid sat> <fee sat> <package|-> <mint>, … ok <n>
//! wallet                                          mint <url> <reached|away> <holds sat> <under way sat> <sold sat>, … ok <n>
//! terms                                           terms <JSON: price_msat_per_gb, methods, port, mints, packages>, ok
//! ```

use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use crate::config::size;
use crate::http::Site;
use crate::identity::client;
use crate::payouts;
use crate::store::Store;
use crate::sync::unix_now;
use crate::wallet::Left;

/// The longest line read, and how long one may take.
const MAX_LINE: usize = 4096;
const LINE_TIME: Duration = Duration::from_secs(10);
/// The longest label, in characters.
const MAX_LABEL: usize = 64;
/// The most orders listed: the newest.
const MAX_ORDERS: usize = 200;

/// Members as the operator names them: npubs or fips addresses.
fn members(word: &str) -> Result<Vec<(Ipv6Addr, Option<String>)>, String> {
    if word == "-" {
        return Ok(Vec::new());
    }
    word.split(',').map(|who| client(who).ok_or_else(|| format!("err who {who}"))).collect()
}

fn addresses(named: &[(Ipv6Addr, Option<String>)]) -> Vec<Ipv6Addr> {
    named.iter().map(|(address, _)| *address).collect()
}

/// Once they are in: the npub each was named by, kept for its address, so
/// that it is shown by it.
fn remember(store: &Store, named: &[(Ipv6Addr, Option<String>)]) -> Result<(), String> {
    for (address, npub) in named {
        if let Some(npub) = npub {
            store.remember(*address, npub).map_err(|e| format!("err {e}"))?;
        }
    }
    Ok(())
}

fn days(word: &str) -> Result<u32, String> {
    let fits = !word.is_empty() && word.len() <= 4 && word.bytes().all(|b| b.is_ascii_digit());
    fits.then(|| word.parse().ok()).flatten().filter(|days| *days <= 3660).ok_or_else(|| "err days".into())
}

fn bytes(word: &str) -> Result<u64, String> {
    size(word).ok_or_else(|| "err size (bytes, or MB, GB, TB)".into())
}

/// A label for the operator's own use: one line of printable text.
fn label(words: &[&str]) -> Result<String, String> {
    let text = words.join(" ");
    if text.chars().count() > MAX_LABEL || text.chars().any(char::is_control) {
        return Err(format!("err label (one line, at most {MAX_LABEL} characters)"));
    }
    Ok(text)
}

/// Do what one line asks; the answer, its last line `ok…` or `err…`.
pub fn answer(store: &Store, line: &str, now: u64) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let done = (|| -> Result<String, String> {
        let store_said = |e: crate::store::Refused| format!("err {e}");
        match words[..] {
            ["grant", size, d, who, ref rest @ ..] => {
                let (bytes, days, named, label) = (bytes(size)?, days(d)?, members(who)?, label(rest)?);
                if named.is_empty() {
                    return Err("err who (a package is for someone)".into());
                }
                let (id, key) = store.grant(bytes, days, &addresses(&named), &label, now).map_err(store_said)?;
                remember(store, &named)?;
                Ok(format!("ok {id} {key}\n"))
            }
            ["top-up", id, size, d] => {
                store.top_up(id, bytes(size)?, days(d)?, now).map_err(store_said)?;
                Ok("ok\n".into())
            }
            ["members", id, who] => {
                let named = members(who)?;
                store.set_members(id, &addresses(&named), now).map_err(store_said)?;
                remember(store, &named)?;
                Ok("ok\n".into())
            }
            ["revoke", id] => {
                store.revoke(id).map_err(store_said)?;
                Ok("ok\n".into())
            }
            ["packages"] => {
                let packages = store.packages().map_err(store_said)?;
                let mut out = String::new();
                for p in &packages {
                    let members = if p.members.is_empty() {
                        "-".to_string()
                    } else {
                        p.members.iter().map(|m| store.name_of(*m)).collect::<Vec<_>>().join(",")
                    };
                    out.push_str(&format!(
                        "package {} {} {} {} {} {} {members} {}\n",
                        p.id,
                        p.standing(now).word(),
                        p.granted,
                        p.used_in,
                        p.used_out,
                        p.until,
                        p.label
                    ));
                }
                out.push_str(&format!("ok {}\n", packages.len()));
                Ok(out)
            }
            ["orders"] => {
                let orders = store.orders(MAX_ORDERS).map_err(store_said)?;
                let mut out = String::new();
                for o in &orders {
                    // Paid; or open, with a token or an invoice; or an
                    // invoice that ended unpaid.
                    let state = match o {
                        o if o.paid => "paid",
                        o if o.ended > 0 => "ended",
                        _ => "open",
                    };
                    out.push_str(&format!(
                        "order {} {state} {} {} {} {} {} {} {} {} {}\n",
                        o.id,
                        o.created,
                        store.name_of(o.buyer),
                        o.offer,
                        o.sat,
                        o.paid_sat,
                        o.fee_sat,
                        o.package.as_deref().unwrap_or("-"),
                        o.mint,
                        o.method
                    ));
                }
                out.push_str(&format!("ok {}\n", orders.len()));
                Ok(out)
            }
            [] => Err("err syntax".into()),
            [
                "grant" | "top-up" | "members" | "revoke" | "packages" | "orders" | "wallet" | "terms" | "token"
                | "tokens" | "take-back" | "quote" | "pay" | "sweep" | "withdrawals",
                ..,
            ] => Err("err arguments".into()),
            _ => Err("err command".into()),
        }
    })();
    match done {
        Ok(out) => out,
        Err(e) => format!("{}\n", e.trim_end()),
    }
}

/// Listen at `path`, for this user alone (and root).
pub fn listen(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        Ok(_) => return Err(format!("{}: exists and is not a socket", path.display())),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(listener)
}

/// Text on one line: what another program's error may say goes into an
/// answer of lines.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(300).collect()
}

/// What became of a payment from the wallet, as a line.
fn left_line(id: &str, left: &Left) -> String {
    match left {
        Left::Paid { sat, fee, proof } => {
            format!("paid {id} {sat} {fee} {}\n", proof.as_deref().filter(|proof| !proof.is_empty()).unwrap_or("-"))
        }
        Left::Pending => format!("pending {id}\n"),
        Left::Not(why) => format!("failed {id} {}\n", one_line(why)),
    }
}

/// What is asked of the service as it runs, and not of its store alone:
/// the wallet, and the terms. None for any other line.
async fn of_the_site(site: &Site, line: &str) -> Option<String> {
    match line.split_whitespace().collect::<Vec<_>>()[..] {
        ["wallet"] => {
            let mut out = String::new();
            let mints = site.desk.as_ref().map(|desk| desk.wallets.mints.as_slice()).unwrap_or_default();
            for mint in mints {
                let (holds, pending) = match mint.balance().await {
                    Ok(balance) => balance,
                    Err(e) => return Some(format!("err wallet {e}\n")),
                };
                let sold = match site.store.sold(&mint.name) {
                    Ok(sold) => sold,
                    Err(e) => return Some(format!("err {e}\n")),
                };
                let out_of_it = match site.store.paid_out(&mint.name) {
                    Ok(out) => out,
                    Err(e) => return Some(format!("err {e}\n")),
                };
                let state = if mint.ready() { "reached" } else { "away" };
                // Whether it gives invoices, as it said when last reached.
                let invoices = if mint.gives_invoices(None) { "invoices" } else { "tokens" };
                // Whether the wallet holds as much as it may there.
                let room = if mint.full() { "full" } else { "room" };
                out.push_str(&format!(
                    "mint {} {state} {holds} {pending} {sold} {invoices} {out_of_it} {room}\n",
                    mint.name
                ));
            }
            // And what the config says of it: the most it may hold at a
            // mint, where it is sent on to, and above how much.
            out.push_str(&format!(
                "ok {} {} {} {}\n",
                mints.len(),
                site.config.wallet_cap,
                site.config.sweep_to.as_deref().unwrap_or("-"),
                site.config.sweep_above
            ));
            Some(out)
        }
        // What leaves the wallet, on the operator's word: see `payouts`.
        ["token", sat] | ["token", sat, _] => {
            let Some(sat) = sat.parse::<u64>().ok().filter(|sat| *sat > 0) else {
                return Some("err a token of how many sat\n".into());
            };
            let mint = line.split_whitespace().nth(2);
            Some(match payouts::token(site, mint, sat).await {
                Ok((id, cost, text)) => format!("token {id} {cost} {text}\nok\n"),
                Err(e) => format!("err {}\n", one_line(&e)),
            })
        }
        ["tokens"] => Some(match payouts::tokens(site).await {
            Ok(out) => {
                let lines: String =
                    out.iter().map(|(mint, name, text)| format!("token {name} {mint} {text}\n")).collect();
                format!("{lines}ok {}\n", out.len())
            }
            Err(e) => format!("err {}\n", one_line(&e)),
        }),
        ["take-back", name] => Some(match payouts::take_back(site, name).await {
            Ok(back) => format!("back {back}\nok\n"),
            Err(e) => format!("err {}\n", one_line(&e)),
        }),
        ["quote", invoice] | ["quote", invoice, _] => {
            let mint = line.split_whitespace().nth(2);
            Some(match payouts::quote(site, mint, invoice).await {
                Ok((mint, payable)) => {
                    format!(
                        "quote {} {} {} {} {mint}\nok\n",
                        payable.quote, payable.sat, payable.fee_most, payable.expires
                    )
                }
                Err(e) => format!("err {}\n", one_line(&e)),
            })
        }
        ["pay", quote] | ["pay", quote, _] => {
            let mint = line.split_whitespace().nth(2);
            Some(match payouts::pay_quoted(site, mint, quote).await {
                Ok((id, left)) => format!("{}ok\n", left_line(&id, &left)),
                Err(e) => format!("err {}\n", one_line(&e)),
            })
        }
        ["sweep"] | ["sweep", _] => {
            let Some(desk) = &site.desk else { return Some("err there is no wallet\n".into()) };
            let named = line.split_whitespace().nth(1);
            let mut out = String::new();
            for mint in desk.wallets.mints.iter().filter(|mint| named.is_none_or(|name| name == mint.name)) {
                match payouts::sweep(site, desk, mint, true).await {
                    Ok(Some((id, left))) => out.push_str(&left_line(&id, &left)),
                    Ok(None) => out.push_str(&format!("nothing {}\n", mint.name)),
                    Err(e) => return Some(format!("err {}: {}\n", mint.name, one_line(&e))),
                }
            }
            Some(format!("{out}ok\n"))
        }
        ["withdrawals"] => Some(match site.store.withdrawals(MAX_ORDERS) {
            Ok(all) => format!("{}ok {}\n", all.iter().map(payouts::line).collect::<String>(), all.len()),
            Err(e) => format!("err {e}\n"),
        }),
        // What the advert says of this exit's terms: what is configured,
        // whether or not its mints answer at this moment.
        ["terms"] => {
            let invoices =
                site.desk.as_ref().is_some_and(|desk| desk.wallets.mints.iter().any(|m| m.gives_invoices(None)));
            let methods: &[&str] = match (&site.desk, invoices) {
                (Some(_), true) => &["cashu", "bolt11"],
                (Some(_), false) => &["cashu"],
                (None, _) => &[],
            };
            let packages: Vec<serde_json::Value> = site
                .config
                .packages
                .iter()
                .map(|p| serde_json::json!({ "id": p.id, "bytes": p.bytes, "sat": p.sat, "days": p.days }))
                .collect();
            let terms = serde_json::json!({
                "price_msat_per_gb": site.config.price_msat_per_gb,
                "methods": methods,
                "port": site.config.port,
                "mints": site.config.mints,
                "packages": packages,
            });
            Some(format!("terms {terms}\nok\n"))
        }
        _ => None,
    }
}

async fn session(site: Arc<Site>, stream: UnixStream) {
    let (store, changed): (&Store, &Notify) = (&site.store, &site.changed);
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).take(MAX_LINE as u64 * 64);
    loop {
        let mut line = String::new();
        let read = match tokio::time::timeout(LINE_TIME, reader.read_line(&mut line)).await {
            Ok(Ok(read)) => read,
            _ => return,
        };
        if read == 0 {
            return;
        }
        let reply = if line.len() > MAX_LINE {
            "err line\n".to_string()
        } else if let Some(reply) = of_the_site(&site, line.trim_end()).await {
            reply
        } else {
            answer(store, line.trim_end(), unix_now())
        };
        let changes = ["grant", "top-up", "members", "revoke"].iter().any(|word| line.trim_start().starts_with(word));
        if changes && reply.lines().last().is_some_and(|last| last.starts_with("ok")) {
            // Something changed: the daemon is told now, not in a while.
            changed.notify_one();
        }
        if writer.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

pub async fn serve(listener: UnixListener, site: Arc<Site>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(session(site.clone(), stream));
            }
            Err(e) => {
                eprintln!("fips-exit-payd: the operator's socket: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const NPUB: &str = "npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl";

    #[test]
    fn the_operator_grants_tops_up_and_revokes() {
        let store = Store::in_memory();
        let granted = answer(&store, &format!("grant 1GB 30 {NPUB},fd99::2 a friend's phone"), NOW);
        let [ok, id, key] = granted.split_whitespace().collect::<Vec<_>>()[..] else { panic!("{granted}") };
        assert_eq!(ok, "ok");
        assert_eq!(key.len(), 64);
        let listed = answer(&store, "packages", NOW);
        assert_eq!(
            listed,
            format!("package {id} live 1000000000 0 0 {} {NPUB},fd99::2 a friend's phone\nok 1\n", NOW + 30 * 86_400)
        );
        assert_eq!(answer(&store, &format!("top-up {id} 500MB 0"), NOW), "ok\n");
        assert_eq!(answer(&store, &format!("members {id} fd99::3"), NOW), "ok\n");
        let listed = answer(&store, "packages", NOW);
        assert!(listed.starts_with(&format!("package {id} live 1500000000 0 0 ")), "{listed}");
        assert!(listed.contains(" fd99::3 "), "{listed}");
        assert_eq!(answer(&store, &format!("revoke {id}"), NOW), "ok\n");
        assert!(answer(&store, "packages", NOW).starts_with(&format!("package {id} revoked ")));
    }

    /// What was paid, as the operator is told it: the wallet at each mint
    /// against what was sold there, the orders, and the terms the advert is
    /// to carry.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_operator_sees_what_was_paid() {
        let w = crate::orders::testing::world(0, Duration::from_secs(600)).await;
        assert_eq!(
            of_the_site(&w.site, "wallet").await.unwrap(),
            format!("mint {} reached 0 0 0 invoices 0 room\nok 1 500000 - 20000\n", w.mint)
        );
        assert_eq!(answer(&w.site.store, "orders", NOW), "ok 0\n");
        let bought = w.buy("fd77::7", "small", &w.token(64).await, None).await.unwrap();
        assert_eq!(
            of_the_site(&w.site, "wallet").await.unwrap(),
            format!("mint {} reached 64 0 64 invoices 0 room\nok 1 500000 - 20000\n", w.mint)
        );
        let orders = answer(&w.site.store, "orders", NOW);
        let [order, id, state, _created, buyer, offer, sat, paid, fee, package, mint, method, ok, n] =
            orders.split_whitespace().collect::<Vec<_>>()[..]
        else {
            panic!("{orders}")
        };
        assert_eq!((order, id, state, buyer, offer), ("order", bought.order.as_str(), "paid", "fd77::7", "small"));
        assert_eq!(
            (sat, paid, fee, package, mint),
            ("64", "64", "0", bought.settled.package.id.as_str(), w.mint.as_str())
        );
        assert_eq!((method, ok, n), ("cashu", "ok", "1"));
        // The package it made is among the packages, said to be bought.
        assert!(answer(&w.site.store, "packages", NOW).contains(" fd77::7 bought: small\n"));
        // What leaves the wallet, on the operator's word: a token, which
        // is out until somebody redeems it, and can be taken back.
        let said = of_the_site(&w.site, "token 40").await.unwrap();
        let ["token", id, "40", text, "ok"] = said.split_whitespace().collect::<Vec<_>>()[..] else { panic!("{said}") };
        assert!(id.starts_with('w') && text.starts_with("cashu"), "{said}");
        let out = of_the_site(&w.site, "tokens").await.unwrap();
        let ["token", name, mint, its_text, "ok", "1"] = out.split_whitespace().collect::<Vec<_>>()[..] else {
            panic!("{out}")
        };
        assert_eq!((mint, its_text), (w.mint.as_str(), text));
        assert_eq!(of_the_site(&w.site, &format!("take-back {name}")).await.unwrap(), "back 40\nok\n");
        assert_eq!(of_the_site(&w.site, "tokens").await.unwrap(), "ok 0\n");
        // An invoice: what it takes is asked, and then it is paid.
        let invoice = fips_exit_test_mint::invoice(20, fips_exit_test_mint::Fate::Paid);
        let said = of_the_site(&w.site, &format!("quote {invoice}")).await.unwrap();
        let ["quote", quote, "20", fee_most, _expires, mint, "ok"] = said.split_whitespace().collect::<Vec<_>>()[..]
        else {
            panic!("{said}")
        };
        assert_eq!((mint, fee_most), (w.mint.as_str(), "2"));
        let said = of_the_site(&w.site, &format!("pay {quote}")).await.unwrap();
        let ["paid", paid_id, "20", _fee, _proof, "ok"] = said.split_whitespace().collect::<Vec<_>>()[..] else {
            panic!("{said}")
        };
        let all = of_the_site(&w.site, "withdrawals").await.unwrap();
        assert!(all.ends_with("ok 2\n"), "{all}");
        assert!(
            all.contains(&format!("withdrawal {id} back ")) && all.contains(&format!("withdrawal {paid_id} done "))
        );
        assert!(all.lines().any(|line| line.ends_with(&format!(" invoice 20 21 {} {invoice}", w.mint))), "{all}");
        assert_eq!(
            of_the_site(&w.site, "wallet").await.unwrap(),
            format!("mint {} reached 43 0 64 invoices 21 room\nok 1 500000 - 20000\n", w.mint)
        );
        // What is not a withdrawal is said on one line, and takes nothing.
        for (asked, why) in [
            ("token 0", "err a token of how many sat"),
            ("token 5000", "err the wallet holds 43 sat"),
            ("token 5 https://mint.example", "err https://mint.example is not a mint in MINTS"),
            ("pay nothing", "err no such quote"),
            ("quote lnbc1", "err "),
            ("take-back nothing", "err no token of that name is out"),
            ("sweep", "err "),
        ] {
            let said = of_the_site(&w.site, asked).await.unwrap();
            assert!(said.starts_with(why) && said.lines().count() == 1, "{asked}: {said}");
        }
        assert!(of_the_site(&w.site, "withdrawals").await.unwrap().ends_with("ok 2\n"));
        let terms = of_the_site(&w.site, "terms").await.unwrap();
        let (line, ok) = terms.trim_end().split_once('\n').unwrap();
        let said: serde_json::Value = serde_json::from_str(line.strip_prefix("terms ").unwrap()).unwrap();
        assert_eq!(
            said,
            serde_json::json!({
                "price_msat_per_gb": 2000000, "methods": ["cashu", "bolt11"], "port": 5170, "mints": [w.mint],
                "packages": [{"id": "small", "bytes": 10000000, "sat": 64, "days": 1},
                             {"id": "big", "bytes": 1000000000, "sat": 1500, "days": 30}],
            })
        );
        assert_eq!(ok, "ok");
        assert_eq!(of_the_site(&w.site, "packages").await, None, "the store's commands are the store's");
        assert_eq!(answer(&w.site.store, "wallet now", NOW), "err arguments\n");
    }

    #[test]
    fn what_is_not_a_command_is_said_and_changes_nothing() {
        let store = Store::in_memory();
        let bad = |line: &str, said: &str| {
            let got = answer(&store, line, NOW);
            assert!(got.starts_with(said) && got.ends_with('\n') && got.lines().count() == 1, "{line:?}: {got:?}");
        };
        bad("", "err syntax");
        bad("reboot", "err command");
        bad("grant 1GB 30", "err arguments");
        bad("grant lots 30 fd99::2", "err size");
        bad("grant 1gb 30 fd99::2", "err size");
        bad("grant 0 30 fd99::2", "err too-much");
        bad("grant 1GB -1 fd99::2", "err days");
        bad("grant 1GB 3661 fd99::2", "err days");
        bad("grant 1GB 30 -", "err who");
        bad("grant 1GB 30 2001:db8::1", "err who");
        bad("grant 1GB 30 npub1mistyped", "err who");
        bad("grant 1GB 30 fd99::2,fd99::2", "err members");
        bad(&format!("grant 1GB 30 fd99::2 {}", "x".repeat(65)), "err label");
        bad("top-up p0000000000000000 1GB 0", "err no-package");
        bad("revoke nothing", "err no-package");
        bad("packages please", "err arguments");
        assert_eq!(answer(&store, "packages", NOW), "ok 0\n");
        assert!(answer(&store, "grant 1GB 0 fd99::2", NOW).starts_with("ok "));
        bad("grant 1GB 0 fd99::2", "err elsewhere fd99::2");
    }
}
