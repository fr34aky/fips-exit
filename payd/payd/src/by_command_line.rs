//! The command-line client (`fips-exit-pay`, in `../client`) against this
//! service, over a socket: what a Linux node's user does, end to end, with
//! a real mint behind it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fips_exit_pay::{Around, DONE, FAILED, WAITING};

use crate::http::Site;
use crate::orders::testing::{World, world};
use crate::store::Order;

/// An npub: a key of zeros, with its checksum.
const NPUB: &str = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme";

/// An exit that sells, answering on a socket of this machine, with its
/// orders looked at as a service does, only sooner.
struct Shop {
    w: World,
    site: Arc<Site>,
    at: SocketAddr,
    state: PathBuf,
}

async fn shop() -> Shop {
    let w = world(0, Duration::from_secs(600)).await;
    w.hold().await;
    let site = w.as_exit(NPUB, |waiting| {
        waiting.every = Duration::from_millis(300);
        (waiting.pace, waiting.chain_pace) = ((1, 1), (1, 1, 1));
    });
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let at = listener.local_addr().unwrap();
    tokio::spawn(crate::http::serve(listener, site.clone(), crate::http::Limits::default(), |_| true));
    tokio::spawn(crate::invoices::keep(site.clone()));
    let state = w.dir.join("client-state");
    Shop { w, site, at, state }
}

impl Shop {
    /// Run the client with `line`, and `input` on its standard input. How
    /// it ended, what it wrote, and what it said beside.
    async fn run(&self, line: &str, input: &str) -> (u8, String, String) {
        let mut args: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        args.insert(1, NPUB.to_string());
        // By its own name and port, at the socket it listens on here.
        args.extend(["--port".to_string(), "5170".to_string(), "--connect".to_string(), self.at.to_string()]);
        args.extend(["--state".to_string(), self.state.display().to_string()]);
        let input = input.to_string();
        tokio::task::spawn_blocking(move || {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let ended = fips_exit_pay::run(
                &args,
                &mut Around {
                    out: &mut out,
                    err: &mut err,
                    input: &mut input.as_bytes(),
                    env: &|_| None,
                    resolve: &fips_exit_pay::resolve,
                    tty: true,
                    pace: Some(Duration::from_millis(300)),
                },
            );
            (ended, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
        })
        .await
        .unwrap()
    }

    /// The newest order in the store, once there is one more than `had`.
    async fn new_order(&self, had: usize) -> Order {
        for _ in 0..100 {
            let orders = self.site.store.orders(50).unwrap();
            if orders.len() > had {
                return orders[0].clone();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no order was made")
    }

    fn kept(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.state.join(format!("{NPUB}.json"))).unwrap()).unwrap()
    }

    /// The package used here, and its key, as they are kept.
    fn kept_key(&self) -> (String, String) {
        let kept = self.kept();
        let package = kept["package"].as_str().unwrap().to_string();
        let keys = kept["keys"].as_array().unwrap();
        let key = keys.iter().find(|key| key["package"] == package.as_str()).unwrap()["key"].as_str().unwrap();
        (package, key.to_string())
    }
}

fn key_in(out: &str) -> String {
    let key = out.lines().find_map(|line| line.strip_prefix("its key: ")).unwrap_or_else(|| panic!("no key in: {out}"));
    assert!(key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()), "{out}");
    key.to_string()
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[tokio::test(flavor = "multi_thread")]
async fn the_terms_as_a_person_reads_them_and_as_a_program_does() {
    let shop = shop().await;
    let (ended, out, err) = shop.run("terms", "").await;
    assert_eq!(ended, DONE, "{err}");
    assert!(out.contains(NPUB) && out.contains("price: 2000 sat for a GB"), "{out}");
    assert!(out.contains("  small") && out.contains("10 MB     1 days       64 sat"), "{out}");
    assert!(out.contains("  big") && out.contains("1 GB    30 days     1500 sat"), "{out}");
    assert!(
        out.contains(
            "paid with: a Cashu token (--token-file); a Lightning invoice (--invoice); bitcoin on the chain (--onchain)"
        ),
        "{out}"
    );
    assert!(
        out.contains(&format!("  tokens of {}", shop.w.mint)) && out.contains("this node (::1): in no package here"),
        "{out}"
    );
    // The address was named by hand, and is not the npub's: said so.
    assert!(err.contains("who answers there is not checked"), "{err}");
    let (ended, out, _) = shop.run("terms --json", "").await;
    let terms: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!((ended, &terms["version"], &terms["exit"]["npub"]), (DONE, &1.into(), &NPUB.into()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_buys_a_package_from_the_command_line() {
    let shop = shop().await;
    let token = shop.w.token(64).await;
    let file = shop.w.dir.join("token");
    std::fs::write(&file, format!("{token}\n")).unwrap();
    let (ended, out, err) = shop.run(&format!("buy small --token-file {}", file.display()), "").await;
    assert_eq!(ended, DONE, "{err}");
    assert!(out.contains("small (10 MB, 1 days) for 64 sat") && out.contains("paid: 64 sat arrived"), "{out}");
    assert!(
        out.contains("live: 10 MB left, until ") && out.contains("in it: ::1") && out.contains("this node is in it"),
        "{out}"
    );
    let key = key_in(&out);
    // The key is kept, in a file that is its owner's alone.
    let (package, kept) = shop.kept_key();
    assert_eq!(kept, key);
    assert_eq!((mode(&shop.state), mode(&shop.state.join(format!("{NPUB}.json")))), (0o700, 0o600));
    assert!(out.contains(&format!("package {package}")), "{out}");
    assert_eq!(shop.site.store.package_with_key(&key).unwrap().unwrap().id, package);
    // The key as it is kept, and the package it opens.
    let (ended, out, _) = shop.run("key", "").await;
    assert_eq!((ended, out), (DONE, format!("{key}\n")));
    let (ended, out, _) = shop.run("package", "").await;
    assert!(ended == DONE && out.starts_with(&format!("package {package}\n  live: 10 MB left")), "{out}");
    let (_, terms, _) = shop.run("terms", "").await;
    assert!(
        terms.contains(&format!("this node (::1): in package {package}")) && terms.contains("live: 10 MB left"),
        "{terms}"
    );
    // The same token again is the same purchase: said, and not paid twice.
    let (ended, out, _) = shop.run(&format!("buy small --token-file {}", file.display()), "").await;
    assert!(ended == DONE && out.contains("(this token bought it before)"), "{out}");
    assert_eq!(shop.site.store.sold(&shop.w.mint).unwrap(), 64);
    // It is answered with a key again, a new one: that is the one kept now.
    let (first, key) = (key, key_in(&out));
    assert!(first != key && shop.kept_key().1 == key);
    // Another, from standard input, added to the same package by its key.
    let (ended, out, err) = shop.run("buy small --token-file - --add", &shop.w.token(64).await).await;
    assert_eq!(ended, DONE, "{err}");
    assert!(out.contains(&format!("added to package {package}")) && out.contains("live: 20 MB left"), "{out}");
    assert_eq!(shop.site.store.packages().unwrap().len(), 1);
    // What the exit refuses is said in its words, with its word for a program.
    let (ended, out, err) = shop.run("buy big --token-file -", &shop.w.token(64).await).await;
    assert_eq!(ended, FAILED, "{out}");
    assert!(err.contains("(too-little)") && err.contains("The token was not touched."), "{err}");
    let (ended, _, err) = shop.run("buy huge --token-file -", &token).await;
    assert!(ended == FAILED && err.contains("the exit sells no package huge: it sells small, big"), "{err}");
    let (ended, _, err) = shop.run("buy small --token-file -", "lnbc1notatoken").await;
    assert!(ended == FAILED && err.contains("no Cashu token"), "{err}");
    // Members: one that is not in it is taken out of nothing; this node leaves.
    let (ended, out, err) = shop.run("remove fd99::9", "").await;
    assert!(ended == DONE && out.contains("in it: ::1"), "{out} {err}");
    let (ended, out, _) = shop.run("leave", "").await;
    assert!(ended == DONE && out.contains(&format!("this node is out of package {package}")), "{out}");
    let (ended, out, _) = shop.run("leave", "").await;
    assert!(ended == DONE && out.contains("this node was in no package here"), "{out}");
    let (ended, out, _) = shop.run("package", "").await;
    assert!(ended == DONE && out.contains("nobody is in it") && out.contains("this node is not in it"), "{out}");
    // A key that opens nothing; and with another's key, kept once it opened.
    let wrong = shop.w.dir.join("wrong-key");
    std::fs::write(&wrong, "ab".repeat(32)).unwrap();
    let (ended, _, err) = shop.run(&format!("package --key-file {}", wrong.display()), "").await;
    assert!(ended == FAILED && err.contains("no package has that key"), "{err}");
    assert_eq!(shop.kept_key(), (package.clone(), key.clone()), "a key that opened nothing is not kept");
    let (_, other_key) = shop.site.store.grant(1000, 0, &[], "another", crate::sync::unix_now()).unwrap();
    let other = shop.w.dir.join("other-key");
    std::fs::write(&other, &other_key).unwrap();
    let (ended, out, err) = shop.run(&format!("package --key-file {}", other.display()), "").await;
    assert!(ended == DONE && out.contains("1 kB left, with no end"), "{out}");
    assert_eq!(shop.kept_key().1, other_key);
    // The package bought here is not forgotten for it: said, and still opened.
    assert!(err.contains(&format!("The key of {package} is kept still: --package {package}")), "{err}");
    let (ended, out, _) = shop.run(&format!("package --package {package}"), "").await;
    assert!(ended == DONE && out.starts_with(&format!("package {package}\n")), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invoice_is_shown_paid_and_buys_a_package_from_the_command_line() {
    let shop = shop().await;
    // Asked for and not waited for: shown, with a code, and written down.
    let (ended, out, err) = shop.run("buy small --invoice --no-wait", "").await;
    assert_eq!(ended, DONE, "{err}");
    let order = shop.new_order(0).await;
    let invoice = order.request.clone().unwrap();
    assert!(
        out.contains(&format!("order {}: pay this invoice of 64 sat, and small (10 MB, 1 days) is bought", order.id)),
        "{out}"
    );
    assert!(out.contains(&format!("\n{invoice}\n")) && out.contains("What is paid after that is lost"), "{out}");
    assert!(out.contains("\x1b[30;107m") && out.contains('█'), "a code is drawn at a terminal: {out}");
    assert_eq!(shop.kept()["orders"][0]["order"], order.id.as_str());
    // What became of it: it waits, and is shown again; without a code if asked so.
    let (ended, out, _) = shop.run("order --no-qr", "").await;
    assert!(ended == WAITING && out.contains(&invoice) && !out.contains('█'), "{out}");
    let (ended, out, _) = shop.run("order --json", "").await;
    let said: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!((ended, &said["state"], &said["request"]), (WAITING, &"waiting".into(), &invoice.clone().into()));
    let (ended, _, err) = shop.run("key --new", "").await;
    assert!(ended == FAILED && err.contains("(not-paid)"), "{err}");
    // Waited for, and paid meanwhile: the package, and its key, asked for once.
    let waiting = shop.run("order --wait", "");
    let paying = async {
        tokio::time::sleep(Duration::from_millis(900)).await;
        shop.w.pay(&invoice).await;
    };
    let ((ended, out, err), ()) = tokio::join!(waiting, paying);
    assert_eq!(ended, DONE, "{out} {err}");
    assert!(out.contains("waiting for the payment") && out.contains("paid: 64 sat arrived"), "{out}");
    let paid = shop.site.store.order(&order.id).unwrap().unwrap();
    let package = paid.package.clone().unwrap();
    assert!(out.contains(&format!("package {package}, with this node in it")), "{out}");
    let key = key_in(&out);
    assert_eq!(shop.site.store.package_with_key(&key).unwrap().unwrap().id, package);
    assert_eq!(shop.kept_key(), (package.clone(), key.clone()));
    // Asked again, it is paid, and the key that is kept stays the key.
    let (ended, out, _) = shop.run("order", "").await;
    assert!(ended == DONE && out.contains("paid: 64 sat arrived") && !out.contains("its key"), "{out}");
    assert_eq!(shop.site.store.package_with_key(&key).unwrap().unwrap().id, package);
    // A new one for the asking: the one before opens nothing.
    let (ended, out, _) = shop.run("key --new", "").await;
    let new = key_in(&out);
    assert!(ended == DONE && new != key && shop.site.store.package_with_key(&key).unwrap().is_none());
    assert_eq!(shop.kept_key().1, new);
    // Bought and waited for in one go, added to that package by its key.
    let had = shop.site.store.orders(50).unwrap().len();
    let buying = shop.run("buy small --invoice --add --json", "");
    let paying = async {
        let order = shop.new_order(had).await;
        shop.w.pay(order.request.as_deref().unwrap()).await;
    };
    let ((ended, out, err), ()) = tokio::join!(buying, paying);
    assert_eq!(ended, DONE, "{out} {err}");
    let lines: Vec<serde_json::Value> = out.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(
        (&lines[0]["state"], &lines[1]["state"], &lines[1]["added"]),
        (&"waiting".into(), &"paid".into(), &true.into())
    );
    assert_eq!(shop.site.store.package(&package).unwrap().unwrap().granted, 20_000_000);
    // An order of somebody else's, or none: nothing is told.
    let (ended, _, err) = shop.run("order o0123456789abcdef", "").await;
    assert!(ended == FAILED && err.contains("(no-such-order)"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bitcoin_on_the_chain_buys_at_the_rate_from_the_command_line() {
    let shop = shop().await;
    let (ended, out, err) = shop.run("buy big --onchain --no-wait", "").await;
    assert_eq!(ended, DONE, "{err}");
    let order = shop.new_order(0).await;
    let address = order.request.clone().unwrap();
    assert!(
        out.contains(&format!("order {}: send 1500 sat to this address, and big (1 GB, 30 days) is bought", order.id)),
        "{out}"
    );
    assert!(
        out.contains(&format!("\n{address}\n")) && out.contains("whatever part or multiple of 1500 sat it is"),
        "{out}"
    );
    assert!(out.contains("What is confirmed after that is lost") && out.contains('█'), "{out}");
    // Half the price arrives while it is waited for.
    let waiting = shop.run("order --wait", "");
    let paying = async {
        tokio::time::sleep(Duration::from_millis(600)).await;
        shop.w.deposit(&address, 750).await;
    };
    let ((ended, out, err), ()) = tokio::join!(waiting, paying);
    assert_eq!(ended, DONE, "{out} {err}");
    assert!(out.contains("paid: 750 sat arrived, of the 1500 sat that big costs"), "{out}");
    assert!(out.contains("its address is good until ") && out.contains("added to the same package"), "{out}");
    let key = key_in(&out);
    let package = shop.site.store.package_with_key(&key).unwrap().unwrap();
    assert_eq!((package.granted, package.members.len()), (500_000_000, 1));
    let (_, terms, _) = shop.run("terms", "").await;
    assert!(terms.contains("live: 500 MB left, until "), "{terms}");
}
