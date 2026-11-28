//! `fips-exit-pay`: buying and managing packages at a paid fips exit, from
//! the command line of a Linux node.
//!
//! ```text
//! fips-exit-pay terms   <exit>                       what the exit costs, and what this node has there
//! fips-exit-pay buy     <exit> <package> <how>       buy a package: --token-file <file|->, --invoice or --onchain
//! fips-exit-pay order   <exit> [<order>] [--wait]    what became of an order
//! fips-exit-pay key     <exit> [--new [<order>]]     the key of what was bought here
//! fips-exit-pay package <exit>                       the package a key opens: what is left, who is in it
//! fips-exit-pay join    <exit>                       put this node into the package a key opens
//! fips-exit-pay remove  <exit> <member>...           take members out of it
//! fips-exit-pay leave   <exit>                       take this node out of the package it is in
//! ```
//!
//! `<exit>` is the exit's npub, which is its name on the mesh and the way
//! to it. This program asks the exit's payment service what a browser
//! would ask its page, over the mesh, as this node: fips has authenticated
//! the connection, so the exit knows who is buying, and this program
//! checks that the address it talks to is the one that follows from the
//! npub. It holds no money. A token is the user's, from a wallet of their
//! own, and an invoice or an address is paid from one.
//!
//! An exit is not trusted with more than what is paid to it. What it says
//! is shown as plain words; an invoice is shown to be paid only if it asks
//! for the price the exit's own terms name; and nothing it answers names a
//! file or a command here.

pub mod http;
#[path = "../../payd/src/identity.rs"]
pub mod identity;
pub mod kept;
pub mod show;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fips_exit_proto::{bytes_shown, date};
use serde_json::{Value, json};

use http::{Answer, Exit, Failed, ask};
use kept::Kept;
use show::{plain, text};

/// The payment service's port, where an exit's config names no other.
pub const PORT: u16 = 5170;
/// The terms' format this program knows.
const TERMS: u64 = 1;
/// How long a question may take, and a token's purchase: the service takes
/// the token to its mint before it answers.
const QUESTION: Duration = Duration::from_secs(40);
const PURCHASE: Duration = Duration::from_secs(90);
/// How often an order is asked about while it waits: one with an invoice,
/// and one with an address, where things take minutes.
const PACE: Duration = Duration::from_secs(5);
const CHAIN_PACE: Duration = Duration::from_secs(30);
/// How often the same is sent again when it is not known what became of
/// it. The same token is the same purchase, and the same order asked for
/// again within a minute is the same order.
const TRIES: usize = 4;

/// How a run ended, as the shell is told.
pub const DONE: u8 = 0;
pub const FAILED: u8 = 1;
pub const USAGE: u8 = 2;
/// Not decided yet: an order that still waits, a token whose end is not
/// known. The same asked again says more.
pub const WAITING: u8 = 3;

const USAGE_TEXT: &str = "usage: fips-exit-pay <command> <exit's npub> ...

  terms   <exit>                     what the exit costs, and what this node has there
  buy     <exit> <package> <how>     buy a package, paid as <how> says:
              --token-file <file>      with a Cashu token of a mint the exit takes (- for standard input)
              --invoice                with a Lightning invoice, which is shown to be paid
              --onchain                with bitcoin on the chain, to an address that is shown
            --add                      add it to the package whose key is kept (or given), not a new one
            --mint <url>               the mint to ask for the invoice or the address
            --no-wait                  do not wait for the payment: `order` says what became of it
  order   <exit> [<order>] [--wait]  what became of an order (the last one made here, if none is named)
  key     <exit>                     the key of the package bought here, as it is kept
  key     <exit> --new [<order>]     ask the exit for a new key: the one before opens nothing any more
  package <exit>                     the package the key opens: what is left, until when, who is in it
  join    <exit>                     put this node into the package the key opens
  remove  <exit> <member>...         take members (npubs, or fips addresses) out of it
  leave   <exit>                     take this node out of the package it is in

  --key-file <file>   the key to use, instead of the one kept (also: FIPS_EXIT_KEY in the environment)
  --json              answer with the exit's JSON, a line for each answer
  --no-qr             draw no QR code
  --port <n>          the payment service's port (5170)
  --state <dir>       where orders and keys are kept (~/.local/state/fips-exit-pay)
  --connect <addr>    connect to this address and port, instead of resolving <npub>.fips

It ends with 0 when it is done, 1 when it is refused or failed, 3 when it is not decided yet.
";

/// What a run has around it: where it writes, what it is given.
pub struct Around<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// Standard input: a token, where one is to be read from it.
    pub input: &'a mut dyn Read,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// Whether what is written is seen by a person at a terminal.
    pub tty: bool,
    /// How long to wait between two looks, for a test; else as the kind of
    /// order has it.
    pub pace: Option<Duration>,
}

/// Why a run stops short.
#[derive(Debug, PartialEq)]
enum Stop {
    Usage(String),
    Failed(String),
    Waiting(String),
}

impl From<Failed> for Stop {
    fn from(failed: Failed) -> Stop {
        Stop::Failed(failed.said().to_string())
    }
}

/// The flags there are, and whether each takes a value.
const FLAGS: [(&str, bool); 14] = [
    ("--port", true),
    ("--connect", true),
    ("--state", true),
    ("--key-file", true),
    ("--token-file", true),
    ("--mint", true),
    ("--json", false),
    ("--no-qr", false),
    ("--invoice", false),
    ("--onchain", false),
    ("--add", false),
    ("--no-wait", false),
    ("--wait", false),
    ("--new", false),
];
/// The flags every command takes.
const EVERY: [&str; 5] = ["--port", "--connect", "--state", "--json", "--no-qr"];

/// What was asked on the command line.
#[derive(Debug, Default)]
struct Asked {
    words: Vec<String>,
    flags: HashMap<&'static str, String>,
}

impl Asked {
    fn of(args: &[String]) -> Result<Asked, Stop> {
        let mut asked = Asked::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            // A lone `-` is a word; so is everything after `--`.
            if arg == "--" {
                asked.words.extend(args.by_ref().cloned());
            } else if arg.starts_with("--") {
                let (name, takes) = *FLAGS
                    .iter()
                    .find(|(name, _)| name == arg)
                    .ok_or_else(|| Stop::Usage(format!("{}: no such option", plain(arg, 40))))?;
                let value = match takes {
                    true => args.next().ok_or_else(|| Stop::Usage(format!("{name} needs a value")))?.clone(),
                    false => String::new(),
                };
                if asked.flags.insert(name, value).is_some() {
                    return Err(Stop::Usage(format!("{name} is said twice")));
                }
            } else {
                asked.words.push(arg.clone());
            }
        }
        Ok(asked)
    }

    fn has(&self, flag: &str) -> bool {
        self.flags.contains_key(flag)
    }

    fn value(&self, flag: &str) -> Option<&str> {
        self.flags.get(flag).map(String::as_str)
    }

    /// The command takes `flags` and those every command takes, and
    /// between `least` and `most` words after the exit.
    fn takes(&self, flags: &[&str], least: usize, most: usize) -> Result<(), Stop> {
        if let Some(odd) = self.flags.keys().find(|flag| !flags.contains(flag) && !EVERY.contains(flag)) {
            return Err(Stop::Usage(format!("{} takes no {odd}", self.words[0])));
        }
        match self.words.len().saturating_sub(2) {
            n if n < least => Err(Stop::Usage(format!("{} needs more than that", self.words[0]))),
            n if n > most => {
                Err(Stop::Usage(format!("{} takes no {}", self.words[0], plain(&self.words[2 + most], 40))))
            }
            _ => Ok(()),
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

macro_rules! say {
    ($around:expr, $($arg:tt)*) => {{ let _ = writeln!($around.out, $($arg)*); }};
}
macro_rules! note {
    ($around:expr, $($arg:tt)*) => {{ let _ = writeln!($around.err, $($arg)*); }};
}

/// Run what `args` ask for (without the program's own name). How it ended.
pub fn run(args: &[String], around: &mut Around) -> u8 {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        let _ = around.out.write_all(USAGE_TEXT.as_bytes());
        return if args.is_empty() { USAGE } else { DONE };
    }
    match command(args, around) {
        Ok(ended) => ended,
        Err(Stop::Usage(why)) => {
            note!(around, "fips-exit-pay: {why}\n\n{USAGE_TEXT}");
            USAGE
        }
        Err(Stop::Failed(why)) => {
            note!(around, "fips-exit-pay: {why}");
            FAILED
        }
        Err(Stop::Waiting(why)) => {
            note!(around, "fips-exit-pay: {why}");
            WAITING
        }
    }
}

fn command(args: &[String], around: &mut Around) -> Result<u8, Stop> {
    let asked = Asked::of(args)?;
    let name = asked.words.first().cloned().unwrap_or_default();
    let name = name.as_str();
    if !["terms", "buy", "order", "key", "package", "join", "remove", "leave"].contains(&name) {
        return Err(Stop::Usage(format!("{}: no such command", plain(name, 40))));
    }
    let npub = asked.words.get(1).ok_or_else(|| Stop::Usage(format!("{name} of which exit? Its npub is missing")))?;
    let exit = reach(npub, &asked, around)?;
    let kept = Kept::at(asked.value("--state"), around.env);
    let run = Run { exit, asked, kept };
    match name {
        "terms" => run.terms(around),
        "buy" => run.buy(around),
        "order" => run.order(around),
        "key" => run.key(around),
        "package" => run.package(around),
        "join" => run.join(around),
        "remove" => run.remove(around),
        _ => run.leave(around),
    }
}

/// Where the exit `npub` is: the address that follows from its key, which
/// the name `<npub>.fips` resolves to on a node that runs fips.
fn reach(npub: &str, asked: &Asked, around: &mut Around) -> Result<Exit, Stop> {
    let npub = npub.trim().to_ascii_lowercase();
    let key = identity::npub_key(&npub).ok_or_else(|| Stop::Usage(format!("{} is no npub", plain(&npub, 80))))?;
    let its = identity::key_address(&key);
    let port = match asked.value("--port") {
        Some(port) => {
            port.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| Stop::Usage("--port: a port".into()))?
        }
        None => PORT,
    };
    let at = match asked.value("--connect") {
        Some(named) => {
            let at: SocketAddr = named
                .parse()
                .map_err(|_| Stop::Usage("--connect: an address and a port, as in [fd00::1]:5170".into()))?;
            // Named by hand: nothing but the user says who answers there.
            if at.ip() != std::net::IpAddr::V6(its) {
                note!(
                    around,
                    "fips-exit-pay: {} is not the address of that npub ({its}): who answers there is not checked",
                    at.ip()
                );
            }
            at
        }
        None => {
            let name = format!("{npub}.fips");
            let found: Vec<SocketAddr> = (name.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| {
                    Stop::Failed(format!(
                        "{name} is not known on this node: is fips running here, and asked for names that end in .fips? ({e})"
                    ))
                })?
                .collect();
            // The mesh carries a connection to that address to the holder of
            // that key and to nobody else: anything else the name is said to
            // be is not the exit.
            *found.iter().find(|at| at.ip() == std::net::IpAddr::V6(its)).ok_or_else(|| {
                Stop::Failed(format!(
                    "{name} is said to be at {}, which is not the address of that npub ({its}): not asked",
                    found.first().map_or("no address".to_string(), |at| at.ip().to_string())
                ))
            })?
        }
    };
    Ok(Exit { host: format!("{npub}.fips:{port}"), npub, at })
}

/// One run: an exit, what was asked, and what is kept.
struct Run {
    exit: Exit,
    asked: Asked,
    kept: Kept,
}

/// What the service said when it refused: its words, and its word for a
/// program.
fn refusal(answer: &Answer) -> String {
    let (said, code) = (text(&answer.body, "error", 400), text(&answer.body, "code", 40));
    match (said.is_empty(), code.is_empty()) {
        (true, true) => format!("the exit refused, with {}", answer.status),
        (true, false) => format!("the exit refused: {code}"),
        (false, true) => said,
        (false, false) => format!("{said} ({code})"),
    }
}

/// A price in millisatoshi, in sat, for a person.
fn sat_of(msat: u64) -> String {
    match msat % 1000 {
        0 => format!("{} sat", msat / 1000),
        part => format!("{}.{part:03} sat", msat / 1000),
    }
}

/// A package on offer, as a person reads it.
fn offer_shown(offer: &Value) -> String {
    format!(
        "{} ({}, {} days)",
        text(offer, "id", 64),
        bytes_shown(offer["bytes"].as_u64().unwrap_or(0)),
        offer["days"].as_u64().unwrap_or(0)
    )
}

/// The ways of paying, as a person names them.
fn way_shown(word: &str) -> String {
    match word {
        "cashu" => "a Cashu token (--token-file)".into(),
        "bolt11" => "a Lightning invoice (--invoice)".into(),
        "onchain" => "bitcoin on the chain (--onchain)".into(),
        other => plain(other, 20),
    }
}

impl Run {
    fn json(&self) -> bool {
        self.asked.has("--json")
    }

    fn pace(&self, around: &Around, usual: Duration) -> Duration {
        around.pace.unwrap_or(usual)
    }

    /// The answer as it is, for a program.
    fn line(&self, around: &mut Around, body: &Value) {
        say!(around, "{body}");
    }

    /// The exit's terms, as the exit itself says them to this node.
    fn terms_of(&self) -> Result<Value, Stop> {
        let answer = ask(&self.exit, "GET", "/v1/terms", None, QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let terms = answer.body;
        if terms["version"].as_u64() != Some(TERMS) {
            return Err(Stop::Failed(
                "the exit's terms are of a kind this program does not know: nothing is bought".into(),
            ));
        }
        if terms["exit"]["npub"].as_str() != Some(self.exit.npub.as_str()) {
            return Err(Stop::Failed(format!(
                "who answers there says it is {}, not the exit that was asked for",
                text(&terms["exit"], "npub", 80)
            )));
        }
        Ok(terms)
    }

    fn terms(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&[], 0, 0)?;
        let terms = self.terms_of()?;
        if self.json() {
            self.line(around, &terms);
            return Ok(DONE);
        }
        let exit = &terms["exit"];
        let (name, about, country) = (text(exit, "name", 80), text(exit, "about", 300), text(exit, "country", 2));
        let named = if name.is_empty() { "an exit".to_string() } else { name };
        match country.is_empty() {
            true => say!(around, "{named}"),
            false => say!(around, "{named}, said to be in {country}"),
        }
        if !about.is_empty() {
            say!(around, "  {about}");
        }
        say!(around, "  {}", self.exit.npub);
        say!(around, "price: {} for a GB", sat_of(terms["price_msat_per_gb"].as_u64().unwrap_or(0)));
        let offers = terms["packages"].as_array().cloned().unwrap_or_default();
        if offers.is_empty() {
            say!(around, "packages: none");
        } else {
            say!(around, "packages:");
            for offer in offers.iter().take(16) {
                say!(
                    around,
                    "  {:<20} {:>10} {:>5} days {:>12}",
                    text(offer, "id", 64),
                    bytes_shown(offer["bytes"].as_u64().unwrap_or(0)),
                    offer["days"].as_u64().unwrap_or(0),
                    format!("{} sat", offer["sat"].as_u64().unwrap_or(0))
                );
            }
        }
        let ways: Vec<String> =
            terms["methods"].as_array().into_iter().flatten().filter_map(Value::as_str).map(way_shown).collect();
        match ways.is_empty() {
            true => say!(around, "paid with: nothing just now (the exit sells nothing, or its mint is away)"),
            false => say!(around, "paid with: {}", ways.join("; ")),
        }
        for mint in terms["mints"].as_array().into_iter().flatten().filter_map(Value::as_str).take(8) {
            say!(around, "  tokens of {}", plain(mint, 200));
        }
        let you = &terms["you"];
        match you["package"].as_object() {
            None => say!(around, "this node ({}): in no package here", text(you, "address", 45)),
            Some(_) => {
                let package = &you["package"];
                say!(around, "this node ({}): in package {}", text(you, "address", 45), text(package, "id", 20));
                say!(around, "  {}", standing_shown(package));
                let shared = package["members"].as_u64().unwrap_or(1);
                if shared > 1 {
                    say!(around, "  shared by {shared}");
                }
                if package["ipv4"].as_bool() == Some(false) {
                    say!(
                        around,
                        "  carried over IPv6 only: another client of this exit has this node's inner IPv4 address"
                    );
                }
            }
        }
        Ok(DONE)
    }

    /// The key to use: the one in the file that was named, the one in the
    /// environment, or the one kept for this exit.
    fn key_to_use(&self, around: &Around) -> Result<String, Stop> {
        let given = match self.asked.value("--key-file") {
            Some(file) => {
                let said = std::fs::read_to_string(file).map_err(|e| Stop::Failed(format!("{file}: {e}")))?;
                Some(said.lines().next().unwrap_or_default().trim().to_string())
            }
            None => (around.env)("FIPS_EXIT_KEY").map(|key| key.trim().to_string()),
        };
        match given {
            Some(key) if show::is_key(&key) => Ok(key.to_ascii_lowercase()),
            Some(_) => Err(Stop::Failed("what was given as the key is no key: 64 hex digits".into())),
            None => self.kept.key(&self.exit.npub).ok_or_else(|| {
                Stop::Failed(
                    "no key is kept for this exit: name a file that holds one with --key-file, or buy a package".into(),
                )
            }),
        }
    }

    /// Keep `key`, of `package`, and say where; or say why not. The key
    /// itself is said either way: whoever bought has it.
    fn keep_key(&self, around: &mut Around, package: &str, key: &str) {
        say!(around, "its key: {key}");
        say!(around, "  whoever has the key sees who is in the package, takes members out of it, and adds to it");
        match self.kept.keep_key(&self.exit.npub, package, key) {
            Ok(file) => say!(around, "  kept in {}", file.display()),
            Err(why) => note!(around, "fips-exit-pay: THE KEY IS NOT KEPT, write it down: {why}"),
        }
    }

    fn buy(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(
            &["--token-file", "--invoice", "--onchain", "--add", "--mint", "--no-wait", "--key-file"],
            1,
            1,
        )?;
        let ways: Vec<&str> =
            ["--token-file", "--invoice", "--onchain"].into_iter().filter(|way| self.asked.has(way)).collect();
        let [way] = ways[..] else {
            return Err(Stop::Usage("buy: paid how? One of --token-file <file>, --invoice, --onchain".into()));
        };
        let word = match way {
            "--token-file" => "cashu",
            "--invoice" => "bolt11",
            _ => "onchain",
        };
        if word == "cashu" && (self.asked.has("--mint") || self.asked.has("--no-wait")) {
            return Err(Stop::Usage(
                "buy: --mint and --no-wait are for an invoice or an address: a token names its mint".into(),
            ));
        }
        if self.asked.has("--key-file") && !self.asked.has("--add") {
            return Err(Stop::Usage("buy: a key is for adding to its package: say --add as well".into()));
        }
        // The token, before anything is asked of anyone.
        let token = match self.asked.value("--token-file") {
            Some(file) => Some(token_from(file, around)?),
            None => None,
        };
        let key = if self.asked.has("--add") { Some(self.key_to_use(around)?) } else { None };
        // What the exit itself says it sells, and for how much.
        let terms = self.terms_of()?;
        let offers = terms["packages"].as_array().cloned().unwrap_or_default();
        let wanted = &self.asked.words[2];
        let offer = offers.iter().find(|offer| offer["id"].as_str() == Some(wanted)).ok_or_else(|| {
            let there: Vec<String> = offers.iter().take(16).map(|offer| text(offer, "id", 64)).collect();
            Stop::Failed(format!("the exit sells no package {}: it sells {}", plain(wanted, 64), there.join(", ")))
        })?;
        let price = offer["sat"]
            .as_u64()
            .filter(|sat| *sat > 0)
            .ok_or_else(|| Stop::Failed("the exit names no price".into()))?;
        let takes: Vec<&str> = terms["methods"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !takes.contains(&word) {
            let instead: Vec<String> = takes.iter().map(|word| way_shown(word)).collect();
            return Err(Stop::Failed(match instead.is_empty() {
                true => "the exit sells nothing just now".into(),
                false => {
                    format!("the exit does not take {} just now: it takes {}", way_shown(word), instead.join("; "))
                }
            }));
        }
        let mut order = json!({ "package": wanted, "method": word });
        if let Some(key) = &key {
            order["key"] = json!(key);
        }
        if let Some(mint) = self.asked.value("--mint") {
            order["mint"] = json!(mint);
        }
        if !self.json() {
            say!(around, "{} for {price} sat, at {}", offer_shown(offer), self.exit.npub);
        }
        match token {
            Some(token) => {
                order["token"] = json!(token);
                self.buy_with_token(around, &order)
            }
            None => self.buy_by_order(around, &order, price),
        }
    }

    /// Send the token. The same token is the same purchase, however often
    /// it is sent: so where the answer is lost, or the exit does not know
    /// yet, it is sent again.
    fn buy_with_token(&self, around: &mut Around, order: &Value) -> Result<u8, Stop> {
        let mut why = String::new();
        for attempt in 0..TRIES {
            if attempt > 0 {
                std::thread::sleep(self.pace(around, PACE));
            }
            let answer = match ask(&self.exit, "POST", "/v1/orders", Some(order), PURCHASE) {
                Ok(answer) => answer,
                // Nothing was sent, the first time: the token is untouched.
                Err(Failed::NotReached(said)) if attempt == 0 => return Err(Stop::Failed(said)),
                Err(failed) => {
                    why = failed.said().to_string();
                    continue;
                }
            };
            if answer.status == 200 {
                return self.bought_with_token(around, &answer.body);
            }
            if !["not-yet", "try-again", "under-way"].contains(&answer.body["code"].as_str().unwrap_or_default()) {
                return Err(Stop::Failed(refusal(&answer)));
            }
            why = refusal(&answer);
        }
        Err(Stop::Waiting(format!(
            "what became of the token is not known yet ({why}). Run the same again, with the same token: it is the same \
             purchase, and is not paid twice"
        )))
    }

    fn bought_with_token(&self, around: &mut Around, bought: &Value) -> Result<u8, Stop> {
        if self.json() {
            self.line(around, bought);
        }
        let package = &bought["package"];
        let id = text(package, "id", 20);
        let key = bought["key"].as_str().filter(|key| show::is_key(key));
        if !self.json() {
            let (paid, fee) = (bought["paid_sat"].as_u64().unwrap_or(0), bought["fee_sat"].as_u64().unwrap_or(0));
            let again = if bought["again"].as_bool() == Some(true) { " (this token bought it before)" } else { "" };
            let fee = if fee > 0 { format!(", after the mint's fee of {fee} sat") } else { String::new() };
            say!(around, "paid: {paid} sat arrived{fee}{again}");
            match bought["added"].as_bool() {
                Some(true) => say!(around, "added to package {id}"),
                _ => say!(around, "package {id}"),
            }
            if package.get("standing").is_some() {
                self.package_shown(around, package);
            }
        }
        match key {
            Some(key) if self.json() => {
                if let Err(why) = self.kept.keep_key(&self.exit.npub, &id, key) {
                    note!(around, "fips-exit-pay: the key is not kept: {why}");
                }
            }
            Some(key) => self.keep_key(around, &id, key),
            None => {}
        }
        Ok(DONE)
    }

    /// Ask for an invoice or an address, show it, and wait for what is
    /// paid.
    fn buy_by_order(&self, around: &mut Around, asked: &Value, price: u64) -> Result<u8, Stop> {
        let mut why = String::new();
        let mut made = None;
        for attempt in 0..TRIES {
            if attempt > 0 {
                std::thread::sleep(self.pace(around, PACE));
            }
            match ask(&self.exit, "POST", "/v1/orders", Some(asked), QUESTION) {
                Ok(answer) if answer.status == 201 || answer.status == 200 => {
                    made = Some(answer.body);
                    break;
                }
                Ok(answer)
                    if ["try-again", "under-way"].contains(&answer.body["code"].as_str().unwrap_or_default()) =>
                {
                    why = refusal(&answer);
                }
                Ok(answer) => return Err(Stop::Failed(refusal(&answer))),
                Err(Failed::NotReached(said)) if attempt == 0 => return Err(Stop::Failed(said)),
                // Asked again within a minute, it is the same order.
                Err(failed) => why = failed.said().to_string(),
            }
        }
        let order = made.ok_or_else(|| Stop::Failed(format!("the exit gave no order: {why}")))?;
        let id = to_pay(&order, Some(price))?;
        let method = order["method"].as_str().unwrap_or_default().to_string();
        if method != asked["method"].as_str().unwrap_or_default() {
            return Err(Stop::Failed(
                "the exit gave an order paid another way than was asked: nothing is shown".into(),
            ));
        }
        // Written down before it is shown: an order is found again by its
        // name alone.
        if let Err(why) = self.kept.keep_order(&self.exit.npub, &id, &method, &text(&order, "offer", 64), now()) {
            note!(around, "fips-exit-pay: the order is not written down ({why}): its name is {id}");
        }
        self.shown_to_pay(around, &order);
        if self.asked.has("--no-wait") {
            if !self.json() {
                say!(around, "what became of it: fips-exit-pay order {}", self.exit.npub);
            }
            return Ok(DONE);
        }
        self.wait(around, &id, &method)
    }

    /// Show what is to be paid for `order`, which [`to_pay`] has read.
    fn shown_to_pay(&self, around: &mut Around, order: &Value) {
        if self.json() {
            return self.line(around, order);
        }
        let (id, sat) = (text(order, "order", 20), order["sat"].as_u64().unwrap_or(0));
        let request = order["request"].as_str().unwrap_or_default();
        let ends = date(order["expires"].as_u64().unwrap_or(0));
        let what = format!(
            "{} ({}, {} days)",
            text(order, "offer", 64),
            bytes_shown(order["bytes"].as_u64().unwrap_or(0)),
            order["days"].as_u64().unwrap_or(0)
        );
        let draw = around.tty && !self.asked.has("--no-qr");
        if order["method"] == "onchain" {
            say!(around, "order {id}: send {sat} sat to this address, and {what} is bought");
            if let Some(code) = show::code(&show::address_link(request, sat)).filter(|_| draw) {
                say!(around, "\n{code}");
            }
            say!(around, "{request}");
            say!(
                around,
                "What arrives buys at that rate, whatever part or multiple of {sat} sat it is, once it is confirmed."
            );
            say!(
                around,
                "It ends {ends}. What is confirmed after that is lost: do not send it late, or with a fee too small."
            );
        } else {
            say!(around, "order {id}: pay this invoice of {sat} sat, and {what} is bought");
            if let Some(code) = show::code(&show::invoice_link(request)).filter(|_| draw) {
                say!(around, "\n{code}");
            }
            say!(around, "{request}");
            say!(around, "It ends {ends}. What is paid after that is lost: do not pay it late.");
        }
    }

    /// Ask what became of order `id` until it is decided.
    fn wait(&self, around: &mut Around, id: &str, method: &str) -> Result<u8, Stop> {
        let pace = self.pace(around, if method == "onchain" { CHAIN_PACE } else { PACE });
        if !self.json() {
            say!(around, "waiting for the payment (stop with ctrl-c: the order stays, and `order` asks again) ...");
        }
        let (mut silent, mut ended) = (0u32, false);
        loop {
            std::thread::sleep(pace);
            let answer = match ask(&self.exit, "GET", &format!("/v1/orders/{id}"), None, QUESTION) {
                Ok(answer) => answer,
                // The exit is away for a moment: the order is not.
                Err(failed) => {
                    silent += 1;
                    if silent == 3 {
                        note!(around, "fips-exit-pay: the exit does not answer ({}): still asking", failed.said());
                    }
                    continue;
                }
            };
            silent = 0;
            if answer.status != 200 {
                return Err(Stop::Failed(refusal(&answer)));
            }
            match answer.body["state"].as_str().unwrap_or_default() {
                "paid" => return self.paid(around, &answer.body),
                "expired" => return Err(Stop::Failed("the order ended, and nothing was paid for it".into())),
                "checking" if !ended => {
                    ended = true;
                    note!(
                        around,
                        "fips-exit-pay: the order can not be paid any more. What was paid in time is still looked for ..."
                    );
                }
                _ => {}
            }
        }
    }

    /// An order is paid: say so, and have the key of the package it made,
    /// if none is kept for it.
    fn paid(&self, around: &mut Around, order: &Value) -> Result<u8, Stop> {
        let id = text(order, "order", 20);
        let package = text(&order["package"], "id", 20);
        let added = order["added"].as_bool() == Some(true);
        if self.json() {
            self.line(around, order);
        } else {
            let (paid, sat) = (order["paid_sat"].as_u64().unwrap_or(0), order["sat"].as_u64().unwrap_or(0));
            match order["method"] == "onchain" {
                true => {
                    say!(around, "paid: {paid} sat arrived, of the {sat} sat that {} costs", text(order, "offer", 64))
                }
                false => say!(around, "paid: {paid} sat arrived"),
            }
            match added {
                true => say!(around, "added to package {package}"),
                false => say!(around, "package {package}, with this node in it"),
            }
            if order.get("request").is_some() {
                let ends = date(order["expires"].as_u64().unwrap_or(0));
                say!(
                    around,
                    "its address is good until {ends}: what is confirmed there by then is added to the same package"
                );
            }
        }
        // Nobody was shown the key of a package an order made: its buyer
        // asks for one. Once: a key asked for again replaces the one kept.
        let have = self.kept.read(&self.exit.npub);
        let kept_for_it =
            have["package"].as_str() == Some(package.as_str()) && self.kept.key(&self.exit.npub).is_some();
        if !added && !kept_for_it && show::is_order_id(&id) {
            match self.new_key(&id) {
                Ok(given) => self.key_given(around, &given),
                Err(Stop::Failed(why)) | Err(Stop::Waiting(why)) | Err(Stop::Usage(why)) => {
                    note!(around, "fips-exit-pay: its key was not had ({why}): ask with `key --new`");
                }
            }
        }
        Ok(DONE)
    }

    /// Ask the exit for a new key of the package order `id` made.
    fn new_key(&self, id: &str) -> Result<Value, Stop> {
        let answer = ask(&self.exit, "POST", &format!("/v1/orders/{id}/key"), Some(&json!({})), QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        if !answer.body["key"].as_str().is_some_and(show::is_key) {
            return Err(Stop::Failed("the exit gave what is no key".into()));
        }
        Ok(answer.body)
    }

    fn key_given(&self, around: &mut Around, given: &Value) {
        let (package, key) = (text(&given["package"], "id", 20), given["key"].as_str().unwrap_or_default());
        if self.json() {
            self.line(around, given);
            if let Err(why) = self.kept.keep_key(&self.exit.npub, &package, key) {
                note!(around, "fips-exit-pay: the key is not kept: {why}");
            }
        } else {
            self.keep_key(around, &package, key);
        }
    }

    /// The order that is meant: the one named, or the last one made here.
    fn order_meant(&self, word: usize) -> Result<String, Stop> {
        match self.asked.words.get(word) {
            Some(id) if show::is_order_id(id) => Ok(id.clone()),
            Some(id) => Err(Stop::Usage(format!("{} is no order's name", plain(id, 40)))),
            None => self
                .kept
                .last_order(&self.exit.npub)
                .ok_or_else(|| Stop::Failed("no order made at this exit is kept here: name one".into())),
        }
    }

    fn order(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&["--wait"], 0, 1)?;
        let id = self.order_meant(2)?;
        let answer = ask(&self.exit, "GET", &format!("/v1/orders/{id}"), None, QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let order = answer.body;
        let method = order["method"].as_str().unwrap_or_default().to_string();
        match order["state"].as_str().unwrap_or_default() {
            "paid" => self.paid(around, &order),
            "expired" => Err(Stop::Failed(format!("order {id} ended, and nothing was paid for it"))),
            "waiting" => {
                // Shown again as something to pay only if it is one.
                to_pay(&order, None)?;
                self.shown_to_pay(around, &order);
                match self.asked.has("--wait") {
                    true => self.wait(around, &id, &method),
                    false => Ok(WAITING),
                }
            }
            _ => {
                if self.json() {
                    self.line(around, &order);
                } else {
                    say!(around, "order {id} can not be paid now; what became of it is still being found out");
                }
                match self.asked.has("--wait") {
                    true => self.wait(around, &id, &method),
                    false => Ok(WAITING),
                }
            }
        }
    }

    fn key(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&["--new"], 0, 1)?;
        if self.asked.has("--new") {
            let id = self.order_meant(2)?;
            let given = self.new_key(&id)?;
            self.key_given(around, &given);
            return Ok(DONE);
        }
        if self.asked.words.len() > 2 {
            return Err(Stop::Usage("key: an order is named with --new, for a new key of what it bought".into()));
        }
        let key = self.kept.key(&self.exit.npub).ok_or_else(|| {
            Stop::Failed(
                "no key is kept for this exit. `key --new` asks the exit for one, for what an order bought".into(),
            )
        })?;
        let package = plain(self.kept.read(&self.exit.npub)["package"].as_str().unwrap_or_default(), 20);
        match self.json() {
            true => self.line(around, &json!({ "key": key, "package": { "id": package } })),
            false => say!(around, "{key}"),
        }
        Ok(DONE)
    }

    /// A package as its key holder sees it.
    fn package_shown(&self, around: &mut Around, package: &Value) {
        say!(around, "  {}", standing_shown(package));
        let members = package["members"].as_array().cloned().unwrap_or_default();
        match members.is_empty() {
            true => say!(around, "  nobody is in it"),
            false => {
                for member in members.iter().take(64) {
                    say!(around, "  in it: {}", text(member, "name", 80));
                }
            }
        }
        match package["you"].as_bool() {
            Some(true) => say!(around, "  this node is in it"),
            Some(false) => say!(around, "  this node is not in it: `join` puts it in"),
            None => {}
        }
    }

    /// Ask something about the package the key opens, and show the package
    /// as it is then.
    fn with_key(&self, around: &mut Around, path: &str, more: Value) -> Result<u8, Stop> {
        let key = self.key_to_use(around)?;
        let mut body = more;
        body["key"] = json!(key);
        let answer = ask(&self.exit, "POST", path, Some(&body), QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let id = text(&answer.body, "id", 20);
        // A key that was given, and opens a package: kept for this exit.
        if (self.asked.has("--key-file") || (around.env)("FIPS_EXIT_KEY").is_some())
            && let Err(why) = self.kept.keep_key(&self.exit.npub, &id, &key)
        {
            note!(around, "fips-exit-pay: the key is not kept: {why}");
        }
        if self.json() {
            self.line(around, &answer.body);
        } else {
            say!(around, "package {id}");
            self.package_shown(around, &answer.body);
        }
        Ok(DONE)
    }

    fn package(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&["--key-file"], 0, 0)?;
        self.with_key(around, "/v1/package", json!({}))
    }

    fn join(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&["--key-file"], 0, 0)?;
        // A node is put in by itself, under the address the exit sees it by.
        let terms = self.terms_of()?;
        let this = terms["you"]["address"]
            .as_str()
            .ok_or_else(|| Stop::Failed("the exit does not say who this node is".into()))?;
        self.with_key(around, "/v1/package/members", json!({ "add": [this] }))
    }

    fn remove(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&["--key-file"], 1, 32)?;
        let members: Vec<&String> = self.asked.words[2..].iter().collect();
        if let Some(odd) = members.iter().find(|member| identity::client(member).is_none()) {
            return Err(Stop::Usage(format!("{} is neither an npub nor a fips address", plain(odd, 80))));
        }
        self.with_key(around, "/v1/package/members", json!({ "remove": members }))
    }

    fn leave(&self, around: &mut Around) -> Result<u8, Stop> {
        self.asked.takes(&[], 0, 0)?;
        let answer = ask(&self.exit, "POST", "/v1/leave", Some(&json!({})), QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        if self.json() {
            self.line(around, &answer.body);
        } else {
            match answer.body["left"].as_str() {
                Some(left) => say!(around, "this node is out of package {}", plain(left, 20)),
                None => say!(around, "this node was in no package here"),
            }
        }
        Ok(DONE)
    }
}

/// How a package stands, what is left of it, and until when.
fn standing_shown(package: &Value) -> String {
    let until = match package["until"].as_u64() {
        Some(until) => format!("until {}", date(until)),
        None => "with no end".to_string(),
    };
    format!(
        "{}: {} left, {until}",
        text(package, "standing", 12),
        bytes_shown(package["bytes_left"].as_u64().unwrap_or(0))
    )
}

/// Read a token from `file`, or from standard input for `-`: one word, as
/// a wallet writes it.
fn token_from(file: &str, around: &mut Around) -> Result<String, Stop> {
    let mut said = String::new();
    let read = match file {
        "-" => around.input.take(64 * 1024).read_to_string(&mut said),
        file => std::fs::File::open(file).and_then(|file| file.take(64 * 1024).read_to_string(&mut said)),
    };
    read.map_err(|e| Stop::Failed(format!("the token could not be read from {}: {e}", plain(file, 200))))?;
    let token = said.trim();
    if !token.to_ascii_lowercase().starts_with("cashu") || token.contains(char::is_whitespace) {
        return Err(Stop::Failed("what was given is no Cashu token: one word that begins with cashu".into()));
    }
    Ok(token.to_string())
}

/// Read an order that waits to be paid, before it is shown as something to
/// pay: its name, and that what it asks for is what it says, and (with
/// `price`) what the exit's terms name. An exit is not taken at its word
/// for more than that.
fn to_pay(order: &Value, price: Option<u64>) -> Result<String, Stop> {
    let nothing = |why: &str| Stop::Failed(format!("{why}: nothing is shown to be paid"));
    let id = order["order"]
        .as_str()
        .filter(|id| show::is_order_id(id))
        .ok_or_else(|| nothing("the exit gave an order with no name"))?;
    let sat = order["sat"].as_u64().filter(|sat| *sat > 0).ok_or_else(|| nothing("the exit's order names no price"))?;
    if price.is_some_and(|price| price != sat) {
        return Err(nothing("the exit's order is for another price than its terms name"));
    }
    if order["state"] != "waiting" {
        return Err(nothing("the exit's order does not wait to be paid"));
    }
    let request = order["request"].as_str().unwrap_or_default();
    match order["method"].as_str() {
        Some("bolt11") => match show::invoice_sat(request) {
            Some(asks) if asks == sat => {}
            Some(asks) => {
                return Err(nothing(&format!("the exit's invoice asks for {asks} sat, and the price is {sat} sat")));
            }
            None => return Err(nothing("what the exit gave is no invoice for an amount")),
        },
        Some("onchain") if show::is_address(request) => {}
        Some("onchain") => return Err(nothing("what the exit gave is no address")),
        _ => return Err(nothing("the exit's order is paid in a way this program does not know")),
    }
    if order["expires"].as_u64().is_none_or(|ends| ends <= now()) {
        return Err(nothing("the exit's order has ended already"));
    }
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// Run `line`, with nothing around it. How it ended, what it wrote,
    /// and what it said beside.
    fn ran(line: &str) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ended = run(
            &words(line),
            &mut Around {
                out: &mut out,
                err: &mut err,
                input: &mut std::io::empty(),
                env: &|_| None,
                tty: false,
                pace: None,
            },
        );
        (ended, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// An npub: a key of zeros, with its checksum.
    const NPUB: &str = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme";

    #[test]
    fn what_is_asked_wrongly_is_said_and_nothing_is_asked_of_anyone() {
        assert_eq!(identity::npub_key(NPUB), Some([0u8; 32]), "the tests' npub is one");
        let (ended, out, _) = ran("");
        assert!(ended == USAGE && out.starts_with("usage: fips-exit-pay"));
        let (ended, out, _) = ran("buy --help");
        assert!(ended == DONE && out.contains("--token-file <file>"));
        for (line, why) in [
            ("sell npub1x", "no such command"),
            ("terms", "Its npub is missing"),
            ("terms npub1notone", "is no npub"),
            ("terms fd00::1", "is no npub"),
            (&format!("terms {NPUB} --frobnicate"), "no such option"),
            (&format!("terms {NPUB} --port"), "--port needs a value"),
            (&format!("terms {NPUB} --port 0 --connect [::1]:1"), "--port: a port"),
            (&format!("terms {NPUB} --connect localhost"), "--connect: an address and a port"),
            (&format!("terms {NPUB} --json --json --connect [::1]:1"), "--json is said twice"),
            (&format!("terms {NPUB} extra --connect [::1]:1"), "terms takes no extra"),
            (&format!("terms {NPUB} --invoice --connect [::1]:1"), "terms takes no --invoice"),
            (&format!("buy {NPUB} --connect [::1]:1 --invoice"), "buy needs more than that"),
            (&format!("buy {NPUB} 1gb --connect [::1]:1"), "paid how?"),
            (&format!("buy {NPUB} 1gb --invoice --onchain --connect [::1]:1"), "paid how?"),
            (
                &format!("buy {NPUB} 1gb --token-file t --mint https://m.example --connect [::1]:1"),
                "a token names its mint",
            ),
            (&format!("buy {NPUB} 1gb --invoice --key-file k --connect [::1]:1"), "say --add as well"),
            (&format!("order {NPUB} o123 --connect [::1]:1"), "is no order's name"),
            (&format!("order {NPUB} ../../v1/terms --connect [::1]:1"), "is no order's name"),
            (&format!("key {NPUB} o0123456789abcdef --connect [::1]:1"), "an order is named with --new"),
            (&format!("remove {NPUB} --connect [::1]:1"), "remove needs more than that"),
            (
                &format!("remove {NPUB} somebody --connect [::1]:1 --state /nonexistent"),
                "neither an npub nor a fips address",
            ),
        ] {
            let (ended, out, err) = ran(line);
            assert_eq!(ended, USAGE, "{line}: {err}");
            assert!(err.contains(why) && out.is_empty(), "{line}: {err}");
        }
        // What is said of it is plain text, whatever was typed.
        let (_, _, err) = ran("terms npub1\x1b[2Jx");
        assert!(!err.contains('\x1b'), "{err:?}");
    }

    #[test]
    fn a_name_that_is_not_the_npubs_address_is_not_asked() {
        // No node here answers for .fips in a test: the name is not known,
        // or it is somebody's and not the npub's. Either way nothing is asked.
        let (ended, out, err) = ran(&format!("terms {NPUB}"));
        assert_eq!(ended, FAILED, "{err}");
        assert!(
            out.is_empty()
                && (err.contains("is not known on this node") || err.contains("is not the address of that npub")),
            "{err}"
        );
        // Named by hand, another address is said to be unchecked.
        let (ended, _, err) = ran(&format!("terms {NPUB} --connect [::1]:1"));
        assert_eq!(ended, FAILED);
        assert!(err.contains("who answers there is not checked") && err.contains("no connection to"), "{err}");
    }

    #[test]
    fn an_order_is_read_before_it_is_shown_to_be_paid() {
        let soon = now() + 600;
        let order = |method: &str, request: &str, sat: u64| {
            json!({ "order": "o0123456789abcdef", "state": "waiting", "method": method, "sat": sat, "request": request,
                    "expires": soon, "offer": "1gb", "bytes": 1_000_000_000u64, "days": 30 })
        };
        assert_eq!(to_pay(&order("bolt11", "lnbc15u1p5qqqqq", 1500), Some(1500)).unwrap(), "o0123456789abcdef");
        assert_eq!(
            to_pay(&order("onchain", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1500), None).unwrap(),
            "o0123456789abcdef"
        );
        let refused = |order: Value, price: Option<u64>| match to_pay(&order, price) {
            Err(Stop::Failed(why)) => why,
            other => panic!("{other:?}"),
        };
        // An invoice for more than the price, or the price changed under way.
        assert!(
            refused(order("bolt11", "lnbc20m1p5qqqqq", 1500), Some(1500))
                .contains("asks for 2000000 sat, and the price is 1500 sat")
        );
        assert!(
            refused(order("bolt11", "lnbc20m1p5qqqqq", 2_000_000), Some(1500))
                .contains("another price than its terms name")
        );
        assert!(refused(order("bolt11", "lnbc1p5qqqqq", 1500), None).contains("no invoice for an amount"));
        assert!(refused(order("onchain", "bc1q\x1b[2J?amount=1", 1500), None).contains("no address"));
        assert!(refused(order("channel", "x", 1500), None).contains("a way this program does not know"));
        let mut ended = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        ended["expires"] = json!(now() - 1);
        assert!(refused(ended, None).contains("has ended already"));
        let mut odd = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        odd["order"] = json!("o1/../../x");
        assert!(refused(odd, None).contains("no name"));
        let mut paid = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        paid["state"] = json!("paid");
        assert!(refused(paid, None).contains("does not wait to be paid"));
    }

    #[test]
    fn a_token_is_one_word_that_begins_as_one_does() {
        let from = |said: &str| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let mut input = said.as_bytes();
            token_from(
                "-",
                &mut Around { out: &mut out, err: &mut err, input: &mut input, env: &|_| None, tty: false, pace: None },
            )
        };
        assert_eq!(from("cashuBabc\n").unwrap(), "cashuBabc");
        assert!(from("").is_err() && from("lnbc1").is_err() && from("cashuB abc").is_err());
        assert!(
            token_from(
                "/nonexistent/token",
                &mut Around {
                    out: &mut Vec::new(),
                    err: &mut Vec::new(),
                    input: &mut std::io::empty(),
                    env: &|_| None,
                    tty: false,
                    pace: None
                }
            )
            .is_err()
        );
    }

    /// Run `line` against a stand-in for an exit that answers with
    /// `answers`, one for each request. How it ended, what it wrote, what
    /// it said beside, and what the stand-in was asked.
    fn against(line: &str, answers: Vec<Vec<u8>>, state: &std::path::Path) -> (u8, String, String, Vec<String>) {
        let (exit, served) = http::testing::service(answers);
        let line = format!("{line} --connect {} --state {}", exit.at, state.display());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ended = run(
            &words(&line),
            &mut Around {
                out: &mut out,
                err: &mut err,
                input: &mut "cashuBtoken".as_bytes(),
                env: &|_| None,
                tty: true,
                pace: Some(Duration::from_millis(20)),
            },
        );
        // The stand-in ends once it has given its last answer, a moment
        // after the command has it. What it was never asked for, it is not
        // waited for.
        for _ in 0..100 {
            if served.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let asked = if served.is_finished() { served.join().unwrap() } else { Vec::new() };
        (ended, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap(), asked)
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fips-exit-pay-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn ok(body: &Value) -> Vec<u8> {
        http::testing::json("200 OK", &body.to_string())
    }

    fn terms_of(npub: &str, name: &str) -> Value {
        json!({ "version": 1, "exit": { "npub": npub, "address": "fd00::e", "name": name, "about": "", "country": "CH" },
                "price_msat_per_gb": 2_000_000, "packages": [{ "id": "1gb", "bytes": 1_000_000_000u64, "sat": 1500, "days": 30 }],
                "mints": ["https://mint.example"], "methods": ["cashu", "bolt11", "onchain"],
                "you": { "address": "fd99::2", "package": null } })
    }

    #[test]
    fn an_exit_is_not_taken_at_its_word_for_what_is_to_be_paid() {
        let state = scratch("word");
        let order = |request: &str, sat: u64| {
            json!({ "order": "o0123456789abcdef", "state": "waiting", "method": "bolt11", "offer": "1gb",
                    "bytes": 1_000_000_000u64, "days": 30, "sat": sat, "mint": "https://mint.example",
                    "request": request, "expires": now() + 600 })
        };
        let created = |body: &Value| http::testing::json("201 Created", &body.to_string());
        // An invoice for more than the price its own terms name: not shown.
        let dear = "lnbc20m1p5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let line = format!("buy {NPUB} 1gb --invoice --no-wait");
        let (ended, out, err, _) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&order(dear, 1500))], &state);
        assert_eq!(ended, FAILED, "{out}");
        assert!(err.contains("asks for 2000000 sat, and the price is 1500 sat: nothing is shown to be paid"), "{err}");
        assert!(!out.contains(dear) && !out.contains('█'), "{out}");
        // The price raised between its terms and its order: not shown either.
        let (ended, out, err, _) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&order(dear, 2_000_000))], &state);
        assert!(ended == FAILED && err.contains("another price than its terms name") && !out.contains(dear), "{err}");
        assert!(!state.exists(), "and nothing of it is kept");
        // Another way to pay than was asked.
        let mut other = order("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1500);
        other["method"] = json!("onchain");
        let (ended, _, err, _) = against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&other)], &state);
        assert!(ended == FAILED && err.contains("paid another way than was asked"), "{err}");
        // As it should be: shown, with a code, and written down.
        let right = "lnbc15u1p5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let (ended, out, err, asked) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&order(right, 1500))], &state);
        assert_eq!(ended, DONE, "{err}");
        assert!(
            out.contains(right)
                && out.contains('█')
                && out.contains("order o0123456789abcdef: pay this invoice of 1500 sat")
        );
        assert!(asked[1].ends_with("{\"method\":\"bolt11\",\"package\":\"1gb\"}"), "{}", asked[1]);
        assert_eq!(
            Kept::at(Some(state.to_str().unwrap()), &|_| None).last_order(NPUB).as_deref(),
            Some("o0123456789abcdef")
        );
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn who_answers_is_the_exit_asked_for_or_nothing_is_bought() {
        let state = scratch("who");
        // It says it is another exit; its terms are of another kind; it sells nothing.
        let other = "npub1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsg5nlgr";
        for (terms, why) in [
            (terms_of(other, "x"), "not the exit that was asked for"),
            (json!({ "version": 2, "exit": { "npub": NPUB } }), "of a kind this program does not know"),
        ] {
            let (ended, out, err, asked) = against(&format!("buy {NPUB} 1gb --token-file -"), vec![ok(&terms)], &state);
            assert!(ended == FAILED && err.contains(why) && out.is_empty(), "{err}");
            assert_eq!(asked.len(), 1, "the token was sent to nobody");
        }
        let mut closed = terms_of(NPUB, "x");
        closed["methods"] = json!(["bolt11"]);
        let (ended, _, err, asked) = against(&format!("buy {NPUB} 1gb --token-file -"), vec![ok(&closed)], &state);
        assert!(ended == FAILED && err.contains("does not take a Cashu token") && asked.len() == 1, "{err}");
        // What it says of itself is shown as plain words.
        let loud = terms_of(NPUB, "An exit\u{1b}[2J\u{202e}\nof mine");
        let (ended, out, _, _) = against(&format!("terms {NPUB}"), vec![ok(&loud)], &state);
        assert!(ended == DONE && out.starts_with("An exit[2J of mine, said to be in CH\n"), "{out:?}");
        assert!(!out.contains('\u{1b}') && out.contains("this node (fd99::2): in no package here"), "{out:?}");
    }

    #[test]
    fn a_token_whose_answer_is_lost_is_sent_again_and_is_the_same_purchase() {
        let state = scratch("again");
        let bought = json!({ "order": "o0123456789abcdef", "paid_sat": 1500, "fee_sat": 0, "added": false, "again": true,
                             "package": { "id": "p0123456789abcdef" }, "key": "ab".repeat(32) });
        let not_yet =
            http::testing::json("503 Service Unavailable", "{\"error\":\"Not known yet.\",\"code\":\"not-yet\"}");
        // An answer that is cut off, one that says not yet, and then the purchase.
        let answers =
            vec![ok(&terms_of(NPUB, "x")), b"HTTP/1.1 200 OK\r\ncontent-le".to_vec(), not_yet.clone(), ok(&bought)];
        let line = format!("buy {NPUB} 1gb --token-file -");
        let (ended, out, err, asked) = against(&line, answers, &state);
        assert_eq!(ended, DONE, "{err}");
        assert!(
            out.contains("paid: 1500 sat arrived (this token bought it before)") && out.contains("its key: abab"),
            "{out}"
        );
        assert_eq!(asked.len(), 4);
        assert!(asked[1..].iter().all(|request| request.contains("\"token\":\"cashuBtoken\"")), "the same, each time");
        // Never decided: said so, to be run again, and it ends as not known.
        let answers = [vec![ok(&terms_of(NPUB, "x"))], vec![not_yet; TRIES]].concat();
        let (ended, out, err, asked) = against(&line, answers, &state);
        assert_eq!((ended, asked.len()), (WAITING, 1 + TRIES), "{out}");
        assert!(err.contains("Run the same again, with the same token") && err.contains("not-yet"), "{err}");
        // Refused outright: not sent again.
        let used = http::testing::json("409 Conflict", "{\"error\":\"This token was spent.\",\"code\":\"used\"}");
        let (ended, _, err, asked) = against(&line, vec![ok(&terms_of(NPUB, "x")), used], &state);
        assert!(ended == FAILED && asked.len() == 2 && err.contains("This token was spent. (used)"), "{err}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn a_price_and_a_refusal_for_a_person() {
        assert_eq!(
            (sat_of(2_000_000), sat_of(1500), sat_of(0)),
            ("2000 sat".into(), "1.500 sat".into(), "0 sat".into())
        );
        let answer = |body: Value| Answer { status: 409, body };
        assert_eq!(
            refusal(&answer(json!({ "error": "This token\x1b[2J was spent.", "code": "used" }))),
            "This token[2J was spent. (used)"
        );
        assert_eq!(refusal(&answer(json!({ "error": "no package has that key" }))), "no package has that key");
        assert_eq!(refusal(&answer(json!({}))), "the exit refused, with 409");
    }
}
