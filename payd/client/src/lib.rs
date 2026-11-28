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
/// An order is not waited for without end: not while the exit has not
/// answered this many times in a row, and not longer than this after the
/// order's own end, in seconds. The order stays, and `order` asks again.
const SILENT: u32 = 60;
const LATE: u64 = 3600;
/// The longest token an exit reads.
const TOKEN: usize = 24 * 1024;

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
  --package <id>      the kept key of this package, instead of the one last bought or used here
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
    /// What a name and a port are on this node: [`resolve`].
    pub resolve: &'a dyn Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
    /// Whether what is written is seen by a person at a terminal.
    pub tty: bool,
    /// How long to wait between two looks, for a test; else as the kind of
    /// order has it.
    pub pace: Option<Duration>,
}

/// What `name` and `port` are, as anything on this node resolves a name:
/// on a node that runs fips, a name that ends in `.fips` is fips's to say.
pub fn resolve(name: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (name, port).to_socket_addrs().map(Iterator::collect)
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
const FLAGS: [(&str, bool); 15] = [
    ("--port", true),
    ("--connect", true),
    ("--state", true),
    ("--key-file", true),
    ("--package", true),
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

    /// Is this asked as its command is to be asked? Said before anything
    /// is looked up or anyone is asked.
    fn rightly(&self) -> Result<(), Stop> {
        let usage = |why: &str| Err(Stop::Usage(why.to_string()));
        let keyed = ["--key-file", "--package"];
        match self.words[0].as_str() {
            "terms" | "leave" => self.takes(&[], 0, 0)?,
            "buy" => {
                let flags = [
                    "--token-file",
                    "--invoice",
                    "--onchain",
                    "--add",
                    "--mint",
                    "--no-wait",
                    "--key-file",
                    "--package",
                ];
                self.takes(&flags, 1, 1)?;
                let ways = ["--token-file", "--invoice", "--onchain"].into_iter().filter(|way| self.has(way)).count();
                if ways != 1 {
                    return usage("buy: paid how? One of --token-file <file>, --invoice, --onchain");
                }
                if self.has("--token-file") && (self.has("--mint") || self.has("--no-wait")) {
                    return usage("buy: --mint and --no-wait are for an invoice or an address: a token names its mint");
                }
                if keyed.iter().any(|flag| self.has(flag)) && !self.has("--add") {
                    return usage("buy: a key is for adding to its package: say --add as well");
                }
            }
            "order" => self.takes(&["--wait"], 0, 1)?,
            "key" => {
                self.takes(&["--new", "--package"], 0, 1)?;
                if self.words.len() > 2 && !self.has("--new") {
                    return usage("key: an order is named with --new, for a new key of what it bought");
                }
                if self.has("--new") && self.has("--package") {
                    return usage("key: a new key is asked for by an order, not by a package");
                }
            }
            "package" | "join" => self.takes(&keyed, 0, 0)?,
            "remove" => {
                self.takes(&keyed, 1, 32)?;
                if let Some(odd) = self.words[2..].iter().find(|member| identity::client(member).is_none()) {
                    return Err(Stop::Usage(format!("{} is neither an npub nor a fips address", plain(odd, 80))));
                }
            }
            other => return Err(Stop::Usage(format!("{}: no such command", plain(other, 40)))),
        }
        if self.has("--key-file") && self.has("--package") {
            return usage("--key-file and --package: one or the other");
        }
        if self.value("--package").is_some_and(|id| !show::is_package_id(id)) {
            return usage("--package: a package's name, p and 16 hex digits");
        }
        // An order that is named is named as the service names one.
        let order = match self.words[0].as_str() {
            "order" | "key" => self.words.get(2),
            _ => None,
        };
        match order {
            Some(id) if !show::is_order_id(id) => Err(Stop::Usage(format!("{} is no order's name", plain(id, 40)))),
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
    let npub = asked.words.get(1).cloned();
    // Asked wrongly, it is said so before any name is looked up.
    if asked.words.is_empty() {
        return Err(Stop::Usage("which command?".into()));
    }
    asked.rightly()?;
    let npub = npub.ok_or_else(|| Stop::Usage(format!("{name} of which exit? Its npub is missing")))?;
    let exit = reach(&npub, &asked, around)?;
    let kept = Kept::at(asked.value("--state"), around.env);
    let run = Run { exit, asked, kept };
    match name.as_str() {
        "terms" => run.terms(around),
        "buy" => run.buy(around),
        "order" => run.order(around),
        "key" => run.key(around),
        "package" => run.with_key(around, "/v1/package", json!({})),
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
    let named = match asked.value("--connect") {
        Some(named) => Some(
            named
                .parse::<SocketAddr>()
                .map_err(|_| Stop::Usage("--connect: an address and a port, as in [fd00::1]:5170".into()))?,
        ),
        None => None,
    };
    // The service answers to its name with its own port and to no other:
    // the port that was named; or the one connected to; or the usual one.
    let port = match asked.value("--port") {
        Some(port) => {
            port.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| Stop::Usage("--port: a port".into()))?
        }
        None => named.map_or(PORT, |at| at.port()),
    };
    let at = match named {
        Some(at) => {
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
            let found = (around.resolve)(&name, port).map_err(|e| {
                Stop::Failed(format!(
                    "{name} is not known on this node: is fips running here, and asked for names that end in .fips? ({e})"
                ))
            })?;
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

/// The price of the package `id` in an exit's terms, in sat.
fn price_in(terms: &Value, id: &str) -> Option<u64> {
    let offers = terms["packages"].as_array()?;
    offers.iter().find(|offer| offer["id"].as_str() == Some(id))?["sat"].as_u64().filter(|sat| *sat > 0)
}

impl Run {
    fn json(&self) -> bool {
        self.asked.has("--json")
    }

    fn pace(&self, around: &Around, usual: Duration) -> Duration {
        around.pace.unwrap_or(usual)
    }

    /// The answer as it is, for a program: on one line, in plain ASCII.
    fn line(&self, around: &mut Around, body: &Value) {
        say!(around, "{}", show::ascii(body));
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

    /// The key to use, and whether it was given for this run: the one in
    /// the file that was named, the one in the environment, the one kept
    /// for the package that was named, or the one of the package last
    /// bought or used here.
    fn key_to_use(&self, around: &Around) -> Result<(String, bool), Stop> {
        if let Some(package) = self.asked.value("--package") {
            let key = self.kept.key_of(&self.exit.npub, package);
            return key
                .map(|key| (key, false))
                .ok_or_else(|| Stop::Failed(format!("no key is kept for package {package}")));
        }
        let given = match self.asked.value("--key-file") {
            Some(file) => {
                let said =
                    std::fs::read_to_string(file).map_err(|e| Stop::Failed(format!("{}: {e}", plain(file, 200))))?;
                Some(said.lines().next().unwrap_or_default().trim().to_string())
            }
            None => (around.env)("FIPS_EXIT_KEY").map(|key| key.trim().to_string()),
        };
        match given {
            Some(key) if show::is_key(&key) => Ok((key.to_ascii_lowercase(), true)),
            Some(_) => Err(Stop::Failed("what was given as the key is no key: 64 hex digits".into())),
            None => self.kept.key(&self.exit.npub).map(|(_, key)| (key, false)).ok_or_else(|| {
                Stop::Failed(
                    "no key is kept for this exit: name a file that holds one with --key-file, or buy a package".into(),
                )
            }),
        }
    }

    /// Keep `key` as the key of `package`, which is the one used here from
    /// now on. Said beside what is written: where it is kept, or that it is
    /// not; and which package was used here before, whose key stays.
    fn kept_key(&self, around: &mut Around, package: &str, key: &str) {
        match self.kept.keep_key(&self.exit.npub, package, key) {
            Ok((file, before)) => {
                if !self.json() {
                    say!(around, "  kept in {}", file.display());
                }
                if let Some(before) = before {
                    note!(
                        around,
                        "fips-exit-pay: package {package} is the one used here from now on. The key of {before} is kept \
                         still: --package {before}"
                    );
                }
            }
            Err(why) => note!(around, "fips-exit-pay: THE KEY IS NOT KEPT, write it down: {why}"),
        }
    }

    /// A key that was just had, for a person: said, since whoever bought
    /// has it, and kept.
    fn key_shown(&self, around: &mut Around, package: &str, key: &str) {
        if !self.json() {
            say!(around, "its key: {key}");
            say!(around, "  whoever has the key sees who is in the package, takes members out of it, and adds to it");
        }
        self.kept_key(around, package, key);
    }

    fn buy(&self, around: &mut Around) -> Result<u8, Stop> {
        let word = match () {
            () if self.asked.has("--token-file") => "cashu",
            () if self.asked.has("--invoice") => "bolt11",
            () => "onchain",
        };
        // The token, before anything is asked of anyone.
        let token = match self.asked.value("--token-file") {
            Some(file) => Some(token_from(file, around)?),
            None => None,
        };
        let key = if self.asked.has("--add") { Some(self.key_to_use(around)?.0) } else { None };
        // What the exit itself says it sells, and for how much.
        let terms = self.terms_of()?;
        let offers = terms["packages"].as_array().cloned().unwrap_or_default();
        let wanted = &self.asked.words[2];
        let offer = offers.iter().find(|offer| offer["id"].as_str() == Some(wanted)).ok_or_else(|| {
            let there: Vec<String> = offers.iter().take(16).map(|offer| text(offer, "id", 64)).collect();
            Stop::Failed(format!("the exit sells no package {}: it sells {}", plain(wanted, 64), there.join(", ")))
        })?;
        let price = price_in(&terms, wanted).ok_or_else(|| Stop::Failed("the exit names no price".into()))?;
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
                // Turned away unread: it would be again.
                Err(Failed::Refused(said)) => return Err(Stop::Failed(said)),
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
        // The key of a package this token made: given with the answer.
        if let Some(key) = bought["key"].as_str().filter(|key| show::is_key(key) && show::is_package_id(&id)) {
            self.key_shown(around, &id, key);
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
                Err(Failed::Refused(said)) => return Err(Stop::Failed(said)),
                // Asked again within a minute, it is the same order.
                Err(failed) => why = failed.said().to_string(),
            }
        }
        let order = made.ok_or_else(|| Stop::Failed(format!("the exit gave no order: {why}")))?;
        let id = to_pay(&order, price)?;
        let method = order["method"].as_str().unwrap_or_default().to_string();
        if method != asked["method"].as_str().unwrap_or_default() {
            return Err(Stop::Failed(
                "the exit gave an order paid another way than was asked: nothing is shown".into(),
            ));
        }
        // Written down before it is shown, with its price: an order is
        // found again by its name alone.
        let made = (method.as_str(), asked["package"].as_str().unwrap_or_default(), price);
        if let Err(why) = self.kept.keep_order(&self.exit.npub, &id, made, now()) {
            note!(around, "fips-exit-pay: the order is not written down ({why}): its name is {id}");
        }
        self.shown_to_pay(around, &order);
        if self.asked.has("--no-wait") {
            if !self.json() {
                say!(around, "what became of it: fips-exit-pay order {}", self.exit.npub);
            }
            return Ok(DONE);
        }
        self.wait(around, &id, &method, order["expires"].as_u64())
    }

    /// Show what is to be paid for `order`, which [`to_pay`] has read.
    fn shown_to_pay(&self, around: &mut Around, order: &Value) {
        let ends = order["expires"].as_u64().unwrap_or(0);
        // The exit says it can be paid, and this node's clock that it has
        // ended: one of the two clocks is wrong, and which is not known.
        if ends <= now() {
            note!(
                around,
                "fips-exit-pay: by this node's clock the order has ended already ({}): its clock, or the exit's, is wrong",
                date(ends)
            );
        }
        if self.json() {
            return self.line(around, order);
        }
        let (id, sat) = (text(order, "order", 20), order["sat"].as_u64().unwrap_or(0));
        let request = order["request"].as_str().unwrap_or_default();
        let ends = date(ends);
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

    /// Ask what became of order `id`, which ends at `ends`, until it is
    /// decided; and not for ever: not of an exit that has stopped
    /// answering, and not long after the order's own end.
    fn wait(&self, around: &mut Around, id: &str, method: &str, ends: Option<u64>) -> Result<u8, Stop> {
        let pace = self.pace(around, if method == "onchain" { CHAIN_PACE } else { PACE });
        if !self.json() {
            say!(around, "waiting for the payment (stop with ctrl-c: the order stays, and `order` asks again) ...");
        }
        let again = format!("the order stays, and `fips-exit-pay order {} {id}` asks again", self.exit.npub);
        let (mut silent, mut ended, mut ends) = (0u32, false, ends);
        loop {
            std::thread::sleep(pace);
            if ends.is_some_and(|ends| now() > ends.saturating_add(LATE)) {
                return Err(Stop::Waiting(format!("the order is not decided long after its end: {again}")));
            }
            let answer = match ask(&self.exit, "GET", &format!("/v1/orders/{id}"), None, QUESTION) {
                Ok(answer) => answer,
                Err(Failed::Refused(said)) => return Err(Stop::Failed(said)),
                // The exit is away for a moment: the order is not.
                Err(failed) => {
                    silent += 1;
                    if silent == 3 {
                        note!(around, "fips-exit-pay: the exit does not answer ({}): still asking", failed.said());
                    }
                    if silent >= SILENT {
                        return Err(Stop::Waiting(format!(
                            "the exit has stopped answering ({}): {again}",
                            failed.said()
                        )));
                    }
                    continue;
                }
            };
            silent = 0;
            if answer.status != 200 {
                return Err(Stop::Failed(refusal(&answer)));
            }
            ends = answer.body["expires"].as_u64().or(ends);
            match answer.body["state"].as_str().unwrap_or_default() {
                "paid" => return self.paid(around, &answer.body, true),
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

    /// An order is paid: say so. Where this run `waited` for the payment
    /// and the order made a package of its own, have that package's key:
    /// nobody was shown it. Asked about later, an order's key is not asked
    /// for by itself: a key that is asked for takes the place of the one
    /// before, which somebody may hold.
    fn paid(&self, around: &mut Around, order: &Value, waited: bool) -> Result<u8, Stop> {
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
        if added || !show::is_order_id(&id) || !show::is_package_id(&package) {
            return Ok(DONE);
        }
        let have = self.kept.key_of(&self.exit.npub, &package).is_some();
        match (have, waited) {
            (true, _) => {}
            (false, true) => match self.new_key(&id) {
                Ok(given) => self.key_given(around, &given),
                Err(Stop::Failed(why)) | Err(Stop::Waiting(why)) | Err(Stop::Usage(why)) => {
                    note!(around, "fips-exit-pay: its key was not had ({why}): ask with `key --new`");
                }
            },
            (false, false) => note!(
                around,
                "fips-exit-pay: no key of package {package} is kept here. `fips-exit-pay key {} --new {id}` asks the exit \
                 for one: any key it gave before opens nothing then",
                self.exit.npub
            ),
        }
        Ok(DONE)
    }

    /// Ask the exit for a new key of the package order `id` made.
    fn new_key(&self, id: &str) -> Result<Value, Stop> {
        let answer = ask(&self.exit, "POST", &format!("/v1/orders/{id}/key"), Some(&json!({})), QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let package = answer.body["package"]["id"].as_str().is_some_and(show::is_package_id);
        if !package || !answer.body["key"].as_str().is_some_and(show::is_key) {
            return Err(Stop::Failed("the exit gave what is no key of a package".into()));
        }
        Ok(answer.body)
    }

    fn key_given(&self, around: &mut Around, given: &Value) {
        let (package, key) = (text(&given["package"], "id", 20), given["key"].as_str().unwrap_or_default());
        if self.json() {
            self.line(around, given);
        }
        self.key_shown(around, &package, key);
    }

    /// The order that is meant: the one named, or the last one made here.
    fn order_meant(&self) -> Result<String, Stop> {
        match self.asked.words.get(2) {
            Some(id) => Ok(id.clone()),
            None => self
                .kept
                .last_order(&self.exit.npub)
                .ok_or_else(|| Stop::Failed("no order made at this exit is kept here: name one".into())),
        }
    }

    fn order(&self, around: &mut Around) -> Result<u8, Stop> {
        let id = self.order_meant()?;
        // Who answers, and what it sells for: as before anything is bought.
        let terms = self.terms_of()?;
        let answer = ask(&self.exit, "GET", &format!("/v1/orders/{id}"), None, QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let order = answer.body;
        let method = order["method"].as_str().unwrap_or_default().to_string();
        let ends = order["expires"].as_u64();
        match order["state"].as_str().unwrap_or_default() {
            "paid" => self.paid(around, &order, false),
            "expired" => Err(Stop::Failed(format!("order {id} ended, and nothing was paid for it"))),
            "waiting" => {
                // Shown again as something to pay only if it is what was
                // ordered: at the price written down when it was made, or
                // else the one the exit's terms name for it now.
                let made = self.kept.order(&self.exit.npub, &id).and_then(|made| made["sat"].as_u64());
                let price = made.or_else(|| price_in(&terms, order["offer"].as_str().unwrap_or_default())).ok_or_else(
                    || {
                        Stop::Failed(
                            "the exit's terms name no price for what this order buys: nothing is shown to be paid"
                                .into(),
                        )
                    },
                )?;
                to_pay(&order, price)?;
                self.shown_to_pay(around, &order);
                match self.asked.has("--wait") {
                    true => self.wait(around, &id, &method, ends),
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
                    true => self.wait(around, &id, &method, ends),
                    false => Ok(WAITING),
                }
            }
        }
    }

    fn key(&self, around: &mut Around) -> Result<u8, Stop> {
        if self.asked.has("--new") {
            let id = self.order_meant()?;
            let given = self.new_key(&id)?;
            self.key_given(around, &given);
            return Ok(DONE);
        }
        let kept = match self.asked.value("--package") {
            Some(package) => self.kept.key_of(&self.exit.npub, package).map(|key| (package.to_string(), key)),
            None => self.kept.key(&self.exit.npub),
        };
        let (package, key) = kept.ok_or_else(|| {
            Stop::Failed(
                "no such key is kept for this exit. `key --new` asks the exit for one, for what an order bought".into(),
            )
        })?;
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
        let (key, given) = self.key_to_use(around)?;
        let mut body = more;
        body["key"] = json!(key);
        let answer = ask(&self.exit, "POST", path, Some(&body), QUESTION)?;
        if answer.status != 200 {
            return Err(Stop::Failed(refusal(&answer)));
        }
        let id = text(&answer.body, "id", 20);
        if self.json() {
            self.line(around, &answer.body);
        } else {
            say!(around, "package {id}");
            self.package_shown(around, &answer.body);
        }
        // A key that was given, and opens a package: kept, as that package's.
        if given && show::is_package_id(&id) && self.kept.key_of(&self.exit.npub, &id).as_deref() != Some(key.as_str())
        {
            self.kept_key(around, &id, &key);
        }
        Ok(DONE)
    }

    fn join(&self, around: &mut Around) -> Result<u8, Stop> {
        // A node is put in by itself, under the address the exit sees it by.
        let terms = self.terms_of()?;
        let this = terms["you"]["address"]
            .as_str()
            .ok_or_else(|| Stop::Failed("the exit does not say who this node is".into()))?;
        self.with_key(around, "/v1/package/members", json!({ "add": [this] }))
    }

    fn remove(&self, around: &mut Around) -> Result<u8, Stop> {
        let members: Vec<&String> = self.asked.words[2..].iter().collect();
        self.with_key(around, "/v1/package/members", json!({ "remove": members }))
    }

    fn leave(&self, around: &mut Around) -> Result<u8, Stop> {
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
/// a wallet writes it, and no longer than an exit reads.
fn token_from(file: &str, around: &mut Around) -> Result<String, Stop> {
    let mut said = String::new();
    let most = TOKEN as u64 + 1024;
    let read = match file {
        "-" => around.input.take(most).read_to_string(&mut said),
        file => std::fs::File::open(file).and_then(|file| file.take(most).read_to_string(&mut said)),
    };
    read.map_err(|e| Stop::Failed(format!("the token could not be read from {}: {e}", plain(file, 200))))?;
    let token = said.trim();
    if !token.to_ascii_lowercase().starts_with("cashu") || token.contains(char::is_whitespace) {
        return Err(Stop::Failed("what was given is no Cashu token: one word that begins with cashu".into()));
    }
    if token.len() > TOKEN {
        return Err(Stop::Failed(format!(
            "the token is longer than an exit reads ({TOKEN} characters): have a wallet make one of fewer proofs"
        )));
    }
    Ok(token.to_string())
}

/// Read an order that waits to be paid, before it is shown as something to
/// pay: its name, that it is for `price`, which the exit's terms named, and
/// that what it asks to be paid is that. An exit is not taken at its word
/// for more.
fn to_pay(order: &Value, price: u64) -> Result<String, Stop> {
    let nothing = |why: &str| Stop::Failed(format!("{why}: nothing is shown to be paid"));
    let id = order["order"]
        .as_str()
        .filter(|id| show::is_order_id(id))
        .ok_or_else(|| nothing("the exit gave an order with no name"))?;
    let sat = order["sat"].as_u64().filter(|sat| *sat > 0).ok_or_else(|| nothing("the exit's order names no price"))?;
    if price != sat {
        return Err(nothing(&format!("the exit's order is for {sat} sat, and what was ordered costs {price} sat")));
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
    if order["expires"].as_u64().is_none() {
        return Err(nothing("the exit's order has no end"));
    }
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// No name is known: nothing in a test asks a resolver.
    fn unknown(_: &str, _: u16) -> std::io::Result<Vec<SocketAddr>> {
        Err(std::io::Error::other("no such name"))
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
                resolve: &unknown,
                tty: false,
                pace: None,
            },
        );
        (ended, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// An npub: a key of zeros, with its checksum.
    const NPUB: &str = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme";

    #[test]
    fn what_is_asked_wrongly_is_said_before_any_name_is_looked_up() {
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
            (&format!("terms {NPUB} --port 0"), "--port: a port"),
            (&format!("terms {NPUB} --connect localhost"), "--connect: an address and a port"),
            (&format!("terms {NPUB} --json --json"), "--json is said twice"),
            (&format!("terms {NPUB} extra"), "terms takes no extra"),
            (&format!("terms {NPUB} --invoice"), "terms takes no --invoice"),
            (&format!("buy {NPUB} --invoice"), "buy needs more than that"),
            (&format!("buy {NPUB} 1gb"), "paid how?"),
            (&format!("buy {NPUB} 1gb --invoice --onchain"), "paid how?"),
            (&format!("buy {NPUB} 1gb --token-file t --mint https://m.example"), "a token names its mint"),
            (&format!("buy {NPUB} 1gb --invoice --key-file k"), "say --add as well"),
            (&format!("buy {NPUB} 1gb --invoice --add --key-file k --package p0123456789abcdef"), "one or the other"),
            (&format!("package {NPUB} --package ../x"), "--package: a package's name"),
            (&format!("order {NPUB} o123"), "is no order's name"),
            (&format!("order {NPUB} ../../v1/terms"), "is no order's name"),
            (&format!("key {NPUB} o0123456789abcdef"), "an order is named with --new"),
            (&format!("key {NPUB} --new --package p0123456789abcdef"), "by an order, not by a package"),
            (&format!("remove {NPUB}"), "remove needs more than that"),
            (&format!("remove {NPUB} somebody"), "neither an npub nor a fips address"),
        ] {
            // A resolver that is asked says so: none of these gets that far.
            let asked = Cell::new(false);
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let ended = run(
                &words(line),
                &mut Around {
                    out: &mut out,
                    err: &mut err,
                    input: &mut std::io::empty(),
                    env: &|_| None,
                    resolve: &|name, port| {
                        asked.set(true);
                        unknown(name, port)
                    },
                    tty: false,
                    pace: None,
                },
            );
            let err = String::from_utf8(err).unwrap();
            assert_eq!((ended, asked.get()), (USAGE, false), "{line}: {err}");
            assert!(err.contains(why) && out.is_empty(), "{line}: {err}");
        }
        // What is said of it is plain text, whatever was typed.
        let (_, _, err) = ran("terms npub1\x1b[2Jx");
        assert!(!err.contains('\x1b'), "{err:?}");
    }

    #[test]
    fn a_name_that_is_not_the_npubs_address_is_not_asked() {
        let with = |resolve: &dyn Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>, line: &str| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let ended = run(
                &words(line),
                &mut Around {
                    out: &mut out,
                    err: &mut err,
                    input: &mut std::io::empty(),
                    env: &|_| None,
                    resolve,
                    tty: false,
                    pace: None,
                },
            );
            (ended, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
        };
        // The name is not known here.
        let (ended, out, err) = with(&unknown, &format!("terms {NPUB}"));
        assert!(ended == FAILED && out.is_empty() && err.contains("is not known on this node"), "{err}");
        // It is said to be somebody's, and not the npub's: nobody is asked.
        // (Somebody listens there, and would answer.)
        let (elsewhere, served) = http::testing::service(vec![b"HTTP/1.1 200 OK\r\n\r\n".to_vec()]);
        let at = elsewhere.at;
        let (ended, _, err) = with(&move |_, _| Ok(vec![at]), &format!("terms {NPUB}"));
        assert!(
            ended == FAILED && err.contains("which is not the address of that npub") && err.contains("not asked"),
            "{err}"
        );
        assert!(!served.is_finished(), "nobody connected there");
        // The name asked for is the npub's, with the port that was named.
        let asked = Cell::new((String::new(), 0));
        let (_, _, err) = with(
            &|name, port| {
                asked.set((name.to_string(), port));
                unknown(name, port)
            },
            &format!("terms {} --port 6000", NPUB.to_uppercase()),
        );
        assert_eq!(asked.take(), (format!("{NPUB}.fips"), 6000), "{err}");
        // Named by hand, another address is said to be unchecked.
        let (ended, _, err) = with(&unknown, &format!("terms {NPUB} --connect [::1]:1"));
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
        assert_eq!(to_pay(&order("bolt11", "lnbc15u1p5qqqqq", 1500), 1500).unwrap(), "o0123456789abcdef");
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert_eq!(to_pay(&order("onchain", address, 1500), 1500).unwrap(), "o0123456789abcdef");
        let refused = |order: Value| match to_pay(&order, 1500) {
            Err(Stop::Failed(why)) => why,
            other => panic!("{other:?}"),
        };
        // An invoice for more than the price, or the price changed under way.
        assert!(
            refused(order("bolt11", "lnbc20m1p5qqqqq", 1500))
                .contains("asks for 2000000 sat, and the price is 1500 sat")
        );
        assert!(
            refused(order("bolt11", "lnbc20m1p5qqqqq", 2_000_000))
                .contains("is for 2000000 sat, and what was ordered costs 1500 sat")
        );
        assert!(refused(order("bolt11", "lnbc1p5qqqqq", 1500)).contains("no invoice for an amount"));
        assert!(refused(order("onchain", "bc1q\x1b[2J?amount=1", 1500)).contains("no address"));
        assert!(refused(order("channel", "x", 1500)).contains("a way this program does not know"));
        let mut endless = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        endless.as_object_mut().unwrap().remove("expires");
        assert!(refused(endless).contains("has no end"));
        let mut odd = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        odd["order"] = json!("o1/../../x");
        assert!(refused(odd).contains("no name"));
        let mut paid = order("bolt11", "lnbc15u1p5qqqqq", 1500);
        paid["state"] = json!("paid");
        assert!(refused(paid).contains("does not wait to be paid"));
    }

    #[test]
    fn a_token_is_one_word_that_begins_as_one_does_and_no_longer_than_an_exit_reads() {
        let from = |file: &str, said: &str| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let mut input = said.as_bytes();
            token_from(
                file,
                &mut Around {
                    out: &mut out,
                    err: &mut err,
                    input: &mut input,
                    env: &|_| None,
                    resolve: &unknown,
                    tty: false,
                    pace: None,
                },
            )
        };
        assert_eq!(from("-", "cashuBabc\n").unwrap(), "cashuBabc");
        assert!(from("-", "").is_err() && from("-", "lnbc1").is_err() && from("-", "cashuB abc").is_err());
        assert!(from("/nonexistent/token", "").is_err());
        assert_eq!(from("-", &format!("cashuB{}", "a".repeat(TOKEN - 6))).unwrap().len(), TOKEN);
        let Err(Stop::Failed(why)) = from("-", &format!("cashuB{}", "a".repeat(TOKEN))) else { panic!("a token") };
        assert!(why.contains("longer than an exit reads"), "{why}");
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
                resolve: &unknown,
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

    const ORDER: &str = "o0123456789abcdef";
    const PACKAGE: &str = "p0123456789abcdef";

    fn waiting(request: &str, sat: u64) -> Value {
        json!({ "order": ORDER, "state": "waiting", "method": "bolt11", "offer": "1gb",
                "bytes": 1_000_000_000u64, "days": 30, "sat": sat, "mint": "https://mint.example",
                "request": request, "expires": now() + 600 })
    }

    fn paid_order() -> Value {
        json!({ "order": ORDER, "state": "paid", "method": "bolt11", "offer": "1gb", "bytes": 1_000_000_000u64, "days": 30,
                "sat": 1500, "mint": "https://mint.example", "paid_sat": 1500, "added": false, "package": { "id": PACKAGE } })
    }

    const RIGHT: &str = "lnbc15u1p5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    const DEAR: &str = "lnbc1500u1p5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    #[test]
    fn an_exit_is_not_taken_at_its_word_for_what_is_to_be_paid() {
        let state = scratch("word");
        let created = |body: &Value| http::testing::json("201 Created", &body.to_string());
        // An invoice for more than the price its own terms name: not shown.
        let line = format!("buy {NPUB} 1gb --invoice --no-wait");
        let (ended, out, err, _) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&waiting(DEAR, 1500))], &state);
        assert_eq!(ended, FAILED, "{out}");
        assert!(err.contains("asks for 150000 sat, and the price is 1500 sat: nothing is shown to be paid"), "{err}");
        assert!(!out.contains(DEAR) && !out.contains('█'), "{out}");
        // The price raised between its terms and its order: not shown either.
        let (ended, out, err, _) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&waiting(DEAR, 150_000))], &state);
        assert!(ended == FAILED && err.contains("is for 150000 sat, and what was ordered costs 1500 sat"), "{err}");
        assert!(!out.contains(DEAR) && !state.exists(), "and nothing of it is kept: {out}");
        // Another way to pay than was asked.
        let mut other = waiting("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 1500);
        other["method"] = json!("onchain");
        let (ended, _, err, _) = against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&other)], &state);
        assert!(ended == FAILED && err.contains("paid another way than was asked"), "{err}");
        // As it should be: shown, with a code, and written down with its price.
        let (ended, out, err, asked) =
            against(&line, vec![ok(&terms_of(NPUB, "An exit")), created(&waiting(RIGHT, 1500))], &state);
        assert_eq!(ended, DONE, "{err}");
        assert!(
            out.contains(RIGHT)
                && out.contains('█')
                && out.contains(&format!("order {ORDER}: pay this invoice of 1500 sat"))
        );
        assert!(asked[1].ends_with("{\"method\":\"bolt11\",\"package\":\"1gb\"}"), "{}", asked[1]);
        // The service is asked by its name with the port it was reached at.
        let port = asked[0].split("Host: ").nth(1).unwrap().split("\r\n").next().unwrap().to_string();
        assert!(port.starts_with(&format!("{NPUB}.fips:")) && !port.ends_with(":5170"), "{port}");
        let kept = Kept::at(Some(state.to_str().unwrap()), &|_| None);
        assert_eq!(kept.last_order(NPUB).as_deref(), Some(ORDER));
        assert_eq!(kept.order(NPUB, ORDER).unwrap()["sat"], 1500);
        // Asked about later, the same order with another price and an
        // invoice to match is not what was ordered: not shown.
        let line = format!("order {NPUB}");
        let (ended, out, err, asked) =
            against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&waiting(DEAR, 150_000))], &state);
        assert_eq!((ended, asked.len()), (FAILED, 2), "{out}");
        assert!(err.contains("is for 150000 sat, and what was ordered costs 1500 sat") && !out.contains(DEAR), "{err}");
        // An order this node did not write down is held to the exit's terms.
        let other_state = scratch("word-other");
        let line = format!("order {NPUB} {ORDER}");
        let (ended, out, _, _) =
            against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&waiting(DEAR, 150_000))], &other_state);
        assert!(ended == FAILED && !out.contains(DEAR), "{out}");
        let (ended, out, _, _) =
            against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&waiting(RIGHT, 1500))], &other_state);
        assert!(ended == WAITING && out.contains(RIGHT), "{out}");
        // And whoever answers has to be the exit, for an order too.
        let (ended, _, err, asked) = against(&line, vec![ok(&terms_of("npub1other", "x"))], &other_state);
        assert!(ended == FAILED && asked.len() == 1 && err.contains("not the exit that was asked for"), "{err}");
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
        let loud = terms_of(NPUB, "An exit\u{1b}[2J\u{9b}2J\u{202e}\nof mine");
        let (ended, out, _, _) = against(&format!("terms {NPUB}"), vec![ok(&loud)], &state);
        assert!(ended == DONE && out.starts_with("An exit[2J2J of mine, said to be in CH\n"), "{out:?}");
        assert!(!out.contains('\u{1b}') && out.contains("this node (fd99::2): in no package here"), "{out:?}");
        // And for a program as JSON that is plain ASCII, and the same value.
        let (ended, out, _, _) = against(&format!("terms {NPUB} --json"), vec![ok(&loud)], &state);
        assert!(ended == DONE && out.bytes().all(|b| b == b'\n' || (b' '..=b'~').contains(&b)), "{out:?}");
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), loud);
    }

    #[test]
    fn a_token_whose_answer_is_lost_is_sent_again_and_is_the_same_purchase() {
        let state = scratch("again");
        let bought = json!({ "order": ORDER, "paid_sat": 1500, "fee_sat": 0, "added": false, "again": true,
                             "package": { "id": PACKAGE }, "key": "ab".repeat(32) });
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
        // Refused outright, in the exit's words or unread: not sent again.
        let used = http::testing::json("409 Conflict", "{\"error\":\"This token was spent.\",\"code\":\"used\"}");
        let (ended, _, err, asked) = against(&line, vec![ok(&terms_of(NPUB, "x")), used], &state);
        assert!(ended == FAILED && asked.len() == 2 && err.contains("This token was spent. (used)"), "{err}");
        let unread = b"HTTP/1.1 413 Payload Too Large\r\ncontent-type: text/plain\r\n\r\ntoo long\n".to_vec();
        let (ended, _, err, asked) = against(&line, vec![ok(&terms_of(NPUB, "x")), unread], &state);
        assert!(ended == FAILED && asked.len() == 2 && err.contains("refused, with 413"), "{err}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn asking_about_an_order_replaces_nobodys_key() {
        let state = scratch("keys");
        let kept = Kept::at(Some(state.to_str().unwrap()), &|_| None);
        // Paid when it is asked about, with no key of its package kept
        // here: said, and no key is asked for. One may be held elsewhere.
        let line = format!("order {NPUB} {ORDER}");
        let (ended, out, err, asked) = against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&paid_order())], &state);
        assert_eq!((ended, asked.len()), (DONE, 2), "{err}");
        assert!(out.contains("paid: 1500 sat arrived") && !out.contains("its key"), "{out}");
        assert!(err.contains(&format!("key {NPUB} --new {ORDER}")) && err.contains("opens nothing then"), "{err}");
        assert_eq!(kept.key(NPUB), None);
        // Waited for, and paid meanwhile: its key is asked for, once.
        let key = json!({ "key": "ab".repeat(32), "package": { "id": PACKAGE, "you": true } });
        let answers = vec![ok(&terms_of(NPUB, "x")), ok(&waiting(RIGHT, 1500)), ok(&paid_order()), ok(&key)];
        let (ended, out, err, asked) = against(&format!("{line} --wait"), answers, &state);
        assert_eq!((ended, asked.len()), (DONE, 4), "{out} {err}");
        assert!(
            asked[3].starts_with(&format!("POST /v1/orders/{ORDER}/key ")) && out.contains("its key: abab"),
            "{out}"
        );
        assert_eq!(kept.key(NPUB), Some((PACKAGE.to_string(), "ab".repeat(32))));
        // Another package's key, given and used: that one is used here from
        // now on, said so, and the first is kept still.
        let (other, other_key) = ("p00000000000000ff", "cd".repeat(32));
        let file = state.join("friend");
        std::fs::write(&file, &other_key).unwrap();
        let theirs =
            json!({ "id": other, "standing": "live", "bytes_left": 5, "until": null, "members": [], "you": false });
        let (ended, _, err, _) =
            against(&format!("package {NPUB} --key-file {}", file.display()), vec![ok(&theirs)], &state);
        assert!(
            ended == DONE && err.contains(&format!("The key of {PACKAGE} is kept still: --package {PACKAGE}")),
            "{err}"
        );
        assert_eq!(kept.key(NPUB), Some((other.to_string(), other_key)));
        let (ended, out, _, _) = against(&format!("key {NPUB} --package {PACKAGE}"), vec![], &state);
        assert_eq!((ended, out), (DONE, format!("{}\n", "ab".repeat(32))));
        // The first order, asked about again: its package's key is kept, and stays.
        let (ended, _, err, asked) = against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&paid_order())], &state);
        assert!(ended == DONE && asked.len() == 2 && !err.contains("--new"), "{err}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn an_order_is_not_waited_for_without_end() {
        let state = scratch("wait");
        // The exit answers once, and then no more: after a while, not known.
        let line = format!("order {NPUB} {ORDER} --wait");
        let began = std::time::Instant::now();
        let (ended, out, err, _) = against(&line, vec![ok(&terms_of(NPUB, "x")), ok(&waiting(RIGHT, 1500))], &state);
        assert_eq!(ended, WAITING, "{out} {err}");
        assert!(
            err.contains("the exit has stopped answering") && err.contains(&format!("order {NPUB} {ORDER}")),
            "{err}"
        );
        assert!(began.elapsed() < Duration::from_secs(20));
        // Long after its end, an order that is still not decided is not either.
        let mut old = waiting(RIGHT, 1500);
        old["expires"] = json!(now() - LATE - 10);
        let mut checking = old.clone();
        checking["state"] = json!("checking");
        let answers = vec![ok(&terms_of(NPUB, "x")), ok(&old), ok(&checking), ok(&checking)];
        let (ended, _, err, _) = against(&line, answers, &state);
        assert!(ended == WAITING && err.contains("not decided long after its end"), "{err}");
        // By this node's clock it had ended when it was shown: said, and shown.
        assert!(err.contains("by this node's clock the order has ended already"), "{err}");
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
