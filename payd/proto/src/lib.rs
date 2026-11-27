//! What a fips exit says about itself on Nostr, and what a byte costs there.
//!
//! An exit that wants to be found publishes one event, signed with its own
//! fips key: kind 30078 (NIP-78 application data, one per author), marked
//! `d` = `fips-exit`. A fips identity is a Nostr key, so the event's author
//! IS the exit, and that is all the event proves. Everything in its tags is
//! what the operator says.
//!
//! This crate is those tags. [`Advert::tags`] writes them for an exit,
//! [`Advert::read`] reads them for a client, and both are held to
//! `vectors/advert.json`, which the exit's own publisher (`fips-exit advert`,
//! in Python) is held to as well.
//!
//! ```text
//! ["d", "fips-exit"]
//! ["v", "1"]                             the tunnel's contract: IP in IPv6,
//!                                        the inner 100.64.0.0/10 address
//! ["access", "open" | "allow-list" | "paid"]
//! ["name", <up to 40 characters>]        optional
//! ["about", <up to 200 characters>]      optional
//! ["country", "DE"]                      optional: ISO 3166-1 alpha-2
//! ["price", "2000000"]                   paid: millisatoshi per gigabyte
//! ["pay", "bolt11", "cashu", …]          paid: the ways of paying on offer
//! ["port", "5170"]                       paid: the payment service, a TCP
//!                                        port on the exit's fips address
//! ["mint", "https://…"]                  paid, up to 4: mints accepted
//! ["package", id, bytes, sat, days]      paid, up to 8: prepaid packages
//! ["expiration", <unix seconds>]         NIP-40
//! ```
//!
//! A number is written one way: digits, no sign, no zero in front. A name
//! or a note is one line with nothing hidden in it ([`tidy`]).
//!
//! An advert is a hint. A client lists exits from it, and asks the exit
//! itself for its terms, over the mesh, before it pays. Nothing but the
//! author is to be trusted: not the price, not the country, and never a
//! mint. The event's content is empty.
//!
//! `access` is `open` (any fips node is served), `allow-list` (only nodes
//! the operator added) or `paid`. A client that does not know a word must
//! not list the advert: it could not use the exit. That is how a phone from
//! before `paid` existed passes over a paid exit.

#![forbid(unsafe_code)]

use std::fmt;

/// NIP-78 application data: addressable, one per author and `d` tag.
pub const KIND: u16 = 30078;
/// The `d` tag that marks an exit's advert.
pub const D_TAG: &str = "fips-exit";
/// The tunnel's contract an advert of this version speaks. A client lists
/// only adverts of a version it speaks itself.
pub const VERSION: &str = "1";

/// The longest name and note, in characters.
pub const MAX_NAME: usize = 40;
pub const MAX_ABOUT: usize = 200;
/// The highest price: 10^12 millisatoshi a gigabyte is a satoshi a byte.
pub const MAX_PRICE: u64 = 1_000_000_000_000;
/// Words read from a `pay` tag; a tag with more is not an advert.
pub const MAX_METHODS: usize = 8;
/// `mint` tags, and the length of one's address in bytes.
pub const MAX_MINTS: usize = 4;
pub const MAX_MINT_BYTES: usize = 256;
/// `package` tags, and what one may say.
pub const MAX_PACKAGES: usize = 8;
pub const MAX_PACKAGE_ID: usize = 20;
pub const MAX_PACKAGE_BYTES: u64 = 1_000_000_000_000_000;
pub const MAX_PACKAGE_SAT: u64 = 100_000_000_000;
pub const MAX_PACKAGE_DAYS: u32 = 3660;
/// An advert may be dated this far ahead (clocks differ), and may not claim
/// to be valid for longer than this.
pub const MAX_SKEW_SECS: u64 = 600;
pub const MAX_LIFETIME_SECS: u64 = 31 * 86400;

/// A gigabyte, as a price counts it.
pub const BYTES_PER_GB: u64 = 1_000_000_000;

/// What `bytes` cost at `price_msat_per_gb`, in millisatoshi, rounded up:
/// a byte that was carried is never free. The exit and its client both
/// count with this.
pub fn amount_due_msat(bytes: u64, price_msat_per_gb: u64) -> u64 {
    let due = (u128::from(bytes) * u128::from(price_msat_per_gb)).div_ceil(u128::from(BYTES_PER_GB));
    u64::try_from(due).unwrap_or(u64::MAX)
}

/// The officially assigned ISO 3166-1 alpha-2 codes.
const COUNTRIES: &str = "\
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI \
BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN \
CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK \
FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM \
HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN \
KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK \
ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP \
NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW \
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF \
TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI \
VN VU WF WS YE YT ZA ZM ZW";

/// Every country code an advert may carry.
pub fn countries() -> impl Iterator<Item = &'static str> {
    COUNTRIES.split(' ')
}

/// Is `code` a country an advert may name: one of the codes ISO 3166-1 has
/// assigned, as it writes them, two capital letters?
pub fn is_country(code: &str) -> bool {
    countries().any(|assigned| assigned == code)
}

/// Who an exit serves, as its operator says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Any fips node.
    Open,
    /// The nodes the operator added.
    AllowList,
    /// Whoever pays: see [`Terms`].
    Paid,
}

impl Access {
    pub fn word(self) -> &'static str {
        match self {
            Access::Open => "open",
            Access::AllowList => "allow-list",
            Access::Paid => "paid",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        [Access::Open, Access::AllowList, Access::Paid].into_iter().find(|access| access.word() == word)
    }
}

/// A way of paying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A Lightning invoice.
    Bolt11,
    /// An on-chain bitcoin address.
    Onchain,
    /// A Cashu token.
    Cashu,
    /// A Cashu Spilman channel: pay as you go.
    Channel,
}

impl Method {
    pub const ALL: [Method; 4] = [Method::Bolt11, Method::Onchain, Method::Cashu, Method::Channel];

    pub fn word(self) -> &'static str {
        match self {
            Method::Bolt11 => "bolt11",
            Method::Onchain => "onchain",
            Method::Cashu => "cashu",
            Method::Channel => "channel",
        }
    }

    pub fn from_word(word: &str) -> Option<Self> {
        Method::ALL.into_iter().find(|method| method.word() == word)
    }
}

/// A prepaid package: so many bytes for so many satoshi, to be used within
/// so many days.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// What the exit calls it: 1 to 20 of `A-Z a-z 0-9 . _ -`.
    pub id: String,
    pub bytes: u64,
    pub sat: u64,
    pub days: u32,
}

impl Package {
    fn valid(&self) -> bool {
        (1..=MAX_PACKAGE_ID).contains(&self.id.len())
            && self.id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            && (1..=MAX_PACKAGE_BYTES).contains(&self.bytes)
            && (1..=MAX_PACKAGE_SAT).contains(&self.sat)
            && (1..=MAX_PACKAGE_DAYS).contains(&self.days)
    }
}

/// What a paid exit says it costs. The exit's own answer, asked over the
/// mesh, is what counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    /// Millisatoshi per gigabyte (10^9 bytes): see [`amount_due_msat`].
    pub price_msat_per_gb: u64,
    /// The ways of paying on offer: at least one, none twice.
    pub methods: Vec<Method>,
    /// The payment service's TCP port on the exit's fips address.
    pub port: u16,
    /// Mints accepted, for a client to choose exits by. Never to be adopted
    /// from an advert. None twice, byte for byte.
    pub mints: Vec<String>,
    pub packages: Vec<Package>,
}

/// Is `url` a mint's address as an advert may carry it: `http://` or
/// `https://` and then the characters an address is made of (RFC 3986),
/// [`MAX_MINT_BYTES`] at most? Nothing here says that it is a mint, or
/// compares two addresses beyond their bytes: the same mint written in two
/// ways is two mints to this crate.
fn mint_url(url: &str) -> bool {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
    let in_an_address = |b: u8| b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b);
    url.len() <= MAX_MINT_BYTES && rest.is_some_and(|rest| !rest.is_empty() && rest.bytes().all(in_an_address))
}

fn distinct<T: PartialEq>(items: &[T]) -> bool {
    items.iter().enumerate().all(|(at, item)| !items[..at].contains(item))
}

impl Terms {
    fn valid(&self) -> bool {
        (1..=MAX_PRICE).contains(&self.price_msat_per_gb)
            && !self.methods.is_empty()
            && distinct(&self.methods)
            && self.port != 0
            && self.mints.len() <= MAX_MINTS
            && self.mints.iter().all(|mint| mint_url(mint))
            && distinct(&self.mints)
            && self.packages.len() <= MAX_PACKAGES
            && self.packages.iter().all(Package::valid)
            && distinct(&self.packages.iter().map(|package| &package.id).collect::<Vec<_>>())
    }

    /// The terms in a paid advert's tags, or `None` if they are not all
    /// there and all in order.
    fn read(tags: &[Vec<String>]) -> Option<Terms> {
        let price_msat_per_gb = number(value(tags, "price")??, 13)?;
        let port = u16::try_from(number(value(tags, "port")??, 5)?).ok()?;
        // Ways of paying this crate does not know are passed over: an exit
        // may offer a newer one beside those a client can use.
        let words = tags.iter().find(|tag| name_is(tag, "pay"))?.get(1..)?;
        if words.len() > MAX_METHODS {
            return None;
        }
        let mut methods = Vec::new();
        for method in words.iter().filter_map(|word| Method::from_word(word)) {
            if !methods.contains(&method) {
                methods.push(method);
            }
        }
        let mut mints = Vec::new();
        for tag in tags.iter().filter(|tag| name_is(tag, "mint")) {
            mints.push(tag.get(1)?.clone());
        }
        let mut packages = Vec::new();
        for tag in tags.iter().filter(|tag| name_is(tag, "package")) {
            let [_, id, bytes, sat, days, ..] = tag.as_slice() else {
                return None;
            };
            packages.push(Package {
                id: id.clone(),
                bytes: number(bytes, 16)?,
                sat: number(sat, 12)?,
                days: u32::try_from(number(days, 4)?).ok()?,
            });
        }
        let terms = Terms { price_msat_per_gb, methods, port, mints, packages };
        terms.valid().then_some(terms)
    }
}

/// An exit's advert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    pub access: Access,
    /// The operator's name for the exit, possibly empty.
    pub name: String,
    /// The operator's note, possibly empty.
    pub about: String,
    /// Where the operator says the exit is: an ISO 3166-1 alpha-2 code.
    pub country: Option<String>,
    /// Unix seconds until which the advert is valid.
    pub expires: u64,
    /// What it costs: there if and only if `access` is [`Access::Paid`].
    pub terms: Option<Terms>,
}

/// Why an advert cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// The name or the note is longer than its limit, or is not one line of
    /// printable text.
    Text,
    /// The country is not an ISO 3166-1 alpha-2 code.
    Country,
    /// Already over at the time it is written, or valid for longer than
    /// [`MAX_LIFETIME_SECS`]: no client would list it.
    Expires,
    /// A paid advert without terms, or terms on one that is not paid.
    AccessAndTerms,
    /// The terms are out of their bounds: see [`Terms`] and the limits.
    Terms,
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Invalid::Text => "the name or the note is too long, or is not one line of printable text",
            Invalid::Country => "the country is not an ISO 3166-1 alpha-2 code",
            Invalid::Expires => "the advert is over already, or valid for more than 31 days",
            Invalid::AccessAndTerms => "terms go with access paid, and only with it",
            Invalid::Terms => "the terms are out of bounds",
        })
    }
}

impl std::error::Error for Invalid {}

fn name_is(tag: &[String], name: &str) -> bool {
    tag.first().is_some_and(|first| first == name)
}

/// The first tag called `name`: `None` if there is none, `Some(None)` if it
/// has no value.
fn value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<Option<&'a str>> {
    tags.iter().find(|tag| name_is(tag, name)).map(|tag| tag.get(1).map(String::as_str))
}

/// A number as an advert writes one, and in the one way it is written:
/// digits and nothing else, `max_digits` at most, and no zero in front of
/// another digit. (`str::parse` alone would take a sign and the zeros.)
fn number(text: &str, max_digits: usize) -> Option<u64> {
    let digits = !text.is_empty() && text.len() <= max_digits && text.bytes().all(|b| b.is_ascii_digit());
    if !digits || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

/// What separates words: Unicode's white space, spelled out, so that an
/// implementation in another language can hold the same list.
fn is_space(c: char) -> bool {
    matches!(c,
        '\u{0009}'..='\u{000D}' | '\u{0020}' | '\u{0085}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}'
        | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

/// What is not shown, or changes how what is next to it is shown: control
/// characters, the characters that turn a line round or hide in it, the
/// invisible tag characters, and the letters that are blank. A name must
/// not be able to rearrange the line it is shown on, carry what cannot be
/// seen, or be an empty row. The two joiners (U+200C, U+200D) are not
/// among them: Persian and the Indic scripts are written with them.
fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}'
        | '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}'
        | '\u{E0000}'..='\u{E007F}'
        | '\u{115F}' | '\u{1160}' | '\u{2800}' | '\u{3164}' | '\u{FFA0}')
}

/// Operator text for a list on a screen: one line of words with single
/// spaces between them, nothing hidden ([`is_hidden`]), `limit` characters
/// at most. What an advert says is cut to this, not refused; `vectors`
/// has the cases, for every implementation.
pub fn tidy(text: &str, limit: usize) -> String {
    let shown: String = text.chars().map(|c| if is_space(c) { ' ' } else { c }).filter(|c| !is_hidden(*c)).collect();
    let words: Vec<&str> = shown.split(' ').filter(|word| !word.is_empty()).collect();
    // Cut, and then no space at the end: the cut may fall just after one.
    let cut: String = words.join(" ").chars().take(limit).collect();
    cut.trim_end_matches(' ').to_string()
}

impl Advert {
    /// The advert's tags, in the one order every publisher writes them, as
    /// written at `now`. An exit that is about to say something no client
    /// would list is told so here, and not by clients that pass it over.
    pub fn tags(&self, now: u64) -> Result<Vec<Vec<String>>, Invalid> {
        if self.expires <= now || self.expires > now.saturating_add(MAX_LIFETIME_SECS) {
            return Err(Invalid::Expires);
        }
        for (text, limit) in [(&self.name, MAX_NAME), (&self.about, MAX_ABOUT)] {
            if *text != tidy(text, limit) {
                return Err(Invalid::Text);
            }
        }
        if self.country.as_deref().is_some_and(|code| !is_country(code)) {
            return Err(Invalid::Country);
        }
        if self.terms.is_some() != (self.access == Access::Paid) {
            return Err(Invalid::AccessAndTerms);
        }
        if self.terms.as_ref().is_some_and(|terms| !terms.valid()) {
            return Err(Invalid::Terms);
        }
        let tag = |words: &[&str]| words.iter().map(|word| word.to_string()).collect::<Vec<String>>();
        let mut tags = vec![tag(&["d", D_TAG]), tag(&["v", VERSION]), tag(&["access", self.access.word()])];
        if !self.name.is_empty() {
            tags.push(tag(&["name", &self.name]));
        }
        if !self.about.is_empty() {
            tags.push(tag(&["about", &self.about]));
        }
        if let Some(country) = &self.country {
            tags.push(tag(&["country", country]));
        }
        if let Some(terms) = &self.terms {
            tags.push(tag(&["price", &terms.price_msat_per_gb.to_string()]));
            let mut pay = vec!["pay"];
            pay.extend(terms.methods.iter().map(|method| method.word()));
            tags.push(tag(&pay));
            tags.push(tag(&["port", &terms.port.to_string()]));
            for mint in &terms.mints {
                tags.push(tag(&["mint", mint]));
            }
            for package in &terms.packages {
                tags.push(tag(&[
                    "package",
                    &package.id,
                    &package.bytes.to_string(),
                    &package.sat.to_string(),
                    &package.days.to_string(),
                ]));
            }
        }
        tags.push(tag(&["expiration", &self.expires.to_string()]));
        Ok(tags)
    }

    /// The advert in an event's tags, if it is one a client can use at
    /// `now`: the marker, this contract's version, a known access word, in
    /// date, and for a paid exit terms that are all there and in order.
    /// `None` for anything else. An advert is untrusted input, and one that
    /// is odd is not shown rather than half shown.
    ///
    /// The caller has checked the event's kind and signature; `created_at`
    /// is the event's. Of a tag that may be there once, the first counts.
    pub fn read(tags: &[Vec<String>], created_at: u64, now: u64) -> Option<Advert> {
        if created_at > now.saturating_add(MAX_SKEW_SECS) {
            return None;
        }
        if value(tags, "d")?? != D_TAG || value(tags, "v")?? != VERSION {
            return None;
        }
        let access = Access::from_word(value(tags, "access")??)?;
        // No expiration, or one already past: an exit that stopped
        // advertising is gone. One absurdly far ahead is not believed: the
        // lifetime is counted from the later of this clock and the event's
        // date, so that an advert written for the longest lifetime is not
        // lost on a reader whose clock is a little behind the exit's.
        let expires = number(value(tags, "expiration")??, 20)?;
        if expires <= now || expires > now.max(created_at).saturating_add(MAX_LIFETIME_SECS) {
            return None;
        }
        // The text is cut to size, as it always was. A country that is not
        // one is another matter: it is a claim a client filters by.
        let country = match value(tags, "country") {
            None => None,
            Some(Some(code)) if is_country(code) => Some(code.to_string()),
            Some(_) => return None,
        };
        let terms = if access == Access::Paid { Some(Terms::read(tags)?) } else { None };
        Some(Advert {
            access,
            name: tidy(value(tags, "name").flatten().unwrap_or(""), MAX_NAME),
            about: tidy(value(tags, "about").flatten().unwrap_or(""), MAX_ABOUT),
            country,
            expires,
            terms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../vectors/advert.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vectors/advert.json is JSON")
    }

    fn tags_of(value: &Value) -> Vec<Vec<String>> {
        let text = |v: &Value| v.as_str().expect("a tag is strings").to_string();
        let tag = |tag: &Value| tag.as_array().expect("a tag").iter().map(text).collect();
        value.as_array().expect("tags").iter().map(tag).collect()
    }

    /// An advert as the vectors write one.
    fn advert_of(value: &Value) -> Advert {
        let number = |v: &Value| v.as_u64().expect("a number");
        let text = |v: &Value| v.as_str().expect("a string").to_string();
        let terms = value.get("terms").filter(|terms| !terms.is_null()).map(|terms| Terms {
            price_msat_per_gb: number(&terms["price_msat_per_gb"]),
            methods: terms["methods"]
                .as_array()
                .expect("methods")
                .iter()
                .map(|word| Method::from_word(word.as_str().unwrap()).expect("a known method"))
                .collect(),
            port: u16::try_from(number(&terms["port"])).unwrap_or(0),
            mints: terms["mints"].as_array().expect("mints").iter().map(text).collect(),
            packages: terms["packages"]
                .as_array()
                .expect("packages")
                .iter()
                .map(|package| Package {
                    id: text(&package["id"]),
                    bytes: number(&package["bytes"]),
                    sat: number(&package["sat"]),
                    days: u32::try_from(number(&package["days"])).unwrap_or(u32::MAX),
                })
                .collect(),
        });
        Advert {
            access: Access::from_word(value["access"].as_str().unwrap()).expect("a known access word"),
            name: text(&value["name"]),
            about: text(&value["about"]),
            country: value.get("country").and_then(Value::as_str).map(str::to_string),
            expires: number(&value["expires"]),
            terms,
        }
    }

    #[test]
    fn an_exit_writes_the_tags_the_vectors_say() {
        let vectors = vectors();
        let cases = vectors["write"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let name = case["case"].as_str().unwrap();
            let written = advert_of(&case["advert"]).tags(case["now"].as_u64().unwrap());
            match case.get("tags") {
                Some(tags) => assert_eq!(written, Ok(tags_of(tags)), "{name}"),
                None => assert!(written.is_err(), "{name}: written as {written:?}"),
            }
        }
    }

    #[test]
    fn a_client_reads_what_the_vectors_say_and_nothing_else() {
        let vectors = vectors();
        let cases = vectors["read"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for case in cases {
            let name = case["case"].as_str().unwrap();
            let (created_at, now) = (case["created_at"].as_u64().unwrap(), case["now"].as_u64().unwrap());
            let read = Advert::read(&tags_of(&case["tags"]), created_at, now);
            let expected = Some(&case["advert"]).filter(|advert| !advert.is_null()).map(advert_of);
            assert_eq!(read, expected, "{name}");
        }
    }

    /// What is written is read back as it was: every advert the vectors have
    /// an exit write.
    #[test]
    fn what_is_written_is_read_back() {
        let vectors = vectors();
        for case in vectors["write"].as_array().unwrap() {
            let (advert, now) = (advert_of(&case["advert"]), case["now"].as_u64().unwrap());
            if let Ok(tags) = advert.tags(now) {
                assert_eq!(Advert::read(&tags, now, now), Some(advert.clone()), "{}", case["case"]);
                // And by a reader whose clock is ten minutes behind the exit's.
                assert_eq!(Advert::read(&tags, now, now - MAX_SKEW_SECS), Some(advert), "{}", case["case"]);
            }
        }
    }

    #[test]
    fn a_byte_costs_what_the_vectors_say() {
        let vectors = vectors();
        let cases = vectors["price"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let (bytes, price) = (case["bytes"].as_u64().unwrap(), case["price_msat_per_gb"].as_u64().unwrap());
            assert_eq!(amount_due_msat(bytes, price), case["msat"].as_u64().unwrap(), "{bytes} bytes at {price}");
        }
        // Rounded up, never down; and no arithmetic that wraps.
        assert_eq!(amount_due_msat(1, 1), 1);
        assert_eq!(amount_due_msat(u64::MAX, MAX_PRICE), u64::MAX);
        assert_eq!(amount_due_msat(u64::MAX, 1), u64::MAX / BYTES_PER_GB + 1);
    }

    #[test]
    fn the_countries_are_the_iso_list() {
        assert_eq!(countries().count(), 249);
        assert!(countries().all(|code| code.len() == 2 && is_country(code)));
        let mut sorted: Vec<&str> = countries().collect();
        sorted.dedup();
        assert_eq!(sorted.len(), 249, "none twice");
        assert!(sorted.windows(2).all(|pair| pair[0] < pair[1]), "in order");
        for not_one in ["", "D", "de", "De", "DEU", "XX", "EU", "UK", "D\u{c4}", " DE", "DE "] {
            assert!(!is_country(not_one), "{not_one:?}");
        }
        // The same list the vectors carry for the exit's publisher.
        let vectors = vectors();
        let listed: Vec<&str> = vectors["countries"].as_str().unwrap().split(' ').collect();
        assert_eq!(listed, countries().collect::<Vec<_>>());
    }

    #[test]
    fn text_is_cut_to_one_tidy_line_as_the_vectors_say() {
        let vectors = vectors();
        let cases = vectors["tidy"].as_array().unwrap();
        assert!(cases.len() >= 30);
        for case in cases {
            let (text, limit) = (case["text"].as_str().unwrap(), case["limit"].as_u64().unwrap() as usize);
            let tidied = tidy(text, limit);
            assert_eq!(tidied, case["tidy"].as_str().unwrap(), "{text:?} to {limit}");
            // What was tidied is tidy: an exit could write it as it is.
            assert_eq!(tidy(&tidied, limit), tidied, "{text:?} to {limit}, again");
        }
        // The list of white space is Unicode's, which the standard library knows too.
        for c in (0..=0x10FFFF).filter_map(char::from_u32) {
            assert_eq!(is_space(c), c.is_whitespace(), "U+{:04X}", c as u32);
            assert!(!c.is_control() || is_hidden(c), "U+{:04X} is a control character", c as u32);
        }
    }

    #[test]
    fn a_number_is_digits() {
        assert_eq!(number("0", 5), Some(0));
        assert_eq!(number("65535", 5), Some(65535));
        for not_one in ["", "+5", "-5", "5 ", " 5", "1e3", "0x10", "1.0", "123456", "\u{663}", "05", "00", "007"] {
            assert_eq!(number(not_one, 5), None, "{not_one:?}");
        }
        assert_eq!(number("18446744073709551616", 20), None, "one more than a u64 holds");
    }
}
