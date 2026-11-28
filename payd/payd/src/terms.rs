//! What the exit says it costs, asked of the exit itself: the advert on
//! Nostr is a hint, and this is what a client goes by before it pays.

use std::net::Ipv6Addr;

use fips_exit_proto::{BYTES_PER_GB, Package};
use serde::Serialize;

use crate::config::Config;

/// The terms' format. A client that does not know a version does not buy.
pub const VERSION: u32 = 1;

/// Who the exit is, as the caller sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Exit {
    /// Its npub: its name on the mesh (`<npub>.fips`), and the way to it.
    /// The node's own key file says it, and the advert is signed with it.
    pub npub: String,
    /// Its fips address, the one this service answers on.
    pub address: Ipv6Addr,
    pub name: String,
    pub about: String,
    /// Where the operator says it is: ISO 3166-1 alpha-2.
    pub country: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PackageTerms {
    pub id: String,
    pub bytes: u64,
    pub sat: u64,
    pub days: u32,
}

/// The caller, as the mesh says it is: the source address of its
/// connection, which fips authenticates.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct You {
    pub address: Ipv6Addr,
    /// The package it is a member of, if any: as the caller may see it.
    pub package: Option<YourPackage>,
}

/// A caller's own package: what is left of it, until when, and how. Not
/// its key, and not who else shares it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct YourPackage {
    pub id: String,
    /// `live`, `used-up`, `over` or `revoked`.
    pub standing: String,
    pub bytes_left: u64,
    /// Unix seconds, or none.
    pub until: Option<u64>,
    /// How many addresses share it, this one included.
    pub members: usize,
    /// Whether this address is carried over IPv4 too: false when another
    /// client of this exit derives the same inner IPv4 address.
    pub ipv4: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Terms {
    pub version: u32,
    pub exit: Exit,
    /// Millisatoshi per gigabyte of 10^9 bytes.
    pub price_msat_per_gb: u64,
    pub packages: Vec<PackageTerms>,
    /// Mints accepted.
    pub mints: Vec<String>,
    /// The ways of paying that work now: `cashu`, a token of an accepted
    /// mint, while one of them is reached; `bolt11`, a Lightning invoice,
    /// while one that is reached gives any. A client buys nothing while
    /// this is empty.
    pub methods: Vec<String>,
    pub you: You,
}

pub fn terms(
    config: &Config,
    exit: &Exit,
    caller: Ipv6Addr,
    package: Option<YourPackage>,
    methods: Vec<String>,
) -> Terms {
    let offered = |p: &Package| PackageTerms { id: p.id.clone(), bytes: p.bytes, sat: p.sat, days: p.days };
    Terms {
        version: VERSION,
        exit: exit.clone(),
        price_msat_per_gb: config.price_msat_per_gb,
        packages: config.packages.iter().map(offered).collect(),
        mints: config.mints.clone(),
        methods,
        you: You { address: caller, package },
    }
}

/// Text for HTML: what could be markup is not.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A number of bytes for a person: in the decimal units a price counts in.
pub fn bytes_shown(bytes: u64) -> String {
    let units = [(1_000_000_000_000, "TB"), (BYTES_PER_GB, "GB"), (1_000_000, "MB"), (1_000, "kB")];
    for (size, unit) in units {
        if bytes >= size {
            let whole = bytes / size;
            let tenth = bytes % size * 10 / size;
            return if tenth == 0 { format!("{whole} {unit}") } else { format!("{whole}.{tenth} {unit}") };
        }
    }
    format!("{bytes} bytes")
}

/// A moment for a person: the date and time in UTC.
pub fn date(unix: u64) -> String {
    let (days, seconds) = (unix / 86_400, unix % 86_400);
    // Days to a date in the proleptic Gregorian calendar (Howard Hinnant's
    // civil_from_days).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year}-{month:02}-{day:02} {:02}:{:02} UTC", seconds / 3600, seconds % 3600 / 60)
}

/// Satoshi for a person: millisatoshi rounded up to whole satoshi.
fn sat_shown(msat: u64) -> String {
    format!("{} sat", msat.div_ceil(1000))
}

/// A page of this exit's: `body` under `title`, with the one stylesheet.
/// Both are markup already: what goes into them is escaped by whoever
/// writes them.
pub fn shell(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body>
<main>
<h1>{title}</h1>
{body}</main>
</body>
</html>
"
    )
}

/// The form that buys one of `offers` with a token. With `key`, what is
/// bought is added to the package that key opens.
pub fn buy_form(offers: &[Package], key: Option<&str>, methods: &[String]) -> String {
    let (by_token, by_invoice) =
        (methods.iter().any(|method| method == "cashu"), methods.iter().any(|method| method == "bolt11"));
    if offers.is_empty() || !(by_token || by_invoice) {
        return String::new();
    }
    let options: String = offers
        .iter()
        .map(|p| {
            format!(
                "<option value=\"{id}\">{id}: {}, {} days, {} sat</option>",
                bytes_shown(p.bytes),
                p.days,
                p.sat,
                id = escape(&p.id)
            )
        })
        .collect();
    let (heading, hidden, invoice_button, button) = match key {
        Some(key) => (
            "<h2>Add to this package</h2>\n",
            format!("<input type=\"hidden\" name=\"key\" value=\"{}\">", escape(key)),
            "Add it, paid with Lightning",
            "Add it, paid with this token",
        ),
        None => ("<h2>Buy a package</h2>\n", String::new(), "Pay with Lightning", "Pay with this token"),
    };
    let mut form = heading.to_string();
    if by_invoice {
        form.push_str(&format!(
            "<form method=\"post\" action=\"/buy\">{hidden}<input type=\"hidden\" name=\"method\" value=\"bolt11\">
<p><label>Package <select name=\"package\">{options}</select></label></p>
<button>{invoice_button}</button>
</form>
<p class=\"you\">An invoice for its price is shown, to pay from a Lightning wallet: on this device, or with another from its code. What is paid is not given back.</p>
"
        ));
    }
    if by_token {
        if by_invoice {
            form.push_str("<h3>Or with a Cashu token</h3>\n");
        }
        form.push_str(&format!(
            "<form method=\"post\" action=\"/buy\">{hidden}
<p><label>Package <select name=\"package\">{options}</select></label></p>
<p><label>A Cashu token for its price, of a mint this exit accepts<br>
<textarea name=\"token\" rows=\"5\" required autocomplete=\"off\" autocapitalize=\"off\" spellcheck=\"false\"></textarea></label></p>
<button>{button}</button>
</form>
<p class=\"you\">The token must be worth the price after the fee its mint takes for redeeming it. One worth less, or over a tenth more, is not touched. What is paid is not given back.</p>
"
        ));
    }
    form
}

/// The page: the same terms, for a browser. No script, no font or file from
/// anywhere else; its one stylesheet is served beside it.
pub fn page(terms: &Terms) -> String {
    let exit = &terms.exit;
    let title = if exit.name.is_empty() { "A fips exit".to_string() } else { escape(&exit.name) };
    let mut rows = String::new();
    for p in &terms.packages {
        let per_gb = u128::from(p.sat) * u128::from(BYTES_PER_GB) / u128::from(p.bytes.max(1));
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{} sat</td><td>{} days</td><td>{per_gb} sat</td></tr>\n",
            escape(&p.id),
            bytes_shown(p.bytes),
            p.sat,
            p.days
        ));
    }
    let packages = if rows.is_empty() {
        "<p>No packages are offered.</p>".to_string()
    } else {
        format!(
            "<table>\n<tr><th>Package</th><th>Data</th><th>Price</th><th>Valid for</th><th>Per GB</th></tr>\n{rows}</table>"
        )
    };
    let mints = if terms.mints.is_empty() {
        "<p>No mint is named.</p>".to_string()
    } else {
        let items: String = terms.mints.iter().map(|m| format!("<li><code>{}</code></li>", escape(m))).collect();
        format!("<ul>{items}</ul>")
    };
    let country = exit.country.as_deref().map(|c| format!(" &middot; {}", escape(c))).unwrap_or_default();
    let about = if exit.about.is_empty() { String::new() } else { format!("<p>{}</p>\n", escape(&exit.about)) };
    let npub = format!("<code>{}.fips</code>", escape(&exit.npub));
    let yours = match &terms.you.package {
        None => String::new(),
        Some(p) => {
            let until = p.until.map(|until| format!(", until {}", date(until))).unwrap_or_default();
            let ipv4 = if p.ipv4 {
                ""
            } else {
                " Another client of this exit has the same inner IPv4 address as this device: it is carried over IPv6 only."
            };
            let now = match p.standing.as_str() {
                "live" => format!("<strong>{}</strong> left{until}.", bytes_shown(p.bytes_left)),
                "used-up" => "It is used up.".to_string(),
                "over" => "Its time is over.".to_string(),
                _ => "It was taken back by the operator.".to_string(),
            };
            format!(
                "<h2>Your package</h2>\n<p>This device is in package <code>{}</code>, with {} device(s). {now}{ipv4}</p>\n\
                 <form method=\"post\" action=\"/leave\"><button>Take this device out of it</button></form>\n",
                escape(&p.id),
                p.members
            )
        }
    };
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{title}</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body>
<main>
<h1>{title}</h1>
<p class=\"who\">{npub}{country}</p>
{about}{yours}<h2>Price</h2>
<p><strong>{per_gb}</strong> a gigabyte, used as you go.</p>
<h2>Packages</h2>
{packages}
<h2>Mints accepted</h2>
{mints}
{buy}<h2>A package of yours</h2>
<form method=\"post\" action=\"/package\"><label>Its key: <input name=\"key\" size=\"40\" autocomplete=\"off\" required></label>
<button>Manage it</button></form>
<p class=\"you\">You are <code>{you}</code> on the mesh. That address is how this exit knows you; nothing else is asked.</p>
</main>
</body>
</html>
",
        per_gb = sat_shown(terms.price_msat_per_gb),
        you = terms.you.address,
        buy = if !terms.methods.is_empty() {
            let offers: Vec<Package> = terms
                .packages
                .iter()
                .map(|p| Package { id: p.id.clone(), bytes: p.bytes, sat: p.sat, days: p.days })
                .collect();
            buy_form(&offers, None, &terms.methods)
        } else {
            "<p class=\"note\">Nothing can be bought here right now: this exit takes no payment at the moment.</p>\n"
                .to_string()
        },
    )
}

/// The page's stylesheet. Plain, and dark when the reader's device is.
pub const STYLE: &str = "\
:root { color-scheme: light dark; --line: #8884; }
body { margin: 0; font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 42rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 1.75rem 0 .5rem; }
h3 { font-size: 1rem; margin: 1.25rem 0 .5rem; }
.qr { display: block; width: 18rem; max-width: 100%; height: auto; }
code { font-size: .85rem; overflow-wrap: anywhere; }
.who { margin-top: 0; opacity: .75; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); }
td:nth-child(n+2), th:nth-child(n+2) { text-align: right; }
.note { margin-top: 2rem; padding: .75rem 1rem; border: 1px solid var(--line); border-radius: .5rem; }
.you { opacity: .75; font-size: .9rem; }
form { margin: .5rem 0; }
td form { margin: 0; }
input, button, select, textarea { font: inherit; }
textarea { width: 100%; box-sizing: border-box; font-family: monospace; font-size: .85rem; }
";

#[cfg(test)]
mod tests {
    use super::*;

    fn exit() -> Exit {
        Exit {
            npub: "npub1example".into(),
            address: "fd14::1".parse().unwrap(),
            name: "An <b>exit</b> & \"more\"".into(),
            about: "In a rack".into(),
            country: Some("CH".into()),
        }
    }

    fn config() -> Config {
        Config {
            port: 5170,
            mesh_if: "fips0".into(),
            price_msat_per_gb: 2_000_000,
            packages: vec![
                Package { id: "1gb".into(), bytes: 1_000_000_000, sat: 1500, days: 30 },
                Package { id: "500mb".into(), bytes: 500_000_000, sat: 900, days: 7 },
            ],
            mints: vec!["https://mint.example.org/<x>".into()],
            name: String::new(),
            about: String::new(),
            country: None,
        }
    }

    #[test]
    fn the_terms_are_the_config_and_the_caller() {
        let caller: Ipv6Addr = "fd99::2".parse().unwrap();
        let json = serde_json::to_value(terms(&config(), &exit(), caller, None, Vec::new())).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "version": 1,
                "exit": {"npub": "npub1example", "address": "fd14::1", "name": "An <b>exit</b> & \"more\"",
                         "about": "In a rack", "country": "CH"},
                "price_msat_per_gb": 2000000,
                "packages": [{"id": "1gb", "bytes": 1000000000, "sat": 1500, "days": 30},
                             {"id": "500mb", "bytes": 500000000, "sat": 900, "days": 7}],
                "mints": ["https://mint.example.org/<x>"],
                "methods": [],
                "you": {"address": "fd99::2", "package": null}
            })
        );
    }

    #[test]
    fn the_page_shows_the_terms_and_nothing_as_markup() {
        let page = page(&terms(&config(), &exit(), "fd99::2".parse().unwrap(), None, Vec::new()));
        assert!(page.contains("<title>An &lt;b&gt;exit&lt;/b&gt; &amp; &quot;more&quot;</title>"));
        assert!(!page.contains("<b>exit</b>"), "the operator's text is not markup");
        assert!(page.contains("<code>https://mint.example.org/&lt;x&gt;</code>"));
        assert!(page.contains("<strong>2000 sat</strong> a gigabyte"));
        assert!(page.contains("<td>1gb</td><td>1 GB</td><td>1500 sat</td><td>30 days</td><td>1500 sat</td>"));
        assert!(page.contains("<td>500mb</td><td>500 MB</td><td>900 sat</td><td>7 days</td><td>1800 sat</td>"));
        assert!(page.contains("<code>fd99::2</code> on the mesh"));
        assert!(page.contains("&middot; CH"));
        assert!(page.contains("Nothing can be bought here right now") && !page.contains("<textarea"));
        assert!(!page.contains("<script") && !page.contains("http://") && !page.contains("//fonts"));
        let none = Terms {
            packages: vec![],
            mints: vec![],
            ..terms(&config(), &exit(), "fd99::2".parse().unwrap(), None, Vec::new())
        };
        let none = super::page(&none);
        assert!(none.contains("No packages are offered.") && none.contains("No mint is named."));
    }

    /// While a token is taken, the page has the form that buys with one.
    #[test]
    fn the_page_sells_while_something_can_be_paid_with() {
        let selling = terms(&config(), &exit(), "fd99::2".parse().unwrap(), None, vec!["cashu".into()]);
        assert_eq!(serde_json::to_value(&selling).unwrap()["methods"], serde_json::json!(["cashu"]));
        let page = page(&selling);
        assert!(page.contains("<form method=\"post\" action=\"/buy\">"), "{page}");
        assert!(page.contains("<option value=\"1gb\">1gb: 1 GB, 30 days, 1500 sat</option>"));
        assert!(page.contains("<option value=\"500mb\">500mb: 500 MB, 7 days, 900 sat</option>"));
        assert!(page.contains("<textarea name=\"token\"") && !page.contains("Nothing can be bought"));
        assert!(!page.contains("name=\"key\" value="), "a package of its own: no key goes with it");
        // Added to a package: the key goes with the form, and is not markup.
        let token = ["cashu".to_string()];
        let add = buy_form(&config().packages, Some("ab\"><x"), &token);
        assert!(add.contains("<h2>Add to this package</h2>"));
        assert!(add.contains("name=\"key\" value=\"ab&quot;&gt;&lt;x\""));
        assert!(!add.contains("Lightning") && !page.contains("Lightning"), "no invoice where no mint gives one");
        assert_eq!(buy_form(&[], None, &token), "", "nothing offered, nothing to buy");
        assert_eq!(buy_form(&config().packages, None, &[]), "", "no way to pay, nothing to buy");
        // Where a mint gives invoices, the form that asks for one comes
        // first; the one for a token is there as before.
        let both = ["cashu".to_string(), "bolt11".to_string()];
        let selling = terms(&config(), &exit(), "fd99::2".parse().unwrap(), None, both.to_vec());
        let page = super::page(&selling);
        let invoice = page.find("<input type=\"hidden\" name=\"method\" value=\"bolt11\">").expect("an invoice form");
        assert!(invoice < page.find("<textarea name=\"token\"").unwrap(), "{page}");
        assert!(
            page.contains("<button>Pay with Lightning</button>")
                && page.contains("<button>Pay with this token</button>")
        );
        assert!(page.contains("<h3>Or with a Cashu token</h3>"));
        let add = buy_form(&config().packages, Some("abcd"), &both);
        assert_eq!(add.matches("name=\"key\" value=\"abcd\"").count(), 2, "the key goes with both forms");
        assert!(add.contains("<button>Add it, paid with Lightning</button>"));
        // An invoice alone: no token is asked for.
        let invoice_only = buy_form(&config().packages, None, &["bolt11".to_string()]);
        assert!(invoice_only.contains("Pay with Lightning") && !invoice_only.contains("textarea"));
        let shell = shell("A title", "<p>the body</p>\n");
        assert!(
            shell.contains("<title>A title</title>") && shell.contains("<h1>A title</h1>\n<p>the body</p>\n</main>")
        );
    }

    #[test]
    fn a_member_sees_its_package() {
        let package = YourPackage {
            id: "p0123456789abcdef".into(),
            standing: "live".into(),
            bytes_left: 750_000_000,
            until: Some(1_800_000_000),
            members: 2,
            ipv4: false,
        };
        let t = terms(&config(), &exit(), "fd99::2".parse().unwrap(), Some(package.clone()), Vec::new());
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(
            json["you"]["package"],
            serde_json::json!({"id": "p0123456789abcdef", "standing": "live", "bytes_left": 750000000,
                               "until": 1800000000, "members": 2, "ipv4": false})
        );
        let shown = page(&t);
        assert!(shown.contains("<strong>750 MB</strong> left, until 2027-01-15 08:00 UTC."), "{shown}");
        assert!(shown.contains("over IPv6 only"));
        let over = YourPackage { standing: "over".into(), ipv4: true, ..package };
        let shown = page(&terms(&config(), &exit(), "fd99::2".parse().unwrap(), Some(over), Vec::new()));
        assert!(shown.contains("Its time is over.") && !shown.contains("IPv6 only"));
    }

    #[test]
    fn numbers_for_a_person() {
        assert_eq!(date(0), "1970-01-01 00:00 UTC");
        assert_eq!(date(1_800_000_000), "2027-01-15 08:00 UTC");
        assert_eq!(date(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(bytes_shown(999), "999 bytes");
        assert_eq!(bytes_shown(1_500), "1.5 kB");
        assert_eq!(bytes_shown(1_000_000_000), "1 GB");
        assert_eq!(bytes_shown(2_500_000_000), "2.5 GB");
        assert_eq!(bytes_shown(1_990_000_000_000), "1.9 TB");
        assert_eq!(sat_shown(2_000_000), "2000 sat");
        assert_eq!(sat_shown(1), "1 sat");
        assert_eq!(escape("<a href='x'>&</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&lt;/a&gt;");
    }
}
