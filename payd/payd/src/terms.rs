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
    /// Its npub, when this service could read it: the node's own key file
    /// says it, and the advert is signed with it.
    pub npub: Option<String>,
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
    /// The ways of paying that work now. None yet: nothing here takes a
    /// payment, and a client buys nothing while this is empty.
    pub methods: Vec<String>,
    pub you: You,
}

pub fn terms(config: &Config, exit: &Exit, caller: Ipv6Addr) -> Terms {
    let package = |p: &Package| PackageTerms { id: p.id.clone(), bytes: p.bytes, sat: p.sat, days: p.days };
    Terms {
        version: VERSION,
        exit: exit.clone(),
        price_msat_per_gb: config.price_msat_per_gb,
        packages: config.packages.iter().map(package).collect(),
        mints: config.mints.clone(),
        methods: Vec::new(),
        you: You { address: caller },
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

/// Satoshi for a person: millisatoshi rounded up to whole satoshi.
fn sat_shown(msat: u64) -> String {
    format!("{} sat", msat.div_ceil(1000))
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
    let npub = exit.npub.as_deref().map(|n| format!("<code>{}</code><br>", escape(n))).unwrap_or_default();
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
<p class=\"who\">{npub}<code>{address}</code>{country}</p>
{about}<h2>Price</h2>
<p><strong>{per_gb}</strong> a gigabyte, used as you go.</p>
<h2>Packages</h2>
{packages}
<h2>Mints accepted</h2>
{mints}
<p class=\"note\">Nothing can be bought here yet: this exit takes no payment so far.</p>
<p class=\"you\">You are <code>{you}</code> on the mesh. That address is how this exit knows you; nothing else is asked.</p>
</main>
</body>
</html>
",
        address = exit.address,
        per_gb = sat_shown(terms.price_msat_per_gb),
        you = terms.you.address,
    )
}

/// The page's stylesheet. Plain, and dark when the reader's device is.
pub const STYLE: &str = "\
:root { color-scheme: light dark; --line: #8884; }
body { margin: 0; font: 16px/1.5 system-ui, sans-serif; }
main { max-width: 42rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 1.75rem 0 .5rem; }
code { font-size: .85rem; overflow-wrap: anywhere; }
.who { margin-top: 0; opacity: .75; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); }
td:nth-child(n+2), th:nth-child(n+2) { text-align: right; }
.note { margin-top: 2rem; padding: .75rem 1rem; border: 1px solid var(--line); border-radius: .5rem; }
.you { opacity: .75; font-size: .9rem; }
";

#[cfg(test)]
mod tests {
    use super::*;

    fn exit() -> Exit {
        Exit {
            npub: Some("npub1example".into()),
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
        let json = serde_json::to_value(terms(&config(), &exit(), caller)).unwrap();
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
                "you": {"address": "fd99::2"}
            })
        );
    }

    #[test]
    fn the_page_shows_the_terms_and_nothing_as_markup() {
        let page = page(&terms(&config(), &exit(), "fd99::2".parse().unwrap()));
        assert!(page.contains("<title>An &lt;b&gt;exit&lt;/b&gt; &amp; &quot;more&quot;</title>"));
        assert!(!page.contains("<b>exit</b>"), "the operator's text is not markup");
        assert!(page.contains("<code>https://mint.example.org/&lt;x&gt;</code>"));
        assert!(page.contains("<strong>2000 sat</strong> a gigabyte"));
        assert!(page.contains("<td>1gb</td><td>1 GB</td><td>1500 sat</td><td>30 days</td><td>1500 sat</td>"));
        assert!(page.contains("<td>500mb</td><td>500 MB</td><td>900 sat</td><td>7 days</td><td>1800 sat</td>"));
        assert!(page.contains("<code>fd99::2</code> on the mesh"));
        assert!(page.contains("&middot; CH"));
        assert!(page.contains("Nothing can be bought here yet"));
        assert!(!page.contains("<script") && !page.contains("http://") && !page.contains("//fonts"));
        let none = Terms { packages: vec![], mints: vec![], ..terms(&config(), &exit(), "fd99::2".parse().unwrap()) };
        let none = super::page(&none);
        assert!(none.contains("No packages are offered.") && none.contains("No mint is named."));
    }

    #[test]
    fn numbers_for_a_person() {
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
