//! What the operator has said: `/etc/fips-exit/config`, the same file the
//! script reads for everything else, so that what this service says about
//! the exit and what the advert says come from one place.

use std::collections::HashMap;
use std::fmt;

use fips_exit_proto::{MAX_ABOUT, MAX_MINTS, MAX_NAME, MAX_PACKAGES, MAX_PRICE, Package, is_country, is_mint_url};

/// The payment service's port when the config names none.
pub const DEFAULT_PORT: u16 = 5170;

/// The settings as the script reads them (`fips-exit`, `load_config` and
/// `config_value`): `KEY=value` lines; a value between quotes, double or
/// single, is taken as it is, `#` included; otherwise a `#` begins a
/// comment. A line that starts with `#` is a comment.
pub fn settings(text: &str) -> HashMap<String, String> {
    let mut settings = HashMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim();
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        settings.insert(key.to_string(), value_of(value));
    }
    settings
}

fn value_of(text: &str) -> String {
    let text = text.trim();
    if let Some(quote) = text.chars().next().filter(|c| *c == '"' || *c == '\'')
        && let Some(closing) = text[1..].find(quote)
    {
        return text[1..1 + closing].to_string();
    }
    text.split('#').next().unwrap_or("").trim().trim_matches('"').to_string()
}

/// What this service needs to know of the exit.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub port: u16,
    pub mesh_if: String,
    pub price_msat_per_gb: u64,
    pub packages: Vec<Package>,
    pub mints: Vec<String>,
    pub name: String,
    pub about: String,
    pub country: Option<String>,
}

/// Why the config cannot be used, said so that the operator knows which
/// line to change.
#[derive(Debug, PartialEq)]
pub struct Wrong(pub String);

impl fmt::Display for Wrong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Digits and nothing else, and no zero in front: as the advert writes a
/// number. (`str::parse` alone would take a sign.)
fn digits(text: &str) -> Option<u64> {
    let well_formed = !text.is_empty()
        && text.len() <= 20
        && text.bytes().all(|b| b.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'));
    if well_formed { text.parse().ok() } else { None }
}

/// A size: a number of bytes, or one with MB, GB or TB after it, in powers
/// of ten as a price counts them.
fn size(text: &str) -> Option<u64> {
    let (number, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => text.split_at(at),
        None => (text, ""),
    };
    let factor = match unit {
        "" => 1,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        "TB" => 1_000_000_000_000,
        _ => return None,
    };
    digits(number)?.checked_mul(factor)
}

/// A package as the config writes one: `id:size:sat:days`, for instance
/// `1gb:1GB:1500:30`.
fn package(text: &str) -> Result<Package, Wrong> {
    let wrong = || Wrong(format!("PACKAGES: {text:?} is not id:size:sat:days (1gb:1GB:1500:30)"));
    let [id, bytes, sat, days] = text.split(':').collect::<Vec<_>>()[..] else {
        return Err(wrong());
    };
    let package = Package {
        id: id.to_string(),
        bytes: size(bytes).ok_or_else(wrong)?,
        sat: digits(sat).ok_or_else(wrong)?,
        days: digits(days).and_then(|days| u32::try_from(days).ok()).ok_or_else(wrong)?,
    };
    if !package.is_valid() {
        return Err(Wrong(format!(
            "PACKAGES: {text:?} is out of bounds: a name of 1 to 20 of A-Z a-z 0-9 . _ -, and a size, a \
             price and days that are none of them nothing"
        )));
    }
    Ok(package)
}

impl Config {
    /// The settings that matter here, checked. `Ok(None)`: the exit does not
    /// sell access (`ACCESS` is not `paid`), and there is nothing to serve.
    pub fn from_settings(settings: &HashMap<String, String>) -> Result<Option<Config>, Wrong> {
        let get = |key: &str| settings.get(key).map(String::as_str).unwrap_or("");
        if get("ACCESS") != "paid" {
            return Ok(None);
        }
        let port = match get("PAY_PORT") {
            "" => DEFAULT_PORT,
            text => digits(text)
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port >= 1024)
                .ok_or_else(|| Wrong(format!("PAY_PORT={text}: a port from 1024 to 65535")))?,
        };
        let price_msat_per_gb =
            digits(get("PRICE_MSAT_PER_GB")).filter(|price| (1..=MAX_PRICE).contains(price)).ok_or_else(|| {
                Wrong(format!(
                    "PRICE_MSAT_PER_GB={}: the price of a gigabyte in millisatoshi, 1 to {MAX_PRICE} \
                     (2000000 is 2000 sat a GB)",
                    get("PRICE_MSAT_PER_GB")
                ))
            })?;
        let packages = get("PACKAGES").split_whitespace().map(package).collect::<Result<Vec<_>, _>>()?;
        if packages.len() > MAX_PACKAGES {
            return Err(Wrong(format!("PACKAGES: at most {MAX_PACKAGES}")));
        }
        for (at, package) in packages.iter().enumerate() {
            if packages[..at].iter().any(|other| other.id == package.id) {
                return Err(Wrong(format!("PACKAGES: {} twice", package.id)));
            }
        }
        let mints: Vec<String> = get("MINTS").split_whitespace().map(str::to_string).collect();
        if mints.len() > MAX_MINTS {
            return Err(Wrong(format!("MINTS: at most {MAX_MINTS}")));
        }
        for (at, mint) in mints.iter().enumerate() {
            if !is_mint_url(mint) {
                return Err(Wrong(format!("MINTS: {mint:?} is not a mint's address (https://…)")));
            }
            if mints[..at].contains(mint) {
                return Err(Wrong(format!("MINTS: {mint} twice")));
            }
        }
        let country = match get("COUNTRY") {
            "" => None,
            code if is_country(code) => Some(code.to_string()),
            code => return Err(Wrong(format!("COUNTRY={code}: two capital letters, ISO 3166-1 (DE, IS, US, …)"))),
        };
        // As the advert takes them: one line, single spaces. Longer is the
        // advert's to refuse; here it is cut, since it is only shown.
        let line = |text: &str, limit: usize| {
            text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(limit).collect()
        };
        Ok(Some(Config {
            port,
            mesh_if: match get("MESH_IF") {
                "" => "fips0".to_string(),
                name => name.to_string(),
            },
            price_msat_per_gb,
            packages,
            mints,
            name: line(get("ADVERT_NAME"), MAX_NAME),
            about: line(get("ADVERT_ABOUT"), MAX_ABOUT),
            country,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Result<Option<Config>, Wrong> {
        Config::from_settings(&settings(text))
    }

    #[test]
    fn a_value_is_read_as_the_script_reads_it() {
        let s = settings(
            "# a comment\n  # KEY=not this\nA=plain # comment\nB=\"Exit #2\"  # comment\nC='single # too'\n\
             D=\"unclosed\nE=\n=nothing\nno equals sign\n F = spaced \n",
        );
        assert_eq!(s.get("A").map(String::as_str), Some("plain"));
        assert_eq!(s.get("B").map(String::as_str), Some("Exit #2"));
        assert_eq!(s.get("C").map(String::as_str), Some("single # too"));
        assert_eq!(s.get("D").map(String::as_str), Some("unclosed"));
        assert_eq!(s.get("E").map(String::as_str), Some(""));
        assert_eq!(s.get("F").map(String::as_str), Some("spaced"));
        assert!(!s.contains_key("KEY") && !s.contains_key("# KEY") && !s.contains_key(""));
    }

    #[test]
    fn an_exit_that_does_not_sell_has_nothing_to_serve() {
        assert_eq!(config(""), Ok(None));
        assert_eq!(config("ACCESS=allow-list\nPRICE_MSAT_PER_GB=nonsense\n"), Ok(None));
    }

    #[test]
    fn a_paid_exit_is_read_whole() {
        let c = config(
            "ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\nPACKAGES=\"1gb:1GB:1500:30  5gb:5000000000:6000:90\"\n\
             MINTS=\"https://mint.example.org http://mintonion.onion\"\nADVERT_NAME=\"An   exit\"\nCOUNTRY=CH\n\
             PAY_PORT=6000\nMESH_IF=fips1\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!((c.port, c.mesh_if.as_str(), c.price_msat_per_gb), (6000, "fips1", 2_000_000));
        assert_eq!(
            c.packages,
            vec![
                Package { id: "1gb".into(), bytes: 1_000_000_000, sat: 1500, days: 30 },
                Package { id: "5gb".into(), bytes: 5_000_000_000, sat: 6000, days: 90 },
            ]
        );
        assert_eq!(c.mints, vec!["https://mint.example.org", "http://mintonion.onion"]);
        assert_eq!((c.name.as_str(), c.about.as_str(), c.country.as_deref()), ("An exit", "", Some("CH")));
        let least = config("ACCESS=paid\nPRICE_MSAT_PER_GB=1\n").unwrap().unwrap();
        assert_eq!((least.port, least.mesh_if.as_str()), (DEFAULT_PORT, "fips0"));
        assert!(least.packages.is_empty() && least.mints.is_empty() && least.country.is_none());
    }

    #[test]
    fn what_is_wrong_is_said_with_its_setting() {
        let wrong = |text: &str, setting: &str| {
            let said = config(&format!("ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\n{text}\n")).unwrap_err().0;
            assert!(said.starts_with(setting), "{text:?}: {said}");
        };
        for price in ["", "0", "+5", "02", "1e6", "1000000000001", "lots"] {
            let said = config(&format!("ACCESS=paid\nPRICE_MSAT_PER_GB={price}\n")).unwrap_err().0;
            assert!(said.starts_with("PRICE_MSAT_PER_GB"), "{price:?}: {said}");
        }
        for port in ["0", "80", "1023", "65536", "http", "05170"] {
            wrong(&format!("PAY_PORT={port}"), "PAY_PORT");
        }
        for packages in [
            "1gb",
            "1gb:1GB:1500",
            "1gb:1GB:1500:30:x",
            "1/gb:1GB:1500:30",
            ":1GB:1500:30",
            "1gb:1gB:1500:30",
            "1gb:0:1500:30",
            "1gb:1GB:0:30",
            "1gb:1GB:1500:0",
            "1gb:1GB:1500:3661",
            "1gb:1PB:1500:30",
            "a:1:1:1 a:2:2:2",
        ] {
            wrong(&format!("PACKAGES=\"{packages}\""), "PACKAGES");
        }
        let nine: Vec<String> = (0..9).map(|i| format!("p{i}:1:1:1")).collect();
        wrong(&format!("PACKAGES=\"{}\"", nine.join(" ")), "PACKAGES");
        for mints in ["ftp://m.example", "https://", "https://m.example/a\"b", "https://a.example https://a.example"] {
            wrong(&format!("MINTS='{mints}'"), "MINTS");
        }
        wrong(
            "MINTS=\"https://a.example https://b.example https://c.example https://d.example https://e.example\"",
            "MINTS",
        );
        for country in ["de", "XX", "DEU", "Germany"] {
            wrong(&format!("COUNTRY={country}"), "COUNTRY");
        }
    }

    #[test]
    fn a_size_is_bytes_or_a_decimal_unit() {
        assert_eq!(size("1500"), Some(1500));
        assert_eq!(size("500MB"), Some(500_000_000));
        assert_eq!(size("1GB"), Some(1_000_000_000));
        assert_eq!(size("2TB"), Some(2_000_000_000_000));
        for bad in ["", "GB", "1 GB", "1gb", "1GiB", "1.5GB", "01GB", "99999999999999999999TB"] {
            assert_eq!(size(bad), None, "{bad:?}");
        }
    }
}
