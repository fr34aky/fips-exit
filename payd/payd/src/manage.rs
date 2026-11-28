//! A package managed by whoever holds its key, over the mesh.
//!
//! The key is given once, when the package is made; whoever has it sees the
//! package and takes members out of it. A device is put in by nobody but
//! itself: it asks, from its own address (fips authenticates it), with the
//! key, and is moved out of whatever package it was in. And it can always
//! take itself out, with no key at all (`leave`). So a key holder cannot
//! hold a stranger's device in its package, take one out of the package it
//! paid for, or learn where one is; to add a phone, the key is given to the
//! phone, and it adds itself.
//!
//! The same, twice: as JSON for a client (fips2go), and as forms for the
//! page, which has no script.
//!
//! ```text
//! POST /v1/package           {"key"}                       the package
//! POST /v1/package/members   {"key", "add": [itself], "remove": [..]}   the package, as it is now
//! POST /v1/leave             {}                            {"left": <id> | null}
//! POST /package, /package/members, /leave                   the same, as forms, answered with a page
//! ```

use std::net::Ipv6Addr;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::http::{Site, answer};
use crate::identity::client;
use crate::store::{MAX_MEMBERS, Package, Refused};
use crate::sync::unix_now;
use crate::terms::{bytes_shown, date, escape};

/// Why a request about a package was not done, and how that is answered.
#[derive(Debug, PartialEq)]
pub enum Fault {
    /// No package has the key, or it is not one. The same answer for both:
    /// nothing is told about keys that are not.
    NoKey,
    /// Something in the request is not what it is to be.
    Bad(String),
    /// A device other than the caller was to be put in.
    NotItself,
    /// A member is in another package that is live.
    Elsewhere(Ipv6Addr),
    /// The store failed.
    Store(String),
}

impl Fault {
    fn status(&self) -> StatusCode {
        match self {
            Fault::NoKey => StatusCode::FORBIDDEN,
            Fault::Bad(_) => StatusCode::BAD_REQUEST,
            Fault::NotItself => StatusCode::FORBIDDEN,
            Fault::Elsewhere(_) => StatusCode::CONFLICT,
            Fault::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn said(&self, site: &Site) -> String {
        match self {
            Fault::NoKey => "no package has that key".into(),
            Fault::Bad(what) => what.clone(),
            Fault::NotItself => "a device is added by itself: give it the key, and add it from it".into(),
            Fault::Elsewhere(address) => format!(
                "{} is in another package; it can move itself here, from its own address, with this key",
                site.store.name_of(*address)
            ),
            Fault::Store(e) => format!("the store: {e}"),
        }
    }
}

impl From<Refused> for Fault {
    fn from(refused: Refused) -> Self {
        match refused {
            Refused::Elsewhere(address) => Fault::Elsewhere(address),
            Refused::Members => Fault::Bad(format!("a package has at most {MAX_MEMBERS} members, none twice")),
            Refused::NoPackage => Fault::NoKey,
            other => Fault::Store(other.to_string()),
        }
    }
}

/// A key as `grant` gives it: 64 hex digits, in either case. Anything else
/// is no key, and is not looked for.
pub fn key_of(key: &str) -> Option<String> {
    let key = key.trim().to_ascii_lowercase();
    (key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())).then_some(key)
}

fn by_key(site: &Site, key: &str) -> Result<Package, Fault> {
    let key = key_of(key).ok_or(Fault::NoKey)?;
    site.store.package_with_key(&key)?.ok_or(Fault::NoKey)
}

/// `who` as an address, and the npub it was named by, if it was.
fn named(who: &str) -> Result<(Ipv6Addr, Option<String>), Fault> {
    client(who).ok_or_else(|| Fault::Bad(format!("{who:.80} is neither an npub nor a fips address")))
}

/// Take out `remove`, and put in `add`, which can only be the caller.
fn change(site: &Site, caller: Ipv6Addr, key: &str, add: &[String], remove: &[String]) -> Result<Package, Fault> {
    if add.len() > 1 || remove.len() > MAX_MEMBERS {
        return Err(Fault::Bad("too many at once".into()));
    }
    let key = key_of(key).ok_or(Fault::NoKey)?;
    let join = match add.first() {
        Some(who) => {
            let (address, npub) = named(who)?;
            if address != caller {
                return Err(Fault::NotItself);
            }
            Some((address, npub))
        }
        None => None,
    };
    let remove: Vec<Ipv6Addr> = remove.iter().map(|who| named(who).map(|(a, _)| a)).collect::<Result<_, _>>()?;
    let package = site.store.change_members(&key, join.as_ref().map(|(a, _)| *a), &remove, unix_now())?;
    // The npub the device added itself by, kept now that it is in.
    if let Some((address, Some(npub))) = join {
        site.store.remember(address, &npub)?;
    }
    site.changed.notify_one();
    Ok(package)
}

fn leave(site: &Site, caller: Ipv6Addr) -> Result<Option<String>, Fault> {
    let left = site.store.leave(caller)?;
    if left.is_some() {
        site.changed.notify_one();
    }
    Ok(left)
}

/// A package as its key holder sees it.
#[derive(Debug, Serialize)]
pub struct View {
    id: String,
    standing: String,
    bytes_left: u64,
    until: Option<u64>,
    members: Vec<Member>,
    /// Whether the caller is one of them.
    you: bool,
}

#[derive(Debug, Serialize)]
struct Member {
    address: Ipv6Addr,
    /// Its npub if it was named by one, and otherwise its address.
    name: String,
}

pub fn view(site: &Site, package: &Package, caller: Ipv6Addr) -> View {
    View {
        id: package.id.clone(),
        standing: package.standing(unix_now()).word().to_string(),
        bytes_left: package.left(),
        until: (package.until != 0).then_some(package.until),
        members: package.members.iter().map(|m| Member { address: *m, name: site.store.name_of(*m) }).collect(),
        you: package.members.contains(&caller),
    }
}

// ---- as JSON ----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithKey {
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Changes {
    key: String,
    #[serde(default)]
    add: Vec<String>,
    #[serde(default)]
    remove: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Nothing {}

fn json(status: StatusCode, value: &impl Serialize) -> Response<Full<Bytes>> {
    answer(status, "application/json", serde_json::to_vec(value).unwrap_or_default())
}

fn json_fault(site: &Site, fault: &Fault) -> Response<Full<Bytes>> {
    json(fault.status(), &serde_json::json!({ "error": fault.said(site) }))
}

/// A JSON request to `path`, from `caller`.
pub fn as_json(site: &Site, caller: Ipv6Addr, path: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let bad = |e: serde_json::Error| Fault::Bad(format!("not the request this is: {e}"));
    // An object, with its fields named: serde would take a list of the
    // fields' values as well, which nobody means to send.
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return json_fault(site, &Fault::Bad("not the request this is: a JSON object".into()));
    }
    let done = match path {
        "/v1/package" => serde_json::from_slice::<WithKey>(body)
            .map_err(bad)
            .and_then(|asked| by_key(site, &asked.key))
            .map(|package| serde_json::to_value(view(site, &package, caller))),
        "/v1/package/members" => serde_json::from_slice::<Changes>(body)
            .map_err(bad)
            .and_then(|asked| change(site, caller, &asked.key, &asked.add, &asked.remove))
            .map(|package| serde_json::to_value(view(site, &package, caller))),
        "/v1/leave" => serde_json::from_slice::<Nothing>(body)
            .map_err(bad)
            .and_then(|_| leave(site, caller))
            .map(|left| Ok(serde_json::json!({ "left": left }))),
        _ => Err(Fault::Bad("nothing here".into())),
    };
    match done {
        Ok(Ok(value)) => json(StatusCode::OK, &value),
        Ok(Err(e)) => json_fault(site, &Fault::Store(e.to_string())),
        Err(fault) => json_fault(site, &fault),
    }
}

// ---- as forms, for the page --------------------------------------------------

/// `a=1&b=x+y` as pairs, percent-decoded. What is not UTF-8 is replaced.
pub fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    let decode = |text: &[u8]| {
        let mut out = Vec::with_capacity(text.len());
        let mut at = 0;
        while at < text.len() {
            match text[at] {
                b'+' => {
                    out.push(b' ');
                    at += 1;
                }
                // Two hex digits, and nothing else (a sign is no digit).
                b'%' if text.get(at + 1..at + 3).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) => {
                    let hex = std::str::from_utf8(&text[at + 1..at + 3]).unwrap_or("00");
                    out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                    at += 3;
                }
                byte => {
                    out.push(byte);
                    at += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    body.split(|b| *b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.iter().position(|b| *b == b'=') {
            Some(at) => (decode(&pair[..at]), decode(&pair[at + 1..])),
            None => (decode(pair), String::new()),
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.trim())
}

/// The page for a package's key holder: who is in it, and forms to change
/// that. `notice` says what was done, or what went wrong.
pub fn page(site: &Site, package: &Package, key: &str, caller: Ipv6Addr, notice: &str) -> String {
    let v = view(site, package, caller);
    // What is bought here is added to this package, while anything is sold.
    let add = if site.methods().is_empty() || v.standing == "revoked" {
        String::new()
    } else {
        crate::terms::buy_form(&site.config.packages, Some(key), &site.methods())
    };
    let key = escape(key);
    let mut rows = String::new();
    for m in &v.members {
        let you = if m.address == caller { " (this device)" } else { "" };
        rows.push_str(&format!(
            "<tr><td><code>{name}</code>{you}</td><td><form method=\"post\" action=\"/package/members\">\
             <input type=\"hidden\" name=\"key\" value=\"{key}\"><input type=\"hidden\" name=\"remove\" value=\"{name}\">\
             <button>Remove</button></form></td></tr>\n",
            name = escape(&m.name)
        ));
    }
    let members =
        if rows.is_empty() { "<p>Nobody is in it.</p>".to_string() } else { format!("<table>\n{rows}</table>") };
    let now = match v.standing.as_str() {
        "live" => format!(
            "<strong>{}</strong> left{}.",
            bytes_shown(v.bytes_left),
            v.until.map(|until| format!(", until {}", date(until))).unwrap_or_default()
        ),
        "used-up" => "It is used up.".to_string(),
        "over" => "Its time is over.".to_string(),
        _ => "It was taken back by the operator.".to_string(),
    };
    let join = if v.you {
        String::new()
    } else {
        format!(
            "<form method=\"post\" action=\"/package/members\"><input type=\"hidden\" name=\"key\" value=\"{key}\">\
             <input type=\"hidden\" name=\"add\" value=\"{caller}\"><button>Add this device</button></form>\n"
        )
    };
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"note\">{}</p>\n", escape(notice)) };
    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>Package {id}</title>
<link rel=\"stylesheet\" href=\"/style.css\">
</head>
<body>
<main>
<h1>Package <code>{id}</code></h1>
<p class=\"who\"><code>{exit}.fips</code></p>
{notice}<p>{now}</p>
<h2>Who is in it</h2>
{members}
{join}{add}<p class=\"you\">Another device is added by itself: give it this package's key, open this exit's page on it, and add it there. Whoever has the key sees who is in the package and can take them out: keep it to those it is for. A device can always take itself out of a package, from the exit's page.</p>
<p><a href=\"/\">Back</a></p>
</main>
</body>
</html>
",
        id = escape(&package.id),
        exit = escape(&site.exit.npub),
    )
}

fn html(status: StatusCode, text: String) -> Response<Full<Bytes>> {
    answer(status, "text/html; charset=utf-8", text)
}

/// A form sent from the page to `path`, from `caller`.
pub fn as_form(site: &Site, caller: Ipv6Addr, path: &str, body: &[u8]) -> Response<Full<Bytes>> {
    let fields = form_fields(body);
    let key = key_of(field(&fields, "key").unwrap_or("")).unwrap_or_default();
    let plain = |status: StatusCode, text: String| {
        html(
            status,
            format!(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" \
                 content=\"width=device-width, initial-scale=1\"><title>Package</title><link rel=\"stylesheet\" \
                 href=\"/style.css\"></head><body><main><p class=\"note\">{}</p><p><a href=\"/\">Back</a></p></main>\
                 </body></html>\n",
                escape(&text)
            ),
        )
    };
    match path {
        "/package" => match by_key(site, &key) {
            Ok(package) => html(StatusCode::OK, page(site, &package, &key, caller, "")),
            Err(fault) => plain(fault.status(), fault.said(site)),
        },
        "/package/members" => {
            let one = |name: &str| field(&fields, name).filter(|v| !v.is_empty()).map(|v| vec![v.to_string()]);
            let (add, remove) = (one("add").unwrap_or_default(), one("remove").unwrap_or_default());
            match change(site, caller, &key, &add, &remove) {
                Ok(package) => {
                    let done = match (add.first(), remove.first()) {
                        (Some(who), _) => format!("{who} is in the package now."),
                        (_, Some(who)) => format!("{who} is out of the package now."),
                        _ => String::new(),
                    };
                    html(StatusCode::OK, page(site, &package, &key, caller, &done))
                }
                // Still the key holder: the page again, with what went wrong.
                Err(fault @ (Fault::Elsewhere(_) | Fault::Bad(_))) => match by_key(site, &key) {
                    Ok(package) => html(fault.status(), page(site, &package, &key, caller, &fault.said(site))),
                    Err(other) => plain(other.status(), other.said(site)),
                },
                Err(fault) => plain(fault.status(), fault.said(site)),
            }
        }
        "/leave" => match leave(site, caller) {
            Ok(Some(id)) => plain(StatusCode::OK, format!("This device is out of package {id} now.")),
            Ok(None) => plain(StatusCode::OK, "This device was in no package.".into()),
            Err(fault) => plain(fault.status(), fault.said(site)),
        },
        _ => plain(StatusCode::NOT_FOUND, "nothing here".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::{Config, settings};
    use crate::store::Store;
    use crate::sync::Seats;
    use crate::terms::Exit;

    const NPUB: &str = "npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl";
    const NPUB_ADDRESS: &str = "fd14:af5b:b52d:a042:618:847d:f4e1:32dc";

    fn site() -> Site {
        let config = Config::from_settings(&settings("ACCESS=paid\nPRICE_MSAT_PER_GB=1\n")).unwrap().unwrap();
        let exit = Exit {
            npub: "npub1exit".into(),
            address: "fd00::e".parse().unwrap(),
            name: String::new(),
            about: String::new(),
            country: None,
        };
        Site::new(config, exit, Arc::new(Store::in_memory()), Seats::default(), Arc::default())
    }

    fn a(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn call(site: &Site, caller: &str, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = as_json(site, a(caller), path, body.to_string().as_bytes());
        let status = response.status();
        let bytes = futures_body(response);
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    fn futures_body(response: Response<Full<Bytes>>) -> Bytes {
        use http_body_util::BodyExt;
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(response.into_body().collect()).unwrap().to_bytes()
    }

    #[test]
    fn the_key_holder_sees_the_package_and_says_who_is_in_it() {
        let site = site();
        let (id, key) = site.store.grant(1_000_000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let (status, seen) = call(&site, "fd77::7", "/v1/package", serde_json::json!({ "key": key }));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(seen["id"], id.as_str());
        assert_eq!(seen["standing"], "live");
        assert_eq!(seen["members"], serde_json::json!([{"address": "fd99::1", "name": "fd99::1"}]));
        assert_eq!(seen["you"], false);
        // The key holder adds itself, and takes another out.
        let (status, seen) = call(
            &site,
            "fd77::7",
            "/v1/package/members",
            serde_json::json!({ "key": key, "add": ["fd77::7"], "remove": ["fd99::1"] }),
        );
        assert_eq!(status, StatusCode::OK, "{seen}");
        assert_eq!(seen["members"], serde_json::json!([{"address": "fd77::7", "name": "fd77::7"}]));
        assert_eq!(seen["you"], true);
        // A device that adds itself by its npub is shown by it.
        let (status, seen) =
            call(&site, NPUB_ADDRESS, "/v1/package/members", serde_json::json!({ "key": key, "add": [NPUB] }));
        assert_eq!(status, StatusCode::OK, "{seen}");
        let added = seen["members"].as_array().unwrap().iter().find(|m| m["address"] == NPUB_ADDRESS).cloned();
        assert_eq!(added, Some(serde_json::json!({"address": NPUB_ADDRESS, "name": NPUB})));
        assert_eq!(site.store.package_of(a(NPUB_ADDRESS)).unwrap().unwrap().id, id);
        // The key in capitals is the same key.
        let (status, _) = call(&site, "fd77::7", "/v1/package", serde_json::json!({ "key": key.to_uppercase() }));
        assert_eq!(status, StatusCode::OK);
    }

    /// A key holder cannot put another device in: not one in no package,
    /// not one in another package, live or waiting for a top-up. Nor is its
    /// npub remembered, nor is it told where that device is.
    #[test]
    fn nobody_is_put_in_but_by_itself() {
        let site = site();
        let (_, key) = site.store.grant(1000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let (elsewhere, _) = site.store.grant(1, 0, &[a("fd55::5")], "", unix_now()).unwrap();
        site.store.fold_usage(&elsewhere, 1, 0).unwrap();
        for stranger in [NPUB, "fd44::4", "fd55::5"] {
            let (status, said) =
                call(&site, "fd99::1", "/v1/package/members", serde_json::json!({ "key": key, "add": [stranger] }));
            assert_eq!(status, StatusCode::FORBIDDEN, "{stranger}: {said}");
            assert_eq!(said["error"], "a device is added by itself: give it the key, and add it from it");
        }
        assert_eq!(site.store.package_of(a("fd55::5")).unwrap().unwrap().id, elsewhere, "left where it was");
        assert_eq!(site.store.name_of(a(NPUB_ADDRESS)), NPUB_ADDRESS, "a stranger's npub is not kept");
        // Taking out what is not a member, by npub, keeps nothing either.
        let (status, _) =
            call(&site, "fd99::1", "/v1/package/members", serde_json::json!({ "key": key, "remove": [NPUB] }));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(site.store.name_of(a(NPUB_ADDRESS)), NPUB_ADDRESS);
        let two = serde_json::json!({ "key": key, "add": ["fd99::1", "fd99::1"] });
        assert_eq!(call(&site, "fd99::1", "/v1/package/members", two).0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_wrong_key_is_told_nothing() {
        let site = site();
        let (_, key) = site.store.grant(1000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let other = "0".repeat(64);
        for wrong in [other.as_str(), "", "short", &format!("{key}0"), &format!("{}g", &key[..63])] {
            let (status, said) = call(&site, "fd77::7", "/v1/package", serde_json::json!({ "key": wrong }));
            assert_eq!((status, said["error"].as_str()), (StatusCode::FORBIDDEN, Some("no package has that key")));
            let (status, _) =
                call(&site, "fd77::7", "/v1/package/members", serde_json::json!({ "key": wrong, "add": ["fd77::7"] }));
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        assert_eq!(site.store.package_of(a("fd77::7")).unwrap(), None);
        // What is not this request at all.
        for body in [serde_json::json!({}), serde_json::json!({"key": key, "extra": 1}), serde_json::json!([key])] {
            assert_eq!(call(&site, "fd77::7", "/v1/package", body).0, StatusCode::BAD_REQUEST);
        }
        let (status, said) =
            call(&site, "fd77::7", "/v1/package/members", serde_json::json!({ "key": key, "add": ["2001:db8::1"] }));
        assert_eq!(status, StatusCode::BAD_REQUEST, "{said}");
    }

    /// Nobody can be held in a stranger's package: put into one by its key
    /// holder, an address is refused if it is in another live package, and
    /// can always move itself, or leave.
    #[test]
    fn a_device_belongs_to_itself() {
        let site = site();
        let (mine, my_key) = site.store.grant(1000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let (theirs, their_key) = site.store.grant(1000, 0, &[a("fd55::5")], "", unix_now()).unwrap();
        // The other key holder cannot take fd99::1.
        let (status, said) =
            call(&site, "fd55::5", "/v1/package/members", serde_json::json!({ "key": their_key, "add": ["fd99::1"] }));
        assert_eq!(status, StatusCode::FORBIDDEN, "{said}");
        assert_eq!(site.store.package_of(a("fd99::1")).unwrap().unwrap().id, mine);
        // fd99::1, with their key, can move itself there.
        let (status, _) =
            call(&site, "fd99::1", "/v1/package/members", serde_json::json!({ "key": their_key, "add": ["fd99::1"] }));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(site.store.package_of(a("fd99::1")).unwrap().unwrap().id, theirs);
        // And leave, with no key at all.
        let (status, said) = call(&site, "fd99::1", "/v1/leave", serde_json::json!({}));
        assert_eq!((status, said), (StatusCode::OK, serde_json::json!({ "left": theirs })));
        let (_, said) = call(&site, "fd99::1", "/v1/leave", serde_json::json!({}));
        assert_eq!(said, serde_json::json!({ "left": null }));
        assert!(site.store.package_with_key(&my_key).unwrap().unwrap().members.is_empty());
    }

    #[test]
    fn a_form_is_decoded() {
        let fields = form_fields(b"key=ab%2Fc&add=npub1x+y&empty=&bare&bad=%zz%4&plus=%2B");
        assert_eq!(
            fields,
            vec![
                ("key".into(), "ab/c".into()),
                ("add".into(), "npub1x y".into()),
                ("empty".into(), "".into()),
                ("bare".into(), "".into()),
                ("bad".into(), "%zz%4".into()),
                ("plus".into(), "+".into()),
            ]
        );
        assert_eq!(form_fields(b"x=%+1"), vec![("x".into(), "% 1".into())], "a sign is no hex digit");
        assert_eq!(form_fields(b""), vec![]);
    }

    #[test]
    fn the_page_manages_a_package() {
        let site = site();
        let (id, key) = site.store.grant(1000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let body = |text: String| {
            String::from_utf8(futures_body(as_form(&site, a("fd77::7"), "/package", text.as_bytes())).to_vec()).unwrap()
        };
        let shown = body(format!("key={key}"));
        assert!(shown.contains(&format!("Package <code>{id}</code>")) && shown.contains("fd99::1"), "{shown}");
        assert!(shown.contains("Add this device"));
        let added = as_form(&site, a("fd77::7"), "/package/members", format!("key={key}&add=fd77%3A%3A7").as_bytes());
        assert_eq!(added.status(), StatusCode::OK);
        assert_eq!(site.store.package_of(a("fd77::7")).unwrap().unwrap().id, id);
        let wrong = as_form(&site, a("fd77::7"), "/package", b"key=nope");
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        let left = as_form(&site, a("fd77::7"), "/leave", b"");
        assert_eq!(left.status(), StatusCode::OK);
        assert_eq!(site.store.package_of(a("fd77::7")).unwrap(), None);
    }
}
