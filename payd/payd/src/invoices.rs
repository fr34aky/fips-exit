//! Buying a package with Lightning, over the mesh.
//!
//! ```text
//! POST /v1/orders              {"package", "method": "bolt11", "key"?, "mint"?}   an order, with its invoice
//! GET  /v1/orders/<order>                                                      what became of it
//! POST /v1/orders/<order>/key  {}                                              a key for the package it made
//! POST /buy                    the same as a form (method=bolt11): on to its order's page
//! GET  /order/<order>          that page: the invoice while it waits, then what it bought
//! POST /order/<order>/key      a key, as a page
//! ```
//!
//! The exit runs no Lightning node. The mint gives the invoice (a quote of
//! its own, NUT-23), and when that is paid the wallet mints ecash for it:
//! what is paid arrives in the exit's wallet as a token's worth does, and
//! only then is anything granted, in the one place where an order becomes
//! a package ([`Store::order_settle`]).
//!
//! An order is written down before its invoice is shown to anyone: no
//! invoice can be paid that this exit does not know of. From then on the
//! mint is asked what became of it, one invoice at a time and not often
//! (a mint is asked little): sooner for one whose buyer is asking, later
//! the older it gets. What the mint says decides:
//!
//! ```text
//! not paid           it waits; given up once its invoice has ended, and a while more
//! paid               the wallet mints for it, and what arrives is the payment
//! paid, and minted   for this wallet, which alone knows the quote and holds its key: the payment
//! ```
//!
//! An order is given up only on the mint's word, asked after its invoice
//! has ended. One that was paid while this service was not running is
//! found at its next start, however late that is.
//!
//! An order is its buyer's: the address that asked sees it, and nobody
//! else. The package it makes has a key that nobody was shown. Its buyer
//! asks for one, and each key asked for takes the place of the one before.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::http::{Site, answer};
use crate::manage;
use crate::orders::{Asked, Desk, Fault, Kind, found_again, json, key_asked, page, refuse_as, settle, whose};
use crate::qr;
use crate::store::{BOLT11, NewInvoice, Order, Store};
use crate::sync::unix_now;
use crate::terms::{bytes_shown, date, escape};
use crate::wallet::{MINT_TIME, Mint, Paid};

/// How many invoices may wait to be paid for one address, and in all. An
/// invoice costs its asker nothing, and cannot be taken back once it is
/// given: so there are few for anyone, and what bounds them for everyone
/// together is the budget they are asked of a mint from.
const WAITING_FOR_ONE: usize = 3;
const WAITING_IN_ALL: usize = 512;
/// How long after its end an invoice is still asked about: a payment that
/// was under way when it ended arrives after it.
const GRACE: u64 = 600;
/// One invoice is asked about at a mint this often, at most.
const LOOK: Duration = Duration::from_secs(3);
/// An invoice nobody is asking about is looked at this long after the last
/// time, at the least and at the most: more seldom the older it is.
const PACE: (u64, u64) = (5, 60);
/// How long an order that was given up is still there to be asked about.
const KEPT: u64 = 86_400;
/// How often the page of an invoice that waits looks again, in seconds.
const REFRESH: &str = "5";

/// What is kept, while the service runs, of the invoices that wait.
pub struct Waiting {
    /// The orders whose buyer asked what became of them since they were
    /// last looked at.
    wanted: Mutex<HashSet<String>>,
    /// The orders for which the wallet was made to count again, the mint
    /// having refused to mint for them as for something signed before:
    /// once for an order, whatever the mint says after.
    recounted: Mutex<HashSet<String>>,
    /// Told when there is an invoice to look at.
    pub look: Notify,
    /// [`LOOK`], [`GRACE`] and [`PACE`], which a test shortens.
    pub every: Duration,
    pub grace: u64,
    pub pace: (u64, u64),
}

impl Default for Waiting {
    fn default() -> Self {
        Waiting {
            wanted: Mutex::default(),
            recounted: Mutex::default(),
            look: Notify::new(),
            every: LOOK,
            grace: GRACE,
            pace: PACE,
        }
    }
}

impl Waiting {
    fn wanted(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.wanted.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The mint to ask for an invoice of `sat`: the one that is `named`, or the
/// first that is reached and gives one for that much.
fn mint_for<'a>(desk: &'a Desk, named: Option<&str>, sat: u64) -> Result<&'a Arc<Mint>, Fault> {
    let mints = &desk.wallets.mints;
    if let Some(name) = named {
        let mint = desk.wallets.named(name).ok_or_else(|| Fault::WrongMint(name.to_string()))?;
        if !mint.ready() {
            return Err(Fault::MintAway(mint.name.clone()));
        }
        if !mint.gives_invoices(Some(sat)) {
            return Err(Fault::NoInvoice(format!("The mint {} gives no invoice for {sat} sat.", mint.name)));
        }
        return Ok(mint);
    }
    if let Some(mint) = mints.iter().find(|mint| mint.ready() && mint.gives_invoices(Some(sat))) {
        return Ok(mint);
    }
    match mints.first() {
        Some(away) if !desk.wallets.ready() => Err(Fault::MintAway(away.name.clone())),
        _ => Err(Fault::NoInvoice(format!("No mint this exit accepts gives an invoice for {sat} sat."))),
    }
}

/// Order what `asked` asks for, for `caller`, to be paid by an invoice: the
/// order, with its invoice. Answered by `until`.
pub async fn order(site: &Arc<Site>, caller: Ipv6Addr, asked: &Asked, until: Instant) -> Result<Order, Fault> {
    let desk = site.desk.as_ref().ok_or(Fault::NotSold)?;
    if asked.method.as_deref() != Some(BOLT11) {
        return Err(Fault::Bad(format!(
            "no such way to pay: {:.40} (cashu, with a token; or bolt11, for an invoice)",
            asked.method.as_deref().unwrap_or_default()
        )));
    }
    if !asked.token.trim().is_empty() {
        return Err(Fault::Bad("an invoice is asked for, and a token was sent too: one or the other".into()));
    }
    let offer = site
        .config
        .packages
        .iter()
        .find(|offer| offer.id == asked.package)
        .ok_or_else(|| Fault::NoOffer(asked.package.clone()))?;
    let key = key_asked(asked)?;
    let mint = mint_for(desk, asked.mint.as_deref(), offer.sat)?;
    let target = tokio::time::timeout_at(until, whose(site, desk, caller, offer, key.as_deref()))
        .await
        .map_err(|_| Fault::Again)??;
    let id = Store::order_id()?;
    // One at a time for an address: so that what it has waiting is counted
    // before another is added to it.
    let _at_work = desk.enter(&id, caller).ok_or(Fault::Busy)?;
    let now = unix_now();
    let (its, all) = site.store.invoices_waiting(caller, now)?;
    if its >= WAITING_FOR_ONE {
        return Err(Fault::TooMany(its));
    }
    if all >= WAITING_IN_ALL || !desk.spend() {
        return Err(Fault::Busy);
    }
    let about = format!("fips exit: {}", offer.id);
    let of_the_mint = async {
        let _turn = mint.turn.lock().await;
        mint.invoice(offer.sat, &about).await
    };
    let quote = match tokio::time::timeout_at(until, of_the_mint).await {
        Ok(Ok(quote)) if quote.expires > now => quote,
        Ok(Ok(_)) => return Err(Fault::NoInvoice(format!("The mint {} gave an invoice that has ended.", mint.name))),
        Ok(Err(e)) => {
            eprintln!("fips-exit-payd: {}: no invoice of {} sat: {e}", mint.name, offer.sat);
            return Err(Fault::NoInvoice(format!("The mint {} gave no invoice: {e}", mint.name)));
        }
        Err(_) => return Err(Fault::Again),
    };
    // Written down before anyone sees the invoice. If this does not come to
    // pass, the mint has a quote nobody knows how to pay.
    let new = NewInvoice {
        buyer: caller,
        mint: &mint.name,
        offer: &offer.id,
        bytes: offer.bytes,
        sat: offer.sat,
        days: offer.days,
        target: target.as_deref(),
        quote: &quote.id,
        quote_key: quote.key.as_deref(),
        request: &quote.request,
        expires: quote.expires,
    };
    site.store.invoice_begin(&id, &new, now)?;
    desk.invoices.look.notify_one();
    site.store.order(&id)?.ok_or(Fault::NoOrder)
}

/// Is `id` written as an order's name is: `o` and 16 small hex digits?
fn is_order_id(id: &str) -> bool {
    id.len() == 17 && id.starts_with('o') && id[1..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The order `id`, for `caller`: its buyer sees it, and nobody else learns
/// that it is there. Asking about an invoice that waits has it looked at
/// soon.
pub fn of(site: &Site, caller: Ipv6Addr, id: &str) -> Result<Order, Fault> {
    if !is_order_id(id) {
        return Err(Fault::NoOrder);
    }
    let order = site.store.order(id)?.filter(|order| order.buyer == caller).ok_or(Fault::NoOrder)?;
    if order.method == BOLT11
        && !order.paid
        && order.ended == 0
        && let Some(desk) = &site.desk
        && desk.invoices.wanted().insert(order.id.clone())
    {
        desk.invoices.look.notify_one();
    }
    Ok(order)
}

/// A new key for the package order `id` made, for `caller`, its buyer. The
/// key before it opens nothing any more.
///
/// For an order paid by invoice: nobody was shown that package's key. One
/// paid with a token was answered with its key, and has it again by sending
/// the token again.
pub fn new_key(site: &Site, caller: Ipv6Addr, id: &str) -> Result<(Order, String), Fault> {
    let order = of(site, caller, id)?;
    if order.method != BOLT11 {
        return Err(Fault::NoNewKey);
    }
    if !order.paid {
        return Err(Fault::NotPaid);
    }
    let key = site.store.order_new_key(&order.id)?.ok_or(Fault::NoNewKey)?;
    Ok((order, key))
}

/// `waiting`, `paid`, or `expired`: given up, its invoice having ended
/// unpaid.
fn state(order: &Order) -> &'static str {
    match order {
        order if order.paid => "paid",
        order if order.ended > 0 => "expired",
        _ => "waiting",
    }
}

/// Whether what `order` paid for was added to the package it was asked for.
fn added(order: &Order) -> bool {
    order.target.is_some() && order.target == order.package
}

/// An order, for a program.
pub fn view(order: &Order) -> serde_json::Value {
    let mut said = serde_json::json!({
        "order": order.id,
        "state": state(order),
        "method": order.method,
        "offer": order.offer,
        "bytes": order.bytes,
        "days": order.days,
        "sat": order.sat,
        "mint": order.mint,
    });
    if order.paid {
        said["paid_sat"] = order.paid_sat.into();
        said["added"] = added(order).into();
        said["package"] = serde_json::json!({ "id": order.package });
    } else if order.ended == 0 && order.method == BOLT11 {
        said["request"] = order.request.clone().into();
        said["expires"] = order.expires.into();
    }
    said
}

// ---- what became of them ------------------------------------------------------

/// Is `order` to be looked at now? `asked` is whether its buyer asked;
/// `looked` is how long ago it was last looked at, if it was since the
/// service started.
fn due(order: &Order, asked: bool, looked: Option<Duration>, waiting: &Waiting, now: u64) -> bool {
    if asked {
        return looked.is_none_or(|ago| ago >= waiting.every);
    }
    let age = now.saturating_sub(order.created);
    let pace = (age / 8).clamp(waiting.pace.0, waiting.pace.1);
    looked.map_or(age, |ago| ago.as_secs()) >= pace
}

/// Ask `mint` what became of `order`'s invoice, and act on it.
async fn look_at(site: &Site, desk: &Desk, mint: &Mint, order: &Order) {
    let Some(quote) = &order.quote else { return };
    let _turn = mint.turn.lock().await;
    let paid = match mint.quote_state(quote, order.quote_key.as_deref()).await {
        Ok(paid) => paid,
        Err(e) => {
            eprintln!("fips-exit-payd: order {}: {} did not say what became of its invoice: {e}", order.id, mint.name);
            return;
        }
    };
    match paid {
        // Given up on the mint's word, and only after the invoice's end: it
        // cannot be paid any more, and what was under way has arrived.
        Paid::No if unix_now() > order.expires.saturating_add(desk.invoices.grace) => {
            if let Err(e) = site.store.invoice_end(&order.id, unix_now()) {
                eprintln!("fips-exit-payd: order {}: {e}", order.id);
            }
        }
        Paid::No => {}
        Paid::Yes => match tokio::time::timeout(MINT_TIME, mint.mint_paid(quote)).await {
            Ok(Ok(sat)) => {
                let _ = settle(site, mint, &order.id, sat);
            }
            // Not minted: the invoice is paid all the same, and the order
            // stays until it is. The wallet finishes what it began when the
            // mint is asked about the quote again.
            Ok(Err(e)) => {
                // Refused as signed before (a mint says it in one of these
                // ways; the last is how one says it of a request to mint):
                // the wallet's file is behind its seed's use, and it counts
                // again before anything else is asked there. Once for an
                // order: a mint that goes on refusing is not asked to count
                // over and over.
                let signed_before = matches!(
                    e,
                    cdk::Error::BlindedMessageAlreadySigned
                        | cdk::Error::DuplicateOutputs
                        | cdk::Error::RequestAlreadyPaid
                );
                let first =
                    || desk.invoices.recounted.lock().unwrap_or_else(|p| p.into_inner()).insert(order.id.clone());
                if signed_before && first() {
                    mint.suspect();
                }
                eprintln!(
                    "fips-exit-payd: order {}: its invoice is paid, and {} has not minted for it yet: {e}",
                    order.id, mint.name
                );
            }
            Err(_) => eprintln!(
                "fips-exit-payd: order {}: its invoice is paid, and {} did not answer in time when asked to mint \
                 for it",
                order.id, mint.name
            ),
        },
        // Minted, and this service did not hear of it (the mint's answer
        // was lost, or the service stopped): the mint mints a quote for the
        // wallet that knows it and holds its key, so it arrived. If the
        // wallet does not hold it, it is found again from the seed.
        Paid::Minted(sat) => {
            let sat = if sat == 0 { order.sat } else { sat };
            if settle(site, mint, &order.id, sat).is_ok() {
                found_again(site, mint).await;
            }
        }
    }
}

/// Look at the invoice that is most due, if one is. How many wait.
async fn round(site: &Site, desk: &Desk, looked: &mut HashMap<String, Instant>) -> usize {
    let now = unix_now();
    if let Err(e) = site.store.invoices_forget(now.saturating_sub(KEPT)) {
        eprintln!("fips-exit-payd: orders that were given up could not be forgotten: {e}");
    }
    let open = match site.store.invoices_open() {
        Ok(open) => open,
        Err(e) => {
            eprintln!("fips-exit-payd: the invoices that wait could not be read: {e}");
            return 0;
        }
    };
    looked.retain(|id, _| open.iter().any(|order| order.id == *id));
    desk.invoices.recounted.lock().unwrap_or_else(|p| p.into_inner()).retain(|id| open.iter().any(|o| o.id == *id));
    let wanted: HashSet<String> = {
        let mut wanted = desk.invoices.wanted();
        wanted.retain(|id| open.iter().any(|order| order.id == *id));
        wanted.clone()
    };
    // Of those that are due at a mint that is there: one that is asked
    // about first, and then the one not looked at for longest.
    let ago = |order: &Order| looked.get(&order.id).map(Instant::elapsed);
    let next = open
        .iter()
        .filter(|order| due(order, wanted.contains(&order.id), ago(order), &desk.invoices, now))
        .filter_map(|order| Some((order, desk.wallets.named(&order.mint).filter(|mint| mint.ready())?)))
        .max_by_key(|(order, _)| (wanted.contains(&order.id), ago(order).is_none(), ago(order)));
    if let Some((order, mint)) = next {
        looked.insert(order.id.clone(), Instant::now());
        desk.invoices.wanted().remove(&order.id);
        look_at(site, desk, mint, order).await;
    }
    open.len()
}

/// Look at the invoices that wait, for as long as the service runs: one at
/// a time, [`LOOK`] apart, and not at all while there are none.
pub async fn keep(site: Arc<Site>) {
    let Some(desk) = site.desk.clone() else { return };
    let mut looked = HashMap::new();
    loop {
        let waiting = round(&site, &desk, &mut looked).await;
        tokio::time::sleep(desk.invoices.every).await;
        if waiting == 0 {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(600)) => {}
                () = desk.invoices.look.notified() => {}
            }
        }
    }
}

// ---- answers ------------------------------------------------------------------

/// An order's page.
fn order_page(site: &Site, caller: Ipv6Addr, order: &Order) -> Response<Full<Bytes>> {
    let what = format!("{} ({}, {} days)", escape(&order.offer), bytes_shown(order.bytes), order.days);
    let back = "<p><a href=\"/\">Back</a></p>\n";
    if order.paid {
        let package = order.package.as_deref().unwrap_or_default();
        let did = if added(order) { "was added to" } else { "is" };
        let mut body = format!(
            "<p class=\"note\">Paid: {} sat arrived, and {} {did} package {}.</p>\n",
            order.paid_sat,
            escape(&order.offer),
            escape(package)
        );
        if let Ok(Some(package)) = site.store.package(package) {
            let until = match package.until {
                0 => String::new(),
                until => format!(", until {}", date(until)),
            };
            if package.members.contains(&caller) {
                body.push_str(&format!(
                    "<p>This device is in it: <strong>{}</strong>{until}.</p>\n",
                    bytes_shown(package.left())
                ));
            }
            if order.method == BOLT11 && !added(order) && !package.revoked {
                body.push_str(&format!(
                    "<h2>Its key</h2>\n<p>Whoever has a package's key sees who is in it, takes devices out of it, and \
                     adds to it. Nobody has been shown this one's. A key shown here takes the place of any shown \
                     before.</p>\n<form method=\"post\" action=\"/order/{}/key\"><button>Show a key for it</button>\
                     </form>\n",
                    order.id
                ));
            }
        }
        body.push_str(back);
        return page(StatusCode::OK, "Paid", &body);
    }
    if order.ended > 0 || order.method != BOLT11 {
        let said = if order.ended > 0 {
            "This order's invoice ended unpaid. Nothing was bought."
        } else {
            "What became of this order's token is not known yet."
        };
        return page(StatusCode::OK, "Not bought", &format!("<p class=\"note\">{said}</p>\n{back}"));
    }
    let request = order.request.as_deref().unwrap_or_default();
    let adds = match &order.target {
        Some(target) => format!(" is added to package {}", escape(target)),
        None => " is a package of this device's".to_string(),
    };
    let body = format!(
        "<p class=\"note\">Pay this invoice of <strong>{sat} sat</strong>, and {what}{adds}.</p>\n{code}\
         <p><a href=\"lightning:{request}\">Open it in a wallet on this device</a></p>\n\
         <p><code>{request}</code></p>\n\
         <p>It ends {ends}. What is paid after that is lost: do not pay it late.</p>\n\
         <p class=\"you\">This page looks again by itself every few seconds, and says so when the payment has \
         arrived. The package is there once it has, whether or not this page is open.</p>\n{back}",
        sat = order.sat,
        code = qr::of_invoice(request).map(|code| format!("<p>{code}</p>\n")).unwrap_or_default(),
        request = escape(request),
        ends = date(order.expires),
    );
    let mut waiting = page(StatusCode::OK, "Pay with Lightning", &body);
    waiting.headers_mut().insert("refresh", HeaderValue::from_static(REFRESH));
    waiting
}

/// On to an order's page, after the form that made it.
fn see(order: &Order) -> Response<Full<Bytes>> {
    let mut see = answer(StatusCode::SEE_OTHER, "text/plain; charset=utf-8", "the order's page\n");
    if let Ok(at) = HeaderValue::from_str(&format!("/order/{}", order.id)) {
        see.headers_mut().insert(header::LOCATION, at);
    }
    see
}

/// An order by invoice asked as `kind`, by `caller`, answered by `until`.
pub async fn respond(
    site: &Arc<Site>,
    caller: Ipv6Addr,
    asked: &Asked,
    kind: Kind,
    until: Instant,
) -> Response<Full<Bytes>> {
    match (kind, order(site, caller, asked, until).await) {
        (_, Err(fault)) => refuse_as(kind, &fault, false),
        (Kind::Json, Ok(order)) => json(StatusCode::CREATED, &view(&order)),
        (Kind::Form, Ok(order)) => see(&order),
    }
}

/// What became of order `id`, for `caller`.
pub fn read(site: &Site, caller: Ipv6Addr, id: &str, kind: Kind) -> Response<Full<Bytes>> {
    match (kind, of(site, caller, id)) {
        (_, Err(fault)) => refuse_as(kind, &fault, false),
        (Kind::Json, Ok(order)) => json(StatusCode::OK, &view(&order)),
        (Kind::Form, Ok(order)) => order_page(site, caller, &order),
    }
}

/// A new key for the package order `id` made, for `caller`.
pub fn key(site: &Site, caller: Ipv6Addr, id: &str, kind: Kind) -> Response<Full<Bytes>> {
    let (order, key) = match new_key(site, caller, id) {
        Ok(made) => made,
        Err(fault) => return refuse_as(kind, &fault, false),
    };
    let package = order.package.as_deref().and_then(|package| site.store.package(package).ok().flatten());
    let Some(package) = package else { return refuse_as(kind, &Fault::NoNewKey, false) };
    match kind {
        Kind::Json => json(
            StatusCode::OK,
            &serde_json::json!({
                "order": order.id,
                "key": key,
                "package": serde_json::to_value(manage::view(site, &package, caller)).unwrap_or_default(),
            }),
        ),
        Kind::Form => {
            let body = format!(
                "<p class=\"note\">{offer} is package {id}.</p>\n<h2>Its key</h2>\n<p><code>{key}</code></p>\n\
                 <p>It is shown this once, and not kept here: keep it. A key shown for this package before opens \
                 nothing any more. Whoever has it sees who is in the package, takes devices out of it, and adds to \
                 it. Another device of yours is added by itself: give it the key, and open this exit's page on \
                 it.</p>\n<form method=\"post\" action=\"/package\"><input type=\"hidden\" name=\"key\" \
                 value=\"{key}\"><button>Manage it</button></form>\n<p><a href=\"/order/{order}\">Back</a></p>\n",
                offer = escape(&order.offer),
                id = escape(&package.id),
                key = escape(&key),
                order = order.id,
            );
            page(StatusCode::OK, "Its key", &body)
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;
    use hyper::Request;

    use super::*;
    use crate::orders::testing::{world, world_with};
    use crate::store::Standing;

    const BUYER: &str = "fd77::7";
    const OTHER: &str = "fd88::8";
    const GIVE_UP: Duration = Duration::from_secs(600);

    fn a(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn by_invoice(package: &str, key: Option<&str>) -> Asked {
        Asked {
            package: package.into(),
            key: key.map(str::to_string),
            method: Some("bolt11".into()),
            ..Asked::default()
        }
    }

    async fn ask(site: &Arc<Site>, caller: &str, package: &str, key: Option<&str>) -> Result<Order, Fault> {
        order(site, a(caller), &by_invoice(package, key), soon()).await
    }

    /// The service's rounds, as one who looks at invoices would make them.
    #[derive(Default)]
    struct Looks(HashMap<String, Instant>);

    impl Looks {
        async fn look(&mut self, site: &Arc<Site>) -> usize {
            round(site, site.desk.as_ref().unwrap(), &mut self.0).await
        }

        /// Look until order `id` is not waiting any more, or a while has
        /// passed. The order as it is then.
        async fn until_decided(&mut self, site: &Arc<Site>, id: &str) -> Order {
            for _ in 0..40 {
                self.look(site).await;
                let now = site.store.order(id).unwrap().unwrap();
                if now.paid || now.ended > 0 {
                    return now;
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            site.store.order(id).unwrap().unwrap()
        }
    }

    async fn body(response: Response<Full<Bytes>>) -> String {
        String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_buys_a_package() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        assert_eq!(w.site.methods(), vec!["cashu", "bolt11"]);
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let now = unix_now();
        assert_eq!((ordered.method.as_str(), ordered.buyer, ordered.offer.as_str()), ("bolt11", a(BUYER), "small"));
        assert_eq!((ordered.sat, ordered.bytes, ordered.days, ordered.paid), (64, 10_000_000, 1, false));
        let request = ordered.request.clone().unwrap();
        assert!(request.starts_with("lnbc640n1"), "an invoice of 64 sat: {request}");
        assert!((now + 3500..=now + 3600).contains(&ordered.expires), "it ends when the mint says");
        assert!(ordered.quote.is_some() && ordered.quote_key.is_some(), "the quote, and the key it is locked to");
        // Its buyer sees it, and nobody else that it is there.
        let seen = view(&of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(
            (&seen["state"], &seen["request"], &seen["expires"]),
            (&"waiting".into(), &request.clone().into(), &ordered.expires.into())
        );
        assert!(seen.get("key").is_none() && seen.get("package").is_none(), "{seen}");
        assert_eq!(of(&w.site, a(OTHER), &ordered.id), Err(Fault::NoOrder));
        assert_eq!(of(&w.site, a(BUYER), "o0123456789abcdef"), Err(Fault::NoOrder));
        assert_eq!(of(&w.site, a(BUYER), "../orders"), Err(Fault::NoOrder));
        // Nothing is granted for an invoice: not while it waits, however
        // often it is looked at.
        let mut looks = Looks::default();
        assert_eq!(looks.look(&w.site).await, 1);
        assert_eq!(looks.look(&w.site).await, 1);
        assert!(w.site.store.packages().unwrap().is_empty() && w.holds().await == 0);
        assert_eq!(new_key(&w.site, a(BUYER), &ordered.id), Err(Fault::NotPaid));
        // Paid: what arrived is in the wallet, and the package is its
        // buyer's.
        w.pay(&request).await;
        let paid = looks.until_decided(&w.site, &ordered.id).await;
        assert!(paid.paid && paid.paid_sat == 64 && paid.fee_sat == 0, "{paid:?}");
        let package = w.site.store.package(paid.package.as_deref().unwrap()).unwrap().unwrap();
        assert_eq!(
            (package.granted, package.members.clone(), package.label.as_str()),
            (10_000_000, vec![a(BUYER)], "bought: small")
        );
        assert_eq!(package.standing(unix_now()), Standing::Live);
        assert_eq!((w.holds().await, w.site.store.sold(&w.mint).unwrap()), (64, 64));
        let seen = view(&of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!((&seen["state"], &seen["paid_sat"], &seen["added"]), (&"paid".into(), &64.into(), &false.into()));
        assert_eq!(seen["package"]["id"], package.id.as_str());
        assert!(seen.get("request").is_none(), "{seen}");
        assert_eq!(looks.look(&w.site).await, 0, "and it waits no more");
        // Its key: nobody was shown one. Its buyer asks, and each one asked
        // for takes the place of the one before.
        let (_, key) = new_key(&w.site, a(BUYER), &ordered.id).unwrap();
        assert_eq!(w.site.store.package_with_key(&key).unwrap().unwrap().id, package.id);
        let (_, newer) = new_key(&w.site, a(BUYER), &ordered.id).unwrap();
        assert!(w.site.store.package_with_key(&key).unwrap().is_none());
        assert_eq!(w.site.store.package_with_key(&newer).unwrap().unwrap().id, package.id);
        assert_eq!(new_key(&w.site, a(OTHER), &ordered.id), Err(Fault::NoOrder));
        // An order paid with a token gives its key to the token, not here.
        let with_token = w.buy(OTHER, "small", &w.token(64).await, None).await.unwrap();
        assert_eq!(new_key(&w.site, a(OTHER), &with_token.order), Err(Fault::NoNewKey));
        assert_eq!(view(&of(&w.site, a(OTHER), &with_token.order).unwrap())["method"], "cashu");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_adds_to_a_package_by_its_key() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let first = w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        let key = first.settled.key.clone().unwrap();
        // Asked by another device, which has the key: it is not put in.
        let ordered = ask(&w.site, OTHER, "big", Some(&key)).await.unwrap();
        assert_eq!(ordered.target.as_deref(), Some(first.settled.package.id.as_str()));
        w.pay(ordered.request.as_deref().unwrap()).await;
        let paid = Looks::default().until_decided(&w.site, &ordered.id).await;
        assert!(paid.paid && paid.package == paid.target, "{paid:?}");
        let package = w.site.store.package(&first.settled.package.id).unwrap().unwrap();
        assert_eq!((package.granted, package.members.clone()), (1_010_000_000, vec![a(BUYER)]));
        assert_eq!(view(&paid)["added"], true);
        assert_eq!(
            new_key(&w.site, a(OTHER), &ordered.id),
            Err(Fault::NoNewKey),
            "its key is the one it was asked with"
        );
        assert_eq!(w.site.store.package_with_key(&key).unwrap().unwrap().id, package.id);
        assert_eq!(w.holds().await, 64 + 1500);
        // A wrong key orders nothing; nor does the key of a package taken back.
        assert_eq!(ask(&w.site, OTHER, "small", Some(&"0".repeat(64))).await, Err(Fault::NoKey));
        w.site.store.revoke(&package.id).unwrap();
        assert_eq!(ask(&w.site, OTHER, "small", Some(&key)).await, Err(Fault::TakenBack));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_that_is_not_paid_ends() {
        let w = world_with(0, GIVE_UP, 2, "").await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let mut looks = Looks::default();
        assert_eq!(looks.look(&w.site).await, 1);
        assert_eq!(w.site.store.order(&ordered.id).unwrap().unwrap().ended, 0, "not before it has ended");
        // Ended, and the mint cannot be asked: it is not given up on that.
        tokio::time::sleep(Duration::from_millis(2600)).await;
        w.proxy.go_away();
        assert!(w.the_mint().reach().await.is_err());
        assert_eq!(looks.look(&w.site).await, 1);
        assert_eq!(w.site.store.order(&ordered.id).unwrap().unwrap().ended, 0, "not without the mint's word");
        w.proxy.pass();
        w.the_mint().reach().await.unwrap();
        let ended = looks.until_decided(&w.site, &ordered.id).await;
        assert!(!ended.paid && ended.ended > 0, "{ended:?}");
        let seen = view(&of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(seen["state"], "expired");
        assert!(seen.get("request").is_none(), "nothing to pay any more: {seen}");
        assert_eq!(new_key(&w.site, a(BUYER), &ordered.id), Err(Fault::NotPaid));
        assert!(w.site.store.packages().unwrap().is_empty());
        assert_eq!(looks.look(&w.site).await, 0);
        // It is there to be asked about for a while, and then forgotten.
        assert_eq!(w.site.store.invoices_forget(ended.ended).unwrap(), 0);
        assert_eq!(w.site.store.invoices_forget(ended.ended + 1).unwrap(), 1);
        assert_eq!(of(&w.site, a(BUYER), &ordered.id), Err(Fault::NoOrder));
    }

    /// What was paid while this service was not running, or not looking, is
    /// found when it looks: whoever asks, and if nobody does.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_paid_while_nobody_looked_is_found() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        w.pay(ordered.request.as_deref().unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        // A service that starts knows nothing of when it last looked.
        let paid = Looks::default().until_decided(&w.site, &ordered.id).await;
        assert!(paid.paid, "{paid:?}");
        assert_eq!(w.holds().await, 64);
    }

    /// The mint mints for the invoice, and its answer does not arrive: the
    /// order is not paid on that, and not lost either.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_of_the_mints_that_was_lost_is_found_again() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        w.pay(ordered.request.as_deref().unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.proxy.lose_mint_answers();
        let mut looks = Looks::default();
        looks.look(&w.site).await;
        let open = w.site.store.order(&ordered.id).unwrap().unwrap();
        assert!(!open.paid && open.ended == 0, "nothing is granted on an answer that did not come: {open:?}");
        assert!(w.site.store.packages().unwrap().is_empty());
        // The mint can be asked again: it minted, for this wallet.
        w.proxy.pass();
        let paid = looks.until_decided(&w.site, &ordered.id).await;
        assert!(paid.paid && paid.paid_sat == 64, "{paid:?}");
        assert_eq!(w.holds().await, 64, "and what it minted is in the wallet");
        assert_eq!(w.site.store.packages().unwrap().len(), 1);
        assert_eq!(looks.look(&w.site).await, 0);
    }

    /// The wallet's file is lost while an invoice waits (a new one is made
    /// from the seed): the order alone is enough to claim what is paid.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_outlives_the_wallets_file() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let anew = w.with_wallets(w.second_wallet("anew").await);
        w.pay(ordered.request.as_deref().unwrap()).await;
        let paid = Looks::default().until_decided(&anew, &ordered.id).await;
        assert!(paid.paid && paid.paid_sat == 64, "{paid:?}");
        let holds = anew.desk.as_ref().unwrap().wallets.mints[0].balance().await.unwrap().0;
        assert_eq!((holds, w.holds().await), (64, 0), "minted by the wallet that is there now");
    }

    /// A wallet whose file is behind its seed's use asks the mint to sign
    /// what it signed before, and is refused: the invoice is paid all the
    /// same, and minted for once the wallet has counted again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wallet_behind_its_seed_mints_once_it_has_counted_again() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let behind = w.with_wallets(w.second_wallet("behind").await);
        // The first wallet takes a token: the mint signs for the seed what
        // the second wallet's file knows nothing of.
        w.buy(OTHER, "small", &w.token(64).await, None).await.unwrap();
        let ordered = ask(&behind, BUYER, "small", None).await.unwrap();
        w.pay(ordered.request.as_deref().unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut looks = Looks::default();
        looks.look(&behind).await;
        let its = &behind.desk.as_ref().unwrap().wallets.mints[0];
        let open = behind.store.order(&ordered.id).unwrap().unwrap();
        assert!(!open.paid && !its.ready(), "refused, and nothing is sold there until it has counted again");
        assert_eq!(looks.look(&behind).await, 1, "nor asked while it has not");
        its.reach().await.unwrap();
        let paid = looks.until_decided(&behind, &ordered.id).await;
        assert!(paid.paid && paid.paid_sat == 64, "{paid:?}");
        assert_eq!(behind.store.sold(&w.mint).unwrap(), 128);
        assert_eq!(its.balance().await.unwrap().0, 128, "what the seed has at the mint, the invoice's too");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invoices_are_few_for_an_address_and_for_all() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let mut waiting = Vec::new();
        for _ in 0..WAITING_FOR_ONE {
            waiting.push(ask(&w.site, BUYER, "small", None).await.unwrap());
        }
        assert_eq!(ask(&w.site, BUYER, "small", None).await, Err(Fault::TooMany(3)));
        assert_eq!(Fault::TooMany(3).status(), StatusCode::TOO_MANY_REQUESTS);
        ask(&w.site, OTHER, "small", None).await.unwrap();
        // One that is paid waits no more, and makes room.
        w.pay(waiting[0].request.as_deref().unwrap()).await;
        assert!(Looks::default().until_decided(&w.site, &waiting[0].id).await.paid);
        ask(&w.site, BUYER, "small", None).await.unwrap();
        // Each is asked of a mint from the same budget as a token is taken:
        // ten at once, for everyone together.
        let mut asked = 5;
        let busy = loop {
            match ask(&w.site, &format!("fd99::{asked}"), "small", None).await {
                Ok(_) => asked += 1,
                Err(fault) => break fault,
            }
        };
        assert_eq!((busy, asked), (Fault::Busy, 10));
        assert!(Fault::Busy.words(false).contains("invoices") && !Fault::Busy.words(false).contains("token"));
        assert_eq!(w.buy("fd99::99", "small", &w.token(64).await, None).await, Err(Fault::Busy), "a token's too");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn who_is_not_given_an_invoice() {
        let w = world_with(0, GIVE_UP, 3600, " huge:10GB:2000000:90").await;
        w.hold().await;
        assert_eq!(ask(&w.site, BUYER, "none", None).await, Err(Fault::NoOffer("none".into())));
        // The mint gives none for that much, and says so of itself.
        let Err(Fault::NoInvoice(why)) = ask(&w.site, BUYER, "huge", None).await else { panic!("an invoice") };
        assert!(why.contains("gives an invoice for 2000000 sat"), "{why}");
        assert_eq!(Fault::NoInvoice(why).status(), StatusCode::SERVICE_UNAVAILABLE);
        // One way to pay or the other, and a way there is.
        let both = Asked { token: "cashuBabc".into(), ..by_invoice("small", None) };
        assert!(matches!(order(&w.site, a(BUYER), &both, soon()).await, Err(Fault::Bad(_))));
        let other = Asked { method: Some("onchain".into()), ..by_invoice("small", None) };
        assert!(matches!(order(&w.site, a(BUYER), &other, soon()).await, Err(Fault::Bad(_))));
        // A mint this exit does not accept is not asked.
        let elsewhere = Asked { mint: Some("https://mint.example".into()), ..by_invoice("small", None) };
        assert_eq!(
            order(&w.site, a(BUYER), &elsewhere, soon()).await,
            Err(Fault::WrongMint("https://mint.example".into()))
        );
        let named = Asked { mint: Some(w.mint.clone()), ..by_invoice("small", None) };
        assert_eq!(order(&w.site, a(BUYER), &named, soon()).await.unwrap().mint, w.mint);
        // Who the daemon would not carry for a package is sold none.
        w.seats.lock().unwrap().insert(a("fd11::1"), "static".into());
        w.seats.lock().unwrap().insert(a("fd11::2"), "free no4".into());
        assert_eq!(ask(&w.site, "fd11::1", "small", None).await, Err(Fault::Listed));
        assert_eq!(ask(&w.site, "fd11::2", "small", None).await, Err(Fault::NoIpv4));
        assert!(!Fault::Listed.words(false).contains("token"), "no token was sent, and none is spoken of");
        // Nor is anyone while the mint cannot be reached, or once the time
        // to answer in is over.
        assert_eq!(order(&w.site, a(BUYER), &by_invoice("small", None), Instant::now()).await, Err(Fault::Again));
        w.proxy.go_away();
        assert!(w.the_mint().reach().await.is_err());
        assert_eq!(ask(&w.site, BUYER, "small", None).await, Err(Fault::MintAway(w.mint.clone())));
        assert_eq!(w.site.methods(), Vec::<String>::new());
        assert_eq!(w.site.store.invoices_waiting(a(BUYER), unix_now()).unwrap(), (1, 1), "the one that was given");
    }

    #[test]
    fn an_invoice_is_looked_at_sooner_when_asked_about_and_later_the_older_it_is() {
        let waiting = Waiting::default();
        let store = Store::in_memory();
        let new = NewInvoice {
            buyer: a(BUYER),
            mint: "https://mint.example",
            offer: "small",
            bytes: 1,
            sat: 1,
            days: 1,
            target: None,
            quote: "q",
            quote_key: None,
            request: "lnbc1",
            expires: 2_000,
        };
        store.invoice_begin("o0000000000000001", &new, 1_000).unwrap();
        let order = store.order("o0000000000000001").unwrap().unwrap();
        let ago = |seconds| Some(Duration::from_secs(seconds));
        // Never looked at: once it is five seconds old.
        assert!(!due(&order, false, None, &waiting, 1_004));
        assert!(due(&order, false, None, &waiting, 1_005));
        // Looked at: again after an eighth of its age, five seconds at the
        // least and a minute at the most.
        assert!(!due(&order, false, ago(4), &waiting, 1_020) && due(&order, false, ago(5), &waiting, 1_020));
        assert!(!due(&order, false, ago(29), &waiting, 1_240) && due(&order, false, ago(30), &waiting, 1_240));
        assert!(!due(&order, false, ago(59), &waiting, 9_000) && due(&order, false, ago(60), &waiting, 9_000));
        // Asked about: now, but not more often than a mint is asked.
        assert!(due(&order, true, None, &waiting, 1_000));
        assert!(!due(&order, true, ago(2), &waiting, 1_000) && due(&order, true, ago(3), &waiting, 1_000));
        // The same quote of the same mint is one order.
        assert!(store.invoice_begin("o0000000000000002", &new, 1_000).is_err());
        assert!(store.orders_open().unwrap().is_empty(), "and it is not a token's order");
    }

    fn request(method: &str, path: &str, kind: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut request = Request::builder().method(method).uri(path).header("host", "npub1exit.fips:5170");
        if !kind.is_empty() {
            request = request.header("content-type", kind);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_order_is_asked_for_and_answered_as_json_and_as_pages() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let (ours, form) = ("http://npub1exit.fips:5170", "application/x-www-form-urlencoded");
        let get =
            |path: &str, caller: &str| crate::http::respond(&w.site, a(caller), &request("GET", path, "", &[]), b"");
        // As JSON: made, with its invoice.
        let made = respond(&w.site, a(BUYER), &by_invoice("small", None), Kind::Json, soon()).await;
        assert_eq!(made.status(), StatusCode::CREATED);
        let made: serde_json::Value = serde_json::from_str(&body(made).await).unwrap();
        let (id, invoice) =
            (made["order"].as_str().unwrap().to_string(), made["request"].as_str().unwrap().to_string());
        assert_eq!((&made["state"], &made["method"], &made["sat"]), (&"waiting".into(), &"bolt11".into(), &64.into()));
        let read = get(&format!("/v1/orders/{id}"), BUYER);
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body(read).await).unwrap(), made);
        let not_theirs = get(&format!("/v1/orders/{id}"), OTHER);
        assert_eq!(not_theirs.status(), StatusCode::NOT_FOUND);
        assert!(body(not_theirs).await.contains("\"code\":\"no-such-order\""));
        // As a form: on to the order's page, which shows the invoice and
        // looks again by itself.
        let seen = respond(&w.site, a(OTHER), &by_invoice("big", None), Kind::Form, soon()).await;
        assert_eq!(seen.status(), StatusCode::SEE_OTHER);
        let at = seen.headers()["location"].to_str().unwrap().to_string();
        assert!(at.starts_with("/order/o") && at.len() == "/order/".len() + 17, "{at}");
        let waiting = get(&at, OTHER);
        assert_eq!((waiting.status(), waiting.headers()["refresh"].to_str().unwrap()), (StatusCode::OK, "5"));
        let page = body(waiting).await;
        assert!(page.contains("<h1>Pay with Lightning</h1>") && page.contains("<strong>1500 sat</strong>"), "{page}");
        assert!(page.contains("big (1 GB, 30 days) is a package of this device's"), "{page}");
        assert!(page.contains("<svg class=\"qr\"") && page.contains("<a href=\"lightning:lnbc15u1"), "{page}");
        assert_eq!(get(&at, BUYER).status(), StatusCode::NOT_FOUND, "another's order is nobody's page");
        // Nothing is changed by reading, and a key is asked for as any
        // change is: from this page or from a program, by a POST.
        let key_path = format!("/order/{id}/key");
        assert_eq!(get(&key_path, BUYER).status(), StatusCode::METHOD_NOT_ALLOWED);
        let post = |path: &str, kind: &str, headers: &[(&str, &str)]| {
            crate::http::respond(&w.site, a(BUYER), &request("POST", path, kind, headers), b"")
        };
        assert_eq!(post(&format!("/v1/orders/{id}"), "application/json", &[]).status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(post(&key_path, form, &[("origin", "http://evil.example")]).status(), StatusCode::FORBIDDEN);
        assert_eq!(post(&key_path, form, &[]).status(), StatusCode::FORBIDDEN);
        assert_eq!(post(&key_path, "text/plain", &[("origin", ours)]).status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let json_key = format!("/v1/orders/{id}/key");
        assert_eq!(
            post(&json_key, "application/json", &[("origin", "http://evil.example")]).status(),
            StatusCode::FORBIDDEN
        );
        let not_paid = post(&key_path, form, &[("origin", ours)]);
        assert_eq!(not_paid.status(), StatusCode::CONFLICT);
        assert!(body(not_paid).await.contains("That order is not paid"));
        // Paid: the page says so, and its buyer has a key for the asking.
        w.pay(&invoice).await;
        assert!(Looks::default().until_decided(&w.site, &id).await.paid);
        let paid = get(&format!("/order/{id}"), BUYER);
        assert!(paid.headers().get("refresh").is_none(), "nothing to look for again");
        let page = body(paid).await;
        assert!(
            page.contains("<h1>Paid</h1>") && page.contains("Paid: 64 sat arrived, and small is package p"),
            "{page}"
        );
        assert!(page.contains("This device is in it: <strong>10 MB</strong>, until "), "{page}");
        assert!(page.contains(&format!("<form method=\"post\" action=\"/order/{id}/key\">")), "{page}");
        assert!(!page.contains("lnbc"), "{page}");
        let shown = post(&key_path, form, &[("origin", ours)]);
        assert_eq!(shown.status(), StatusCode::OK);
        let page = body(shown).await;
        let key = page.split("<code>").nth(1).unwrap().split("</code>").next().unwrap().to_string();
        let package = w.site.store.package_with_key(&key).unwrap().expect("the key that was shown opens it");
        assert!(page.contains(&format!("name=\"key\" value=\"{key}\"")) && page.contains("<h1>Its key</h1>"), "{page}");
        let as_json = post(&json_key, "application/json", &[]);
        assert_eq!(as_json.status(), StatusCode::OK);
        let said: serde_json::Value = serde_json::from_str(&body(as_json).await).unwrap();
        assert_eq!((&said["order"], &said["package"]["id"]), (&id.clone().into(), &package.id.clone().into()));
        assert_eq!(said["package"]["members"].as_array().unwrap().len(), 1, "whoever has the key sees who is in it");
        let newer = said["key"].as_str().unwrap();
        assert!(newer != key && w.site.store.package_with_key(&key).unwrap().is_none());
        assert_eq!(w.site.store.package_with_key(newer).unwrap().unwrap().id, package.id);
        // What is refused is said without a word of a token.
        let refused = respond(&w.site, a(BUYER), &by_invoice("none", None), Kind::Form, soon()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let page = body(refused).await;
        assert!(page.contains("No package none is offered here.") && !page.contains("token"), "{page}");
    }
}
