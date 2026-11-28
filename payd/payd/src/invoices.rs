//! Buying a package with Lightning or on the chain, over the mesh.
//!
//! ```text
//! POST /v1/orders              {"package", "method": "bolt11", "key"?, "mint"?}   an order, with its invoice
//! POST /v1/orders              {"package", "method": "onchain", "key"?, "mint"?}  an order, with its address
//! GET  /v1/orders/<order>                                                      what became of it
//! POST /v1/orders/<order>/key  {}                                              a key for the package it made
//! POST /buy                    the same as a form (method=bolt11, or onchain): on to its order's page
//! GET  /order/<order>          that page: what to pay while it waits, then what it bought
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
//! found at its next start, however late that is. An invoice is shown to
//! its buyer only while it can be paid: not once it has ended, though the
//! order is still asked about for a while then.
//!
//! An order is its buyer's: the address that asked sees it, and nobody
//! else. The package it makes has a key that nobody was shown. Its buyer
//! asks for one, and each key asked for takes the place of the one before.
//!
//! # On the chain
//!
//! The same orders, with `"method": "onchain"`, are paid with bitcoin on
//! the chain, where a mint takes that (NUT-30): the mint gives an address,
//! and counts what arrives there once it is confirmed. An address names no
//! amount, and a payment on the chain cannot be refused or sent back, so
//! what arrives is not held to the price: it buys at the rate of what was
//! ordered, whatever part or multiple of the price it is, as it arrives.
//! Half the price buys half the bytes and half the time; a little less
//! than the price, as when a wallet takes its fee out of what it sends,
//! buys a little less. The first that arrives makes the package; what
//! arrives after, until the order's end, is added to it. The mint is asked
//! more seldom than about an invoice, since the chain takes its time, and
//! until the order's end whether or not anything has arrived. That end is
//! the mint's for its address, and two days at the most: what is confirmed
//! after it is lost to whoever sent it, and the page says when that is.
//!
//! Each amount that arrives is credited once: an order keeps how much has
//! arrived in all, as the mint counts it and the wallet has minted for,
//! and only what is over that is new ([`Store::order_credit`]).

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
use crate::store::{BOLT11, CASHU, NewInvoice, ONCHAIN, Order, Store};
use crate::sync::unix_now;
use crate::terms::{bytes_shown, date, escape};
use crate::wallet::{MINT_TIME, Mint, Paid};

/// How many invoices may wait to be paid for one address, and in all. An
/// invoice costs its asker nothing, and cannot be taken back once it is
/// given: so there are few for anyone, and what bounds them for everyone
/// together is the budget they are asked of a mint from.
const WAITING_FOR_ONE: usize = 3;
const WAITING_IN_ALL: usize = 512;
/// How many addresses nothing has arrived at may wait in all. Counted apart
/// from the invoices, and fewer: one lasts two days where an invoice lasts
/// minutes, each is asked about at its mint for as long, and asking for
/// one costs nothing. So those nobody pays keep no invoice from being
/// given, and take a bounded part of what a mint is asked.
const ADDRESSES_IN_ALL: usize = 64;
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
/// An invoice is given to a buyer only if it lasts this long, in seconds:
/// one that ends before it can be paid is a way to lose what is paid.
const LIFE: u64 = 60;
/// What is asked for again within this many seconds is the order there is
/// for it already: a form sent twice makes one invoice.
const SAME: u64 = 60;
/// How long a request waits for another of its address that is under way.
const UNDER_WAY: Duration = Duration::from_secs(5);
/// How often the page of an invoice that waits looks again, in seconds; and
/// that of an address, where things take minutes.
const REFRESH: &str = "5";
const CHAIN_REFRESH: &str = "30";
/// How long an address is good for, in seconds, where its mint names no
/// sooner end: two days. A payment on the chain is confirmed when miners
/// take it, which is not for its sender to say.
const CHAIN_LIFE: u64 = 172_800;
/// How long after its end, and [`GRACE`], an address is still asked about
/// while its mint does not say what arrived there or will not mint for
/// it: a week. After that the order is ended all the same, and kept.
const CHAIN_PATIENCE: u64 = 604_800;
/// How long an order by address that ended with nothing arrived is kept,
/// with the quote and the key that claim what arrives there after all:
/// ninety days. What comes late on the chain comes days late.
const CHAIN_KEPT: u64 = 7_776_000;
/// An order paid on the chain is looked at this long after the last time,
/// at the least and at the most, while nothing has arrived; and this
/// seldom once something has, for what may come after. Its buyer's asking
/// has it looked at as often as the least.
const CHAIN_PACE: (u64, u64, u64) = (30, 900, 600);

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
    /// [`LOOK`], [`GRACE`], [`PACE`], [`LIFE`], [`CHAIN_PACE`] and
    /// [`CHAIN_LIFE`], which a test shortens.
    pub every: Duration,
    pub grace: u64,
    pub pace: (u64, u64),
    pub life: u64,
    pub chain_pace: (u64, u64, u64),
    pub chain_life: u64,
    /// [`CHAIN_PATIENCE`].
    pub chain_patience: u64,
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
            life: LIFE,
            chain_pace: CHAIN_PACE,
            chain_life: CHAIN_LIFE,
            chain_patience: CHAIN_PATIENCE,
        }
    }
}

impl Waiting {
    /// For a test: looked at whenever the test says, given up as soon as
    /// it has ended, and nothing given that ends within `life` seconds.
    #[cfg(test)]
    pub fn at_once(&mut self, life: u64) {
        (self.every, self.grace, self.pace, self.life, self.chain_pace) = (Duration::ZERO, 0, (0, 0), life, (0, 0, 0));
    }

    fn wanted(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.wanted.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Does `mint` give what an order paid by `method` is paid to, for `sat`:
/// an invoice, or an address?
fn gives(mint: &Mint, method: &str, sat: u64) -> bool {
    match method {
        ONCHAIN => mint.takes_onchain(Some(sat)).is_some(),
        _ => mint.gives_invoices(Some(sat)),
    }
}

/// What a mint does not give, or what none gives, for a person.
fn not_given(method: &str, sat: u64, none: bool) -> String {
    match (method, none) {
        (ONCHAIN, false) => format!("takes no payment on the chain of {sat} sat"),
        (ONCHAIN, true) => format!("takes a payment on the chain of {sat} sat"),
        (_, false) => format!("gives no invoice for {sat} sat"),
        (_, true) => format!("gives an invoice for {sat} sat"),
    }
}

/// The mint to ask for an invoice of `sat`, or an address to pay as much
/// to: the one that is `named`, or the first that is reached and gives one.
fn mint_for<'a>(desk: &'a Desk, named: Option<&str>, sat: u64, method: &str) -> Result<&'a Arc<Mint>, Fault> {
    let mints = &desk.wallets.mints;
    if let Some(name) = named {
        let mint = desk.wallets.named(name).ok_or_else(|| Fault::WrongMint(name.to_string()))?;
        if !mint.ready() {
            return Err(Fault::MintAway(mint.name.clone()));
        }
        if mint.full() {
            return Err(Fault::WalletFull);
        }
        if !gives(mint, method, sat) {
            return Err(Fault::NoInvoice(format!("The mint {} {}.", mint.name, not_given(method, sat, false))));
        }
        return Ok(mint);
    }
    if let Some(mint) = mints.iter().find(|mint| mint.sells() && gives(mint, method, sat)) {
        return Ok(mint);
    }
    match mints.first() {
        Some(away) if !mints.iter().any(|mint| mint.ready()) => Err(Fault::MintAway(away.name.clone())),
        Some(_) if !desk.wallets.ready() => Err(Fault::WalletFull),
        _ => Err(Fault::NoInvoice(format!("No mint this exit accepts {}.", not_given(method, sat, true)))),
    }
}

/// Order what `asked` asks for, for `caller`, to be paid by an invoice or
/// to an address on the chain: the order, with that. Answered by `until`.
pub async fn order(site: &Arc<Site>, caller: Ipv6Addr, asked: &Asked, until: Instant) -> Result<Order, Fault> {
    let desk = site.desk.as_ref().ok_or(Fault::NotSold)?;
    let method = match asked.method.as_deref() {
        Some(BOLT11) => BOLT11,
        Some(ONCHAIN) => ONCHAIN,
        other => {
            return Err(Fault::Bad(format!(
                "no such way to pay: {:.40} (cashu, with a token; bolt11, for an invoice; onchain, for an address)",
                other.unwrap_or_default()
            )));
        }
    };
    if !asked.token.trim().is_empty() {
        return Err(Fault::Bad(
            "an invoice or an address is asked for, and a token was sent too: one or the other".into(),
        ));
    }
    let offer = site
        .config
        .packages
        .iter()
        .find(|offer| offer.id == asked.package)
        .ok_or_else(|| Fault::NoOffer(asked.package.clone()))?;
    let key = key_asked(asked)?;
    let mint = mint_for(desk, asked.mint.as_deref(), offer.sat, method)?;
    let target = tokio::time::timeout_at(until, whose(site, desk, caller, offer, key.as_deref()))
        .await
        .map_err(|_| Fault::Again)??;
    let id = Store::order_id()?;
    // What is ordered, before the mint has given anything for it.
    let asking = NewInvoice {
        method,
        buyer: caller,
        mint: &mint.name,
        offer: &offer.id,
        bytes: offer.bytes,
        sat: offer.sat,
        days: offer.days,
        target: target.as_deref(),
        quote: "",
        quote_key: None,
        request: "",
        expires: 0,
    };
    // The same asked again a moment later (a form sent twice) is the order
    // there is for it already. An address is, beyond that, the same for as
    // long as nothing has arrived at it and it is good for a day more:
    // asking again does not use up what an address may have waiting.
    let there_is = || {
        let now = unix_now();
        let lasts = now.saturating_add(desk.invoices.life);
        match site.store.invoice_recent(&asking, now.saturating_sub(SAME), lasts)? {
            None if method == ONCHAIN => {
                site.store.invoice_recent(&asking, 0, lasts.max(now.saturating_add(desk.invoices.chain_life / 2)))
            }
            found => Ok(found),
        }
    };
    // One at a time for an address: so that what it has waiting is counted
    // before another is added to it. Another request of this address that
    // is under way is waited for a little: it may be making that order.
    let patience = Instant::now() + UNDER_WAY;
    let _at_work = loop {
        if let Some(order) = there_is()? {
            return Ok(order);
        }
        match desk.enter(&id, caller) {
            Some(at_work) => break at_work,
            None if Instant::now() < patience.min(until) => tokio::time::sleep(Duration::from_millis(200)).await,
            None => return Err(Fault::UnderWay),
        }
    };
    if let Some(order) = there_is()? {
        return Ok(order);
    }
    // Invoices and addresses are counted apart: neither takes the other's
    // place.
    let (its, all) = site.store.invoices_waiting(caller, method, unix_now())?;
    if its >= WAITING_FOR_ONE {
        return Err(Fault::TooMany(its));
    }
    let room = if method == ONCHAIN { ADDRESSES_IN_ALL } else { WAITING_IN_ALL };
    if all >= room || !desk.spend() {
        return Err(Fault::Busy);
    }
    let about = format!("fips exit: {}", offer.id);
    let of_the_mint = async {
        let _turn = mint.turn.lock().await;
        match method {
            ONCHAIN => mint.address().await,
            _ => mint.invoice(offer.sat, &about).await,
        }
    };
    let what = if method == ONCHAIN { "address" } else { "invoice" };
    let mut quote = match tokio::time::timeout_at(until, of_the_mint).await {
        Ok(Ok(quote)) => quote,
        Ok(Err(e)) => {
            eprintln!("fips-exit-payd: {}: no {what} for {} sat: {e}", mint.name, offer.sat);
            return Err(Fault::NoInvoice(format!("The mint {} gave no {what}: {e}", mint.name)));
        }
        Err(_) => return Err(Fault::Again),
    };
    // By the clock as it is now, the mint having answered. An address is
    // good until the mint says, and two days at the most: after that it is
    // not looked at any more.
    let now = unix_now();
    if method == ONCHAIN {
        let ours = now.saturating_add(desk.invoices.chain_life);
        quote.expires = if quote.expires == 0 { ours } else { quote.expires.min(ours) };
    }
    // What ends before it can be paid is not given to anyone.
    if quote.expires < now.saturating_add(desk.invoices.life) {
        return Err(Fault::NoInvoice(format!("The mint {} gave an {what} that ends too soon to pay.", mint.name)));
    }
    // Written down before anyone sees the invoice or the address. If this
    // does not come to pass, the mint has a quote nobody knows how to pay.
    let new = NewInvoice {
        quote: &quote.id,
        quote_key: quote.key.as_deref(),
        request: &quote.request,
        expires: quote.expires,
        ..asking
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
    // An invoice that is not paid; an address, to which more may come.
    let looked_at = (order.method == BOLT11 && !order.paid) || order.method == ONCHAIN;
    if looked_at
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
/// For an order paid by invoice or on the chain: nobody was shown that
/// package's key. One paid with a token was answered with its key, and has
/// it again by sending the token again.
pub fn new_key(site: &Site, caller: Ipv6Addr, id: &str) -> Result<(Order, String), Fault> {
    let order = of(site, caller, id)?;
    if order.method == CASHU {
        return Err(Fault::NoNewKey);
    }
    if !order.paid {
        return Err(Fault::NotPaid);
    }
    let key = site.store.order_new_key(&order.id)?.ok_or(Fault::NoNewKey)?;
    Ok((order, key))
}

/// What an order has come to, as its buyer is told.
#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// Its invoice can be paid, or its address paid to, and nothing has
    /// arrived.
    Waiting,
    /// Nothing can be paid for it now, and what became of it is still being
    /// found out: its invoice has ended and may have been paid in time, its
    /// mint is not one this exit takes any more, or it is a token's order
    /// whose mint has not answered.
    Checking,
    Paid,
    /// Given up: its invoice ended unpaid.
    Expired,
}

/// Can `order` be paid now: is it one with an invoice or an address, which
/// has not ended, at a mint this exit takes? An invoice that is paid
/// cannot be paid again; an address can be paid to as often as one likes.
fn payable(site: &Site, order: &Order, now: u64) -> bool {
    let taken_here = || site.desk.as_ref().is_some_and(|desk| desk.wallets.named(&order.mint).is_some());
    let more = (order.method == BOLT11 && !order.paid) || order.method == ONCHAIN;
    more && order.ended == 0 && now < order.expires && taken_here()
}

impl State {
    fn of(site: &Site, order: &Order, now: u64) -> State {
        match order {
            order if order.paid => State::Paid,
            order if order.ended > 0 => State::Expired,
            order if payable(site, order, now) => State::Waiting,
            _ => State::Checking,
        }
    }

    fn word(self) -> &'static str {
        match self {
            State::Waiting => "waiting",
            State::Checking => "checking",
            State::Paid => "paid",
            State::Expired => "expired",
        }
    }
}

/// Whether what `order` paid for was added to the package it was asked for.
fn added(order: &Order) -> bool {
    order.target.is_some() && order.target == order.package
}

/// An order, for a program. Its invoice, or its address, is in it only
/// while it can be paid.
pub fn view(site: &Site, order: &Order) -> serde_json::Value {
    let now = unix_now();
    let state = State::of(site, order, now);
    let mut said = serde_json::json!({
        "order": order.id,
        "state": state.word(),
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
    }
    if payable(site, order, now) {
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
    let age = now.saturating_sub(order.created);
    if order.method == ONCHAIN {
        // The chain takes minutes: asked about, not more often than its
        // least; else by its age; and seldom once something has arrived.
        let (least, most, after) = waiting.chain_pace;
        let pace = match (asked, order.paid) {
            (true, _) => least,
            (false, true) => after,
            (false, false) => (age / 8).clamp(least, most),
        };
        return looked.map_or(if asked { u64::MAX } else { age }, |ago| ago.as_secs()) >= pace;
    }
    if asked {
        return looked.is_none_or(|ago| ago >= waiting.every);
    }
    let pace = (age / 8).clamp(waiting.pace.0, waiting.pace.1);
    looked.map_or(age, |ago| ago.as_secs()) >= pace
}

/// The mint refused to mint for `order`, with `error`. Where it refused as
/// for something it signed before (a mint says it in one of these ways;
/// the last is how one says it of a request to mint), the wallet's file is
/// behind its seed's use, and it counts again before anything else is
/// asked there. Once for an order: a mint that goes on refusing is not
/// asked to count over and over.
fn not_minted(desk: &Desk, mint: &Mint, order: &Order, error: &cdk::Error) {
    let signed_before = matches!(
        error,
        cdk::Error::BlindedMessageAlreadySigned | cdk::Error::DuplicateOutputs | cdk::Error::RequestAlreadyPaid
    );
    let first = || desk.invoices.recounted.lock().unwrap_or_else(|p| p.into_inner()).insert(order.id.clone());
    if signed_before && first() {
        mint.suspect();
    }
    eprintln!("fips-exit-payd: order {}: it is paid, and {} has not minted for it yet: {error}", order.id, mint.name);
}

/// Ask `mint` what arrived at `order`'s address, mint for what was not
/// minted for yet, and credit what is new. The caller holds the mint's
/// turn.
async fn look_at_address(site: &Site, desk: &Desk, mint: &Mint, order: &Order, quote: &str) {
    // Long after its end, an order whose mint will not say what arrived,
    // or will not mint for it, is ended all the same: it is kept, with
    // what claims it, and not asked about for ever.
    let given_up = |why: &str| {
        let last = order.expires.saturating_add(desk.invoices.grace).saturating_add(desk.invoices.chain_patience);
        if unix_now() > last {
            eprintln!(
                "fips-exit-payd: ORDER {} IS GIVEN UP LONG AFTER ITS END, {why}. Its quote at {} is {quote}; what \
                 arrived for it so far is {} sat. It is kept, and not asked about any more.",
                order.id, mint.name, order.paid_sat
            );
            if let Err(e) = site.store.invoice_end(&order.id, unix_now()) {
                eprintln!("fips-exit-payd: order {}: {e}", order.id);
            }
        }
    };
    let (confirmed, minted) = match mint.arrived(quote, order.quote_key.as_deref()).await {
        Ok(arrived) => arrived,
        Err(e) => {
            eprintln!("fips-exit-payd: order {}: {} did not say what arrived at its address: {e}", order.id, mint.name);
            return given_up("ITS MINT NOT SAYING WHAT ARRIVED AT ITS ADDRESS");
        }
    };
    // What the mint minted for the quote it minted for this wallet, which
    // alone knows the quote and holds its key: that has arrived.
    let mut arrived = minted;
    if confirmed > minted {
        match tokio::time::timeout(MINT_TIME, mint.mint_paid(quote)).await {
            Ok(Ok(sat)) => arrived = minted.saturating_add(sat),
            Ok(Err(e)) => not_minted(desk, mint, order, &e),
            Err(_) => eprintln!(
                "fips-exit-payd: order {}: {} sat arrived at its address, and {} did not answer in time when asked \
                 to mint for them",
                order.id,
                confirmed - minted,
                mint.name
            ),
        }
    }
    if arrived > order.paid_sat {
        match site.store.order_credit(&order.id, arrived, unix_now()) {
            Ok(Some(credited)) => {
                mint.holds_more(credited.sat);
                eprintln!(
                    "fips-exit-payd: order {}: {} sat arrived on the chain at {} ({arrived} in all); {} package {}",
                    order.id,
                    credited.sat,
                    mint.name,
                    if credited.first { "they are, or went to," } else { "added to" },
                    credited.package.id
                );
                site.changed.notify_one();
                // Some of it was minted without this service hearing of it
                // (an answer lost, or the service stopped): if the wallet
                // does not hold it, it is found again from the seed.
                if minted > order.paid_sat {
                    found_again(site, mint).await;
                }
            }
            Ok(None) => {}
            // Not ended on this look, whatever the hour: it is in the
            // wallet, and the order stays open until it is credited.
            Err(e) => {
                eprintln!(
                    "fips-exit-payd: ORDER {}: {arrived} SAT ARRIVED AND COULD NOT BE CREDITED: {e}. It is tried \
                     again.",
                    order.id
                );
                return;
            }
        }
    }
    // Something that arrived is still to be minted: not ended, but for the
    // mint refusing it long after.
    if arrived < confirmed {
        return given_up("ITS MINT NOT MINTING FOR WHAT ARRIVED AT ITS ADDRESS");
    }
    // Its end, and a while more: nothing further is looked for at this
    // address.
    if unix_now() > order.expires.saturating_add(desk.invoices.grace)
        && let Err(e) = site.store.invoice_end(&order.id, unix_now())
    {
        eprintln!("fips-exit-payd: order {}: {e}", order.id);
    }
}

/// Ask `mint` what became of `order`'s invoice, and act on it.
async fn look_at(site: &Site, desk: &Desk, mint: &Mint, order: &Order) {
    let Some(quote) = &order.quote else { return };
    let _turn = mint.turn.lock().await;
    if order.method == ONCHAIN {
        return look_at_address(site, desk, mint, order, quote).await;
    }
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
            Ok(Err(e)) => not_minted(desk, mint, order, &e),
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

/// What the one who looks at invoices remembers from one look to the next.
#[derive(Default)]
pub struct Looks {
    /// When each waiting order was last looked at, since the service
    /// started.
    looked: HashMap<String, Instant>,
    /// Whether the last look went to an order because its buyer asked: the
    /// next goes to the one not looked at for longest, whoever asks.
    asked_last: bool,
    /// The orders said, in the log, to wait for a mint that is not taken
    /// here any more.
    stranded: HashSet<String>,
}

/// Look at the invoice that is most due, if one is. How many wait at a mint
/// that is taken here.
async fn round(site: &Site, desk: &Desk, looks: &mut Looks) -> usize {
    let now = unix_now();
    if let Err(e) = site.store.invoices_forget(now.saturating_sub(KEPT), now.saturating_sub(CHAIN_KEPT)) {
        eprintln!("fips-exit-payd: orders that were given up could not be forgotten: {e}");
    }
    let open = match site.store.invoices_open() {
        Ok(open) => open,
        Err(e) => {
            eprintln!("fips-exit-payd: the invoices that wait could not be read: {e}");
            return 0;
        }
    };
    let waits = |id: &String| open.iter().any(|order| order.id == *id);
    looks.looked.retain(|id, _| waits(id));
    looks.stranded.retain(|id| waits(id));
    desk.invoices.recounted.lock().unwrap_or_else(|p| p.into_inner()).retain(|id| waits(id));
    let wanted: HashSet<String> = {
        let mut wanted = desk.invoices.wanted();
        wanted.retain(|id| waits(id));
        wanted.clone()
    };
    // An invoice of a mint that was taken out of MINTS cannot be asked
    // about: what is paid for it is at that mint, and the order is kept,
    // with what claims it, until the mint is taken here again. Said once.
    let (here, stranded): (Vec<&Order>, Vec<&Order>) =
        open.iter().partition(|order| desk.wallets.named(&order.mint).is_some());
    for order in stranded {
        if looks.stranded.insert(order.id.clone()) {
            eprintln!(
                "fips-exit-payd: ORDER {} WAITS TO BE PAID AT {}, WHICH IS NOT AMONG MINTS ANY MORE. If it is \
                 paid, what was paid is at that mint, and nothing is granted for it: put the mint back in MINTS \
                 until `fips-exit orders` shows no order of it open.",
                order.id, order.mint
            );
        }
    }
    // Of those that are due at a mint that is reached: one whose buyer is
    // asking, and then the one not looked at for longest. Every other look
    // goes to the one not looked at for longest whoever is asking, so that
    // those who ask do not keep everyone else from being looked at.
    let ago = |order: &Order| looks.looked.get(&order.id).map(Instant::elapsed);
    let asked = |order: &Order| wanted.contains(&order.id);
    let fair = looks.asked_last;
    let next = here
        .iter()
        .filter(|order| due(order, asked(order), ago(order), &desk.invoices, now))
        .filter_map(|order| Some((*order, desk.wallets.named(&order.mint).filter(|mint| mint.ready())?)))
        .max_by_key(|(order, _)| (!fair && asked(order), ago(order).is_none(), ago(order)));
    if let Some((order, mint)) = next {
        looks.asked_last = !fair && asked(order);
        looks.looked.insert(order.id.clone(), Instant::now());
        desk.invoices.wanted().remove(&order.id);
        look_at(site, desk, mint, order).await;
    }
    here.len()
}

/// Look at the invoices that wait, for as long as the service runs: one at
/// a time, [`LOOK`] apart, and not at all while there are none.
pub async fn keep(site: Arc<Site>) {
    let Some(desk) = site.desk.clone() else { return };
    let mut looks = Looks::default();
    loop {
        let waiting = round(&site, &desk, &mut looks).await;
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

/// Where an order paid on the chain is paid to, for its page: the address
/// as text, as a `bitcoin:` link that names the price, and as a code; how
/// often the mint wants a payment confirmed; and until when.
fn pay_to(site: &Site, order: &Order) -> String {
    let address = order.request.as_deref().unwrap_or_default();
    // The price as a link writes it: in bitcoin, to the satoshi.
    let link = format!("bitcoin:{address}?amount={}.{:08}", order.sat / 100_000_000, order.sat % 100_000_000);
    let mint = site.desk.as_ref().and_then(|desk| desk.wallets.named(&order.mint));
    let chain = mint.and_then(|mint| mint.takes_onchain(None));
    let confirmed = match chain.map(|chain| chain.confirmations) {
        Some(0) | None => "once the mint has seen it confirmed".to_string(),
        Some(1) => "once it is confirmed".to_string(),
        Some(times) => format!("once it is confirmed {times} times"),
    };
    // What the mint says it takes at once: what is outside that may count
    // for nothing there.
    let bounds = match chain {
        Some(chain) if chain.least > 1 && chain.most < u64::MAX => {
            format!(" The mint takes no less than {} sat at once, and no more than {} sat.", chain.least, chain.most)
        }
        Some(chain) if chain.least > 1 => format!(" The mint takes no less than {} sat at once.", chain.least),
        Some(chain) if chain.most < u64::MAX => format!(" The mint takes no more than {} sat at once.", chain.most),
        _ => String::new(),
    };
    format!(
        "{code}<p><a href=\"{link}\">Open it in a wallet on this device</a></p>\n<p><code>{address}</code></p>\n\
         <p>What arrives counts {confirmed}, and what is confirmed after {ends} is lost: do not send it late, or \
         with a fee too small to be confirmed by then.{bounds}</p>\n",
        code = qr::svg(&link).map(|code| format!("<p>{code}</p>\n")).unwrap_or_default(),
        link = escape(&link),
        address = escape(address),
        ends = date(order.expires),
    )
}

/// An order's page.
fn order_page(site: &Site, caller: Ipv6Addr, order: &Order) -> Response<Full<Bytes>> {
    let what = format!("{} ({}, {} days)", escape(&order.offer), bytes_shown(order.bytes), order.days);
    let back = "<p><a href=\"/\">Back</a></p>\n";
    let on_the_chain = order.method == ONCHAIN;
    let now = unix_now();
    if order.paid {
        let package = order.package.as_deref().unwrap_or_default();
        let did = if added(order) { "was added to" } else { "is" };
        let mut body = if on_the_chain {
            // What arrived, and what it bought of what was ordered.
            let bought = u128::from(order.bytes) * u128::from(order.paid_sat) / u128::from(order.sat.max(1));
            format!(
                "<p class=\"note\">Paid: {} sat arrived, of the {} sat that {} costs. That buys {}, which went to \
                 package {}.</p>\n",
                order.paid_sat,
                order.sat,
                escape(&order.offer),
                bytes_shown(u64::try_from(bought).unwrap_or(u64::MAX)),
                escape(package)
            )
        } else {
            format!(
                "<p class=\"note\">Paid: {} sat arrived, and {} {did} package {}.</p>\n",
                order.paid_sat,
                escape(&order.offer),
                escape(package)
            )
        };
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
            if order.method != CASHU && !added(order) && !package.revoked {
                body.push_str(&format!(
                    "<h2>Its key</h2>\n<p>Whoever has a package's key sees who is in it, takes devices out of it, and \
                     adds to it. Nobody has been shown this one's. A key shown here takes the place of any shown \
                     before.</p>\n<form method=\"post\" action=\"/order/{}/key\"><button>Show a key for it</button>\
                     </form>\n",
                    order.id
                ));
            }
        }
        // An address can be paid to again, until its order ends.
        let more = on_the_chain && payable(site, order, now);
        if more {
            body.push_str(&format!(
                "<h2>More</h2>\n<p>What is sent to the same address is added to that package at the same rate.</p>\n{}",
                pay_to(site, order)
            ));
        }
        body.push_str(back);
        let mut paid = page(StatusCode::OK, "Paid", &body);
        if more {
            paid.headers_mut().insert("refresh", HeaderValue::from_static(CHAIN_REFRESH));
        }
        return paid;
    }
    let state = State::of(site, order, now);
    if state == State::Expired {
        let said = if on_the_chain {
            "Nothing arrived at this order's address before it ended. Nothing was bought."
        } else {
            "This order's invoice ended unpaid. Nothing was bought."
        };
        return page(StatusCode::OK, "Not bought", &format!("<p class=\"note\">{said}</p>\n{back}"));
    }
    if state == State::Checking {
        // Nothing to pay here now: no invoice or address, no code, no link.
        let ended = now >= order.expires;
        let said = match (order.method.as_str(), ended) {
            (BOLT11, true) => {
                "This order's invoice has ended: it cannot be paid any more. If it was paid before it ended, the \
                 payment is still looked for, and this page says so when it is found."
            }
            (ONCHAIN, true) => {
                "This order has ended: send nothing to its address any more. If something was confirmed there \
                 before it ended, it is still looked for, and this page says so when it is found."
            }
            (BOLT11 | ONCHAIN, false) => {
                "This exit does not take payments at this order's mint any more: pay nothing for it."
            }
            _ => "What became of this order's token is not known yet.",
        };
        let mut checking = page(StatusCode::OK, "Not paid", &format!("<p class=\"note\">{said}</p>\n{back}"));
        checking.headers_mut().insert("refresh", HeaderValue::from_static(REFRESH));
        return checking;
    }
    let adds = match &order.target {
        Some(target) => format!(" is added to package {}", escape(target)),
        None => " is a package of this device's".to_string(),
    };
    if on_the_chain {
        let body = format!(
            "<p class=\"note\">Send <strong>{sat} sat</strong> to this address, and {what}{adds}.</p>\n{to}\
             <p>What arrives buys at that rate, whatever part or multiple of {sat} sat it is: half of it buys half \
             the bytes and half the time. So a little less, as when a wallet takes its fee out of what it sends, \
             buys a little less, and is not lost. Nothing is given back.</p>\n\
             <p class=\"you\">This page looks again by itself, and says so when something has arrived. The package \
             is there once it has, whether or not this page is open.</p>\n{back}",
            sat = order.sat,
            to = pay_to(site, order),
        );
        let mut waiting = page(StatusCode::OK, "Pay on the chain", &body);
        waiting.headers_mut().insert("refresh", HeaderValue::from_static(CHAIN_REFRESH));
        return waiting;
    }
    let request = order.request.as_deref().unwrap_or_default();
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
        (Kind::Json, Ok(order)) => json(StatusCode::CREATED, &view(site, &order)),
        (Kind::Form, Ok(order)) => see(&order),
    }
}

/// What became of order `id`, for `caller`.
pub fn read(site: &Site, caller: Ipv6Addr, id: &str, kind: Kind) -> Response<Full<Bytes>> {
    match (kind, of(site, caller, id)) {
        (_, Err(fault)) => refuse_as(kind, &fault, false),
        (Kind::Json, Ok(order)) => json(StatusCode::OK, &view(site, &order)),
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
    use crate::wallet::Wallets;

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

    /// The service's rounds, as the one who looks at invoices makes them.
    impl Looks {
        async fn look(&mut self, site: &Arc<Site>) -> usize {
            round(site, site.desk.as_ref().unwrap(), self).await
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
        assert_eq!(w.site.methods(), vec!["cashu", "bolt11", "onchain"]);
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let now = unix_now();
        assert_eq!((ordered.method.as_str(), ordered.buyer, ordered.offer.as_str()), ("bolt11", a(BUYER), "small"));
        assert_eq!((ordered.sat, ordered.bytes, ordered.days, ordered.paid), (64, 10_000_000, 1, false));
        let request = ordered.request.clone().unwrap();
        assert!(request.starts_with("lnbc640n1"), "an invoice of 64 sat: {request}");
        assert!((now + 3500..=now + 3600).contains(&ordered.expires), "it ends when the mint says");
        assert!(ordered.quote.is_some() && ordered.quote_key.is_some(), "the quote, and the key it is locked to");
        // Its buyer sees it, and nobody else that it is there.
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
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
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
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
        assert_eq!(view(&w.site, &of(&w.site, a(OTHER), &with_token.order).unwrap())["method"], "cashu");
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
        assert_eq!(view(&w.site, &paid)["added"], true);
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
        let w = world_with(0, GIVE_UP, 2, "", "").await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let mut looks = Looks::default();
        assert_eq!(looks.look(&w.site).await, 1);
        assert_eq!(w.site.store.order(&ordered.id).unwrap().unwrap().ended, 0, "not before it has ended");
        // Ended: it is not shown to be paid any more, as JSON or on its page,
        // though it is still asked about.
        tokio::time::sleep(Duration::from_millis(2600)).await;
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(seen["state"], "checking");
        assert!(seen.get("request").is_none() && seen.get("expires").is_none(), "{seen}");
        let page = read(&w.site, a(BUYER), &ordered.id, Kind::Form);
        assert_eq!(page.headers()["refresh"], "5", "it looks again: a payment made in time may yet be found");
        let page = body(page).await;
        assert!(page.contains("has ended: it cannot be paid any more"), "{page}");
        assert!(!page.contains("lnbc") && !page.contains("<svg") && !page.contains("lightning:"), "{page}");
        assert_eq!(
            w.site.store.invoices_waiting(a(BUYER), BOLT11, unix_now()).unwrap(),
            (0, 0),
            "it keeps nobody's place"
        );
        // The mint cannot be asked: it is not given up on that.
        w.proxy.go_away();
        assert!(w.the_mint().reach().await.is_err());
        assert_eq!(looks.look(&w.site).await, 1);
        assert_eq!(w.site.store.order(&ordered.id).unwrap().unwrap().ended, 0, "not without the mint's word");
        w.proxy.pass();
        w.the_mint().reach().await.unwrap();
        let ended = looks.until_decided(&w.site, &ordered.id).await;
        assert!(!ended.paid && ended.ended > 0, "{ended:?}");
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(seen["state"], "expired");
        assert!(seen.get("request").is_none(), "nothing to pay any more: {seen}");
        assert_eq!(new_key(&w.site, a(BUYER), &ordered.id), Err(Fault::NotPaid));
        assert!(w.site.store.packages().unwrap().is_empty());
        assert_eq!(looks.look(&w.site).await, 0);
        // It is there to be asked about for a while, and then forgotten.
        assert_eq!(w.site.store.invoices_forget(ended.ended, u64::MAX).unwrap(), 0);
        assert_eq!(w.site.store.invoices_forget(ended.ended + 1, 0).unwrap(), 1);
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
        let (_, key) = w.site.store.grant(1000, 0, &[], "another", unix_now()).unwrap();
        let small = ask(&w.site, BUYER, "small", None).await.unwrap();
        let big = ask(&w.site, BUYER, "big", None).await.unwrap();
        let added = ask(&w.site, BUYER, "small", Some(&key)).await.unwrap();
        assert!(small.id != big.id && small.id != added.id && small.request != added.request);
        assert_eq!(ask(&w.site, BUYER, "big", Some(&key)).await, Err(Fault::TooMany(3)));
        assert_eq!(Fault::TooMany(3).status(), StatusCode::TOO_MANY_REQUESTS);
        // The same asked again is the order there is for it, not a fourth:
        // a form sent twice makes one invoice.
        assert_eq!(ask(&w.site, BUYER, "small", None).await.unwrap().id, small.id);
        assert_eq!(ask(&w.site, BUYER, "small", Some(&key)).await.unwrap().id, added.id);
        // And at the same moment: one asks the mint, the other waits for it.
        let (one, other) = tokio::join!(ask(&w.site, OTHER, "small", None), ask(&w.site, OTHER, "small", None));
        assert_eq!(one.unwrap().id, other.unwrap().id);
        assert_eq!(w.site.store.invoices_waiting(a(OTHER), BOLT11, unix_now()).unwrap(), (1, 4));
        // One that is paid waits no more, and makes room; what is asked
        // then is a new order.
        w.pay(small.request.as_deref().unwrap()).await;
        assert!(Looks::default().until_decided(&w.site, &small.id).await.paid);
        assert!(ask(&w.site, BUYER, "small", None).await.unwrap().id != small.id);
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
        assert!(Fault::Busy.words(false).contains("ordered") && !Fault::Busy.words(false).contains("token"));
        assert_eq!(w.buy("fd99::99", "small", &w.token(64).await, None).await, Err(Fault::Busy), "a token's too");
        // What is asked for again costs nothing of it.
        assert_eq!(ask(&w.site, BUYER, "big", None).await.unwrap().id, big.id);
    }

    /// Those who ask about their orders do not keep the others from being
    /// looked at: every other look goes to whichever waited longest.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_order_nobody_asks_about_is_looked_at_all_the_same() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let asked_about = ask(&w.site, BUYER, "small", None).await.unwrap();
        let mut looks = Looks::default();
        // Looked at once each, so that neither is new to the one who looks.
        looks.look(&w.site).await;
        looks.look(&w.site).await;
        let quiet = ask(&w.site, OTHER, "small", None).await.unwrap();
        looks.look(&w.site).await;
        let at = |looks: &Looks, order: &Order| looks.looked[&order.id];
        for _ in 0..3 {
            // Its buyer asks, over and over: a look for it, and then one for
            // the other, which nobody asks about.
            of(&w.site, a(BUYER), &asked_about.id).unwrap();
            let (before, quiet_before) = (at(&looks, &asked_about), at(&looks, &quiet));
            looks.look(&w.site).await;
            assert!(at(&looks, &asked_about) > before && at(&looks, &quiet) == quiet_before);
            of(&w.site, a(BUYER), &asked_about.id).unwrap();
            let before = at(&looks, &asked_about);
            looks.look(&w.site).await;
            assert!(at(&looks, &asked_about) == before && at(&looks, &quiet) > quiet_before, "the other's turn");
        }
        // So one that is paid with nobody watching is found among them.
        w.pay(quiet.request.as_deref().unwrap()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        for _ in 0..2 {
            of(&w.site, a(BUYER), &asked_about.id).unwrap();
            looks.look(&w.site).await;
        }
        assert!(w.site.store.order(&quiet.id).unwrap().unwrap().paid);
    }

    /// An invoice of a mint that was taken out of MINTS: nothing can be
    /// asked about it, so it is not shown to be paid, and it is not given
    /// up either; with the mint back, what was paid is found.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_of_a_mint_that_is_not_taken_any_more_waits_for_it() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        let another = fips_exit_test_mint::start("127.0.0.1:0".parse().unwrap(), 0).await.unwrap();
        let dir = w.dir.join("without");
        std::fs::create_dir(&dir).unwrap();
        let wallets = Wallets::open(&dir, std::slice::from_ref(&another)).await.unwrap();
        wallets.mints[0].reach().await.unwrap();
        let without = w.with_wallets(wallets);
        let mut looks = Looks::default();
        assert_eq!(looks.look(&without).await, 0, "none that can be looked at");
        assert!(looks.stranded.contains(&ordered.id), "and it is said, once");
        let seen = view(&without, &of(&without, a(BUYER), &ordered.id).unwrap());
        assert_eq!(seen["state"], "checking");
        assert!(seen.get("request").is_none(), "{seen}");
        let page = body(read(&without, a(BUYER), &ordered.id, Kind::Form)).await;
        assert!(
            page.contains("does not take payments at this order&#39;s mint any more")
                || page.contains("order's mint any more"),
            "{page}"
        );
        assert!(!page.contains("lnbc"), "{page}");
        let kept = without.store.order(&ordered.id).unwrap().unwrap();
        assert!(!kept.paid && kept.ended == 0);
        // Paid all the same, and the mint taken again: found.
        w.pay(ordered.request.as_deref().unwrap()).await;
        assert!(Looks::default().until_decided(&w.site, &ordered.id).await.paid);
    }

    /// The wallet's file knows the quote and not its key (it learnt the
    /// quote from the mint, and stopped before it had the key from the
    /// order): the key is put to it whenever it is missing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_quote_the_wallet_has_without_its_key_gets_it_from_the_order() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = ask(&w.site, BUYER, "small", None).await.unwrap();
        w.the_mint().forget_key(ordered.quote.as_deref().unwrap()).await;
        w.pay(ordered.request.as_deref().unwrap()).await;
        let paid = Looks::default().until_decided(&w.site, &ordered.id).await;
        assert!(paid.paid && w.holds().await == 64, "{paid:?}");
    }

    /// An invoice that ends before it could be paid is given to nobody; and
    /// what a mint said of its invoices is remembered from one start to the
    /// next.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_that_ends_too_soon_is_not_given() {
        let w = world_with(0, GIVE_UP, 30, "", "").await;
        w.hold().await;
        let strict = w.with_invoice_life(LIFE);
        let Err(Fault::NoInvoice(why)) = ask(&strict, BUYER, "small", None).await else { panic!("an invoice") };
        assert!(why.contains("ends too soon to pay"), "{why}");
        assert!(w.site.store.orders(10).unwrap().is_empty(), "and no order is made of it");
        ask(&w.with_invoice_life(20), BUYER, "small", None).await.unwrap();
        // A service that starts again, its mint not reached yet: it sells
        // nothing, and knows what it will sell for.
        let again = Wallets::open(&w.dir, std::slice::from_ref(&w.mint)).await.unwrap();
        assert!(again.mints[0].gives_invoices(None) && !again.mints[0].ready() && !again.invoicing());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn who_is_not_given_an_invoice() {
        let w = world_with(0, GIVE_UP, 3600, " huge:10GB:2000000:90", "").await;
        w.hold().await;
        assert_eq!(ask(&w.site, BUYER, "none", None).await, Err(Fault::NoOffer("none".into())));
        // The mint gives none for that much, and says so of itself.
        let Err(Fault::NoInvoice(why)) = ask(&w.site, BUYER, "huge", None).await else { panic!("an invoice") };
        assert!(why.contains("gives an invoice for 2000000 sat"), "{why}");
        assert_eq!(Fault::NoInvoice(why).status(), StatusCode::SERVICE_UNAVAILABLE);
        // One way to pay or the other, and a way there is.
        let both = Asked { token: "cashuBabc".into(), ..by_invoice("small", None) };
        assert!(matches!(order(&w.site, a(BUYER), &both, soon()).await, Err(Fault::Bad(_))));
        let other = Asked { method: Some("channel".into()), ..by_invoice("small", None) };
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
        assert_eq!(order(&w.site, a("fd55::5"), &by_invoice("big", None), Instant::now()).await, Err(Fault::Again));
        w.proxy.go_away();
        assert!(w.the_mint().reach().await.is_err());
        assert_eq!(ask(&w.site, BUYER, "small", None).await, Err(Fault::MintAway(w.mint.clone())));
        assert_eq!(w.site.methods(), Vec::<String>::new());
        assert_eq!(
            w.site.store.invoices_waiting(a(BUYER), BOLT11, unix_now()).unwrap(),
            (1, 1),
            "the one that was given"
        );
    }

    #[test]
    fn an_invoice_is_looked_at_sooner_when_asked_about_and_later_the_older_it_is() {
        let waiting = Waiting::default();
        let store = Store::in_memory();
        let new = NewInvoice {
            method: BOLT11,
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

    fn on_the_chain(package: &str, key: Option<&str>) -> Asked {
        Asked { method: Some("onchain".into()), ..by_invoice(package, key) }
    }

    /// Look until what has arrived for order `id` is `sat`, or a while has
    /// passed. The order as it is then.
    async fn until_arrived(looks: &mut Looks, site: &Arc<Site>, id: &str, sat: u64) -> Order {
        for _ in 0..40 {
            looks.look(site).await;
            let now = site.store.order(id).unwrap().unwrap();
            if now.paid_sat == sat {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        site.store.order(id).unwrap().unwrap()
    }

    /// What arrives at an order's address buys at the rate of what was
    /// ordered, as it arrives: a part of the price, the rest, and more.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_arrives_on_the_chain_buys_at_the_packages_rate() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        let now = unix_now();
        assert_eq!((ordered.method.as_str(), ordered.sat, ordered.paid), ("onchain", 64, false));
        let address = ordered.request.clone().unwrap();
        assert!(address.starts_with("bcrt1q"), "an address: {address}");
        assert!((now + CHAIN_LIFE - 60..=now + CHAIN_LIFE).contains(&ordered.expires), "good for two days");
        assert!(ordered.quote.is_some() && ordered.quote_key.is_some());
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(
            (&seen["state"], &seen["request"], &seen["method"]),
            (&"waiting".into(), &address.clone().into(), &"onchain".into())
        );
        assert_eq!(of(&w.site, a(OTHER), &ordered.id), Err(Fault::NoOrder));
        // Asked for again, it is the same address: not another to wait.
        assert_eq!(order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap().id, ordered.id);
        // Nothing arrives by itself, and nothing is granted for an address.
        let mut looks = Looks::default();
        assert_eq!(looks.look(&w.site).await, 1);
        assert!(w.site.store.packages().unwrap().is_empty() && w.holds().await == 0);
        assert_eq!(new_key(&w.site, a(BUYER), &ordered.id), Err(Fault::NotPaid));
        // Half the price: half the bytes, and half the time.
        w.deposit(&address, 32).await;
        let paid = until_arrived(&mut looks, &w.site, &ordered.id, 32).await;
        assert!(paid.paid && paid.paid_sat == 32, "{paid:?}");
        let package = w.site.store.package(paid.package.as_deref().unwrap()).unwrap().unwrap();
        assert_eq!((package.granted, package.members.clone()), (5_000_000, vec![a(BUYER)]));
        let half_a_day = unix_now() + 43_200;
        assert!((half_a_day - 30..=half_a_day).contains(&package.until), "half a day: {}", package.until - unix_now());
        assert_eq!((w.holds().await, w.site.store.sold(&w.mint).unwrap()), (32, 32));
        // It is paid, and its address is still there to be paid to.
        let seen = view(&w.site, &of(&w.site, a(BUYER), &ordered.id).unwrap());
        assert_eq!(
            (&seen["state"], &seen["paid_sat"], &seen["request"]),
            (&"paid".into(), &32.into(), &address.clone().into())
        );
        // The rest: the whole of what was ordered, to the byte and the second.
        w.deposit(&address, 32).await;
        let paid = until_arrived(&mut looks, &w.site, &ordered.id, 64).await;
        let whole = w.site.store.package(&package.id).unwrap().unwrap();
        assert_eq!((paid.paid_sat, whole.granted, whole.until), (64, 10_000_000, package.until + 43_200));
        // More than the price buys more, at the same rate.
        w.deposit(&address, 96).await;
        let paid = until_arrived(&mut looks, &w.site, &ordered.id, 160).await;
        let more = w.site.store.package(&package.id).unwrap().unwrap();
        assert_eq!((paid.paid_sat, more.granted, more.until), (160, 25_000_000, package.until + 43_200 + 129_600));
        assert_eq!((w.holds().await, w.site.store.sold(&w.mint).unwrap()), (160, 160));
        assert_eq!(w.site.store.packages().unwrap().len(), 1, "one package, added to");
        // Its key, for its buyer.
        let (_, key) = new_key(&w.site, a(BUYER), &ordered.id).unwrap();
        assert_eq!(w.site.store.package_with_key(&key).unwrap().unwrap().id, package.id);
        assert_eq!(looks.look(&w.site).await, 1, "and it is looked at until its end, for what may come");
        // Asked for again once something has arrived, it is another order.
        assert!(order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap().id != ordered.id);
    }

    /// Addresses are few for one buyer and for all, and counted apart from
    /// the invoices: neither takes the other's place.
    #[tokio::test(flavor = "multi_thread")]
    async fn addresses_are_few_and_keep_no_invoice_from_being_given() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let (_, key) = w.site.store.grant(1000, 0, &[], "another", unix_now()).unwrap();
        for (package, key) in [("small", None), ("big", None), ("small", Some(key.as_str()))] {
            order(&w.site, a(BUYER), &on_the_chain(package, key), soon()).await.unwrap();
        }
        assert_eq!(order(&w.site, a(BUYER), &on_the_chain("big", Some(&key)), soon()).await, Err(Fault::TooMany(3)));
        assert_eq!(w.site.store.invoices_waiting(a(BUYER), ONCHAIN, unix_now()).unwrap(), (3, 3));
        assert_eq!(w.site.store.invoices_waiting(a(BUYER), BOLT11, unix_now()).unwrap(), (0, 0));
        let invoice = ask(&w.site, BUYER, "big", Some(&key)).await.unwrap();
        assert_eq!(invoice.method, BOLT11, "an invoice all the same");
        // As many wait in all as may: no address more, for anyone, and an
        // invoice as before.
        let now = unix_now();
        for n in 3..ADDRESSES_IN_ALL {
            let new = NewInvoice {
                method: ONCHAIN,
                buyer: a(&format!("fd77::{n}")),
                mint: &w.mint,
                offer: "small",
                bytes: 10_000_000,
                sat: 64,
                days: 1,
                target: None,
                quote: &format!("q{n}"),
                quote_key: None,
                request: &format!("bcrt1q{n}"),
                expires: now + 3600,
            };
            w.site.store.invoice_begin(&format!("o{n:016x}"), &new, now).unwrap();
        }
        assert_eq!(order(&w.site, a(OTHER), &on_the_chain("small", None), soon()).await, Err(Fault::Busy));
        assert_eq!(ask(&w.site, OTHER, "small", None).await.unwrap().method, BOLT11);
        // One at which something arrived keeps no place: it cost something.
        let paid = format!("o{:016x}", 3);
        w.site.store.order_credit(&paid, 1, now).unwrap().unwrap();
        assert_eq!(order(&w.site, a(OTHER), &on_the_chain("small", None), soon()).await.unwrap().method, ONCHAIN);
    }

    /// Paid on the chain with the key of a package: what arrives is added
    /// to that package, its bytes and its time, and nobody is put in.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_arrives_on_the_chain_adds_to_a_package_by_its_key() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let first = w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        let (key, before) = (first.settled.key.clone().unwrap(), first.settled.package.clone());
        let ordered = order(&w.site, a(OTHER), &on_the_chain("big", Some(&key)), soon()).await.unwrap();
        assert_eq!(ordered.target.as_deref(), Some(before.id.as_str()));
        // A third of 1500 sat: a third of a gigabyte, and ten days.
        w.deposit(ordered.request.as_deref().unwrap(), 500).await;
        let paid = until_arrived(&mut Looks::default(), &w.site, &ordered.id, 500).await;
        assert_eq!(paid.package, paid.target);
        let after = w.site.store.package(&before.id).unwrap().unwrap();
        assert_eq!((after.granted, after.members.clone()), (10_000_000 + 333_333_333, vec![a(BUYER)]));
        assert_eq!(after.until, before.until + 864_000);
        assert_eq!(view(&w.site, &paid)["added"], true);
        assert_eq!(new_key(&w.site, a(OTHER), &ordered.id), Err(Fault::NoNewKey));
    }

    /// An address is good until its order ends. After that it is not shown,
    /// nothing more is looked for there, and what arrives is not counted.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_address_ends() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let short = w.with_chain_life(6);
        let unpaid = order(&short, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        let paid = order(&short, a(OTHER), &on_the_chain("small", None), soon()).await.unwrap();
        assert!(unpaid.expires <= unix_now() + 6);
        let mut looks = Looks::default();
        w.deposit(paid.request.as_deref().unwrap(), 64).await;
        assert!(until_arrived(&mut looks, &short, &paid.id, 64).await.paid);
        let left = paid.expires.saturating_sub(unix_now());
        tokio::time::sleep(Duration::from_millis(left * 1000 + 1100)).await;
        // Ended: neither is shown to be paid to any more.
        let seen = view(&short, &of(&short, a(BUYER), &unpaid.id).unwrap());
        assert_eq!(seen["state"], "checking");
        assert!(seen.get("request").is_none(), "{seen}");
        let seen = view(&short, &of(&short, a(OTHER), &paid.id).unwrap());
        assert_eq!(seen["state"], "paid");
        assert!(seen.get("request").is_none(), "{seen}");
        let page = body(read(&short, a(BUYER), &unpaid.id, Kind::Form)).await;
        assert!(page.contains("This order has ended: send nothing to its address any more"), "{page}");
        assert!(!page.contains("bcrt1q") && !page.contains("<svg"), "{page}");
        // Looked at once more, each: then nothing is looked for there.
        for _ in 0..4 {
            looks.look(&short).await;
        }
        let (unpaid, paid) =
            (short.store.order(&unpaid.id).unwrap().unwrap(), short.store.order(&paid.id).unwrap().unwrap());
        assert!(!unpaid.paid && unpaid.ended > 0 && paid.paid && paid.ended > 0, "{unpaid:?} {paid:?}");
        assert_eq!(view(&short, &unpaid)["state"], "expired");
        assert_eq!(looks.look(&short).await, 0);
        // What arrives after is not counted: it says so on the page, before.
        w.deposit(paid.request.as_deref().unwrap(), 64).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        looks.look(&short).await;
        assert_eq!(short.store.order(&paid.id).unwrap().unwrap().paid_sat, 64);
        assert_eq!(short.store.sold(&w.mint).unwrap(), 64);
    }

    /// The mint mints for what arrived, and its answer does not arrive:
    /// nothing is credited on that, and nothing is lost or credited twice.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_arrived_on_the_chain_is_credited_once_though_an_answer_was_lost() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let ordered = order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        w.deposit(ordered.request.as_deref().unwrap(), 64).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.proxy.lose_onchain_mint_answers();
        let mut looks = Looks::default();
        looks.look(&w.site).await;
        let open = w.site.store.order(&ordered.id).unwrap().unwrap();
        assert!(!open.paid && w.site.store.packages().unwrap().is_empty(), "{open:?}");
        w.proxy.pass();
        let paid = until_arrived(&mut looks, &w.site, &ordered.id, 64).await;
        assert!(paid.paid && paid.paid_sat == 64, "{paid:?}");
        for _ in 0..3 {
            looks.look(&w.site).await;
        }
        assert_eq!((w.holds().await, w.site.store.sold(&w.mint).unwrap()), (64, 64), "once, and in the wallet");
        assert_eq!(w.site.store.package(paid.package.as_deref().unwrap()).unwrap().unwrap().granted, 10_000_000);
        // With the wallet's file lost while an address waits, the order is
        // enough to claim what arrives there.
        let another = order(&w.site, a(OTHER), &on_the_chain("small", None), soon()).await.unwrap();
        let anew = w.with_wallets(w.second_wallet("anew").await);
        w.deposit(another.request.as_deref().unwrap(), 16).await;
        let paid = until_arrived(&mut Looks::default(), &anew, &another.id, 16).await;
        assert!(paid.paid && paid.paid_sat == 16, "{paid:?}");
    }

    /// An order whose mint does not say what arrived at its address is
    /// asked about long after its end, and then ended all the same: kept,
    /// with what claims it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_address_its_mint_says_nothing_of_is_given_up_long_after_its_end_and_kept() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let now = unix_now();
        let new = NewInvoice {
            method: ONCHAIN,
            buyer: a(BUYER),
            mint: &w.mint,
            offer: "small",
            bytes: 10_000_000,
            sat: 64,
            days: 1,
            target: None,
            quote: "a-quote-the-mint-does-not-know",
            quote_key: None,
            request: "bcrt1qgone",
            expires: now - 100,
        };
        w.site.store.invoice_begin("o00000000000000aa", &new, now - 200).unwrap();
        // Its end has passed, and a week has not: it stays, and is asked about.
        let mut looks = Looks::default();
        for _ in 0..3 {
            assert_eq!(looks.look(&w.site).await, 1);
        }
        assert_eq!(w.site.store.order("o00000000000000aa").unwrap().unwrap().ended, 0);
        // Long after: ended, and not forgotten with the invoices of a day ago.
        let impatient = w.with_waiting(|waiting| waiting.chain_patience = 0);
        Looks::default().look(&impatient).await;
        let ended = w.site.store.order("o00000000000000aa").unwrap().unwrap();
        assert!(ended.ended > 0 && !ended.paid && ended.quote.is_some(), "{ended:?}");
        assert_eq!(Looks::default().look(&impatient).await, 0);
        assert_eq!(w.site.store.invoices_forget(u64::MAX, ended.ended).unwrap(), 0, "kept for ninety days");
        assert!(w.site.store.order(&ended.id).unwrap().is_some());
        assert_eq!(w.site.store.invoices_forget(0, ended.ended + 1).unwrap(), 1);
    }

    /// An address asked for twice in a moment is one address, however soon
    /// it ends; and one given for another price is not given for this one.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_same_address_is_given_for_the_same_thing_at_the_same_price() {
        let w = world(0, GIVE_UP).await;
        w.hold().await;
        let now = unix_now();
        let short = NewInvoice {
            method: ONCHAIN,
            buyer: a(BUYER),
            mint: &w.mint,
            offer: "small",
            bytes: 10_000_000,
            sat: 64,
            days: 1,
            target: None,
            quote: "q1",
            quote_key: None,
            request: "bcrt1qshort",
            expires: now + 3600,
        };
        // Good for an hour, not for a day: the same for a minute.
        w.site.store.invoice_begin("o00000000000000b1", &short, now).unwrap();
        let again = order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        assert_eq!(again.id, "o00000000000000b1");
        // After that minute, another: this one ends too soon to be given again.
        w.site.store.change("UPDATE orders SET created = created - 61 WHERE id = 'o00000000000000b1'");
        let fresh = order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        assert!(fresh.id != "o00000000000000b1" && fresh.expires > now + 86_400);
        // The fresh one is good for two days: the same, whenever it is asked for.
        w.site.store.change(&format!("UPDATE orders SET created = created - 3600 WHERE id = '{}'", fresh.id));
        assert_eq!(order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap().id, fresh.id);
        // But not once the offer costs something else than it did then.
        w.site.store.change(&format!("UPDATE orders SET sat = 32 WHERE id = '{}'", fresh.id));
        let repriced = order(&w.site, a(BUYER), &on_the_chain("small", None), soon()).await.unwrap();
        assert!(repriced.id != fresh.id && repriced.sat == 64);
    }

    #[test]
    fn an_address_is_looked_at_more_seldom_than_an_invoice() {
        let waiting = Waiting::default();
        let store = Store::in_memory();
        let new = NewInvoice {
            method: ONCHAIN,
            buyer: a(BUYER),
            mint: "https://mint.example",
            offer: "small",
            bytes: 1_000,
            sat: 64,
            days: 1,
            target: None,
            quote: "q",
            quote_key: None,
            request: "bc1q",
            expires: 200_000,
        };
        store.invoice_begin("o0000000000000001", &new, 1_000).unwrap();
        let order = store.order("o0000000000000001").unwrap().unwrap();
        let ago = |seconds| Some(Duration::from_secs(seconds));
        // Never looked at: once it is half a minute old. Then by its age,
        // a quarter of an hour at the most.
        assert!(!due(&order, false, None, &waiting, 1_029) && due(&order, false, None, &waiting, 1_030));
        assert!(!due(&order, false, ago(29), &waiting, 1_100) && due(&order, false, ago(30), &waiting, 1_100));
        assert!(!due(&order, false, ago(899), &waiting, 50_000) && due(&order, false, ago(900), &waiting, 50_000));
        // Asked about: not more often than every half minute.
        assert!(due(&order, true, None, &waiting, 1_000));
        assert!(!due(&order, true, ago(29), &waiting, 1_000) && due(&order, true, ago(30), &waiting, 1_000));
        // Something arrived: every ten minutes, for what may come after.
        // Parts of the price add up to what the whole buys, to the byte.
        for (arrived, bytes) in [(1, 15), (2, 16), (63, 953), (64, 16)] {
            let credited = store.order_credit(&order.id, arrived, 2_000).unwrap().unwrap();
            assert_eq!((credited.bytes, credited.arrived), (bytes, arrived));
        }
        assert_eq!(store.order_credit(&order.id, 64, 2_000).unwrap(), None, "what was credited is not credited again");
        assert_eq!(store.order_credit(&order.id, 50, 2_000).unwrap(), None);
        let order = store.order(&order.id).unwrap().unwrap();
        let package = store.package(order.package.as_deref().unwrap()).unwrap().unwrap();
        assert_eq!((package.granted, package.until), (1_000, 2_000 + 86_400));
        assert!(!due(&order, false, ago(599), &waiting, 9_000) && due(&order, false, ago(600), &waiting, 9_000));
        // It is looked at until it has ended, paid as it is; an invoice
        // that is paid is not.
        assert_eq!(store.invoices_open().unwrap().len(), 1);
        store.invoice_end(&order.id, 300_000).unwrap();
        assert!(store.invoices_open().unwrap().is_empty());
        assert_eq!(store.invoices_forget(u64::MAX, u64::MAX).unwrap(), 0, "and what was paid is not forgotten");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_order_on_the_chain_is_answered_as_json_and_as_pages() {
        let w = world_with(0, GIVE_UP, 3600, " huge:10GB:2000000:90", "").await;
        w.hold().await;
        let get =
            |path: &str, caller: &str| crate::http::respond(&w.site, a(caller), &request("GET", path, "", &[]), b"");
        let made = respond(&w.site, a(BUYER), &on_the_chain("small", None), Kind::Json, soon()).await;
        assert_eq!(made.status(), StatusCode::CREATED);
        let made: serde_json::Value = serde_json::from_str(&body(made).await).unwrap();
        assert_eq!((&made["state"], &made["method"], &made["sat"]), (&"waiting".into(), &"onchain".into(), &64.into()));
        let seen = respond(&w.site, a(OTHER), &on_the_chain("big", None), Kind::Form, soon()).await;
        assert_eq!(seen.status(), StatusCode::SEE_OTHER);
        let at = seen.headers()["location"].to_str().unwrap().to_string();
        let waiting = get(&at, OTHER);
        assert_eq!(waiting.headers()["refresh"], "30", "the chain takes its time");
        let page = body(waiting).await;
        assert!(
            page.contains("<h1>Pay on the chain</h1>")
                && page.contains("Send <strong>1500 sat</strong> to this address"),
            "{page}"
        );
        assert!(page.contains("<svg class=\"qr\"") && page.contains("?amount=0.00001500\">"), "{page}");
        assert!(page.contains("<a href=\"bitcoin:bcrt1q") && page.contains("once it is confirmed"), "{page}");
        assert!(page.contains("half of it buys half the bytes and half the time"), "{page}");
        assert!(page.contains("The mint takes no more than 1000000 sat at once."), "{page}");
        // A part of the price arrived: the page says what it bought, and
        // where more can be sent.
        let id = at.strip_prefix("/order/").unwrap().to_string();
        let address = w.site.store.order(&id).unwrap().unwrap().request.unwrap();
        w.deposit(&address, 750).await;
        assert_eq!(until_arrived(&mut Looks::default(), &w.site, &id, 750).await.paid_sat, 750);
        let paid = get(&at, OTHER);
        assert_eq!(paid.headers()["refresh"], "30", "more may come");
        let page = body(paid).await;
        assert!(page.contains("Paid: 750 sat arrived, of the 1500 sat that big costs. That buys 500 MB"), "{page}");
        assert!(page.contains("This device is in it: <strong>500 MB</strong>, until "), "{page}");
        assert!(
            page.contains("<h2>More</h2>") && page.contains(&address) && page.contains("Show a key for it"),
            "{page}"
        );
        // The first page offers it where a mint takes it, and a price no
        // mint takes on the chain is given no address.
        let front = body(get("/", BUYER)).await;
        assert!(
            front.contains("name=\"method\" value=\"onchain\"") && front.contains("<button>Pay on the chain</button>")
        );
        let Err(Fault::NoInvoice(why)) = order(&w.site, a(BUYER), &on_the_chain("huge", None), soon()).await else {
            panic!("an address")
        };
        assert!(why.contains("takes a payment on the chain of 2000000 sat"), "{why}");
        let refused = respond(&w.site, a(BUYER), &on_the_chain("none", None), Kind::Json, soon()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
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
