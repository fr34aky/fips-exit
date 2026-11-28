//! Buying a package with a Cashu token, over the mesh.
//!
//! ```text
//! POST /v1/orders   {"package", "token", "key"?}   the package, and its key if it is a new one
//! POST /buy         the same as a form, answered with a page
//! ```
//!
//! (The same two ask for an invoice instead, with `"method": "bolt11"` and
//! no token: see `invoices`.)
//!
//! With a `key`, what is bought is added to the package that key opens;
//! without, it is a package of its own, with the device that asked in it.
//!
//! A token is looked at before anything is asked of its mint: it must be of
//! a mint this exit accepts, and worth the price after the mint's fee, and
//! not much more. One that is not is given back untouched. Then the order
//! is written down, the token is taken to the mint, and only what arrived
//! in the wallet becomes a package: in one place, [`Store::order_settle`].
//!
//! What may go wrong between asking the mint and hearing from it is not
//! guessed at. An order whose answer was lost stays open; the wallet is let
//! to finish what it began; and the mint is asked two things: whether it
//! signed what this wallet asked for in exchange for the token, and whether
//! the token's proofs are spent. One exchange does both at once, so:
//!
//! ```text
//! signed, and spent           the mint took the token for this wallet: paid
//! not signed, and spent       someone else spent it: nothing is granted
//! signed, and not spent       signed before, for something else (the wallet's
//!                             file is behind its seed's use): nothing is
//!                             granted, and the wallet counts again
//! not signed, and not spent   it may yet arrive: asked again, for a while
//! ```
//!
//! The same token sent again by its buyer is answered with what became of
//! it, and with a new key for the package if it made one: the answer that
//! carried the first may not have arrived.

use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Deserialize;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::http::{Site, answer};
use crate::manage;
use crate::store::{Begun, MAX_BYTES, NewOrder, Order, Refused, Settled, Store};
use crate::sync::{seat_of, unix_now};
use crate::terms::{bytes_shown, date, escape, shell};
use crate::wallet::{self, Inputs, MINT_TIME, Mint, Recorded, Refusal, Wallets};

/// How long a request waits to hear what became of its order. One that
/// takes longer is answered "not yet", and goes on.
const ANSWER_TIME: Duration = Duration::from_secs(30);
/// How many orders may be under way at once.
const AT_ONCE: usize = 8;
/// Tokens taken to a mint, for the whole service: this many in a burst, and
/// one more every six seconds. Limits for one address stop nobody who can
/// make new addresses. Within what the wallet library itself allows a mint
/// to be asked (20 requests at once, then one every three seconds), with
/// room for what else is asked there: past that the library makes a request
/// wait, and a token would be half taken for longer.
const BURST: f64 = 10.0;
const PER_SECOND: f64 = 1.0 / 6.0;
/// How long after an order began the mint is still asked whether it signed
/// for it, when it has said no so far.
const GIVE_UP: Duration = Duration::from_secs(600);
/// How often open orders are looked at again.
const AGAIN: Duration = Duration::from_secs(20);

/// What a purchase asks for.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asked {
    /// The id of a package on offer.
    pub package: String,
    /// The token that pays for it, when a token does.
    #[serde(default)]
    pub token: String,
    /// The key of a package to add to.
    #[serde(default)]
    pub key: Option<String>,
    /// How it is paid: `cashu`, with `token` (and so when nothing is said);
    /// or `bolt11`, by an invoice that is asked for here.
    #[serde(default)]
    pub method: Option<String>,
    /// For an invoice: the mint to ask for it, of those this exit accepts.
    #[serde(default)]
    pub mint: Option<String>,
}

/// How a purchase is asked, and so how it is answered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Json,
    Form,
}

/// A purchase done.
#[derive(Debug, PartialEq)]
pub struct Bought {
    pub order: String,
    /// The package, and what was bought as it was offered: of the order,
    /// whatever a request that sends its token again asks for.
    pub settled: Settled,
    /// Whether this token had paid before, and this is that purchase again.
    pub again: bool,
}

/// Why nothing was bought.
#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    /// This exit takes no payment (no mint is named, or none is reached).
    NotSold,
    NoOffer(String),
    /// The token cannot be read, or is not one this exit takes.
    Token(String),
    WrongMint(String),
    MintAway(String),
    TooLittle {
        value: u64,
        fee: u64,
        price: u64,
    },
    TooMuch {
        net: u64,
        price: u64,
    },
    /// There is an order for this token already, and it is not the caller's.
    Used,
    /// The order is under way, and what became of it is not known yet.
    NotYet,
    NoKey,
    TakenBack,
    Full,
    /// The caller is on the operator's own list.
    Listed,
    /// The caller would be carried without IPv4.
    NoIpv4,
    ExitDown,
    Busy,
    /// The mint did not take the token.
    Refused(String),
    /// The token could not be taken to its mint just now, and is untouched.
    Again,
    Bad(String),
    Store(String),
    /// No invoice is to be had: no mint gives one for that much, or the
    /// mint that was asked gave none.
    NoInvoice(String),
    /// The caller has this many invoices waiting to be paid already.
    TooMany(usize),
    /// There is no such order, as far as the caller may know.
    NoOrder,
    /// The order is not paid, so there is no package of it to have a key.
    NotPaid,
    /// The order made no package of its own to give a key of.
    NoNewKey,
    /// Another request of the caller's is under way, and did not end.
    UnderWay,
}

impl Fault {
    pub fn status(&self) -> StatusCode {
        match self {
            Fault::NotSold | Fault::MintAway(_) | Fault::ExitDown | Fault::Again | Fault::NoInvoice(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Fault::NoOffer(_) | Fault::Token(_) | Fault::WrongMint(_) | Fault::TooMuch { .. } | Fault::Bad(_) => {
                StatusCode::BAD_REQUEST
            }
            Fault::TooLittle { .. } => StatusCode::PAYMENT_REQUIRED,
            Fault::Used
            | Fault::TakenBack
            | Fault::Full
            | Fault::Listed
            | Fault::NoIpv4
            | Fault::Refused(_)
            | Fault::NotPaid
            | Fault::NoNewKey => StatusCode::CONFLICT,
            Fault::NotYet => StatusCode::ACCEPTED,
            Fault::NoKey => StatusCode::FORBIDDEN,
            Fault::NoOrder => StatusCode::NOT_FOUND,
            Fault::Busy | Fault::TooMany(_) | Fault::UnderWay => StatusCode::TOO_MANY_REQUESTS,
            Fault::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// A word for a program.
    pub fn code(&self) -> &'static str {
        match self {
            Fault::NotSold => "not-sold",
            Fault::NoOffer(_) => "no-such-package",
            Fault::Token(_) => "token",
            Fault::WrongMint(_) => "mint",
            Fault::MintAway(_) => "mint-away",
            Fault::TooLittle { .. } => "too-little",
            Fault::TooMuch { .. } => "too-much",
            Fault::Used => "used",
            Fault::NotYet => "not-yet",
            Fault::NoKey => "no-key",
            Fault::TakenBack => "taken-back",
            Fault::Full => "full",
            Fault::Listed => "listed",
            Fault::NoIpv4 => "no-ipv4",
            Fault::ExitDown => "exit-down",
            Fault::Busy => "busy",
            Fault::Refused(_) => "refused",
            Fault::Again => "try-again",
            Fault::Bad(_) => "bad-request",
            Fault::Store(_) => "store",
            Fault::NoInvoice(_) => "no-invoice",
            Fault::TooMany(_) => "too-many",
            Fault::NoOrder => "no-such-order",
            Fault::NotPaid => "not-paid",
            Fault::NoNewKey => "no-key-to-give",
            Fault::UnderWay => "under-way",
        }
    }

    /// And words for a person. Whenever the token was not touched, they say
    /// so.
    #[cfg(test)]
    pub fn said(&self) -> String {
        self.words(true)
    }

    /// The same for a purchase that sent a token (`with_token`), or one
    /// that asked for an invoice and so sent none.
    pub fn words(&self, with_token: bool) -> String {
        let untouched = if with_token { "The token was not touched." } else { "" };
        let said = match self {
            Fault::NotSold if !with_token => "Nothing can be bought here right now.".into(),
            Fault::Busy if !with_token => {
                "Too many invoices are being asked for just now: try again in a minute.".into()
            }
            Fault::Again if !with_token => "No invoice could be had just now: try again in a minute.".into(),
            Fault::WrongMint(mint) if !with_token => format!("{mint:.200} is not a mint this exit accepts."),
            Fault::NotSold => "Nothing can be bought here right now: no token is taken to a mint.".into(),
            Fault::NoOffer(id) => format!("No package {id:.40} is offered here. {untouched}"),
            Fault::Token(why) => format!("{why}. {untouched}"),
            Fault::WrongMint(mint) => {
                format!("The token is of {mint:.200}, which is not a mint this exit accepts. {untouched}")
            }
            Fault::MintAway(mint) => format!("The mint {mint} cannot be reached right now. {untouched}"),
            Fault::TooLittle { value, fee, price } => format!(
                "The token is worth {value} sat, and its mint takes {fee} sat for redeeming it: that is less than \
                 the price of {price} sat. {untouched}"
            ),
            Fault::TooMuch { net, price } => format!(
                "The token is worth {net} sat after its mint's fee, and the price is {price} sat: what is over is \
                 not given back, so one that is worth this much more is not taken. {untouched}"
            ),
            Fault::Used => "That token has been used here already.".into(),
            Fault::NotYet => {
                "The token was taken to its mint, and what became of it is not known yet. Send the same token again \
                 in a moment: it is not taken twice."
                    .into()
            }
            Fault::NoKey => format!("No package has that key. {untouched}"),
            Fault::TakenBack => format!("That package was taken back by the operator. {untouched}"),
            Fault::Full => format!("That package cannot hold more. {untouched}"),
            Fault::Listed => {
                format!("This device is on the exit's own list, and is carried without a package. {untouched}")
            }
            Fault::NoIpv4 => format!(
                "Another client of this exit has the inner IPv4 address this device would get, so it would be \
                 carried over IPv6 only: no package is sold to it for now. {untouched}"
            ),
            Fault::ExitDown => format!("The exit is not running. {untouched}"),
            Fault::Busy => format!("Too many tokens are being redeemed just now: try again in a minute. {untouched}"),
            Fault::Refused(why) => format!("The mint did not take the token: {why:.200}. Nothing was bought."),
            Fault::Again => {
                format!("The token could not be taken to its mint just now: send it again in a minute. {untouched}")
            }
            Fault::Bad(what) => what.clone(),
            Fault::Store(e) => format!("the store: {e}"),
            Fault::NoInvoice(why) => format!("{why:.300}"),
            Fault::TooMany(waiting) => format!(
                "This device has {waiting} invoices waiting to be paid here: pay one of them, or ask again when one \
                 has run out."
            ),
            Fault::NoOrder => "There is no such order of this device's.".into(),
            Fault::NotPaid => "That order is not paid: there is no package of it yet.".into(),
            Fault::UnderWay => {
                "Another purchase of this device's is being made here just now: try again in a moment.".into()
            }
            Fault::NoNewKey => {
                "No key is given for that order here. What it paid for was added to the package it was asked for; \
                 or its package was taken back; or it was paid with a token, which has its key again by being sent \
                 again."
                    .into()
            }
        };
        said.trim_end().to_string()
    }
}

impl From<Refusal> for Fault {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Token(why) => Fault::Token(why),
            Refusal::WrongMint(mint) => Fault::WrongMint(mint),
            Refusal::MintAway(mint) => Fault::MintAway(mint),
        }
    }
}

impl From<Refused> for Fault {
    fn from(refused: Refused) -> Self {
        Fault::Store(refused.to_string())
    }
}

/// Where tokens are taken: the wallets, and what bounds their use.
pub struct Desk {
    pub wallets: Arc<Wallets>,
    /// The daemon's control socket: it is asked whether an address can be
    /// served before anything is sold to it.
    control: PathBuf,
    /// One question to the daemon at a time: it takes few connections.
    asking: tokio::sync::Mutex<()>,
    /// The orders a request is working on now, and who asked: those are not
    /// the reconciler's to decide.
    at_work: Mutex<(HashSet<String>, HashSet<Ipv6Addr>)>,
    places: Arc<Semaphore>,
    /// What is left of the budget, and when that was so.
    budget: Mutex<(f64, Instant)>,
    /// Told when an order is left open, so that it is looked at soon.
    pub wake: Notify,
    pub give_up: Duration,
    /// What is kept of the invoices that wait to be paid.
    pub invoices: crate::invoices::Waiting,
}

/// An order being worked on by a request, until this is dropped.
pub struct AtWork {
    desk: Arc<Desk>,
    order: String,
    buyer: Ipv6Addr,
}

impl Drop for AtWork {
    fn drop(&mut self) {
        let mut at_work = self.desk.at_work.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        at_work.0.remove(&self.order);
        at_work.1.remove(&self.buyer);
    }
}

impl Desk {
    pub fn new(wallets: Arc<Wallets>, control: PathBuf) -> Desk {
        Desk {
            wallets,
            control,
            asking: tokio::sync::Mutex::new(()),
            at_work: Mutex::default(),
            places: Arc::new(Semaphore::new(AT_ONCE)),
            budget: Mutex::new((BURST, Instant::now())),
            wake: Notify::new(),
            give_up: GIVE_UP,
            invoices: crate::invoices::Waiting::default(),
        }
    }

    /// One token's worth of the budget, if there is any. An invoice asked
    /// of a mint is paid for from the same.
    pub fn spend(&self) -> bool {
        let mut budget = self.budget.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let left = (budget.0 + now.duration_since(budget.1).as_secs_f64() * PER_SECOND).min(BURST);
        *budget = (if left >= 1.0 { left - 1.0 } else { left }, now);
        left >= 1.0
    }

    /// Begin work on `order` for `buyer`: one order at a time for an
    /// address.
    pub fn enter(self: &Arc<Self>, order: &str, buyer: Ipv6Addr) -> Option<AtWork> {
        let mut at_work = self.at_work.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !at_work.1.insert(buyer) {
            return None;
        }
        at_work.0.insert(order.to_string());
        Some(AtWork { desk: self.clone(), order: order.to_string(), buyer })
    }

    fn is_at_work(&self, order: &str) -> bool {
        self.at_work.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).0.contains(order)
    }

    /// Can `caller` be sold a package of its own? The daemon says what the
    /// address is to it. For a package that is only added to, the exit has
    /// to be running, and that is all.
    async fn can_serve(&self, caller: Ipv6Addr, of_its_own: bool) -> Result<(), Fault> {
        let _one = self.asking.lock().await;
        let seat = tokio::time::timeout(Duration::from_secs(5), seat_of(&self.control, caller))
            .await
            .map_err(|_| Fault::ExitDown)?
            .map_err(|_| Fault::ExitDown)?;
        let words: Vec<&str> = seat.split_whitespace().collect();
        match words[..] {
            _ if !of_its_own => Ok(()),
            ["static"] => Err(Fault::Listed),
            [.., "no4"] => Err(Fault::NoIpv4),
            ["free", "v4"] | ["member", _, "v4"] => Ok(()),
            _ => Err(Fault::ExitDown),
        }
    }
}

/// The key the purchase names, if it names one: as a key is written.
pub fn key_asked(asked: &Asked) -> Result<Option<String>, Fault> {
    match asked.key.as_deref().map(str::trim).filter(|key| !key.is_empty()) {
        Some(key) => manage::key_of(key).map(Some).ok_or(Fault::NoKey),
        None => Ok(None),
    }
}

/// An order there already is for the token: what became of it, for its
/// buyer; nothing of it for anyone else.
fn known(site: &Site, caller: Ipv6Addr, order: &Order) -> Result<Bought, Fault> {
    if order.buyer != caller {
        return Err(Fault::Used);
    }
    if !order.paid {
        if let Some(desk) = &site.desk {
            desk.wake.notify_one();
        }
        return Err(Fault::NotYet);
    }
    let settled = site.store.order_settle(&order.id, order.paid_sat, unix_now())?;
    // The key that came with the first answer may never have arrived: a new
    // one, for a package this order made.
    let key = if settled.added { None } else { site.store.order_new_key(&order.id)? };
    Ok(Bought { order: order.id.clone(), settled: Settled { key, ..settled }, again: true })
}

/// Order `id` is paid: `paid` sat arrived.
pub fn settle(site: &Site, mint: &Mint, id: &str, paid: u64) -> Result<Bought, Fault> {
    match site.store.order_settle(id, paid, unix_now()) {
        Ok(settled) => {
            eprintln!(
                "fips-exit-payd: order {id}: {paid} sat arrived at {}; {} package {}",
                mint.name,
                if settled.added { "added to" } else { "it is" },
                settled.package.id
            );
            site.changed.notify_one();
            Ok(Bought { order: id.to_string(), settled, again: false })
        }
        Err(e) => {
            // What arrived is in the wallet, and the order is open: it is
            // settled when the store takes it.
            eprintln!(
                "fips-exit-payd: ORDER {id} IS PAID ({paid} sat) AND COULD NOT BE SETTLED: {e}. It is tried again."
            );
            Err(Fault::NotYet)
        }
    }
}

/// Take `token` to `mint` for order `id`, which is written down and at work.
async fn take(
    site: Arc<Site>,
    mint: Arc<Mint>,
    id: String,
    token: String,
    receipt: [u8; 32],
    _at_work: AtWork,
    _place: OwnedSemaphorePermit,
) -> Result<Bought, Fault> {
    let Some(desk) = site.desk.clone() else { return Err(Fault::NotSold) };
    let turn = mint.turn.lock().await;
    let outcome = match tokio::time::timeout(MINT_TIME, mint.receive(&token, &id)).await {
        Ok(Ok(paid)) => settle(&site, &mint, &id, paid),
        // The mint said no, or was not reached, or its answer was lost. The
        // wallet knows which: whether it has something unfinished.
        Ok(Err(error)) => {
            // A mint that says it signed before what the wallet asked of it
            // now (in either of the ways mints say it): the wallet's file
            // is behind its seed's use, and what was signed then is not
            // this order's, whatever is found of it later.
            let stale = matches!(error, cdk::Error::BlindedMessageAlreadySigned | cdk::Error::DuplicateOutputs);
            match mint.unfinished(&receipt).await {
                Ok(None) => {
                    site.store.order_drop(&id)?;
                    if stale {
                        mint.suspect();
                        Err(Fault::Again)
                    } else if error.is_definitive_failure() {
                        eprintln!("fips-exit-payd: order {id}: {} did not take the token: {error}", mint.name);
                        Err(Fault::Refused(error.to_string()))
                    } else {
                        Err(Fault::Again)
                    }
                }
                // Unfinished: decided now if the mint can be asked, and
                // else left open. What the mint said is not the end of it
                // by itself: "spent" may be the wallet's own request having
                // spent the token.
                Ok(Some(_)) => {
                    decide(&site, &desk, &mint, Some(Mine { id: &id, stale })).await.mine.unwrap_or(Err(Fault::NotYet))
                }
                Err(_) => Err(Fault::NotYet),
            }
        }
        Err(_) => Err(Fault::NotYet),
    };
    drop(turn);
    if outcome == Err(Fault::NotYet) {
        eprintln!("fips-exit-payd: order {id}: what became of the token at {} is not known yet", mint.name);
        desk.wake.notify_one();
    }
    outcome
}

/// What is asked of a new purchase before its token goes anywhere: that it
/// is worth the price and not much more, that the package it is to be added
/// to can take it, and that the caller can be served. The package to add
/// to, if one.
async fn fits(
    site: &Site,
    desk: &Desk,
    caller: Ipv6Addr,
    offer: &fips_exit_proto::Package,
    key: Option<&str>,
    look: &wallet::Look,
) -> Result<Option<String>, Fault> {
    let net = look.value.saturating_sub(look.fee);
    if net < offer.sat {
        return Err(Fault::TooLittle { value: look.value, fee: look.fee, price: offer.sat });
    }
    if net > offer.sat + offer.sat / 10 {
        return Err(Fault::TooMuch { net, price: offer.sat });
    }
    whose(site, desk, caller, offer, key).await
}

/// Whose package a purchase of `offer` by `caller` is to be: the package
/// `key` opens, if it can take it, or (None) one of the caller's own, if
/// the caller can be served.
pub async fn whose(
    site: &Site,
    desk: &Desk,
    caller: Ipv6Addr,
    offer: &fips_exit_proto::Package,
    key: Option<&str>,
) -> Result<Option<String>, Fault> {
    let target = match key {
        Some(key) => {
            let package = site.store.package_with_key(key)?.ok_or(Fault::NoKey)?;
            if package.revoked {
                return Err(Fault::TakenBack);
            }
            if package.granted.saturating_add(offer.bytes) > MAX_BYTES {
                return Err(Fault::Full);
            }
            Some(package.id)
        }
        None => None,
    };
    desk.can_serve(caller, target.is_none()).await?;
    Ok(target)
}

/// Buy what `asked` asks for, for `caller`, and say what became of it by
/// `until`: the connection that asks lives no longer.
pub async fn buy(site: &Arc<Site>, caller: Ipv6Addr, asked: &Asked, until: Instant) -> Result<Bought, Fault> {
    let desk = site.desk.as_ref().ok_or(Fault::NotSold)?;
    let (token, text) = wallet::parse(&asked.token)?;
    let mint = desk.wallets.mint_of(&token)?;
    // The same token again: what became of it, whatever is asked now and
    // whatever could be sold now. Before everything that is asked only of a
    // new purchase, each of which would say that the token was not touched.
    if let Some(receipt) = mint.receipt(&token).await
        && let Some(order) = site.store.order_with_receipt(&receipt)?
    {
        return known(site, caller, &order);
    }
    if !mint.ready() {
        return Err(Fault::MintAway(mint.name.clone()));
    }
    if Instant::now() >= until {
        return Err(Fault::Again);
    }
    let offer = site
        .config
        .packages
        .iter()
        .find(|offer| offer.id == asked.package)
        .ok_or_else(|| Fault::NoOffer(asked.package.clone()))?;
    let key = key_asked(asked)?;
    // Nothing has been taken anywhere so far, so running out of time is
    // nothing lost.
    let checked = tokio::time::timeout_at(until, async {
        let look = mint.look(&token).await?;
        let target = fits(site, desk, caller, offer, key.as_deref(), &look).await?;
        Ok::<_, Fault>((look, target))
    });
    let (look, target) = checked.await.map_err(|_| Fault::Again)??;
    let place = desk.places.clone().try_acquire_owned().map_err(|_| Fault::Busy)?;
    let id = Store::order_id()?;
    let at_work = desk.enter(&id, caller).ok_or(Fault::Busy)?;
    if !desk.spend() {
        return Err(Fault::Busy);
    }
    let new = NewOrder {
        buyer: caller,
        mint: &mint.name,
        offer: &offer.id,
        bytes: offer.bytes,
        sat: offer.sat,
        days: offer.days,
        target: target.as_deref(),
        receipt: &look.receipt,
        value: look.value,
        inputs: &look.inputs,
    };
    if let Begun::Known(order) = site.store.order_begin(&id, &new, unix_now())? {
        return known(site, caller, &order);
    }
    // On its own, so that it goes on whatever becomes of this request: a
    // token half taken is not left because a connection closed. The request
    // waits for it as long as its connection lives, and then says "not
    // yet".
    let task = tokio::spawn(take(site.clone(), mint.clone(), id, text, look.receipt, at_work, place));
    let wait = until.saturating_duration_since(Instant::now()).min(ANSWER_TIME);
    match tokio::time::timeout(wait, task).await {
        Ok(Ok(outcome)) => outcome,
        _ => Err(Fault::NotYet),
    }
}

// ---- what was left open -----------------------------------------------------

/// Decide the open orders that no request is working on: those a restart,
/// a lost answer or a slow mint left behind. How many are still open.
pub async fn round(site: &Site) -> usize {
    let Some(desk) = &site.desk else { return 0 };
    let open = match site.store.orders_open() {
        Ok(open) => open,
        Err(e) => {
            eprintln!("fips-exit-payd: the open orders could not be read: {e}");
            return 0;
        }
    };
    let mut left = 0;
    for mint in &desk.wallets.mints {
        if open.iter().any(|order| order.mint == mint.name) {
            let _turn = mint.turn.lock().await;
            left += decide(site, desk, mint, None).await.left;
        }
    }
    // An order at a mint that is not accepted any more waits for it.
    left + open.iter().filter(|order| desk.wallets.named(&order.mint).is_none()).count()
}

/// What [`decide`] came to.
struct Decided {
    /// How many orders at the mint are still open.
    left: usize,
    /// What became of the order it was asked about in particular, if that
    /// is known now.
    mine: Option<Result<Bought, Fault>>,
}

/// The order of the request that asks [`decide`].
#[derive(Clone, Copy)]
struct Mine<'a> {
    id: &'a str,
    /// The mint has just said that it signed before what the wallet asked
    /// it to sign for this order: that is not this order's, then.
    stale: bool,
}

/// What an open order has come to.
enum Verdict {
    /// This much arrived.
    Paid(u64),
    /// The mint did not take the token for this wallet, and its proofs are
    /// spent: by someone else.
    SpentElsewhere,
    /// What the mint has signed of this order's outputs it signed before:
    /// the wallet's file is behind its seed's use.
    Stale,
    /// The token was not taken, and will not be now.
    NotTaken,
    Open,
}

/// Decide the open orders at `mint`, whose turn the caller holds: all that
/// no request is working on, and `mine`, the order of the request that
/// asks.
///
/// The one place where the wallet is let to finish what it began, and so
/// the one place that must keep, first, what the wallet asked the mint to
/// sign for every open order: once the wallet has put itself right it does
/// not know any more, and what it concludes is not what is gone by.
async fn decide(site: &Site, desk: &Desk, mint: &Mint, mine: Option<Mine<'_>>) -> Decided {
    let receipt = |order: &Order| <[u8; 32]>::try_from(order.receipt.as_slice()).ok();
    let is_mine = |order: &Order| mine.is_some_and(|mine| mine.id == order.id);
    let all = site.store.orders_open().unwrap_or_default();
    let all: Vec<&Order> = all.iter().filter(|order| order.mint == mint.name).collect();
    let mut open: Vec<Order> = all
        .iter()
        .filter(|order| is_mine(order) || !desk.is_at_work(&order.id))
        .map(|order| (*order).clone())
        .collect();
    let mut decided = Decided { left: all.len() - open.len(), mine: None };
    let mut unfinished = false;
    for order in &mut open {
        let Some(receipt) = receipt(order) else { continue };
        match mint.unfinished(&receipt).await {
            Ok(Some(found)) => {
                unfinished = true;
                if let (None, Some(outputs)) = (&order.outputs, found.outputs) {
                    if let Err(e) = site.store.order_keep_outputs(&order.id, &outputs) {
                        eprintln!(
                            "fips-exit-payd: order {}: what was asked of the mint could not be kept: {e}",
                            order.id
                        );
                        decided.left += open.len();
                        return decided;
                    }
                    order.outputs = Some(outputs);
                }
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("fips-exit-payd: {}: the wallet could not be read: {e}", mint.name);
                decided.left += open.len();
                return decided;
            }
        }
    }
    // Whether the wallet finished what it began, as far as the mint let
    // it. If it did not (the mint was slow, or away), a request of its own
    // may still be on its way, and nothing is given up in this round.
    let mut finished = true;
    if unfinished && let Err(e) = mint.put_right().await {
        eprintln!("fips-exit-payd: {}: the wallet could not finish what it began: {e}", mint.name);
        finished = false;
    }
    for order in &open {
        let Some(receipt) = receipt(order) else { continue };
        let Ok(still) = mint.unfinished(&receipt).await else {
            decided.left += 1;
            continue;
        };
        let old = unix_now().saturating_sub(order.created) >= desk.give_up.as_secs();
        let verdict = match &order.outputs {
            Some(_) if mine.is_some_and(|mine| mine.id == order.id && mine.stale) => Verdict::Stale,
            // The mint was asked to sign for it: the mint says whether it
            // did, and whether the token is spent. One exchange does both.
            Some(outputs) => match (mint.signed(outputs).await, mint.inputs(&order.inputs).await) {
                (Ok(sat), Ok(Inputs::Spent)) if sat > 0 => Verdict::Paid(sat),
                (Ok(sat), Ok(_)) if sat > 0 => Verdict::Stale,
                (Ok(_), Ok(Inputs::Spent | Inputs::Partly)) => Verdict::SpentElsewhere,
                // Neither, so far. Given up only when the wallet has
                // nothing of it left to ask again, and long enough after it
                // asked that nothing of it is still on its way.
                (Ok(_), Ok(Inputs::Unspent)) if old && finished && still.is_none() => Verdict::NotTaken,
                _ => Verdict::Open,
            },
            // It was not: the wallet either took the token without a hitch
            // and the order was not settled (its record says so), or never
            // came to ask.
            None if still.is_some() => Verdict::Open,
            None => match mint.recorded(&order.id).await {
                Ok(Recorded::Received(sat, _)) => Verdict::Paid(sat),
                Ok(_) => Verdict::NotTaken,
                Err(_) => Verdict::Open,
            },
        };
        // An order that came to nothing is forgotten, and with it what the
        // wallet could not give up by itself.
        let forget = |why: String| async move {
            eprintln!("fips-exit-payd: order {}: {why}: forgotten", order.id);
            if still.is_some()
                && let Err(e) = mint.forget(&receipt).await
            {
                eprintln!("fips-exit-payd: {}: the wallet could not give the token up: {e}", mint.name);
            }
            site.store.order_drop(&order.id).map_err(|e| Fault::Store(e.to_string()))
        };
        let outcome = match verdict {
            Verdict::Open => Err(Fault::NotYet),
            Verdict::SpentElsewhere => {
                let forgotten = forget("the token is spent, and not for this exit".into()).await;
                forgotten.and(Err(Fault::Refused("it is spent already".into())))
            }
            Verdict::NotTaken => forget(format!("{} did not take the token", mint.name)).await.and(Err(Fault::Again)),
            Verdict::Stale => {
                mint.suspect();
                forget("the mint signed what was asked of it before this order".into()).await.and(Err(Fault::Again))
            }
            Verdict::Paid(sat) => {
                let settled = settle(site, mint, &order.id, sat);
                if settled.is_ok() && order.outputs.is_some() {
                    found_again(site, mint).await;
                }
                settled
            }
        };
        if matches!(outcome, Err(Fault::NotYet | Fault::Store(_))) {
            decided.left += 1;
        }
        if is_mine(order) {
            decided.mine = Some(outcome);
        }
    }
    decided
}

/// An order was settled on the mint's word, and not because the wallet took
/// what was paid without a hitch: if the wallet does not hold it, it is
/// found again from the seed. The caller holds the mint's turn.
pub async fn found_again(site: &Site, mint: &Mint) {
    let (holds, sold) = (mint.balance().await.map(|b| b.0), site.store.sold(&mint.name));
    if let (Ok(holds), Ok(sold)) = (holds, sold)
        && holds < sold
    {
        let found = mint.count_again().await.unwrap_or_else(|e| format!("not counted again: {e}"));
        eprintln!("fips-exit-payd: {}: the wallet held {holds} sat of {sold} sat sold: {found}", mint.name);
    }
}

/// Look at the open orders for as long as the service runs: at its start,
/// when one is left open, and every [`AGAIN`] while there are any.
pub async fn keep(site: Arc<Site>) {
    let Some(desk) = site.desk.clone() else { return };
    loop {
        let left = round(&site).await;
        let wait = if left > 0 { AGAIN } else { Duration::from_secs(600) };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = desk.wake.notified() => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

// ---- answers ------------------------------------------------------------------

/// Does the caller hold the key of the package it bought or added to: was
/// it given one now, or did it ask with the one that opens it?
fn holds_key(site: &Site, asked: &Asked, bought: &Bought) -> Option<String> {
    if let Some(key) = &bought.settled.key {
        return Some(key.clone());
    }
    let key = key_asked(asked).ok().flatten()?;
    let opens = site.store.package_with_key(&key).ok().flatten()?;
    (opens.id == bought.settled.package.id).then_some(key)
}

pub fn json(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    answer(status, "application/json", serde_json::to_vec(value).unwrap_or_default())
}

pub fn page(status: StatusCode, title: &str, body: &str) -> Response<Full<Bytes>> {
    answer(status, "text/html; charset=utf-8", shell(title, body))
}

/// What was bought, for a person.
fn bought_words(bought: &Bought) -> String {
    let (settled, offer) = (&bought.settled, &bought.settled.offer);
    let fee =
        if settled.fee_sat > 0 { format!(" (its mint took {} sat more)", settled.fee_sat) } else { String::new() };
    let what = if settled.added {
        format!("{offer} was added to package {}", settled.package.id)
    } else {
        format!("{offer} is package {}", settled.package.id)
    };
    if bought.again {
        format!("This token paid before: {} sat arrived{fee}, and {what}.", settled.paid_sat)
    } else {
        format!("Paid: {} sat arrived{fee}, and {what}.", settled.paid_sat)
    }
}

/// A purchase asked as `kind`, by `caller`, answered by `until`.
pub async fn respond(
    site: &Arc<Site>,
    caller: Ipv6Addr,
    asked: &Asked,
    kind: Kind,
    until: Instant,
) -> Response<Full<Bytes>> {
    // Another way to pay than a token: an invoice is asked for.
    if asked.method.as_deref().is_some_and(|method| method != crate::store::CASHU) {
        return crate::invoices::respond(site, caller, asked, kind, until).await;
    }
    let outcome = buy(site, caller, asked, until).await;
    match (kind, outcome) {
        (Kind::Json, Err(fault)) => refuse(Kind::Json, &fault),
        (Kind::Form, Err(fault)) => refuse(Kind::Form, &fault),
        (Kind::Json, Ok(bought)) => {
            let holds = holds_key(site, asked, &bought);
            let settled = &bought.settled;
            // Who is in a package is for whoever holds its key.
            let package = match &holds {
                Some(_) => serde_json::to_value(manage::view(site, &settled.package, caller)).unwrap_or_default(),
                None => serde_json::json!({ "id": settled.package.id }),
            };
            let mut said = serde_json::json!({
                "order": bought.order,
                "paid_sat": settled.paid_sat,
                "fee_sat": settled.fee_sat,
                "added": settled.added,
                "again": bought.again,
                "package": package,
            });
            if let Some(key) = &settled.key {
                said["key"] = serde_json::Value::String(key.clone());
            }
            json(StatusCode::OK, &said)
        }
        (Kind::Form, Ok(bought)) => {
            let done = bought_words(&bought);
            let settled = &bought.settled;
            match (holds_key(site, asked, &bought), &settled.key) {
                // Added to a package whose key the buyer has: its page.
                (Some(key), None) => answer(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    manage::page(site, &settled.package, &key, caller, &done),
                ),
                // A package of its own: its key, this once.
                (Some(key), Some(_)) => {
                    let until = match settled.package.until {
                        0 => String::new(),
                        until => format!(", until {}", date(until)),
                    };
                    let again = if bought.again {
                        "<p>The key it had before opens nothing any more: this is its key now.</p>\n"
                    } else {
                        ""
                    };
                    let body = format!(
                        "<p class=\"note\">{done}</p>\n<p>This device is in it: <strong>{left}</strong>{until}.</p>\n\
                         <h2>Its key</h2>\n<p><code>{key}</code></p>\n{again}<p>It is shown this once, and not kept \
                         here: keep it. Whoever has it sees who is in the package, takes devices out of it, and adds \
                         to it. Another device of yours is added by itself: give it the key, and open this exit's \
                         page on it.</p>\n<form method=\"post\" action=\"/package\"><input type=\"hidden\" \
                         name=\"key\" value=\"{key}\"><button>Manage it</button></form>\n<p><a href=\"/\">Back</a></p>\n",
                        done = escape(&done),
                        left = bytes_shown(settled.package.left()),
                        key = escape(&key),
                    );
                    page(StatusCode::OK, "Paid", &body)
                }
                (None, _) => {
                    let body = format!("<p class=\"note\">{}</p>\n<p><a href=\"/\">Back</a></p>\n", escape(&done));
                    page(StatusCode::OK, "Paid", &body)
                }
            }
        }
    }
}

/// A purchase as JSON.
pub fn asked_json(body: &[u8]) -> Result<Asked, Fault> {
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(Fault::Bad("not the request this is: a JSON object".into()));
    }
    serde_json::from_slice(body).map_err(|e| Fault::Bad(format!("not the request this is: {e}")))
}

/// A purchase as the page's form sends it.
pub fn asked_form(body: &[u8]) -> Asked {
    let fields = manage::form_fields(body);
    let field = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.trim().to_string());
    Asked {
        package: field("package").unwrap_or_default(),
        token: field("token").unwrap_or_default(),
        key: field("key").filter(|key| !key.is_empty()),
        method: field("method").filter(|method| !method.is_empty()),
        mint: field("mint").filter(|mint| !mint.is_empty()),
    }
}

/// A request that is not a purchase, said as `kind` is answered.
pub fn refuse(kind: Kind, fault: &Fault) -> Response<Full<Bytes>> {
    refuse_as(kind, fault, true)
}

/// The same, for a purchase that sent a token or (`with_token` false) one
/// that sent none.
pub fn refuse_as(kind: Kind, fault: &Fault, with_token: bool) -> Response<Full<Bytes>> {
    let said = fault.words(with_token);
    match kind {
        Kind::Json => json(fault.status(), &serde_json::json!({ "error": said, "code": fault.code() })),
        Kind::Form => page(
            fault.status(),
            match fault {
                Fault::NotYet => "Not known yet",
                Fault::NoOrder => "No such order",
                Fault::NotPaid | Fault::NoNewKey => "No key",
                _ => "Not bought",
            },
            &format!("<p class=\"note\">{}</p>\n<p><a href=\"/\">Back</a></p>\n", escape(&said)),
        ),
    }
}

/// A whole exit's payment side for a test: a mint, a way to it that can
/// lose things, a wallet, a daemon that says what an address is.
#[cfg(test)]
pub mod testing {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use fips_exit_test_mint::Proxy;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::config::{Config, settings};
    use crate::sync::Seats;
    use crate::terms::Exit;

    pub struct World {
        pub site: Arc<Site>,
        /// The mint as the exit names it: by way of `proxy`.
        pub mint: String,
        /// The mint itself: where a test says what becomes of its invoices.
        pub direct: String,
        pub proxy: Proxy,
        pub dir: PathBuf,
        /// What the daemon says an address is, when it is not `free v4`.
        pub seats: Arc<Mutex<HashMap<Ipv6Addr, String>>>,
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    static WORLDS: AtomicUsize = AtomicUsize::new(0);

    /// A daemon that answers `check`, and nothing else.
    async fn daemon(listener: tokio::net::UnixListener, seats: Arc<Mutex<HashMap<Ipv6Addr, String>>>) {
        while let Ok((stream, _)) = listener.accept().await {
            let seats = seats.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let answer = match line.split_whitespace().collect::<Vec<_>>()[..] {
                        ["check", address] => {
                            let seat =
                                address.parse().ok().and_then(|address| seats.lock().unwrap().get(&address).cloned());
                            format!("ok {}\n", seat.unwrap_or_else(|| "free v4".into()))
                        }
                        _ => "err command\n".into(),
                    };
                    if writer.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    /// An exit that sells `small` (10 MB, 64 sat, a day) and `big` (1 GB,
    /// 1500 sat, 30 days) for tokens of a mint of its own, which takes
    /// `fee_ppk` for a proof; an open order is given up after `give_up`.
    pub async fn world(fee_ppk: u64, give_up: Duration) -> World {
        world_with(fee_ppk, give_up, 3600, "").await
    }

    /// The same, with invoices that end after `invoice_seconds`, and
    /// `more` packages on offer. An invoice that waits is looked at
    /// whenever a test says so, and given up as soon as it has ended.
    pub async fn world_with(fee_ppk: u64, give_up: Duration, invoice_seconds: u64, more: &str) -> World {
        let dir = std::env::temp_dir().join(format!(
            "fips-exit-payd-orders-{}-{}",
            std::process::id(),
            WORLDS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mint =
            fips_exit_test_mint::start_with("127.0.0.1:0".parse().unwrap(), fee_ppk, invoice_seconds).await.unwrap();
        let proxy = fips_exit_test_mint::proxy(&mint).await.unwrap();
        let config = Config::from_settings(&settings(&format!(
            "ACCESS=paid\nPRICE_MSAT_PER_GB=2000000\nPACKAGES=\"small:10MB:64:1 big:1GB:1500:30{more}\"\nMINTS={}\n",
            proxy.url
        )))
        .unwrap()
        .unwrap();
        let exit = Exit {
            npub: "npub1exit".into(),
            address: "fd00::e".parse().unwrap(),
            name: String::new(),
            about: String::new(),
            country: None,
        };
        let control = dir.join("control.sock");
        let seats: Arc<Mutex<HashMap<Ipv6Addr, String>>> = Arc::default();
        tokio::spawn(daemon(tokio::net::UnixListener::bind(&control).unwrap(), seats.clone()));
        let wallets = Arc::new(Wallets::open(&dir, &config.mints).await.unwrap());
        for mint in &wallets.mints {
            mint.reach().await.unwrap();
        }
        let mut desk = Desk::new(wallets, control);
        desk.give_up = give_up;
        (desk.invoices.every, desk.invoices.grace, desk.invoices.pace, desk.invoices.life) =
            (Duration::ZERO, 0, (0, 0), 0);
        let mut site = Site::new(config, exit, Arc::new(Store::in_memory()), Seats::default(), Arc::default());
        site.desk = Some(Arc::new(desk));
        World { site: Arc::new(site), mint: proxy.url.clone(), direct: mint, proxy, dir, seats }
    }

    impl World {
        /// A token of `sat` of the exit's mint, from a wallet of a buyer's.
        pub async fn token(&self, sat: u64) -> String {
            fips_exit_test_mint::new_token(&self.mint, sat, false).await.unwrap()
        }

        pub fn the_mint(&self) -> &Arc<Mint> {
            &self.site.desk.as_ref().unwrap().wallets.mints[0]
        }

        /// What the exit's wallet holds, in sat.
        pub async fn holds(&self) -> u64 {
            self.the_mint().balance().await.unwrap().0
        }

        pub async fn buy(&self, caller: &str, package: &str, token: &str, key: Option<&str>) -> Result<Bought, Fault> {
            let asked = Asked {
                package: package.into(),
                token: token.into(),
                key: key.map(str::to_string),
                ..Asked::default()
            };
            buy(&self.site, caller.parse().unwrap(), &asked, Instant::now() + Duration::from_secs(60)).await
        }

        /// Another wallet on this exit's seed, in a directory of its own
        /// with nothing but the seed: as when a second service is started
        /// with a copy of it, which is not to be done.
        pub async fn second_wallet(&self, name: &str) -> Wallets {
            let dir = self.dir.join(name);
            std::fs::create_dir(&dir).unwrap();
            std::fs::copy(self.dir.join("seed"), dir.join("seed")).unwrap();
            let wallets = Wallets::open(&dir, std::slice::from_ref(&self.mint)).await.unwrap();
            wallets.mints[0].reach().await.unwrap();
            wallets
        }

        /// The same exit with `wallets` in place of its own: as after its
        /// wallet's file was lost, or with a second service on its seed.
        pub fn with_wallets(&self, wallets: Wallets) -> Arc<Site> {
            let mut desk = Desk::new(Arc::new(wallets), self.dir.join("control.sock"));
            (desk.invoices.every, desk.invoices.grace, desk.invoices.pace, desk.invoices.life) =
                (Duration::ZERO, 0, (0, 0), 0);
            let mut site = Site::new(
                self.site.config.clone(),
                self.site.exit.clone(),
                self.site.store.clone(),
                Seats::default(),
                Arc::default(),
            );
            site.desk = Some(Arc::new(desk));
            Arc::new(site)
        }

        /// The same exit, with its own wallet, that gives nobody an invoice
        /// which ends within `life` seconds.
        pub fn with_invoice_life(&self, life: u64) -> Arc<Site> {
            let wallets = self.site.desk.as_ref().unwrap().wallets.clone();
            let mut desk = Desk::new(wallets, self.dir.join("control.sock"));
            (desk.invoices.every, desk.invoices.grace, desk.invoices.pace, desk.invoices.life) =
                (Duration::ZERO, 0, (0, 0), life);
            let mut site = Site::new(
                self.site.config.clone(),
                self.site.exit.clone(),
                self.site.store.clone(),
                Seats::default(),
                Arc::default(),
            );
            site.desk = Some(Arc::new(desk));
            Arc::new(site)
        }

        /// From now on the mint's invoices are paid when [`World::pay`]
        /// says so.
        pub async fn hold(&self) {
            fips_exit_test_mint::hold(&self.direct).await.unwrap();
        }

        /// Somebody pays the invoice `request`.
        pub async fn pay(&self, request: &str) {
            fips_exit_test_mint::pay(&self.direct, request).await.unwrap();
        }

        /// Is `token` still good: can a wallet of somebody's redeem it?
        pub async fn still_good(&self, token: &str) -> bool {
            let wallet = fips_exit_test_mint::wallet(&self.mint).await.unwrap();
            wallet.receive(token, cdk::wallet::ReceiveOptions::default()).await.is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::testing::{World, world};
    use super::*;
    use crate::store::Standing;

    const BUYER: &str = "fd77::7";
    const OTHER: &str = "fd88::8";

    fn a(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }

    async fn body(response: Response<Full<Bytes>>) -> String {
        String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    async fn ask(
        w: &World,
        caller: &str,
        package: &str,
        token: &str,
        key: Option<&str>,
        kind: Kind,
    ) -> (StatusCode, String) {
        let asked =
            Asked { package: package.into(), token: token.into(), key: key.map(str::to_string), ..Asked::default() };
        let response = respond(&w.site, a(caller), &asked, kind, Instant::now() + Duration::from_secs(60)).await;
        (response.status(), body(response).await)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_buys_a_package() {
        let w = world(0, GIVE_UP).await;
        assert_eq!(w.site.methods(), vec!["cashu", "bolt11"], "the tests' mint gives invoices too");
        let token = w.token(64).await;
        let bought = w.buy(BUYER, "small", &format!("  cashu:{token}\n"), None).await.unwrap();
        let (settled, now) = (&bought.settled, unix_now());
        assert!(!bought.again && !settled.added);
        assert_eq!((settled.paid_sat, settled.fee_sat), (64, 0));
        let package = &settled.package;
        assert_eq!(
            (package.granted, package.members.clone(), package.label.as_str()),
            (10_000_000, vec![a(BUYER)], "bought: small")
        );
        assert!((now + 86_390..=now + 86_400).contains(&package.until), "a day from now");
        assert_eq!(package.standing(now), Standing::Live);
        // Its key opens it, and what was paid is in the wallet, once.
        let key = settled.key.clone().unwrap();
        assert_eq!(w.site.store.package_with_key(&key).unwrap().unwrap().id, package.id);
        assert_eq!(w.holds().await, 64);
        assert_eq!(w.site.store.sold(&w.mint).unwrap(), 64);
        let order = w.site.store.order(&bought.order).unwrap().unwrap();
        assert!(order.paid && order.package.as_deref() == Some(package.id.as_str()) && order.outputs.is_none());
        assert_eq!((order.buyer, order.offer.as_str(), order.sat, order.value), (a(BUYER), "small", 64, 64));
        assert!(!w.still_good(&token).await, "the token is the exit's now");
        // A little over the price is taken, and kept.
        let over = w.token(66).await;
        assert_eq!(w.buy(OTHER, "small", &over, None).await.unwrap().settled.paid_sat, 66);
        assert_eq!(w.holds().await, 130);
        // A buyer that was in a package is moved to the one it bought.
        let again = w.token(64).await;
        let moved = w.buy(BUYER, "small", &again, None).await.unwrap();
        assert_ne!(moved.settled.package.id, package.id);
        assert_eq!(w.site.store.package_of(a(BUYER)).unwrap().unwrap().id, moved.settled.package.id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_same_token_again_is_the_same_purchase() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        let first = w.buy(BUYER, "small", &token, None).await.unwrap();
        let first_key = first.settled.key.clone().unwrap();
        // Its buyer, again (the answer may not have arrived): the same
        // package, and a new key for it. Whatever is asked for this time.
        let again = w.buy(BUYER, "no such package", &token, Some("not a key")).await.unwrap();
        assert!(again.again);
        assert_eq!(again.settled.offer, "small", "what was bought, not what is asked now");
        assert_eq!(
            (again.order.as_str(), &again.settled.package.id),
            (first.order.as_str(), &first.settled.package.id)
        );
        assert_eq!((again.settled.paid_sat, again.settled.package.granted), (64, 10_000_000), "nothing was added");
        let new_key = again.settled.key.clone().unwrap();
        assert_ne!(new_key, first_key);
        assert_eq!(w.site.store.package_with_key(&first_key).unwrap(), None, "the key before opens nothing");
        assert_eq!(w.site.store.package_with_key(&new_key).unwrap().unwrap().id, first.settled.package.id);
        // Anyone else is told that it is used, and nothing of whose it is.
        assert_eq!(w.buy(OTHER, "small", &token, None).await, Err(Fault::Used));
        assert_eq!((w.holds().await, w.site.store.sold(&w.mint).unwrap()), (64, 64), "paid once");
        assert_eq!(w.site.store.orders(10).unwrap().len(), 1);
        // A package the operator took back gets no new key.
        w.site.store.revoke(&first.settled.package.id).unwrap();
        assert_eq!(w.buy(BUYER, "small", &token, None).await.unwrap().settled.key, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_that_does_not_fit_is_not_touched() {
        let w = world(0, GIVE_UP).await;
        let (little, much) = (w.token(63).await, w.token(71).await);
        assert_eq!(w.buy(BUYER, "small", &little, None).await, Err(Fault::TooLittle { value: 63, fee: 0, price: 64 }));
        assert_eq!(w.buy(BUYER, "small", &much, None).await, Err(Fault::TooMuch { net: 71, price: 64 }));
        assert_eq!(w.buy(BUYER, "none", &little, None).await, Err(Fault::NoOffer("none".into())));
        for not_one in ["", "   ", "hello", "cashuBnotbase64!", "cashuAeyJ9", &"cashuB".repeat(5000)] {
            let refused = w.buy(BUYER, "small", not_one, None).await;
            assert!(matches!(refused, Err(Fault::Token(_))), "{not_one:.20}: {refused:?}");
        }
        // Of a mint this exit does not accept: that mint is not asked.
        let elsewhere = fips_exit_test_mint::start("127.0.0.1:0".parse().unwrap(), 0).await.unwrap();
        let foreign = fips_exit_test_mint::new_token(&elsewhere, 64, false).await.unwrap();
        assert_eq!(w.buy(BUYER, "small", &foreign, None).await, Err(Fault::WrongMint(elsewhere.clone())));
        // Nothing was written down, nothing arrived, and each is as good as
        // it was.
        assert!(w.site.store.orders(10).unwrap().is_empty());
        assert_eq!(w.holds().await, 0);
        assert!(w.still_good(&little).await && w.still_good(&much).await);
        let theirs = fips_exit_test_mint::wallet(&elsewhere).await.unwrap();
        assert!(theirs.receive(&foreign, cdk::wallet::ReceiveOptions::default()).await.is_ok());
        for fault in
            [Fault::TooLittle { value: 63, fee: 0, price: 64 }, Fault::WrongMint(elsewhere), Fault::Busy, Fault::Listed]
        {
            assert!(fault.said().contains("The token was not touched."), "{fault:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_mints_fee_is_the_buyers() {
        // A tenth of a sat for every proof redeemed, rounded up.
        let w = world(100, GIVE_UP).await;
        let bare = w.token(64).await;
        let Err(Fault::TooLittle { value: 64, fee, price: 64 }) = w.buy(BUYER, "small", &bare, None).await else {
            panic!("a token of the bare price was taken, though its mint takes a fee")
        };
        assert!(fee >= 1);
        assert!(w.still_good(&bare).await);
        // With the fee on top (how much depends on how many proofs the
        // token is made of): what arrives is the price, or a little more.
        let mut bought = None;
        for over in 1..=6 {
            match w.buy(BUYER, "small", &w.token(64 + over).await, None).await {
                Err(Fault::TooLittle { .. }) => continue,
                other => {
                    bought = Some((64 + over, other.unwrap()));
                    break;
                }
            }
        }
        let (value, bought) = bought.expect("no token of 65 to 70 sat was worth 64 after the fee");
        let settled = &bought.settled;
        assert!(settled.fee_sat >= 1 && settled.paid_sat >= 64);
        assert_eq!(settled.paid_sat + settled.fee_sat, value, "what arrived and the fee are what the token was");
        assert_eq!(w.holds().await, settled.paid_sat);
        assert_eq!(w.site.store.order(&bought.order).unwrap().unwrap().value, value);
    }

    /// The mint says the token is spent. The wallet library does not take
    /// that as final (its own request may have spent it); the mint, asked
    /// what it signed for this wallet, says nothing, and so it is: refused
    /// at once, with nothing left behind in the wallet.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_spent_token_buys_nothing() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        assert!(w.still_good(&token).await, "redeemed by someone else, here");
        let refused = w.buy(BUYER, "small", &token, None).await;
        assert_eq!(refused, Err(Fault::Refused("it is spent already".into())));
        assert!(w.site.store.orders(10).unwrap().is_empty() && w.site.store.packages().unwrap().is_empty());
        assert_eq!(w.the_mint().balance().await.unwrap(), (0, 0), "nothing held, nothing under way");
        // And again, as often as it is sent.
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Refused("it is spent already".into())));
        assert_eq!(round(&w.site).await, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn what_is_bought_with_a_key_is_added_to_its_package() {
        let w = world(0, GIVE_UP).await;
        let now = unix_now();
        let (id, key) = w.site.store.grant(1000, 2, &[a("fd99::1")], "given", now).unwrap();
        let token = w.token(64).await;
        let bought = w.buy(BUYER, "small", &token, Some(&key.to_uppercase())).await.unwrap();
        assert!(bought.settled.added && bought.settled.key.is_none());
        let package = &bought.settled.package;
        assert_eq!((package.id.as_str(), package.granted), (id.as_str(), 10_001_000));
        assert!((now + 3 * 86_400 - 5..=now + 3 * 86_400 + 5).contains(&package.until), "a day more");
        assert_eq!(package.members, vec![a("fd99::1")], "who paid is not put in by paying");
        // The same again is that addition again, and adds nothing.
        let again = w.buy(BUYER, "small", &token, Some(&key)).await.unwrap();
        assert!(again.again && again.settled.added);
        assert_eq!(again.settled.package.granted, 10_001_000);
        // No such key, or a package taken back: not touched.
        let (next, other) = (w.token(64).await, "0".repeat(64));
        assert_eq!(w.buy(BUYER, "small", &next, Some(&other)).await, Err(Fault::NoKey));
        assert_eq!(w.buy(BUYER, "small", &next, Some("not a key")).await, Err(Fault::NoKey));
        w.site.store.revoke(&id).unwrap();
        assert_eq!(w.buy(BUYER, "small", &next, Some(&key)).await, Err(Fault::TakenBack));
        assert!(w.still_good(&next).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn who_cannot_be_served_is_not_sold_to() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        w.seats.lock().unwrap().insert(a(BUYER), "static".into());
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Listed));
        w.seats.lock().unwrap().insert(a(BUYER), "free no4".into());
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NoIpv4));
        w.seats.lock().unwrap().insert(a(BUYER), "member p0123456789abcdef no4".into());
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NoIpv4));
        // What it adds to a package of someone's is another matter: that
        // package's members are carried, not who pays.
        let (_, key) = w.site.store.grant(1000, 0, &[a("fd99::1")], "", unix_now()).unwrap();
        let other = w.token(64).await;
        assert!(w.buy(BUYER, "small", &other, Some(&key)).await.unwrap().settled.added);
        // And with the exit not running, nothing is sold at all.
        std::fs::remove_file(w.dir.join("control.sock")).unwrap();
        assert_eq!(w.buy(OTHER, "small", &token, None).await, Err(Fault::ExitDown));
        assert_eq!(w.site.store.orders(10).unwrap().len(), 1);
        assert!(w.still_good(&token).await);
    }

    /// The mint took the token and its answer never arrived. The mint is
    /// asked what it signed for this wallet, and the order is paid: within
    /// the same request, when the mint can be asked.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_answer_of_the_mints_that_was_lost_is_found_again() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        w.proxy.lose_swap_answers();
        let bought = w.buy(BUYER, "small", &token, None).await.unwrap();
        assert!(!bought.again && bought.settled.key.is_some());
        assert_eq!((bought.settled.paid_sat, bought.settled.package.granted), (64, 10_000_000));
        assert_eq!((w.the_mint().balance().await.unwrap(), w.site.store.sold(&w.mint).unwrap()), ((64, 0), 64));
        assert!(w.site.store.orders_open().unwrap().is_empty());
    }

    /// The same, and the mint cannot be asked afterwards. The order stays
    /// open, and its buyer is told so; nothing is granted on a guess. When
    /// the mint is back it says what it signed, and the order is paid.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_order_stays_open_while_the_mint_cannot_be_asked() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        w.proxy.lose_a_swap_answer_and_go_away();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        let open = w.site.store.orders_open().unwrap();
        assert_eq!(open.len(), 1);
        assert!(open[0].outputs.is_some(), "what the mint was asked to sign is kept");
        assert!(w.site.store.packages().unwrap().is_empty());
        // Asked again meanwhile: not yet, for its buyer; used, for another.
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        assert_eq!(w.buy(OTHER, "small", &token, None).await, Err(Fault::Used));
        assert_eq!(round(&w.site).await, 1);
        w.proxy.pass();
        assert_eq!(round(&w.site).await, 0);
        let order = w.site.store.order(&open[0].id).unwrap().unwrap();
        assert!(order.paid && order.paid_sat == 64 && order.outputs.is_none());
        let package = w.site.store.package_of(a(BUYER)).unwrap().unwrap();
        assert_eq!((package.granted, order.package.as_deref()), (10_000_000, Some(package.id.as_str())));
        assert_eq!((w.the_mint().balance().await.unwrap(), w.site.store.sold(&w.mint).unwrap()), ((64, 0), 64));
        // And the buyer, asking again, gets the key the lost answer had.
        let again = w.buy(BUYER, "small", &token, None).await.unwrap();
        assert!(again.again && again.settled.key.is_some());
        assert_eq!(round(&w.site).await, 0, "and it is not paid twice");
        assert_eq!(w.site.store.sold(&w.mint).unwrap(), 64);
    }

    /// The mint was away when the token was taken to it. The wallet takes
    /// it there again when the mint is back, and what the mint then takes
    /// is paid. Nothing is given up meanwhile, however old the order: the
    /// wallet's own request may be on its way.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_that_did_not_reach_the_mint_is_taken_there_again() {
        let w = world(0, Duration::ZERO).await;
        let (token, another) = (w.token(64).await, w.token(64).await);
        w.proxy.go_away();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        assert_eq!(round(&w.site).await, 1);
        assert_eq!(round(&w.site).await, 1);
        assert!(w.site.store.packages().unwrap().is_empty());
        // Its buyer, asking meanwhile, is told that it is not known yet:
        // not that nothing is sold, though the mint is away.
        assert!(w.the_mint().reach().await.is_err() && w.site.methods().is_empty());
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        assert_eq!(w.buy(OTHER, "small", &another, None).await, Err(Fault::MintAway(w.mint.clone())));
        w.proxy.pass();
        assert_eq!(round(&w.site).await, 0);
        assert_eq!(w.site.store.package_of(a(BUYER)).unwrap().unwrap().granted, 10_000_000);
        assert_eq!(w.the_mint().balance().await.unwrap(), (64, 0));
    }

    /// The mint answers, but not to the swap, and the token is not spent.
    /// The wallet gives it up; the exit asks for a while whether the mint
    /// signed after all, and then forgets the order: the token is its
    /// sender's, as good as it was.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_the_mint_did_not_take_is_its_senders() {
        let w = world(0, Duration::ZERO).await;
        let token = w.token(64).await;
        w.proxy.refuse_swaps();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Again));
        assert!(Fault::Again.said().contains("The token was not touched."));
        assert!(w.site.store.orders(10).unwrap().is_empty());
        assert_eq!(w.the_mint().balance().await.unwrap(), (0, 0));
        w.proxy.pass();
        assert_eq!(w.buy(BUYER, "small", &token, None).await.unwrap().settled.paid_sat, 64);
        // While the exit still waits, the order is open, and is not begun
        // a second time.
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        w.proxy.refuse_swaps();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        w.proxy.pass();
        assert_eq!(round(&w.site).await, 1);
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        assert_eq!(w.site.store.orders(10).unwrap().len(), 1);
    }

    /// A token its sender spent elsewhere, taken to the mint, whose answer
    /// ("spent") is lost. All the wallet can find is that the proofs are
    /// spent, which they would also be had the mint taken them for it, and
    /// it cannot finish. The exit asks the mint what it signed for this
    /// wallet, which is nothing: someone else spent it. Nothing is granted,
    /// and the wallet is left holding nothing of it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_spent_elsewhere_buys_nothing_though_the_answer_was_lost() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        assert!(w.still_good(&token).await, "its sender redeems it, here");
        w.proxy.lose_swap_answers();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Refused("it is spent already".into())));
        assert!(w.site.store.orders(10).unwrap().is_empty(), "forgotten");
        assert!(w.site.store.packages().unwrap().is_empty(), "nothing was granted");
        assert_eq!((w.the_mint().balance().await.unwrap(), w.site.store.sold(&w.mint).unwrap()), ((0, 0), 0));
        // The same, with the mint away after it answered: open until the
        // mint can be asked, and then that.
        w.proxy.pass();
        let token = w.token(64).await;
        assert!(w.still_good(&token).await);
        w.proxy.lose_a_swap_answer_and_go_away();
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::NotYet));
        let order = w.site.store.orders_open().unwrap().remove(0);
        assert_eq!(round(&w.site).await, 1);
        w.proxy.pass();
        assert_eq!(round(&w.site).await, 0);
        assert_eq!(w.site.store.order(&order.id).unwrap(), None);
        assert!(w.site.store.packages().unwrap().is_empty());
        assert_eq!(w.the_mint().balance().await.unwrap(), (0, 0));
        assert_eq!(w.the_mint().recorded(&order.id).await, Ok(Recorded::No));
    }

    /// A wallet whose file is behind what its seed was used for asks the
    /// mint to sign what the mint signed before. The mint refuses, and what
    /// it signed then is not a payment now: nothing is granted, the token
    /// is as good as it was, and nothing is sold until the wallet has
    /// counted again. Here it is behind because a second wallet uses its
    /// seed, which is not to be done.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_the_mint_signed_before_is_not_a_payment() {
        for answer_lost in [false, true] {
            let w = world(0, GIVE_UP).await;
            let second = w.second_wallet("second").await;
            let (_, theirs) = wallet::parse(&w.token(64).await).unwrap();
            assert_eq!(second.mints[0].receive(&theirs, "theirs").await.unwrap(), 64);
            // The exit's wallet would now ask for what the mint signed for
            // the second one.
            let token = w.token(64).await;
            if answer_lost {
                w.proxy.lose_swap_answers();
            }
            assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Again), "answer lost: {answer_lost}");
            w.proxy.pass();
            assert!(w.site.store.orders(10).unwrap().is_empty() && w.site.store.packages().unwrap().is_empty());
            assert_eq!(w.site.store.sold(&w.mint).unwrap(), 0);
            assert!(!w.the_mint().ready(), "nothing is sold at a mint the wallet is behind at");
            assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::MintAway(w.mint.clone())));
            // Counted again, it knows of what its seed has, and sells.
            w.the_mint().reach().await.unwrap();
            assert_eq!(w.the_mint().balance().await.unwrap(), (64, 0), "what the second wallet took, found");
            assert_eq!(w.buy(BUYER, "small", &token, None).await.unwrap().settled.paid_sat, 64);
            assert_eq!(w.the_mint().balance().await.unwrap(), (128, 0));
        }
    }

    /// What a service that died left behind: a token that arrived in the
    /// wallet and was not yet settled is; an order nothing came of is
    /// forgotten.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_a_restart_left_open_is_decided() {
        let w = world(0, GIVE_UP).await;
        let (store, mint) = (&w.site.store, w.the_mint());
        let begin = |id: &str, receipt: &[u8; 32]| {
            let new = NewOrder {
                buyer: a(BUYER),
                mint: &w.mint,
                offer: "small",
                bytes: 10_000_000,
                sat: 64,
                days: 1,
                target: None,
                receipt,
                value: 64,
                inputs: "[]",
            };
            store.order_begin(id, &new, unix_now()).unwrap()
        };
        // Arrived, and the service died before it settled.
        let token = w.token(64).await;
        let (parsed, text) = wallet::parse(&token).unwrap();
        let look = mint.look(&parsed).await.unwrap();
        assert_eq!(begin("o000000000000000a", &look.receipt), Begun::New("o000000000000000a".into()));
        assert_eq!(mint.receive(&text, "o000000000000000a").await.unwrap(), 64);
        // Begun, and the service died before the wallet did anything.
        assert_eq!(begin("o000000000000000b", &[7; 32]), Begun::New("o000000000000000b".into()));
        assert_eq!(round(&w.site).await, 0);
        let paid = store.order("o000000000000000a").unwrap().unwrap();
        assert!(paid.paid && paid.paid_sat == 64);
        assert_eq!(store.package_of(a(BUYER)).unwrap().unwrap().id, paid.package.unwrap());
        assert_eq!(store.order("o000000000000000b").unwrap(), None);
        assert_eq!(store.sold(&w.mint).unwrap(), 64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_so_much_is_asked_of_a_mint() {
        let w = world(0, GIVE_UP).await;
        let desk = w.site.desk.clone().unwrap();
        // One order at a time for an address.
        let first = desk.enter("o1", a(BUYER)).unwrap();
        assert!(desk.enter("o2", a(BUYER)).is_none());
        assert!(desk.is_at_work("o1") && !desk.is_at_work("o2"));
        let other = desk.enter("o3", a(OTHER)).unwrap();
        drop((first, other));
        assert!(!desk.is_at_work("o1") && desk.enter("o2", a(BUYER)).is_some());
        // And a budget of tokens for everyone together.
        assert!((0..BURST as usize).all(|_| desk.spend()));
        assert!(!desk.spend());
        let token = w.token(64).await;
        assert_eq!(w.buy(BUYER, "small", &token, None).await, Err(Fault::Busy));
        // And a connection that has no time left for an answer asks for
        // nothing.
        let asked = Asked { package: "small".into(), token: token.clone(), ..Asked::default() };
        assert_eq!(buy(&w.site, a(BUYER), &asked, Instant::now()).await, Err(Fault::Again));
        assert!(w.site.store.orders(10).unwrap().is_empty());
        assert!(w.still_good(&token).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_purchase_is_answered_as_it_was_asked() {
        let w = world(0, GIVE_UP).await;
        // As JSON: the package as its key holder sees it, and its key.
        let token = w.token(64).await;
        let (status, said) = ask(&w, BUYER, "small", &token, None, Kind::Json).await;
        let said: serde_json::Value = serde_json::from_str(&said).unwrap();
        assert_eq!(status, StatusCode::OK, "{said}");
        let key = said["key"].as_str().unwrap().to_string();
        assert_eq!(key.len(), 64);
        assert_eq!(
            (&said["paid_sat"], &said["fee_sat"], &said["added"], &said["again"]),
            (&64.into(), &0.into(), &false.into(), &false.into())
        );
        assert_eq!(said["package"]["members"], serde_json::json!([{"address": BUYER, "name": BUYER}]));
        assert_eq!((&said["package"]["you"], &said["package"]["bytes_left"]), (&true.into(), &10_000_000.into()));
        // What went wrong, with a word for a program.
        let (status, said) = ask(&w, OTHER, "small", &token, None, Kind::Json).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(serde_json::from_str::<serde_json::Value>(&said).unwrap()["code"], "used");
        let (status, said) = ask(&w, OTHER, "big", &w.token(64).await, None, Kind::Json).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(said.contains("\"code\":\"too-little\"") && said.contains("The token was not touched."), "{said}");
        // Added with a key that is not the package's any more (the buyer
        // has since got a new one): what was paid is said, not who is in it.
        let added = w.token(64).await;
        let (status, _) = ask(&w, OTHER, "small", &added, Some(&key), Kind::Json).await;
        assert_eq!(status, StatusCode::OK);
        let new_key = w.buy(BUYER, "small", &token, None).await.unwrap().settled.key.unwrap();
        let (status, said) = ask(&w, OTHER, "small", &added, Some(&key), Kind::Json).await;
        let said: serde_json::Value = serde_json::from_str(&said).unwrap();
        assert_eq!((status, &said["again"]), (StatusCode::OK, &true.into()));
        assert_eq!(said["package"], serde_json::json!({ "id": said["package"]["id"] }), "{said}");
        assert!(said.get("key").is_none());
        // As a form: a page with the key, once; and the package's page when
        // it was added to with its key.
        let token = w.token(64).await;
        let (status, page) = ask(&w, "fd66::6", "small", &token, None, Kind::Form).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            page.contains("<h1>Paid</h1>") && page.contains("Paid: 64 sat arrived, and small is package p"),
            "{page}"
        );
        assert!(page.contains("<h2>Its key</h2>") && page.contains("<button>Manage it</button>"));
        assert!(page.contains("<strong>10 MB</strong>, until "));
        let (status, page) = ask(&w, "fd66::6", "small", &w.token(64).await, Some(&new_key), Kind::Form).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            page.contains("<h1>Package <code>p")
                && page.contains("Paid: 64 sat arrived, and small was added to package p"),
            "{page}"
        );
        assert!(page.contains("<h2>Add to this package</h2>"), "and more can be added there");
        let (status, page) = ask(&w, "fd66::6", "big", &token, None, Kind::Form).await;
        assert_eq!(status, StatusCode::OK);
        assert!(page.contains("This token paid before: 64 sat arrived, and small is package p"), "{page}");
        assert!(page.contains("The key it had before opens nothing any more"));
        let (status, page) = ask(&w, "fd66::6", "small", "nonsense", None, Kind::Form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(page.contains("<h1>Not bought</h1>") && page.contains("That is not a Cashu token"), "{page}");
        // And the page offers it while it can be paid for.
        let front =
            crate::terms::page(&crate::terms::terms(&w.site.config, &w.site.exit, a(OTHER), None, w.site.methods()));
        assert!(front.contains("<h2>Buy a package</h2>"));
    }

    /// The whole way: a request on a socket, a token, a package, and the
    /// daemon told at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_purchase_over_a_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let w = world(0, GIVE_UP).await;
        let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
        let at = listener.local_addr().unwrap();
        tokio::spawn(crate::http::serve(listener, w.site.clone(), crate::http::Limits::default(), |_| true));
        let told = w.site.changed.clone();
        let body = serde_json::json!({ "package": "small", "token": w.token(64).await }).to_string();
        let request = format!(
            "POST /v1/orders HTTP/1.1\r\nHost: npub1exit.fips:5170\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(at).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(30), stream.read_to_string(&mut answer)).await.unwrap().unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
        assert!(
            answer.to_ascii_lowercase().contains("cache-control: no-store"),
            "a key is not kept by anyone on the way"
        );
        let said: serde_json::Value = serde_json::from_str(answer.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        // The caller is the address the connection came from.
        assert_eq!(said["package"]["members"][0]["address"], "::1");
        assert_eq!(said["key"].as_str().unwrap().len(), 64);
        tokio::time::timeout(Duration::from_secs(5), told.notified()).await.expect("the daemon is told at once");
        // A form from the page, with a key: added to that package.
        let key = said["key"].as_str().unwrap();
        let form = format!("package=small&key={key}&token={}", w.token(64).await);
        let request = format!(
            "POST /buy HTTP/1.1\r\nHost: npub1exit.fips:5170\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Origin: http://npub1exit.fips:5170\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{form}",
            form.len()
        );
        let mut stream = tokio::net::TcpStream::connect(at).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        tokio::time::timeout(Duration::from_secs(30), stream.read_to_string(&mut answer)).await.unwrap().unwrap();
        assert!(
            answer.starts_with("HTTP/1.1 200 OK\r\n") && answer.contains("small was added to package p"),
            "{answer}"
        );
        assert_eq!(w.site.store.package_of("::1".parse().unwrap()).unwrap().unwrap().granted, 20_000_000);
    }

    /// The seed is words in a file of the service's own; the wallet's file
    /// can be lost, and what it held is found again at the mint.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_seed_finds_again_what_the_wallet_held() {
        use std::os::unix::fs::PermissionsExt;
        let w = world(0, GIVE_UP).await;
        w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        let seed = std::fs::read_to_string(w.dir.join("seed")).unwrap();
        assert_eq!(seed.split_whitespace().count(), 24);
        assert_eq!(std::fs::metadata(w.dir.join("seed")).unwrap().permissions().mode() & 0o777, 0o600);
        // Another directory, with the seed and nothing else.
        let dir = w.dir.join("moved");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("seed"), &seed).unwrap();
        let notes = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("recount-"))
                .count()
        };
        let wallets = Wallets::open(&dir, std::slice::from_ref(&w.mint)).await.unwrap();
        assert_eq!(wallets.mints[0].balance().await.unwrap(), (0, 0));
        assert_eq!(notes(), 1, "that it is to be counted again is written down");
        // The service stops before it reached the mint, and starts again:
        // the wallet's file is there now, and it is still to be counted.
        drop(wallets);
        let wallets = Wallets::open(&dir, std::slice::from_ref(&w.mint)).await.unwrap();
        assert_eq!((wallets.mints[0].balance().await.unwrap(), notes()), ((0, 0), 1));
        wallets.mints[0].reach().await.unwrap();
        assert_eq!(wallets.mints[0].balance().await.unwrap(), (64, 0), "counted again from the seed");
        assert_eq!(notes(), 0);
        assert_eq!(std::fs::read_to_string(dir.join("seed")).unwrap(), seed, "and the seed is as it was");
        // A seed that is not one is not replaced: what it holds would be gone.
        std::fs::write(dir.join("seed"), "not a seed").unwrap();
        let refused = Wallets::open(&dir, std::slice::from_ref(&w.mint)).await.err().unwrap();
        assert!(refused.contains("it is not replaced"), "{refused}");
        assert_eq!(std::fs::read_to_string(dir.join("seed")).unwrap(), "not a seed");
        // And a wallet's file without its seed is not given another.
        std::fs::remove_file(dir.join("seed")).unwrap();
        let refused = Wallets::open(&dir, std::slice::from_ref(&w.mint)).await.err().unwrap();
        assert!(refused.contains("seed is missing"), "{refused}");
        assert!(!dir.join("seed").exists());
    }

    /// A wallet's file that is older than its seed's use (an old copy put
    /// back) is found to be behind when the mint is reached, and counts
    /// again before anything is sold.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wallet_behind_its_seed_counts_again_before_it_sells() {
        let w = world(0, GIVE_UP).await;
        w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        // The seed, and a wallet's file that knows of nothing.
        let dir = w.dir.join("old");
        std::fs::create_dir(&dir).unwrap();
        std::fs::copy(w.dir.join("seed"), dir.join("seed")).unwrap();
        std::fs::write(dir.join("wallet.db"), b"").unwrap();
        let wallets = Wallets::open(&dir, std::slice::from_ref(&w.mint)).await.unwrap();
        assert!(!wallets.ready());
        assert_eq!(wallets.mints[0].balance().await.unwrap(), (0, 0));
        wallets.mints[0].reach().await.unwrap();
        assert_eq!(wallets.mints[0].balance().await.unwrap(), (64, 0));
    }

    /// A mint that is not reached: nothing is offered, and a token of it is
    /// not touched.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mint_that_is_away_sells_nothing() {
        let w = world(0, GIVE_UP).await;
        let token = w.token(64).await;
        let dir = w.dir.join("away");
        std::fs::create_dir(&dir).unwrap();
        // Nobody listens there.
        let nowhere = "http://127.0.0.1:9".to_string();
        let wallets = Arc::new(Wallets::open(&dir, &[nowhere.clone(), w.mint.clone()]).await.unwrap());
        assert!(wallets.mints[0].reach().await.is_err());
        assert!(!wallets.ready());
        let (parsed, _) = wallet::parse(&token).unwrap();
        let named = wallets.mint_of(&parsed).expect("an accepted mint, reached or not");
        assert!(!named.ready(), "not reached yet");
        wallets.mints[1].reach().await.unwrap();
        assert!(wallets.ready() && named.ready());
        assert!(Wallets::open(&dir, &[w.mint.clone(), format!("{}/", w.mint)]).await.is_err(), "the same mint twice");
    }
}
