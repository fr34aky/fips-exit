//! What leaves the wallet: for the operator, and for nobody else.
//!
//! Nothing here is reached from the mesh. What is paid arrives in the
//! wallet by what a stranger does; it leaves by what the operator says, on
//! the service's own socket, or by what the operator's config says:
//!
//! ```text
//! a token            ecash of the wallet's as text, for whoever is given it
//! an invoice paid    the mint pays a Lightning invoice with what the wallet holds
//! sent on            the same, by itself, to the operator's Lightning address
//!                    (SWEEP_TO) once a mint holds more than SWEEP_ABOVE
//! ```
//!
//! And a wallet that holds as much as it may (`WALLET_CAP`) sells nothing
//! more at that mint: a wallet on a server is protected by holding little.
//!
//! Everything that leaves is written down before the mint is asked
//! (`withdrawals`), with the most it may cost; then what it did cost, or
//! that it came to nothing. A payment whose end is not known stays written
//! as begun, counts as gone, and the mint is asked about it until it says.
//! While one is under way at a mint nothing else is sent on from there.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::http::Site;
use crate::orders::Desk;
use crate::store::{NewWithdrawal, Withdrawal};
use crate::sync::unix_now;
use crate::wallet::{Inputs, Left, MINT_TIME, Mint, PAY_TIME, Payable, Recorded, TokenState};

/// The kinds of withdrawal, as they are kept.
pub const TOKEN: &str = "token";
pub const INVOICE: &str = "invoice";
pub const SWEEP: &str = "sweep";

/// How often what is under way is asked about, and the wallet looked at to
/// see whether it is to be sent on.
const EVERY: Duration = Duration::from_secs(60);
/// Every so many rounds the mint is asked which tokens were redeemed.
const TOKENS_EVERY: u64 = 15;
/// How long nothing is sent on from a mint after sending on from it failed.
const AFTER_A_FAILURE: Duration = Duration::from_secs(900);
/// What is left in the wallet when it is sent on, for what the mint may
/// take: a fiftieth and 4 sat at first, and twice that after a try that
/// did not fit.
fn left_for_fees(holds: u64, tries: u32) -> u64 {
    (holds / 50 + 4).saturating_mul(1 << tries.min(4))
}
/// The most a mint may ask for sending `sat` on, in sat: a twentieth and
/// 20 sat. One that asks more is not paid by itself.
fn fee_bound(sat: u64) -> u64 {
    sat / 20 + 20
}

/// Where an invoice for what is sent on comes from.
pub enum Source {
    /// The Lightning address in the config: its host is asked.
    Address,
    /// Whatever a test says.
    #[cfg(test)]
    Invoices(Box<dyn Fn(u64) -> String + Send + Sync>),
}

/// What is kept, while the service runs, of sending the wallet on.
pub struct Sweeping {
    pub source: Source,
    /// For each mint: when it may next be sent on from, after a failure,
    /// and how many tries did not fit.
    after: Mutex<HashMap<String, (Instant, u32)>>,
    /// [`EVERY`], and how long a mint is waited for when it pays
    /// ([`PAY_TIME`]), which a test shortens.
    pub every: Duration,
    pub pay_time: Duration,
}

impl Default for Sweeping {
    fn default() -> Self {
        Sweeping { source: Source::Address, after: Mutex::default(), every: EVERY, pay_time: PAY_TIME }
    }
}

/// The mint the operator means: the one that is named, or the only one.
fn mint_named<'a>(desk: &'a Desk, named: Option<&str>) -> Result<&'a Arc<Mint>, String> {
    match (named, desk.wallets.mints.as_slice()) {
        (Some(name), _) => desk.wallets.named(name).ok_or_else(|| format!("{name:.200} is not a mint in MINTS")),
        (None, [only]) => Ok(only),
        (None, _) => Err("which mint: name one of MINTS".into()),
    }
}

fn desk(site: &Site) -> Result<&Arc<Desk>, String> {
    site.desk.as_ref().ok_or_else(|| "there is no wallet: no mint is named (MINTS)".to_string())
}

fn stored<T>(result: Result<T, crate::store::Refused>) -> Result<T, String> {
    result.map_err(|e| format!("the store: {e}"))
}

/// What left the wallet at `mint` since it held `before`, as it has it now.
async fn gone(mint: &Mint, before: u64) -> u64 {
    before.saturating_sub(mint.balance().await.map_or(before, |held| held.0))
}

/// The mint's wallet is told which tokens are out there, as the store has
/// them: what it must not take for its own when it counts again.
pub fn remember_out(site: &Site, mint: &Mint) {
    if let Ok(out) = site.store.tokens_out(Some(&mint.name)) {
        mint.set_out(out.into_iter().filter_map(|token| token.ys).collect());
    }
}

/// Before anything is sold or sent on: which tokens are out at each mint,
/// and what each mint's wallet holds (for whether it is full).
pub async fn start(site: &Site) {
    let Some(desk) = &site.desk else { return };
    for mint in &desk.wallets.mints {
        remember_out(site, mint);
        let _ = mint.balance().await;
    }
}

/// What the wallet's record of taking a token back is kept under.
fn back_tag(id: &str) -> String {
    format!("back:{id}")
}

/// The token of withdrawal `id` is made, and its text is `text`: written
/// down as out, with its proofs, for `cost` (or, where that was not
/// measured, for what the token is worth). What it was written down for.
async fn out(site: &Site, mint: &Mint, id: &str, text: &str, cost: Option<u64>) -> Result<u64, String> {
    let looked = match crate::wallet::parse(text) {
        Ok((token, _)) => mint.look(&token).await.ok(),
        Err(_) => None,
    };
    // Its text is kept whatever can be said of it besides.
    let (worth, ys) = looked.map_or((0, "[]".to_string()), |look| (look.value, look.inputs));
    let cost = cost.unwrap_or(worth);
    stored(site.store.withdrawal_token(id, text, &ys, cost, unix_now()))?;
    remember_out(site, mint);
    Ok(cost)
}

/// Hand out a token worth `sat` from the wallet at a mint. The withdrawal's
/// name, what it cost, and the token's text.
pub async fn token(site: &Site, named: Option<&str>, sat: u64) -> Result<(String, u64, String), String> {
    let mint = mint_named(desk(site)?, named)?;
    if sat == 0 {
        return Err("a token of nothing".into());
    }
    let _turn = mint.turn.lock().await;
    let (before, _) = mint.balance().await?;
    if sat > before {
        return Err(format!("the wallet holds {before} sat at {}", mint.name));
    }
    // Written down before it is made, with the name the wallet keeps it
    // by: if the service stops here, that says whether there is a token.
    let most = before.min(sat.saturating_add(sat / 50 + 16));
    let mut begun = None;
    let made = mint
        .token_out(sat, |name| {
            let new =
                NewWithdrawal { mint: &mint.name, kind: TOKEN, sat, cost_most: most, to_whom: "", reference: name };
            begun = Some((stored(site.store.withdrawal_begin(&new, unix_now()))?, name.to_string()));
            Ok(())
        })
        .await;
    let Some((id, name)) = begun else { return Err(made.err().unwrap_or_else(|| "no token was made".into())) };
    let why = match made {
        Ok(text) => {
            let cost = out(site, mint, &id, &text, Some(gone(mint, before).await)).await?;
            eprintln!("fips-exit-payd: withdrawal {id}: a token of {sat} sat of {} was handed out", mint.name);
            return Ok((id, cost, text));
        }
        Err(why) => why,
    };
    // Not made, as far as was heard: the wallet may be in the middle of
    // it. It is let to finish, and what it has then says what happened.
    let finished = crate::orders::finish(site, mint).await;
    match (mint.token_state(&name).await, mint.token_text(&name).await) {
        (Ok(TokenState::Out), Ok(Some(text))) => {
            out(site, mint, &id, &text, Some(gone(mint, before).await)).await?;
            Err(format!("{why}. The token was made all the same: its text is among `wallet tokens` (withdrawal {id})"))
        }
        (Ok(TokenState::Nothing), _) if finished => {
            // What the mint took for the try, if it took anything.
            stored(site.store.withdrawal_end(&id, false, gone(mint, before).await, unix_now()))?;
            Err(why)
        }
        _ => Err(format!(
            "{why}. Whether a token was made is not known yet: withdrawal {id} says so once it is (`wallet out`)"
        )),
    }
}

/// The proofs of token `out` are spent at the mint: by this wallet, if it
/// was taking the token back and did not hear of it, or else by whoever
/// had the token. Written down as what it was; what came back, if it was
/// taken back. The caller holds the mint's turn.
async fn spent(site: &Site, mint: &Mint, token: &Withdrawal) -> Result<Option<u64>, String> {
    let tag = back_tag(&token.id);
    let mut recorded = mint.recorded(&tag).await?;
    if recorded == Recorded::Pending && crate::orders::finish(site, mint).await {
        recorded = mint.recorded(&tag).await?;
    }
    let back = match recorded {
        Recorded::Received(sat, _) => {
            stored(site.store.withdrawal_back(&token.id, sat, unix_now()))?;
            eprintln!("fips-exit-payd: the token of withdrawal {} was taken back: {sat} sat", token.id);
            Some(sat)
        }
        Recorded::Pending => return Err("whether it came back is not known yet".into()),
        Recorded::No => {
            stored(site.store.withdrawal_redeemed(&token.id))?;
            None
        }
    };
    if let Some(name) = &token.quote {
        mint.token_struck(name).await;
    }
    remember_out(site, mint);
    let _ = mint.balance().await;
    Ok(back)
}

/// A token whose withdrawal is written as begun, and which the wallet has
/// made (the service stopped in between): written down as out, with its
/// text. Nothing is asked of the mint. Whether it was one.
async fn adopt(site: &Site, mint: &Mint, begun: &Withdrawal) -> bool {
    let Some(name) = &begun.quote else { return false };
    if begun.kind != TOKEN || mint.token_state(name).await != Ok(TokenState::Out) {
        return false;
    }
    match mint.token_text(name).await {
        // What it cost was not measured: what it is worth.
        Ok(Some(text)) => out(site, mint, &begun.id, &text, None).await.is_ok(),
        _ => false,
    }
}

/// The tokens that are out, at each mint: the mint's name, the name of the
/// token's withdrawal, its text, and whether the mint could be asked about
/// it just now. One the mint says is spent is out no more, and not listed.
/// A mint that cannot be asked keeps nothing from being listed: the text
/// of a token is kept here.
pub async fn tokens(site: &Site) -> Result<Vec<(String, String, String, bool)>, String> {
    let desk = desk(site)?;
    let mut listed = Vec::new();
    for mint in &desk.wallets.mints {
        let _turn = mint.turn.lock().await;
        for begun in stored(site.store.withdrawals_begun(&mint.name))? {
            adopt(site, mint, &begun).await;
        }
        // A mint that does not answer is asked once, not once for a token.
        let mut ask = mint.ready();
        for token in stored(site.store.tokens_out(Some(&mint.name)))? {
            let (Some(text), Some(ys)) = (&token.token, &token.ys) else { continue };
            let mut asked = false;
            if ask {
                match mint.inputs(ys).await {
                    Ok(Inputs::Spent) => match spent(site, mint, &token).await {
                        Ok(_) => continue,
                        Err(_) => asked = true,
                    },
                    Ok(_) => asked = true,
                    Err(_) => ask = false,
                }
            }
            listed.push((mint.name.clone(), token.id.clone(), text.clone(), asked));
        }
    }
    // Those of a mint that is not named any more: their text all the same.
    for token in stored(site.store.tokens_out(None))? {
        if desk.wallets.named(&token.mint).is_none()
            && let Some(text) = token.token
        {
            listed.push((token.mint, token.id, text, false));
        }
    }
    Ok(listed)
}

/// Take back the token of withdrawal `id`, which nobody has redeemed: it
/// is exchanged at its mint for what the wallet holds again, and its text
/// is worth nothing after. What came back, in sat.
pub async fn take_back(site: &Site, id: &str) -> Result<u64, String> {
    let none = "no token of that name is out: it was redeemed, taken back, or never made";
    let token = stored(site.store.tokens_out(None))?.into_iter().find(|token| token.id == id).ok_or(none)?;
    let mint = desk(site)?
        .wallets
        .named(&token.mint)
        .ok_or_else(|| format!("its mint, {}, is not in MINTS any more", token.mint))?;
    let (Some(text), Some(ys)) = (&token.token, &token.ys) else { return Err(none.into()) };
    let _turn = mint.turn.lock().await;
    let tag = back_tag(&token.id);
    // Asked before, and not heard of: what became of that, first.
    if mint.recorded(&tag).await? != Recorded::No {
        return spent(site, mint, &token).await?.ok_or_else(|| none.to_string());
    }
    let why = match tokio::time::timeout(MINT_TIME, mint.receive(text, &tag)).await {
        Ok(Ok(back)) => {
            stored(site.store.withdrawal_back(&token.id, back, unix_now()))?;
            if let Some(name) = &token.quote {
                mint.token_struck(name).await;
            }
            remember_out(site, mint);
            let _ = mint.balance().await;
            eprintln!("fips-exit-payd: the token of withdrawal {} was taken back: {back} sat", token.id);
            return Ok(back);
        }
        Ok(Err(e)) => e.to_string(),
        Err(_) => "the mint did not answer in time".to_string(),
    };
    // Not heard that it came back: the mint may have exchanged it all the
    // same. The wallet is let to finish, and the mint says whether the
    // token is spent: by this wallet, then, or by whoever had it.
    crate::orders::finish(site, mint).await;
    match mint.inputs(ys).await {
        Ok(Inputs::Spent) => match spent(site, mint, &token).await? {
            Some(back) => Ok(back),
            None => Err("it was redeemed already, by whoever had it".into()),
        },
        Ok(_) => Err(format!("{why}. It is out still, and can be taken back again")),
        Err(_) => Err(format!("{why}. Whether it came back is not known yet: `wallet out` says so once it is")),
    }
}

/// An invoice as it is kept and compared: in small letters, which is the
/// same invoice (it is written in either, and never in both).
fn as_kept(invoice: &str) -> String {
    invoice.trim().to_ascii_lowercase()
}

/// An invoice is paid once: not one that a withdrawal paid already, or is
/// paying. A mint, and the Lightning node behind it, would refuse it too;
/// this does not wait for them to.
fn not_paid_before(site: &Site, invoice: &str) -> Result<(), String> {
    match stored(site.store.withdrawal_to(&as_kept(invoice)))? {
        Some(before) => Err(format!(
            "that invoice was paid out of this wallet already, or is being paid: withdrawal {} ({})",
            before.id, before.state
        )),
        None => Ok(()),
    }
}

/// What paying `invoice` from the wallet at a mint would take. Nothing is
/// paid by asking.
pub async fn quote(site: &Site, named: Option<&str>, invoice: &str) -> Result<(String, Payable), String> {
    let mint = mint_named(desk(site)?, named)?;
    not_paid_before(site, invoice)?;
    let _turn = mint.turn.lock().await;
    let payable = mint.payable(invoice).await?;
    Ok((mint.name.clone(), payable))
}

/// Pay what `payable` is for from the wallet at `mint`, as `kind`, to
/// `to_whom`. The withdrawal's name, and what became of it.
async fn pay(site: &Site, mint: &Mint, payable: &Payable, kind: &str, to_whom: &str) -> Result<(String, Left), String> {
    let (before, _) = mint.balance().await?;
    let most = payable.sat.saturating_add(payable.fee_most);
    if most > before {
        return Err(format!(
            "the wallet holds {before} sat at {}, and this takes {} sat and up to {} more for the mint",
            mint.name, payable.sat, payable.fee_most
        ));
    }
    let new =
        NewWithdrawal { mint: &mint.name, kind, sat: payable.sat, cost_most: most, to_whom, reference: &payable.quote };
    let id = stored(site.store.withdrawal_begin(&new, unix_now()))?;
    let wait = site.desk.as_ref().map_or(PAY_TIME, |desk| desk.sweeping.pay_time);
    let left = mint.pay(&payable.quote, wait).await;
    // What left the wallet for it, as the wallet has it now.
    let gone = gone(mint, before).await;
    match &left {
        Left::Paid { sat, fee, .. } => {
            stored(site.store.withdrawal_end(&id, true, gone, unix_now()))?;
            eprintln!("fips-exit-payd: withdrawal {id}: {} paid {sat} sat for the wallet, for {fee} sat", mint.name);
        }
        Left::Not(why) => {
            stored(site.store.withdrawal_end(&id, false, gone, unix_now()))?;
            eprintln!("fips-exit-payd: withdrawal {id}: {} did not pay {} sat: {why}", mint.name, payable.sat);
        }
        // Under way: what is held back for it counts as gone, and what
        // comes back of that when it ends is taken off again.
        Left::Pending => {
            stored(site.store.withdrawal_cost(&id, gone.max(most)))?;
            eprintln!(
                "fips-exit-payd: withdrawal {id}: what became of {} sat that {} was to pay is not known yet",
                payable.sat, mint.name
            );
        }
    }
    Ok((id, left))
}

/// Pay the invoice that `quote` (as [`quote`] gave it) is for.
pub async fn pay_quoted(site: &Site, named: Option<&str>, quote: &str) -> Result<(String, Left), String> {
    let mint = mint_named(desk(site)?, named)?;
    let _turn = mint.turn.lock().await;
    let (payable, invoice) = mint.quoted(quote).await?.ok_or("no such quote: ask what the invoice takes first")?;
    if payable.expires != 0 && payable.expires <= unix_now() {
        return Err("that quote has ended: ask what the invoice takes again".into());
    }
    if stored(site.store.withdrawals(usize::MAX))?.iter().any(|w| w.quote.as_deref() == Some(quote)) {
        return Err("that quote was paid from already: an invoice is paid once".into());
    }
    not_paid_before(site, &invoice)?;
    pay(site, mint, &payable, INVOICE, &as_kept(&invoice)).await
}

/// Ask `mint` what became of what was begun there and has no known end. How
/// much is still under way.
pub async fn settle(site: &Site, mint: &Mint) -> usize {
    let (begun, out) = match (site.store.withdrawals_begun(&mint.name), site.store.tokens_out(Some(&mint.name))) {
        (Ok(begun), Ok(out)) if !(begun.is_empty() && out.is_empty()) => (begun, out),
        (Ok(_), Ok(_)) => return 0,
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("fips-exit-payd: the withdrawals could not be read: {e}");
            return 0;
        }
    };
    let _turn = mint.turn.lock().await;
    let mut under_way = 0;
    // A token that was being taken back when that was last heard of: what
    // the wallet's record of it says now.
    for token in &out {
        if matches!(mint.recorded(&back_tag(&token.id)).await, Ok(Recorded::Pending | Recorded::Received(..)))
            && spent(site, mint, token).await.is_err()
        {
            under_way += 1;
        }
    }
    for withdrawal in &begun {
        let Some(reference) = &withdrawal.quote else { continue };
        if withdrawal.kind == TOKEN {
            // A token: made if the wallet keeps it. One the wallet was in
            // the middle of making is let to be finished first.
            let mut state = mint.token_state(reference).await;
            if state == Ok(TokenState::Unfinished) && crate::orders::finish(site, mint).await {
                state = mint.token_state(reference).await;
            }
            match state {
                Ok(TokenState::Out) if adopt(site, mint, withdrawal).await => eprintln!(
                    "fips-exit-payd: withdrawal {}: a token of {} sat of {} was made: it is among those that are out",
                    withdrawal.id, withdrawal.sat, mint.name
                ),
                // Never made, as far as the wallet knows. Nobody was given
                // its text (a token is written down as out before that),
                // so whatever the wallet holds for it is the wallet's:
                // found again from the seed if it is missing.
                Ok(TokenState::Nothing) => {
                    if site.store.withdrawal_end(&withdrawal.id, false, 0, unix_now()).is_err() {
                        under_way += 1;
                        continue;
                    }
                    eprintln!("fips-exit-payd: withdrawal {}: no token was made", withdrawal.id);
                    crate::orders::found_again(site, mint).await;
                }
                _ => under_way += 1,
            }
            continue;
        }
        let Ok((before, _)) = mint.balance().await else {
            under_way += 1;
            continue;
        };
        let done = match mint.payment(reference).await {
            Ok(Left::Paid { .. }) => true,
            Ok(Left::Not(_)) => false,
            Ok(Left::Pending) | Err(_) => {
                under_way += 1;
                continue;
            }
        };
        // What came back to the wallet by asking is taken off what was
        // held back for it.
        let back = mint.balance().await.map_or(0, |held| held.0.saturating_sub(before));
        let cost = if done { withdrawal.cost_sat.saturating_sub(back) } else { 0 };
        if let Err(e) = site.store.withdrawal_end(&withdrawal.id, done, cost, unix_now()) {
            eprintln!("fips-exit-payd: withdrawal {}: {e}", withdrawal.id);
            under_way += 1;
            continue;
        }
        eprintln!(
            "fips-exit-payd: withdrawal {}: {} of {} sat at {}: {}",
            withdrawal.id,
            withdrawal.kind,
            withdrawal.sat,
            mint.name,
            if done { "it left the wallet" } else { "it came to nothing" }
        );
    }
    let _ = mint.balance().await;
    under_way
}

/// Send on what the wallet holds at `mint` to the operator's address, if
/// the config names one and the wallet holds more than it says (or
/// `whatever` it holds, when the operator says so now). What was sent, if
/// anything was.
pub async fn sweep(site: &Site, desk: &Desk, mint: &Mint, whatever: bool) -> Result<Option<(String, Left)>, String> {
    let Some(to) = &site.config.sweep_to else {
        return if whatever { Err("nowhere to send it: SWEEP_TO is not set".into()) } else { Ok(None) };
    };
    if !mint.ready() {
        return if whatever { Err(format!("{} is not reached", mint.name)) } else { Ok(None) };
    }
    // One thing leaves at a time: what is under way may come back.
    if settle(site, mint).await > 0 {
        return if whatever { Err("a withdrawal is under way there: its end first".into()) } else { Ok(None) };
    }
    let waited = |desk: &Desk| desk.sweeping.after.lock().unwrap_or_else(|p| p.into_inner()).get(&mint.name).copied();
    let tries = match waited(desk) {
        Some((until, _)) if !whatever && Instant::now() < until => return Ok(None),
        Some((_, tries)) => tries,
        None => 0,
    };
    let _turn = mint.turn.lock().await;
    let (holds, _) = mint.balance().await?;
    if holds == 0 || (!whatever && holds <= site.config.sweep_above) {
        return Ok(None);
    }
    let failed = |why: String, fits: bool| {
        let tries = if fits { tries } else { tries + 1 };
        let mut after = desk.sweeping.after.lock().unwrap_or_else(|p| p.into_inner());
        after.insert(mint.name.clone(), (Instant::now() + AFTER_A_FAILURE, tries));
        eprintln!("fips-exit-payd: {}: {holds} sat were not sent on to {to}: {why}", mint.name);
        Err(why)
    };
    let sat = holds.saturating_sub(left_for_fees(holds, tries));
    if sat == 0 {
        return failed("too little to send on, after what the mint may take".into(), true);
    }
    let asked = match &desk.sweeping.source {
        Source::Address => mint.payable_to(to, sat).await,
        #[cfg(test)]
        Source::Invoices(make) => mint.payable(&make(sat)).await,
    };
    let payable = match asked {
        Ok(payable) => payable,
        Err(e) => return failed(format!("no price for it: {e}"), true),
    };
    if payable.fee_most > fee_bound(payable.sat) {
        return failed(
            format!("the mint may take up to {} sat for sending {} sat on: not paid by itself", payable.fee_most, sat),
            true,
        );
    }
    if payable.sat.saturating_add(payable.fee_most) > holds {
        return failed(format!("it takes up to {} sat more than the wallet holds", payable.fee_most), false);
    }
    let (id, left) = pay(site, mint, &payable, SWEEP, to).await?;
    match &left {
        // What did not fit after all (the mint takes for what goes in,
        // too): more is left for it next time. Any other failure (no way
        // to the address just now) says nothing of what fits.
        Left::Not(why) => {
            let fits = !why.to_ascii_lowercase().contains("insufficient");
            let _ = failed(why.clone(), fits);
        }
        _ => {
            desk.sweeping.after.lock().unwrap_or_else(|p| p.into_inner()).remove(&mint.name);
        }
    }
    Ok(Some((id, left)))
}

/// For as long as the service runs: ask about what is under way, see what
/// each mint holds, and send it on when it is more than the config says.
pub async fn keep(site: Arc<Site>) {
    let Some(desk) = site.desk.clone() else { return };
    let mut round = 0u64;
    loop {
        for mint in &desk.wallets.mints {
            // What it holds, for whether it is full.
            let _ = mint.balance().await;
            if !mint.ready() {
                continue;
            }
            // What is under way, whether or not anything is sent on.
            settle(&site, mint).await;
            let _ = sweep(&site, &desk, mint, false).await;
        }
        // Now and then: which of the tokens that are out were redeemed.
        if round.is_multiple_of(TOKENS_EVERY) {
            let _ = tokens(&site).await;
        }
        round += 1;
        tokio::time::sleep(desk.sweeping.every).await;
    }
}

/// A withdrawal as a line for the operator's script.
pub fn line(withdrawal: &Withdrawal) -> String {
    let to_whom = if withdrawal.to_whom.is_empty() { "-" } else { &withdrawal.to_whom };
    format!(
        "withdrawal {} {} {} {} {} {} {} {}\n",
        withdrawal.id,
        withdrawal.state,
        withdrawal.created,
        withdrawal.kind,
        withdrawal.sat,
        withdrawal.cost_sat,
        withdrawal.mint,
        to_whom.split_whitespace().next().unwrap_or("-")
    )
}

#[cfg(test)]
mod tests {
    use fips_exit_test_mint::Fate;

    use super::*;
    use crate::orders::Fault;
    use crate::orders::testing::{World, world, world_with};

    const BUYER: &str = "fd77::7";
    const OTHER: &str = "fd88::8";
    const GIVE_UP: Duration = Duration::from_secs(600);

    /// An exit whose wallet holds 1564 sat: a big package and a small one
    /// were bought.
    async fn sold(w: &World) {
        w.buy(BUYER, "big", &w.token(1500).await, None).await.unwrap();
        w.buy(OTHER, "small", &w.token(64).await, None).await.unwrap();
        assert_eq!(w.holds().await, 1564);
    }

    fn withdrawals(w: &World) -> Vec<Withdrawal> {
        w.site.store.withdrawals(100).unwrap()
    }

    /// What the wallet holds is what was sold less what left it: to the sat.
    async fn the_books_agree(w: &World) {
        let (sold, out) = (w.site.store.sold(&w.mint).unwrap(), w.site.store.paid_out(&w.mint).unwrap());
        assert_eq!(w.holds().await + out, sold, "holds {} and {out} left it, of {sold} sold", w.holds().await);
    }

    /// A token is taken back at the mint it is of, whichever mint is asked
    /// first: they share the wallet's file.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_is_taken_back_at_the_mint_it_is_of() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let another = fips_exit_test_mint::start("127.0.0.1:0".parse().unwrap(), 0).await.unwrap();
        let wallets = crate::wallet::Wallets::open(&w.dir, &[w.mint.clone(), another.clone()]).await.unwrap();
        for mint in &wallets.mints {
            mint.reach().await.unwrap();
        }
        let theirs = fips_exit_test_mint::new_token(&another, 200, false).await.unwrap();
        let (_, theirs) = crate::wallet::parse(&theirs).unwrap();
        assert_eq!(wallets.mints[1].receive(&theirs, "theirs").await.unwrap(), 200);
        let both = w.with_wallets(wallets);
        assert!(token(&both, None, 5).await.unwrap_err().contains("which mint"), "two mints: one is named");
        token(&both, Some(&another), 150).await.unwrap();
        let out = tokens(&both).await.unwrap();
        assert_eq!((out.len(), out[0].0.as_str(), out[0].3), (1, another.as_str(), true));
        assert_eq!(take_back(&both, &out[0].1).await.unwrap(), 150);
        assert!(tokens(&both).await.unwrap().is_empty());
        // With the first mint away, the second's tokens are listed still.
        token(&both, Some(&another), 50).await.unwrap();
        w.proxy.go_away();
        let out = tokens(&both).await.unwrap();
        assert_eq!((out.len(), out[0].0.as_str()), (1, another.as_str()));
    }

    /// What the wallet's file remembers of a token is not what is gone by:
    /// the wallet forgets one when it puts itself right, or counts again.
    /// A token that is out is listed, kept from the wallet's own, and taken
    /// back all the same.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_is_out_whatever_the_wallets_file_remembers_of_it() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        // 300 of 1564 is made by exchanging what the wallet holds.
        let (id, _, text) = token(&w.site, None, 300).await.unwrap();
        let mint = w.the_mint();
        for _ in 0..2 {
            {
                let _turn = mint.turn.lock().await;
                assert!(crate::orders::finish(&w.site, mint).await, "the wallet puts itself right");
                mint.count_again().await.unwrap();
                assert!(crate::orders::finish(&w.site, mint).await);
            }
            assert_eq!(w.holds().await, 1264, "what is out is not the wallet's again");
            let out = tokens(&w.site).await.unwrap();
            assert_eq!(out.len(), 1, "and it is out still");
            assert_eq!((out[0].1.as_str(), out[0].2.as_str(), out[0].3), (id.as_str(), text.as_str(), true));
        }
        the_books_agree(&w).await;
        assert_eq!(take_back(&w.site, &id).await, Ok(300));
        assert_eq!(w.holds().await, 1564);
        assert!(!w.still_good(&text).await);
        the_books_agree(&w).await;
    }

    /// The service stopped between a token being made and that being
    /// written down: the token is found in the wallet, written down as out
    /// for what it is worth, and stays written as made once it is redeemed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_made_and_not_written_down_is_found() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let mint = w.the_mint();
        let mut id = String::new();
        let text = {
            let _turn = mint.turn.lock().await;
            let made = mint.token_out(300, |name| {
                let new = NewWithdrawal {
                    mint: &w.mint,
                    kind: TOKEN,
                    sat: 300,
                    cost_most: 322,
                    to_whom: "",
                    reference: name,
                };
                id = w.site.store.withdrawal_begin(&new, unix_now()).map_err(|e| e.to_string())?;
                Ok(())
            });
            made.await.unwrap()
        };
        assert_eq!(withdrawals(&w)[0].state, "begun");
        // Its text is to be had: it is listed, and written down by that.
        let out = tokens(&w.site).await.unwrap();
        assert_eq!((out.len(), out[0].1.as_str(), out[0].2.as_str()), (1, id.as_str(), text.as_str()));
        let written = withdrawals(&w).pop().unwrap();
        assert_eq!((written.state.as_str(), written.cost_sat), ("done", 300), "for what it is worth, not the most");
        the_books_agree(&w).await;
        // Redeemed: out no more, and still a token that was made.
        assert!(w.still_good(&text).await);
        assert!(tokens(&w.site).await.unwrap().is_empty());
        assert_eq!(settle(&w.site, mint).await, 0);
        let written = withdrawals(&w).pop().unwrap();
        assert_eq!((written.state.as_str(), written.cost_sat), ("done", 300));
        assert!(take_back(&w.site, &id).await.is_err());
        the_books_agree(&w).await;
    }

    /// A token taken back, the mint's answer lost and the mint then away:
    /// it is not known what became of it, and it is found out later by
    /// whoever asks.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_taken_back_unheard_is_written_down_when_it_is_known() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let (id, _, text) = token(&w.site, None, 500).await.unwrap();
        w.proxy.lose_a_swap_answer_and_go_away();
        let unheard = take_back(&w.site, &id).await.unwrap_err();
        assert!(unheard.contains("not known yet"), "{unheard}");
        let written = withdrawals(&w).pop().unwrap();
        assert_eq!((written.state.as_str(), written.token.is_some()), ("done", true), "out, as far as is known");
        // The mint is back: asked about what is under way, it came back.
        w.proxy.pass();
        assert_eq!(settle(&w.site, w.the_mint()).await, 0);
        let written = withdrawals(&w).pop().unwrap();
        assert_eq!((written.state.as_str(), written.cost_sat), ("back", 0));
        assert_eq!(w.holds().await, 1564);
        assert!(!w.still_good(&text).await && tokens(&w.site).await.unwrap().is_empty());
        the_books_agree(&w).await;
        // With the mint away, the tokens that are out are listed at once,
        // and each as not asked about.
        token(&w.site, None, 100).await.unwrap();
        token(&w.site, None, 50).await.unwrap();
        w.proxy.go_away();
        let asked = tokio::time::Instant::now();
        let out = tokens(&w.site).await.unwrap();
        assert_eq!((out.len(), out[0].3, out[1].3), (2, false, false));
        assert!(asked.elapsed() < Duration::from_secs(20), "the mint is asked once, not once for each");
    }

    /// What a wallet holds is known before anything is sold: one that is
    /// full when the service starts sells nothing from the start.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wallet_that_is_full_at_the_start_sells_nothing() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let wallets = crate::wallet::Wallets::open(&w.dir, std::slice::from_ref(&w.mint)).await.unwrap();
        wallets.set_cap(1000);
        wallets.mints[0].reach().await.unwrap();
        let again = w.with_wallets(wallets);
        start(&again).await;
        assert!(again.desk.as_ref().unwrap().wallets.mints[0].full() && again.methods().is_empty());
    }

    /// Counting the wallet again from its seed finds everything the mint
    /// calls unspent, a token that was handed out among it: that stays its
    /// holder's.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_was_handed_out_is_not_the_wallets_again_when_it_counts() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let (_, _, text) = token(&w.site, None, 500).await.unwrap();
        assert_eq!(w.holds().await, 1064);
        {
            let _turn = w.the_mint().turn.lock().await;
            w.the_mint().count_again().await.unwrap();
        }
        assert_eq!(w.holds().await, 1064, "it holds what it held");
        the_books_agree(&w).await;
        assert_eq!(tokens(&w.site).await.unwrap().len(), 1, "and the token is out still");
        assert!(w.still_good(&text).await, "for whoever has it");
    }

    /// The mint's answer is lost while a token is made, or taken back:
    /// whatever is said then, the wallet is let to finish, and what is
    /// written down agrees with what it holds.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_whose_making_or_taking_back_is_interrupted() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        // 300 of 1564: the wallet has no such proofs, and asks the mint to
        // exchange some.
        w.proxy.lose_swap_answers();
        let made = token(&w.site, None, 300).await;
        w.proxy.pass();
        assert_eq!(settle(&w.site, w.the_mint()).await, 0, "its end is known once the mint answers");
        let out = tokens(&w.site).await.unwrap();
        let written = withdrawals(&w).pop().unwrap();
        match (&made, out.len()) {
            (Ok(_), 1) => assert_eq!(written.state, "done"),
            (Err(_), 1) => assert_eq!(written.state, "done", "made after all: {made:?}"),
            (Err(_), 0) => assert_eq!((written.state.as_str(), w.holds().await), ("failed", 1564), "{made:?}"),
            other => panic!("{other:?}"),
        }
        the_books_agree(&w).await;
        // Taken back, the answer lost: it is the wallet's again all the
        // same, and is written down so.
        let (_, _, text) = token(&w.site, None, 500).await.unwrap();
        let name = tokens(&w.site).await.unwrap().into_iter().find(|out| out.2 == text).unwrap().1;
        let before = w.holds().await;
        w.proxy.lose_swap_answers();
        let back = take_back(&w.site, &name).await;
        w.proxy.pass();
        assert_eq!(back, Ok(500), "what came back is what the wallet holds more");
        assert_eq!(w.holds().await, before + 500);
        assert!(!w.still_good(&text).await, "and the token is worth nothing");
        let taken = withdrawals(&w).into_iter().find(|out| out.sat == 500).unwrap();
        assert_eq!((taken.state.as_str(), taken.cost_sat), ("back", 0));
        the_books_agree(&w).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_is_handed_out_and_taken_back() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        assert_eq!(token(&w.site, None, 0).await.unwrap_err(), "a token of nothing");
        assert!(token(&w.site, None, 1565).await.unwrap_err().contains("holds 1564 sat"));
        assert!(token(&w.site, Some("https://mint.example"), 5).await.unwrap_err().contains("not a mint in MINTS"));
        assert!(withdrawals(&w).is_empty(), "what was refused is no withdrawal");
        // A token of 1000: its text is the money, and what it cost is
        // written down.
        let (id, cost, text) = token(&w.site, None, 1000).await.unwrap();
        assert_eq!((cost, w.holds().await), (1000, 564));
        let [out] = &withdrawals(&w)[..] else { panic!("one withdrawal") };
        assert_eq!(
            (out.id.as_str(), out.kind.as_str(), out.state.as_str(), out.sat, out.cost_sat),
            (id.as_str(), TOKEN, "done", 1000, 1000)
        );
        assert_eq!(w.site.store.paid_out(&w.mint).unwrap(), 1000);
        // Nobody has redeemed it: it is among those that are out, with its
        // text, for a token whose text was lost.
        let out_now = tokens(&w.site).await.unwrap();
        assert_eq!(out_now.len(), 1);
        assert_eq!((out_now[0].0.as_str(), out_now[0].2.as_str()), (w.mint.as_str(), text.as_str()));
        // Somebody redeems it: it is theirs, and out no more.
        assert!(w.still_good(&text).await);
        assert!(tokens(&w.site).await.unwrap().is_empty());
        assert!(take_back(&w.site, &out_now[0].1).await.is_err(), "what was redeemed is not taken back");
        // Another, taken back before anyone has it: the wallet's again.
        let (_, _, lost) = token(&w.site, Some(&w.mint), 500).await.unwrap();
        assert_eq!(w.holds().await, 64);
        let name = tokens(&w.site).await.unwrap()[0].1.clone();
        assert_eq!(take_back(&w.site, &name).await.unwrap(), 500);
        assert_eq!(w.holds().await, 564);
        assert!(!w.still_good(&lost).await, "its text is worth nothing now");
        let back = withdrawals(&w).into_iter().find(|out| out.sat == 500).unwrap();
        assert_eq!((back.state.as_str(), back.cost_sat), ("back", 0));
        assert_eq!(w.site.store.paid_out(&w.mint).unwrap(), 1000);
        assert!(take_back(&w.site, &name).await.is_err() && take_back(&w.site, "not-a-name").await.is_err());
        the_books_agree(&w).await;
    }

    /// At a mint that takes a fee, a token is worth what was asked to
    /// whoever redeems it, and costs the wallet that and the fee.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_costs_what_its_mint_takes_too() {
        let w = world(1000, GIVE_UP).await;
        w.buy(BUYER, "big", &fips_exit_test_mint::new_token(&w.mint, 1500, true).await.unwrap(), None).await.unwrap();
        let before = w.holds().await;
        let (_, cost, text) = token(&w.site, None, 1000).await.unwrap();
        assert!(cost > 1000 && before - w.holds().await == cost, "{cost}");
        let theirs = fips_exit_test_mint::wallet(&w.mint).await.unwrap();
        let got = u64::from(theirs.receive(&text, cdk::wallet::ReceiveOptions::default()).await.unwrap());
        assert!((995..=1000).contains(&got), "worth what was asked, as near as the mint's fee lets it be: {got}");
        assert_eq!(w.site.store.paid_out(&w.mint).unwrap(), cost);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_is_paid_from_the_wallet() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        // What it takes is asked first, and asking pays nothing.
        let (mint, payable) = quote(&w.site, None, &fips_exit_test_mint::invoice(500, Fate::Paid)).await.unwrap();
        assert_eq!((mint.as_str(), payable.sat), (w.mint.as_str(), 500));
        assert!((1..=25).contains(&payable.fee_most), "{payable:?}");
        assert!(withdrawals(&w).is_empty() && w.holds().await == 1564);
        assert!(quote(&w.site, None, "not an invoice").await.is_err());
        // Paid: what left is what was paid and what the mint took.
        let (id, left) = pay_quoted(&w.site, None, &payable.quote).await.unwrap();
        let Left::Paid { sat: 500, fee, .. } = left else { panic!("{left:?}") };
        let holds = w.holds().await;
        assert!(holds < 1064 && holds >= 1064 - payable.fee_most, "{holds}");
        let [paid] = &withdrawals(&w)[..] else { panic!("one withdrawal") };
        assert_eq!(
            (paid.id.as_str(), paid.kind.as_str(), paid.state.as_str(), paid.sat),
            (id.as_str(), INVOICE, "done", 500)
        );
        assert_eq!(paid.cost_sat, 1564 - holds);
        assert!(paid.cost_sat >= 500 + fee && paid.to_whom.starts_with("lnbc5u1"));
        assert_eq!(w.site.store.paid_out(&w.mint).unwrap(), 1564 - holds);
        // An invoice is paid once: not by its quote again, and not by a
        // new quote for it, however it is written.
        assert!(pay_quoted(&w.site, None, &payable.quote).await.unwrap_err().contains("paid from already"));
        let again = quote(&w.site, None, &paid.to_whom.to_ascii_uppercase()).await.unwrap_err();
        assert!(again.contains("paid out of this wallet already") && again.contains(&id), "{again}");
        assert!(pay_quoted(&w.site, None, "no-such-quote").await.unwrap_err().contains("no such quote"));
        // More than the wallet holds is not begun.
        let (_, too_much) = quote(&w.site, None, &fips_exit_test_mint::invoice(holds, Fate::Paid)).await.unwrap();
        assert!(pay_quoted(&w.site, None, &too_much.quote).await.unwrap_err().contains("the wallet holds"));
        assert_eq!(withdrawals(&w).len(), 1);
        // A payment that fails takes nothing.
        let (_, fails) = quote(&w.site, None, &fips_exit_test_mint::invoice(100, Fate::Fails)).await.unwrap();
        let (_, left) = pay_quoted(&w.site, None, &fails.quote).await.unwrap();
        assert!(matches!(left, Left::Not(_)), "{left:?}");
        assert_eq!(w.holds().await, holds);
        let failed = withdrawals(&w).into_iter().find(|out| out.sat == 100).unwrap();
        assert_eq!((failed.state.as_str(), failed.cost_sat), ("failed", 0));
        the_books_agree(&w).await;
    }

    /// A payment whose end is not known (the mint's answer was lost, and
    /// the mint could not be asked) counts as gone, is asked about, and is
    /// then what it came to.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_payment_whose_end_is_not_known_is_asked_about() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        // The answer alone lost: the wallet asks the mint what became of
        // it, and it is paid.
        let (_, payable) = quote(&w.site, None, &fips_exit_test_mint::invoice(200, Fate::Paid)).await.unwrap();
        w.proxy.lose_melt_answers();
        let (_, left) = pay_quoted(&w.site, None, &payable.quote).await.unwrap();
        assert!(matches!(left, Left::Paid { sat: 200, .. }), "{left:?}");
        w.proxy.pass();
        let held = w.holds().await;
        // The answer lost and the mint away: not known, which is not
        // failed.
        let (_, payable) = quote(&w.site, None, &fips_exit_test_mint::invoice(500, Fate::Paid)).await.unwrap();
        w.proxy.lose_a_melt_answer_and_go_away();
        let (id, left) = pay_quoted(&w.site, None, &payable.quote).await.unwrap();
        assert_eq!(left, Left::Pending);
        let begun = withdrawals(&w).into_iter().find(|out| out.id == id).unwrap();
        assert_eq!((begun.state.as_str(), begun.cost_sat), ("begun", 500 + payable.fee_most));
        let gone_before = 1564 - held;
        assert_eq!(w.site.store.paid_out(&w.mint).unwrap(), gone_before + 500 + payable.fee_most, "it counts as gone");
        assert_eq!(settle(&w.site, w.the_mint()).await, 1, "and the mint cannot be asked");
        // Asked again, with the mint there: it paid.
        w.proxy.pass();
        assert_eq!(settle(&w.site, w.the_mint()).await, 0);
        let done = withdrawals(&w).into_iter().find(|out| out.id == id).unwrap();
        assert_eq!(done.state, "done", "{done:?}");
        assert!((500..=500 + payable.fee_most).contains(&done.cost_sat));
        let holds = w.holds().await;
        assert!(
            (held - 500 - payable.fee_most..held - 500).contains(&holds),
            "what the mint did not take came back: {holds}"
        );
        // A token that was written down and never made (the service
        // stopped in between) came to nothing.
        let name = "00000000-0000-4000-8000-000000000000";
        let new = NewWithdrawal { mint: &w.mint, kind: TOKEN, sat: 10, cost_most: 12, to_whom: "", reference: name };
        let never = w.site.store.withdrawal_begin(&new, 1).unwrap();
        assert_eq!(settle(&w.site, w.the_mint()).await, 0);
        let never = withdrawals(&w).into_iter().find(|out| out.id == never).unwrap();
        assert_eq!((never.state.as_str(), never.cost_sat), ("failed", 0));
        // What the payment cost is what left, not the most it might have:
        // the books agree to the sat.
        the_books_agree(&w).await;
    }

    /// A payment the mint says is under way stays written as begun, and
    /// nothing else is sent on from there while it is.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_payment_under_way_keeps_the_wallet_from_being_sent_on() {
        let w = world_with(0, GIVE_UP, 3600, "", "SWEEP_TO=me@example.org\nSWEEP_ABOVE=100\n").await;
        sold(&w).await;
        let (_, hangs) = quote(&w.site, None, &fips_exit_test_mint::invoice(500, Fate::Hangs)).await.unwrap();
        let (_, left) = pay_quoted(&w.site, None, &hangs.quote).await.unwrap();
        assert_eq!(left, Left::Pending);
        assert_eq!(settle(&w.site, w.the_mint()).await, 1, "and it is still under way when asked");
        assert_eq!(withdrawals(&w)[0].state, "begun");
        let desk = w.site.desk.as_ref().unwrap();
        assert_eq!(
            sweep(&w.site, desk, w.the_mint(), false).await,
            Ok(None),
            "above what the config says, and not sent on"
        );
        assert!(sweep(&w.site, desk, w.the_mint(), true).await.unwrap_err().contains("under way"));
        assert_eq!(withdrawals(&w).len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_wallet_is_sent_on_above_what_the_config_says() {
        let w = world_with(0, GIVE_UP, 3600, "", "SWEEP_TO=me@example.org\nSWEEP_ABOVE=1000\n").await;
        let desk = w.site.desk.as_ref().unwrap();
        w.buy(OTHER, "small", &w.token(64).await, None).await.unwrap();
        assert_eq!(sweep(&w.site, desk, w.the_mint(), false).await, Ok(None), "not above it");
        assert!(withdrawals(&w).is_empty());
        w.buy(BUYER, "big", &w.token(1500).await, None).await.unwrap();
        // Above it: what is held, less what is left for the mint to take.
        let Some((id, Left::Paid { sat, .. })) = sweep(&w.site, desk, w.the_mint(), false).await.unwrap() else {
            panic!("nothing was sent on")
        };
        assert_eq!(sat, 1564 - (1564 / 50 + 4));
        let [sent] = &withdrawals(&w)[..] else { panic!("one withdrawal") };
        assert_eq!((sent.id.as_str(), sent.kind.as_str(), sent.state.as_str()), (id.as_str(), SWEEP, "done"));
        assert_eq!((sent.sat, sent.to_whom.as_str()), (sat, "me@example.org"));
        let holds = w.holds().await;
        assert!(holds < 40 && sent.cost_sat == 1564 - holds, "{holds} left of what was held for the mint");
        assert_eq!(sweep(&w.site, desk, w.the_mint(), false).await, Ok(None), "and not again");
        // The operator says so: whatever it holds.
        w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        assert!(matches!(sweep(&w.site, desk, w.the_mint(), true).await, Ok(Some((_, Left::Paid { .. })))));
        // A payment that fails takes nothing, and is not tried again at
        // once: later, or when the operator says.
        w.buy(BUYER, "big", &w.token(1500).await, None).await.unwrap();
        let before = w.holds().await;
        *w.fate.lock().unwrap() = Fate::Fails;
        assert!(matches!(sweep(&w.site, desk, w.the_mint(), false).await, Ok(Some((_, Left::Not(_))))));
        assert_eq!(w.holds().await, before);
        *w.fate.lock().unwrap() = Fate::Paid;
        assert_eq!(sweep(&w.site, desk, w.the_mint(), false).await, Ok(None), "not at once");
        assert!(matches!(sweep(&w.site, desk, w.the_mint(), true).await, Ok(Some((_, Left::Paid { .. })))));
        // Sold, and what left: the two add up to what is held.
        let (sold, out) = (w.site.store.sold(&w.mint).unwrap(), w.site.store.paid_out(&w.mint).unwrap());
        assert_eq!(w.holds().await + out, sold);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn nothing_is_sent_on_where_the_config_names_nowhere() {
        let w = world(0, GIVE_UP).await;
        sold(&w).await;
        let desk = w.site.desk.as_ref().unwrap();
        assert_eq!(sweep(&w.site, desk, w.the_mint(), false).await, Ok(None));
        assert!(sweep(&w.site, desk, w.the_mint(), true).await.unwrap_err().contains("SWEEP_TO is not set"));
        assert!(withdrawals(&w).is_empty() && w.holds().await == 1564);
        assert_eq!((left_for_fees(1564, 0), left_for_fees(1564, 1), fee_bound(1000)), (35, 70, 70));
    }

    /// A wallet that holds as much as it may sells nothing more, by token
    /// or by invoice, until something has left it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_wallet_that_is_full_sells_nothing() {
        let w = world_with(0, GIVE_UP, 3600, "", "WALLET_CAP=100\n").await;
        w.hold().await;
        w.buy(BUYER, "small", &w.token(64).await, None).await.unwrap();
        assert_eq!(w.site.methods(), vec!["cashu", "bolt11", "onchain"], "64 of 100: there is room");
        w.buy(OTHER, "small", &w.token(64).await, None).await.unwrap();
        assert!(w.the_mint().full() && w.site.methods().is_empty(), "128 of 100");
        let token_of_theirs = w.token(64).await;
        assert_eq!(w.buy("fd99::9", "small", &token_of_theirs, None).await, Err(Fault::WalletFull));
        assert!(w.still_good(&token_of_theirs).await, "and the token is not touched");
        let by_invoice = crate::orders::Asked {
            package: "small".into(),
            method: Some("bolt11".into()),
            ..crate::orders::Asked::default()
        };
        let until = tokio::time::Instant::now() + Duration::from_secs(30);
        assert_eq!(
            crate::invoices::order(&w.site, "fd99::9".parse().unwrap(), &by_invoice, until).await,
            Err(Fault::WalletFull)
        );
        assert_eq!(Fault::WalletFull.status(), hyper::StatusCode::SERVICE_UNAVAILABLE);
        // Something leaves it: it sells again.
        token(&w.site, None, 100).await.unwrap();
        assert!(!w.the_mint().full() && w.site.methods() == vec!["cashu", "bolt11", "onchain"]);
        w.buy("fd99::9", "small", &w.token(64).await, None).await.unwrap();
    }
}
