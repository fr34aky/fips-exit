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
use crate::wallet::{Left, Mint, PAY_TIME, Payable};

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
    let mut id = None;
    let made = mint
        .token_out(sat, |name| {
            let new =
                NewWithdrawal { mint: &mint.name, kind: TOKEN, sat, cost_most: most, to_whom: "", reference: name };
            id = Some(stored(site.store.withdrawal_begin(&new, unix_now()))?);
            Ok(())
        })
        .await;
    let after = mint.balance().await.map_or(before, |(holds, _)| holds);
    let Some(id) = id else { return Err(made.err().unwrap_or_else(|| "no token was made".into())) };
    match made {
        Ok(text) => {
            let cost = before.saturating_sub(after);
            stored(site.store.withdrawal_end(&id, true, cost, unix_now()))?;
            eprintln!("fips-exit-payd: withdrawal {id}: a token of {sat} sat of {} was handed out", mint.name);
            Ok((id, cost, text))
        }
        Err(e) => {
            stored(site.store.withdrawal_end(&id, false, 0, unix_now()))?;
            Err(e)
        }
    }
}

/// The tokens handed out at each mint that nobody has redeemed: the mint's
/// name, the token's name, its text.
pub async fn tokens(site: &Site) -> Result<Vec<(String, String, String)>, String> {
    let mut out = Vec::new();
    for mint in &desk(site)?.wallets.mints {
        let _turn = mint.turn.lock().await;
        for (name, text) in mint.tokens_out().await? {
            out.push((mint.name.clone(), name, text));
        }
    }
    Ok(out)
}

/// Take back the token that was handed out as `name`, which nobody has
/// redeemed. What came back, in sat.
pub async fn take_back(site: &Site, name: &str) -> Result<u64, String> {
    let mints = &desk(site)?.wallets.mints;
    for mint in mints {
        let _turn = mint.turn.lock().await;
        if !mint.token_is_out(name).await? {
            continue;
        }
        let back = mint.token_back(name).await?;
        let _ = mint.balance().await;
        stored(site.store.withdrawal_back(name, back, unix_now()))?;
        eprintln!("fips-exit-payd: the token {name} of {} was taken back: {back} sat", mint.name);
        return Ok(back);
    }
    Err("no token of that name is out: it was redeemed, or never made".into())
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
    let after = mint.balance().await.map_or(before, |(holds, _)| holds);
    match &left {
        Left::Paid { sat, fee, .. } => {
            stored(site.store.withdrawal_end(&id, true, before.saturating_sub(after), unix_now()))?;
            eprintln!("fips-exit-payd: withdrawal {id}: {} paid {sat} sat for the wallet, for {fee} sat", mint.name);
        }
        Left::Not(why) => {
            stored(site.store.withdrawal_end(&id, false, 0, unix_now()))?;
            eprintln!("fips-exit-payd: withdrawal {id}: {} did not pay {} sat: {why}", mint.name, payable.sat);
        }
        Left::Pending => eprintln!(
            "fips-exit-payd: withdrawal {id}: what became of {} sat that {} was to pay is not known yet",
            payable.sat, mint.name
        ),
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
    let begun = match site.store.withdrawals_begun(&mint.name) {
        Ok(begun) if !begun.is_empty() => begun,
        Ok(_) => return 0,
        Err(e) => {
            eprintln!("fips-exit-payd: the withdrawals could not be read: {e}");
            return 0;
        }
    };
    let _turn = mint.turn.lock().await;
    let mut under_way = 0;
    for withdrawal in &begun {
        let Some(reference) = &withdrawal.quote else { continue };
        // A token: made if the wallet keeps it, and never made if not.
        let ended = if withdrawal.kind == TOKEN {
            match mint.token_is_out(reference).await {
                Ok(made) => Some((made, withdrawal.cost_sat)),
                Err(_) => None,
            }
        } else {
            match mint.payment(reference).await {
                Ok(Left::Paid { sat, fee, .. }) => Some((true, sat.saturating_add(fee))),
                Ok(Left::Not(_)) => Some((false, 0)),
                Ok(Left::Pending) | Err(_) => None,
            }
        };
        match ended {
            Some((done, cost)) => {
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
                    if done { "it left the wallet" } else { "it came to nothing, and nothing left" }
                );
            }
            None => under_way += 1,
        }
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
        // too): more is left for it next time.
        Left::Not(why) => {
            let _ = failed(why.clone(), false);
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
            // Now and then: which of the tokens handed out were redeemed,
            // so that they do not count as under way for ever.
            if round.is_multiple_of(TOKENS_EVERY) {
                let _turn = mint.turn.lock().await;
                let _ = mint.tokens_out().await;
                let _ = mint.balance().await;
            }
            let _ = sweep(&site, &desk, mint, false).await;
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
        assert_eq!(w.site.methods(), vec!["cashu", "bolt11"], "64 of 100: there is room");
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
        assert!(!w.the_mint().full() && w.site.methods() == vec!["cashu", "bolt11"]);
        w.buy("fd99::9", "small", &w.token(64).await, None).await.unwrap();
    }
}
