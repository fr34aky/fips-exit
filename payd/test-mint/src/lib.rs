//! A Cashu mint for tests: in memory, served over HTTP as a real one is,
//! with a Lightning backend that is fake and pays its own invoices. And a
//! wallet of its own, which mints ecash there and hands it out as a token.
//!
//! An invoice of the mint's is paid at once, by nobody. A test of someone
//! paying one says [`hold`] first: from then on an invoice is paid when the
//! test says [`pay`], and not before.
//!
//! Nothing here is for use with money: the mint forgets everything when it
//! stops, and its sats are paid by nobody.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cdk::amount::SplitTarget;
use cdk::cdk_payment::{
    self as payment, CreateIncomingPaymentResponse, Event, IncomingPaymentOptions, MakePaymentResponse, MintPayment,
    OutgoingPaymentOptions, PaymentIdentifier, PaymentQuoteResponse, SettingsResponse, WaitPaymentResponse,
};
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::nut00::KnownMethod;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
use cdk::types::{FeeReserve, QuoteTTL};
use cdk::wallet::{SendOptions, Wallet};
use cdk::{Amount, Bolt11Invoice};
use cdk_fake_wallet::FakeWallet;
use futures::{Stream, StreamExt};

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("/dev/urandom");
    bytes
}

fn said(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// What the test says of the mint's invoices: whether they are held, and
/// which of them are paid.
#[derive(Default)]
struct Paying {
    holding: AtomicBool,
    /// What the backend paid and the mint has not been told of, by the
    /// payment it is for.
    held: Mutex<HashMap<String, WaitPaymentResponse>>,
    /// The payments the mint may know of.
    paid: Mutex<HashSet<String>>,
    /// Where the mint hears of a payment.
    tell: Mutex<Option<tokio::sync::mpsc::Sender<Event>>>,
}

impl Paying {
    /// Is the mint not to know of payment `id` yet?
    fn holds(&self, id: &str) -> bool {
        self.holding.load(Ordering::SeqCst) && !self.paid.lock().unwrap().contains(id)
    }

    /// The invoice `request` is paid: the mint hears of it.
    async fn pay(&self, request: &str) -> Result<(), String> {
        let invoice = Bolt11Invoice::from_str(request.trim()).map_err(|e| format!("not an invoice: {e}"))?;
        let id = PaymentIdentifier::PaymentHash(*invoice.payment_hash().as_ref()).to_string();
        self.paid.lock().unwrap().insert(id.clone());
        let held = self.held.lock().unwrap().remove(&id);
        let tell = self.tell.lock().unwrap().clone();
        if let (Some(held), Some(tell)) = (held, tell) {
            tell.send(Event::PaymentReceived(held)).await.map_err(said)?;
        }
        Ok(())
    }
}

/// The mint's Lightning backend: the fake one, which pays every invoice at
/// once, with the news of a payment held back while the test says so.
struct Held {
    backend: FakeWallet,
    paying: Arc<Paying>,
}

#[async_trait::async_trait]
impl MintPayment for Held {
    type Err = payment::Error;

    async fn get_settings(&self) -> Result<SettingsResponse, Self::Err> {
        self.backend.get_settings().await
    }

    async fn create_incoming_payment_request(
        &self,
        options: IncomingPaymentOptions,
    ) -> Result<CreateIncomingPaymentResponse, Self::Err> {
        self.backend.create_incoming_payment_request(options).await
    }

    async fn get_payment_quote(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<PaymentQuoteResponse, Self::Err> {
        self.backend.get_payment_quote(unit, options).await
    }

    async fn make_payment(
        &self,
        unit: &CurrencyUnit,
        options: OutgoingPaymentOptions,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.backend.make_payment(unit, options).await
    }

    async fn wait_payment_event(&self) -> Result<Pin<Box<dyn Stream<Item = Event> + Send>>, Self::Err> {
        let mut events = self.backend.wait_payment_event().await?;
        let (tell, told) = tokio::sync::mpsc::channel(64);
        *self.paying.tell.lock().unwrap() = Some(tell.clone());
        let paying = self.paying.clone();
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if let Event::PaymentReceived(received) = &event {
                    let id = received.payment_identifier.to_string();
                    if paying.holds(&id) {
                        paying.held.lock().unwrap().insert(id, received.clone());
                        continue;
                    }
                }
                if tell.send(event).await.is_err() {
                    return;
                }
            }
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(told)))
    }

    fn is_payment_event_stream_active(&self) -> bool {
        self.backend.is_payment_event_stream_active()
    }

    fn cancel_payment_event_stream(&self) {
        self.backend.cancel_payment_event_stream()
    }

    async fn check_incoming_payment_status(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<Vec<WaitPaymentResponse>, Self::Err> {
        if self.paying.holds(&payment_identifier.to_string()) {
            return Ok(Vec::new());
        }
        self.backend.check_incoming_payment_status(payment_identifier).await
    }

    async fn check_outgoing_payment(
        &self,
        payment_identifier: &PaymentIdentifier,
    ) -> Result<MakePaymentResponse, Self::Err> {
        self.backend.check_outgoing_payment(payment_identifier).await
    }
}

/// Start a mint on `listen` (port 0 for any), whose keysets charge
/// `input_fee_ppk` per proof spent. Its URL; it runs until the runtime ends.
pub async fn start(listen: SocketAddr, input_fee_ppk: u64) -> Result<String, String> {
    start_with(listen, input_fee_ppk, 3600).await
}

/// The same, with invoices that end `invoice_seconds` after they were asked
/// for.
pub async fn start_with(listen: SocketAddr, input_fee_ppk: u64, invoice_seconds: u64) -> Result<String, String> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.map_err(said)?);
    let mut builder = MintBuilder::new(db.clone());
    let paying = Arc::new(Paying::default());
    let backend = Held {
        backend: FakeWallet::new(
            FeeReserve { min_fee_reserve: 1.into(), percent_fee_reserve: 1.0 },
            HashMap::default(),
            HashSet::default(),
            // Seconds before an invoice counts as paid.
            0,
            CurrencyUnit::Sat,
        ),
        paying: paying.clone(),
    };
    builder
        .add_payment_processor(
            CurrencyUnit::Sat,
            PaymentMethod::Known(KnownMethod::Bolt11),
            MintMeltLimits::new(1, 1_000_000),
            Arc::new(backend),
        )
        .await
        .map_err(said)?;
    builder.set_unit_fee(&CurrencyUnit::Sat, input_fee_ppk).map_err(said)?;
    let listener = tokio::net::TcpListener::bind(listen).await.map_err(said)?;
    let at = listener.local_addr().map_err(said)?;
    let url = match at {
        SocketAddr::V6(v6) => format!("http://[{}]:{}", v6.ip(), v6.port()),
        SocketAddr::V4(v4) => format!("http://{v4}"),
    };
    let mint = builder
        .with_name("fips-exit test mint".into())
        .with_description("a mint for tests: nothing it gives out is worth anything".into())
        .with_urls(vec![url.clone()])
        .build_with_seed(db, &random::<32>())
        .await
        .map_err(said)?;
    mint.set_quote_ttl(QuoteTTL::new(invoice_seconds, 3600)).await.map_err(said)?;
    mint.start().await.map_err(said)?;
    let router = cdk_axum::create_mint_router(Arc::new(mint), vec!["bolt11".to_string()]).await.map_err(said)?;
    // What a test says of the mint's invoices, beside what a mint answers.
    let (holding, payer) = (paying.clone(), paying);
    let router = router
        .route(
            "/test/hold",
            axum::routing::post(move || async move {
                holding.holding.store(true, Ordering::SeqCst);
                "held\n"
            }),
        )
        .route(
            "/test/pay",
            axum::routing::post(move |request: String| async move {
                match payer.pay(&request).await {
                    Ok(()) => (axum::http::StatusCode::OK, "paid\n".to_string()),
                    Err(e) => (axum::http::StatusCode::BAD_REQUEST, format!("{e}\n")),
                }
            }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(url)
}

/// `body` posted to `path` at `mint` (as [`start`] gave it): what a test
/// says to the mint that no wallet would.
async fn post(mint: &str, path: &str, body: &str) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let at = mint.strip_prefix("http://").unwrap_or(mint);
    let mut stream = tokio::net::TcpStream::connect(at).await.map_err(|e| format!("{mint}: {e}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {at}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: \
         close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.map_err(said)?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.map_err(said)?;
    if answer.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("{mint}{path}: {}", answer.lines().last().unwrap_or("no answer")))
    }
}

/// From now on an invoice of `mint` is paid when [`pay`] says so, and not
/// at once.
pub async fn hold(mint: &str) -> Result<(), String> {
    post(mint, "/test/hold", "").await
}

/// The invoice `request` of `mint` is paid.
pub async fn pay(mint: &str, request: &str) -> Result<(), String> {
    post(mint, "/test/pay", request).await
}

/// A wallet at `mint`, in memory, with a seed of its own.
pub async fn wallet(mint: &str) -> Result<Wallet, String> {
    let store = Arc::new(cdk_sqlite::wallet::memory::empty().await.map_err(said)?);
    Wallet::new(mint, CurrencyUnit::Sat, store, random::<64>(), None).map_err(said)
}

/// Ecash of `amount` sat in `wallet`, minted with an invoice the mint's fake
/// backend pays itself.
pub async fn fill(wallet: &Wallet, amount: u64) -> Result<(), String> {
    let quote = wallet
        .mint_quote(PaymentMethod::Known(KnownMethod::Bolt11), Some(Amount::from(amount)), None, None)
        .await
        .map_err(said)?;
    // Paid here, whether or not the mint's invoices are held.
    pay(&wallet.mint_url.to_string(), &quote.request).await?;
    for _ in 0..100 {
        let state = wallet.check_mint_quote_status(&quote.id).await.map_err(said)?.state;
        if state == MintQuoteState::Paid {
            // As few proofs as the amount takes: a token of it is short.
            wallet.mint(&quote.id, SplitTarget::Value(Amount::from(amount)), None).await.map_err(said)?;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err("the mint's fake backend did not pay its invoice".into())
}

/// A token of `amount` sat from `wallet`. With `include_fee`, it is worth
/// that much after the fee the receiver pays to swap it, and so a little
/// more.
pub async fn token(wallet: &Wallet, amount: u64, include_fee: bool) -> Result<String, String> {
    let options = SendOptions { include_fee, ..SendOptions::default() };
    let prepared = wallet.prepare_send(Amount::from(amount), options).await.map_err(said)?;
    Ok(prepared.confirm(None).await.map_err(said)?.to_string())
}

/// A token of `amount` sat from a new wallet at `mint`, filled for it.
pub async fn new_token(mint: &str, amount: u64, include_fee: bool) -> Result<String, String> {
    let wallet = wallet(mint).await?;
    // Enough for the fee too, whatever it is.
    fill(&wallet, amount + if include_fee { 64 } else { 0 }).await?;
    token(&wallet, amount, include_fee).await
}

/// What a [`Proxy`] does: with a wallet's request to swap (or to mint, when
/// it is told so), or, when it is away, with everything.
const PASS: u8 = 0;
const LOSE_ANSWER: u8 = 1;
const REFUSE: u8 = 2;
const LOSE_ANSWER_AND_GO: u8 = 3;
const AWAY: u8 = 4;

/// A way to a mint on which what is asked or answered can be lost: for
/// tests of what a wallet's owner does when it cannot know whether the mint
/// took a token. Everything else is passed on.
pub struct Proxy {
    /// Where it listens: a mint's address, to whoever does not know better.
    pub url: String,
    swaps: Arc<std::sync::atomic::AtomicU8>,
    /// What the mode is about: the path of a swap, or of minting.
    about: Arc<Mutex<&'static str>>,
}

const SWAP: &str = "/v1/swap";
const MINT: &str = "/v1/mint/bolt11";

impl Proxy {
    /// Pass everything on: as when it began.
    pub fn pass(&self) {
        *self.about.lock().unwrap() = SWAP;
        self.swaps.store(PASS, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass a request to mint what an invoice paid for on to the mint, and
    /// lose the mint's answer.
    pub fn lose_mint_answers(&self) {
        *self.about.lock().unwrap() = MINT;
        self.swaps.store(LOSE_ANSWER, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass a swap on to the mint, and lose the mint's answer.
    pub fn lose_swap_answers(&self) {
        self.swaps.store(LOSE_ANSWER, std::sync::atomic::Ordering::SeqCst);
    }

    /// Do not pass a swap on at all.
    pub fn refuse_swaps(&self) {
        self.swaps.store(REFUSE, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass the next swap on, lose the mint's answer, and be away from
    /// then on: the mint took it, and cannot be asked.
    pub fn lose_a_swap_answer_and_go_away(&self) {
        self.swaps.store(LOSE_ANSWER_AND_GO, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass nothing on: a mint that cannot be reached.
    pub fn go_away(&self) {
        self.swaps.store(AWAY, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One request from `client`, passed to `upstream` or not, as `swaps` says.
async fn relay(
    mut client: tokio::net::TcpStream,
    upstream: SocketAddr,
    swaps: Arc<std::sync::atomic::AtomicU8>,
    about: &'static str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    let mut buffer = [0u8; 8192];
    // The head, then as much body as it says.
    let (head_end, length) = loop {
        match client.read(&mut buffer).await {
            Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
            _ => return,
        }
        if let Some(at) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..at]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|length| length.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (at + 4, length);
        }
    };
    while request.len() < head_end + length {
        match client.read(&mut buffer).await {
            Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&request[..head_end]).into_owned();
    let is_swap = head.lines().next().is_some_and(|line| line.split(' ').nth(1) == Some(about));
    let mode = match swaps.load(std::sync::atomic::Ordering::SeqCst) {
        AWAY => AWAY,
        mode if is_swap => mode,
        _ => PASS,
    };
    if mode == REFUSE || mode == AWAY {
        return;
    }
    // One request for a connection, on both sides.
    let mut lines: Vec<&str> =
        head.trim_end().lines().filter(|line| !line.to_ascii_lowercase().starts_with("connection:")).collect();
    lines.push("Connection: close");
    let mut passed = format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes();
    passed.extend_from_slice(&request[head_end..]);
    let Ok(mut mint) = tokio::net::TcpStream::connect(upstream).await else { return };
    if mint.write_all(&passed).await.is_err() {
        return;
    }
    let mut answer = Vec::new();
    let _ = mint.read_to_end(&mut answer).await;
    if mode == LOSE_ANSWER_AND_GO {
        swaps.store(AWAY, std::sync::atomic::Ordering::SeqCst);
    }
    if mode == LOSE_ANSWER || mode == LOSE_ANSWER_AND_GO {
        return;
    }
    let _ = client.write_all(&answer).await;
    let _ = client.shutdown().await;
}

/// A [`Proxy`] in front of the mint at `mint` (as [`start`] gave it).
pub async fn proxy(mint: &str) -> Result<Proxy, String> {
    let upstream: SocketAddr =
        mint.strip_prefix("http://").unwrap_or(mint).parse().map_err(|_| format!("{mint}: http://address:port"))?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.map_err(said)?;
    let url = format!("http://{}", listener.local_addr().map_err(said)?);
    let swaps = Arc::new(std::sync::atomic::AtomicU8::new(PASS));
    let about = Arc::new(Mutex::new(SWAP));
    let (mode, what) = (swaps.clone(), about.clone());
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let about = *what.lock().unwrap();
            tokio::spawn(relay(client, upstream, mode.clone(), about));
        }
    });
    Ok(Proxy { url, swaps, about })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state(wallet: &Wallet, quote: &str) -> MintQuoteState {
        wallet.check_mint_quote_status(quote).await.unwrap().state
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_invoice_is_paid_at_once_until_it_is_held_and_then_when_the_test_says() {
        let mint = start("127.0.0.1:0".parse().unwrap(), 0).await.unwrap();
        let wallet = wallet(&mint).await.unwrap();
        let bolt11 = || PaymentMethod::Known(KnownMethod::Bolt11);
        let quote = wallet.mint_quote(bolt11(), Some(Amount::from(21)), None, None).await.unwrap();
        for _ in 0..50 {
            if state(&wallet, &quote.id).await == MintQuoteState::Paid {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(state(&wallet, &quote.id).await, MintQuoteState::Paid, "paid by nobody, at once");

        hold(&mint).await.unwrap();
        let held = wallet.mint_quote(bolt11(), Some(Amount::from(34)), None, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(state(&wallet, &held.id).await, MintQuoteState::Unpaid, "held");
        assert!(wallet.mint(&held.id, SplitTarget::default(), None).await.is_err(), "and nothing is minted for it");
        pay(&mint, &held.request).await.unwrap();
        for _ in 0..50 {
            if state(&wallet, &held.id).await == MintQuoteState::Paid {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(state(&wallet, &held.id).await, MintQuoteState::Paid, "paid when the test said so");
        wallet.mint(&held.id, SplitTarget::default(), None).await.unwrap();
        assert_eq!(wallet.total_balance().await.unwrap(), Amount::from(34));
        // A wallet is still filled while invoices are held: it pays its own.
        fill(&wallet, 8).await.unwrap();
        assert_eq!(wallet.total_balance().await.unwrap(), Amount::from(42));
        assert!(pay(&mint, "not an invoice").await.is_err());
    }
}
