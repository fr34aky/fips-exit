//! A Cashu mint for tests: in memory, served over HTTP as a real one is,
//! with a Lightning backend that is fake and pays its own invoices. And a
//! wallet of its own, which mints ecash there and hands it out as a token.
//!
//! An invoice of the mint's is paid at once, by nobody. A test of someone
//! paying one says [`hold`] first: from then on an invoice is paid when the
//! test says [`pay`], and not before. The same holds for an address the mint
//! gives for a payment on the chain: what arrives there, and is confirmed,
//! is what the test says with [`deposit`].
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    /// The invoice the mint gave last.
    last: Mutex<Option<String>>,
    /// The addresses the mint gave for payments on the chain, each with
    /// what the backend knows it by, and what the test said arrived there.
    addresses: Mutex<HashMap<String, PaymentIdentifier>>,
    deposits: Mutex<HashMap<String, Vec<WaitPaymentResponse>>>,
}

impl Paying {
    /// Is the mint not to know of payment `id` yet?
    fn holds(&self, id: &str) -> bool {
        self.holding.load(Ordering::SeqCst) && !self.paid.lock().unwrap().contains(id)
    }

    /// `sat` arrived at `address`, which the mint gave for a payment on the
    /// chain, and are confirmed: the mint hears of it. As often as a test
    /// says, each time as a payment of its own.
    async fn deposit(&self, address: &str, sat: u64) -> Result<(), String> {
        let id = self.addresses.lock().unwrap().get(address.trim()).cloned();
        let id = id.ok_or_else(|| format!("{address}: not an address this mint gave"))?;
        let arrived = WaitPaymentResponse {
            payment_identifier: id.clone(),
            payment_amount: cdk::Amount::new(sat, CurrencyUnit::Sat),
            payment_id: format!("deposit-{}", hex(&random::<12>())),
        };
        self.deposits.lock().unwrap().entry(id.to_string()).or_default().push(arrived.clone());
        let tell = self.tell.lock().unwrap().clone();
        match tell {
            Some(tell) => tell.send(Event::PaymentReceived(arrived)).await.map_err(said),
            None => Err("the mint is not listening for payments".into()),
        }
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
        let on_the_chain = matches!(options, IncomingPaymentOptions::Onchain(_));
        let made = self.backend.create_incoming_payment_request(options).await?;
        *self.paying.last.lock().unwrap() = Some(made.request.clone());
        if on_the_chain {
            self.paying.addresses.lock().unwrap().insert(made.request.clone(), made.request_lookup_id.clone());
        }
        Ok(made)
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
        // What a test said arrived at an address is all that did, once its
        // payments are held.
        let id = payment_identifier.to_string();
        if self.paying.holds(&id) {
            return Ok(self.paying.deposits.lock().unwrap().get(&id).cloned().unwrap_or_default());
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
            // What it may take for paying an invoice: 2 sat, or a fiftieth.
            FeeReserve { min_fee_reserve: 2.into(), percent_fee_reserve: 0.02 },
            HashMap::default(),
            HashSet::default(),
            // Seconds before an invoice counts as paid.
            0,
            CurrencyUnit::Sat,
        ),
        paying: paying.clone(),
    };
    let backend = Arc::new(backend);
    for method in [KnownMethod::Bolt11, KnownMethod::Onchain] {
        builder
            .add_payment_processor(
                CurrencyUnit::Sat,
                PaymentMethod::Known(method),
                MintMeltLimits::new(1, 1_000_000),
                backend.clone(),
            )
            .await
            .map_err(said)?;
    }
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
    let ways = vec!["bolt11".to_string(), "onchain".to_string()];
    let router = cdk_axum::create_mint_router(Arc::new(mint), ways).await.map_err(said)?;
    // What a test says of the mint's invoices, beside what a mint answers.
    let (holding, payer, asked, chain) = (paying.clone(), paying.clone(), paying.clone(), paying);
    let router = router
        .route(
            "/test/deposit",
            axum::routing::post(move |said: String| async move {
                // "<address> <sat>"
                let arrived = match said.split_whitespace().collect::<Vec<_>>()[..] {
                    [address, sat] => match sat.parse() {
                        Ok(sat) => chain.deposit(address, sat).await,
                        Err(_) => Err(format!("{sat}: sat")),
                    },
                    _ => Err("an address and a number of sat".to_string()),
                };
                match arrived {
                    Ok(()) => (axum::http::StatusCode::OK, "arrived\n".to_string()),
                    Err(e) => (axum::http::StatusCode::BAD_REQUEST, format!("{e}\n")),
                }
            }),
        )
        .route(
            "/test/last",
            axum::routing::post(move || async move {
                match asked.last.lock().unwrap().clone() {
                    Some(invoice) => (axum::http::StatusCode::OK, format!("{invoice}\n")),
                    None => (axum::http::StatusCode::NOT_FOUND, "no invoice was given yet\n".to_string()),
                }
            }),
        )
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
/// says to the mint that no wallet would. What the mint says to it.
async fn post(mint: &str, path: &str, body: &str) -> Result<String, String> {
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
        Ok(answer.split("\r\n\r\n").nth(1).unwrap_or_default().trim().to_string())
    } else {
        Err(format!("{mint}{path}: {}", answer.lines().last().unwrap_or("no answer")))
    }
}

/// From now on an invoice of `mint` is paid when [`pay`] says so, and not
/// at once.
pub async fn hold(mint: &str) -> Result<(), String> {
    post(mint, "/test/hold", "").await.map(drop)
}

/// The invoice `request` of `mint` is paid.
pub async fn pay(mint: &str, request: &str) -> Result<(), String> {
    post(mint, "/test/pay", request).await.map(drop)
}

/// `sat` arrive at `address`, which `mint` gave for a payment on the chain,
/// and are confirmed.
pub async fn deposit(mint: &str, address: &str, sat: u64) -> Result<(), String> {
    post(mint, "/test/deposit", &format!("{address} {sat}")).await.map(drop)
}

/// The invoice `mint` gave last, to whoever asked for it.
pub async fn last(mint: &str) -> Result<String, String> {
    post(mint, "/test/last", "").await
}

/// What becomes of an invoice when the mint is asked to pay it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fate {
    Paid,
    /// The payment fails: the mint says so at once.
    Fails,
    /// The payment neither arrives nor fails: under way, whenever the
    /// mint is asked.
    Hangs,
}

/// A Lightning invoice of `sat` for a mint of these tests to pay, which
/// meets `fate` when one does. Nobody is paid by it.
pub fn invoice(sat: u64, fate: Fate) -> String {
    use cdk::nuts::MeltQuoteState::{Failed, Paid, Pending};
    let (pay_invoice_state, check_payment_state) = match fate {
        Fate::Paid => (Paid, Paid),
        Fate::Fails => (Failed, Failed),
        Fate::Hangs => (Pending, Pending),
    };
    let says = cdk_fake_wallet::FakeInvoiceDescription {
        pay_invoice_state,
        check_payment_state,
        pay_err: false,
        check_err: false,
    };
    let says = serde_json::to_string(&says).expect("a description");
    cdk_fake_wallet::create_fake_invoice(sat * 1000, says).to_string()
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
const MELT: &str = "/v1/melt/bolt11";
const MINT_ONCHAIN: &str = "/v1/mint/onchain";

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

    /// The same for what arrived on the chain.
    pub fn lose_onchain_mint_answers(&self) {
        *self.about.lock().unwrap() = MINT_ONCHAIN;
        self.swaps.store(LOSE_ANSWER, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass a request to pay an invoice on to the mint, and lose the mint's
    /// answer.
    pub fn lose_melt_answers(&self) {
        *self.about.lock().unwrap() = MELT;
        self.swaps.store(LOSE_ANSWER, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass the next request to pay an invoice on, lose the mint's answer,
    /// and be away from then on: the mint paid, and cannot be asked.
    pub fn lose_a_melt_answer_and_go_away(&self) {
        *self.about.lock().unwrap() = MELT;
        self.swaps.store(LOSE_ANSWER_AND_GO, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass a swap on to the mint, and lose the mint's answer.
    pub fn lose_swap_answers(&self) {
        *self.about.lock().unwrap() = SWAP;
        self.swaps.store(LOSE_ANSWER, std::sync::atomic::Ordering::SeqCst);
    }

    /// Do not pass a swap on at all.
    pub fn refuse_swaps(&self) {
        *self.about.lock().unwrap() = SWAP;
        self.swaps.store(REFUSE, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass the next swap on, lose the mint's answer, and be away from
    /// then on: the mint took it, and cannot be asked.
    pub fn lose_a_swap_answer_and_go_away(&self) {
        *self.about.lock().unwrap() = SWAP;
        self.swaps.store(LOSE_ANSWER_AND_GO, std::sync::atomic::Ordering::SeqCst);
    }

    /// Pass nothing on: a mint that cannot be reached.
    pub fn go_away(&self) {
        *self.about.lock().unwrap() = SWAP;
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

    /// What arrives at an address the mint gave is what the test says, as
    /// often as it says: the mint counts it up, and a wallet mints what was
    /// not minted yet.
    #[tokio::test(flavor = "multi_thread")]
    async fn what_arrives_on_the_chain_is_what_the_test_says() {
        let mint = start("127.0.0.1:0".parse().unwrap(), 0).await.unwrap();
        hold(&mint).await.unwrap();
        let wallet = wallet(&mint).await.unwrap();
        let quote = wallet.mint_quote(PaymentMethod::Known(KnownMethod::Onchain), None, None, None).await.unwrap();
        assert!(quote.request.starts_with("bcrt1q"), "an address: {}", quote.request);
        let now = |id: String| {
            let wallet = &wallet;
            async move {
                let quote = wallet.check_mint_quote_status(&id).await.unwrap();
                (u64::from(quote.amount_paid), u64::from(quote.amount_issued))
            }
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(now(quote.id.clone()).await, (0, 0), "nothing arrives by itself");
        deposit(&mint, &quote.request, 700).await.unwrap();
        for _ in 0..50 {
            if now(quote.id.clone()).await.0 == 700 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(now(quote.id.clone()).await, (700, 0));
        let minted = wallet.mint(&quote.id, SplitTarget::default(), None).await.unwrap();
        assert_eq!(minted.iter().map(|proof| u64::from(proof.amount)).sum::<u64>(), 700);
        assert_eq!(now(quote.id.clone()).await, (700, 700));
        // More arrives at the same address: counted up, and minted too.
        deposit(&mint, &quote.request, 800).await.unwrap();
        for _ in 0..50 {
            if now(quote.id.clone()).await.0 == 1500 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(now(quote.id.clone()).await, (1500, 700));
        wallet.mint(&quote.id, SplitTarget::default(), None).await.unwrap();
        assert_eq!(now(quote.id.clone()).await, (1500, 1500));
        assert_eq!(wallet.total_balance().await.unwrap(), Amount::from(1500));
        assert!(deposit(&mint, "bcrt1qnotanaddressofthismint", 5).await.is_err());
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
        assert_eq!(last(&mint).await.unwrap(), held.request, "the invoice it gave last");
        fill(&wallet, 8).await.unwrap();
        assert_eq!(wallet.total_balance().await.unwrap(), Amount::from(42));
        assert!(pay(&mint, "not an invoice").await.is_err());
    }
}
