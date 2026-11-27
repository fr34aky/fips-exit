//! A Cashu mint for tests: in memory, served over HTTP as a real one is,
//! with a Lightning backend that is fake and pays its own invoices. And a
//! wallet of its own, which mints ecash there and hands it out as a token.
//!
//! Nothing here is for use with money: the mint forgets everything when it
//! stops, and its sats are paid by nobody.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use cdk::Amount;
use cdk::amount::SplitTarget;
use cdk::mint::{MintBuilder, MintMeltLimits};
use cdk::nuts::nut00::KnownMethod;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
use cdk::types::{FeeReserve, QuoteTTL};
use cdk::wallet::{SendOptions, Wallet};
use cdk_fake_wallet::FakeWallet;

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("/dev/urandom");
    bytes
}

fn said(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Start a mint on `listen` (port 0 for any), whose keysets charge
/// `input_fee_ppk` per proof spent. Its URL; it runs until the runtime ends.
pub async fn start(listen: SocketAddr, input_fee_ppk: u64) -> Result<String, String> {
    let db = Arc::new(cdk_sqlite::mint::memory::empty().await.map_err(said)?);
    let mut builder = MintBuilder::new(db.clone());
    let backend = FakeWallet::new(
        FeeReserve { min_fee_reserve: 1.into(), percent_fee_reserve: 1.0 },
        HashMap::default(),
        HashSet::default(),
        // Seconds before an invoice counts as paid.
        0,
        CurrencyUnit::Sat,
    );
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
    mint.set_quote_ttl(QuoteTTL::new(3600, 3600)).await.map_err(said)?;
    mint.start().await.map_err(said)?;
    let router = cdk_axum::create_mint_router(Arc::new(mint), vec!["bolt11".to_string()]).await.map_err(said)?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(url)
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
    for _ in 0..100 {
        let state = wallet.check_mint_quote_status(&quote.id).await.map_err(said)?.state;
        if state == MintQuoteState::Paid {
            wallet.mint(&quote.id, SplitTarget::default(), None).await.map_err(said)?;
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

/// What a [`Proxy`] does: with a wallet's request to swap, or, when it is
/// away, with everything.
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
}

impl Proxy {
    /// Pass everything on: as when it began.
    pub fn pass(&self) {
        self.swaps.store(PASS, std::sync::atomic::Ordering::SeqCst);
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
async fn relay(mut client: tokio::net::TcpStream, upstream: SocketAddr, swaps: Arc<std::sync::atomic::AtomicU8>) {
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
    let is_swap = head.lines().next().is_some_and(|line| line.contains("/v1/swap"));
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
    let mode = swaps.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(relay(client, upstream, mode.clone()));
        }
    });
    Ok(Proxy { url, swaps })
}
