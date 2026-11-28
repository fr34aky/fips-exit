//! The exit's own Cashu wallet: where what is paid arrives, as ecash at the
//! mints the operator accepts (`MINTS`).
//!
//! The wallet is the wallet library's (cdk): nothing of blind signatures is
//! written here. What is here is what the exit needs around it: a seed kept
//! as words, one wallet for each accepted mint, what can be said of a token
//! before anything is asked of the mint, and one question the library does
//! not put by itself: did the mint sign what *this* wallet asked for in
//! exchange for a token? After an answer of the mint's was lost, the library
//! goes by whether the token's proofs are spent, whoever spent them: it
//! then either cannot finish, or, where the mint cannot say what it signed,
//! counts the token as received. The exit asks the mint what it signed for
//! this wallet, and grants only that (see `orders`).
//!
//! Two files in the service's state directory: `seed`, 24 words (BIP-39),
//! and `wallet.db`, the library's store. Whoever has the seed has what the
//! wallet holds, and can find it again at the mints with any wallet that
//! restores from a seed (NUT-13).
//!
//! What is paid by Lightning arrives the same way: the mint gives an invoice
//! (a quote), and once that is paid the wallet mints ecash for it. A quote
//! is locked to a key of the wallet's (NUT-20, where the mint has it), so
//! that nobody else mints what was paid.
//!
//! What the wallet holds leaves it in two ways, both the library's: as a
//! token, which is ecash for whoever has its text; or by the mint paying a
//! Lightning invoice for it (a melt, NUT-05). Nothing here decides that
//! either happens: `payouts` does, for the operator.
//!
//! What the wallet asks a mint to sign follows from the seed and a counter
//! in the wallet's file. A file that is behind its seed's use (a new one, or
//! an old copy put back) would ask for what the mint has signed already:
//! the mint refuses that, and what it signed before must not be taken for
//! a payment. So before anything is sold at a mint the wallet's next
//! requests are asked about there, and a wallet that is behind counts again
//! from its seed first. One wallet for a seed: two at once are each behind
//! the other.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use cdk::amount::SplitTarget;
use cdk::cdk_database::WalletDatabase;
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::KnownMethod;
use cdk::nuts::nut04::MintMethodOptions;
use cdk::nuts::{
    BlindedMessage, CheckStateRequest, CurrencyUnit, MeltQuoteState, MintQuoteState, PaymentMethod, PreMintSecrets,
    ProofsMethods, PublicKey, RestoreRequest, SecretKey, State, Token,
};
use cdk::wallet::types::{
    KeysetLoadPolicy, OperationData, ReceiveSagaState, SendSagaState, TransactionDirection, TransactionId,
    TransactionStatus, WalletSagaState,
};
use cdk::wallet::{ReceiveOptions, SendOptions, Wallet};
use cdk_sqlite::wallet::WalletSqliteDatabase;
use sha2::{Digest, Sha256};

use crate::store::random;

/// How long anything asked of a mint may take. The library sets no limit
/// of its own on a request.
pub const MINT_TIME: Duration = Duration::from_secs(25);
/// How long a mint may take to pay an invoice before the payment is left
/// as under way: a Lightning payment finds its way, or does not, in about
/// that.
pub const PAY_TIME: Duration = Duration::from_secs(60);
/// The longest token read, in characters, and the most proofs in one: a
/// bound on what a stranger can make this service, and the mint, work on.
pub const MAX_TOKEN: usize = 24 * 1024;
pub const MAX_PROOFS: usize = 64;
/// How many of the wallet's next requests to a mint are asked about, to
/// find out whether its file is behind its seed's use: as many as a wallet
/// asks about at a time when it counts again.
const AHEAD: u32 = 100;

/// Why a token is not taken, found without asking the mint anything about
/// it: the token is untouched.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// Not a token, or not one this wallet can take.
    Token(String),
    /// From a mint this exit does not accept.
    WrongMint(String),
    /// From an accepted mint that has not been reached yet.
    MintAway(String),
}

/// What a token is, as far as can be said here.
#[derive(Debug, Clone, PartialEq)]
pub struct Look {
    /// SHA-256 over its proofs: the same proofs are the same token, however
    /// they are written.
    pub receipt: [u8; 32],
    /// What it says it is worth, in sat, and what the mint takes for
    /// redeeming it.
    pub value: u64,
    pub fee: u64,
    /// Its proofs as the mint knows them (their `Y`s, as JSON): what the
    /// mint is asked about when it is asked whether they are spent.
    pub inputs: String,
}

/// What a token's proofs are at the mint.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Inputs {
    /// All spent: by whoever the mint took them from.
    Spent,
    /// Some spent: by someone else, since an exchange takes all or none.
    Partly,
    /// None spent, yet.
    Unspent,
}

/// What the wallet was in the middle of for a token, when it was
/// interrupted.
#[derive(Debug, Clone, PartialEq)]
pub struct Unfinished {
    /// What it asked the mint to sign in exchange, as JSON, once it had got
    /// as far as asking.
    pub outputs: Option<String>,
}

/// What the wallet's own record says of an order's token.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Recorded {
    /// Nothing, or that it failed.
    No,
    /// That it is under way.
    Pending,
    /// That this much arrived, in sat, for this fee.
    Received(u64, u64),
}

/// What a mint says of the invoices it gives, in sat.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Lightning {
    /// The least and the most an invoice may be for.
    least: u64,
    most: u64,
    /// Whether an invoice may say what it is for.
    describes: bool,
}

/// An invoice of a mint's, and the quote it stands for there.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub id: String,
    /// The invoice: a BOLT11 payment request.
    pub request: String,
    /// When it ends, in Unix seconds.
    pub expires: u64,
    /// The key the quote is locked to, where the wallet made one.
    pub key: Option<String>,
}

/// What a mint says of a quote.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Paid {
    /// Its invoice is not paid.
    No,
    /// It is, and nothing was minted for it yet.
    Yes,
    /// It is, and this much was minted for it, in sat: for this wallet,
    /// which alone knows the quote and holds its key.
    Minted(u64),
}

impl Lightning {
    /// What a mint's description of itself says of its invoices (NUT-04),
    /// if it gives any for sat.
    fn of(info: &cdk::nuts::MintInfo) -> Option<Lightning> {
        let minting = &info.nuts.nut04;
        minting.get_settings(&CurrencyUnit::Sat, &bolt11()).filter(|_| !minting.disabled).map(|its| Lightning {
            least: its.min_amount.map_or(1, |least| least.to_u64().max(1)),
            most: its.max_amount.map_or(u64::MAX, |most| most.to_u64()),
            describes: matches!(its.options, Some(MintMethodOptions::Bolt11 { description: true })),
        })
    }
}

/// What the wallet has of a token it was to hand out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenState {
    /// Made, and not redeemed as far as the wallet knows: it is out.
    Out,
    /// Begun and not made: the wallet may hold something for it still.
    Unfinished,
    /// Nothing: it was never made, or was redeemed, or taken back.
    Nothing,
}

/// What paying an invoice from the wallet takes, as the mint quotes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Payable {
    /// The mint's quote: what the payment is made by, and asked about by.
    pub quote: String,
    /// What is paid, and the most the mint may take on top (what it does
    /// not use of that comes back), in sat.
    pub sat: u64,
    pub fee_most: u64,
    /// When the quote ends, in Unix seconds.
    pub expires: u64,
}

/// What became of a payment from the wallet.
#[derive(Debug, Clone, PartialEq)]
pub enum Left {
    /// Paid: this much, for this fee, with the proof of it where the mint
    /// gave one.
    Paid { sat: u64, fee: u64, proof: Option<String> },
    /// Under way: the mint has what pays for it, and has not said.
    Pending,
    /// Not paid, and nothing left the wallet: why.
    Not(String),
}

fn bolt11() -> PaymentMethod {
    PaymentMethod::Known(KnownMethod::Bolt11)
}

fn said(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// `asked` of a mint, within [`MINT_TIME`].
async fn within<T, E: std::fmt::Display>(asked: impl Future<Output = Result<T, E>>) -> Result<T, String> {
    match tokio::time::timeout(MINT_TIME, asked).await {
        Ok(answer) => answer.map_err(said),
        Err(_) => Err("the mint did not answer in time".into()),
    }
}

/// A token as text: `cashuA…` or `cashuB…`, with whatever a person pasted
/// around it (spaces, line breaks, a `cashu:` in front). The token, and its
/// text without those.
pub fn parse(text: &str) -> Result<(Token, String), Refusal> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let text = text.strip_prefix("cashu:").unwrap_or(&text);
    if text.is_empty() {
        return Err(Refusal::Token("No token was given".into()));
    }
    if text.len() > MAX_TOKEN {
        return Err(Refusal::Token(format!("A token of more than {MAX_TOKEN} characters is not read")));
    }
    let token =
        Token::from_str(text).map_err(|_| Refusal::Token("That is not a Cashu token (cashuA… or cashuB…)".into()))?;
    Ok((token, text.to_string()))
}

/// The receipt of a set of proofs: SHA-256 over their `Y`s, in order.
fn receipt_of(proofs: &cdk::nuts::Proofs) -> Result<[u8; 32], String> {
    let mut ys: Vec<[u8; 33]> = proofs.ys().map_err(said)?.iter().map(|y| y.to_bytes()).collect();
    ys.sort_unstable();
    let before = ys.len();
    ys.dedup();
    if ys.len() != before {
        return Err("The token has the same proof twice".into());
    }
    let mut hash = Sha256::new();
    for y in &ys {
        hash.update(y);
    }
    Ok(hash.finalize().into())
}

/// The wallet at one mint.
pub struct Mint {
    /// The mint as the config names it.
    pub name: String,
    url: MintUrl,
    wallet: Wallet,
    db: Arc<WalletSqliteDatabase>,
    seed: [u8; 64],
    /// Whether tokens are taken at it: it has been reached, and its keys
    /// are known.
    ready: AtomicBool,
    /// The seed was here and the wallet's file was not: what the seed has
    /// at the mint is counted again before anything else is done there. A
    /// file says so until it is done, since the wallet's file is there from
    /// the first start on.
    count_first: AtomicBool,
    marker: PathBuf,
    /// The wallet's next requests are to be asked about before anything is
    /// sold: at the start, and when the mint has refused one as signed
    /// already.
    look_ahead: AtomicBool,
    /// Told when this mint is to be reached again now.
    again: Arc<tokio::sync::Notify>,
    /// What the mint said of its invoices when it was last reached, if it
    /// gives any for sat.
    lightning: std::sync::Mutex<Option<Lightning>>,
    /// What the wallet held here when that was last asked, in sat; and the
    /// most it may hold (0: any amount), from where on nothing is sold.
    held: AtomicU64,
    cap: AtomicU64,
    /// The proofs of the tokens that were handed out here and that nobody
    /// has redeemed (each token's `Y`s, as JSON): somebody else's, however
    /// unspent the mint calls them.
    out: std::sync::Mutex<Vec<String>>,
    /// One thing at a time at a mint: a token taken, an invoice asked for
    /// or minted, or what was interrupted put right, never two at once.
    pub turn: tokio::sync::Mutex<()>,
}

impl Mint {
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    /// Reach the mint: its description and its keys, and what an earlier
    /// run of this wallet left there if its file was lost. Said in the log
    /// when it changes.
    pub async fn reach(&self) -> Result<(), String> {
        let reached = async {
            // Asked of the mint itself: what the wallet remembers of it
            // does not say that it is there.
            let info = within(self.wallet.fetch_mint_info()).await?.ok_or("it says nothing of itself")?;
            // What is done after an answer was lost rests on these two: the
            // state of a proof (NUT-07) and what was signed (NUT-09).
            if !info.nuts.nut07.supported || !info.nuts.nut09.supported {
                return Err("it does not say what it has signed (NUT-07 and NUT-09): tokens of it are not taken".into());
            }
            let keysets = within(self.wallet.keysets(KeysetLoadPolicy::CacheThenNetwork)).await?;
            if !keysets.iter().any(|keyset| keyset.unit == CurrencyUnit::Sat) {
                return Err("it has no keys for sat".to_string());
            }
            // Whether it gives invoices, as it says itself (NUT-04).
            *self.lightning.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Lightning::of(&info);
            if self.count_first.load(Ordering::Relaxed) || self.look_ahead.load(Ordering::Relaxed) {
                let _turn = self.turn.lock().await;
                if self.count_first.load(Ordering::Relaxed) || self.behind().await? {
                    let found = self.count_again().await?;
                    eprintln!("fips-exit-payd: {}: the wallet's file was behind its seed's use: {found}", self.name);
                    if self.behind().await? {
                        return Err(
                            "it has signed more for this wallet's seed than the wallet knows of, and counting \
                                    again did not find it: is another wallet using the seed?"
                                .into(),
                        );
                    }
                }
                match std::fs::remove_file(&self.marker) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err(format!("{}: {e}", self.marker.display()));
                    }
                    _ => {}
                }
                self.count_first.store(false, Ordering::Relaxed);
                self.look_ahead.store(false, Ordering::Relaxed);
            }
            Ok(())
        }
        .await;
        let was = self.ready.swap(reached.is_ok(), Ordering::Relaxed);
        match &reached {
            Ok(()) if !was => eprintln!("fips-exit-payd: {}: reached, tokens of this mint are taken", self.name),
            Err(e) if was => eprintln!("fips-exit-payd: {}: not reached any more ({e})", self.name),
            _ => {}
        }
        reached
    }

    /// Has the mint signed any of the wallet's next requests already? Then
    /// the wallet's file is behind what its seed was used for. The caller
    /// holds [`Mint::turn`].
    async fn behind(&self) -> Result<bool, String> {
        let keyset = within(self.wallet.active_keyset()).await?.id;
        let next = self.db.increment_keyset_counter(&keyset, 0).await.map_err(said)?;
        let outputs = PreMintSecrets::restore_batch(keyset, &self.seed, next, next.saturating_add(AHEAD))
            .map_err(said)?
            .blinded_messages();
        let answer = within(self.wallet.mint_connector().post_restore(RestoreRequest { outputs })).await?;
        Ok(!answer.signatures.is_empty())
    }

    /// The mint has signed before what the wallet asked it to sign now:
    /// nothing is sold here until the wallet has counted again, at once.
    pub fn suspect(&self) {
        // Counted again in full, not only looked ahead: the request the
        // mint refused has moved the wallet's counter past what it signed
        // before, and what was signed there is the wallet's all the same.
        // Written down, so that a restart does not forget it.
        self.count_first.store(true, Ordering::Relaxed);
        if let Err(e) = std::fs::write(&self.marker, format!("{}\n", self.name)) {
            eprintln!("fips-exit-payd: {}: {e}", self.marker.display());
        }
        self.look_ahead.store(true, Ordering::Relaxed);
        if self.ready.swap(false, Ordering::Relaxed) {
            eprintln!(
                "fips-exit-payd: {}: THE MINT HAS SIGNED BEFORE WHAT THE WALLET ASKED OF IT NOW: the wallet's file is \
                 behind its seed's use. Nothing is sold here until it has counted again.",
                self.name
            );
        }
        self.again.notify_one();
    }

    /// The receipt of `token`, if this wallet knows its mint's keys:
    /// without them it has taken no token of it. Nothing is asked of the
    /// mint.
    pub async fn receipt(&self, token: &Token) -> Option<[u8; 32]> {
        let keysets = self.db.get_mint_keysets(self.url.clone()).await.ok().flatten()?;
        receipt_of(&token.proofs(&keysets).ok()?).ok()
    }

    /// What the proofs `inputs` (as [`Look`] has them) are at the mint
    /// (NUT-07).
    pub async fn inputs(&self, inputs: &str) -> Result<Inputs, String> {
        let ys: Vec<PublicKey> = serde_json::from_str(inputs).map_err(said)?;
        let answer =
            within(self.wallet.mint_connector().post_check_state(CheckStateRequest { ys: ys.clone() })).await?;
        let spent = ys
            .iter()
            .filter(|y| answer.states.iter().any(|state| state.y == **y && state.state == State::Spent))
            .count();
        Ok(match spent {
            0 => Inputs::Unspent,
            all if all == ys.len() => Inputs::Spent,
            _ => Inputs::Partly,
        })
    }

    /// What `token`, which names this mint, is: its proofs, its worth, the
    /// mint's fee. Nothing is asked of the mint about the token.
    pub async fn look(&self, token: &Token) -> Result<Look, Refusal> {
        let no = |why: &str| Refusal::Token(why.to_string());
        if token.unit().unwrap_or_default() != CurrencyUnit::Sat {
            return Err(no("The token is not in sat"));
        }
        let keysets = self
            .db
            .get_mint_keysets(self.url.clone())
            .await
            .ok()
            .flatten()
            .ok_or_else(|| Refusal::MintAway(self.name.clone()))?;
        let proofs = token.proofs(&keysets).map_err(|_| no("The token's proofs are not of its mint's keys"))?;
        if proofs.is_empty() || proofs.len() > MAX_PROOFS {
            return Err(no(&format!("A token of 1 to {MAX_PROOFS} proofs is taken")));
        }
        let value = proofs.total_amount().map_err(|_| no("The token's amounts do not add up"))?.to_u64();
        let receipt = receipt_of(&proofs).map_err(|e| no(&e))?;
        let inputs = proofs.ys().ok().and_then(|ys| serde_json::to_string(&ys).ok());
        let inputs = inputs.ok_or_else(|| no("The token's proofs cannot be read"))?;
        let fee = within(self.wallet.get_proofs_fee(&proofs))
            .await
            .map_err(|_| Refusal::MintAway(self.name.clone()))?
            .total
            .to_u64();
        Ok(Look { receipt, value, fee, inputs })
    }

    /// Redeem `token` at the mint, for `order`. What arrived, in sat.
    ///
    /// The caller holds this mint's [`Mint::turn`]. An error does not say
    /// whether the mint took the token: [`Mint::unfinished`] does.
    pub async fn receive(&self, token: &str, order: &str) -> Result<u64, cdk::Error> {
        let options = ReceiveOptions {
            metadata: HashMap::from([("order".to_string(), order.to_string())]),
            ..Default::default()
        };
        Ok(self.wallet.receive(token, options).await?.to_u64())
    }

    /// What the wallet has begun for the token with `receipt` and not
    /// finished, as its store keeps it.
    async fn begun(&self, receipt: &[u8; 32]) -> Result<Option<cdk::wallet::types::WalletSaga>, String> {
        let keysets = self.db.get_mint_keysets(self.url.clone()).await.map_err(said)?.unwrap_or_default();
        for saga in self.db.get_incomplete_sagas().await.map_err(said)? {
            let (WalletSagaState::Receive(_), OperationData::Receive(data)) = (&saga.state, &saga.data) else {
                continue;
            };
            let its = data
                .token
                .as_deref()
                .and_then(|token| Token::from_str(token).ok())
                .and_then(|token| token.proofs(&keysets).ok())
                .and_then(|proofs| receipt_of(&proofs).ok());
            if saga.mint_url == self.url && its.as_ref() == Some(receipt) {
                return Ok(Some(saga));
            }
        }
        Ok(None)
    }

    /// What the wallet has still under way for the token with `receipt`:
    /// something it began and did not finish.
    pub async fn unfinished(&self, receipt: &[u8; 32]) -> Result<Option<Unfinished>, String> {
        let Some(saga) = self.begun(receipt).await? else { return Ok(None) };
        let outputs = match (&saga.state, &saga.data) {
            (WalletSagaState::Receive(ReceiveSagaState::SwapRequested), OperationData::Receive(data)) => {
                match &data.blinded_messages {
                    Some(outputs) if !outputs.is_empty() => Some(serde_json::to_string(outputs).map_err(said)?),
                    _ => None,
                }
            }
            _ => None,
        };
        Ok(Some(Unfinished { outputs }))
    }

    /// Give up what the wallet began for the token with `receipt`, which
    /// the mint did not take for this wallet: the token's proofs, which the
    /// wallet held as under way, its note of what it began, and its record
    /// of a payment that was none. As the library gives a token up itself,
    /// for one it cannot: the caller holds [`Mint::turn`], and knows from
    /// the mint that nothing was signed.
    pub async fn forget(&self, receipt: &[u8; 32]) -> Result<(), String> {
        let Some(saga) = self.begun(receipt).await? else { return Ok(()) };
        let held = self.db.get_reserved_proofs(&saga.id).await.map_err(said)?;
        self.db.update_proofs(Vec::new(), held.iter().map(|proof| proof.y).collect()).await.map_err(said)?;
        self.db.delete_saga(&saga.id).await.map_err(said)?;
        self.db.remove_transaction(TransactionId::from_saga_id(saga.id)).await.map_err(said)
    }

    /// Let the wallet put right what it was interrupted in: asking the mint
    /// again, or giving up what the mint did not take. The caller holds
    /// [`Mint::turn`], and has kept the outputs of everything unfinished
    /// first: what the wallet concludes here is not what the exit goes by.
    pub async fn put_right(&self) -> Result<(), String> {
        let report = within(self.wallet.recover_incomplete_sagas()).await?;
        if report.recovered + report.compensated + report.skipped + report.failed > 0 {
            eprintln!(
                "fips-exit-payd: {}: the wallet put right what it was interrupted in: {} finished, {} given up, \
                 {} waiting for the mint, {} it could not",
                self.name, report.recovered, report.compensated, report.skipped, report.failed
            );
        }
        Ok(())
    }

    /// How many sat the mint has signed of `outputs` (as [`Unfinished`]
    /// kept them): what this wallet asked it to sign in exchange for a
    /// token. Nothing, if the exchange did not happen; the mint signs them
    /// for nobody else, since nobody else can ask for them. It may have
    /// signed them for this wallet before, if the wallet's file is behind:
    /// so this is a payment only together with the token's proofs being
    /// spent ([`Mint::inputs`]), which one exchange does at once.
    pub async fn signed(&self, outputs: &str) -> Result<u64, String> {
        let outputs: Vec<BlindedMessage> = serde_json::from_str(outputs).map_err(said)?;
        let asked: Vec<_> = outputs.iter().map(|output| output.blinded_secret).collect();
        let answer = within(self.wallet.mint_connector().post_restore(RestoreRequest { outputs })).await?;
        // Only what was asked about counts, whatever the mint adds.
        let mut sat = 0u64;
        for (output, signature) in answer.outputs.iter().zip(&answer.signatures) {
            if asked.contains(&output.blinded_secret) {
                sat = sat.saturating_add(signature.amount.to_u64());
            }
        }
        Ok(sat)
    }

    /// What the wallet's own record says of `order`'s token.
    pub async fn recorded(&self, order: &str) -> Result<Recorded, String> {
        let all = self.wallet.list_transactions(Some(TransactionDirection::Incoming)).await.map_err(said)?;
        let mut found = Recorded::No;
        for transaction in all.iter().filter(|t| t.metadata.get("order").map(String::as_str) == Some(order)) {
            match transaction.status {
                TransactionStatus::Completed => {
                    return Ok(Recorded::Received(transaction.amount.to_u64(), transaction.fee.to_u64()));
                }
                TransactionStatus::Pending => found = Recorded::Pending,
                TransactionStatus::Failed => {}
            }
        }
        Ok(found)
    }

    /// What the wallet holds at this mint, and what it has under way, in sat.
    pub async fn balance(&self) -> Result<(u64, u64), String> {
        let holds = self.wallet.total_balance().await.map_err(said)?.to_u64();
        let pending = self.wallet.total_pending_balance().await.map_err(said)?.to_u64();
        self.held.store(holds, Ordering::Relaxed);
        Ok((holds, pending))
    }

    /// `sat` more arrived: counted to what is held until that is asked
    /// again, so that a wallet which has just become full sells no more.
    pub fn holds_more(&self, sat: u64) {
        self.held.fetch_add(sat, Ordering::Relaxed);
    }

    /// Is the wallet full here: did it hold as much as it may, or more,
    /// when that was last asked ([`Mint::balance`])? Nothing is sold at a
    /// mint where it is.
    pub fn full(&self) -> bool {
        let cap = self.cap.load(Ordering::Relaxed);
        cap != 0 && self.held.load(Ordering::Relaxed) >= cap
    }

    /// Whether anything is sold at this mint now: it is reached, and the
    /// wallet may hold more.
    pub fn sells(&self) -> bool {
        self.ready() && !self.full()
    }

    /// A token worth `sat` to whoever redeems it: what its mint takes for
    /// redeeming it is added to it. Its text. `named` is told the name the
    /// wallet keeps it by, before it is made: what is written down of it
    /// then says, after a stop, whether it was. The caller holds
    /// [`Mint::turn`].
    ///
    /// The text is the money: whoever has it has what it is worth.
    pub async fn token_out(&self, sat: u64, named: impl FnOnce(&str) -> Result<(), String>) -> Result<String, String> {
        let options = SendOptions { include_fee: true, ..SendOptions::default() };
        let prepared = within(self.wallet.prepare_send(cdk::Amount::from(sat), options)).await?;
        if let Err(e) = named(&prepared.operation_id().to_string()) {
            let _ = prepared.cancel().await;
            return Err(e);
        }
        Ok(within(prepared.confirm(None)).await?.to_string())
    }

    /// What the wallet has, at this mint, of the token it keeps as `name`.
    pub async fn token_state(&self, name: &str) -> Result<TokenState, String> {
        let Ok(name) = name.parse() else { return Ok(TokenState::Nothing) };
        let saga = self.db.get_saga(&name).await.map_err(said)?.filter(|saga| saga.mint_url == self.url);
        Ok(match saga.map(|saga| (saga.state, saga.data)) {
            Some((WalletSagaState::Send(SendSagaState::TokenCreated), OperationData::Send(data)))
                if data.token.is_some() =>
            {
                TokenState::Out
            }
            Some((WalletSagaState::Send(_), _)) => TokenState::Unfinished,
            _ => TokenState::Nothing,
        })
    }

    /// The text of the token the wallet keeps as `name`, while it keeps it.
    pub async fn token_text(&self, name: &str) -> Result<Option<String>, String> {
        let Ok(name) = name.parse() else { return Ok(None) };
        let saga = self.db.get_saga(&name).await.map_err(said)?.filter(|saga| saga.mint_url == self.url);
        Ok(match saga.map(|saga| saga.data) {
            Some(OperationData::Send(data)) => data.token,
            _ => None,
        })
    }

    /// Tell the wallet that the token it keeps as `name` is out no more
    /// (redeemed, or taken back): it strikes it off by asking the mint.
    /// What the wallet keeps of a token is not gone by, so this may fail.
    pub async fn token_struck(&self, name: &str) {
        if let Ok(name) = name.parse() {
            let _ = within(self.wallet.check_send_status(name)).await;
        }
    }

    /// What it takes to pay `invoice` from the wallet, as the mint quotes
    /// it. Nothing is paid by asking. The caller holds [`Mint::turn`].
    pub async fn payable(&self, invoice: &str) -> Result<Payable, String> {
        let quote = within(self.wallet.melt_quote(bolt11(), invoice, None, None)).await?;
        Ok(Payable {
            quote: quote.id,
            sat: quote.amount.to_u64(),
            fee_most: quote.fee_reserve.to_u64(),
            expires: quote.expiry,
        })
    }

    /// The same for `sat` sent to a Lightning address: its host is asked
    /// for an invoice of that much (and nothing else is asked of it), which
    /// the library checks to be for that much and for that address.
    pub async fn payable_to(&self, address: &str, sat: u64) -> Result<Payable, String> {
        let msat = sat.checked_mul(1000).ok_or("too much")?;
        let quote = within(self.wallet.melt_lightning_address_quote(address, cdk::Amount::from(msat))).await?;
        Ok(Payable {
            quote: quote.id,
            sat: quote.amount.to_u64(),
            fee_most: quote.fee_reserve.to_u64(),
            expires: quote.expiry,
        })
    }

    /// What the wallet's file knows of `quote`, a payment it asked a price
    /// for: what it takes, and the invoice it is for.
    pub async fn quoted(&self, quote: &str) -> Result<Option<(Payable, String)>, String> {
        let known = self.db.get_melt_quote(quote).await.map_err(said)?;
        Ok(known.filter(|known| known.mint_url.as_ref().is_none_or(|url| *url == self.url)).map(|known| {
            let payable = Payable {
                quote: known.id,
                sat: known.amount.to_u64(),
                fee_most: known.fee_reserve.to_u64(),
                expires: known.expiry,
            };
            (payable, known.request)
        }))
    }

    /// Is the wallet in the middle of paying for `quote`?
    async fn paying(&self, quote: &str) -> Result<bool, String> {
        let sagas = self.db.get_incomplete_sagas().await.map_err(said)?;
        Ok(sagas.iter().any(|saga| {
            saga.mint_url == self.url && matches!(&saga.data, OperationData::Melt(data) if data.quote_id == quote)
        }))
    }

    /// Have the mint pay what `quote` is for, with what the wallet holds.
    /// The caller holds [`Mint::turn`].
    ///
    /// What is said is what is known: a payment whose end is not known
    /// after `wait` (the mint took its time, or could not be asked what
    /// became of it) is under way, and [`Mint::payment`] says later what
    /// became of it.
    pub async fn pay(&self, quote: &str, wait: Duration) -> Left {
        let prepared = match within(self.wallet.prepare_melt(quote, HashMap::new())).await {
            Ok(prepared) => prepared,
            Err(e) => return Left::Not(e),
        };
        let unknown = |why: String| async move {
            match self.paying(quote).await {
                Ok(false) => Left::Not(why),
                _ => Left::Pending,
            }
        };
        match tokio::time::timeout(wait, prepared.confirm()).await {
            Ok(Ok(melt)) => match melt.state() {
                MeltQuoteState::Paid => Left::Paid {
                    sat: melt.amount().to_u64(),
                    fee: melt.fee_paid().to_u64(),
                    proof: melt.payment_proof().map(str::to_string),
                },
                MeltQuoteState::Pending | MeltQuoteState::Unknown => Left::Pending,
                MeltQuoteState::Unpaid | MeltQuoteState::Failed => unknown("the mint did not pay it".into()).await,
            },
            Ok(Err(e)) => unknown(e.to_string()).await,
            Err(_) => unknown("the mint did not answer in time".into()).await,
        }
    }

    /// What became of a payment for `quote` that was under way, as the mint
    /// says now: the wallet finishes what it began for it by asking. Its
    /// fee is not said here: the most it may have been is what the quote
    /// said. The caller holds [`Mint::turn`].
    pub async fn payment(&self, quote: &str) -> Result<Left, String> {
        let now = within(self.wallet.check_melt_quote_status(quote)).await?;
        Ok(match now.state {
            MeltQuoteState::Paid => {
                Left::Paid { sat: now.amount.to_u64(), fee: now.fee_reserve.to_u64(), proof: now.payment_proof }
            }
            MeltQuoteState::Pending | MeltQuoteState::Unknown => Left::Pending,
            // Not paid, as far as the mint says: an end only once the
            // wallet has nothing of it left that it may still be asking.
            MeltQuoteState::Unpaid | MeltQuoteState::Failed if self.paying(quote).await? => Left::Pending,
            MeltQuoteState::Unpaid | MeltQuoteState::Failed => Left::Not("the mint did not pay it".into()),
        })
    }

    /// Does the mint give invoices, as far as it has said: for `sat`, or
    /// (for none) at all?
    pub fn gives_invoices(&self, sat: Option<u64>) -> bool {
        let lightning = *self.lightning.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        lightning.is_some_and(|its| sat.is_none_or(|sat| (its.least..=its.most).contains(&sat)))
    }

    /// Ask the mint for an invoice of `sat`, which says it is for `about`
    /// where the mint lets an invoice say anything. The caller holds
    /// [`Mint::turn`].
    ///
    /// The invoice is read here, and is one of exactly `sat`: a buyer is
    /// shown nothing else.
    pub async fn invoice(&self, sat: u64, about: &str) -> Result<Quote, String> {
        let lightning = *self.lightning.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let describes = lightning.is_some_and(|its| its.describes);
        let about = describes.then(|| about.to_string());
        let quote = within(self.wallet.mint_quote(bolt11(), Some(cdk::Amount::from(sat)), about, None)).await?;
        let invoice = cdk::Bolt11Invoice::from_str(&quote.request)
            .map_err(|e| format!("what the mint gave is not an invoice: {e}"))?;
        if invoice.amount_milli_satoshis() != sat.checked_mul(1000) {
            return Err(format!("the mint's invoice is not for {sat} sat"));
        }
        // It ends when the mint says its quote does, or when the invoice
        // itself does: whichever is first.
        let ends = invoice.expires_at().map_or(u64::MAX, |ends| ends.as_secs());
        let expires = if quote.expiry == 0 { ends } else { quote.expiry.min(ends) };
        if expires == u64::MAX {
            return Err("the mint's invoice does not say when it ends".into());
        }
        Ok(Quote {
            id: quote.id,
            request: quote.request,
            expires,
            key: quote.secret_key.as_ref().map(SecretKey::to_secret_hex),
        })
    }

    /// What the mint says of `quote`, which `key` is locked to. The caller
    /// holds [`Mint::turn`].
    ///
    /// A quote the wallet's file does not know (the file is a new one, or
    /// an old one put back) is learnt from the mint again, and its key from
    /// what the order kept: so what was paid can be minted whatever became
    /// of the wallet's file. Where the wallet was interrupted in minting
    /// for the quote, it finishes that here.
    pub async fn quote_state(&self, quote: &str, key: Option<&str>) -> Result<Paid, String> {
        let known = match self.db.get_mint_quote(quote).await.map_err(said)? {
            Some(known) => known,
            None => within(self.wallet.fetch_mint_quote(quote, Some(bolt11()))).await?,
        };
        // Its key, whenever the wallet's file has the quote without it: it
        // is learnt from the mint without one, and may have been left so.
        if known.secret_key.is_none()
            && let Some(key) = key
        {
            let mut with_key = known;
            with_key.secret_key = Some(SecretKey::from_hex(key).map_err(said)?);
            self.db.add_mint_quote(with_key).await.map_err(said)?;
        }
        let now = within(self.wallet.check_mint_quote_status(quote)).await?;
        Ok(match now.state {
            MintQuoteState::Unpaid => Paid::No,
            MintQuoteState::Paid => Paid::Yes,
            MintQuoteState::Issued => Paid::Minted(now.amount_issued.to_u64()),
        })
    }

    /// Have the wallet's file know `quote` without its key: as when it
    /// learnt the quote from the mint and stopped there.
    #[cfg(test)]
    pub async fn forget_key(&self, quote: &str) {
        let mut known = self.db.get_mint_quote(quote).await.unwrap().unwrap();
        known.secret_key = None;
        self.db.add_mint_quote(known).await.unwrap();
    }

    /// Mint what `quote`'s invoice paid for. What arrived, in sat. The
    /// caller holds [`Mint::turn`], and sets the time it may take.
    pub async fn mint_paid(&self, quote: &str) -> Result<u64, cdk::Error> {
        let proofs = self.wallet.mint(quote, SplitTarget::default(), None).await?;
        Ok(proofs.total_amount()?.to_u64())
    }

    /// The tokens that are out here, by their proofs (each token's `Y`s as
    /// JSON): what [`Mint::count_again`] must not take for the wallet's.
    pub fn set_out(&self, ys: Vec<String>) {
        *self.out.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = ys;
    }

    /// A token that was handed out and not redeemed is unspent at the mint,
    /// and counting takes whatever is unspent for the wallet's own. It is
    /// its holder's: its proofs are put back as out, so that nothing is
    /// spent from under them.
    async fn keep_out(&self) -> Result<(), String> {
        let out = self.out.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        for ys in out {
            let ys: Vec<PublicKey> = serde_json::from_str(&ys).map_err(said)?;
            self.db.update_proofs_state(ys, State::PendingSpent).await.map_err(said)?;
        }
        Ok(())
    }

    /// Find again, from the seed, what this wallet has at the mint
    /// (NUT-09). The caller holds [`Mint::turn`].
    pub async fn count_again(&self) -> Result<String, String> {
        let found = tokio::time::timeout(MINT_TIME * 8, self.wallet.restore())
            .await
            .map_err(|_| "the mint did not answer in time".to_string())?
            .map_err(said)?;
        self.keep_out().await?;
        Ok(format!("{} sat found again at the mint, {} spent, {} under way", found.unspent, found.spent, found.pending))
    }
}

/// The wallets, one for each accepted mint.
pub struct Wallets {
    pub mints: Vec<Arc<Mint>>,
    /// Told when a mint is to be reached again now.
    again: Arc<tokio::sync::Notify>,
}

/// The seed in `path`, made if it is not there: 24 words, for this user
/// alone. Whether it was there already. Not made beside a wallet's file
/// that is there (`wallet_there`): what that holds was made with a seed
/// that is gone, and a new one would only be mistaken for it.
fn seed(path: &Path, wallet_there: bool) -> Result<([u8; 64], bool), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let wrong = |e: &dyn std::fmt::Display| format!("{}: {e}", path.display());
    match std::fs::read_to_string(path) {
        Ok(words) => {
            let mnemonic = bip39::Mnemonic::parse_normalized(words.trim()).map_err(|e| {
                wrong(&format!("not a seed of words ({e}); it is not replaced: what it holds would be lost"))
            })?;
            Ok((mnemonic.to_seed_normalized(""), true))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && wallet_there => Err(wrong(
            &"the wallet's seed is missing, and its file (wallet.db) is there: what that holds was made with the \
              seed. Put the seed back; or, for a new wallet, move wallet.db away",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let entropy = random(32).map_err(|e| wrong(&e))?;
            let mnemonic = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| wrong(&e))?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| wrong(&e))?;
            file.write_all(format!("{mnemonic}\n").as_bytes()).and_then(|()| file.sync_all()).map_err(|e| wrong(&e))?;
            Ok((mnemonic.to_seed_normalized(""), false))
        }
        Err(e) => Err(wrong(&e)),
    }
}

impl Wallets {
    /// The wallets for `mints`, kept in `dir`. Nothing is asked of a mint
    /// here: [`Mint::reach`] does that.
    pub async fn open(dir: &Path, mints: &[String]) -> Result<Wallets, String> {
        let file = dir.join("wallet.db");
        let file_was_there = file.exists();
        let (seed, seed_was_there) = seed(&dir.join("seed"), file_was_there)?;
        // A seed with no wallet's file: what the seed has at each mint is
        // counted again there. Written down before the file is made, and
        // until it is done for that mint: the file is there from now on.
        let marker = |name: &str| dir.join(format!("recount-{}", &crate::store::hex(&Sha256::digest(name))[..16]));
        if seed_was_there && !file_was_there {
            for name in mints {
                std::fs::write(marker(name), format!("{name}\n")).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
        }
        let db = Arc::new(WalletSqliteDatabase::new(&file).await.map_err(|e| format!("{}: {e}", file.display()))?);
        let again = Arc::new(tokio::sync::Notify::new());
        let mut opened = Vec::new();
        for name in mints {
            let url = MintUrl::from_str(name).map_err(|e| format!("MINTS: {name}: {e}"))?;
            if opened.iter().any(|other: &Arc<Mint>| other.url == url) {
                return Err(format!("MINTS: {name} twice"));
            }
            let wallet = Wallet::new(name, CurrencyUnit::Sat, db.clone(), seed, None)
                .map_err(|e| format!("MINTS: {name}: {e}"))?;
            // What the mint said of its invoices when it was last reached,
            // as the wallet's file remembers it: so that what the exit says
            // it sells for does not change with every start.
            let remembered = db.get_mint(url.clone()).await.ok().flatten();
            let lightning = remembered.as_ref().and_then(Lightning::of);
            opened.push(Arc::new(Mint {
                name: name.clone(),
                url,
                wallet,
                db: db.clone(),
                seed,
                ready: AtomicBool::new(false),
                count_first: AtomicBool::new(marker(name).exists()),
                marker: marker(name),
                look_ahead: AtomicBool::new(true),
                again: again.clone(),
                lightning: std::sync::Mutex::new(lightning),
                held: AtomicU64::new(0),
                cap: AtomicU64::new(0),
                out: std::sync::Mutex::new(Vec::new()),
                turn: tokio::sync::Mutex::new(()),
            }));
        }
        Ok(Wallets { mints: opened, again })
    }

    /// Whether a token is taken at any mint now.
    pub fn ready(&self) -> bool {
        self.mints.iter().any(|mint| mint.sells())
    }

    /// Whether any mint at which something is sold now gives invoices.
    pub fn invoicing(&self) -> bool {
        self.mints.iter().any(|mint| mint.sells() && mint.gives_invoices(None))
    }

    /// The most the wallet may hold at a mint, in sat (0: any amount): at
    /// that, nothing is sold there.
    pub fn set_cap(&self, sat: u64) {
        for mint in &self.mints {
            mint.cap.store(sat, Ordering::Relaxed);
        }
    }

    /// The wallet at the mint `token` names, which must be an accepted
    /// one. Whether it is reached is another matter ([`Mint::ready`]).
    pub fn mint_of(&self, token: &Token) -> Result<&Arc<Mint>, Refusal> {
        let named = token.mint_url().map_err(|_| Refusal::Token("A token of one mint is taken".into()))?;
        self.mints.iter().find(|mint| mint.url == named).ok_or_else(|| Refusal::WrongMint(named.to_string()))
    }

    pub fn named(&self, name: &str) -> Option<&Arc<Mint>> {
        self.mints.iter().find(|mint| mint.name == name)
    }

    /// Reach every mint, and again: often while one is away, seldom once
    /// all are there (their keys change seldom).
    pub async fn keep(self: Arc<Self>) {
        loop {
            let mut all = true;
            for mint in &self.mints {
                all &= mint.reach().await.is_ok();
            }
            tokio::select! {
                () = tokio::time::sleep(if all { Duration::from_secs(900) } else { Duration::from_secs(30) }) => {}
                () = self.again.notified() => {}
            }
        }
    }
}
