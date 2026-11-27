//! The paid-exit admission rule, as pure data and pure functions.
//!
//! A Go implementation of the same rule lives in tollgate's `src/fips_exit`
//! (`Challenge.Canonical`, `Claim.Verify`, `Derive`, `VerdictFor`). The exit
//! daemon must be able to decide admission on hosts where the Go module is not
//! present, so the rule exists a second time here. Neither side is allowed to
//! be the authority for the other: both are held to one file,
//! `contracts/fips-exit-admission-vectors.json`, which is generated from the Go
//! implementation and pinned by the tests in `tests/admission_vectors.rs`.
//!
//! Nothing here touches a socket, a file, a process or a firewall rule, and
//! nothing here is wired into `main.rs` yet. Signalling the daemon, persisting
//! grants and sampling the transport's observed source address are the
//! caller's business; this module only answers "may this claim be admitted" and
//! "what should happen to this grant now" for the inputs it is handed.
//!
//! Cryptography is BIP340 schnorr over secp256k1, verifying
//! `SHA-256(Challenge::canonical())` under the buyer's x-only key. The verifier,
//! `k256`, is pure Rust: this crate must keep cross-compiling to musl targets
//! with no C toolchain assumptions beyond libc, so a verifier that compiles
//! libsecp256k1 through `cc` is not an option here. `k256` implements the same
//! BIP340 rules, and the pinned vectors are what prove the two agree.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The domain-separation tag, mixed in before everything else. It makes an
/// admission signature useless as a Nostr event signature and vice versa.
///
/// The trailing NUL is part of the tag; `canonical()` below is the authority on
/// the exact bytes, and the pinned vectors pin them.
pub const CANONICAL_PREFIX: &[u8] = b"tollgate-fips-exit/claim\0";

/// Serialization version, mixed in right after the prefix so a future layout
/// can never be mistaken for this one.
pub const CANONICAL_VERSION: u8 = 0x01;

/// Length of a hex-encoded 64-byte BIP340 signature.
pub const SIG_HEX_LEN: usize = 128;

/// How far in the future `issued_at` may sit before a claim is refused as not
/// yet valid.
pub const CLOCK_SKEW_ALLOWANCE_NS: i64 = 60_000_000_000;

/// A decoded 32-byte x-only public key: a peer's identity.
pub type PeerKey = [u8; 32];

/// The all-zero key, which is not a valid x-only point and therefore not an
/// identity.
pub const ZERO_KEY: PeerKey = [0u8; 32];

/// What a grant is bounded by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BillingMode {
    /// Bounded by the wall-clock window only.
    Time,
    /// Bounded by the wall-clock window and a caller-supplied byte counter.
    Bytes,
}

impl BillingMode {
    /// The wire spelling shared with the Go side and the clients file.
    pub const fn as_str(self) -> &'static str {
        match self {
            BillingMode::Time => "time",
            BillingMode::Bytes => "bytes",
        }
    }

    /// Parses the wire spelling. Unknown spellings are `None`, never a default:
    /// guessing a mode would guess what a grant is bounded by.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "time" => Some(BillingMode::Time),
            "bytes" => Some(BillingMode::Bytes),
            _ => None,
        }
    }
}

/// The exit's offer: which exit key is being bought, a fresh nonce, the
/// validity window, the price and the billing mode.
///
/// Times are UNIX nanoseconds because that is the width the signed bytes carry;
/// converting from a calendar spelling belongs to the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Identifies the exit that issued the offer.
    pub exit_key: PeerKey,
    /// Single-use value that makes a claim non-replayable.
    pub nonce: [u8; 16],
    /// When the exit created the offer.
    pub issued_at_ns: i64,
    /// The instant the offer stops being acceptable.
    pub expires_at_ns: i64,
    /// The quoted price, signed so buyer and exit cannot disagree later.
    pub price_sats: u64,
    /// The billing mode the price buys.
    pub mode: BillingMode,
}

/// Returns the exact bytes a buyer signs.
///
/// Layout, big-endian throughout, no padding and no optional fields:
///
/// ```text
/// offset  size  field
/// 0       25    domain prefix "tollgate-fips-exit/claim\0"
/// 25      1     format version, 0x01
/// 26      32    exit key
/// 58      16    nonce
/// 74      8     issued_at as int64 UNIX nanoseconds, two's complement
/// 82      8     expires_at as int64 UNIX nanoseconds, two's complement
/// 90      8     price_sats as uint64
/// 98      2     length of the mode string as uint16
/// 100     N     mode string bytes
/// ```
///
/// Every variable-length field is length-prefixed and every fixed-width field
/// is exactly its width, so two different challenges cannot produce the same
/// bytes: shifting a byte between the price and the mode length, or extending
/// a mode string, changes the framing instead of sliding into the neighbour.
pub fn canonical(challenge: &Challenge) -> Vec<u8> {
    let mode = challenge.mode.as_str().as_bytes();
    let mut out =
        Vec::with_capacity(CANONICAL_PREFIX.len() + 1 + 32 + 16 + 8 + 8 + 8 + 2 + mode.len());
    out.extend_from_slice(CANONICAL_PREFIX);
    out.push(CANONICAL_VERSION);
    out.extend_from_slice(&challenge.exit_key);
    out.extend_from_slice(&challenge.nonce);
    out.extend_from_slice(&(challenge.issued_at_ns as u64).to_be_bytes());
    out.extend_from_slice(&(challenge.expires_at_ns as u64).to_be_bytes());
    out.extend_from_slice(&challenge.price_sats.to_be_bytes());
    // `mode.len()` is a compile-time constant of at most 5 here, so the
    // truncating cast to u16 cannot lose anything.
    out.extend_from_slice(&(mode.len() as u16).to_be_bytes());
    out.extend_from_slice(mode);
    out
}

/// The 32-byte BIP340 message a buyer signs: SHA-256 over the canonical bytes.
///
/// It is separate from [`canonical`] so the schnorr call always gets the fixed
/// width the curve requires, and so the hash is pinned in one place.
pub fn sign_digest(canonical: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical).into()
}

/// The addresses a peer key maps onto, derived exactly as fips2go does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Derived {
    /// The address the exit sees as a packet's source, and the one the clients
    /// file lists. `fd`-prefixed, collision-free in practice.
    pub outer: Ipv6Addr,
    /// The peer's address inside the tunnel. Only 22 identity bits, so it can
    /// collide: it is not an identity and not proof of anything.
    pub inner: Ipv4Addr,
}

/// Derives the FIPS outer IPv6 address and the exit-tunnel inner IPv4 address
/// for a 32-byte x-only key.
///
/// Curve membership is not checked: the transport's peer handshake owns that,
/// and the derivation is a plain hash so it needs no curve.
pub fn derive(key: &PeerKey) -> Derived {
    let digest = Sha256::digest(key);
    let mut outer = [0u8; 16];
    outer[0] = 0xfd;
    outer[1..].copy_from_slice(&digest[..15]);
    Derived {
        outer: Ipv6Addr::from(outer),
        inner: Ipv4Addr::new(100, 0x40 | (digest[0] & 0x3f), digest[1], digest[2]),
    }
}

/// Why a claim was refused.
///
/// The variants are distinct on purpose: a caller can tell "you did not prove
/// the key" from "you proved the key but not this tunnel" from "the terms aged
/// out". [`VerificationError::CHECK_ORDER`] records the order [`verify`] tries
/// them in, which decides which failure a caller learns about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The claim cannot be parsed into a checkable shape: zero buyer key, zero
    /// challenge exit key, or a signature that is not 128 characters of
    /// lower-case hex.
    Malformed,
    /// A well-formed claim whose schnorr signature does not verify under the
    /// buyer key: the stolen-npub case.
    Signature,
    /// A validly signed claim whose buyer key does not derive to the source
    /// address the transport observed for this tunnel.
    Unbound,
    /// `now` is not before the challenge expiry. Expiry is inclusive.
    Expired,
    /// An issue time more than the clock-skew allowance in the future.
    NotYetValid,
}

impl VerificationError {
    /// The check order [`verify`] applies, first failure wins. This is the
    /// order the contract states, and it carries meaning: the signature check
    /// precedes the binding check so that a claim signed by the wrong key is
    /// reported as impersonation even when the tunnel is also wrong; binding
    /// precedes expiry so that an expired claim from a foreign tunnel is never
    /// mistaken for a lapsed purchase.
    pub const CHECK_ORDER: [VerificationError; 5] = [
        VerificationError::Malformed,
        VerificationError::Signature,
        VerificationError::Unbound,
        VerificationError::Expired,
        VerificationError::NotYetValid,
    ];

    /// The sentinel spelling the contract file uses for this failure, and the
    /// only string a caller should print or log.
    pub const fn sentinel(self) -> &'static str {
        match self {
            VerificationError::Malformed => "malformed",
            VerificationError::Signature => "signature",
            VerificationError::Unbound => "unbound",
            VerificationError::Expired => "expired",
            VerificationError::NotYetValid => "not-yet-valid",
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.sentinel())
    }
}

impl std::error::Error for VerificationError {}

/// A buyer's answer to a challenge: the terms, the buyer key, and a BIP340
/// signature by that key over [`canonical`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim<'a> {
    /// The terms being accepted.
    pub challenge: Challenge,
    /// The key the signature must verify under, and the key whose derivation
    /// must match the observed source address.
    pub buyer: PeerKey,
    /// 128 characters of lower-case hex.
    pub sig_hex: &'a str,
}

/// Checks a claim against `now` and the source address the transport observed
/// for this tunnel. `Ok(())` means the claim is well formed, signed by the
/// buyer, bound to that source and inside its window.
///
/// Checks run in [`VerificationError::CHECK_ORDER`] and stop at the first failure.
/// An unparseable, unspecified or absent observed source is refused as
/// [`VerificationError::Unbound`]: there is no address to compare against, and
/// falling back to the zero address would turn a transport bug into free
/// access.
pub fn verify(
    claim: &Claim<'_>,
    now_ns: i64,
    observed_source: Option<Ipv6Addr>,
) -> Result<(), VerificationError> {
    // a. shape.
    if claim.buyer == ZERO_KEY {
        return Err(VerificationError::Malformed);
    }
    if claim.challenge.exit_key == ZERO_KEY {
        return Err(VerificationError::Malformed);
    }
    let sig = decode_signature_hex(claim.sig_hex).ok_or(VerificationError::Malformed)?;

    // b. proof of key possession. A malformed key or signature is simply not a
    // valid signature, so it lands here rather than in `Malformed`, matching
    // the Go side.
    if !verify_schnorr(
        &claim.buyer,
        &sign_digest(&canonical(&claim.challenge)),
        &sig,
    ) {
        return Err(VerificationError::Signature);
    }

    // c. binding to the tunnel the transport actually saw.
    let observed = observed_source
        .filter(|addr| !addr.is_unspecified())
        .ok_or(VerificationError::Unbound)?;
    if derive(&claim.buyer).outer != observed {
        return Err(VerificationError::Unbound);
    }

    // d. expiry, inclusive: at exactly `expires_at_ns` the claim is gone.
    if now_ns >= claim.challenge.expires_at_ns {
        return Err(VerificationError::Expired);
    }

    // e. not yet valid.
    if claim.challenge.issued_at_ns > now_ns.saturating_add(CLOCK_SKEW_ALLOWANCE_NS) {
        return Err(VerificationError::NotYetValid);
    }
    Ok(())
}

/// Decodes the hex spelling of a BIP340 signature, refusing anything that is
/// not exactly 128 lower-case hex characters.
fn decode_signature_hex(sig_hex: &str) -> Option<[u8; 64]> {
    let bytes = sig_hex.as_bytes();
    if bytes.len() != SIG_HEX_LEN {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = lower_hex_digit(pair[0])?;
        let lo = lower_hex_digit(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn lower_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Reports whether `sig` is a valid BIP340 signature over `digest` under the
/// x-only `key`. Anything unparseable reports `false`, exactly as the Go side
/// does: the caller could not tell that case apart from a bad signature anyway.
fn verify_schnorr(key: &PeerKey, digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig.as_slice()) else {
        return false;
    };
    verifying_key.verify_raw(digest, &signature).is_ok()
}

/// One durable grant, as far as a verdict needs to look at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The instant the grant stops being valid. Expiry is inclusive.
    pub expires_at_ns: i64,
    /// What the grant is bounded by.
    pub mode: BillingMode,
    /// Bytes the grant authorises. Ignored entirely under [`BillingMode::Time`].
    pub byte_budget: u64,
    /// Bytes already recorded for this peer.
    pub bytes_used: u64,
}

/// The decision for one peer at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The grant is live; the peer stays admitted.
    Keep,
    /// The wall-clock window has closed.
    RevokeExpired,
    /// The byte budget has been reached.
    RevokeExhausted,
    /// No live grant is held; admission requires a new purchase.
    Renew,
}

impl Verdict {
    /// The spelling the contract file and out-of-band decisions use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Keep => "keep",
            Verdict::RevokeExpired => "revoke-expired",
            Verdict::RevokeExhausted => "revoke-exhausted",
            Verdict::Renew => "renew",
        }
    }
}

/// Decides one peer. `grant` is the record held for it, if any; `observed_bytes`
/// is the caller's counter for this peer, used only under [`BillingMode::Bytes`]
/// and only to raise the recorded usage (a lower report never rewinds it). Pass
/// the recorded value to ask about the grant as it stands.
///
/// Boundaries are inclusive in the money direction: at exactly `expires_at_ns`
/// the grant is gone, and the budget is exhausted AT the budget value — 5000 of
/// 5000 revokes, 4999 of 5000 keeps.
pub fn verdict(grant: Option<&Grant>, now_ns: i64, observed_bytes: u64) -> Verdict {
    let Some(grant) = grant else {
        return Verdict::Renew;
    };
    if now_ns >= grant.expires_at_ns {
        return Verdict::RevokeExpired;
    }
    if grant.mode == BillingMode::Bytes && grant.bytes_used.max(observed_bytes) >= grant.byte_budget
    {
        return Verdict::RevokeExhausted;
    }
    Verdict::Keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_challenge() -> Challenge {
        Challenge {
            exit_key: [0x11; 32],
            nonce: [0x22; 16],
            issued_at_ns: 1_800_000_000_000_000_000,
            expires_at_ns: 1_800_000_060_000_000_000,
            price_sats: 2,
            mode: BillingMode::Bytes,
        }
    }

    #[test]
    fn canonical_is_framed_exactly_once() {
        let bytes = canonical(&sample_challenge());
        assert_eq!(&bytes[..CANONICAL_PREFIX.len()], CANONICAL_PREFIX);
        assert_eq!(bytes[CANONICAL_PREFIX.len()], CANONICAL_VERSION);
        assert_eq!(
            bytes.len(),
            CANONICAL_PREFIX.len() + 1 + 32 + 16 + 8 + 8 + 8 + 2 + 5
        );
        // The mode length is a big-endian u16 immediately before the mode.
        assert_eq!(&bytes[bytes.len() - 7..bytes.len() - 5], &[0x00, 0x05]);
        assert_eq!(&bytes[bytes.len() - 5..], b"bytes");
    }

    #[test]
    fn mode_is_inside_the_signed_bytes() {
        let mut other = sample_challenge();
        other.mode = BillingMode::Time;
        assert_ne!(
            sign_digest(&canonical(&sample_challenge())),
            sign_digest(&canonical(&other))
        );
    }

    #[test]
    fn signature_hex_must_be_lower_case_and_fixed_width() {
        assert!(decode_signature_hex(&"d".repeat(128)).is_some());
        assert!(decode_signature_hex(&"D".repeat(128)).is_none());
        assert!(decode_signature_hex(&"d".repeat(127)).is_none());
        assert!(decode_signature_hex(&"g".repeat(128)).is_none());
    }

    #[test]
    fn no_grant_renews() {
        assert_eq!(verdict(None, 0, 0), Verdict::Renew);
    }

    #[test]
    fn time_mode_ignores_a_byte_counter() {
        let grant = Grant {
            expires_at_ns: 100,
            mode: BillingMode::Time,
            byte_budget: 0,
            bytes_used: 0,
        };
        assert_eq!(verdict(Some(&grant), 0, u64::MAX), Verdict::Keep);
    }

    #[test]
    fn a_lower_observation_never_rewinds_usage() {
        let grant = Grant {
            expires_at_ns: 100,
            mode: BillingMode::Bytes,
            byte_budget: 5000,
            bytes_used: 5000,
        };
        assert_eq!(verdict(Some(&grant), 0, 0), Verdict::RevokeExhausted);
    }

    #[test]
    fn check_order_is_the_contract_order() {
        assert_eq!(
            VerificationError::CHECK_ORDER.map(VerificationError::sentinel),
            [
                "malformed",
                "signature",
                "unbound",
                "expired",
                "not-yet-valid"
            ]
        );
    }

    #[test]
    fn shape_is_checked_before_the_signature() {
        let claim = Claim {
            challenge: sample_challenge(),
            buyer: ZERO_KEY,
            sig_hex: "d".repeat(128).leak(),
        };
        assert_eq!(verify(&claim, 0, None), Err(VerificationError::Malformed));
    }
}
