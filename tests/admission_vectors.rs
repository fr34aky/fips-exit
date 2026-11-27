//! Reproduces every pinned admission vector from the contract file.
//!
//! The rule exists twice — once in Go, once in [`fips_exitd::admission`] — so
//! neither side may hold its own expected values. This test reads the contract
//! file and compares against it; no expected value is spelled in this file.
//!
//! The file is taken from `FIPS_EXIT_CONTRACT` when that is set (so a change to
//! PRTA's contract can be checked without vendoring), and otherwise from
//! `test/vectors/fips-exit-admission-vectors.json`, a pinned mirror.
//!
//! Every assertion names the vector and, where one exists, the field it was
//! checking, so a mismatch says which value drifted rather than just "left !=
//! right".

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use fips_exitd::admission::{
    BillingMode, CANONICAL_PREFIX, CANONICAL_VERSION, Challenge, Claim, Grant, canonical, derive,
    sign_digest, verdict, verify,
};

/// Where the contract file lives for this run.
fn contract_path() -> PathBuf {
    match std::env::var_os("FIPS_EXIT_CONTRACT") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test")
            .join("vectors")
            .join("fips-exit-admission-vectors.json"),
    }
}

fn contract() -> serde_json::Value {
    let path = contract_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read the admission contract at {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("parse the admission contract at {}: {err}", path.display()))
}

fn unhex(what: &str, s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|err| panic!("{what} is not hex: {err}"))
}

fn key_of(vector: &str, field: &str, s: &str) -> [u8; 32] {
    let bytes = unhex(&format!("vector {vector}, field {field}"), s);
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "vector {vector}, field {field}: expected 32 bytes, got {}",
            bytes.len()
        )
    })
}

fn nonce_of(vector: &str, field: &str, s: &str) -> [u8; 16] {
    let bytes = unhex(&format!("vector {vector}, field {field}"), s);
    bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "vector {vector}, field {field}: expected 16 bytes, got {}",
            bytes.len()
        )
    })
}

fn u64_field(vector: &str, field: &str, value: &serde_json::Value) -> u64 {
    value
        .as_u64()
        .unwrap_or_else(|| panic!("vector {vector}, field {field}: not a u64"))
}

/// Parses the contract's `YYYY-MM-DDTHH:MM:SSZ` spelling into UNIX nanoseconds,
/// without a date library: the contract only ever writes this exact shape.
fn unix_nanos(what: &str, s: &str) -> i64 {
    let b = s.as_bytes();
    assert!(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z',
        "{what}: expected YYYY-MM-DDTHH:MM:SSZ, got {s:?}"
    );
    let num = |from: usize, to: usize| -> i64 {
        s[from..to]
            .parse::<i64>()
            .unwrap_or_else(|err| panic!("{what}: field {from}..{to} is not a number: {err}"))
    };
    let (year, month, day) = (num(0, 4), num(5, 7), num(8, 10));
    let (hour, minute, second) = (num(11, 13), num(14, 16), num(17, 19));

    // Days from the civil epoch, by Howard Hinnant's days_from_civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    ((days * 86_400) + hour * 3_600 + minute * 60 + second) * 1_000_000_000
}

#[test]
fn canonical_vectors_reproduce() {
    let contract = contract();
    let vectors = contract["canonical"]
        .as_array()
        .expect("the contract's \"canonical\" group is an array");
    assert_eq!(
        vectors.len(),
        3,
        "the contract pins three canonical encodings"
    );

    for vector in vectors {
        let name = vector["name"]
            .as_str()
            .expect("canonical vector has a name");
        let mode_name = vector["mode"]
            .as_str()
            .expect("canonical vector has a mode");

        let challenge = Challenge {
            exit_key: key_of(
                name,
                "exit_key_hex",
                vector["exit_key_hex"].as_str().unwrap(),
            ),
            nonce: nonce_of(name, "nonce_hex", vector["nonce_hex"].as_str().unwrap()),
            issued_at_ns: unix_nanos(
                &format!("vector {name}, field issued_at"),
                vector["issued_at"].as_str().unwrap(),
            ),
            expires_at_ns: unix_nanos(
                &format!("vector {name}, field expires_at"),
                vector["expires_at"].as_str().unwrap(),
            ),
            price_sats: u64_field(name, "price_sats", &vector["price_sats"]),
            mode: BillingMode::parse(mode_name)
                .unwrap_or_else(|| panic!("vector {name}, field mode: unknown mode {mode_name:?}")),
        };

        let want_bytes = unhex(
            &format!("vector {name}, field canonical_hex"),
            vector["canonical_hex"].as_str().unwrap(),
        );
        let got_bytes = canonical(&challenge);
        assert_eq!(
            hex::encode(&got_bytes),
            hex::encode(&want_bytes),
            "vector {name}, field canonical_hex"
        );

        let want_digest = unhex(
            &format!("vector {name}, field sig_digest_hex"),
            vector["sig_digest_hex"].as_str().unwrap(),
        );
        assert_eq!(
            hex::encode(sign_digest(&got_bytes)),
            hex::encode(&want_digest),
            "vector {name}, field sig_digest_hex"
        );
    }
}

#[test]
fn derive_vectors_reproduce() {
    let contract = contract();
    let vectors = contract["derive"]
        .as_array()
        .expect("the contract's \"derive\" group is an array");
    assert_eq!(vectors.len(), 3, "the contract pins three derivations");

    for vector in vectors {
        let key_hex = vector["key_hex"].as_str().unwrap();
        let key = key_of("derive", "key_hex", key_hex);
        let derived = derive(&key);

        let want_outer: Ipv6Addr = vector["outer"]
            .as_str()
            .unwrap()
            .parse()
            .expect("vector outer is an IPv6 address");
        assert_eq!(
            derived.outer, want_outer,
            "derive vector key {key_hex}, field outer"
        );

        let want_inner: Ipv4Addr = vector["inner"]
            .as_str()
            .unwrap()
            .parse()
            .expect("vector inner is an IPv4 address");
        assert_eq!(
            derived.inner, want_inner,
            "derive vector key {key_hex}, field inner"
        );
    }
}

/// Rebuilds a [`Challenge`] from canonical bytes, checking the framing as it
/// goes so a change to the layout fails here rather than silently inside
/// `canonical()`, which would otherwise be checking itself.
fn challenge_from_canonical(name: &str, bytes: &[u8]) -> Challenge {
    assert_eq!(
        &bytes[..CANONICAL_PREFIX.len()],
        CANONICAL_PREFIX,
        "vector {name}, field canonical_hex: domain prefix"
    );
    let mut at = CANONICAL_PREFIX.len();
    assert_eq!(
        bytes[at], CANONICAL_VERSION,
        "vector {name}, field canonical_hex: version byte"
    );
    at += 1;
    let exit_key: [u8; 32] = bytes[at..at + 32].try_into().unwrap();
    at += 32;
    let nonce: [u8; 16] = bytes[at..at + 16].try_into().unwrap();
    at += 16;
    let be64 = |at: usize| i64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
    let issued_at_ns = be64(at);
    at += 8;
    let expires_at_ns = be64(at);
    at += 8;
    let price_sats = u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
    at += 8;
    let mode_len = u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap()) as usize;
    at += 2;
    let mode = std::str::from_utf8(&bytes[at..at + mode_len]).unwrap();
    at += mode_len;
    assert_eq!(
        at,
        bytes.len(),
        "vector {name}, field canonical_hex: trailing bytes"
    );
    Challenge {
        exit_key,
        nonce,
        issued_at_ns,
        expires_at_ns,
        price_sats,
        mode: BillingMode::parse(mode)
            .unwrap_or_else(|| panic!("vector {name}, field canonical_hex: unknown mode {mode:?}")),
    }
}

#[test]
fn verify_vectors_reproduce() {
    let contract = contract();
    let vectors = contract["verify"]
        .as_array()
        .expect("the contract's \"verify\" group is an array");
    assert_eq!(vectors.len(), 4, "the contract pins four verify outcomes");

    for vector in vectors {
        let name = vector["name"].as_str().expect("verify vector has a name");
        let canonical_bytes = unhex(
            &format!("vector {name}, field canonical_hex"),
            vector["canonical_hex"].as_str().unwrap(),
        );
        let challenge = challenge_from_canonical(name, &canonical_bytes);
        // The verify vectors pin the terms but not a "now", so the claim is
        // judged at the instant its own terms were issued: strictly inside the
        // window, so only the check the vector names can fail.
        let now_ns = challenge.issued_at_ns;
        let claim = Claim {
            challenge,
            buyer: key_of(name, "buyer_hex", vector["buyer_hex"].as_str().unwrap()),
            sig_hex: vector["sig_hex"].as_str().unwrap(),
        };
        let observed_text = vector["observed_source"].as_str().unwrap();
        let observed: Ipv6Addr = observed_text
            .parse()
            .unwrap_or_else(|err| panic!("vector {name}, field observed_source: {err}"));

        let want = vector["expect_error"].as_str().unwrap();
        let got = match verify(&claim, now_ns, Some(observed)) {
            Ok(()) => String::new(),
            Err(err) => err.sentinel().to_string(),
        };
        assert_eq!(got, want, "vector {name}, field expect_error");
    }
}

#[test]
fn verdict_vectors_reproduce() {
    let contract = contract();
    let vectors = contract["verdicts"]
        .as_array()
        .expect("the contract's \"verdicts\" group is an array");
    assert_eq!(vectors.len(), 5, "the contract pins five verdicts");

    for vector in vectors {
        let name = vector["name"].as_str().expect("verdict vector has a name");
        let mode_name = vector["mode"].as_str().expect("verdict vector has a mode");
        let mode = BillingMode::parse(mode_name)
            .unwrap_or_else(|| panic!("vector {name}, field mode: unknown mode {mode_name:?}"));
        let grant = Grant {
            expires_at_ns: unix_nanos(
                &format!("vector {name}, field expires_at"),
                vector["expires_at"].as_str().unwrap(),
            ),
            mode,
            byte_budget: u64_field(name, "byte_budget", &vector["byte_budget"]),
            bytes_used: u64_field(name, "bytes_used", &vector["bytes_used"]),
        };
        let now_ns = unix_nanos(
            &format!("vector {name}, field now"),
            vector["now"].as_str().unwrap(),
        );

        // The counter a caller would report is the recorded one: this asks what
        // happens to the grant as it stands.
        let got = verdict(Some(&grant), now_ns, grant.bytes_used);
        assert_eq!(
            got.as_str(),
            vector["verdict"].as_str().unwrap(),
            "vector {name}, field verdict"
        );
    }
}

#[test]
fn every_contract_sentinel_has_a_variant() {
    // The variants must map 1:1 onto the contract's sentinels. Every sentinel
    // the contract names must be one this crate can produce, and every variant
    // must have a distinct spelling.
    let contract = contract();
    let sentinels: Vec<&str> = contract["verify"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["expect_error"].as_str().unwrap())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        sentinels,
        ["signature", "unbound", "signature"],
        "the contract's non-empty verify sentinels"
    );

    let mut known: Vec<&str> = fips_exitd::admission::VerificationError::CHECK_ORDER
        .iter()
        .map(|e| e.sentinel())
        .collect();
    for sentinel in sentinels {
        assert!(
            known.contains(&sentinel),
            "sentinel {sentinel:?} has no VerificationError variant"
        );
    }
    known.sort_unstable();
    known.dedup();
    assert_eq!(
        known.len(),
        fips_exitd::admission::VerificationError::CHECK_ORDER.len(),
        "two variants share a sentinel spelling"
    );
}
