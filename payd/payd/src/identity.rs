//! Who a fips node is: its npub, and the fips address that follows from it.

use std::net::Ipv6Addr;

use sha2::{Digest, Sha256};

const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut check = 1u32;
    for value in values {
        let top = check >> 25;
        check = (check & 0x1ff_ffff) << 5 ^ u32::from(*value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                check ^= generator;
            }
        }
    }
    check
}

/// The 32-byte key in an `npub1…`, if it is one, checksum and all.
pub fn npub_key(npub: &str) -> Option<[u8; 32]> {
    let data = npub.strip_prefix("npub1")?;
    let values: Vec<u8> =
        data.bytes().map(|c| BECH32.iter().position(|b| *b == c).map(|at| at as u8)).collect::<Option<_>>()?;
    let mut expanded: Vec<u8> = b"npub".iter().map(|c| c >> 5).collect();
    expanded.push(0);
    expanded.extend(b"npub".iter().map(|c| c & 31));
    expanded.extend(&values);
    if values.len() < 6 || bech32_polymod(&expanded) != 1 {
        return None;
    }
    let (mut acc, mut bits, mut key) = (0u32, 0u32, Vec::new());
    for value in &values[..values.len() - 6] {
        acc = (acc << 5 | u32::from(*value)) & 0xfff;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push((acc >> bits) as u8);
        }
    }
    key.try_into().ok()
}

/// The fips address of a key: `fd` and the first 15 bytes of its SHA-256,
/// as fips derives it.
pub fn key_address(key: &[u8; 32]) -> Ipv6Addr {
    let digest = Sha256::digest(key);
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&digest[..15]);
    Ipv6Addr::from(octets)
}

/// A client as a person names it: its npub, or its fips address. Its
/// address, and the npub if that is what it was named by.
pub fn client(text: &str) -> Option<(Ipv6Addr, Option<String>)> {
    let lower = text.trim().to_ascii_lowercase();
    if lower.starts_with("npub1") {
        return npub_key(&lower).map(|key| (key_address(&key), Some(lower)));
    }
    lower.parse::<Ipv6Addr>().ok().filter(|address| address.octets()[0] == 0xfd).map(|address| (address, None))
}
