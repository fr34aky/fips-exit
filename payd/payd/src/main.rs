//! fips-exit-payd: the payment service of a paid fips exit.
//!
//! It runs beside the exit as a user of its own, with no privilege, and
//! answers on the exit's fips address only. A caller there is known by the
//! address its connection comes from, which fips authenticates: no account
//! and no login.
//!
//! So far it says what the exit costs (`GET /v1/terms`, and a page for a
//! browser at `/`) and takes no payment. What is to come is in
//! docs/paid-exit.md.

mod config;
mod http;
mod terms;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

use crate::config::Config;
use crate::terms::Exit;

struct Args {
    config: String,
    public_key: String,
    /// Where to listen instead of the mesh address: for tests.
    listen: Option<SocketAddr>,
}

fn parse_args() -> Result<Args, String> {
    let mut args =
        Args { config: "/etc/fips-exit/config".into(), public_key: "/etc/fips/fips.pub".into(), listen: None };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let value = argv.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--config" => args.config = value,
            "--pub" => args.public_key = value,
            "--listen" => args.listen = Some(value.parse().map_err(|_| format!("--listen {value}: [address]:port"))?),
            other => {
                return Err(format!(
                    "unknown argument {other}\nusage: fips-exit-payd [--config FILE] [--pub FILE] [--listen [ADDRESS]:PORT]"
                ));
            }
        }
    }
    Ok(args)
}

/// The fips addresses of `interface`, from the kernel's list of IPv6
/// addresses: no privilege needed, nothing to link.
fn mesh_addresses(interface: &str, list: &str) -> Vec<Ipv6Addr> {
    let mut found = Vec::new();
    'lines: for line in list.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [hex, _, _, _, _, name] = fields[..] else { continue };
        if name != interface || hex.len() != 32 {
            continue;
        }
        let mut octets = [0u8; 16];
        for (at, octet) in octets.iter_mut().enumerate() {
            let Some(Ok(value)) = hex.get(2 * at..2 * at + 2).map(|pair| u8::from_str_radix(pair, 16)) else {
                continue 'lines;
            };
            *octet = value;
        }
        if octets[0] == 0xfd {
            found.push(Ipv6Addr::from(octets));
        }
    }
    found
}

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
fn npub_key(npub: &str) -> Option<[u8; 32]> {
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
fn key_address(key: &[u8; 32]) -> Ipv6Addr {
    let digest = Sha256::digest(key);
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..].copy_from_slice(&digest[..15]);
    Ipv6Addr::from(octets)
}

/// The node's npub, from its public key file: shown, and a name this
/// service answers to (`<npub>.fips`). None if it cannot be read or is not
/// an npub.
fn npub(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let npub = text.trim().to_ascii_lowercase();
    npub_key(&npub).map(|_| npub)
}

/// Where to listen, of the fips addresses `interface` has, and whether the
/// node's npub is the one there. The address of the npub, when the
/// interface has it; otherwise the interface's one fips address, and the
/// npub not shown, since it would name another node. An interface with
/// several and none of them the npub's is not guessed at: the script opens
/// the firewall for one of them, which may not be the one chosen here.
fn choose(addresses: &[Ipv6Addr], npub: Option<String>) -> Result<(Ipv6Addr, Option<String>), String> {
    let of_npub = npub.as_deref().and_then(npub_key).map(|key| key_address(&key));
    if let Some(address) = of_npub.filter(|address| addresses.contains(address)) {
        return Ok((address, npub));
    }
    match addresses {
        [] => Err("no fips address".into()),
        [only] => Ok((*only, None)),
        _ => Err(format!(
            "{} fips addresses, and none of them is the node's own ({}): which one to answer on?",
            addresses.len(),
            npub.as_deref().unwrap_or("its public key file cannot be read")
        )),
    }
}

async fn run() -> Result<(), String> {
    let args = parse_args()?;
    let text = std::fs::read_to_string(&args.config).map_err(|e| format!("{}: {e}", args.config))?;
    let Some(config) = Config::from_settings(&config::settings(&text)).map_err(|e| format!("{}: {e}", args.config))?
    else {
        // Not an error: the service may be enabled on an exit that sells
        // nothing for now.
        eprintln!("fips-exit-payd: ACCESS is not paid in {}: nothing to sell, nothing to serve", args.config);
        return Ok(());
    };
    let read_npub = npub(&args.public_key);
    let (listen, npub) = match args.listen {
        Some(listen) => {
            let IpAddr::V6(address) = listen.ip() else {
                return Err(format!("{listen}: an IPv6 address, the exit's fips address"));
            };
            // The npub only if it is this address's.
            let theirs = read_npub.as_deref().and_then(npub_key).map(|key| key_address(&key));
            (listen, read_npub.clone().filter(|_| theirs == Some(address)))
        }
        None => {
            // fips brings its interface up a moment after it starts.
            let mut addresses = Vec::new();
            for attempt in 0..60 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let list = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
                addresses = mesh_addresses(&config.mesh_if, &list);
                if !addresses.is_empty() {
                    break;
                }
            }
            let (address, npub) = choose(&addresses, read_npub.clone()).map_err(|e| {
                format!("{}: {e}{}", config.mesh_if, if addresses.is_empty() { ": is fips running?" } else { "" })
            })?;
            (SocketAddr::new(IpAddr::V6(address), config.port), npub)
        }
    };
    if npub.is_none()
        && let Some(stale) = &read_npub
    {
        eprintln!("fips-exit-payd: {stale} in {} is not the npub of {}: not shown", args.public_key, listen.ip());
    }
    let IpAddr::V6(address) = listen.ip() else { unreachable!("checked above") };
    let exit =
        Exit { npub, address, name: config.name.clone(), about: config.about.clone(), country: config.country.clone() };
    let listener = TcpListener::bind(listen).await.map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    eprintln!(
        "fips-exit-payd: the terms of {} on http://{listen}/ (price {} msat a GB, {} package(s), nothing for sale yet)",
        exit.npub.as_deref().unwrap_or("this exit"),
        config.price_msat_per_gb,
        config.packages.len()
    );
    let site = Arc::new(http::Site::new(config, exit));
    // With --listen, which tests use, a peer from anywhere is talked to.
    let admit: fn(IpAddr) -> bool = if args.listen.is_some() { |_| true } else { http::on_the_mesh };
    tokio::select! {
        () = http::serve(listener, site, http::Limits::default(), admit) => Ok(()),
        // Stopped, or no way to be told to stop: the second is a failure,
        // so that systemd starts the service again.
        stopped = tokio::signal::ctrl_c() => stopped.map_err(|e| format!("cannot wait for a signal: {e}")),
    }
}

fn main() {
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("fips-exit-payd: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = runtime.block_on(run()) {
        eprintln!("fips-exit-payd: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl";
    const NODE_ADDRESS: &str = "fd14:af5b:b52d:a042:618:847d:f4e1:32dc";

    #[test]
    fn the_mesh_addresses_are_found_in_the_kernels_list() {
        let list = "fe80000000000000719824fe0b35ec95 0c 40 20 80    fips0\n\
                    fd14af5bb52da0420618847df4e132dc 0c 80 00 80    fips0\n\
                    fd99000000000000000000000000000a 02 80 00 80    other\n\
                    fd99000000000000000000000000000b 02 80 00 80    other\n\
                    00000000000000000000000000000001 01 80 10 80       lo\n";
        assert_eq!(mesh_addresses("fips0", list), vec![NODE_ADDRESS.parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(mesh_addresses("other", list).len(), 2);
        assert!(mesh_addresses("lo", list).is_empty(), "not a fips address");
        assert!(mesh_addresses("wlan0", list).is_empty());
        assert!(mesh_addresses("fips0", "fdzz 0c 80 00 80 fips0\nbroken\n\n").is_empty());
    }

    #[test]
    fn an_npub_is_a_key_and_its_address_is_what_fips_derives() {
        // This machine's node: its npub, and the address fips0 has.
        let key = npub_key(NODE).unwrap();
        assert_eq!(key_address(&key), NODE_ADDRESS.parse::<Ipv6Addr>().unwrap());
        let mistyped = NODE.replace("9gvc", "9gvd");
        for bad in [
            "",
            "npub1",
            "nsec19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl",
            &mistyped,
            &NODE[..NODE.len() - 1],
            &format!("{NODE}q"),
            &NODE.to_uppercase(),
        ] {
            assert_eq!(npub_key(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_address_answered_on_is_the_npubs_or_the_only_one() {
        let node: Ipv6Addr = NODE_ADDRESS.parse().unwrap();
        let other: Ipv6Addr = "fd99::a".parse().unwrap();
        let npub = Some(NODE.to_string());
        assert_eq!(choose(&[other, node], npub.clone()), Ok((node, npub.clone())));
        assert_eq!(choose(&[node], npub.clone()), Ok((node, npub.clone())));
        // The npub names another node: the one address, and no npub shown.
        assert_eq!(choose(&[other], npub.clone()), Ok((other, None)));
        assert_eq!(choose(&[other], None), Ok((other, None)));
        // Several, and none the npub's: not guessed.
        assert!(choose(&[other, "fd99::b".parse().unwrap()], npub.clone()).is_err());
        assert!(choose(&[other, "fd99::b".parse().unwrap()], None).is_err());
        assert!(choose(&[], npub).is_err());
    }

    #[test]
    fn an_npub_is_read_or_left_out() {
        let dir = std::env::temp_dir().join(format!("fips-exit-payd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fips.pub");
        let path = path.to_str().unwrap();
        let real = NODE;
        std::fs::write(path, format!("{real}\n")).unwrap();
        assert_eq!(npub(path).as_deref(), Some(real));
        std::fs::write(path, real.to_uppercase()).unwrap();
        assert_eq!(npub(path).as_deref(), Some(real), "bech32 in capitals is the same");
        for bad in [
            "",
            "nsec1…",
            "npub1short",
            &format!("{real}<script>"),
            &real.replace('9', "/"),
            &real.replace("9gvc", "9gvd"),
        ] {
            std::fs::write(path, bad).unwrap();
            assert_eq!(npub(path), None, "{bad:?}");
        }
        assert_eq!(npub("/nonexistent/fips.pub"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
