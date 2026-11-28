//! fips-exit-payd: the payment service of a paid fips exit.
//!
//! It runs beside the exit as a user of its own, with no privilege, and
//! answers on the exit's fips address only. A caller there is known by the
//! address its connection comes from, which fips authenticates: no account
//! and no login.
//!
//! It says what the exit costs (`GET /v1/terms`, and a page for a browser
//! at `/`), keeps the packages and tells the exit's daemon whom to carry,
//! and sells packages for Cashu tokens of the mints the operator accepts,
//! which arrive in a wallet of its own. What is to come is in
//! docs/paid-exit.md.

mod admin;
mod config;
mod http;
mod identity;
mod invoices;
mod manage;
mod orders;
mod qr;
mod store;
mod sync;
mod terms;
mod wallet;

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use crate::config::Config;
use crate::identity::{key_address, npub_key};
use crate::terms::Exit;

struct Args {
    config: String,
    public_key: String,
    /// Where to listen instead of the mesh address: for tests.
    listen: Option<SocketAddr>,
    /// The directory the store is kept in.
    state: PathBuf,
    /// The daemon's control socket, and the operator's socket of this
    /// service.
    control: PathBuf,
    admin: PathBuf,
}

/// A directory systemd made for the service and named in `variable`, or
/// `fallback`.
fn directory(variable: &str, fallback: &str) -> PathBuf {
    // systemd may name several, with colons between them: the first.
    match std::env::var(variable) {
        Ok(named) if !named.is_empty() => PathBuf::from(named.split(':').next().unwrap_or(&named)),
        _ => PathBuf::from(fallback),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config: "/etc/fips-exit/config".into(),
        public_key: "/etc/fips/fips.pub".into(),
        listen: None,
        state: directory("STATE_DIRECTORY", "/var/lib/fips-exit-payd"),
        control: "/run/fips-exit/control.sock".into(),
        admin: directory("RUNTIME_DIRECTORY", "/run/fips-exit-payd").join("admin.sock"),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let value = argv.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--config" => args.config = value,
            "--pub" => args.public_key = value,
            "--listen" => args.listen = Some(value.parse().map_err(|_| format!("--listen {value}: [address]:port"))?),
            "--state" => args.state = value.into(),
            "--control" => args.control = value.into(),
            "--admin" => args.admin = value.into(),
            other => {
                return Err(format!(
                    "unknown argument {other}\nusage: fips-exit-payd [--config FILE] [--pub FILE] [--listen [ADDRESS]:PORT] \
                     [--state DIRECTORY] [--control SOCKET] [--admin SOCKET]"
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

/// The node's npub, from its public key file: shown, and a name this
/// service answers to (`<npub>.fips`). None if it cannot be read or is not
/// an npub.
fn npub(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let npub = text.trim().to_ascii_lowercase();
    npub_key(&npub).map(|_| npub)
}

/// Where to listen: the fips address of the node's npub, which `interface`
/// must have. The npub is the exit's name on the mesh, and the only way to
/// it: a node reaches a fips address only once it has resolved the npub
/// that address belongs to (`<npub>.fips`). An exit whose npub is not known
/// here, or is another node's, is not served at all.
fn choose(addresses: &[Ipv6Addr], npub: Option<&str>, key_file: &str) -> Result<Ipv6Addr, String> {
    let Some(npub) = npub else {
        return Err(format!("{key_file} has no npub: the exit is reached by its npub, and it is not known here"));
    };
    let of_npub = npub_key(npub).map(|key| key_address(&key)).ok_or_else(|| format!("{npub} is not an npub"))?;
    if addresses.contains(&of_npub) {
        Ok(of_npub)
    } else if addresses.is_empty() {
        Err("no fips address: is fips running?".into())
    } else {
        Err(format!("{npub} (from {key_file}) is not this node: its address {of_npub} is not here"))
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
    let listen = match args.listen {
        Some(listen) => {
            let IpAddr::V6(address) = listen.ip() else {
                return Err(format!("{listen}: an IPv6 address, the exit's fips address"));
            };
            choose(&[address], read_npub.as_deref(), &args.public_key)?;
            listen
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
            let address = choose(&addresses, read_npub.as_deref(), &args.public_key)
                .map_err(|e| format!("{}: {e}", config.mesh_if))?;
            SocketAddr::new(IpAddr::V6(address), config.port)
        }
    };
    let (Some(npub), IpAddr::V6(address)) = (read_npub, listen.ip()) else { unreachable!("checked by choose") };
    let exit =
        Exit { npub, address, name: config.name.clone(), about: config.about.clone(), country: config.country.clone() };
    let listener = TcpListener::bind(listen).await.map_err(|e| format!("cannot listen on {listen}: {e}"))?;
    eprintln!(
        "fips-exit-payd: the terms on http://{}.fips:{}/ (price {} msat a GB, {} package(s), {})",
        exit.npub,
        listen.port(),
        config.price_msat_per_gb,
        config.packages.len(),
        match config.mints.len() {
            0 => "no mint named in MINTS: nothing is sold".to_string(),
            mints => format!("sold for tokens of {mints} mint(s)"),
        }
    );
    // The packages, kept; the daemon kept as they say; the operator's way in.
    let store = Arc::new(store::Store::open(&args.state.join("payd.db"))?);
    let seats = sync::Seats::default();
    let changed = Arc::new(tokio::sync::Notify::new());
    let admin = admin::listen(&args.admin)?;
    eprintln!(
        "fips-exit-payd: {} package(s) kept in {}; the operator's socket is {}; the daemon's, {}",
        store.packages().map_err(|e| e.to_string())?.len(),
        args.state.display(),
        args.admin.display(),
        args.control.display()
    );
    tokio::spawn(sync::keep(store.clone(), args.control.clone(), seats.clone(), changed.clone()));
    let mut site = http::Site::new(config, exit, store, seats, changed);
    // The wallet, on an exit that names a mint: what is paid arrives there.
    if !site.config.mints.is_empty() {
        let wallets = Arc::new(wallet::Wallets::open(&args.state, &site.config.mints).await?);
        eprintln!(
            "fips-exit-payd: the wallet is kept in {}: its seed (the file `seed`) is what it holds, to be kept safe",
            args.state.display()
        );
        site.desk = Some(Arc::new(orders::Desk::new(wallets.clone(), args.control.clone())));
        tokio::spawn(wallets.keep());
    }
    let site = Arc::new(site);
    // What an earlier run left open is decided before anything new.
    tokio::spawn(orders::keep(site.clone()));
    tokio::spawn(invoices::keep(site.clone()));
    tokio::spawn(admin::serve(admin, site.clone()));
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
    fn the_address_answered_on_is_the_npubs_and_nothing_else() {
        let node: Ipv6Addr = NODE_ADDRESS.parse().unwrap();
        let other: Ipv6Addr = "fd99::a".parse().unwrap();
        assert_eq!(choose(&[other, node], Some(NODE), "fips.pub"), Ok(node));
        assert_eq!(choose(&[node], Some(NODE), "fips.pub"), Ok(node));
        // The npub names another node, or there is none: nothing is served,
        // not even on the interface's one address.
        assert!(choose(&[other], Some(NODE), "fips.pub").unwrap_err().contains("is not this node"));
        assert!(choose(&[other], None, "fips.pub").unwrap_err().contains("has no npub"));
        assert!(choose(&[], Some(NODE), "fips.pub").unwrap_err().contains("is fips running?"));
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
