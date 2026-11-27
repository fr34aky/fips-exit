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

/// The fips address of `interface`, from the kernel's list of IPv6
/// addresses: no privilege needed, nothing to link.
fn mesh_address(interface: &str, list: &str) -> Option<Ipv6Addr> {
    for line in list.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [hex, _, _, _, _, name] = fields[..] else { continue };
        if name != interface || hex.len() != 32 {
            continue;
        }
        let mut octets = [0u8; 16];
        for (at, octet) in octets.iter_mut().enumerate() {
            *octet = u8::from_str_radix(hex.get(2 * at..2 * at + 2)?, 16).ok()?;
        }
        if octets[0] == 0xfd {
            return Some(Ipv6Addr::from(octets));
        }
    }
    None
}

/// The node's npub, from its public key file: shown, and a name this
/// service answers to (`<npub>.fips`). None if it cannot be read, or what
/// is there is not one.
fn npub(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let npub = text.trim();
    let looks_right = npub.len() == 63 && npub.starts_with("npub1") && npub.bytes().all(|b| b.is_ascii_alphanumeric());
    looks_right.then(|| npub.to_string())
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
    let listen = match args.listen {
        Some(listen) => listen,
        None => {
            // fips brings its interface up a moment after it starts.
            let mut found = None;
            for attempt in 0..60 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let list = std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default();
                found = mesh_address(&config.mesh_if, &list);
                if found.is_some() {
                    break;
                }
            }
            let address = found.ok_or_else(|| format!("{} has no fips address: is fips running?", config.mesh_if))?;
            SocketAddr::new(IpAddr::V6(address), config.port)
        }
    };
    let IpAddr::V6(address) = listen.ip() else {
        return Err(format!("{listen}: an IPv6 address, the exit's fips address"));
    };
    let exit = Exit {
        npub: npub(&args.public_key),
        address,
        name: config.name.clone(),
        about: config.about.clone(),
        country: config.country.clone(),
    };
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
        () = http::serve(listener, site, http::Limits::default(), admit) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
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

    #[test]
    fn the_mesh_address_is_found_in_the_kernels_list() {
        let list = "fe80000000000000719824fe0b35ec95 0c 40 20 80    fips0\n\
                    fd14af5bb52da0420618847df4e132dc 0c 80 00 80    fips0\n\
                    fd99000000000000000000000000000a 02 80 00 80    other\n\
                    00000000000000000000000000000001 01 80 10 80       lo\n";
        assert_eq!(mesh_address("fips0", list), Some("fd14:af5b:b52d:a042:618:847d:f4e1:32dc".parse().unwrap()));
        assert_eq!(mesh_address("other", list), Some("fd99::a".parse().unwrap()));
        assert_eq!(mesh_address("lo", list), None, "not a fips address");
        assert_eq!(mesh_address("wlan0", list), None);
        assert_eq!(mesh_address("fips0", "fdzz 0c 80 00 80 fips0\nbroken\n\n"), None);
    }

    #[test]
    fn an_npub_is_read_or_left_out() {
        let dir = std::env::temp_dir().join(format!("fips-exit-payd-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fips.pub");
        let path = path.to_str().unwrap();
        let real = "npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl";
        std::fs::write(path, format!("{real}\n")).unwrap();
        assert_eq!(npub(path).as_deref(), Some(real));
        for bad in ["", "nsec1…", "npub1short", &format!("{real}<script>"), &real.replace('9', "/")] {
            std::fs::write(path, bad).unwrap();
            assert_eq!(npub(path), None, "{bad:?}");
        }
        assert_eq!(npub("/nonexistent/fips.pub"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
