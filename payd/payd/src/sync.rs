//! Keeping the daemon's accounts as the store says.
//!
//! The store is the truth. Every few seconds, and at once after a change,
//! the service asks the daemon over its control socket what it has
//! counted, folds that into the store, and tells it what is to be carried:
//! each live package as an account with its members, and nothing else of
//! the service's. When the daemon has started again (its epoch changes) its
//! table is empty, and every live package is put again, with what it had
//! used.

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Notify;

use crate::store::{Standing, Store};

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// How often the daemon is asked when nothing has changed here.
pub const EVERY: Duration = Duration::from_secs(2);
/// How long one answer of the daemon's may take.
const ANSWER: Duration = Duration::from_secs(5);

/// One session on the daemon's control socket.
struct Daemon {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Daemon {
    async fn connect(path: &PathBuf) -> Result<Daemon, String> {
        let stream = UnixStream::connect(path).await.map_err(|e| format!("{}: {e}", path.display()))?;
        let (reader, writer) = stream.into_split();
        Ok(Daemon { reader: BufReader::new(reader), writer })
    }

    /// Send one command; the lines of the answer, the last of which says
    /// `ok` or `err`.
    async fn ask(&mut self, command: &str) -> Result<Vec<String>, String> {
        self.writer.write_all(format!("{command}\n").as_bytes()).await.map_err(|e| e.to_string())?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = tokio::time::timeout(ANSWER, self.reader.read_line(&mut line))
                .await
                .map_err(|_| "the daemon did not answer".to_string())?
                .map_err(|e| e.to_string())?;
            if read == 0 {
                return Err("the daemon closed the connection".into());
            }
            let line = line.trim_end().to_string();
            let last = line.starts_with("ok") || line.starts_with("err");
            lines.push(line);
            if last || lines.len() > 100_000 {
                return Ok(lines);
            }
        }
    }

    /// The last line of the answer, which must say `ok`.
    async fn tell(&mut self, command: &str) -> Result<String, String> {
        let answer = self.ask(command).await?;
        let last = answer.last().cloned().unwrap_or_default();
        if last.starts_with("ok") { Ok(last) } else { Err(format!("{command:.40}…: {last}")) }
    }
}

/// What was last put for a package: when it is the same, it is not put
/// again. Counts are not in it: they come from the daemon.
#[derive(Debug, Clone, PartialEq)]
struct Pushed {
    granted: u64,
    until: u64,
    members: Vec<Ipv6Addr>,
}

/// What the service knows of the daemon between two rounds.
#[derive(Default)]
pub struct Sync {
    epoch: Option<String>,
    pushed: HashMap<String, Pushed>,
}

/// How each member sits in the daemon (`v4`, `no4`, `static`), as its last
/// `put` said: shared with the pages, which tell a member that is carried
/// for IPv6 only.
pub type Seats = Arc<Mutex<HashMap<Ipv6Addr, String>>>;

/// Is `name` an account of this service's: `p` and 16 hex digits?
fn ours(name: &str) -> bool {
    name.len() == 17 && name.starts_with('p') && name[1..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One round. What it did, for the log.
pub async fn round(store: &Store, control: &PathBuf, sync: &mut Sync, seats: &Seats) -> Result<Vec<String>, String> {
    let mut done = Vec::new();
    let mut daemon = Daemon::connect(control).await?;
    let stat = daemon.tell("stat").await?;
    let Some(epoch) = stat.split_whitespace().find_map(|word| word.strip_prefix("epoch=")).map(str::to_string) else {
        return Err(format!("the daemon's stat: {stat}"));
    };
    let epoch = Some(epoch);
    if epoch != sync.epoch {
        if sync.epoch.is_some() {
            done.push("the daemon started again: every live package is put again".to_string());
        }
        sync.pushed.clear();
        sync.epoch = epoch;
    }
    // What the daemon has counted, into the store, before anything is
    // decided from the store.
    let mut there = HashSet::new();
    for line in daemon.ask("usage").await? {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let ["account", name, _granted, used_in, used_out, ..] = words[..]
            && ours(name)
        {
            there.insert(name.to_string());
            if let (Ok(used_in), Ok(used_out)) = (used_in.parse(), used_out.parse()) {
                store.fold_usage(name, used_in, used_out).map_err(|e| e.to_string())?;
            }
        }
    }
    let now = unix_now();
    for package in store.packages().map_err(|e| e.to_string())? {
        let standing = package.standing(now);
        if standing != Standing::Live {
            if there.contains(&package.id) || sync.pushed.contains_key(&package.id) {
                let answer = daemon.tell(&format!("drop {}", package.id)).await;
                if answer.is_ok() || answer.as_ref().is_err_and(|e| e.ends_with("err no-account")) {
                    sync.pushed.remove(&package.id);
                    if there.contains(&package.id) {
                        done.push(format!("{} is {}: dropped", package.id, standing.word()));
                    }
                } else {
                    answer?;
                }
            }
            continue;
        }
        let wanted = Pushed { granted: package.granted, until: package.until, members: package.members.clone() };
        if sync.pushed.get(&package.id) == Some(&wanted) && there.contains(&package.id) {
            continue;
        }
        let members = if package.members.is_empty() {
            "-".to_string()
        } else {
            package.members.iter().map(Ipv6Addr::to_string).collect::<Vec<_>>().join(",")
        };
        let answer = daemon
            .tell(&format!(
                "put {} {} {} {} {members} {}",
                package.id, package.granted, package.used_in, package.used_out, package.until
            ))
            .await?;
        let mut seated = seats.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for word in answer.split_whitespace().skip(1) {
            if let Some((address, seat)) = word.split_once('=')
                && let Ok(address) = address.parse()
            {
                seated.insert(address, seat.to_string());
            }
        }
        drop(seated);
        if !there.contains(&package.id) {
            done.push(format!(
                "{} put: {} member(s), {} bytes left",
                package.id,
                package.members.len(),
                package.left()
            ));
        }
        sync.pushed.insert(package.id.clone(), wanted);
    }
    Ok(done)
}

/// Rounds for as long as the service runs: every [`EVERY`], and at once
/// when `changed` is notified. A daemon that cannot be reached is said
/// once, and again when it can be.
pub async fn keep(store: Arc<Store>, control: PathBuf, seats: Seats, changed: Arc<Notify>) {
    let mut sync = Sync::default();
    let mut failing: Option<String> = None;
    loop {
        match round(&store, &control, &mut sync, &seats).await {
            Ok(done) => {
                if failing.take().is_some() {
                    eprintln!("fips-exit-payd: the daemon answers again");
                }
                for line in done {
                    eprintln!("fips-exit-payd: {line}");
                }
            }
            Err(e) => {
                if failing.as_deref() != Some(e.as_str()) {
                    eprintln!("fips-exit-payd: the daemon's accounts cannot be kept: {e}");
                }
                // Asked again from the start next time: whatever was put
                // may not be there.
                sync.epoch = None;
                failing = Some(e);
            }
        }
        tokio::select! {
            () = tokio::time::sleep(EVERY) => {}
            () = changed.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[test]
    fn only_the_services_own_accounts_are_its() {
        assert!(ours("p0123456789abcdef"));
        for not in ["pkg", "p0123456789ABCDEF", "p0123456789abcde", "q0123456789abcdef", "p0123456789abcdefg", ""] {
            assert!(!ours(not), "{not}");
        }
    }

    /// A daemon on a socket that answers like the real one, from a table
    /// the test can look at.
    #[derive(Default)]
    struct FakeDaemon {
        epoch: u64,
        accounts: HashMap<String, (u64, u64, u64, u64, Vec<String>)>,
        heard: Vec<String>,
    }

    async fn fake(path: PathBuf, daemon: Arc<Mutex<FakeDaemon>>) {
        let listener = UnixListener::bind(&path).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let daemon = daemon.clone();
            tokio::spawn(async move {
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let answer = {
                        let mut d = daemon.lock().unwrap();
                        d.heard.push(line.clone());
                        let words: Vec<&str> = line.split_whitespace().collect();
                        match words[..] {
                            ["stat"] => {
                                format!("ok epoch={} accounts={} resolver=1 counts=0\n", d.epoch, d.accounts.len())
                            }
                            ["usage"] => {
                                let mut out: String = d
                                    .accounts
                                    .iter()
                                    .map(|(n, (g, i, o, u, _))| format!("account {n} {g} {i} {o} {u}\n"))
                                    .collect();
                                out.push_str(&format!("ok {}\n", d.accounts.len()));
                                out
                            }
                            ["put", name, g, i, o, members, until] => {
                                let members: Vec<String> = if members == "-" {
                                    vec![]
                                } else {
                                    members.split(',').map(str::to_string).collect()
                                };
                                let seats: String = members.iter().map(|m| format!(" {m}=v4")).collect();
                                let entry = d.accounts.entry(name.to_string()).or_insert((0, 0, 0, 0, vec![]));
                                entry.0 = entry.0.max(g.parse().unwrap());
                                entry.1 = entry.1.max(i.parse().unwrap());
                                entry.2 = entry.2.max(o.parse().unwrap());
                                entry.3 = until.parse().unwrap();
                                entry.4 = members;
                                format!("ok{seats}\n")
                            }
                            ["drop", name] => {
                                if d.accounts.remove(name).is_some() {
                                    "ok\n".into()
                                } else {
                                    "err no-account\n".into()
                                }
                            }
                            _ => "err command\n".into(),
                        }
                    };
                    if writer.write_all(answer.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    fn address(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, n, 0, 0, 0, 0, 0, 1)
    }

    #[tokio::test]
    async fn the_daemon_is_kept_as_the_store_says() {
        let dir = std::env::temp_dir().join(format!("fips-exit-payd-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let _ = std::fs::remove_file(&path);
        let daemon = Arc::new(Mutex::new(FakeDaemon { epoch: 1, ..FakeDaemon::default() }));
        tokio::spawn(fake(path.clone(), daemon.clone()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let store = Store::in_memory();
        let seats: Seats = Arc::default();
        let mut sync = Sync::default();
        let now = unix_now();

        // A package is put, with its members and its end.
        let (id, _) = store.grant(1000, 1, &[address(1), address(2)], "", now).unwrap();
        round(&store, &path, &mut sync, &seats).await.unwrap();
        let account = daemon.lock().unwrap().accounts.get(&id).cloned().unwrap();
        assert_eq!((account.0, account.1, account.2, account.3), (1000, 0, 0, now + 86_400));
        assert_eq!(account.4, vec![address(1).to_string(), address(2).to_string()]);
        assert_eq!(seats.lock().unwrap().get(&address(1)).map(String::as_str), Some("v4"));
        // Nothing changed: it is not put again.
        daemon.lock().unwrap().heard.clear();
        round(&store, &path, &mut sync, &seats).await.unwrap();
        assert_eq!(daemon.lock().unwrap().heard, vec!["stat", "usage"]);
        // What the daemon counted goes into the store.
        daemon.lock().unwrap().accounts.get_mut(&id).unwrap().1 = 300;
        daemon.lock().unwrap().accounts.get_mut(&id).unwrap().2 = 200;
        round(&store, &path, &mut sync, &seats).await.unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().used(), 500);
        // The daemon starts again, with nothing: the package is put again,
        // with what it had used.
        {
            let mut d = daemon.lock().unwrap();
            d.epoch = 2;
            d.accounts.clear();
        }
        let done = round(&store, &path, &mut sync, &seats).await.unwrap();
        assert!(done.iter().any(|line| line.contains("started again")), "{done:?}");
        let account = daemon.lock().unwrap().accounts.get(&id).cloned().unwrap();
        assert_eq!((account.0, account.1, account.2), (1000, 300, 200));
        // Used up, by the daemon's count: dropped, and the store knows.
        daemon.lock().unwrap().accounts.get_mut(&id).unwrap().2 = 700;
        round(&store, &path, &mut sync, &seats).await.unwrap();
        assert!(!daemon.lock().unwrap().accounts.contains_key(&id));
        assert_eq!(store.package(&id).unwrap().unwrap().standing(now), Standing::UsedUp);
        // Topped up: put again, live.
        store.top_up(&id, 5000, 0, now).unwrap();
        round(&store, &path, &mut sync, &seats).await.unwrap();
        assert_eq!(daemon.lock().unwrap().accounts.get(&id).map(|a| a.0), Some(6000));
        // Revoked: dropped. An account that is not the service's is left alone.
        daemon.lock().unwrap().accounts.insert("by-hand".into(), (5, 0, 0, 0, vec![]));
        store.revoke(&id).unwrap();
        round(&store, &path, &mut sync, &seats).await.unwrap();
        let names: Vec<String> = daemon.lock().unwrap().accounts.keys().cloned().collect();
        assert_eq!(names, vec!["by-hand".to_string()]);
        // A package that is over, and that the daemon still has after the
        // service started again: dropped all the same.
        let (old, _) = store.grant(1000, 1, &[address(3)], "", now - 2 * 86_400).unwrap();
        daemon.lock().unwrap().accounts.insert(old.clone(), (1000, 0, 0, now - 86_400, vec![]));
        let mut fresh = Sync::default();
        round(&store, &path, &mut fresh, &seats).await.unwrap();
        assert!(!daemon.lock().unwrap().accounts.contains_key(&old));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn no_daemon_is_said() {
        let store = Store::in_memory();
        let mut sync = Sync::default();
        let said = round(&store, &PathBuf::from("/nonexistent/control.sock"), &mut sync, &Seats::default()).await;
        assert!(said.unwrap_err().contains("/nonexistent/control.sock"));
    }
}
