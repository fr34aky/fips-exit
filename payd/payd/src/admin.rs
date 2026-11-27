//! The operator's own way into the service: a Unix socket in the service's
//! runtime directory, which only the service's user and root can open, and
//! which `fips-exit grant`, `packages`, `top-up`, `members` and `revoke`
//! speak to. Packages made here are given away: nothing is paid for them.
//!
//! One command a line, words with spaces between them; every answer ends in
//! a line that begins `ok` or `err`.
//!
//! ```text
//! grant <size> <days> <npub|address,…> [label…]   ok <id> <key>
//! top-up <id> <size> <days>                       ok
//! members <id> <npub|address,…|->                 ok
//! revoke <id>                                     ok
//! packages                                        package <id> <standing> <granted> <used_in> <used_out> <until> <members|-> [label], … ok <n>
//! ```

use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use crate::config::size;
use crate::identity::client;
use crate::store::Store;
use crate::sync::unix_now;

/// The longest line read, and how long one may take.
const MAX_LINE: usize = 4096;
const LINE_TIME: Duration = Duration::from_secs(10);
/// The longest label, in characters.
const MAX_LABEL: usize = 64;

/// Members as the operator names them: npubs or fips addresses.
fn members(word: &str) -> Result<Vec<(Ipv6Addr, Option<String>)>, String> {
    if word == "-" {
        return Ok(Vec::new());
    }
    word.split(',').map(|who| client(who).ok_or_else(|| format!("err who {who}"))).collect()
}

fn addresses(named: &[(Ipv6Addr, Option<String>)]) -> Vec<Ipv6Addr> {
    named.iter().map(|(address, _)| *address).collect()
}

/// Once they are in: the npub each was named by, kept for its address, so
/// that it is shown by it.
fn remember(store: &Store, named: &[(Ipv6Addr, Option<String>)]) -> Result<(), String> {
    for (address, npub) in named {
        if let Some(npub) = npub {
            store.remember(*address, npub).map_err(|e| format!("err {e}"))?;
        }
    }
    Ok(())
}

fn days(word: &str) -> Result<u32, String> {
    let fits = !word.is_empty() && word.len() <= 4 && word.bytes().all(|b| b.is_ascii_digit());
    fits.then(|| word.parse().ok()).flatten().filter(|days| *days <= 3660).ok_or_else(|| "err days".into())
}

fn bytes(word: &str) -> Result<u64, String> {
    size(word).ok_or_else(|| "err size (bytes, or MB, GB, TB)".into())
}

/// A label for the operator's own use: one line of printable text.
fn label(words: &[&str]) -> Result<String, String> {
    let text = words.join(" ");
    if text.chars().count() > MAX_LABEL || text.chars().any(char::is_control) {
        return Err(format!("err label (one line, at most {MAX_LABEL} characters)"));
    }
    Ok(text)
}

/// Do what one line asks; the answer, its last line `ok…` or `err…`.
pub fn answer(store: &Store, line: &str, now: u64) -> String {
    let words: Vec<&str> = line.split_whitespace().collect();
    let done = (|| -> Result<String, String> {
        let store_said = |e: crate::store::Refused| format!("err {e}");
        match words[..] {
            ["grant", size, d, who, ref rest @ ..] => {
                let (bytes, days, named, label) = (bytes(size)?, days(d)?, members(who)?, label(rest)?);
                if named.is_empty() {
                    return Err("err who (a package is for someone)".into());
                }
                let (id, key) = store.grant(bytes, days, &addresses(&named), &label, now).map_err(store_said)?;
                remember(store, &named)?;
                Ok(format!("ok {id} {key}\n"))
            }
            ["top-up", id, size, d] => {
                store.top_up(id, bytes(size)?, days(d)?, now).map_err(store_said)?;
                Ok("ok\n".into())
            }
            ["members", id, who] => {
                let named = members(who)?;
                store.set_members(id, &addresses(&named), now).map_err(store_said)?;
                remember(store, &named)?;
                Ok("ok\n".into())
            }
            ["revoke", id] => {
                store.revoke(id).map_err(store_said)?;
                Ok("ok\n".into())
            }
            ["packages"] => {
                let packages = store.packages().map_err(store_said)?;
                let mut out = String::new();
                for p in &packages {
                    let members = if p.members.is_empty() {
                        "-".to_string()
                    } else {
                        p.members.iter().map(|m| store.name_of(*m)).collect::<Vec<_>>().join(",")
                    };
                    out.push_str(&format!(
                        "package {} {} {} {} {} {} {members} {}\n",
                        p.id,
                        p.standing(now).word(),
                        p.granted,
                        p.used_in,
                        p.used_out,
                        p.until,
                        p.label
                    ));
                }
                out.push_str(&format!("ok {}\n", packages.len()));
                Ok(out)
            }
            [] => Err("err syntax".into()),
            ["grant" | "top-up" | "members" | "revoke" | "packages", ..] => Err("err arguments".into()),
            _ => Err("err command".into()),
        }
    })();
    match done {
        Ok(out) => out,
        Err(e) => format!("{}\n", e.trim_end()),
    }
}

/// Listen at `path`, for this user alone (and root).
pub fn listen(path: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(found) if found.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        Ok(_) => return Err(format!("{}: exists and is not a socket", path.display())),
        Err(_) => {}
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(listener)
}

async fn session(store: Arc<Store>, changed: Arc<Notify>, stream: UnixStream) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader).take(MAX_LINE as u64 * 64);
    loop {
        let mut line = String::new();
        let read = match tokio::time::timeout(LINE_TIME, reader.read_line(&mut line)).await {
            Ok(Ok(read)) => read,
            _ => return,
        };
        if read == 0 {
            return;
        }
        let reply =
            if line.len() > MAX_LINE { "err line\n".to_string() } else { answer(&store, line.trim_end(), unix_now()) };
        if reply.lines().last().is_some_and(|last| last.starts_with("ok")) && !line.trim_start().starts_with("packages")
        {
            // Something changed: the daemon is told now, not in a while.
            changed.notify_one();
        }
        if writer.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

pub async fn serve(listener: UnixListener, store: Arc<Store>, changed: Arc<Notify>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(session(store.clone(), changed.clone(), stream));
            }
            Err(e) => {
                eprintln!("fips-exit-payd: the operator's socket: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const NPUB: &str = "npub19gvc005p4zwlf6qldnd8yvpumyqcn4xkhedjwrfqs43udk27gkmqu9p3yl";

    #[test]
    fn the_operator_grants_tops_up_and_revokes() {
        let store = Store::in_memory();
        let granted = answer(&store, &format!("grant 1GB 30 {NPUB},fd99::2 a friend's phone"), NOW);
        let [ok, id, key] = granted.split_whitespace().collect::<Vec<_>>()[..] else { panic!("{granted}") };
        assert_eq!(ok, "ok");
        assert_eq!(key.len(), 64);
        let listed = answer(&store, "packages", NOW);
        assert_eq!(
            listed,
            format!("package {id} live 1000000000 0 0 {} {NPUB},fd99::2 a friend's phone\nok 1\n", NOW + 30 * 86_400)
        );
        assert_eq!(answer(&store, &format!("top-up {id} 500MB 0"), NOW), "ok\n");
        assert_eq!(answer(&store, &format!("members {id} fd99::3"), NOW), "ok\n");
        let listed = answer(&store, "packages", NOW);
        assert!(listed.starts_with(&format!("package {id} live 1500000000 0 0 ")), "{listed}");
        assert!(listed.contains(" fd99::3 "), "{listed}");
        assert_eq!(answer(&store, &format!("revoke {id}"), NOW), "ok\n");
        assert!(answer(&store, "packages", NOW).starts_with(&format!("package {id} revoked ")));
    }

    #[test]
    fn what_is_not_a_command_is_said_and_changes_nothing() {
        let store = Store::in_memory();
        let bad = |line: &str, said: &str| {
            let got = answer(&store, line, NOW);
            assert!(got.starts_with(said) && got.ends_with('\n') && got.lines().count() == 1, "{line:?}: {got:?}");
        };
        bad("", "err syntax");
        bad("reboot", "err command");
        bad("grant 1GB 30", "err arguments");
        bad("grant lots 30 fd99::2", "err size");
        bad("grant 1gb 30 fd99::2", "err size");
        bad("grant 0 30 fd99::2", "err too-much");
        bad("grant 1GB -1 fd99::2", "err days");
        bad("grant 1GB 3661 fd99::2", "err days");
        bad("grant 1GB 30 -", "err who");
        bad("grant 1GB 30 2001:db8::1", "err who");
        bad("grant 1GB 30 npub1mistyped", "err who");
        bad("grant 1GB 30 fd99::2,fd99::2", "err members");
        bad(&format!("grant 1GB 30 fd99::2 {}", "x".repeat(65)), "err label");
        bad("top-up p0000000000000000 1GB 0", "err no-package");
        bad("revoke nothing", "err no-package");
        bad("packages please", "err arguments");
        assert_eq!(answer(&store, "packages", NOW), "ok 0\n");
        assert!(answer(&store, "grant 1GB 0 fd99::2", NOW).starts_with("ok "));
        bad("grant 1GB 0 fd99::2", "err elsewhere fd99::2");
    }
}
