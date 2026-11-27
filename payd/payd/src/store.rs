//! What the service keeps: packages, and the fips addresses that share
//! them. SQLite, in the service's own state directory.
//!
//! A package is an account in the exit's daemon: its id is the account's
//! name, and what the daemon has counted is folded in here, so that a
//! restart of either side loses nothing but the last seconds. A package
//! has a key, given once when it is made and kept here only as its hash:
//! whoever holds it manages the package.

use std::net::Ipv6Addr;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

/// The schema, by version. Each step is applied once, in order.
const SCHEMA: &[&str] = &[
    "
    CREATE TABLE packages (
        -- The account's name in the daemon: 'p' and 16 hex digits.
        id TEXT PRIMARY KEY,
        -- SHA-256 of the package's key; the key itself is not kept.
        key_hash BLOB NOT NULL UNIQUE,
        label TEXT NOT NULL DEFAULT '',
        granted INTEGER NOT NULL,
        used_in INTEGER NOT NULL DEFAULT 0,
        used_out INTEGER NOT NULL DEFAULT 0,
        -- Unix seconds, or 0 for no end.
        until INTEGER NOT NULL DEFAULT 0,
        created INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
    );
    -- An address is in one package at a time.
    CREATE TABLE members (
        address TEXT PRIMARY KEY,
        package TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE
    );
    CREATE INDEX members_by_package ON members(package);
",
    "
    -- The npub an address was named by, when it was: an address is the
    -- hash of its npub, so the npub is a fact about the address, and is
    -- what a person knows a node by.
    CREATE TABLE names (
        address TEXT PRIMARY KEY,
        npub TEXT NOT NULL
    );
",
];

/// The most a package may be granted: what the daemon takes.
pub const MAX_BYTES: u64 = u64::MAX / 4;
/// The most members a package may have: what the daemon takes.
pub const MAX_MEMBERS: usize = 32;

/// A package as it is kept.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub id: String,
    pub label: String,
    pub granted: u64,
    pub used_in: u64,
    pub used_out: u64,
    pub until: u64,
    pub created: u64,
    pub revoked: bool,
    pub members: Vec<Ipv6Addr>,
}

/// What a package is, at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Its members are carried.
    Live,
    /// Its bytes are used up.
    UsedUp,
    /// Its time is over.
    Over,
    /// Taken back by the operator.
    Revoked,
}

impl Standing {
    pub fn word(self) -> &'static str {
        match self {
            Standing::Live => "live",
            Standing::UsedUp => "used-up",
            Standing::Over => "over",
            Standing::Revoked => "revoked",
        }
    }
}

impl Package {
    pub fn used(&self) -> u64 {
        self.used_in.saturating_add(self.used_out)
    }

    pub fn left(&self) -> u64 {
        self.granted.saturating_sub(self.used())
    }

    pub fn standing(&self, now: u64) -> Standing {
        if self.revoked {
            Standing::Revoked
        } else if self.until != 0 && now >= self.until {
            Standing::Over
        } else if self.used() >= self.granted {
            Standing::UsedUp
        } else {
            Standing::Live
        }
    }
}

/// Why something asked of the store was not done.
#[derive(Debug, PartialEq)]
pub enum Refused {
    /// No package with that id.
    NoPackage,
    /// An address is a member of another package that is live.
    Elsewhere(Ipv6Addr),
    /// More members than the daemon takes, or an address twice.
    Members,
    /// More bytes than the daemon takes.
    TooMuch,
    /// Its time is over, and a top-up gave it no more days.
    Over,
    /// The database said no.
    Store(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::NoPackage => f.write_str("no-package"),
            Refused::Elsewhere(address) => write!(f, "elsewhere {address}"),
            Refused::Members => write!(f, "members (at most {MAX_MEMBERS}, none twice)"),
            Refused::TooMuch => f.write_str("too-much"),
            Refused::Over => f.write_str("over (its time has ended: give it days too)"),
            Refused::Store(e) => write!(f, "store {e}"),
        }
    }
}

impl From<rusqlite::Error> for Refused {
    fn from(e: rusqlite::Error) -> Self {
        Refused::Store(e.to_string())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `n` random bytes, from the kernel.
pub fn random(n: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub fn key_hash(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

fn as_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub struct Store {
    db: Mutex<Connection>,
}

impl Store {
    /// The store at `path`, made if it is not there, and brought to the
    /// current schema.
    pub fn open(path: &Path) -> Result<Store, String> {
        let db = Connection::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Store::with(db)
    }

    #[cfg(test)]
    pub fn in_memory() -> Store {
        Store::with(Connection::open_in_memory().unwrap()).unwrap()
    }

    fn with(db: Connection) -> Result<Store, String> {
        let setup = || -> rusqlite::Result<()> {
            db.pragma_update(None, "journal_mode", "WAL")?;
            db.pragma_update(None, "foreign_keys", true)?;
            db.pragma_update(None, "synchronous", "FULL")?;
            let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
            for (step, sql) in SCHEMA.iter().enumerate().skip(usize::try_from(version).unwrap_or(0)) {
                let tx = db.unchecked_transaction()?;
                tx.execute_batch(sql)?;
                tx.pragma_update(None, "user_version", step + 1)?;
                tx.commit()?;
            }
            Ok(())
        };
        setup().map_err(|e| format!("the store: {e}"))?;
        Ok(Store { db: Mutex::new(db) })
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn members_of(db: &Connection, id: &str) -> rusqlite::Result<Vec<Ipv6Addr>> {
        let mut query = db.prepare_cached("SELECT address FROM members WHERE package = ?1 ORDER BY address")?;
        let rows = query.query_map([id], |row| row.get::<_, String>(0))?;
        Ok(rows.filter_map(|row| row.ok()?.parse().ok()).collect())
    }

    fn package_in(db: &Connection, id: &str) -> rusqlite::Result<Option<Package>> {
        let found = db
            .query_row(
                "SELECT id, label, granted, used_in, used_out, until, created, revoked FROM packages WHERE id = ?1",
                [id],
                |row| {
                    Ok(Package {
                        id: row.get(0)?,
                        label: row.get(1)?,
                        granted: as_u64(row.get(2)?),
                        used_in: as_u64(row.get(3)?),
                        used_out: as_u64(row.get(4)?),
                        until: as_u64(row.get(5)?),
                        created: as_u64(row.get(6)?),
                        revoked: row.get::<_, i64>(7)? != 0,
                        members: Vec::new(),
                    })
                },
            )
            .optional()?;
        match found {
            Some(mut package) => {
                package.members = Store::members_of(db, id)?;
                Ok(Some(package))
            }
            None => Ok(None),
        }
    }

    #[cfg(test)]
    pub fn package(&self, id: &str) -> Result<Option<Package>, Refused> {
        Ok(Store::package_in(&self.db(), id)?)
    }

    /// Every package, newest first.
    pub fn packages(&self) -> Result<Vec<Package>, Refused> {
        let db = self.db();
        let ids: Vec<String> = {
            let mut query = db.prepare_cached("SELECT id FROM packages ORDER BY created DESC, id")?;
            query.query_map([], |row| row.get(0))?.collect::<rusqlite::Result<_>>()?
        };
        Ok(ids.iter().filter_map(|id| Store::package_in(&db, id).ok().flatten()).collect())
    }

    /// Put `members` into package `id` and take every other address out of
    /// it. An address in another package that is live is refused, and
    /// nothing changes; one in a package that is not live any more is moved,
    /// and so is `mover`, wherever it is: the address that asks for itself.
    /// Nobody can be held in a stranger's package by being put there, since
    /// it can always move itself out (or [`Store::leave`]).
    fn seat(db: &Connection, id: &str, members: &[Ipv6Addr], now: u64, mover: Option<Ipv6Addr>) -> Result<(), Refused> {
        if members.len() > MAX_MEMBERS || members.iter().enumerate().any(|(at, m)| members[..at].contains(m)) {
            return Err(Refused::Members);
        }
        for member in members {
            let other: Option<String> = db
                .query_row("SELECT package FROM members WHERE address = ?1", [member.to_string()], |row| row.get(0))
                .optional()?;
            if let Some(other) = other.filter(|other| other != id)
                && mover != Some(*member)
                && Store::package_in(db, &other)?.is_some_and(|p| p.standing(now) == Standing::Live)
            {
                return Err(Refused::Elsewhere(*member));
            }
        }
        db.execute("DELETE FROM members WHERE package = ?1", [id])?;
        for member in members {
            db.execute(
                "INSERT INTO members (address, package) VALUES (?1, ?2)
                 ON CONFLICT(address) DO UPDATE SET package = excluded.package",
                params![member.to_string(), id],
            )?;
        }
        Ok(())
    }

    /// A new package: `bytes` for `members`, for `days` from `now` (0 for no
    /// end). Its id and its key; the key is not kept, only its hash.
    pub fn grant(
        &self,
        bytes: u64,
        days: u32,
        members: &[Ipv6Addr],
        label: &str,
        now: u64,
    ) -> Result<(String, String), Refused> {
        if bytes == 0 || bytes > MAX_BYTES {
            return Err(Refused::TooMuch);
        }
        let id = format!("p{}", hex(&random(8).map_err(|e| Refused::Store(e.to_string()))?));
        let key = hex(&random(32).map_err(|e| Refused::Store(e.to_string()))?);
        let until = if days == 0 { 0 } else { now + u64::from(days) * 86_400 };
        let mut db = self.db();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO packages (id, key_hash, label, granted, until, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, key_hash(&key), label, as_i64(bytes), as_i64(until), as_i64(now)],
        )?;
        Store::seat(&tx, &id, members, now, None)?;
        tx.commit()?;
        Ok((id, key))
    }

    /// More bytes for package `id`, and more days: counted from its end, or
    /// from now if that has passed. A package without an end keeps none.
    pub fn top_up(&self, id: &str, bytes: u64, days: u32, now: u64) -> Result<(), Refused> {
        let db = self.db();
        let package = Store::package_in(&db, id)?.ok_or(Refused::NoPackage)?;
        let granted = package.granted.checked_add(bytes).filter(|g| *g <= MAX_BYTES).ok_or(Refused::TooMuch)?;
        // Bytes alone would leave it as over as it was, and say otherwise.
        if days == 0 && package.until != 0 && now >= package.until {
            return Err(Refused::Over);
        }
        let until = match (package.until, days) {
            (0, _) | (_, 0) => package.until,
            (until, days) => until.max(now) + u64::from(days) * 86_400,
        };
        db.execute(
            "UPDATE packages SET granted = ?2, until = ?3 WHERE id = ?1",
            params![id, as_i64(granted), as_i64(until)],
        )?;
        Ok(())
    }

    pub fn set_members(&self, id: &str, members: &[Ipv6Addr], now: u64) -> Result<(), Refused> {
        self.set_members_for(id, members, now, None)
    }

    /// The same, asked by `mover` (the address a request came from), which
    /// may move itself out of another live package.
    pub fn set_members_for(
        &self,
        id: &str,
        members: &[Ipv6Addr],
        now: u64,
        mover: Option<Ipv6Addr>,
    ) -> Result<(), Refused> {
        let mut db = self.db();
        let tx = db.transaction()?;
        Store::package_in(&tx, id)?.ok_or(Refused::NoPackage)?;
        Store::seat(&tx, id, members, now, mover)?;
        tx.commit()?;
        Ok(())
    }

    /// The package whose key this is, if any. The key itself is not kept:
    /// its hash is looked for.
    pub fn package_with_key(&self, key: &str) -> Result<Option<Package>, Refused> {
        let db = self.db();
        let id: Option<String> = db
            .query_row("SELECT id FROM packages WHERE key_hash = ?1", [key_hash(key)], |row| row.get(0))
            .optional()?;
        match id {
            Some(id) => Ok(Store::package_in(&db, &id)?),
            None => Ok(None),
        }
    }

    /// Take `address` out of whatever package it is in. The package it was
    /// in, if any.
    pub fn leave(&self, address: Ipv6Addr) -> Result<Option<String>, Refused> {
        let db = self.db();
        let id: Option<String> = db
            .query_row("SELECT package FROM members WHERE address = ?1", [address.to_string()], |row| row.get(0))
            .optional()?;
        db.execute("DELETE FROM members WHERE address = ?1", [address.to_string()])?;
        Ok(id)
    }

    /// Take package `id` back. Its members are carried no more; it is kept,
    /// with what it used.
    pub fn revoke(&self, id: &str) -> Result<(), Refused> {
        let changed = self.db().execute("UPDATE packages SET revoked = 1 WHERE id = ?1", [id])?;
        if changed == 0 { Err(Refused::NoPackage) } else { Ok(()) }
    }

    /// What the daemon has counted for package `id`. Counts only grow: a
    /// lower number (the daemon started again, and has not been told yet)
    /// changes nothing.
    pub fn fold_usage(&self, id: &str, used_in: u64, used_out: u64) -> Result<(), Refused> {
        self.db().execute(
            "UPDATE packages SET used_in = MAX(used_in, ?2), used_out = MAX(used_out, ?3) WHERE id = ?1",
            params![id, as_i64(used_in), as_i64(used_out)],
        )?;
        Ok(())
    }

    /// Remember that `address` is `npub`'s. The caller has checked that it is.
    pub fn remember(&self, address: Ipv6Addr, npub: &str) -> Result<(), Refused> {
        self.db().execute(
            "INSERT INTO names (address, npub) VALUES (?1, ?2) ON CONFLICT(address) DO UPDATE SET npub = excluded.npub",
            params![address.to_string(), npub],
        )?;
        Ok(())
    }

    /// How a person knows `address`: its npub if it was ever named by it,
    /// and otherwise the address.
    pub fn name_of(&self, address: Ipv6Addr) -> String {
        self.db()
            .query_row("SELECT npub FROM names WHERE address = ?1", [address.to_string()], |row| row.get(0))
            .unwrap_or_else(|_| address.to_string())
    }

    /// The package `address` is a member of, if there is one.
    pub fn package_of(&self, address: Ipv6Addr) -> Result<Option<Package>, Refused> {
        let db = self.db();
        let id: Option<String> = db
            .query_row("SELECT package FROM members WHERE address = ?1", [address.to_string()], |row| row.get(0))
            .optional()?;
        match id {
            Some(id) => Ok(Store::package_in(&db, &id)?),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn a(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, n, 0, 0, 0, 0, 0, 1)
    }

    #[test]
    fn a_package_is_made_with_a_key_that_is_not_kept() {
        let store = Store::in_memory();
        let (id, key) = store.grant(1_000_000, 30, &[a(1), a(2)], "a friend", NOW).unwrap();
        assert!(id.len() == 17 && id.starts_with('p') && id[1..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()));
        let p = store.package(&id).unwrap().unwrap();
        assert_eq!((p.granted, p.used(), p.until, p.label.as_str()), (1_000_000, 0, NOW + 30 * 86_400, "a friend"));
        assert_eq!(p.members, vec![a(1), a(2)]);
        assert_eq!(p.standing(NOW), Standing::Live);
        let hash: Vec<u8> = store.db().query_row("SELECT key_hash FROM packages", [], |row| row.get(0)).unwrap();
        assert_eq!(hash, key_hash(&key));
        let dumped: String = store
            .db()
            .query_row("SELECT group_concat(id || label || granted, '') FROM packages", [], |row| row.get(0))
            .unwrap();
        assert!(!dumped.contains(&key));
        // Another package is another id and another key.
        let (other, other_key) = store.grant(1, 0, &[a(3)], "", NOW).unwrap();
        assert!(other != id && other_key != key);
        assert_eq!(store.package(&other).unwrap().unwrap().until, 0);
    }

    #[test]
    fn an_address_is_in_one_live_package_at_a_time() {
        let store = Store::in_memory();
        let (first, _) = store.grant(1000, 1, &[a(1)], "", NOW).unwrap();
        assert_eq!(store.grant(1000, 1, &[a(2), a(1)], "", NOW), Err(Refused::Elsewhere(a(1))));
        assert_eq!(store.packages().unwrap().len(), 1, "a refused grant leaves nothing behind");
        let (second, _) = store.grant(1000, 1, &[a(2)], "", NOW).unwrap();
        assert_eq!(store.set_members(&second, &[a(2), a(1)], NOW), Err(Refused::Elsewhere(a(1))));
        assert_eq!(store.package(&second).unwrap().unwrap().members, vec![a(2)], "nothing changed");
        // Once the first is over, its member may be moved.
        assert_eq!(store.set_members(&second, &[a(2), a(1)], NOW + 86_400), Ok(()));
        assert!(store.package(&first).unwrap().unwrap().members.is_empty());
        assert_eq!(store.package_of(a(1)).unwrap().unwrap().id, second);
        // And once a package is revoked, too.
        store.revoke(&second).unwrap();
        let (third, _) = store.grant(1000, 0, &[a(1)], "", NOW).unwrap();
        assert_eq!(store.package_of(a(1)).unwrap().unwrap().id, third);
        assert_eq!(store.set_members(&third, &[a(5), a(5)], NOW), Err(Refused::Members));
        let many: Vec<Ipv6Addr> = (10..10 + MAX_MEMBERS as u16 + 1).map(a).collect();
        assert_eq!(store.set_members(&third, &many, NOW), Err(Refused::Members));
        assert_eq!(store.set_members("p0000000000000000", &[a(9)], NOW), Err(Refused::NoPackage));
    }

    #[test]
    fn a_package_stands_by_its_bytes_its_time_and_the_operator() {
        let store = Store::in_memory();
        let (id, _) = store.grant(1000, 1, &[a(1)], "", NOW).unwrap();
        store.fold_usage(&id, 400, 500).unwrap();
        store.fold_usage(&id, 100, 100).unwrap();
        let p = store.package(&id).unwrap().unwrap();
        assert_eq!((p.used_in, p.used_out, p.left()), (400, 500, 100), "counts only grow");
        assert_eq!(p.standing(NOW), Standing::Live);
        assert_eq!(p.standing(NOW + 86_400), Standing::Over);
        store.fold_usage(&id, 500, 500).unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().standing(NOW), Standing::UsedUp);
        store.top_up(&id, 1000, 0, NOW).unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().standing(NOW), Standing::Live);
        // More days: from its end, or from now once that has passed.
        store.top_up(&id, 0, 2, NOW).unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().until, NOW + 3 * 86_400);
        assert_eq!(store.top_up(&id, 500, 0, NOW + 10 * 86_400), Err(Refused::Over), "bytes alone, when it is over");
        store.top_up(&id, 0, 1, NOW + 10 * 86_400).unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().until, NOW + 11 * 86_400);
        store.revoke(&id).unwrap();
        assert_eq!(store.package(&id).unwrap().unwrap().standing(NOW), Standing::Revoked);
        assert_eq!(store.revoke("p0000000000000000"), Err(Refused::NoPackage));
        assert_eq!(store.top_up(&id, MAX_BYTES, 0, NOW), Err(Refused::TooMuch));
        assert_eq!(store.grant(0, 1, &[a(7)], "", NOW), Err(Refused::TooMuch));
        assert_eq!(store.grant(MAX_BYTES + 1, 1, &[a(7)], "", NOW), Err(Refused::TooMuch));
    }

    #[test]
    fn a_key_finds_its_package_and_an_address_may_move_itself() {
        let store = Store::in_memory();
        let (first, first_key) = store.grant(1000, 0, &[a(1)], "", NOW).unwrap();
        let (second, second_key) = store.grant(1000, 0, &[a(2)], "", NOW).unwrap();
        assert_eq!(store.package_with_key(&first_key).unwrap().unwrap().id, first);
        assert_eq!(store.package_with_key(&second_key).unwrap().unwrap().id, second);
        for wrong in ["", "00", &first_key[..63], &format!("{first_key}0"), &first_key.to_uppercase()] {
            assert_eq!(store.package_with_key(wrong).unwrap(), None, "{wrong:?}");
        }
        // Whoever holds the second key cannot take a(1) from the first, live
        // package; a(1) itself, asking, can move.
        assert_eq!(store.set_members_for(&second, &[a(2), a(1)], NOW, None), Err(Refused::Elsewhere(a(1))));
        assert_eq!(store.set_members_for(&second, &[a(2), a(1)], NOW, Some(a(3))), Err(Refused::Elsewhere(a(1))));
        assert_eq!(store.set_members_for(&second, &[a(2), a(1)], NOW, Some(a(1))), Ok(()));
        assert_eq!(store.package_of(a(1)).unwrap().unwrap().id, second);
        assert!(store.package(&first).unwrap().unwrap().members.is_empty());
        // And an address can always leave, whoever put it there.
        assert_eq!(store.leave(a(1)), Ok(Some(second.clone())));
        assert_eq!(store.package_of(a(1)).unwrap(), None);
        assert_eq!(store.leave(a(1)), Ok(None));
        assert_eq!(store.package(&second).unwrap().unwrap().members, vec![a(2)]);
    }

    #[test]
    fn the_store_outlives_the_service() {
        let dir = std::env::temp_dir().join(format!("fips-exit-payd-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payd.db");
        let id = {
            let store = Store::open(&path).unwrap();
            let (id, _) = store.grant(5000, 0, &[a(1)], "kept", NOW).unwrap();
            store.fold_usage(&id, 10, 20).unwrap();
            id
        };
        let store = Store::open(&path).unwrap();
        let p = store.package(&id).unwrap().unwrap();
        assert_eq!((p.used_in, p.used_out, p.label.as_str(), p.members.clone()), (10, 20, "kept", vec![a(1)]));
        let version: i64 = store.db().pragma_query_value(None, "user_version", |row| row.get(0)).unwrap();
        assert_eq!(version, SCHEMA.len() as i64);
        // A name, kept too.
        store.remember(a(1), "npub1kept").unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.name_of(a(1)), "npub1kept");
        assert_eq!(store.name_of(a(2)), a(2).to_string());
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
