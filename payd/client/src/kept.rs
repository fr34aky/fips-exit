//! What this program keeps from one run to the next, for each exit: the
//! orders it made there, and the key of the package it bought.
//!
//! An order paid by invoice or on the chain is reached again by its name
//! only, and a package is managed by its key only: neither can be asked of
//! the exit by a node that has lost it. So both are written down, in a
//! file that is its owner's alone, for whoever has a package's key
//! manages the package.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

/// How many orders are remembered for an exit: the newest.
const ORDERS: usize = 20;

/// Where things are kept, if anywhere.
#[derive(Debug, Clone, PartialEq)]
pub struct Kept {
    dir: Option<PathBuf>,
}

impl Kept {
    /// In `named`, the directory the caller named; or in the user's own
    /// state directory (`$XDG_STATE_HOME`, else `~/.local/state`). Nowhere
    /// if there is none of those.
    pub fn at(named: Option<&str>, env: &dyn Fn(&str) -> Option<String>) -> Kept {
        let absolute = |path: String| Some(PathBuf::from(path)).filter(|path| path.is_absolute());
        let dir = match named {
            Some(dir) => Some(PathBuf::from(dir)),
            None => env("XDG_STATE_HOME")
                .and_then(absolute)
                .or_else(|| env("HOME").and_then(absolute).map(|home| home.join(".local/state")))
                .map(|state| state.join("fips-exit-pay")),
        };
        Kept { dir }
    }

    /// The file of the exit `npub`, which is an npub: letters and digits.
    pub fn file(&self, npub: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|dir| dir.join(format!("{npub}.json")))
    }

    /// What is kept for `npub`: an object, empty where there is nothing or
    /// nothing that can be read.
    pub fn read(&self, npub: &str) -> Value {
        self.file(npub)
            .and_then(|file| std::fs::read(file).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}))
    }

    /// The key kept for `npub`, if there is one.
    pub fn key(&self, npub: &str) -> Option<String> {
        self.read(npub)["key"].as_str().filter(|key| crate::show::is_key(key)).map(str::to_string)
    }

    /// The newest order kept for `npub`.
    pub fn last_order(&self, npub: &str) -> Option<String> {
        let kept = self.read(npub);
        let id = kept["orders"].as_array()?.last()?["order"].as_str()?;
        crate::show::is_order_id(id).then(|| id.to_string())
    }

    /// Keep for `npub` what `change` makes of what is kept. The file it is
    /// in: its owner's alone, and whole or not there.
    fn change(&self, npub: &str, change: impl FnOnce(&mut Value)) -> Result<PathBuf, String> {
        let dir = self.dir.as_ref().ok_or("there is nowhere to keep it (no HOME): name a directory with --state")?;
        let file = dir.join(format!("{npub}.json"));
        let mut kept = self.read(npub);
        change(&mut kept);
        let failed = |what: &Path, e: std::io::Error| format!("{}: {e}", what.display());
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| failed(dir, e))?;
        let new = dir.join(format!(".{npub}.json.{}", std::process::id()));
        let written = (|| {
            let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&new)?;
            // A file left by a run that died is this user's, and may be
            // wider than it should: narrowed before anything is in it.
            out.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            out.write_all(serde_json::to_string_pretty(&kept).unwrap_or_default().as_bytes())?;
            out.write_all(b"\n")?;
            out.sync_all()?;
            std::fs::rename(&new, &file)
        })();
        written.map_err(|e| {
            let _ = std::fs::remove_file(&new);
            failed(&file, e)
        })?;
        Ok(file)
    }

    /// Keep the key of package `package` at `npub`: the one before it is
    /// no key any more.
    pub fn keep_key(&self, npub: &str, package: &str, key: &str) -> Result<PathBuf, String> {
        self.change(npub, |kept| {
            kept["key"] = json!(key);
            kept["package"] = json!(package);
        })
    }

    /// Keep that order `order` was made at `npub`, paid by `method`, for
    /// `offer`, at `now`.
    pub fn keep_order(&self, npub: &str, order: &str, method: &str, offer: &str, now: u64) -> Result<PathBuf, String> {
        self.change(npub, |kept| {
            let mut orders: Vec<Value> = kept["orders"].as_array().cloned().unwrap_or_default();
            orders.retain(|kept| kept["order"] != order);
            orders.push(json!({ "order": order, "method": method, "package": offer, "at": now }));
            let from = orders.len().saturating_sub(ORDERS);
            kept["orders"] = Value::Array(orders.split_off(from));
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fips-exit-pay-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn what_is_kept_is_its_owners_alone_and_read_again() {
        let dir = scratch("kept").join("state/fips-exit-pay");
        let kept = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!((kept.key("npub1x"), kept.last_order("npub1x")), (None, None));
        let key = "ab".repeat(32);
        let file = kept.keep_key("npub1x", "p0123456789abcdef", &key).unwrap();
        assert_eq!(file, dir.join("npub1x.json"));
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        kept.keep_order("npub1x", "o0000000000000001", "bolt11", "1gb", 1000).unwrap();
        kept.keep_order("npub1x", "o0000000000000002", "onchain", "5gb", 2000).unwrap();
        // An order kept again is kept once, as the newest.
        kept.keep_order("npub1x", "o0000000000000001", "bolt11", "1gb", 3000).unwrap();
        let again = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!(again.key("npub1x"), Some(key));
        assert_eq!(again.last_order("npub1x").as_deref(), Some("o0000000000000001"));
        assert_eq!(again.read("npub1x")["orders"].as_array().unwrap().len(), 2);
        assert_eq!(again.key("npub1y"), None, "an exit's own");
        // The newest twenty, and no file but the one.
        for n in 0..30 {
            kept.keep_order("npub1x", &format!("o{n:016x}"), "bolt11", "1gb", n).unwrap();
        }
        assert_eq!(kept.read("npub1x")["orders"].as_array().unwrap().len(), ORDERS);
        assert_eq!(kept.last_order("npub1x").as_deref(), Some("o000000000000001d"));
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = scratch("kept");
    }

    #[test]
    fn where_things_are_kept() {
        let env = |home: Option<&'static str>, state: Option<&'static str>| {
            move |name: &str| match name {
                "HOME" => home.map(str::to_string),
                "XDG_STATE_HOME" => state.map(str::to_string),
                _ => None,
            }
        };
        let file = |kept: Kept| kept.file("npub1x").map(|file| file.to_string_lossy().to_string());
        assert_eq!(
            file(Kept::at(None, &env(Some("/home/a"), None))).unwrap(),
            "/home/a/.local/state/fips-exit-pay/npub1x.json"
        );
        assert_eq!(file(Kept::at(None, &env(Some("/home/a"), Some("/s")))).unwrap(), "/s/fips-exit-pay/npub1x.json");
        assert_eq!(
            file(Kept::at(None, &env(Some("/home/a"), Some("relative")))).unwrap(),
            "/home/a/.local/state/fips-exit-pay/npub1x.json"
        );
        assert_eq!(file(Kept::at(Some("/k"), &env(None, None))).unwrap(), "/k/npub1x.json");
        // Nowhere: nothing is read, and keeping says why not.
        let nowhere = Kept::at(None, &env(None, None));
        assert_eq!(file(nowhere.clone()), None);
        assert_eq!(nowhere.key("npub1x"), None);
        assert!(nowhere.keep_key("npub1x", "p1", &"ab".repeat(32)).unwrap_err().contains("--state"));
        // What is in the file and is no key or no order is not taken for one.
        let dir = scratch("odd");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("npub1x.json"), "{\"key\": \"\\u001b[2J\", \"orders\": [{\"order\": \"../x\"}]}")
            .unwrap();
        let odd = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!((odd.key("npub1x"), odd.last_order("npub1x")), (None, None));
        std::fs::write(dir.join("npub1x.json"), "not json").unwrap();
        assert_eq!(odd.read("npub1x"), json!({}));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
