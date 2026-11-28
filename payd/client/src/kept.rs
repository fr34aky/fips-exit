//! What this program keeps from one run to the next, for each exit: the
//! orders it made there, and the keys of the packages it bought.
//!
//! An order paid by invoice or on the chain is reached again by its name
//! only, and a package is managed by its key only: neither can be asked of
//! the exit by a node that has lost it. So both are written down, in a
//! file that is its owner's alone, for whoever has a package's key
//! manages the package.
//!
//! ```text
//! { "package": "p…",                                   the package used here when none is named
//!   "keys":    [ { "package": "p…", "key": "…" } ],     a key for each package, the newest last
//!   "orders":  [ { "order": "o…", "method", "package": <what was ordered>, "sat", "at" } ] }
//! ```

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::show::{is_key, is_order_id, is_package_id};

/// How many orders are remembered for an exit, and how many keys: the
/// newest.
const ORDERS: usize = 20;
const KEYS: usize = 32;

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

    /// What is kept for `npub`: an object, empty where there is no file.
    /// A file that is there and cannot be read as one is said, not taken
    /// for nothing.
    fn load(&self, npub: &str) -> Result<Value, String> {
        let Some(file) = self.file(npub) else { return Ok(json!({})) };
        let odd = |why: String| format!("{} is not what this program keeps ({why})", file.display());
        match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| odd(e.to_string()))
                .and_then(|kept| if kept.is_object() { Ok(kept) } else { Err(odd("no object".into())) }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
            Err(e) => Err(odd(e.to_string())),
        }
    }

    /// What is kept for `npub`, to be read: nothing where there is nothing
    /// that can be.
    pub fn read(&self, npub: &str) -> Value {
        self.load(npub).unwrap_or_else(|_| json!({}))
    }

    /// The key kept for `package` at `npub`.
    pub fn key_of(&self, npub: &str, package: &str) -> Option<String> {
        let kept = self.read(npub);
        let keys = kept["keys"].as_array()?;
        let key = keys.iter().rev().find(|kept| kept["package"] == package)?["key"].as_str()?;
        is_key(key).then(|| key.to_string())
    }

    /// The package used at `npub` when none is named, and its key.
    pub fn key(&self, npub: &str) -> Option<(String, String)> {
        let package = self.read(npub)["package"].as_str().filter(|id| is_package_id(id))?.to_string();
        let key = self.key_of(npub, &package)?;
        Some((package, key))
    }

    /// The order `id` as it was kept at `npub`, when it was made.
    pub fn order(&self, npub: &str, id: &str) -> Option<Value> {
        self.read(npub)["orders"].as_array()?.iter().rev().find(|kept| kept["order"] == id).cloned()
    }

    /// The newest order kept for `npub`.
    pub fn last_order(&self, npub: &str) -> Option<String> {
        let kept = self.read(npub);
        let id = kept["orders"].as_array()?.last()?["order"].as_str()?;
        is_order_id(id).then(|| id.to_string())
    }

    /// Keep for `npub` what `change` makes of what is kept. The file it is
    /// in: its owner's alone, and whole or not there. One run at a time:
    /// what another keeps meanwhile is not lost.
    fn change(&self, npub: &str, change: impl FnOnce(&mut Value)) -> Result<PathBuf, String> {
        let dir = self.dir.as_ref().ok_or("there is nowhere to keep it (no HOME): name a directory with --state")?;
        let file = dir.join(format!("{npub}.json"));
        let failed = |what: &Path, e: std::io::Error| format!("{}: {e}", what.display());
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).map_err(|e| failed(dir, e))?;
        let lock = dir.join(".lock");
        let held = std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(&lock);
        let held = held.map_err(|e| failed(&lock, e))?;
        held.lock().map_err(|e| failed(&lock, e))?;
        // A file that is there and is not this program's is left as it is.
        let mut kept = self.load(npub).map_err(|why| format!("{why}: it is left as it is"))?;
        change(&mut kept);
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

    /// Keep `key` as the key of `package` at `npub`, and have that package
    /// be the one used there. The file, and the package that was used
    /// there before if it was another: its key is kept still.
    pub fn keep_key(&self, npub: &str, package: &str, key: &str) -> Result<(PathBuf, Option<String>), String> {
        let mut before = None;
        let file = self.change(npub, |kept| {
            before = kept["package"].as_str().filter(|id| *id != package && is_package_id(id)).map(str::to_string);
            let mut keys: Vec<Value> = kept["keys"].as_array().cloned().unwrap_or_default();
            keys.retain(|kept| kept["package"] != package);
            keys.push(json!({ "package": package, "key": key }));
            let from = keys.len().saturating_sub(KEYS);
            kept["keys"] = Value::Array(keys.split_off(from));
            kept["package"] = json!(package);
        })?;
        Ok((file, before))
    }

    /// Keep that order `order` was made at `npub`: `made` is how it is
    /// paid, what was ordered, and its price in sat. At `now`.
    pub fn keep_order(&self, npub: &str, order: &str, made: (&str, &str, u64), now: u64) -> Result<PathBuf, String> {
        let (method, offer, sat) = made;
        self.change(npub, |kept| {
            let mut orders: Vec<Value> = kept["orders"].as_array().cloned().unwrap_or_default();
            orders.retain(|kept| kept["order"] != order);
            orders.push(json!({ "order": order, "method": method, "package": offer, "sat": sat, "at": now }));
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

    const A: &str = "p00000000000000aa";
    const B: &str = "p00000000000000bb";

    #[test]
    fn what_is_kept_is_its_owners_alone_and_read_again() {
        let dir = scratch("kept").join("state/fips-exit-pay");
        let kept = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!((kept.key("npub1x"), kept.last_order("npub1x")), (None, None));
        let key = "ab".repeat(32);
        let (file, before) = kept.keep_key("npub1x", A, &key).unwrap();
        assert_eq!((file.clone(), before), (dir.join("npub1x.json"), None));
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        kept.keep_order("npub1x", "o0000000000000001", ("bolt11", "1gb", 1500), 1000).unwrap();
        kept.keep_order("npub1x", "o0000000000000002", ("onchain", "5gb", 6000), 2000).unwrap();
        // An order kept again is kept once, as the newest.
        kept.keep_order("npub1x", "o0000000000000001", ("bolt11", "1gb", 1500), 3000).unwrap();
        let again = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!(again.key("npub1x"), Some((A.to_string(), key.clone())));
        assert_eq!(again.last_order("npub1x").as_deref(), Some("o0000000000000001"));
        assert_eq!(again.read("npub1x")["orders"].as_array().unwrap().len(), 2);
        assert_eq!(again.order("npub1x", "o0000000000000002").unwrap()["sat"], 6000);
        assert_eq!(again.key("npub1y"), None, "an exit's own");
        // Another package's key: that one is used from now on, and the
        // first is kept still.
        let other = "cd".repeat(32);
        assert_eq!(kept.keep_key("npub1x", B, &other).unwrap().1.as_deref(), Some(A));
        assert_eq!(kept.key("npub1x"), Some((B.to_string(), other.clone())));
        assert_eq!(kept.key_of("npub1x", A), Some(key));
        // A new key for a package takes the place of its key, and no other's.
        let new = "ef".repeat(32);
        assert_eq!(kept.keep_key("npub1x", B, &new).unwrap().1, None);
        assert_eq!((kept.key_of("npub1x", B), kept.read("npub1x")["keys"].as_array().unwrap().len()), (Some(new), 2));
        // The newest twenty orders, and no file but the one and its lock.
        for n in 0..30 {
            kept.keep_order("npub1x", &format!("o{n:016x}"), ("bolt11", "1gb", 1500), n).unwrap();
        }
        assert_eq!(kept.read("npub1x")["orders"].as_array().unwrap().len(), ORDERS);
        assert_eq!(kept.last_order("npub1x").as_deref(), Some("o000000000000001d"));
        let mut there: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        there.sort();
        assert_eq!(there, [".lock", "npub1x.json"]);
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
        assert!(nowhere.keep_key("npub1x", A, &"ab".repeat(32)).unwrap_err().contains("--state"));
    }

    #[test]
    fn a_file_that_is_not_this_programs_is_neither_believed_nor_written_over() {
        let dir = scratch("odd");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("npub1x.json");
        // What is in it and is no key, no package or no order is not taken for one.
        let odd = "{\"package\": \"../x\", \"keys\": [{\"package\": \"../x\", \"key\": \"\\u001b[2J\"}], \"orders\": [{\"order\": \"../x\"}]}";
        std::fs::write(&file, odd).unwrap();
        let kept = Kept::at(Some(dir.to_str().unwrap()), &|_| None);
        assert_eq!((kept.key("npub1x"), kept.key_of("npub1x", "../x"), kept.last_order("npub1x")), (None, None, None));
        // What is no JSON (a hand slipped while editing it) is read as
        // nothing, and is not written over: the key in it is not lost.
        let slipped = format!(
            "{{\"package\": \"{A}\", \"keys\": [{{\"package\": \"{A}\", \"key\": \"{}\"}},]}}",
            "ab".repeat(32)
        );
        std::fs::write(&file, &slipped).unwrap();
        assert_eq!(kept.read("npub1x"), json!({}));
        let refused = kept.keep_order("npub1x", "o0000000000000001", ("bolt11", "1gb", 1500), 1).unwrap_err();
        assert!(refused.contains("is not what this program keeps") && refused.contains("left as it is"), "{refused}");
        assert!(kept.keep_key("npub1x", B, &"cd".repeat(32)).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), slipped);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
