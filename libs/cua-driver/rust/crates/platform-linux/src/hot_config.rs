// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Reusable `mtime + len` hot-reload cache for JSON configuration files under
//! `~/.config/cua-ycwang/` (`dialog_rules.json`, `webview_probes.json`, etc.).

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    modified_ns: Option<u128>,
    len: u64,
}

fn read_file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let modified_ns = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());
    Some(FileStamp {
        modified_ns,
        len: meta.len(),
    })
}

struct CachedConfig<T> {
    path: PathBuf,
    stamp: FileStamp,
    value: Arc<T>,
}

/// Process-lifetime hot-reload cache keyed by `(path, mtime_ns, byte_len)`.
pub struct HotJsonCache<T> {
    inner: RwLock<Option<CachedConfig<T>>>,
}

impl<T> Default for HotJsonCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> HotJsonCache<T> {
    pub const fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    pub fn invalidate(&self) {
        if let Ok(mut guard) = self.inner.write() {
            *guard = None;
        }
    }
}

impl<T: DeserializeOwned> HotJsonCache<T> {
    /// Load `path` from disk or reuse the cached value when `path`, `mtime`,
    /// and `len` are unchanged. Returns `Ok(None)` when the file does not exist.
    pub fn get_or_load(&self, path: &Path) -> Result<Option<Arc<T>>> {
        let Some(stamp) = read_file_stamp(path) else {
            self.invalidate();
            return Ok(None);
        };

        if let Ok(guard) = self.inner.read() {
            if let Some(cached) = guard.as_ref() {
                if cached.path == path && cached.stamp == stamp {
                    return Ok(Some(Arc::clone(&cached.value)));
                }
            }
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let parsed: T = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse JSON config {}", path.display()))?;
        let value = Arc::new(parsed);

        if let Ok(mut guard) = self.inner.write() {
            *guard = Some(CachedConfig {
                path: path.to_path_buf(),
                stamp,
                value: Arc::clone(&value),
            });
        }
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SampleCfg {
        version: u32,
        label: String,
    }

    #[test]
    fn reloads_when_mtime_or_len_changes_and_clears_when_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.json");
        let cache = HotJsonCache::<SampleCfg>::new();

        assert!(cache.get_or_load(&path).unwrap().is_none());

        std::fs::write(&path, r#"{"version":1,"label":"alpha"}"#).unwrap();
        let first = cache.get_or_load(&path).unwrap().unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(first.label, "alpha");

        let cached = cache.get_or_load(&path).unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &cached));

        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(&path, r#"{"version":2,"label":"beta-updated"}"#).unwrap();
        let second = cache.get_or_load(&path).unwrap().unwrap();
        assert_eq!(second.version, 2);
        assert_eq!(second.label, "beta-updated");
        assert!(!Arc::ptr_eq(&first, &second));

        std::fs::remove_file(&path).unwrap();
        assert!(cache.get_or_load(&path).unwrap().is_none());
    }
}
