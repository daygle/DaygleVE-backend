//! A tiny persistent JSON record store.
//!
//! libvirt and LXC persist the *domain/container* themselves, but DaygleVE also
//! keeps its own structured view of each resource (the exact `Vm`/`Lxc`/`Bridge`
//! the API returns, including fields the host tools don't round-trip cleanly).
//! Those records live as one JSON file per id under `<state_dir>/<kind>/`, so
//! they survive a backend restart. Live state (running/stopped, link up/down)
//! is always overlaid from the host at read time — this store holds intent and
//! metadata, not liveness.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::fs;

use crate::error::{ApiResult, AppError};

/// A directory of `<id>.json` records of a single resource kind.
pub struct JsonStore {
    dir: PathBuf,
}

impl JsonStore {
    /// A store rooted at `<state_dir>/<kind>`.
    pub fn new(state_dir: &std::path::Path, kind: &str) -> Self {
        Self {
            dir: state_dir.join(kind),
        }
    }

    /// Build the record path for `id`, refusing any id that could escape the
    /// store directory (allowlist-validated via [`ensure_safe_id`]).
    fn path_for(&self, id: &str) -> ApiResult<PathBuf> {
        crate::services::ensure_safe_id(id)?;
        // Defence in depth: the record must be a single filename component, so
        // reject anything the OS would read as a nested path or traversal.
        let file = format!("{id}.json");
        if Path::new(&file).file_name() != Some(OsStr::new(file.as_str())) {
            return Err(AppError::validation(format!("invalid resource id: {id:?}")));
        }
        Ok(self.dir.join(file))
    }

    async fn ensure_dir(&self) -> ApiResult<()> {
        fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", self.dir.display())))
    }

    /// Write (or overwrite) the record for `id`.
    pub async fn put<T: Serialize>(&self, id: &str, value: &T) -> ApiResult<()> {
        self.ensure_dir().await?;
        let path = self.path_for(id)?;
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| AppError::internal(format!("serialize record: {e}")))?;
        // Atomic write: write a temp file then rename over the target, so a
        // crash or full disk mid-write never leaves a truncated record that
        // would break get/list — readers see either the old or new file.
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, bytes)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", tmp.display())))?;
        fs::rename(&tmp, &path)
            .await
            .map_err(|e| AppError::internal(format!("rename into {}: {e}", path.display())))
    }

    /// Read the record for `id`, or `None` if it does not exist.
    pub async fn get<T: DeserializeOwned>(&self, id: &str) -> ApiResult<Option<T>> {
        let path = self.path_for(id)?;
        match fs::read(&path).await {
            Ok(bytes) => {
                let value = serde_json::from_slice(&bytes)
                    .map_err(|e| AppError::internal(format!("parse {}: {e}", path.display())))?;
                Ok(Some(value))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AppError::internal(format!("read {}: {e}", path.display()))),
        }
    }

    /// Remove the record for `id`; returns whether a record existed.
    pub async fn delete(&self, id: &str) -> ApiResult<bool> {
        let path = self.path_for(id)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(AppError::internal(format!(
                "remove {}: {e}",
                path.display()
            ))),
        }
    }

    /// Read every record in the store (order unspecified).
    pub async fn list<T: DeserializeOwned>(&self) -> ApiResult<Vec<T>> {
        let mut out = Vec::new();
        let mut entries = match fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(AppError::internal(format!(
                    "read_dir {}: {e}",
                    self.dir.display()
                )))
            }
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AppError::internal(format!("read_dir entry: {e}")))?
        {
            let entry_path = entry.path();
            if entry_path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // Only read files whose stem is a valid id, and read them through
            // the sanitized path builder rather than the raw dir entry.
            let Some(stem) = entry_path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let path = match self.path_for(stem) {
                Ok(path) => path,
                Err(_) => continue,
            };
            let bytes = fs::read(&path)
                .await
                .map_err(|e| AppError::internal(format!("read {}: {e}", path.display())))?;
            let value = serde_json::from_slice(&bytes)
                .map_err(|e| AppError::internal(format!("parse {}: {e}", path.display())))?;
            out.push(value);
        }
        Ok(out)
    }
}
