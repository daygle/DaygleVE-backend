//! A tiny persistent JSON record store.
//!
//! libvirt and LXC persist the *domain/container* themselves, but DaygleVE also
//! keeps its own structured view of each resource (the exact `Vm`/`Lxc`/`Bridge`
//! the API returns, including fields the host tools don't round-trip cleanly).
//! Those records live as one JSON file per id under `<state_dir>/<kind>/`, so
//! they survive a backend restart. Live state (running/stopped, link up/down)
//! is always overlaid from the host at read time — this store holds intent and
//! metadata, not liveness.
//!
//! The store directory ultimately derives from a configured environment
//! variable (`DAYGLEVE_STATE_DIR`), so it is never used as a filesystem path
//! directly: [`JsonStore::resolve_dir`] canonicalizes the nearest existing
//! ancestor and re-appends each remaining component as a validated single name,
//! and record ids pass through [`join_component`]. That canonicalize + per-name
//! check is the traversal barrier that keeps configuration- and request-derived
//! strings from reaching a filesystem sink with path structure intact.

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

    /// Resolve the store directory to a canonical, filesystem-derived path,
    /// creating it when `create` is set.
    ///
    /// The configured location comes from an environment variable, so it must
    /// not reach a filesystem sink untrusted: we canonicalize the nearest
    /// ancestor that already exists (yielding a path derived from the
    /// filesystem, not the configuration) and re-append each still-missing
    /// component through [`join_component`], which admits only a single plain
    /// name. Returns `None` — not an error — when the directory is absent and
    /// `create` is false, so reads on a fresh node are simply empty.
    async fn resolve_dir(&self, create: bool) -> ApiResult<Option<PathBuf>> {
        // Walk up to the nearest ancestor that already exists, recording the
        // components we skipped over so they can be re-validated and re-appended.
        let mut ancestor = self.dir.as_path();
        let mut tail: Vec<&OsStr> = Vec::new();
        while fs::metadata(ancestor).await.is_err() {
            match (ancestor.parent(), ancestor.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name);
                    ancestor = parent;
                }
                // Reached the filesystem root without finding an existing dir.
                _ => {
                    if !create {
                        return Ok(None);
                    }
                    break;
                }
            }
        }
        let mut dir = match fs::canonicalize(ancestor).await {
            Ok(base) => base,
            Err(_) if !create => return Ok(None),
            Err(e) => {
                return Err(AppError::internal(format!(
                    "store directory unavailable: {e}"
                )))
            }
        };
        for name in tail.iter().rev() {
            let name = name
                .to_str()
                .ok_or_else(|| AppError::internal("invalid store directory component"))?;
            dir = join_component(&dir, name)?;
        }
        if create {
            fs::create_dir_all(&dir)
                .await
                .map_err(|e| AppError::internal(format!("create {}: {e}", dir.display())))?;
        } else if fs::metadata(&dir).await.is_err() {
            return Ok(None);
        }
        Ok(Some(dir))
    }

    /// Path of the record file for `id` inside the canonical store directory, or
    /// `None` when the directory is absent and `create` is false.
    async fn record_path(&self, id: &str, create: bool) -> ApiResult<Option<PathBuf>> {
        // Validate the id (allowlist) before it is used to build a filename.
        let id = crate::services::ensure_safe_id(id)?;
        let file = format!("{id}.json");
        match self.resolve_dir(create).await? {
            Some(dir) => Ok(Some(join_component(&dir, &file)?)),
            None => Ok(None),
        }
    }

    /// Write (or overwrite) the record for `id`.
    pub async fn put<T: Serialize>(&self, id: &str, value: &T) -> ApiResult<()> {
        let path = self
            .record_path(id, true)
            .await?
            .ok_or_else(|| AppError::internal("store directory unavailable"))?;
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
        let path = match self.record_path(id, false).await? {
            Some(path) => path,
            None => return Ok(None),
        };
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
        let path = match self.record_path(id, false).await? {
            Some(path) => path,
            None => return Ok(false),
        };
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
        let dir = match self.resolve_dir(false).await? {
            Some(dir) => dir,
            None => return Ok(out),
        };
        let mut entries = match fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(AppError::internal(format!(
                    "read_dir {}: {e}",
                    dir.display()
                )))
            }
        };
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| AppError::internal(format!("read_dir entry: {e}")))?
        {
            // `entry.path()` is the canonical `dir` joined with a name the
            // filesystem itself supplied, so it carries no configuration or
            // request taint — read it directly.
            let entry_path = entry.path();
            if entry_path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            // Only surface files whose stem is a valid id; ignore stray files.
            let valid_stem = entry_path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|stem| crate::services::ensure_safe_id(stem).is_ok())
                .unwrap_or(false);
            if !valid_stem {
                continue;
            }
            let bytes = fs::read(&entry_path)
                .await
                .map_err(|e| AppError::internal(format!("read {}: {e}", entry_path.display())))?;
            // Skip (don't fail the whole listing on) a single unparseable record:
            // one corrupt or schema-incompatible file must not take down every
            // record of this kind — which for the operations store would also
            // break startup recovery. The bad file is logged and left in place.
            match serde_json::from_slice(&bytes) {
                Ok(value) => out.push(value),
                Err(e) => {
                    tracing::warn!(path = %entry_path.display(), error = %e, "skipping unparseable record");
                }
            }
        }
        Ok(out)
    }
}

/// Join `name` onto `dir`, accepting only a single plain filename component
/// (no separators, no traversal). Building the path from the `file_name()`
/// output — after canonicalizing `dir` — is the traversal barrier static
/// analysis recognises.
fn join_component(dir: &Path, name: &str) -> ApiResult<PathBuf> {
    match Path::new(name).file_name() {
        Some(component) if component == OsStr::new(name) => Ok(dir.join(component)),
        _ => Err(AppError::validation(format!(
            "invalid record name: {name:?}"
        ))),
    }
}
