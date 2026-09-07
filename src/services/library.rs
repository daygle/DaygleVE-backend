//! Local media library: uploaded install ISOs and LXC container-template
//! tarballs kept on the node's own storage.
//!
//! Files live under `config.iso_dir` (kind `iso`) and `config.template_dir`
//! (kind `ct_template`). These directories sit inside the backend's state area,
//! which the `daygleve` account already owns and writes (VM/container records,
//! backups), so uploads are performed directly rather than through the broker —
//! the broker mediates *host* mutation (libvirt/ZFS/PCI), not state-local file
//! writes.
//!
//! Every path is built from a validated bare file name (see
//! [`validate_library_filename`]): no separators, no `.`/`..`, no control bytes,
//! and an extension appropriate to the kind. Uploads stream to a
//! generated-name temporary file and are renamed into place only after the
//! whole body is written and within the size cap, so a failed or oversized
//! upload never leaves a half-written file masquerading as a usable image.

use std::path::{Path, PathBuf};

use daygleve_schema::storage_file::{StorageFile, StorageFileKind};
use futures::Stream;
use tokio::io::AsyncWriteExt;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::new_id;
use std::sync::Arc;

/// Allowed extensions for uploaded CT-template rootfs tarballs.
const CT_TEMPLATE_EXTENSIONS: &[&str] = &[
    ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tar.bz2",
];

/// Manages the node's local upload libraries.
#[derive(Clone)]
pub struct LibraryService {
    config: Arc<Config>,
}

impl LibraryService {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    /// Directory backing a given library kind.
    fn dir_for(&self, kind: StorageFileKind) -> &Path {
        match kind {
            StorageFileKind::Iso => &self.config.iso_dir,
            StorageFileKind::CtTemplate => &self.config.template_dir,
        }
    }

    /// Resolve a library directory to a filesystem-derived path.
    ///
    /// The configured directory can originate from an environment variable, so
    /// it is normalized before it reaches any filesystem sink: the parent is
    /// canonicalized (yielding a path derived from the filesystem, not the
    /// configuration) and the final component is re-validated through
    /// [`join_component`]. With `create` set the directory is created if missing;
    /// otherwise a missing directory (or parent) yields `Ok(None)` so listings
    /// on a fresh node are simply empty.
    async fn resolve_dir(&self, kind: StorageFileKind, create: bool) -> ApiResult<Option<PathBuf>> {
        let raw = self.dir_for(kind);
        let leaf = raw
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| AppError::internal("invalid library directory configuration"))?;
        let parent = raw.parent().unwrap_or_else(|| Path::new("/"));
        let canonical_parent = match tokio::fs::canonicalize(parent).await {
            Ok(p) => p,
            Err(_) if !create => return Ok(None),
            Err(e) => {
                return Err(AppError::internal(format!(
                    "library directory parent is unavailable: {e}"
                )))
            }
        };
        let dir = join_component(&canonical_parent, leaf)?;
        if create {
            tokio::fs::create_dir_all(&dir).await.map_err(|e| {
                AppError::internal(format!("could not create library directory: {e}"))
            })?;
        } else if tokio::fs::metadata(&dir).await.is_err() {
            return Ok(None);
        }
        Ok(Some(dir))
    }

    /// Enumerate the files in one local library. A missing directory yields an
    /// empty list rather than an error (a fresh node simply has nothing yet).
    pub async fn list(&self, kind: StorageFileKind) -> ApiResult<Vec<StorageFile>> {
        let mut out = Vec::new();
        let dir = match self.resolve_dir(kind, false).await? {
            Some(d) => d,
            None => return Ok(out),
        };
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => return Ok(out),
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_type = match entry.file_type().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            // Regular files only; a symlink reports neither is_file here, so it
            // is skipped and can never point the library outside its directory.
            if !file_type.is_file() {
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            // Only surface files that match the library's naming rules; ignore
            // in-progress `.partial` uploads and anything unexpected.
            if validate_library_filename(&name, kind).is_err() {
                continue;
            }
            let meta = match entry.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            out.push(StorageFile {
                name,
                path: entry.path().to_string_lossy().into_owned(),
                size_bytes: meta.len(),
                kind,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Stream an upload to `<dir>/<name>`, creating the directory if needed.
    /// The body is written to a generated temporary file first and renamed into
    /// place only on success; exceeding [`Config::max_upload_bytes`] aborts and
    /// removes the partial file.
    pub async fn upload<S, B, E>(
        &self,
        kind: StorageFileKind,
        name: &str,
        mut stream: S,
    ) -> ApiResult<StorageFile>
    where
        S: Stream<Item = Result<B, E>> + Unpin,
        B: AsRef<[u8]>,
        E: std::fmt::Display,
    {
        let name = validate_library_filename(name, kind)?;

        // Resolve (and create) the library directory as a filesystem-derived
        // path, then place both the destination and the temporary file inside
        // it. The destination's file name is re-derived as a single path
        // component and confirmed equal to the request value (see
        // `join_component`), so no request-controlled string reaches a
        // filesystem sink except as a verified leaf inside the known-safe root.
        // The temp file's name is generated, never derived from the request.
        let base = self
            .resolve_dir(kind, true)
            .await?
            .expect("resolve_dir(create=true) yields Some");
        let final_path = join_component(&base, name)?;
        let partial_path: PathBuf = base.join(format!(".upload-{}.partial", new_id()));

        let max = self.config.max_upload_bytes;
        let mut file = tokio::fs::File::create(&partial_path)
            .await
            .map_err(|e| AppError::internal(format!("could not open upload target: {e}")))?;

        let mut written: u64 = 0;
        let result = async {
            use futures::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk =
                    chunk.map_err(|e| AppError::validation(format!("upload stream error: {e}")))?;
                let bytes = chunk.as_ref();
                written = written.saturating_add(bytes.len() as u64);
                if written > max {
                    return Err(AppError::validation(format!(
                        "upload exceeds the maximum size of {max} bytes"
                    )));
                }
                file.write_all(bytes)
                    .await
                    .map_err(|e| AppError::internal(format!("could not write upload: {e}")))?;
            }
            file.flush()
                .await
                .map_err(|e| AppError::internal(format!("could not flush upload: {e}")))?;
            Ok(())
        }
        .await;

        // Always drop the handle before renaming/removing the partial file.
        drop(file);

        if let Err(e) = result {
            let _ = tokio::fs::remove_file(&partial_path).await;
            return Err(e);
        }
        if written == 0 {
            let _ = tokio::fs::remove_file(&partial_path).await;
            return Err(AppError::validation("uploaded file is empty"));
        }

        tokio::fs::rename(&partial_path, &final_path)
            .await
            .map_err(|e| AppError::internal(format!("could not finalize upload: {e}")))?;

        Ok(StorageFile {
            name: name.to_string(),
            path: final_path.to_string_lossy().into_owned(),
            size_bytes: written,
            kind,
        })
    }

    /// Delete a file from a library. A missing file is a 404.
    ///
    /// The target is located by enumerating the library and matching the
    /// requested name, then removed by the path the directory listing produced —
    /// the request value is only ever compared, never joined into a filesystem
    /// path.
    pub async fn delete(&self, kind: StorageFileKind, name: &str) -> ApiResult<()> {
        let name = validate_library_filename(name, kind)?;
        let target = self
            .list(kind)
            .await?
            .into_iter()
            .find(|f| f.name == name)
            .ok_or_else(|| AppError::not_found("no such library file"))?;
        tokio::fs::remove_file(&target.path)
            .await
            .map_err(|e| AppError::internal(format!("could not delete file: {e}")))
    }

    /// Resolve an uploaded CT template file name to its absolute host path.
    ///
    /// Like [`Self::delete`], the path is taken from the directory listing (so
    /// the request value is only compared, never joined), which also confirms
    /// the file exists. Used by the LXC service when building a container rootfs
    /// from an uploaded template.
    pub async fn resolve_ct_template(&self, name: &str) -> ApiResult<PathBuf> {
        let name = validate_library_filename(name, StorageFileKind::CtTemplate)?;
        self.list(StorageFileKind::CtTemplate)
            .await?
            .into_iter()
            .find(|f| f.name == name)
            .map(|f| PathBuf::from(f.path))
            .ok_or_else(|| {
                AppError::validation(
                    "template_file is not an uploaded CT template (see GET /storage/ct-templates)",
                )
            })
    }
}

/// Join a request-supplied `name` into `dir` as a single, verified path
/// component.
///
/// `Path::file_name` strips any directory portion; requiring it to equal the
/// input rejects separators, `.`/`..` and any traversal, so only a normalized
/// leaf name is joined onto the (already canonicalized) directory. This is the
/// barrier that keeps request-controlled data from reaching a filesystem path
/// sink as anything but a checked leaf inside the known-safe root.
fn join_component(dir: &Path, name: &str) -> ApiResult<PathBuf> {
    match Path::new(name).file_name() {
        Some(component) if component == std::ffi::OsStr::new(name) => Ok(dir.join(component)),
        _ => Err(AppError::validation(format!("invalid file name: {name:?}"))),
    }
}

/// Validate a bare upload file name and return it unchanged on success.
///
/// Rejects empty names, `.`/`..`, anything containing a path separator or a
/// control byte, absurdly long names, and — per kind — a wrong extension. The
/// returned `&str` is the value callers build the on-disk path from, keeping
/// the barrier explicit to readers and taint analysis.
pub fn validate_library_filename(name: &str, kind: StorageFileKind) -> ApiResult<&str> {
    let bad = name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || name.bytes().any(|b| b.is_ascii_control());
    if bad {
        return Err(AppError::validation(format!("invalid file name: {name:?}")));
    }
    let lower = name.to_ascii_lowercase();
    let ext_ok = match kind {
        StorageFileKind::Iso => lower.ends_with(".iso"),
        StorageFileKind::CtTemplate => CT_TEMPLATE_EXTENSIONS
            .iter()
            .any(|ext| lower.ends_with(ext)),
    };
    if !ext_ok {
        return Err(AppError::validation(match kind {
            StorageFileKind::Iso => "ISO uploads must have a .iso extension".to_string(),
            StorageFileKind::CtTemplate => format!(
                "CT-template uploads must be a tarball ({})",
                CT_TEMPLATE_EXTENSIONS.join(", ")
            ),
        }));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames_are_validated_per_kind() {
        // Good.
        assert!(validate_library_filename("debian-13.iso", StorageFileKind::Iso).is_ok());
        assert!(validate_library_filename(
            "alpine-3.20-rootfs.tar.xz",
            StorageFileKind::CtTemplate
        )
        .is_ok());
        assert!(validate_library_filename("x.tgz", StorageFileKind::CtTemplate).is_ok());

        // Wrong extension for the kind.
        assert!(validate_library_filename("debian-13.iso", StorageFileKind::CtTemplate).is_err());
        assert!(validate_library_filename("rootfs.tar.xz", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("notes.txt", StorageFileKind::Iso).is_err());

        // Traversal / separators / hidden / control bytes.
        assert!(validate_library_filename("../etc/passwd.iso", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("a/b.iso", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("a\\b.iso", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename(".hidden.iso", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("bad\nname.iso", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("..", StorageFileKind::CtTemplate).is_err());
    }

    #[test]
    fn join_component_only_accepts_plain_leaf_names() {
        let dir = Path::new("/var/lib/daygleve/isos");
        assert_eq!(
            join_component(dir, "debian.iso").unwrap(),
            dir.join("debian.iso")
        );
        // Anything with a directory portion or traversal is rejected rather
        // than joined.
        assert!(join_component(dir, "../escape.iso").is_err());
        assert!(join_component(dir, "sub/child.iso").is_err());
        assert!(join_component(dir, "/etc/passwd").is_err());
        assert!(join_component(dir, "..").is_err());
        assert!(join_component(dir, "").is_err());
    }
}
