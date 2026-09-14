//! Local media library: uploaded install ISOs and LXC container-template
//! tarballs kept on the node's own storage.
//!
//! Files live under `config.iso_dir` (kind `iso`) and `config.template_dir`
//! (kind `ct_template`). These directories sit inside the backend's state area,
//! which the `daygleve` account already owns and writes (VM/container records,
//! backups), so uploads are performed directly rather than through the broker -
//! the broker mediates *host* mutation (libvirt/ZFS/PCI), not state-local file
//! writes.
//!
//! Every path is built from a validated bare file name (see
//! [`validate_library_filename`]): no separators, no `.`/`..`, no control bytes,
//! and an extension appropriate to the kind. Uploads stream to a
//! generated-name temporary file and are renamed into place only after the
//! whole body is written and within the size cap, so a failed or oversized
//! upload never leaves a half-written file masquerading as a usable image.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use daygleve_schema::storage_file::{
    DiskImageFetch, DiskImageFetchState, FetchDiskImageRequest, StorageFile, StorageFileKind,
};
use futures::Stream;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

/// Allowed extensions for uploaded CT-template rootfs tarballs.
const CT_TEMPLATE_EXTENSIONS: &[&str] = &[
    ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tar.bz2",
];

/// Allowed extensions for uploaded VM disk images offered for import.
const DISK_IMAGE_EXTENSIONS: &[&str] =
    &[".qcow2", ".vmdk", ".raw", ".img", ".vdi", ".vhd", ".vhdx"];

/// Redirect hops a URL fetch will follow before giving up.
const MAX_FETCH_REDIRECTS: usize = 5;
/// Overall wall-clock cap for one URL fetch (large images over slow mirrors).
const FETCH_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
/// How many finished fetch records to keep in the in-memory status list.
const MAX_FETCH_HISTORY: usize = 50;

/// Manages the node's local upload libraries.
#[derive(Clone)]
pub struct LibraryService {
    config: Arc<Config>,
    /// In-memory status of disk-image URL fetches (in-progress and recent).
    /// Completed downloads also appear in the disk-image library listing.
    fetches: Arc<RwLock<Vec<DiskImageFetch>>>,
}

impl LibraryService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            fetches: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Directory backing a given library kind.
    fn dir_for(&self, kind: StorageFileKind) -> &Path {
        match kind {
            StorageFileKind::Iso => &self.config.iso_dir,
            StorageFileKind::CtTemplate => &self.config.template_dir,
            StorageFileKind::DiskImage => &self.config.disk_image_dir,
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
    /// requested name, then removed by the path the directory listing produced -
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

    /// Resolve an uploaded disk-image file name to its absolute host path.
    ///
    /// Like [`Self::resolve_ct_template`], the path is taken from the directory
    /// listing (so the request value is only compared, never joined), which also
    /// confirms the file exists. Used by the KVM service when importing an
    /// uploaded disk image into a new zvol.
    pub async fn resolve_disk_image(&self, name: &str) -> ApiResult<PathBuf> {
        let name = validate_library_filename(name, StorageFileKind::DiskImage)?;
        self.list(StorageFileKind::DiskImage)
            .await?
            .into_iter()
            .find(|f| f.name == name)
            .map(|f| PathBuf::from(f.path))
            .ok_or_else(|| {
                AppError::validation(
                    "image_name is not an uploaded disk image (see GET /storage/disk-images)",
                )
            })
    }

    /// Recent disk-image URL fetches, newest first.
    pub async fn list_fetches(&self) -> Vec<DiskImageFetch> {
        let mut list = self.fetches.read().await.clone();
        list.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        list
    }

    /// Validate a fetch request, register it, and start the download in the
    /// background. Returns the initial `downloading` status.
    pub async fn start_fetch(&self, req: FetchDiskImageRequest) -> ApiResult<DiskImageFetch> {
        let url = parse_fetch_url(&req.url)?;
        let name = derive_fetch_name(&url, req.name.as_deref())?;

        let fetch = DiskImageFetch {
            id: new_id(),
            url: url.to_string(),
            name: name.clone(),
            state: DiskImageFetchState::Downloading,
            bytes_downloaded: 0,
            total_bytes: None,
            error: None,
            started_at: now_ts(),
            finished_at: None,
        };
        {
            let mut fetches = self.fetches.write().await;
            fetches.push(fetch.clone());
            prune_fetches(&mut fetches);
        }

        let this = self.clone();
        let id = fetch.id.clone();
        tokio::spawn(async move {
            let result = this.run_fetch(&id, url, &name).await;
            this.finish_fetch(&id, result).await;
        });
        Ok(fetch)
    }

    /// Download the (already-validated) URL into the disk-image library,
    /// re-validating the host at every redirect hop. Streams the body through
    /// the same size-capped, temp-then-rename [`Self::upload`] path.
    async fn run_fetch(&self, id: &str, url: reqwest::Url, name: &str) -> ApiResult<u64> {
        use futures::StreamExt;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(20))
            .timeout(FETCH_TIMEOUT)
            .build()
            .map_err(|e| AppError::internal(format!("build http client: {e}")))?;

        // Follow redirects manually so each hop's host is re-validated against
        // the private-address blocklist (a redirect can otherwise point the
        // fetch at an internal address).
        let mut current = url;
        let response = loop_response(&client, &mut current).await?;

        if let Some(total) = response.content_length() {
            if total > self.config.max_upload_bytes {
                return Err(AppError::validation(format!(
                    "remote file is {total} bytes, exceeding the maximum of {}",
                    self.config.max_upload_bytes
                )));
            }
            self.set_fetch_total(id, total).await;
        }

        let stream = response.bytes_stream().boxed();
        let file = self
            .upload(StorageFileKind::DiskImage, name, stream)
            .await?;
        Ok(file.size_bytes)
    }

    async fn set_fetch_total(&self, id: &str, total: u64) {
        if let Some(f) = self.fetches.write().await.iter_mut().find(|f| f.id == id) {
            f.total_bytes = Some(total);
        }
    }

    async fn finish_fetch(&self, id: &str, result: ApiResult<u64>) {
        let mut fetches = self.fetches.write().await;
        if let Some(f) = fetches.iter_mut().find(|f| f.id == id) {
            f.finished_at = Some(now_ts());
            match result {
                Ok(bytes) => {
                    f.state = DiskImageFetchState::Completed;
                    f.bytes_downloaded = bytes;
                }
                Err(e) => {
                    f.state = DiskImageFetchState::Failed;
                    f.error = Some(e.message().to_string());
                }
            }
        }
    }
}

/// Follow redirects manually, validating every hop's host, and return the final
/// success response. `current` is advanced to the final URL.
async fn loop_response(
    client: &reqwest::Client,
    current: &mut reqwest::Url,
) -> ApiResult<reqwest::Response> {
    for _ in 0..=MAX_FETCH_REDIRECTS {
        validate_public_url(current).await?;
        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| AppError::hypervisor(format!("fetch failed: {e}")))?;
        let status = response.status();
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| AppError::hypervisor("redirect without a location"))?;
            *current = current
                .join(location)
                .map_err(|e| AppError::validation(format!("invalid redirect target: {e}")))?;
            continue;
        }
        if !status.is_success() {
            return Err(AppError::hypervisor(format!(
                "remote server returned HTTP {}",
                status.as_u16()
            )));
        }
        return Ok(response);
    }
    Err(AppError::hypervisor("too many redirects"))
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
/// control byte, absurdly long names, and - per kind - a wrong extension. The
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
        StorageFileKind::DiskImage => DISK_IMAGE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)),
    };
    if !ext_ok {
        return Err(AppError::validation(match kind {
            StorageFileKind::Iso => "ISO uploads must have a .iso extension".to_string(),
            StorageFileKind::CtTemplate => format!(
                "CT-template uploads must be a tarball ({})",
                CT_TEMPLATE_EXTENSIONS.join(", ")
            ),
            StorageFileKind::DiskImage => format!(
                "disk-image uploads must be a supported disk image ({})",
                DISK_IMAGE_EXTENSIONS.join(", ")
            ),
        }));
    }
    Ok(name)
}

/// Parse and vet a fetch URL: `http`/`https` only, a host present, and no
/// embedded credentials.
fn parse_fetch_url(raw: &str) -> ApiResult<reqwest::Url> {
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|e| AppError::validation(format!("invalid url: {e}")))?;
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(AppError::validation(format!(
                "unsupported url scheme {other:?}; use http or https"
            )))
        }
    }
    if url.host_str().is_none() {
        return Err(AppError::validation("url has no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::validation("url must not contain credentials"));
    }
    Ok(url)
}

/// Determine the destination file name: the caller-provided `name`, else the
/// URL's last path segment. Either way it must pass the disk-image filename
/// rules (supported extension, no separators/traversal).
fn derive_fetch_name(url: &reqwest::Url, provided: Option<&str>) -> ApiResult<String> {
    let candidate = match provided {
        Some(n) => n.trim().to_string(),
        None => url
            .path_segments()
            .and_then(|mut s| s.next_back().map(str::to_string))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::validation("could not derive a file name from the url; provide `name`")
            })?,
    };
    validate_library_filename(&candidate, StorageFileKind::DiskImage)?;
    Ok(candidate)
}

/// Reject fetching from an address that is not a public unicast address. This
/// is the SSRF barrier: a literal-IP host is checked directly, and a named host
/// is DNS-resolved with every resolved address checked. Re-run at each redirect
/// hop by [`loop_response`].
async fn validate_public_url(url: &reqwest::Url) -> ApiResult<()> {
    let host = url
        .host_str()
        .ok_or_else(|| AppError::validation("url has no host"))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip_is_disallowed(ip) {
            return Err(AppError::validation(
                "refusing to fetch from a private, loopback, or link-local address",
            ));
        }
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| AppError::validation(format!("could not resolve host {host:?}: {e}")))?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if ip_is_disallowed(addr.ip()) {
            return Err(AppError::validation(
                "host resolves to a private, loopback, or link-local address; refusing to fetch",
            ));
        }
    }
    if !any {
        return Err(AppError::validation(format!(
            "host {host:?} did not resolve"
        )));
    }
    Ok(())
}

/// Whether an IP is one DaygleVE must never fetch from (loopback, private,
/// link-local, unspecified, multicast, CGNAT, documentation, etc.).
fn ip_is_disallowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_disallowed(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
            // fe80::/10 link-local
            {
                return true;
            }
            // A v4-mapped address (::ffff:a.b.c.d) is judged by its v4 rules.
            match v6.to_ipv4_mapped() {
                Some(v4) => ipv4_disallowed(v4),
                None => false,
            }
        }
    }
}

fn ipv4_disallowed(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || o[0] == 0                            // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
}

/// Cap the retained fetch history, dropping the oldest finished entries but
/// never an in-progress one.
fn prune_fetches(fetches: &mut Vec<DiskImageFetch>) {
    while fetches.len() > MAX_FETCH_HISTORY {
        match fetches
            .iter()
            .position(|f| f.state != DiskImageFetchState::Downloading)
        {
            Some(pos) => {
                fetches.remove(pos);
            }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_url_scheme_and_credentials_are_enforced() {
        assert!(parse_fetch_url("https://mirror.example/focal.qcow2").is_ok());
        assert!(parse_fetch_url("http://mirror.example/focal.img").is_ok());
        assert!(parse_fetch_url("file:///etc/passwd").is_err());
        assert!(parse_fetch_url("ftp://mirror.example/x.raw").is_err());
        assert!(parse_fetch_url("https://user:pw@mirror.example/x.qcow2").is_err());
        assert!(parse_fetch_url("not a url").is_err());
    }

    #[test]
    fn fetch_name_derivation_and_extension() {
        let url = reqwest::Url::parse("https://mirror.example/images/focal-server.qcow2").unwrap();
        assert_eq!(derive_fetch_name(&url, None).unwrap(), "focal-server.qcow2");
        // Explicit name overrides the URL.
        assert_eq!(
            derive_fetch_name(&url, Some("my-disk.img")).unwrap(),
            "my-disk.img"
        );
        // A URL without a disk-image extension needs an explicit, valid name.
        let bare = reqwest::Url::parse("https://mirror.example/download").unwrap();
        assert!(derive_fetch_name(&bare, None).is_err());
        assert!(derive_fetch_name(&bare, Some("disk.raw")).is_ok());
        assert!(derive_fetch_name(&bare, Some("disk.txt")).is_err());
        // A separator in an explicit name is rejected (no traversal).
        assert!(derive_fetch_name(&bare, Some("../x.qcow2")).is_err());
    }

    #[test]
    fn private_and_special_addresses_are_blocked() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(
                ip_is_disallowed(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(
                !ip_is_disallowed(ip.parse().unwrap()),
                "{ip} should be allowed"
            );
        }
    }

    #[tokio::test]
    async fn validate_public_url_rejects_private_literals() {
        assert!(
            validate_public_url(&reqwest::Url::parse("http://127.0.0.1/x.img").unwrap())
                .await
                .is_err()
        );
        assert!(validate_public_url(
            &reqwest::Url::parse("http://169.254.169.254/latest").unwrap()
        )
        .await
        .is_err());
        assert!(
            validate_public_url(&reqwest::Url::parse("https://1.1.1.1/x.qcow2").unwrap())
                .await
                .is_ok()
        );
    }

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
        assert!(
            validate_library_filename("focal-server.qcow2", StorageFileKind::DiskImage).is_ok()
        );
        assert!(validate_library_filename("disk.vmdk", StorageFileKind::DiskImage).is_ok());
        assert!(validate_library_filename("win.vhdx", StorageFileKind::DiskImage).is_ok());

        // Wrong extension for the kind.
        assert!(validate_library_filename("debian-13.iso", StorageFileKind::CtTemplate).is_err());
        assert!(validate_library_filename("rootfs.tar.xz", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("notes.txt", StorageFileKind::Iso).is_err());
        assert!(validate_library_filename("debian-13.iso", StorageFileKind::DiskImage).is_err());
        assert!(validate_library_filename("disk.qcow2", StorageFileKind::Iso).is_err());

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
