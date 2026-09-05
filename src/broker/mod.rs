//! Host broker protocol: the wire contract between the DaygleVE backend and
//! the root-owned `daygleve-broker` process.
//!
//! This module is deliberately **self-contained** (no `crate::` imports): it
//! is compiled into both binaries, and the broker must validate every request
//! *independently* of the backend's own service-layer checks. Defense in
//! depth requires the two validation layers to be separate code paths.
//!
//! Framing: every message is `u32 little-endian byte length` followed by that
//! many bytes of UTF-8 JSON. Chunk payloads are base64 inside the JSON so the
//! framing stays text-safe and trivially auditable.

#![allow(dead_code)]

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

/// Protocol version. Requests with a mismatching `v` are rejected.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum size of a control frame (requests, unary responses) in bytes.
pub const CONTROL_FRAME_MAX: u32 = 1024 * 1024;
/// Maximum payload bytes carried by a single streaming chunk frame.
pub const CHUNK_PAYLOAD_MAX: usize = 256 * 1024;

/// Hard upper bound the broker accepts for an exec, regardless of what the
/// client requests. Long-running workflows belong in the job system.
pub const EXEC_TIMEOUT_CAP: Duration = Duration::from_secs(900);

/// Default per-exec timeout requested by the backend for unary operations
/// (matches the direct-path command wrapper's 300s bound).
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Mint a fresh correlation id for a broker request.
pub fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
// ---------------------------------------------------------------------------
// Requests (backend -> broker)
// ---------------------------------------------------------------------------

/// One privileged operation requested from the broker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub v: u32,
    /// Correlation id for logging (backend request id or operation id).
    pub id: String,
    /// The operation to perform.
    #[serde(flatten)]
    pub op: Op,
}

/// The operation types the broker understands. Everything else is rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Op {
    /// Liveness check; proves the authenticated broker socket is serving.
    Ping,
    /// Execute an allowlisted host program. With `stream` set, stdout/stdin
    /// stream as chunk frames instead of being buffered (backup send/receive).
    Exec {
        /// Program name (allowlist key), e.g. `zfs`.
        program: String,
        /// Argument vector; passed to the child verbatim (no shell).
        args: Vec<String>,
        /// Stream stdout back in chunks instead of buffering it.
        #[serde(default)]
        stream: bool,
        /// Also accept stdin chunks from the client (restore paths).
        #[serde(default)]
        stdin_stream: bool,
        /// Per-exec timeout in seconds, capped by [`EXEC_TIMEOUT_CAP`].
        #[serde(default = "default_timeout_secs")]
        timeout_secs: u64,
    },
    /// A constrained PCI sysfs write for vfio-pci passthrough. The broker
    /// derives both the exact sysfs path and the written value from `kind`
    /// and `address`; the client never supplies a free-form path or value.
    PciWrite {
        /// Which constrained write to perform.
        kind: PciWriteKind,
        /// PCI address, e.g. `0000:01:00.0`.
        address: String,
    },
    /// Append a validated DaygleVE limits/networking block to
    /// `/var/lib/lxc/{name}/config`. The path is derived from the validated
    /// container name; the block must contain only permitted lxc keys.
    LxcConfigAppend {
        /// Container name (path-safe, validated).
        name: String,
        /// The config lines to append.
        block: String,
    },
}

fn default_timeout_secs() -> u64 {
    300
}

/// The constrained PCI sysfs writes the broker permits.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PciWriteKind {
    /// Unbind the device from its current driver (value = the PCI address).
    Unbind,
    /// Pin the device to vfio-pci (value fixed to `vfio-pci`).
    Override,
    /// Bind the device to vfio-pci (value = the PCI address).
    Bind,
}

// ---------------------------------------------------------------------------
// Streaming frames (both directions, after the initial request)
// ---------------------------------------------------------------------------

/// A mid-operation frame while an exec is streaming.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum StreamFrame {
    /// Client -> broker: a chunk of stdin for the child process.
    Stdin {
        /// Base64-encoded stdin bytes (empty chunk is legal but pointless).
        d: String,
    },
    /// Client -> broker: stdin is complete; close the child's stdin.
    StdinEof,
    /// Broker -> client: a chunk of the child's stdout.
    Stdout {
        /// Base64-encoded stdout bytes.
        d: String,
    },
    /// Broker -> client: terminal frame with the child's exit status.
    Exit {
        /// Child exit code (or -1 when killed/failed to spawn).
        code: i32,
        /// Captured stderr, trimmed.
        #[serde(default)]
        stderr: String,
        /// True when the exec hit the broker-side timeout.
        #[serde(default)]
        timed_out: bool,
    },
}

// ---------------------------------------------------------------------------
// Unary response (broker -> backend, non-streaming ops and protocol errors)
// ---------------------------------------------------------------------------

/// Terminal response for non-streaming operations, or a protocol-level error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// Whether the requested operation completed successfully.
    pub ok: bool,
    /// Captured stdout, when applicable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stdout: String,
    /// Captured stderr, when applicable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stderr: String,
    /// Child exit code when the operation ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// Error classification: `spawn_not_found` lets the backend degrade a
    /// list/inventory call to "nothing to show" (dev hosts without a tool).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Human-readable failure message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// Successful unary response.
    pub fn success(stdout: String, stderr: String, code: i32) -> Self {
        Self {
            ok: true,
            stdout,
            stderr,
            code: Some(code),
            error_kind: None,
            error: None,
        }
    }

    /// Protocol/validation failure (bad request, auth, unsupported op...).
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr: String::new(),
            code: None,
            error_kind: Some("protocol".to_string()),
            error: Some(error.into()),
        }
    }

    /// The child could not be spawned because the binary does not exist.
    pub fn spawn_not_found(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr: String::new(),
            code: None,
            error_kind: Some("spawn_not_found".to_string()),
            error: Some(error.into()),
        }
    }

    /// The child ran but exited non-zero (or was killed).
    pub fn exec_failed(error: impl Into<String>, stderr: String) -> Self {
        Self {
            ok: false,
            stdout: String::new(),
            stderr,
            code: Some(-1),
            error_kind: Some("exec".to_string()),
            error: Some(error.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Framing (shared by client and server)
// ---------------------------------------------------------------------------

/// Read one length-prefixed JSON frame, rejecting oversized frames.
pub mod framing {
    use serde::de::DeserializeOwned;

    use super::CONTROL_FRAME_MAX;

    /// Wire/protocol failure. Kept separate from execution failures so callers
    /// can distinguish "broker misbehaving" from "operation failed".
    #[derive(Debug)]
    pub struct FrameError(pub String);

    impl std::fmt::Display for FrameError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "broker framing error: {}", self.0)
        }
    }

    impl std::error::Error for FrameError {}

    /// Read one frame: a `u32` LE length prefix followed by that many bytes.
    pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>, FrameError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;

        let mut len_buf = [0u8; 4];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| FrameError(format!("read length prefix: {e}")))?;
        let len = u32::from_le_bytes(len_buf);
        if len == 0 {
            return Err(FrameError("zero-length frame".to_string()));
        }
        if len > CONTROL_FRAME_MAX {
            return Err(FrameError(format!(
                "frame of {len} bytes exceeds the {} byte limit",
                CONTROL_FRAME_MAX
            )));
        }
        let mut buf = vec![0u8; len as usize];
        reader
            .read_exact(&mut buf)
            .await
            .map_err(|e| FrameError(format!("read frame body: {e}")))?;
        Ok(buf)
    }

    /// Read one frame and deserialize it as JSON.
    pub async fn read_json<R, T>(reader: &mut R) -> Result<T, FrameError>
    where
        R: tokio::io::AsyncRead + Unpin,
        T: DeserializeOwned,
    {
        let bytes = read_frame(reader).await?;
        serde_json::from_slice(&bytes).map_err(|e| FrameError(format!("parse frame: {e}")))
    }

    /// Write one length-prefixed frame and flush.
    pub async fn write_frame<W>(writer: &mut W, body: &[u8]) -> Result<(), FrameError>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let len = u32::try_from(body.len())
            .map_err(|_| FrameError("frame body too large".to_string()))?;
        if len > CONTROL_FRAME_MAX {
            return Err(FrameError("frame body too large".to_string()));
        }
        writer
            .write_all(&len.to_le_bytes())
            .await
            .map_err(|e| FrameError(format!("write length prefix: {e}")))?;
        writer
            .write_all(body)
            .await
            .map_err(|e| FrameError(format!("write frame body: {e}")))?;
        writer
            .flush()
            .await
            .map_err(|e| FrameError(format!("flush frame: {e}")))
    }

    /// Serialize a value and write it as one frame.
    pub async fn write_json<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
    where
        W: tokio::io::AsyncWrite + Unpin,
        T: serde::Serialize,
    {
        let bytes =
            serde_json::to_vec(value).map_err(|e| FrameError(format!("serialize frame: {e}")))?;
        write_frame(writer, &bytes).await
    }
}

// ---------------------------------------------------------------------------
// Independent broker-side validation
// ---------------------------------------------------------------------------

/// Programs the broker will execute, resolved to fixed absolute paths.
///
/// This table is intentionally duplicated from the backend's command wrapper:
/// the broker must not trust backend-side validation, and a change to one
/// allowlist must be a conscious, reviewed act.
pub fn program_path(program: &str) -> Option<&'static str> {
    Some(match program {
        "bridge" => "/usr/sbin/bridge",
        "ip" => "/usr/sbin/ip",
        "lxc-cgroup" => "/usr/bin/lxc-cgroup",
        "lxc-create" => "/usr/bin/lxc-create",
        "lxc-destroy" => "/usr/bin/lxc-destroy",
        "lxc-freeze" => "/usr/bin/lxc-freeze",
        "lxc-info" => "/usr/bin/lxc-info",
        "lxc-ls" => "/usr/bin/lxc-ls",
        "lxc-start" => "/usr/bin/lxc-start",
        "lxc-stop" => "/usr/bin/lxc-stop",
        "lxc-unfreeze" => "/usr/bin/lxc-unfreeze",
        "mount" => "/usr/bin/mount",
        "umount" => "/usr/bin/umount",
        "virsh" => "/usr/bin/virsh",
        "zfs" => "/usr/sbin/zfs",
        "zpool" => "/usr/sbin/zpool",
        _ => return None,
    })
}

/// Validate one argv element: no NUL bytes, bounded length. Arguments are
/// passed as argv elements (there is no shell), so arbitrary characters are
/// otherwise safe; length bounds keep a single request from exhausting
/// broker memory.
fn validate_arg(arg: &str) -> Result<(), &'static str> {
    if arg.contains('\0') {
        return Err("argument contains NUL");
    }
    if arg.len() > 4096 {
        return Err("argument exceeds 4096 bytes");
    }
    Ok(())
}

/// Validate an exec request against the broker's independent allowlist.
pub fn validate_exec(program: &str, args: &[String]) -> Result<(), String> {
    if program_path(program).is_none() {
        return Err(format!("program `{program}` is not permitted"));
    }
    if args.len() > 256 {
        return Err("too many arguments (max 256)".to_string());
    }
    for arg in args {
        validate_arg(arg).map_err(|e| format!("invalid argument: {e}"))?;
        if arg.chars().any(|c| c.is_control()) {
            return Err("argument contains a control character".to_string());
        }
    }
    validate_exec_shape(program, args)
}

/// Reject command classes that are not part of DaygleVE's host-operation
/// surface. This is intentionally conservative: adding a new host subcommand
/// requires a reviewed broker change instead of silently expanding the root
/// boundary.
fn validate_exec_shape(program: &str, args: &[String]) -> Result<(), String> {
    let subcommand = match program {
        "virsh" => {
            let mut index = 0;
            while index < args.len() {
                if args[index] == "-c" {
                    index += 2;
                } else if args[index].starts_with('-') {
                    index += 1;
                } else {
                    break;
                }
            }
            args.get(index).map(String::as_str)
        }
        _ => args.first().map(String::as_str),
    };
    let allowed = match program {
        "virsh" => matches!(
            subcommand,
            Some(
                "list"
                    | "domstate"
                    | "hostname"
                    | "start"
                    | "shutdown"
                    | "destroy"
                    | "reboot"
                    | "reset"
                    | "pause"
                    | "resume"
                    | "define"
                    | "undefine"
                    | "domrename"
                    | "vncdisplay"
            )
        ),
        "zfs" => matches!(
            subcommand,
            Some(
                "list"
                    | "create"
                    | "set"
                    | "destroy"
                    | "snapshot"
                    | "clone"
                    | "promote"
                    | "rollback"
                    | "send"
                    | "receive"
            )
        ),
        "zpool" => matches!(subcommand, Some("list" | "status")),
        "lxc-create" | "lxc-destroy" | "lxc-start" | "lxc-stop" | "lxc-freeze" | "lxc-unfreeze"
        | "lxc-info" | "lxc-cgroup" | "lxc-ls" => true,
        "ip" => {
            args.windows(2).any(|pair| pair == ["link", "show"])
                || args.windows(2).any(|pair| pair == ["addr", "show"])
                || args.windows(2).any(|pair| pair == ["link", "add"])
                || args.windows(2).any(|pair| pair == ["link", "set"])
                || args.windows(2).any(|pair| pair == ["link", "del"])
                || args.windows(2).any(|pair| pair == ["addr", "add"])
        }
        "bridge" => matches!(subcommand, Some("vlan")),
        "mount" => args.iter().any(|arg| arg == "-t"),
        "umount" => !args.is_empty(),
        _ => false,
    };
    if !allowed {
        return Err(format!("command shape for `{program}` is not permitted"));
    }
    validate_exec_args(program, args)
}

fn safe_zfs_value(value: &str) -> bool {
    !value.starts_with('-')
        && !value.contains("/../")
        && !value.ends_with("/..")
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_' | b'-' | b':' | b'/' | b'@' | b'=' | b',' | b'%'
                )
        })
}

fn validate_zfs_args(args: &[String]) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or_default();
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "-H" | "-h" | "-p" | "-Hp" | "-r" | "-F") {
            index += 1;
            continue;
        }
        if matches!(arg.as_str(), "-o" | "-t" | "-d" | "-V") {
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{arg} requires a value"))?;
            if !safe_zfs_value(value) {
                return Err("ZFS option value is unsafe".to_string());
            }
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            return Err(format!("ZFS option `{arg}` is not permitted"));
        }
        if command == "set" && index == 1 {
            if !safe_zfs_property(arg) {
                return Err("ZFS set requires a constrained property=value argument".to_string());
            }
        } else if arg.contains('@') {
            if !safe_snapshot_ref(arg) {
                return Err("ZFS snapshot reference is unsafe".to_string());
            }
        } else if !safe_dataset(arg) {
            return Err("ZFS dataset argument is unsafe".to_string());
        }
        index += 1;
    }
    Ok(())
}

fn safe_zfs_property(value: &str) -> bool {
    let Some((key, property)) = value.split_once('=') else {
        return false;
    };
    let key_allowed = key == "daygleve:description" || key == "quota";
    key_allowed
        && !property.is_empty()
        && property.len() <= 512
        && !property.chars().any(|c| c.is_control())
        && property
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b' '))
}

fn validate_zpool_args(args: &[String]) -> Result<(), String> {
    let mut index = 1;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "-H" | "-p" | "-Hp") {
            index += 1;
        } else if arg == "-o" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "zpool -o requires a value".to_string())?;
            if !safe_zfs_value(value) {
                return Err("zpool column list is unsafe".to_string());
            }
            index += 2;
        } else if arg.starts_with('-') {
            return Err(format!("zpool option `{arg}` is not permitted"));
        } else {
            if !safe_dataset(arg) {
                return Err("zpool argument contains an unsafe value".to_string());
            }
            index += 1;
        }
    }
    Ok(())
}

fn safe_cli_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
}

fn safe_dataset(value: &str) -> bool {
    !value.contains('@')
        && !value.starts_with('/')
        && !value.starts_with('-')
        && !value.ends_with('/')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'))
}

fn safe_snapshot_ref(value: &str) -> bool {
    let Some((dataset, snapshot)) = value.split_once('@') else {
        return false;
    };
    safe_dataset(dataset)
        && !snapshot.is_empty()
        && snapshot
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn safe_abs_path(value: &str, prefix: &str, suffix: Option<&str>) -> bool {
    value.starts_with(prefix)
        && !value.contains("/../")
        && !value.ends_with("/..")
        && suffix.is_none_or(|ending| value.ends_with(ending))
}

fn safe_mount_source(filesystem: &str, source: &str) -> bool {
    let prefix_ok = match filesystem {
        "nfs" => source.split_once(':').is_some_and(|(host, export)| {
            !host.is_empty() && !export.is_empty() && !export.starts_with('-')
        }),
        "cifs" => source.starts_with("//") && source[2..].contains('/'),
        _ => false,
    };
    prefix_ok
        && !source.contains("..")
        && !source.contains(',')
        && !source.chars().any(|c| c.is_control() || c.is_whitespace())
        && source
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'))
}

fn validate_mount_options(options: &str) -> Result<(), String> {
    const DENIED: &[&str] = &["rw", "suid", "dev", "exec", "remount", "bind"];
    if options.is_empty()
        || !options.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'=' | b',' | b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return Err("mount options contain unsafe characters".to_string());
    }
    for option in options.split(',') {
        let key = option
            .split('=')
            .next()
            .unwrap_or(option)
            .to_ascii_lowercase();
        if DENIED.contains(&key.as_str()) {
            return Err(format!("mount option `{key}` is not permitted"));
        }
        if key == "credentials" {
            let value = option
                .split_once('=')
                .map(|(_, value)| value)
                .unwrap_or_default();
            if !safe_abs_path(value, "/var/lib/daygleve/", Some(".cred")) {
                return Err("credentials file is outside DaygleVE state".to_string());
            }
        }
    }
    Ok(())
}

fn arg_after<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].as_str())
}

/// Independent argument/path validation. The broker must not merely trust the
/// backend's already-sanitized argv: a compromised backend can speak the local
/// protocol directly, so host paths, datasets, domain names, and network
/// targets are constrained a second time here.
fn validate_exec_args(program: &str, args: &[String]) -> Result<(), String> {
    match program {
        "virsh" => {
            if arg_after(args, "-c") != Some("qemu:///system") {
                return Err("virsh must use qemu:///system".to_string());
            }
            let command = args
                .iter()
                .position(|arg| arg == "-c")
                .and_then(|i| args.get(i + 2))
                .map(String::as_str)
                .ok_or_else(|| "virsh command is missing".to_string())?;
            for arg in args
                .iter()
                .skip_while(|arg| arg.as_str() != command)
                .skip(1)
            {
                if command == "define" && !safe_abs_path(arg, "/var/lib/daygleve/", Some(".xml")) {
                    return Err("virsh define path is outside DaygleVE state".to_string());
                }
                if command != "define" && !safe_cli_name(arg) && !arg.starts_with('-') {
                    return Err("virsh argument contains an unsafe value".to_string());
                }
            }
        }
        "zfs" => validate_zfs_args(args)?,
        "zpool" => validate_zpool_args(args)?,
        name if name.starts_with("lxc-") => {
            if let Some(container) = arg_after(args, "-n") {
                if !validate_lxc_name(container).is_ok() {
                    return Err("LXC target name is unsafe".to_string());
                }
            }
            for arg in args {
                if arg.starts_with('/') && !safe_abs_path(arg, "/var/lib/daygleve/", None) {
                    return Err("LXC path is outside DaygleVE state".to_string());
                }
            }
        }
        "ip" | "bridge" => {
            for arg in args {
                if arg.starts_with('/') || arg.contains('\0') || arg.chars().any(|c| c.is_control())
                {
                    return Err("network argument contains an unsafe value".to_string());
                }
            }
        }
        "mount" => {
            let filesystem =
                arg_after(args, "-t").ok_or_else(|| "mount type is required".to_string())?;
            if !matches!(filesystem, "nfs" | "cifs") {
                return Err("only nfs and cifs mounts are permitted".to_string());
            }
            let source = args
                .get(args.len().saturating_sub(2))
                .map(String::as_str)
                .ok_or_else(|| "mount source is required".to_string())?;
            if !safe_mount_source(filesystem, source) {
                return Err("mount source is not a permitted network share".to_string());
            }
            if let Some(options) = arg_after(args, "-o") {
                validate_mount_options(options)?;
            }
            let target = args.last().map(String::as_str).unwrap_or_default();
            if !safe_abs_path(target, "/var/lib/daygleve/", None) {
                return Err("mount target is outside DaygleVE state".to_string());
            }
        }
        "umount" => match args {
            [target] if safe_abs_path(target, "/var/lib/daygleve/", None) => {}
            _ => return Err("umount target is outside DaygleVE state".to_string()),
        },
        _ => {}
    }
    Ok(())
}

/// Validate a PCI address: `domain:bus:slot.function`, lowercase hex.
pub fn validate_pci_address(address: &str) -> Result<(), String> {
    let valid = address.len() == 12
        && address.as_bytes()[4] == b':'
        && address.as_bytes()[7] == b':'
        && address.as_bytes()[10] == b'.'
        && address.as_bytes()[11].is_ascii_digit()
        && address.as_bytes()[11] <= b'7'
        && address.chars().enumerate().all(|(i, c)| match i {
            4 | 7 | 10 => c == ':' || c == '.',
            _ => c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid PCI address `{address}`"))
    }
}

/// The exact sysfs path and value the broker writes for a [`PciWriteKind`].
pub fn pci_write_target(kind: PciWriteKind, address: &str) -> (std::path::PathBuf, String) {
    let addr = std::path::PathBuf::from("/sys/bus/pci");
    match kind {
        PciWriteKind::Unbind => (
            addr.join("devices")
                .join(address)
                .join("driver")
                .join("unbind"),
            address.to_string(),
        ),
        PciWriteKind::Override => (
            addr.join("devices").join(address).join("driver_override"),
            "vfio-pci".to_string(),
        ),
        PciWriteKind::Bind => (
            addr.join("drivers").join("vfio-pci").join("bind"),
            address.to_string(),
        ),
    }
}

/// Validate a container name before it may touch a path.
pub fn validate_lxc_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid container name `{name}`"))
    }
}

/// Validate a config block destined for `/var/lib/lxc/{name}/config`.
///
/// Only the two DaygleVE-controlled key families are permitted
/// (`lxc.cgroup2.*`, `lxc.net.*`); anything else is rejected so the backend
/// can never write arbitrary LXC configuration keys through the broker.
pub fn validate_lxc_config_block(block: &str) -> Result<(), String> {
    if block.is_empty() {
        return Err("config block is empty".to_string());
    }
    if block.len() > 8192 {
        return Err("config block exceeds 8192 bytes".to_string());
    }
    if block.contains('\0') {
        return Err("config block contains NUL".to_string());
    }
    for line in block.lines().filter(|l| !l.trim().is_empty()) {
        let is_comment = line.trim_start().starts_with('#');
        if is_comment {
            continue;
        }
        let body = line.trim();
        let valid = body.starts_with("lxc.cgroup2.") || body.starts_with("lxc.net.");
        if !valid || !body.contains(" = ") {
            return Err(format!(
                "config line not permitted: `{}`",
                truncate(body, 80)
            ));
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// Validate a request end-to-end before the broker performs anything.
pub fn validate_request(req: &Request) -> Result<(), String> {
    if req.v != PROTOCOL_VERSION {
        return Err(format!("unsupported protocol version {}", req.v));
    }
    if req.id.is_empty() || req.id.len() > 128 || req.id.contains('\0') {
        return Err("invalid request id".to_string());
    }
    match &req.op {
        Op::Ping => {}
        Op::Exec {
            program,
            args,
            timeout_secs,
            ..
        } => {
            validate_exec(program, args)?;
            if *timeout_secs == 0 || *timeout_secs > EXEC_TIMEOUT_CAP.as_secs() {
                return Err("timeout_secs out of range".to_string());
            }
        }
        Op::PciWrite { kind: _, address } => validate_pci_address(address)?,
        Op::LxcConfigAppend { name, block } => {
            validate_lxc_name(name)?;
            validate_lxc_config_block(block)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_req(program: &str, args: &[&str]) -> Request {
        Request {
            v: PROTOCOL_VERSION,
            id: "test-req".to_string(),
            op: Op::Exec {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                stream: false,
                stdin_stream: false,
                timeout_secs: 300,
            },
        }
    }

    #[test]
    fn broker_allowlist_covers_the_documented_host_tools() {
        for program in [
            "virsh",
            "zfs",
            "zpool",
            "lxc-start",
            "lxc-stop",
            "ip",
            "bridge",
            "mount",
            "umount",
        ] {
            assert!(
                program_path(program).is_some(),
                "{program} should be allowed"
            );
        }
        for program in ["sh", "bash", "python3", "dd", "rm", ""] {
            assert!(
                program_path(program).is_none(),
                "{program} must be rejected"
            );
        }
    }

    #[test]
    fn exec_validation_rejects_bad_programs_and_args() {
        assert!(validate_exec("sh", &["-c".to_string(), "id".to_string()]).is_err());
        assert!(validate_exec(
            "zfs",
            &[
                "list".to_string(),
                "-Hp".to_string(),
                "-o".to_string(),
                "name,used".to_string(),
                "tank/vm".to_string()
            ]
        )
        .is_ok());
        assert!(validate_exec(
            "zpool",
            &[
                "list".to_string(),
                "-Hp".to_string(),
                "-o".to_string(),
                "name,size".to_string()
            ]
        )
        .is_ok());
        assert!(validate_exec(
            "zfs",
            &[
                "set".to_string(),
                "daygleve:description=hello world".to_string(),
                "tank/vm".to_string(),
            ],
        )
        .is_ok());
        assert!(validate_exec(
            "zfs",
            &[
                "set".to_string(),
                "quota=10G".to_string(),
                "tank/lxc/web".to_string()
            ],
        )
        .is_ok());
        assert!(validate_exec("zfs", &["load-key".to_string()]).is_err());
        assert!(validate_exec("zfs", &["list".to_string(), "\0bad".to_string()]).is_err());
        assert!(validate_exec(
            "virsh",
            &[
                "-c".to_string(),
                "qemu:///system".to_string(),
                "define".to_string(),
                "/etc/passwd".to_string()
            ]
        )
        .is_err());
        assert!(validate_exec(
            "mount",
            &[
                "-t".to_string(),
                "nfs".to_string(),
                "nas:/exports/isos".to_string(),
                "/var/lib/daygleve/mounts/x".to_string()
            ]
        )
        .is_ok());
        assert!(validate_exec(
            "mount",
            &[
                "-t".to_string(),
                "nfs".to_string(),
                "nas:/exports/isos".to_string(),
                "/etc".to_string()
            ]
        )
        .is_err());
        let long_arg = "x".repeat(5000);
        assert!(validate_exec("zfs", std::slice::from_ref(&long_arg)).is_err());
    }

    #[test]
    fn pci_addresses_and_writes_are_constrained() {
        assert!(validate_pci_address("0000:01:00.0").is_ok());
        assert!(validate_pci_address("0000:0a:00.1").is_ok());
        assert!(validate_pci_address("0000:01:00.8").is_err()); // function > 7
        assert!(validate_pci_address("0000:1:00.0").is_err());
        assert!(validate_pci_address("../../etc/passwd").is_err());

        let (path, value) = pci_write_target(PciWriteKind::Override, "0000:01:00.0");
        assert_eq!(
            path,
            std::path::PathBuf::from("/sys/bus/pci/devices/0000:01:00.0/driver_override")
        );
        assert_eq!(value, "vfio-pci");

        let (path, value) = pci_write_target(PciWriteKind::Bind, "0000:01:00.0");
        assert_eq!(
            path,
            std::path::PathBuf::from("/sys/bus/pci/drivers/vfio-pci/bind")
        );
        assert_eq!(value, "0000:01:00.0");
    }

    #[test]
    fn lxc_config_blocks_only_allow_daygleve_keys() {
        let good = "\n# --- DaygleVE limits & networking ---\nlxc.cgroup2.memory.max = 536870912\nlxc.net.0.type = veth\n";
        assert!(validate_lxc_config_block(good).is_ok());

        for bad in [
            "lxc.mount.entry = /etc /etc none bind\n",
            "lxc.rootfs.path = /\n",
            "lxc.hook.pre-start = /bin/sh\n",
            "include = /etc/passwd\n",
            "",
        ] {
            assert!(
                validate_lxc_config_block(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn lxc_names_are_path_safe() {
        assert!(validate_lxc_name("web-01").is_ok());
        assert!(validate_lxc_name("ct_1.a").is_ok());
        assert!(validate_lxc_name("../etc").is_err());
        assert!(validate_lxc_name("/abs").is_err());
        assert!(validate_lxc_name(".hidden").is_err());
        assert!(validate_lxc_name("").is_err());
    }

    #[test]
    fn requests_round_trip_and_validate() {
        let req = exec_req("zfs", &["list", "-H"]);
        let json = serde_json::to_string(&req).expect("serialize request");
        let parsed: Request = serde_json::from_str(&json).expect("parse request");
        assert_eq!(req, parsed);
        assert!(validate_request(&parsed).is_ok());

        let bad = Request {
            v: 99,
            ..exec_req("zfs", &["list"])
        };
        assert!(validate_request(&bad).is_err());

        let unknown = serde_json::from_str::<Request>(r#"{"v":1,"id":"x","type":"reboot"}"#);
        assert!(unknown.is_err());
    }

    #[test]
    fn op_tag_uses_snake_case_type_field() {
        let req = Request {
            v: PROTOCOL_VERSION,
            id: "r".to_string(),
            op: Op::PciWrite {
                kind: PciWriteKind::Override,
                address: "0000:01:00.0".to_string(),
            },
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains(r#""type":"pci_write""#), "{json}");
        assert!(validate_request(&req).is_ok());

        let ping = Request {
            v: PROTOCOL_VERSION,
            id: "ping".to_string(),
            op: Op::Ping,
        };
        assert!(validate_request(&ping).is_ok());
    }
}
