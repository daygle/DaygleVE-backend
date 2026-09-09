//! Root-owned Unix broker server for privileged DaygleVE host operations.

#![cfg(unix)]

use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;

use super::framing;
use super::{
    validate_lxc_config_block, validate_lxc_name, validate_request, Op, PciWriteKind, Request,
    Response, StreamFrame, CHUNK_PAYLOAD_MAX, EXEC_TIMEOUT_CAP,
};

/// Runtime configuration for the broker listener.
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub socket_path: PathBuf,
    pub allowed_uid: u32,
}

#[derive(Debug)]
enum ServeError {
    Auth(String),
    BadRequest(String),
    Exec(String),
    SpawnNotFound(String),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(message) => write!(f, "authorization failed: {message}"),
            Self::BadRequest(message) => write!(f, "bad request: {message}"),
            Self::Exec(message) => write!(f, "execution failed: {message}"),
            Self::SpawnNotFound(message) => write!(f, "program not found: {message}"),
        }
    }
}

impl std::error::Error for ServeError {}

impl ServeError {
    fn to_response(&self) -> Response {
        match self {
            Self::SpawnNotFound(message) => Response::spawn_not_found(message.clone()),
            Self::Exec(message) => Response::exec_failed(message.clone(), String::new()),
            Self::Auth(message) | Self::BadRequest(message) => Response::failure(message.clone()),
        }
    }
}

/// Start the broker listener. The parent directory must be owned/protected by
/// the service manager; this function removes only a stale socket at the exact
/// configured path.
pub async fn serve(config: BrokerConfig) -> std::io::Result<()> {
    remove_stale_socket(&config.socket_path)?;
    let listener = UnixListener::bind(&config.socket_path)?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660))?;

    tracing::info!(
        socket = %config.socket_path.display(),
        allowed_uid = config.allowed_uid,
        "daygleve-broker listening"
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = config.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, &cfg).await {
                tracing::warn!(error = %error, "broker connection rejected or ended");
            }
        });
    }
}

fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "broker socket path is not a Unix socket: {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn check_peer_uid(stream: &UnixStream, allowed_uid: u32) -> Result<(), ServeError> {
    let credentials = stream
        .peer_cred()
        .map_err(|e| ServeError::Auth(format!("could not read peer credentials: {e}")))?;
    let uid = credentials.uid();
    if uid == allowed_uid || uid == 0 {
        Ok(())
    } else {
        Err(ServeError::Auth(format!(
            "peer uid {uid} is not authorized (expected {allowed_uid})"
        )))
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    config: &BrokerConfig,
) -> Result<(), ServeError> {
    if let Err(error) = check_peer_uid(&stream, config.allowed_uid) {
        let _ = reply_response(&mut stream, error.to_response()).await;
        return Ok(());
    }
    let request: Request = match framing::read_json(&mut stream).await {
        Ok(request) => request,
        Err(error) => {
            let _ = reply_response(&mut stream, Response::failure(error.0)).await;
            return Ok(());
        }
    };
    if let Err(reason) = validate_request(&request) {
        reply_response(
            &mut stream,
            Response::failure(format!("request rejected: {reason}")),
        )
        .await?;
        return Ok(());
    }

    tracing::info!(id = %request.id, operation = ?request.op, "broker executing request");

    match request.op {
        Op::Ping => {
            reply_response(
                &mut stream,
                Response::success("pong".to_string(), String::new(), 0),
            )
            .await
        }
        Op::Exec {
            program,
            args,
            stream: true,
            stdin_stream,
            timeout_secs,
        } => {
            let (reader, writer) = stream.into_split();
            stream_exec(reader, writer, &program, &args, stdin_stream, timeout_secs).await
        }
        Op::Exec {
            program,
            args,
            stream: false,
            stdin_stream: false,
            timeout_secs,
        } => {
            let response = match unary_exec(&program, &args, timeout_secs).await {
                Ok(response) => response,
                Err(error) => error.to_response(),
            };
            reply_response(&mut stream, response).await
        }
        Op::Exec { .. } => {
            reply_response(
                &mut stream,
                Response::failure("stdin_stream requires stream=true"),
            )
            .await
        }
        Op::PciWrite { kind, address } => {
            let response = match handle_pci_write(kind, &address).await {
                Ok(()) => Response::success(String::new(), String::new(), 0),
                Err(message) => Response::exec_failed(message, String::new()),
            };
            reply_response(&mut stream, response).await
        }
        Op::LxcConfigAppend { name, block } => {
            let response = match handle_lxc_config_append(&name, &block).await {
                Ok(()) => Response::success(String::new(), String::new(), 0),
                Err(message) => Response::exec_failed(message, String::new()),
            };
            reply_response(&mut stream, response).await
        }
        Op::LxcRootfsSet { name, dataset } => {
            let response = match handle_lxc_rootfs_set(&name, &dataset).await {
                Ok(()) => Response::success(String::new(), String::new(), 0),
                Err(message) => Response::exec_failed(message, String::new()),
            };
            reply_response(&mut stream, response).await
        }
        Op::ConsoleAttach { pty, timeout_secs } => {
            let (reader, writer) = stream.into_split();
            stream_console(reader, writer, &pty, timeout_secs).await
        }
        Op::LxcConsoleAttach { name, timeout_secs } => {
            let (reader, writer) = stream.into_split();
            stream_lxc_console(reader, writer, &name, timeout_secs).await
        }
    }
}

async fn reply_response<W>(writer: &mut W, response: Response) -> Result<(), ServeError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    framing::write_json(writer, &response)
        .await
        .map_err(|e| ServeError::BadRequest(e.0))
}

fn command_for(executable: &str) -> Command {
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    command
}

async fn spawn_child(command: &mut Command) -> Result<tokio::process::Child, ServeError> {
    command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ServeError::SpawnNotFound(e.to_string())
        } else {
            ServeError::Exec(format!("spawn failed: {e}"))
        }
    })
}

async fn unary_exec(
    program: &str,
    args: &[String],
    timeout_secs: u64,
) -> Result<Response, ServeError> {
    let executable = super::program_path(program)
        .ok_or_else(|| ServeError::BadRequest(format!("program `{program}` is not permitted")))?;
    let timeout = Duration::from_secs(timeout_secs.min(EXEC_TIMEOUT_CAP.as_secs()));
    let mut command = command_for(executable);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = spawn_child(&mut command).await?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| {
            ServeError::Exec(format!(
                "`{program}` timed out after {}s",
                timeout.as_secs()
            ))
        })?
        .map_err(|e| ServeError::Exec(format!("wait for child: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    if code == 0 {
        Ok(Response::success(stdout, stderr, code))
    } else {
        Ok(Response::exec_failed(
            format!("`{program} {}` failed: {}", args.join(" "), stderr.trim()),
            stderr,
        ))
    }
}

async fn stream_exec(
    reader: tokio::net::unix::OwnedReadHalf,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    program: &str,
    args: &[String],
    stdin_stream: bool,
    timeout_secs: u64,
) -> Result<(), ServeError> {
    let executable = super::program_path(program)
        .ok_or_else(|| ServeError::BadRequest(format!("program `{program}` is not permitted")))?;
    let timeout = Duration::from_secs(timeout_secs.min(EXEC_TIMEOUT_CAP.as_secs()));
    let mut command = command_for(executable);
    command
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin_stream {
        command.stdin(std::process::Stdio::piped());
    } else {
        command.stdin(std::process::Stdio::null());
    }

    let mut child = match spawn_child(&mut command).await {
        Ok(child) => child,
        Err(error) => {
            send_exit(&mut writer, -1, error.to_string(), false).await?;
            return Ok(());
        }
    };
    let mut stdin_pump = None;
    if stdin_stream {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ServeError::Exec("child stdin was not captured".to_string()))?;
        stdin_pump = Some(tokio::spawn(feed_stdin(reader, stdin)));
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ServeError::Exec("child stdout was not captured".to_string()))?;

    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ServeError::Exec("child stderr was not captured".to_string()))?;
    let stderr_task = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes).await;
        String::from_utf8_lossy(&bytes).trim().to_string()
    });

    let deadline = tokio::time::Instant::now() + timeout;
    let mut chunk = vec![0u8; CHUNK_PAYLOAD_MAX];
    loop {
        match tokio::time::timeout_at(deadline, stdout.read(&mut chunk)).await {
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let stderr = stderr_task.await.unwrap_or_default();
                send_exit(&mut writer, -1, stderr, true).await?;
                break;
            }
            Ok(Err(error)) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let stderr = stderr_task.await.unwrap_or_default();
                send_exit(
                    &mut writer,
                    -1,
                    format!("read child stdout: {error}; {stderr}"),
                    false,
                )
                .await?;
                break;
            }
            Ok(Ok(0)) => {
                let status = child
                    .wait()
                    .await
                    .map_err(|e| ServeError::Exec(format!("wait for child: {e}")))?;
                let stderr = stderr_task.await.unwrap_or_default();
                send_exit(&mut writer, status.code().unwrap_or(-1), stderr, false).await?;
                break;
            }
            Ok(Ok(size)) => {
                let frame = StreamFrame::Stdout {
                    d: base64::engine::general_purpose::STANDARD.encode(&chunk[..size]),
                };
                framing::write_json(&mut writer, &frame)
                    .await
                    .map_err(|e| ServeError::Exec(e.0))?;
            }
        }
    }

    if let Some(task) = stdin_pump {
        let _ = task.await;
    }
    Ok(())
}

async fn send_exit(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    code: i32,
    stderr: String,
    timed_out: bool,
) -> Result<(), ServeError> {
    framing::write_json(
        writer,
        &StreamFrame::Exit {
            code,
            stderr,
            timed_out,
        },
    )
    .await
    .map_err(|e| ServeError::Exec(e.0))
}

async fn feed_stdin(
    mut reader: tokio::net::unix::OwnedReadHalf,
    mut stdin: tokio::process::ChildStdin,
) {
    loop {
        match framing::read_json::<_, StreamFrame>(&mut reader).await {
            Ok(StreamFrame::Stdin { d }) => {
                let bytes = match base64::engine::general_purpose::STANDARD.decode(d) {
                    Ok(bytes) if bytes.len() <= CHUNK_PAYLOAD_MAX => bytes,
                    _ => break,
                };
                if stdin.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            Ok(StreamFrame::StdinEof) | Err(_) => break,
            Ok(_) => break,
        }
    }
}

/// Bridge a guest console pty to the client, reusing the streaming-exec frames:
/// the pty's output flows out as `Stdout` chunks and the client's `Stdin` chunks
/// are written to the pty. The pty is opened read-write (a second write handle
/// is opened for keystrokes so reads and writes proceed concurrently), and is
/// confirmed to be a character device before any I/O so a swapped path cannot
/// turn this into a write to a regular file. The session ends with an `Exit`
/// frame on pty EOF/error, client disconnect, or the deadline.
async fn stream_console(
    reader: tokio::net::unix::OwnedReadHalf,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    pty: &str,
    timeout_secs: u64,
) -> Result<(), ServeError> {
    if let Err(reason) = super::validate_console_pty(pty) {
        return send_exit(&mut writer, -1, reason, false).await;
    }
    let mut read_file = match tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(pty)
        .await
    {
        Ok(file) => file,
        Err(e) => return send_exit(&mut writer, -1, format!("open {pty}: {e}"), false).await,
    };
    match read_file.metadata().await {
        Ok(meta) if meta.file_type().is_char_device() => {}
        Ok(_) => {
            return send_exit(
                &mut writer,
                -1,
                format!("{pty} is not a console device"),
                false,
            )
            .await
        }
        Err(e) => return send_exit(&mut writer, -1, format!("stat {pty}: {e}"), false).await,
    }
    let write_file = match tokio::fs::OpenOptions::new().write(true).open(pty).await {
        Ok(file) => file,
        Err(e) => return send_exit(&mut writer, -1, format!("open {pty}: {e}"), false).await,
    };

    let stdin_task = tokio::spawn(feed_console(reader, write_file));

    // The timeout is an idle window, reset on console output, rather than an
    // absolute cap: an actively-used console must not be dropped mid-session,
    // but one with no output for the whole window is reclaimed.
    let timeout = Duration::from_secs(timeout_secs.min(EXEC_TIMEOUT_CAP.as_secs()));
    let mut chunk = vec![0u8; CHUNK_PAYLOAD_MAX];
    loop {
        let deadline = tokio::time::Instant::now() + timeout;
        match tokio::time::timeout_at(deadline, read_file.read(&mut chunk)).await {
            Err(_) => {
                send_exit(&mut writer, 0, String::new(), true).await?;
                break;
            }
            Ok(Ok(0)) => {
                send_exit(&mut writer, 0, String::new(), false).await?;
                break;
            }
            Ok(Err(error)) => {
                send_exit(&mut writer, -1, format!("read {pty}: {error}"), false).await?;
                break;
            }
            Ok(Ok(size)) => {
                let frame = StreamFrame::Stdout {
                    d: base64::engine::general_purpose::STANDARD.encode(&chunk[..size]),
                };
                if framing::write_json(&mut writer, &frame).await.is_err() {
                    break;
                }
            }
        }
    }

    stdin_task.abort();
    let _ = stdin_task.await;
    Ok(())
}

/// Pump client `Stdin` frames (keystrokes) into a console sink (a pty file or a
/// pty master) until the client signals EOF, disconnects, or sends a malformed
/// frame.
async fn feed_console<W>(mut reader: tokio::net::unix::OwnedReadHalf, mut sink: W)
where
    W: tokio::io::AsyncWrite + Unpin,
{
    loop {
        match framing::read_json::<_, StreamFrame>(&mut reader).await {
            Ok(StreamFrame::Stdin { d }) => {
                let bytes = match base64::engine::general_purpose::STANDARD.decode(d) {
                    Ok(bytes) if bytes.len() <= CHUNK_PAYLOAD_MAX => bytes,
                    _ => break,
                };
                if sink.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = sink.flush().await;
            }
            Ok(StreamFrame::StdinEof) | Err(_) => break,
            Ok(_) => break,
        }
    }
}

/// Bridge an LXC container console to the client. LXC has no `ttyconsole` pty
/// path, so the broker allocates a pty and runs `lxc-console` on it (giving the
/// container a real terminal), then bridges the pty master with the same
/// `Stdin`/`Stdout` frames as a VM console. The session ends when `lxc-console`
/// exits, the pty closes, the client disconnects, or the idle deadline elapses.
async fn stream_lxc_console(
    reader: tokio::net::unix::OwnedReadHalf,
    mut writer: tokio::net::unix::OwnedWriteHalf,
    name: &str,
    timeout_secs: u64,
) -> Result<(), ServeError> {
    if let Err(reason) = super::validate_lxc_name(name) {
        return send_exit(&mut writer, -1, reason, false).await;
    }
    let exe = match super::program_path("lxc-console") {
        Some(path) => path,
        None => {
            return send_exit(
                &mut writer,
                -1,
                "lxc-console is not permitted".into(),
                false,
            )
            .await
        }
    };

    let pty = match pty_process::Pty::new() {
        Ok(pty) => pty,
        Err(e) => return send_exit(&mut writer, -1, format!("allocate pty: {e}"), false).await,
    };
    let pts = match pty.pts() {
        Ok(pts) => pts,
        Err(e) => return send_exit(&mut writer, -1, format!("open pts: {e}"), false).await,
    };
    // `-t 0` selects the first tty; the default Ctrl-a escape is left in place so
    // the operator can still detach a stuck session locally.
    let mut command = pty_process::Command::new(exe);
    command
        .args(["-n", name, "-t", "0"])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color");
    let mut child = match command.spawn(&pts) {
        Ok(child) => child,
        Err(e) => {
            return send_exit(&mut writer, -1, format!("start lxc-console: {e}"), false).await
        }
    };
    drop(pts);

    let (mut pty_read, pty_write) = tokio::io::split(pty);
    let stdin_task = tokio::spawn(feed_console(reader, pty_write));

    let timeout = Duration::from_secs(timeout_secs.min(EXEC_TIMEOUT_CAP.as_secs()));
    let mut chunk = vec![0u8; CHUNK_PAYLOAD_MAX];
    loop {
        let deadline = tokio::time::Instant::now() + timeout;
        match tokio::time::timeout_at(deadline, pty_read.read(&mut chunk)).await {
            Err(_) => {
                let _ = child.start_kill();
                send_exit(&mut writer, 0, String::new(), true).await?;
                break;
            }
            Ok(Ok(0)) => {
                let _ = child.wait().await;
                send_exit(&mut writer, 0, String::new(), false).await?;
                break;
            }
            Ok(Err(error)) => {
                let _ = child.start_kill();
                send_exit(&mut writer, -1, format!("read console: {error}"), false).await?;
                break;
            }
            Ok(Ok(size)) => {
                let frame = StreamFrame::Stdout {
                    d: base64::engine::general_purpose::STANDARD.encode(&chunk[..size]),
                };
                if framing::write_json(&mut writer, &frame).await.is_err() {
                    let _ = child.start_kill();
                    break;
                }
            }
        }
    }

    stdin_task.abort();
    let _ = stdin_task.await;
    let _ = child.start_kill();
    Ok(())
}

async fn handle_pci_write(kind: PciWriteKind, address: &str) -> Result<(), String> {
    let (path, value) = super::pci_write_target(kind, address);
    tokio::fs::write(&path, value.as_bytes())
        .await
        .map_err(|e| format!("write {}: {e}", path.display()))
}

async fn handle_lxc_config_append(name: &str, block: &str) -> Result<(), String> {
    validate_lxc_name(name)?;
    validate_lxc_config_block(block)?;
    let path = Path::new("/var/lib/lxc").join(name).join("config");
    let block = block.as_bytes().to_vec();
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .write(true);
        let mut file = options
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        use std::io::Write;
        file.write_all(&block)
            .map_err(|e| format!("append {}: {e}", path.display()))?;
        file.sync_data()
            .map_err(|e| format!("sync {}: {e}", path.display()))
    })
    .await
    .map_err(|e| format!("append task failed: {e}"))?
}

/// Rewrite the container config's `lxc.rootfs.path` line to point at a new
/// `zfs:<dataset>` rootfs (rootfs migration). The rewrite is a bounded,
/// line-filtered edit of the existing config file: any existing
/// `lxc.rootfs.path`/`lxc.rootfs.device` line is replaced, everything else
/// passes through untouched. Fails when the config has no rootfs line to
/// replace (the broker never fabricates one).
async fn handle_lxc_rootfs_set(name: &str, dataset: &str) -> Result<(), String> {
    validate_lxc_name(name)?;
    validate_zfs_dataset_path(dataset)?;
    if !dataset.contains('/') {
        return Err("rootfs dataset must include a pool component".to_string());
    }
    let path = Path::new("/var/lib/lxc").join(name).join("config");
    let dataset = dataset.to_string();
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .write(true);
        let mut file = options
            .open(&path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        if metadata.len() > 1024 * 1024 {
            return Err(format!("{} exceeds 1 MiB", path.display()));
        }
        use std::io::{Read, Seek, SeekFrom, Write};
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let new_path_line = format!("lxc.rootfs.path = zfs:{dataset}");
        let mut replaced = false;
        let mut out = String::with_capacity(text.len() + new_path_line.len() + 2);
        for line in text.split('\n') {
            // Re-emit every line (minus its \n, which we add back uniformly);
            // a trailing empty element from a final newline is preserved.
            let trimmed = line.trim_start();
            if trimmed.starts_with("lxc.rootfs.path") || trimmed.starts_with("lxc.rootfs.device") {
                if !replaced {
                    out.push_str(&new_path_line);
                    out.push('\n');
                    replaced = true;
                }
                // Drop duplicate/old rootfs lines entirely.
                continue;
            }
            out.push_str(line.trim_end_matches('\r'));
            out.push('\n');
        }
        if !replaced {
            return Err(format!(
                "{} has no lxc.rootfs.path line to replace",
                path.display()
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("seek {}: {e}", path.display()))?;
        file.set_len(0)
            .map_err(|e| format!("truncate {}: {e}", path.display()))?;
        file.write_all(out.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        file.sync_data()
            .map_err(|e| format!("sync {}: {e}", path.display()))
    })
    .await
    .map_err(|e| format!("rootfs set task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_write_targets_are_fixed_paths() {
        let (path, value) = super::super::pci_write_target(PciWriteKind::Unbind, "0000:01:00.0");
        assert!(path.starts_with("/sys/bus/pci/devices/0000:01:00.0"));
        assert_eq!(value, "0000:01:00.0");
    }
}
