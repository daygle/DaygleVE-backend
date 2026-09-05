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
    command.spawn().await.map_err(|e| {
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
    mut reader: tokio::net::unix::OwnedReadHalf,
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
    let result = loop {
        match tokio::time::timeout_at(deadline, stdout.read(&mut chunk)).await {
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                let stderr = stderr_task.await.unwrap_or_default();
                send_exit(&mut writer, -1, stderr, true).await?;
                break ();
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
                break ();
            }
            Ok(Ok(0)) => {
                let status = child
                    .wait()
                    .await
                    .map_err(|e| ServeError::Exec(format!("wait for child: {e}")))?;
                let stderr = stderr_task.await.unwrap_or_default();
                send_exit(&mut writer, status.code().unwrap_or(-1), stderr, false).await?;
                break ();
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
    };

    if let Some(task) = stdin_pump {
        let _ = task.await;
    }
    Ok(result)
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
