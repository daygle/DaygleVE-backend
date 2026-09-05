//! Unix-socket client for the root-owned broker, used by the backend's
//! command routing layer.
//!
//! The client is deliberately thin: it frames the request, relies on the
//! broker's own per-exec timeout, and translates broker outcomes into a small
//! error vocabulary the command layer can map onto the API's error envelope.
//!
//! Unix-only: the broker transport is a local Unix socket with peer
//! credential authentication. On other platforms this module compiles empty
//! and the backend keeps its direct execution path (dev hosts).

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

use super::framing;
use super::{
    Op, PciWriteKind, Request, Response, StreamFrame, CHUNK_PAYLOAD_MAX, EXEC_TIMEOUT_CAP,
    PROTOCOL_VERSION,
};

/// How long a backup/restore stream may run before the broker kills it.
pub const STREAM_TIMEOUT_SECS: u64 = EXEC_TIMEOUT_CAP.as_secs();

/// Everything that can go wrong between the backend and the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    /// The broker socket is not connectable (not running, socket removed).
    Unavailable(String),
    /// The broker could not spawn the requested binary (not installed).
    SpawnNotFound(String),
    /// The child ran and failed (non-zero exit, timeout, stderr reported).
    Exec(String),
    /// The broker rejected the request or the protocol broke.
    Protocol(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Unavailable(m) => write!(f, "broker unavailable: {m}"),
            BrokerError::SpawnNotFound(m) => write!(f, "broker: {m}"),
            BrokerError::Exec(m) => write!(f, "broker: {m}"),
            BrokerError::Protocol(m) => write!(f, "broker protocol error: {m}"),
        }
    }
}

impl std::error::Error for BrokerError {}

/// Outcome of a broker exec that captured stdout.
pub struct ExecOutput {
    /// Captured stdout of the child process.
    pub stdout: String,
}

/// One client per operation: the broker serves a single request per
/// connection, which keeps state handling trivial and leaks nothing between
/// operations.
pub struct BrokerClient {
    socket: PathBuf,
    /// Deadline for connect + unary round-trips. Streaming execs are bounded
    /// by the broker-side per-exec timeout instead.
    unary_timeout: Duration,
}

impl BrokerClient {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            unary_timeout: Duration::from_secs(330),
        }
    }

    async fn connect(&self) -> Result<UnixStream, BrokerError> {
        tokio::time::timeout(self.unary_timeout, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| BrokerError::Unavailable("connect timed out".to_string()))?
            .map_err(|e| {
                BrokerError::Unavailable(format!("connect {}: {e}", self.socket.display()))
            })
    }

    fn request(&self, op: Op) -> Request {
        Request {
            v: PROTOCOL_VERSION,
            id: super::new_request_id(),
            op,
        }
    }

    /// Confirm that the broker socket is live and accepting authenticated requests.
    /// This is deliberately short so the security-posture endpoint cannot block
    /// on a wedged local socket for the full command timeout.
    pub async fn ping(&self) -> Result<(), BrokerError> {
        tokio::time::timeout(Duration::from_secs(2), self.ping_inner())
            .await
            .map_err(|_| BrokerError::Unavailable("ping timed out".to_string()))?
    }

    async fn ping_inner(&self) -> Result<(), BrokerError> {
        let mut stream = self.connect().await?;
        let request = self.request(Op::Ping);
        match self.unary(&mut stream, &request).await? {
            UnaryOutcome::Response(resp) => response_to_unit(resp),
            UnaryOutcome::Stream(_) => Err(BrokerError::Protocol(
                "unexpected streaming frame on broker ping".to_string(),
            )),
        }
    }

    /// Execute an allowlisted program, capturing stdout.
    pub async fn exec(&self, program: &str, args: &[&str]) -> Result<ExecOutput, BrokerError> {
        let mut stream = self.connect().await?;
        let request = self.request(Op::Exec {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stream: false,
            stdin_stream: false,
            timeout_secs: super::DEFAULT_TIMEOUT_SECS,
        });
        match self.unary(&mut stream, &request).await? {
            UnaryOutcome::Response(resp) => {
                response_to_output(resp).map(|stdout| ExecOutput { stdout })
            }
            UnaryOutcome::Stream(_) => Err(BrokerError::Protocol(
                "unexpected streaming frame on a unary exec".to_string(),
            )),
        }
    }

    /// Execute with stdout streaming to `sink` and (optionally) stdin pumped
    /// from `source`. Used by backup send (stdout -> file) and restore
    /// (file -> stdin). Success requires the broker's terminal `Exit` frame
    /// with exit code 0.
    pub async fn exec_streamed<S, K>(
        &self,
        program: &str,
        args: &[&str],
        source: Option<S>,
        sink: &mut K,
    ) -> Result<(), BrokerError>
    where
        S: AsyncRead + Unpin + Send + 'static,
        K: AsyncWrite + Unpin,
    {
        let stream = self.connect().await?;
        let (mut reader, mut writer) = stream.into_split();

        let request = self.request(Op::Exec {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            stream: true,
            stdin_stream: source.is_some(),
            timeout_secs: STREAM_TIMEOUT_SECS,
        });
        framing::write_json(&mut writer, &request)
            .await
            .map_err(|e| BrokerError::Protocol(e.0))?;

        // Pump stdin in the background so stdout can flow while we write.
        // When there is no source, the write half is held (unused) until the
        // response completes so the connection does not close early.
        let mut held_writer = Some(writer);
        let pump = source.map(|mut src| {
            let mut writer = held_writer.take().expect("writer available for pump");
            tokio::spawn(async move {
                let mut chunk = vec![0u8; CHUNK_PAYLOAD_MAX];
                loop {
                    let n = match src.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    let frame = StreamFrame::Stdin {
                        d: base64::engine::general_purpose::STANDARD.encode(&chunk[..n]),
                    };
                    if framing::write_json(&mut writer, &frame).await.is_err() {
                        break;
                    }
                }
                let _ = framing::write_json(&mut writer, &StreamFrame::StdinEof).await;
                writer
            })
        });

        let result = loop {
            let frame: StreamFrame = match framing::read_json(&mut reader).await {
                Ok(f) => f,
                Err(e) => break Err(BrokerError::Protocol(e.0)),
            };
            match frame {
                StreamFrame::Stdout { d } => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&d)
                        .map_err(|e| BrokerError::Protocol(format!("bad stdout chunk: {e}")))?;
                    if let Err(e) = sink.write_all(&bytes).await {
                        break Err(BrokerError::Exec(format!("write stream: {e}")));
                    }
                }
                StreamFrame::Exit {
                    code,
                    stderr,
                    timed_out,
                } => {
                    if let Err(e) = sink.flush().await {
                        break Err(BrokerError::Exec(format!("flush stream: {e}")));
                    }
                    if code == 0 {
                        break Ok(());
                    }
                    if timed_out {
                        break Err(BrokerError::Exec(format!(
                            "`{program}` timed out in the broker after {STREAM_TIMEOUT_SECS}s"
                        )));
                    }
                    break Err(BrokerError::Exec(format!(
                        "`{program} {}` failed: {}",
                        args.join(" "),
                        stderr.trim()
                    )));
                }
                StreamFrame::Stdin { .. } | StreamFrame::StdinEof => {
                    break Err(BrokerError::Protocol(
                        "broker sent an stdin frame to the client".to_string(),
                    ));
                }
            }
        };

        // The broker may terminate early on a failed spawn or timeout. Abort
        // the pump before dropping the socket so a slow/infinite source cannot
        // keep the API operation stuck after the broker has already replied.
        if let Some(handle) = pump {
            handle.abort();
            let _ = handle.await;
        }
        drop(held_writer);
        result
    }

    /// Perform a constrained PCI sysfs write (vfio-pci passthrough).
    pub async fn pci_write(&self, kind: PciWriteKind, address: &str) -> Result<(), BrokerError> {
        let mut stream = self.connect().await?;
        let request = self.request(Op::PciWrite {
            kind,
            address: address.to_string(),
        });
        match self.unary(&mut stream, &request).await? {
            UnaryOutcome::Response(resp) => response_to_unit(resp),
            UnaryOutcome::Stream(_) => Err(BrokerError::Protocol(
                "unexpected streaming frame on a PCI write".to_string(),
            )),
        }
    }

    /// Append a validated limits/networking block to an LXC container config.
    pub async fn lxc_config_append(&self, name: &str, block: &str) -> Result<(), BrokerError> {
        let mut stream = self.connect().await?;
        let request = self.request(Op::LxcConfigAppend {
            name: name.to_string(),
            block: block.to_string(),
        });
        match self.unary(&mut stream, &request).await? {
            UnaryOutcome::Response(resp) => response_to_unit(resp),
            UnaryOutcome::Stream(_) => Err(BrokerError::Protocol(
                "unexpected streaming frame on an LXC config append".to_string(),
            )),
        }
    }

    /// Send one request, read the broker's single reply.
    async fn unary(
        &self,
        stream: &mut UnixStream,
        request: &Request,
    ) -> Result<UnaryOutcome, BrokerError> {
        framing::write_json(stream, request)
            .await
            .map_err(|e| BrokerError::Protocol(e.0))?;
        let outcome = tokio::time::timeout(self.unary_timeout, async {
            let bytes = framing::read_frame(stream)
                .await
                .map_err(|e| BrokerError::Protocol(e.0))?;
            // A unary op terminates with a Response frame; a streaming op
            // terminates with an Exit frame. Try both parses so protocol
            // failures surface as such rather than as parse noise.
            if let Ok(frame) = serde_json::from_slice::<StreamFrame>(&bytes) {
                if matches!(frame, StreamFrame::Exit { .. }) {
                    return Ok(UnaryOutcome::Stream(frame));
                }
            }
            let resp: Response = serde_json::from_slice(&bytes)
                .map_err(|e| BrokerError::Protocol(format!("parse response: {e}")))?;
            Ok(UnaryOutcome::Response(resp))
        })
        .await
        .map_err(|_| BrokerError::Exec("broker reply timed out".to_string()))??;
        Ok(outcome)
    }
}

enum UnaryOutcome {
    Response(Response),
    Stream(StreamFrame),
}

fn response_to_output(resp: Response) -> Result<String, BrokerError> {
    if resp.ok {
        return Ok(resp.stdout);
    }
    Err(match resp.error_kind.as_deref() {
        Some("spawn_not_found") => {
            BrokerError::SpawnNotFound(resp.error.unwrap_or_else(|| "not found".to_string()))
        }
        Some("exec") => BrokerError::Exec(resp.error.unwrap_or_else(|| "exec failed".to_string())),
        _ => BrokerError::Protocol(resp.error.unwrap_or_else(|| "unknown failure".to_string())),
    })
}

fn response_to_unit(resp: Response) -> Result<(), BrokerError> {
    response_to_output(resp).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-process broker stub: reads one request, answers one Response
    /// frame. Exercises framing plus client mapping without executing host
    /// commands.
    #[tokio::test]
    async fn client_round_trips_a_unary_response() {
        let (socket_path, server) = spawn_stub(|| Response::success("hi".into(), String::new(), 0));
        let client = BrokerClient::new(socket_path.clone());
        let out = client
            .exec("zfs", &["list", "-H"])
            .await
            .expect("exec should succeed");
        assert_eq!(out.stdout, "hi");
        server.await.expect("server task");

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn client_maps_spawn_not_found() {
        let (socket_path, server) =
            spawn_stub(|| Response::spawn_not_found("zfs is not installed"));
        let client = BrokerClient::new(socket_path.clone());
        let err = client
            .exec("zfs", &["list"])
            .await
            .expect_err("should fail");
        assert!(matches!(err, BrokerError::SpawnNotFound(_)));
        server.await.expect("server task");

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn client_maps_exec_failure() {
        let (socket_path, server) = spawn_stub(|| {
            Response::exec_failed("`zfs list` failed: no such pool", "no such pool".into())
        });
        let client = BrokerClient::new(socket_path.clone());
        let err = client
            .exec("zfs", &["list"])
            .await
            .expect_err("should fail");
        assert!(matches!(err, BrokerError::Exec(_)), "{err:?}");
        server.await.expect("server task");

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test]
    async fn client_streams_stdout_and_reports_exit() {
        let dir =
            std::env::temp_dir().join(format!("daygleve-broker-stream-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let socket_path = dir.join("stream.sock");
        let _ = std::fs::remove_file(&socket_path);

        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _req: Request = framing::read_json(&mut stream).await.expect("read request");
            let chunk = StreamFrame::Stdout {
                d: base64::engine::general_purpose::STANDARD.encode(b"stream-data"),
            };
            framing::write_json(&mut stream, &chunk)
                .await
                .expect("chunk");
            framing::write_json(
                &mut stream,
                &StreamFrame::Exit {
                    code: 0,
                    stderr: String::new(),
                    timed_out: false,
                },
            )
            .await
            .expect("exit");
        });

        let client = BrokerClient::new(socket_path.clone());
        let mut sink = Vec::new();
        client
            .exec_streamed(
                "zfs",
                &["send", "pool/ds@snap"],
                Option::<std::io::Empty>::None,
                &mut sink,
            )
            .await
            .expect("stream should succeed");
        assert_eq!(sink, b"stream-data");
        server.await.expect("server task");

        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// Bind a stub socket that answers every connection with the given
    /// response. Returns the socket path and the accept task.
    fn spawn_stub<F>(respond: F) -> (std::path::PathBuf, tokio::task::JoinHandle<()>)
    where
        F: Fn() -> Response + Send + 'static,
    {
        let dir = std::env::temp_dir().join(format!("daygleve-broker-stub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let socket_path = dir.join("stub.sock");
        let _ = std::fs::remove_file(&socket_path);
        let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind stub socket");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _req: Request = framing::read_json(&mut stream).await.expect("read request");
            framing::write_json(&mut stream, &respond())
                .await
                .expect("respond");
        });
        (socket_path, task)
    }
}
