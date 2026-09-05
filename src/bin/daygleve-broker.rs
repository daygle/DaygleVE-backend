//! Entry point for the root-owned DaygleVE host broker.
//!
//! The broker is intentionally a separate executable from the HTTP API. The
//! appliance runs it as root with primary group `daygleve`; the backend connects
//! through `/run/daygleve/broker.sock` as the unprivileged `daygleve` user.

#[cfg(unix)]
#[path = "../broker/mod.rs"]
mod broker;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let socket_path = std::env::var_os("DAYGLEVE_BROKER_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/daygleve/broker.sock"));
    let allowed_uid = std::env::var("DAYGLEVE_BROKER_UID")
        .map_err(|_| "DAYGLEVE_BROKER_UID must be set; refusing an unauthenticated broker")?
        .parse::<u32>()
        .map_err(|_| "DAYGLEVE_BROKER_UID must be a numeric uid")?;

    broker::server::serve(broker::server::BrokerConfig {
        socket_path,
        allowed_uid,
    })
    .await?;
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("daygleve-broker is supported only on Unix/Linux appliances");
}
