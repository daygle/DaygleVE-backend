//! Host (node) firewall.
//!
//! Renders the [`HostFirewall`] configuration to an nftables batch and applies
//! it through the broker (`nft -f <batch>`). Unlike the per-VM firewall (which
//! hooks `forward` and judges only guest MAC traffic), this hooks `input`, so it
//! filters traffic destined for the host itself and never touches forwarded
//! guest traffic — the two coexist in separate tables.
//!
//! Two rules are always emitted ahead of the operator's rules: loopback
//! (`iif lo`) and established/related return traffic are unconditionally
//! accepted, so switching to a default-drop policy can never sever local
//! sockets or in-flight connections. The chain keeps a permissive base policy
//! and, when the default is drop, ends with an explicit `drop` — so a partially
//! written ruleset (nft applies a batch atomically, but belt-and-suspenders)
//! fails open rather than bricking the node.
//!
//! The config is persisted as a single record so it survives restarts; the
//! backend re-applies it on boot.

use std::net::IpAddr;
use std::sync::Arc;

use daygleve_schema::firewall::{
    FirewallAction, FirewallPolicy, FirewallProtocol, HostFirewall, HostFirewallRule,
};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{command, ensure_safe_cidr};

/// Store record id for the single host-firewall config.
const RECORD_ID: &str = "host";
/// nftables table name (family `inet`, covering IPv4 and IPv6).
const TABLE: &str = "daygleve_host";

pub struct HostFirewallService {
    store: JsonStore,
    config: Arc<Config>,
    /// Serializes config mutation + apply so two updates can't interleave the
    /// read-modify-write or race two `nft -f` invocations.
    apply_lock: Mutex<()>,
}

impl HostFirewallService {
    pub fn new(config: Arc<Config>) -> Self {
        let store = JsonStore::new(&config.state_dir, "host_firewall");
        Self {
            store,
            config,
            apply_lock: Mutex::new(()),
        }
    }

    /// The current host-firewall config, or the default (disabled) when none has
    /// been saved yet.
    pub async fn get(&self) -> ApiResult<HostFirewall> {
        Ok(self
            .store
            .get::<HostFirewall>(RECORD_ID)
            .await?
            .unwrap_or_default())
    }

    /// Replace the host-firewall config: validate, apply to the host, then
    /// persist. The apply happens before the write so a rejected ruleset never
    /// becomes the saved state.
    pub async fn update(&self, cfg: HostFirewall) -> ApiResult<HostFirewall> {
        validate(&cfg)?;
        let _guard = self.apply_lock.lock().await;
        self.apply(&cfg).await?;
        self.store.put(RECORD_ID, &cfg).await?;
        Ok(cfg)
    }

    /// Re-apply the persisted config at startup. Best-effort: a failure is logged
    /// but does not abort boot (the node should still come up so an operator can
    /// fix the ruleset over the API).
    pub async fn apply_persisted(&self) {
        let cfg = match self.get().await {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(
                    error = e.message(),
                    "could not load host firewall config at startup"
                );
                return;
            }
        };
        let _guard = self.apply_lock.lock().await;
        if let Err(e) = self.apply(&cfg).await {
            tracing::warn!(
                error = e.message(),
                "could not apply host firewall at startup"
            );
        }
    }

    /// Render the batch for `cfg` and hand it to nft. Caller holds `apply_lock`.
    async fn apply(&self, cfg: &HostFirewall) -> ApiResult<()> {
        let batch = nft_host_batch(cfg)?;
        let dir = self.config.state_dir.join("firewall");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AppError::internal(format!("create firewall dir: {e}")))?;
        // Constant file name joined to the state dir: no request-controlled
        // component reaches the path, and it stays inside the broker's allowed
        // `/var/lib/daygleve/` root.
        let path = dir.join("host.nft");
        tokio::fs::write(&path, &batch)
            .await
            .map_err(|e| AppError::internal(format!("write firewall batch: {e}")))?;
        let path_str = path
            .to_str()
            .ok_or_else(|| AppError::internal("firewall batch path is not valid UTF-8"))?;
        command::run_ok("nft", &["-f", path_str]).await
    }
}

/// Validate a config before it can reach nft: every source CIDR is checked, and
/// a destination port is only meaningful for tcp/udp.
fn validate(cfg: &HostFirewall) -> ApiResult<()> {
    for rule in &cfg.rules {
        if let Some(cidr) = rule.source_cidr.as_deref() {
            ensure_safe_cidr(cidr, "firewall rule source_cidr")?;
        }
        if rule.dest_port.is_some()
            && !matches!(rule.protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp)
        {
            return Err(AppError::validation(
                "dest_port is only valid for tcp or udp rules",
            ));
        }
    }
    Ok(())
}

/// Render the nftables batch for the host firewall. When disabled, the chain is
/// left empty (base policy accept), which is a no-op filter.
fn nft_host_batch(cfg: &HostFirewall) -> ApiResult<String> {
    let mut b = String::new();
    b.push_str(&format!("add table inet {TABLE}\n"));
    b.push_str(&format!(
        "add chain inet {TABLE} input {{ type filter hook input priority 0; policy accept; }}\n"
    ));
    b.push_str(&format!("flush chain inet {TABLE} input\n"));

    if !cfg.enabled {
        // Disabled: an empty accept chain filters nothing.
        return Ok(b);
    }

    // Never lock out local sockets or existing connections.
    b.push_str(&format!("add rule inet {TABLE} input iif lo accept\n"));
    b.push_str(&format!(
        "add rule inet {TABLE} input ct state established,related accept\n"
    ));

    for rule in &cfg.rules {
        b.push_str(&format!(
            "add rule inet {TABLE} input {}\n",
            render_rule(rule)?
        ));
    }

    // Default policy tail: an explicit drop for unmatched traffic when the
    // default is deny. (Accept needs no tail — the base policy already accepts.)
    if matches!(cfg.default_input_policy, FirewallPolicy::Drop) {
        b.push_str(&format!("add rule inet {TABLE} input drop\n"));
    }
    Ok(b)
}

/// Render one rule's match + verdict into an nft rule body (no `add rule …`
/// prefix). CIDRs are already validated by [`validate`].
fn render_rule(rule: &HostFirewallRule) -> ApiResult<String> {
    let mut parts: Vec<String> = Vec::new();

    if let Some(cidr) = rule.source_cidr.as_deref() {
        // `inet` tables need the address family spelled out: `ip` vs `ip6`.
        let family = cidr_family(cidr)?;
        parts.push(format!("{family} saddr {cidr}"));
    }

    match rule.protocol {
        FirewallProtocol::Tcp => match rule.dest_port {
            Some(port) => parts.push(format!("tcp dport {port}")),
            None => parts.push("meta l4proto tcp".to_string()),
        },
        FirewallProtocol::Udp => match rule.dest_port {
            Some(port) => parts.push(format!("udp dport {port}")),
            None => parts.push("meta l4proto udp".to_string()),
        },
        // Cover both ICMP and ICMPv6 in the inet table.
        FirewallProtocol::Icmp => parts.push("meta l4proto { icmp, icmpv6 }".to_string()),
        // No protocol match — the rule applies to all traffic (subject to the
        // source CIDR, if any).
        FirewallProtocol::Any => {}
    }

    let verdict = match rule.action {
        FirewallAction::Accept => "accept",
        FirewallAction::Drop => "drop",
        FirewallAction::Reject => "reject",
    };
    parts.push(verdict.to_string());
    Ok(parts.join(" "))
}

/// The nft address-family keyword (`ip` or `ip6`) for a validated CIDR.
fn cidr_family(cidr: &str) -> ApiResult<&'static str> {
    let addr = cidr.split_once('/').map(|(a, _)| a).unwrap_or(cidr);
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok("ip"),
        Ok(IpAddr::V6(_)) => Ok("ip6"),
        Err(_) => Err(AppError::internal("firewall rule cidr failed to parse")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        action: FirewallAction,
        protocol: FirewallProtocol,
        source_cidr: Option<&str>,
        dest_port: Option<u16>,
    ) -> HostFirewallRule {
        HostFirewallRule {
            action,
            protocol,
            source_cidr: source_cidr.map(String::from),
            dest_port,
            description: None,
        }
    }

    #[test]
    fn disabled_renders_empty_accept_chain() {
        let batch = nft_host_batch(&HostFirewall::default()).unwrap();
        assert!(batch.contains("add table inet daygleve_host"));
        assert!(batch.contains("flush chain inet daygleve_host input"));
        // No rules and no trailing drop when disabled.
        assert!(!batch.contains(" drop\n"));
        assert!(!batch.contains("iif lo"));
    }

    #[test]
    fn enabled_default_drop_emits_baseline_and_tail() {
        let cfg = HostFirewall {
            enabled: true,
            default_input_policy: FirewallPolicy::Drop,
            rules: vec![rule(
                FirewallAction::Accept,
                FirewallProtocol::Tcp,
                Some("10.0.0.0/24"),
                Some(22),
            )],
        };
        let batch = nft_host_batch(&cfg).unwrap();
        assert!(batch.contains("input iif lo accept"));
        assert!(batch.contains("ct state established,related accept"));
        assert!(batch.contains("ip saddr 10.0.0.0/24 tcp dport 22 accept"));
        // Default-drop tail present.
        assert!(batch
            .trim_end()
            .ends_with("add rule inet daygleve_host input drop"));
    }

    #[test]
    fn enabled_default_accept_has_no_drop_tail() {
        let cfg = HostFirewall {
            enabled: true,
            default_input_policy: FirewallPolicy::Accept,
            rules: vec![rule(
                FirewallAction::Drop,
                FirewallProtocol::Any,
                Some("203.0.113.5/32"),
                None,
            )],
        };
        let batch = nft_host_batch(&cfg).unwrap();
        assert!(batch.contains("ip saddr 203.0.113.5/32 drop"));
        assert!(!batch.trim_end().ends_with("input drop"));
    }

    #[test]
    fn ipv6_source_uses_ip6_family() {
        let r = rule(
            FirewallAction::Accept,
            FirewallProtocol::Any,
            Some("2001:db8::/32"),
            None,
        );
        assert_eq!(render_rule(&r).unwrap(), "ip6 saddr 2001:db8::/32 accept");
    }

    #[test]
    fn icmp_and_reject_render() {
        let r = rule(FirewallAction::Reject, FirewallProtocol::Icmp, None, None);
        assert_eq!(
            render_rule(&r).unwrap(),
            "meta l4proto { icmp, icmpv6 } reject"
        );
    }

    #[test]
    fn udp_without_port_matches_l4proto() {
        let r = rule(FirewallAction::Accept, FirewallProtocol::Udp, None, None);
        assert_eq!(render_rule(&r).unwrap(), "meta l4proto udp accept");
    }

    #[test]
    fn validate_rejects_port_on_non_tcp_udp() {
        let cfg = HostFirewall {
            enabled: true,
            default_input_policy: FirewallPolicy::Accept,
            rules: vec![rule(
                FirewallAction::Accept,
                FirewallProtocol::Icmp,
                None,
                Some(22),
            )],
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_bad_cidr() {
        let cfg = HostFirewall {
            enabled: true,
            default_input_policy: FirewallPolicy::Accept,
            rules: vec![rule(
                FirewallAction::Accept,
                FirewallProtocol::Tcp,
                Some("not-a-cidr"),
                Some(22),
            )],
        };
        assert!(validate(&cfg).is_err());
    }
}
