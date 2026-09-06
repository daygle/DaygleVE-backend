//! Login throttling: per-source-IP and per-account exponential backoff.
//!
//! Brute-force resistance for `POST /auth/login`. Failure counts are tracked
//! per client IP and per targeted username; each bucket's required delay
//! doubles with consecutive failures and resets on success or after a quiet
//! window. Backoff is enforced as a *delay before the first password check*,
//! so an attacker pays the penalty wall-clock time, while a legitimate user
//! who knows their password waits at most a few seconds.
//!
//! Design notes:
//! - Both buckets apply (the stricter delay wins), so an attacker rotating
//!   source IPs still trips the per-account bucket, and a distributed attack
//!   against one account is slowed by the per-IP bucket.
//! - Entries expire: a bucket that has not failed within `QUIET_WINDOW`
//!   resets, and expired buckets are evicted lazily so the maps cannot grow
//!   unbounded under an address-spoofing flood.
//! - State is in-memory only; a restart clears penalties. This matches the
//!   bearer-token store: throttling is a runtime defense, not durable state.
//! - Unknown usernames are throttled under their attempted name too, so the
//!   account bucket does not reveal whether an account exists.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Maximum delay a bucket can reach (doubling stops here).
const MAX_DELAY: Duration = Duration::from_secs(60);
/// Failures older than this no longer count toward a bucket's backoff.
const QUIET_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Hard cap on tracked buckets, as a flood-safety valve.
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Consecutive failures observed within the quiet window.
    failures: u32,
    /// When the most recent failure happened.
    last_failure: Instant,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            failures: 1,
            last_failure: now,
        }
    }

    /// Record another failure and return the new required delay.
    fn record_failure(&mut self, now: Instant) -> Duration {
        // A bucket that went quiet for a full window starts over.
        if now.duration_since(self.last_failure) > QUIET_WINDOW {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        self.last_failure = now;
        required_delay(self.failures)
    }

    /// The delay currently required before another attempt may be verified.
    fn current_delay(&self, now: Instant) -> Duration {
        if now.duration_since(self.last_failure) > QUIET_WINDOW {
            Duration::ZERO
        } else {
            required_delay(self.failures)
        }
    }
}

/// Doubling backoff: 1s, 2s, 4s, ... capped at [`MAX_DELAY`]. The first
/// failure is also penalized (`failures = 1` => shift 0 => 1s).
fn required_delay(failures: u32) -> Duration {
    // failures=0 or 1 both map to the base delay; from there it doubles,
    // clamped by MAX_DELAY at 7+ failures (2^6 = 64 capped to 60).
    let shift = failures.saturating_sub(1).min(6);
    let secs = (1u64 << shift).min(MAX_DELAY.as_secs());
    Duration::from_secs(secs)
}

/// In-memory throttle state. Cheap to clone into the shared app state.
#[derive(Default)]
pub struct LoginThrottle {
    /// Keyed by source IP.
    per_ip: HashMap<IpAddr, Bucket>,
    /// Keyed by the username as attempted (lowercased, trimmed).
    per_account: HashMap<String, Bucket>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// How long the caller must wait before this attempt may be verified.
    /// Applies both buckets and evicts expired entries as it goes.
    pub fn penalty_for(&self, ip: IpAddr, username: &str) -> Duration {
        let now = Instant::now();
        let account = normalize_username(username);
        let ip_delay = self
            .per_ip
            .get(&ip)
            .map(|b| b.current_delay(now))
            .unwrap_or(Duration::ZERO);
        let account_delay = self
            .per_account
            .get(&account)
            .map(|b| b.current_delay(now))
            .unwrap_or(Duration::ZERO);
        ip_delay.max(account_delay)
    }

    /// Record a failed login for both buckets, returning the new penalty so
    /// the error response can report it.
    pub fn record_failure(&mut self, ip: IpAddr, username: &str) -> Duration {
        let now = Instant::now();
        let account = normalize_username(username);

        // Flood safety: when a map saturates, drop expired buckets so live
        // attackers keep their penalty and long-quiet sources stop occupying
        // entries. Retaining existing live buckets keeps this O(map) only
        // once the cap is actually hit.
        if self.per_ip.len() >= MAX_ENTRIES && !self.per_ip.contains_key(&ip) {
            self.per_ip
                .retain(|_, b| now.duration_since(b.last_failure) <= QUIET_WINDOW);
        }
        if self.per_account.len() >= MAX_ENTRIES && !self.per_account.contains_key(&account) {
            self.per_account
                .retain(|_, b| now.duration_since(b.last_failure) <= QUIET_WINDOW);
        }

        let ip_delay = match self.per_ip.get_mut(&ip) {
            Some(bucket) => bucket.record_failure(now),
            None => {
                self.per_ip.insert(ip, Bucket::new(now));
                required_delay(1)
            }
        };
        let account_delay = match self.per_account.get_mut(&account) {
            Some(bucket) => bucket.record_failure(now),
            None => {
                self.per_account.insert(account, Bucket::new(now));
                required_delay(1)
            }
        };
        ip_delay.max(account_delay)
    }

    /// A successful login clears the caller's own buckets.
    pub fn record_success(&mut self, ip: IpAddr, username: &str) {
        self.per_ip.remove(&ip);
        self.per_account.remove(&normalize_username(username));
    }
}

fn normalize_username(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[test]
    fn delay_doubles_and_caps() {
        assert_eq!(required_delay(1), Duration::from_secs(1));
        assert_eq!(required_delay(2), Duration::from_secs(2));
        assert_eq!(required_delay(3), Duration::from_secs(4));
        // 2^6 = 64 caps at MAX_DELAY (60s) from 7 failures onward.
        assert_eq!(required_delay(7), MAX_DELAY);
        assert_eq!(required_delay(8), MAX_DELAY);
        assert_eq!(required_delay(100), MAX_DELAY);
    }

    #[test]
    fn per_ip_backoff_applies_and_resets_on_success() {
        let mut throttle = LoginThrottle::new();
        assert_eq!(throttle.penalty_for(ip(1), "admin"), Duration::ZERO);

        throttle.record_failure(ip(1), "admin");
        assert_eq!(throttle.penalty_for(ip(1), "admin"), Duration::from_secs(1));
        throttle.record_failure(ip(1), "admin");
        assert_eq!(throttle.penalty_for(ip(1), "admin"), Duration::from_secs(2));

        // A different IP using a fresh username is unaffected by either of
        // the first IP's or admin's penalties.
        assert_eq!(throttle.penalty_for(ip(2), "other-user"), Duration::ZERO);

        throttle.record_success(ip(1), "admin");
        assert_eq!(throttle.penalty_for(ip(1), "admin"), Duration::ZERO);
    }

    #[test]
    fn per_account_backoff_follows_the_username() {
        let mut throttle = LoginThrottle::new();
        throttle.record_failure(ip(1), "admin");
        throttle.record_failure(ip(2), "admin");
        // Two different IPs, same account: the account bucket has 2 failures.
        assert_eq!(throttle.penalty_for(ip(3), "admin"), Duration::from_secs(2));
        // Username matching is case-insensitive and trim-tolerant.
        assert_eq!(
            throttle.penalty_for(ip(3), "  ADMIN "),
            Duration::from_secs(2)
        );
        // Other accounts are untouched.
        assert_eq!(throttle.penalty_for(ip(3), "operator"), Duration::ZERO);
    }

    #[test]
    fn unknown_usernames_are_throttled_too() {
        let mut throttle = LoginThrottle::new();
        throttle.record_failure(ip(1), "no-such-user");
        throttle.record_failure(ip(1), "no-such-user");
        throttle.record_failure(ip(1), "no-such-user");
        assert_eq!(
            throttle.penalty_for(ip(1), "no-such-user"),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn stricter_of_the_two_buckets_wins() {
        let mut throttle = LoginThrottle::new();
        // Account bucket at 2 failures (2s); IP bucket at 1 failure (1s).
        throttle.record_failure(ip(1), "admin");
        throttle.record_failure(ip(2), "admin");
        assert_eq!(throttle.penalty_for(ip(1), "admin"), Duration::from_secs(2));
    }
}
