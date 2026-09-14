//! Time-based one-time passwords (TOTP, RFC 6238) for the optional second
//! factor.
//!
//! This module is deliberately small and self-contained: it generates shared
//! secrets, renders the `otpauth://` provisioning URI authenticator apps read
//! from a QR code, and verifies a submitted 6-digit code against the current
//! time window (with a one-step tolerance on either side for clock skew). The
//! HOTP core is HMAC-SHA1 over the time counter, per RFC 4226 / RFC 6238.
//!
//! Secrets are handled as raw bytes here; the auth service persists them
//! base32-encoded (the form authenticator apps expect).

use base32::Alphabet;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// TOTP time step, in seconds. 30s is the near-universal default and what every
/// mainstream authenticator app assumes.
const PERIOD_SECS: u64 = 30;

/// Number of digits in a generated code.
const DIGITS: u32 = 6;

/// The base32 alphabet used for secrets: RFC 4648 without padding, uppercase —
/// the form Google Authenticator and compatible apps expect.
const B32: Alphabet = Alphabet::Rfc4648 { padding: false };

/// Generate a fresh 160-bit secret, base32-encoded. 160 bits (20 bytes) matches
/// the SHA-1 block/output size and is the RFC 6238 recommended length.
pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32::encode(B32, &bytes)
}

/// Build the `otpauth://totp/...` provisioning URI for a secret, encoding the
/// issuer and account label so the authenticator names the entry sensibly.
pub fn provisioning_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    // Label is `Issuer:account`; the two parts are percent-encoded separately
    // so the colon stays a literal separator (per the otpauth convention) while
    // spaces or reserved characters inside either part can't break the URI.
    let label = format!("{}:{}", percent_encode(issuer), percent_encode(account));
    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        label,
        secret_b32,
        percent_encode(issuer),
        DIGITS,
        PERIOD_SECS,
    )
}

/// Verify a submitted code against the secret at the given Unix time, accepting
/// the current step and one step on either side to tolerate clock skew and a
/// code entered as it rolls over. Returns false for a malformed secret or code.
pub fn verify(secret_b32: &str, code: &str, unix_time: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(key) = base32::decode(B32, &secret_b32.to_ascii_uppercase()) else {
        return false;
    };
    if key.is_empty() {
        return false;
    }
    let step = unix_time / PERIOD_SECS;
    // Windows -1, 0, +1. `step` is u64; guard the -1 at the epoch boundary.
    for counter in [step.wrapping_sub(1), step, step + 1] {
        // Skip the wrapped-around underflow at time ~0 (never happens in
        // practice, but keeps the comparison honest).
        if counter > step + 1 {
            continue;
        }
        if let Some(expected) = hotp(&key, counter) {
            // Constant-time compare of the two 6-digit strings.
            if ct_eq(expected.as_bytes(), code.as_bytes()) {
                return true;
            }
        }
    }
    false
}

/// The current TOTP code for a secret at the given Unix time. Returns `None`
/// for a malformed base32 secret. Test-only: used to exercise the enrollment
/// and login flows; production verification does not go through it.
#[cfg(test)]
pub fn current_code(secret_b32: &str, unix_time: u64) -> Option<String> {
    let key = base32::decode(B32, &secret_b32.to_ascii_uppercase())?;
    if key.is_empty() {
        return None;
    }
    hotp(&key, unix_time / PERIOD_SECS)
}

/// The HOTP value (RFC 4226) for a key and counter, as a zero-padded
/// `DIGITS`-wide decimal string. `None` only if the HMAC key length is rejected
/// (it never is for our fixed-size secrets).
fn hotp(key: &[u8], counter: u64) -> Option<String> {
    let mut mac = HmacSha1::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation: low 4 bits of the last byte select a 4-byte offset.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10u32.pow(DIGITS);
    Some(format!("{:0width$}", bin % modulo, width = DIGITS as usize))
}

/// Constant-time byte-slice equality, so code verification does not leak timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimal RFC 3986 percent-encoding for the URI label/issuer: keep the
/// unreserved set, escape everything else.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors use an 8-byte ASCII seed "12345678901234567890"
    // for SHA-1. Encode it to base32 and check known code values.
    fn rfc_secret() -> String {
        base32::encode(B32, b"12345678901234567890")
    }

    #[test]
    fn matches_rfc6238_vectors_sha1() {
        let secret = rfc_secret();
        // (unix_time, expected 8-digit code) from RFC 6238; we take the low 6.
        // T=59 -> 94287082 ; T=1111111109 -> 07081804 ; T=1234567890 -> 89005924
        let key = base32::decode(B32, &secret).unwrap();
        assert_eq!(&hotp(&key, 59 / 30).unwrap(), "287082");
        assert_eq!(&hotp(&key, 1111111109 / 30).unwrap(), "081804");
        assert_eq!(&hotp(&key, 1234567890 / 30).unwrap(), "005924");
    }

    #[test]
    fn verify_accepts_current_and_adjacent_windows() {
        let secret = rfc_secret();
        let key = base32::decode(B32, &secret).unwrap();
        let now = 1_600_000_000u64;
        let step = now / 30;
        let current = hotp(&key, step).unwrap();
        let prev = hotp(&key, step - 1).unwrap();
        let next = hotp(&key, step + 1).unwrap();
        assert!(verify(&secret, &current, now));
        assert!(verify(&secret, &prev, now));
        assert!(verify(&secret, &next, now));
        // Two steps away must be rejected.
        let far = hotp(&key, step + 3).unwrap();
        assert!(!verify(&secret, &far, now));
    }

    #[test]
    fn verify_rejects_malformed() {
        let secret = generate_secret();
        assert!(!verify(&secret, "12345", 0), "too short");
        assert!(!verify(&secret, "1234567", 0), "too long");
        assert!(!verify(&secret, "abcdef", 0), "non-digit");
        assert!(!verify("not base 32!", "123456", 0), "bad secret");
    }

    #[test]
    fn generate_secret_is_valid_base32() {
        let secret = generate_secret();
        assert!(base32::decode(B32, &secret).is_some());
        assert_eq!(base32::decode(B32, &secret).unwrap().len(), 20);
    }

    #[test]
    fn provisioning_uri_encodes_label() {
        let uri = provisioning_uri("ABC234", "DaygleVE", "admin user");
        assert!(uri.starts_with("otpauth://totp/DaygleVE:admin%20user?"));
        assert!(uri.contains("secret=ABC234"));
        assert!(uri.contains("issuer=DaygleVE"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
