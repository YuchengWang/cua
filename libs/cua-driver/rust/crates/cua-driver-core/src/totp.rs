// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Reusable RFC 6238 TOTP generator with `otpauth://` URI parsing,
//! boundary-wait protection, and explicit memory zeroization.

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256, Sha512};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// Default TOTP time step in seconds (RFC 6238).
pub const DEFAULT_TOTP_PERIOD_SECS: u64 = 30;
/// Default TOTP code length in digits.
pub const DEFAULT_TOTP_DIGITS: u32 = 6;
/// Default minimum remaining seconds in the current window before waiting for the next window.
pub const DEFAULT_MIN_REMAINING_SECS: u64 = 4;

/// Supported HMAC hash algorithms for RFC 6238 TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for TotpAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TotpAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            other => anyhow::bail!("unsupported TOTP algorithm '{other}' (expected SHA1, SHA256, or SHA512)"),
        }
    }
}

/// Parsed TOTP configuration. Secret bytes are zeroized on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpConfig {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &format!("<redacted {} bytes>", self.secret.len()))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish()
    }
}

/// Result of generating a TOTP code with boundary-wait metadata.
/// The generated `code` is zeroized on drop and redacted from `Debug`.
pub struct TotpGenerationOutcome {
    pub code: Zeroizing<String>,
    pub waited_boundary: bool,
    pub waited_ms: u64,
    pub remaining_secs: u64,
    pub period: u64,
    pub digits: u32,
}

impl fmt::Debug for TotpGenerationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpGenerationOutcome")
            .field("code", &"<redacted>")
            .field("waited_boundary", &self.waited_boundary)
            .field("waited_ms", &self.waited_ms)
            .field("remaining_secs", &self.remaining_secs)
            .field("period", &self.period)
            .field("digits", &self.digits)
            .finish()
    }
}

impl TotpConfig {
    /// Construct a validated [`TotpConfig`] from raw secret bytes.
    pub fn new(
        secret: Zeroizing<Vec<u8>>,
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
    ) -> anyhow::Result<Self> {
        if secret.is_empty() {
            anyhow::bail!("TOTP secret must not be empty");
        }
        if !(6..=8).contains(&digits) {
            anyhow::bail!("TOTP digits must be between 6 and 8 (got {digits})");
        }
        if period == 0 {
            anyhow::bail!("TOTP period must be greater than 0");
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
        })
    }

    /// Parse either a raw Base32 secret (tolerating whitespace and lowercase)
    /// or an `otpauth://totp/...` URI.
    pub fn from_secret_or_uri(raw: &str) -> anyhow::Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            anyhow::bail!("TOTP secret or URI is empty");
        }
        if trimmed.len() >= 10 && trimmed[..10].eq_ignore_ascii_case("otpauth://") {
            return Self::from_otpauth_uri(trimmed);
        }
        let secret = decode_base32(trimmed)?;
        Self::new(secret, TotpAlgorithm::Sha1, DEFAULT_TOTP_DIGITS, DEFAULT_TOTP_PERIOD_SECS)
    }

    /// Parse an `otpauth://totp/...` URI without ever echoing the secret in errors.
    pub fn from_otpauth_uri(uri: &str) -> anyhow::Result<Self> {
        let parsed = Url::parse(uri.trim())
            .map_err(|_| anyhow::anyhow!("invalid otpauth URI format"))?;
        if !parsed.scheme().eq_ignore_ascii_case("otpauth") {
            anyhow::bail!("expected otpauth:// URI scheme");
        }
        let otp_type = parsed.host_str().unwrap_or_default();
        if !otp_type.eq_ignore_ascii_case("totp") {
            anyhow::bail!("unsupported otpauth type '{otp_type}' (expected 'totp')");
        }

        let mut secret_param: Option<Zeroizing<String>> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = DEFAULT_TOTP_DIGITS;
        let mut period = DEFAULT_TOTP_PERIOD_SECS;

        for (k, v) in parsed.query_pairs() {
            if k.eq_ignore_ascii_case("secret") {
                secret_param = Some(Zeroizing::new(v.into_owned()));
            } else if k.eq_ignore_ascii_case("algorithm") {
                algorithm = v.parse::<TotpAlgorithm>()?;
            } else if k.eq_ignore_ascii_case("digits") {
                digits = v
                    .parse::<u32>()
                    .map_err(|_| anyhow::anyhow!("invalid TOTP digits parameter"))?;
            } else if k.eq_ignore_ascii_case("period") {
                period = v
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("invalid TOTP period parameter"))?;
            }
        }

        let raw_secret = secret_param
            .ok_or_else(|| anyhow::anyhow!("otpauth URI is missing required 'secret' parameter"))?;
        let secret = decode_base32(&raw_secret)?;
        Self::new(secret, algorithm, digits, period)
    }

    /// Generate the RFC 6238 TOTP code for a specific UNIX timestamp (seconds).
    pub fn generate_at(&self, unix_secs: u64) -> Zeroizing<String> {
        let counter = unix_secs / self.period;
        let msg = counter.to_be_bytes();
        let mut digest = hmac_digest(self.algorithm, &self.secret, &msg);
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin_code = (((digest[offset] & 0x7f) as u32) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | (digest[offset + 3] as u32);
        digest.zeroize();

        let modulo = 10u32.pow(self.digits);
        let otp = bin_code % modulo;
        let width = self.digits as usize;
        Zeroizing::new(format!("{otp:0width$}"))
    }

    /// Generate a TOTP code at the current wall-clock time, waiting into the next
    /// period if fewer than `min_remaining_secs` remain in the current period.
    pub fn generate_now_with_guard(
        &self,
        min_remaining_secs: u64,
    ) -> anyhow::Result<TotpGenerationOutcome> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("system clock before UNIX_EPOCH: {e}"))?;
        let now_ms = now.as_millis() as u64;
        let period_ms = self.period.saturating_mul(1_000);
        let elapsed_ms = now_ms % period_ms;
        let remaining_ms = period_ms - elapsed_ms;
        let remaining_secs = remaining_ms.div_ceil(1_000);

        let effective_min = if min_remaining_secs == 0 {
            0
        } else {
            min_remaining_secs.min(self.period.saturating_sub(1))
        };

        let mut waited_boundary = false;
        let mut waited_ms = 0u64;

        let active_unix_secs = if effective_min > 0 && remaining_secs <= effective_min {
            // Sleep slightly past the boundary (+50ms) so the subsequent clock read
            // lands cleanly inside the new TOTP period.
            let sleep_ms = remaining_ms.saturating_add(50);
            std::thread::sleep(Duration::from_millis(sleep_ms));
            waited_boundary = true;
            waited_ms = sleep_ms;
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| anyhow::anyhow!("system clock before UNIX_EPOCH: {e}"))?
                .as_secs()
        } else {
            now.as_secs()
        };

        let final_remaining = remaining_secs_in_period(active_unix_secs, self.period);
        let code = self.generate_at(active_unix_secs);

        Ok(TotpGenerationOutcome {
            code,
            waited_boundary,
            waited_ms,
            remaining_secs: final_remaining,
            period: self.period,
            digits: self.digits,
        })
    }
}

/// Remaining whole seconds in the current TOTP period (`1..=period`).
pub const fn remaining_secs_in_period(unix_secs: u64, period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    period - (unix_secs % period)
}

/// Returns `true` when the current period has `<= effective_min` seconds left
/// (so callers should wait for the next period before typing the code).
pub const fn should_wait_for_next_period(
    unix_secs: u64,
    period: u64,
    min_remaining_secs: u64,
) -> bool {
    if period <= 1 || min_remaining_secs == 0 {
        return false;
    }
    let effective_min = if min_remaining_secs >= period {
        period - 1
    } else {
        min_remaining_secs
    };
    remaining_secs_in_period(unix_secs, period) <= effective_min
}

/// Decode a RFC 4648 Base32 string (ignoring whitespace, case-insensitive, optional `=` padding).
pub fn decode_base32(input: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut cleaned = Zeroizing::new(Vec::<u8>::with_capacity(input.len()));
    for b in input.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        cleaned.push(b.to_ascii_uppercase());
    }
    while cleaned.last() == Some(&b'=') {
        cleaned.pop();
    }
    if cleaned.is_empty() {
        anyhow::bail!("Base32 TOTP secret is empty");
    }

    let mut out = Zeroizing::new(Vec::with_capacity((cleaned.len() * 5) / 8));
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for &b in cleaned.iter() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => anyhow::bail!("invalid Base32 character in TOTP secret"),
        };
        buffer = (buffer << 5) | (val as u32);
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            out.push(((buffer >> bits_left) & 0xff) as u8);
        }
    }

    buffer.zeroize();
    if out.is_empty() {
        anyhow::bail!("Base32 TOTP secret decoded to zero bytes");
    }
    Ok(out)
}

/// RFC 2104 HMAC over `SHA-1`, `SHA-256`, or `SHA-512` with zeroized key pads.
fn hmac_digest(algorithm: TotpAlgorithm, key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    let block_size = match algorithm {
        TotpAlgorithm::Sha1 | TotpAlgorithm::Sha256 => 64usize,
        TotpAlgorithm::Sha512 => 128usize,
    };

    let mut key_block = Zeroizing::new(vec![0u8; block_size]);
    if key.len() > block_size {
        let hashed = hash_bytes(algorithm, key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new(vec![0x36u8; block_size]);
    let mut opad = Zeroizing::new(vec![0x5cu8; block_size]);
    for i in 0..block_size {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_input = Zeroizing::new(Vec::with_capacity(block_size + message.len()));
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = hash_bytes(algorithm, &inner_input);

    let mut outer_input = Zeroizing::new(Vec::with_capacity(block_size + inner_hash.len()));
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    hash_bytes(algorithm, &outer_input)
}

fn hash_bytes(algorithm: TotpAlgorithm, data: &[u8]) -> Zeroizing<Vec<u8>> {
    match algorithm {
        TotpAlgorithm::Sha1 => Zeroizing::new(sha1_digest(data).to_vec()),
        TotpAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Zeroizing::new(hasher.finalize().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            Zeroizing::new(hasher.finalize().to_vec())
        }
    }
}

/// Pure-Rust RFC 3174 SHA-1 digest (used only for standard RFC 6238 HMAC-SHA1 TOTP).
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Zeroizing::new(Vec::with_capacity(data.len() + 72));
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = Zeroizing::new([0u32; 80]);
    for chunk in padded.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test seeds:
    // SHA1:   "12345678901234567890" (20 bytes)
    // SHA256: "12345678901234567890123456789012" (32 bytes)
    // SHA512: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
    const SEED_20: &[u8] = b"12345678901234567890";
    const SEED_32: &[u8] = b"12345678901234567890123456789012";
    const SEED_64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn rfc6238_appendix_b_test_vectors_sha1_sha256_sha512() {
        let vectors: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        let cfg1 = TotpConfig::new(Zeroizing::new(SEED_20.to_vec()), TotpAlgorithm::Sha1, 8, 30).unwrap();
        let cfg256 = TotpConfig::new(Zeroizing::new(SEED_32.to_vec()), TotpAlgorithm::Sha256, 8, 30).unwrap();
        let cfg512 = TotpConfig::new(Zeroizing::new(SEED_64.to_vec()), TotpAlgorithm::Sha512, 8, 30).unwrap();

        for &(ts, exp1, exp256, exp512) in vectors {
            assert_eq!(cfg1.generate_at(ts).as_str(), exp1, "SHA1 mismatch at {ts}");
            assert_eq!(cfg256.generate_at(ts).as_str(), exp256, "SHA256 mismatch at {ts}");
            assert_eq!(cfg512.generate_at(ts).as_str(), exp512, "SHA512 mismatch at {ts}");
        }
    }

    #[test]
    fn base32_tolerates_whitespace_lowercase_and_padding() {
        // "12345678901234567890" in Base32 is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let canonical = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let messy = " gezd gnbv gy3t qojq gezd gnbv gy3t qojq==== ";
        assert_eq!(decode_base32(canonical).unwrap().as_slice(), SEED_20);
        assert_eq!(decode_base32(messy).unwrap().as_slice(), SEED_20);

        let cfg = TotpConfig::from_secret_or_uri(messy).unwrap();
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(cfg.digits, 6);
        assert_eq!(cfg.period, 30);
        assert_eq!(cfg.generate_at(59).as_str(), "287082");
    }

    #[test]
    fn otpauth_uri_parsing_extracts_params_and_rejects_invalid() {
        let uri = "otpauth://totp/IBKR:paper_user?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=IBKR&algorithm=SHA256&digits=8&period=30";
        let cfg = TotpConfig::from_secret_or_uri(uri).unwrap();
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 30);

        // HOTP must be rejected
        let hotp = "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQ&counter=1";
        assert!(TotpConfig::from_secret_or_uri(hotp).is_err());

        // Missing secret must be rejected
        let no_secret = "otpauth://totp/Test?issuer=IBKR";
        assert!(TotpConfig::from_secret_or_uri(no_secret).is_err());
    }

    #[test]
    fn boundary_guard_detects_expiring_window() {
        // Period = 30s, min_remaining_secs = 4s
        assert_eq!(remaining_secs_in_period(0, 30), 30);
        assert_eq!(remaining_secs_in_period(25, 30), 5);
        assert_eq!(remaining_secs_in_period(26, 30), 4);
        assert_eq!(remaining_secs_in_period(29, 30), 1);

        assert!(!should_wait_for_next_period(0, 30, 4));
        assert!(!should_wait_for_next_period(25, 30, 4));
        assert!(should_wait_for_next_period(26, 30, 4));
        assert!(should_wait_for_next_period(29, 30, 4));
        assert!(!should_wait_for_next_period(29, 30, 0));
    }

    #[test]
    fn debug_output_never_leaks_secret_or_code() {
        let cfg = TotpConfig::from_secret_or_uri("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        let dbg_cfg = format!("{cfg:?}");
        assert!(!dbg_cfg.contains("GEZD"));
        assert!(!dbg_cfg.contains("123456"));

        let outcome = cfg.generate_now_with_guard(0).unwrap();
        let dbg_out = format!("{outcome:?}");
        assert!(!dbg_out.contains(outcome.code.as_str()));
        assert!(dbg_out.contains("<redacted>"));
    }
}
