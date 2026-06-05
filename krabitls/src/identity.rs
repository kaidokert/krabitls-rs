//! Server-identity checks against a parsed [`CertView`].
//!
//! Server-flight verification proves key possession; callers still need a
//! policy that binds that key to the intended peer. This module supports
//! pinned public keys and SAN hostname matching. It does not build or verify
//! certificate chains.

use crate::traits::cert::CertView;

/// Reasons a server-identity check may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IdentityError {
    /// Cert had no SubjectAltName extension.
    NoSan,
    /// None of the cert's SAN dNSName entries matched the requested hostname.
    HostnameMismatch,
    /// Cert's SAN extension was malformed (bad DER framing inside).
    MalformedSan,
    /// Pinned public key doesn't match the cert's public key.
    PinMismatch,
    /// Pinned-key check ran with a pin whose algorithm family didn't match
    /// the cert (e.g. Ed25519 pin against an RSA cert).
    PinAlgorithmMismatch,
}

/// Public key material pinned out-of-band.
#[derive(Debug, Clone, Copy)]
pub enum PinnedPubkey<'a> {
    /// 32-byte raw Ed25519 public key.
    Ed25519([u8; 32]),
    /// RSA modulus + exponent. Available with `feature = "rsa"`.
    #[cfg(feature = "rsa")]
    Rsa { modulus: &'a [u8], exponent: u32 },
    /// Lifetime binding for the Ed25519-only variant when `feature = "rsa"`
    /// is off (and a placeholder for future borrowed variants).
    #[doc(hidden)]
    _Phantom(core::marker::PhantomData<&'a ()>),
}

/// Compare the cert's public key to a pinned reference.
pub fn verify_pinned_pubkey(
    cert_view: &CertView<'_>,
    pin: &PinnedPubkey<'_>,
) -> Result<(), IdentityError> {
    match (cert_view, pin) {
        (CertView::Ed25519 { pubkey, .. }, PinnedPubkey::Ed25519(expected)) => {
            if **pubkey == *expected {
                Ok(())
            } else {
                Err(IdentityError::PinMismatch)
            }
        }
        #[cfg(feature = "rsa")]
        (
            CertView::Rsa {
                modulus, exponent, ..
            },
            PinnedPubkey::Rsa {
                modulus: pm,
                exponent: pe,
            },
        ) => {
            if modulus == pm && exponent == pe {
                Ok(())
            } else {
                Err(IdentityError::PinMismatch)
            }
        }
        _ => Err(IdentityError::PinAlgorithmMismatch),
    }
}

/// Verify the cert's SubjectAltName binds the given hostname.
///
/// Matching is ASCII-case-insensitive. Wildcards are limited to the leftmost
/// label and match exactly one candidate label.
pub fn verify_hostname(cert_view: &CertView<'_>, hostname: &[u8]) -> Result<(), IdentityError> {
    let san = cert_view.san().ok_or(IdentityError::NoSan)?;
    for entry in san_dns_names(san) {
        let entry = entry?;
        if dns_name_matches(entry, hostname) {
            return Ok(());
        }
    }
    Err(IdentityError::HostnameMismatch)
}

/// Iterator over dNSName entries in a SAN `GeneralNames` SEQUENCE.
pub fn san_dns_names(san_bytes: &[u8]) -> SanDnsIter<'_> {
    SanDnsIter { rest: san_bytes }
}

pub struct SanDnsIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SanDnsIter<'a> {
    type Item = Result<&'a [u8], IdentityError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.rest.is_empty() {
            let (tag, len, rest_after_header) = match decode_tlv_header(self.rest) {
                Ok(t) => t,
                Err(e) => {
                    self.rest = &[];
                    return Some(Err(e));
                }
            };
            if rest_after_header.len() < len {
                self.rest = &[];
                return Some(Err(IdentityError::MalformedSan));
            }
            let (value, tail) = rest_after_header.split_at(len);
            self.rest = tail;
            // dNSName = [2] IMPLICIT IA5String → primitive, context-specific, tag 2.
            const DNS_NAME_TAG: u8 = 0x82;
            if tag == DNS_NAME_TAG {
                return Some(Ok(value));
            }
            // Skip every other GeneralName variant.
        }
        None
    }
}

/// Decode one DER TLV header: returns `(tag, length, &rest_after_header)`.
/// Supports definite-form lengths up to 4 bytes (covers everything realistic
/// for cert extensions; RFC 5280 doesn't pin a hard cap but indefinite-form
/// length is forbidden by DER).
fn decode_tlv_header(buf: &[u8]) -> Result<(u8, usize, &[u8]), IdentityError> {
    if buf.len() < 2 {
        return Err(IdentityError::MalformedSan);
    }
    let tag = buf[0];
    let first_len = buf[1];
    if first_len < 0x80 {
        return Ok((tag, first_len as usize, &buf[2..]));
    }
    let n = (first_len & 0x7f) as usize;
    if n == 0 || n > 4 || buf.len() < 2 + n {
        return Err(IdentityError::MalformedSan);
    }
    // Up to 4 length bytes => values up to `u32::MAX`. Don't shift through
    // `usize`: a 16-bit `usize` can't hold n > 2 bytes and would silently
    // truncate. Accumulate as `u32`, then convert.
    let mut len: u32 = 0;
    for i in 0..n {
        len = (len << 8) | (buf[2 + i] as u32);
    }
    let len: usize = len.try_into().map_err(|_| IdentityError::MalformedSan)?;
    Ok((tag, len, &buf[2 + n..]))
}

/// Match one SAN dNSName pattern against a candidate hostname.
///
/// Rules (RFC 6125 §6.4.3 simplified to the leftmost-label-only profile):
///
/// - Exact ASCII-case-insensitive match: yes.
/// - `*.example.com` matches `<one-label>.example.com` (label may not be
///   empty and may not itself contain `.`).
/// - `*` alone, or wildcards in non-leftmost positions, are rejected.
fn dns_name_matches(pattern: &[u8], hostname: &[u8]) -> bool {
    if let Some(suffix) = pattern.strip_prefix(b"*.") {
        // Wildcard pattern. The suffix begins with the dot we kept off the
        // strip, so we need the hostname to be of the form `<label>.<suffix>`
        // where the label is non-empty and dot-free.
        if suffix.is_empty() || suffix.contains(&b'*') {
            return false;
        }
        // hostname must be longer than the suffix (at least one label + dot).
        if hostname.len() <= suffix.len() + 1 {
            return false;
        }
        let split_at = hostname.len() - suffix.len();
        let (label_with_dot, tail) = hostname.split_at(split_at);
        if !ascii_eq_ignore_case(tail, suffix) {
            return false;
        }
        // label_with_dot ends with '.', preceded by the wildcarded label.
        if label_with_dot.last() != Some(&b'.') {
            return false;
        }
        let label = &label_with_dot[..label_with_dot.len() - 1];
        if label.is_empty() || label.contains(&b'.') {
            return false;
        }
        true
    } else {
        // No wildcards allowed in non-leftmost positions either.
        if pattern.contains(&b'*') {
            return false;
        }
        ascii_eq_ignore_case(pattern, hostname)
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

// Cert validity-window check.
// Gated on feature = "validity" — embedded builds without a clock pay
// no code-size cost for either the check or the TimeSource trait.

/// Reasons [`verify_validity`] may reject a cert.
#[cfg(feature = "validity")]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValidityError {
    /// Caller's current time is before the cert's `notBefore`.
    NotYetValid { not_before: u64, now: u64 },
    /// Caller's current time is past the cert's `notAfter`.
    Expired { not_after: u64, now: u64 },
    /// `validity_der` didn't decode as `SEQUENCE { Time, Time }` with
    /// `Time = UTCTime | GeneralizedTime`.
    Malformed,
}

/// Check the cert's `notBefore` / `notAfter` window against a caller-
/// supplied [`crate::traits::TimeSource`].
///
/// X.509 wire encoding for `Time`: either `UTCTime` (2-digit year,
/// pivots at 50 per RFC 5280 §4.1.2.5.1) or `GeneralizedTime` (4-digit
/// year). Both end with the literal `Z` (UTC). krabitls parses both
/// shapes into Unix epoch seconds and does a closed-interval check.
///
/// `Ok(())` means `not_before <= now <= not_after`. The cert is
/// considered valid *at the boundaries* — same as every other widely-
/// deployed verifier.
#[cfg(feature = "validity")]
pub fn verify_validity<T: crate::traits::time::TimeSource>(
    cert_view: &crate::traits::cert::CertView<'_>,
    time: &T,
) -> Result<(), ValidityError> {
    let (not_before, not_after) = parse_validity_der(cert_view.validity_der())?;
    let now = time.now_unix_secs();
    if now < not_before {
        return Err(ValidityError::NotYetValid { not_before, now });
    }
    if now > not_after {
        return Err(ValidityError::Expired { not_after, now });
    }
    Ok(())
}

/// Decode the `Validity SEQUENCE { notBefore Time, notAfter Time }`
/// from the captured DER bytes. Returns `(not_before, not_after)` in
/// Unix-epoch seconds.
#[cfg(feature = "validity")]
fn parse_validity_der(der: &[u8]) -> Result<(u64, u64), ValidityError> {
    let (seq_tag, seq_len, body) = decode_tlv_header_inner(der)?;
    if seq_tag != 0x30 || body.len() < seq_len {
        return Err(ValidityError::Malformed);
    }
    let body = &body[..seq_len];
    let (t1_tag, t1_len, after1) = decode_tlv_header_inner(body)?;
    if after1.len() < t1_len {
        return Err(ValidityError::Malformed);
    }
    let not_before = decode_time(t1_tag, &after1[..t1_len])?;
    let rest = &after1[t1_len..];
    let (t2_tag, t2_len, after2) = decode_tlv_header_inner(rest)?;
    if after2.len() < t2_len {
        return Err(ValidityError::Malformed);
    }
    let not_after = decode_time(t2_tag, &after2[..t2_len])?;
    // RFC 5280 §4.1.2.5: `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`
    // is *exactly* two Time fields — reject `SEQUENCE { Time, Time, ...trailing }`
    // so a malformed encoding can't slip through as long as the first two
    // timestamps happen to bracket `now`.
    if !after2[t2_len..].is_empty() {
        return Err(ValidityError::Malformed);
    }
    Ok((not_before, not_after))
}

/// TLV-header decoder for the validity walker. Returns `(tag, length,
/// rest_after_header)`. Delegates to the SAN walker's `decode_tlv_header`
/// so the 16-bit-safe length accumulation (u32 → `try_into::<usize>()`)
/// is shared instead of duplicated — the previous in-place copy here
/// silently truncated on 16-bit `usize` for long-form lengths with n > 2.
#[cfg(feature = "validity")]
fn decode_tlv_header_inner(buf: &[u8]) -> Result<(u8, usize, &[u8]), ValidityError> {
    decode_tlv_header(buf).map_err(|_| ValidityError::Malformed)
}

/// Decode one X.509 `Time` value (either `UTCTime` 0x17 or
/// `GeneralizedTime` 0x18) into Unix epoch seconds.
#[cfg(feature = "validity")]
fn decode_time(tag: u8, body: &[u8]) -> Result<u64, ValidityError> {
    // UTCTime:         YYMMDDHHMMSSZ  (13 chars, 2-digit year)
    // GeneralizedTime: YYYYMMDDHHMMSSZ (15 chars, 4-digit year)
    let (year, mm, dd, hh, mn, ss) = match tag {
        0x17 if body.len() == 13 && body[12] == b'Z' => {
            let yy = parse_n(body, 0, 2)?;
            // RFC 5280 §4.1.2.5.1: YY < 50 → 20YY, YY >= 50 → 19YY.
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (
                year,
                parse_n(body, 2, 2)?,
                parse_n(body, 4, 2)?,
                parse_n(body, 6, 2)?,
                parse_n(body, 8, 2)?,
                parse_n(body, 10, 2)?,
            )
        }
        0x18 if body.len() == 15 && body[14] == b'Z' => (
            parse_n(body, 0, 4)?,
            parse_n(body, 4, 2)?,
            parse_n(body, 6, 2)?,
            parse_n(body, 8, 2)?,
            parse_n(body, 10, 2)?,
            parse_n(body, 12, 2)?,
        ),
        _ => return Err(ValidityError::Malformed),
    };
    days_to_epoch_secs(year, mm, dd, hh, mn, ss).ok_or(ValidityError::Malformed)
}

/// Parse `n` ASCII digits at `body[start..start+n]` into a `u32`.
#[cfg(feature = "validity")]
fn parse_n(body: &[u8], start: usize, n: usize) -> Result<u32, ValidityError> {
    let mut v: u32 = 0;
    for i in 0..n {
        let b = body[start + i];
        if !b.is_ascii_digit() {
            return Err(ValidityError::Malformed);
        }
        v = v * 10 + (b - b'0') as u32;
    }
    Ok(v)
}

/// Convert a Gregorian (Y, M, D, h, m, s) UTC moment into Unix epoch
/// seconds. Returns `None` for impossible dates (month 0, day 32, etc.)
/// or pre-1970 (cert validity can't predate the epoch in any realistic
/// deployment).
///
/// Algorithm: Hinnant civil-from-days, applied forward. Shifts Feb to
/// the "end of the year" so leap-year edges drop out cleanly.
#[cfg(feature = "validity")]
fn days_to_epoch_secs(y: u32, m: u32, d: u32, h: u32, mn: u32, s: u32) -> Option<u64> {
    if y < 1970 || m == 0 || m > 12 || d == 0 || h > 23 || mn > 59 || s > 60 {
        return None;
    }
    // Per-month day limit so Feb 30 / Apr 31 / etc. don't pass through.
    // Gregorian leap rule: divisible by 4 except centuries unless ÷400.
    // `is_multiple_of` (Rust 1.87+, satisfied by our edition-2024 MSRV)
    // dodges clippy::manual-is-multiple-of for the non-power-of-2 divisors.
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    // `m` is validated to `1..=12` at the top of this function, so by the
    // time we reach this match it's always exactly one of the listed
    // values. The `_ => 28` wildcard covers non-leap February (the only
    // remaining case) and avoids `unreachable!()`, which would link
    // panic-fmt machinery into the binary in `no_std` builds.
    let days_in_month: u32 = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        _ => 28,
    };
    if d > days_in_month {
        return None;
    }
    let yp = if m <= 2 { y - 1 } else { y };
    let era = yp / 400;
    let yoe = yp - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_0000_03_01 = era as i64 * 146097 + doe as i64;
    // Epoch (1970-01-01) is 719468 days after 0000-03-01 in this counting.
    let days_since_epoch = days_since_0000_03_01 - 719468;
    if days_since_epoch < 0 {
        return None;
    }
    let secs =
        (days_since_epoch as u64) * 86400 + (h as u64) * 3600 + (mn as u64) * 60 + (s as u64);
    Some(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(dns_name_matches(b"example.com", b"example.com"));
    }

    #[test]
    fn case_insensitive() {
        assert!(dns_name_matches(b"Example.COM", b"example.com"));
        assert!(dns_name_matches(b"example.com", b"EXAMPLE.com"));
    }

    #[test]
    fn no_partial_suffix() {
        assert!(!dns_name_matches(b"example.com", b"foo.example.com"));
        assert!(!dns_name_matches(b"foo.example.com", b"example.com"));
    }

    #[test]
    fn wildcard_matches_one_label() {
        assert!(dns_name_matches(b"*.example.com", b"foo.example.com"));
        assert!(dns_name_matches(b"*.example.com", b"FOO.example.com"));
    }

    #[test]
    fn wildcard_rejects_two_labels() {
        assert!(!dns_name_matches(b"*.example.com", b"a.b.example.com"));
    }

    #[test]
    fn wildcard_rejects_apex() {
        assert!(!dns_name_matches(b"*.example.com", b"example.com"));
    }

    #[test]
    fn wildcard_rejects_empty_label() {
        assert!(!dns_name_matches(b"*.example.com", b".example.com"));
    }

    #[test]
    fn wildcard_rejects_non_leftmost() {
        assert!(!dns_name_matches(b"foo.*.com", b"foo.bar.com"));
        assert!(!dns_name_matches(b"*foo.com", b"abcfoo.com"));
    }

    /// Encode one DER TLV: short-form length only (sufficient for the test
    /// inputs we build here).
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 0x80);
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn iterates_one_dns_name() {
        let san = tlv(0x82, b"example.com");
        let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
        assert_eq!(names, vec![&b"example.com"[..]]);
    }

    #[test]
    fn iterates_multiple_dns_names() {
        let mut san = vec![];
        san.extend(tlv(0x82, b"example.com"));
        san.extend(tlv(0x82, b"www.example.com"));
        let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
        assert_eq!(names, vec![&b"example.com"[..], &b"www.example.com"[..]]);
    }

    #[test]
    fn skips_non_dns_general_names() {
        let mut san = vec![];
        // rfc822Name [1]
        san.extend(tlv(0x81, b"foo@bar.com"));
        // dNSName [2]
        san.extend(tlv(0x82, b"example.com"));
        // uniformResourceIdentifier [6]
        san.extend(tlv(0x86, b"https://example.com"));
        let names: Vec<&[u8]> = san_dns_names(&san).map(|r| r.unwrap()).collect();
        assert_eq!(names, vec![&b"example.com"[..]]);
    }

    #[test]
    fn truncated_san_reports_error() {
        let san = [0x82, 0x05, b'a', b'b']; // claims 5 bytes, only 2 present
        let r = san_dns_names(&san).next().unwrap();
        assert_eq!(r, Err(IdentityError::MalformedSan));
    }

    fn ed25519_view(pubkey: &[u8; 32]) -> CertView<'_> {
        const SIG: [u8; 64] = [0u8; 64];
        CertView::Ed25519 {
            tbs: &[],
            signature: &SIG,
            pubkey,
            san: None,
            validity_der: &[],
        }
    }

    #[test]
    fn pin_match_ed25519() {
        let pk = [0x42u8; 32];
        let view = ed25519_view(&pk);
        assert_eq!(
            verify_pinned_pubkey(&view, &PinnedPubkey::Ed25519(pk)),
            Ok(())
        );
    }

    #[test]
    fn pin_mismatch_ed25519() {
        let pk = [0x42u8; 32];
        let other = [0x43u8; 32];
        let view = ed25519_view(&pk);
        assert_eq!(
            verify_pinned_pubkey(&view, &PinnedPubkey::Ed25519(other)),
            Err(IdentityError::PinMismatch)
        );
    }

    #[test]
    fn pin_algorithm_mismatch() {
        let pk = [0x42u8; 32];
        let view = ed25519_view(&pk);
        // Use the phantom-only variant to force a non-matching shape.
        let pin = PinnedPubkey::_Phantom(core::marker::PhantomData);
        assert_eq!(
            verify_pinned_pubkey(&view, &pin),
            Err(IdentityError::PinAlgorithmMismatch)
        );
    }

    #[cfg(feature = "validity")]
    mod validity_tests {
        use super::super::*;
        use crate::traits::cert::CertView;
        use crate::traits::time::{FixedTime, TimeSource};

        /// 2020-01-15T00:00:00Z = 1579046400 epoch seconds.
        const T_2020_01_15: u64 = 1579046400;
        /// 2030-01-15T00:00:00Z = 1894665600.
        const T_2030_01_15: u64 = 1894665600;
        /// 2024-06-15T12:34:56Z = 1718454896.
        const T_2024_06_15_LATE: u64 = 1718454896;

        #[test]
        fn days_to_epoch_known_anchors() {
            assert_eq!(days_to_epoch_secs(1970, 1, 1, 0, 0, 0), Some(0));
            assert_eq!(days_to_epoch_secs(2000, 1, 1, 0, 0, 0), Some(946684800));
            assert_eq!(days_to_epoch_secs(2020, 1, 15, 0, 0, 0), Some(T_2020_01_15));
            assert_eq!(
                days_to_epoch_secs(2024, 6, 15, 12, 34, 56),
                Some(T_2024_06_15_LATE)
            );
        }

        #[test]
        fn days_to_epoch_rejects_pre_epoch_and_bad_dates() {
            assert!(days_to_epoch_secs(1969, 12, 31, 23, 59, 59).is_none());
            assert!(days_to_epoch_secs(2024, 0, 1, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 13, 1, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 1, 0, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 1, 32, 0, 0, 0).is_none());
        }

        #[test]
        fn days_to_epoch_rejects_per_month_day_overflow() {
            assert!(days_to_epoch_secs(2024, 4, 31, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 6, 31, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 9, 31, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 11, 31, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2023, 2, 29, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2024, 2, 30, 0, 0, 0).is_none());
            assert!(days_to_epoch_secs(2100, 2, 29, 0, 0, 0).is_none());
        }

        #[test]
        fn days_to_epoch_accepts_per_month_day_edges() {
            assert!(days_to_epoch_secs(2024, 1, 31, 0, 0, 0).is_some());
            assert!(days_to_epoch_secs(2024, 12, 31, 0, 0, 0).is_some());
            assert!(days_to_epoch_secs(2024, 4, 30, 0, 0, 0).is_some());
            assert!(days_to_epoch_secs(2024, 2, 29, 0, 0, 0).is_some());
            assert!(days_to_epoch_secs(2000, 2, 29, 0, 0, 0).is_some());
            assert!(days_to_epoch_secs(2023, 2, 28, 0, 0, 0).is_some());
        }

        #[test]
        fn decode_utctime() {
            let v = decode_time(0x17, b"200115000000Z").unwrap();
            assert_eq!(v, T_2020_01_15);
        }

        #[test]
        fn decode_utctime_pivot_at_50() {
            // RFC 5280: YY < 50 → 20YY; YY >= 50 → 19YY. days_to_epoch
            // rejects pre-1970, so YY=99 → 1999 is the latest pre-1970-safe
            // value vs YY=49 → 2049.
            let yy_49 = decode_time(0x17, b"490101000000Z").unwrap();
            let yy_99 = decode_time(0x17, b"991231235959Z").unwrap();
            assert!(yy_49 > yy_99);
            // YY=50 → 1950, pre-1970, rejected.
            assert!(decode_time(0x17, b"500101000000Z").is_err());
        }

        #[test]
        fn decode_generalizedtime() {
            let v = decode_time(0x18, b"20300115000000Z").unwrap();
            assert_eq!(v, T_2030_01_15);
        }

        #[test]
        fn decode_time_rejects_bad_shapes() {
            assert!(decode_time(0x17, b"200115000000X").is_err()); // missing Z
            assert!(decode_time(0x17, b"2001150000Z").is_err()); // wrong length
            assert!(decode_time(0x17, b"20A115000000Z").is_err()); // non-digit
            assert!(decode_time(0x16, b"200115000000Z").is_err()); // wrong tag
        }

        /// Encode a `Validity SEQUENCE { UTCTime, UTCTime }` (short-form
        /// length only — total fits in 32 bytes).
        fn validity_der(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
            let mut body = Vec::new();
            body.push(0x17);
            body.push(not_before.len() as u8);
            body.extend_from_slice(not_before);
            body.push(0x17);
            body.push(not_after.len() as u8);
            body.extend_from_slice(not_after);
            let mut out = Vec::new();
            out.push(0x30); // SEQUENCE
            out.push(body.len() as u8);
            out.extend(body);
            out
        }

        fn cert_view_with_validity(validity_der: &[u8]) -> CertView<'_> {
            const SIG: [u8; 64] = [0u8; 64];
            const PK: [u8; 32] = [0u8; 32];
            CertView::Ed25519 {
                tbs: &[],
                signature: &SIG,
                pubkey: &PK,
                san: None,
                validity_der,
            }
        }

        #[test]
        fn validity_ok_in_window() {
            let der = validity_der(b"200115000000Z", b"300115000000Z");
            let view = cert_view_with_validity(&der);
            assert_eq!(
                verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
                Ok(())
            );
        }

        #[test]
        fn validity_not_yet_valid() {
            let der = validity_der(b"300115000000Z", b"400115000000Z");
            let view = cert_view_with_validity(&der);
            assert_eq!(
                verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
                Err(ValidityError::NotYetValid {
                    not_before: T_2030_01_15,
                    now: T_2024_06_15_LATE,
                })
            );
        }

        #[test]
        fn validity_expired() {
            let der = validity_der(b"100115000000Z", b"200115000000Z");
            let view = cert_view_with_validity(&der);
            assert!(matches!(
                verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
                Err(ValidityError::Expired { .. })
            ));
        }

        #[test]
        fn validity_malformed_der_rejected() {
            let der = [0xFF, 0xFF, 0xFF];
            let view = cert_view_with_validity(&der);
            assert_eq!(
                verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
                Err(ValidityError::Malformed)
            );
        }

        #[test]
        fn validity_rejects_trailing_fields_in_sequence() {
            // `Validity ::= SEQUENCE { notBefore Time, notAfter Time }` is
            // exactly two Time fields. Append a third TLV inside the SEQUENCE
            // (here: a NULL `0x05 0x00`) and confirm it's rejected rather
            // than silently accepted because the first two timestamps happen
            // to bracket `now`.
            let two_times = validity_der(b"200115000000Z", b"300115000000Z");
            // Pull out the inner SEQUENCE body, append the trailing TLV, and
            // re-wrap with a fixed SEQUENCE header. The two-Time body is
            // `two_times[2..]`; the SEQUENCE header is `0x30 <len>`.
            let inner = &two_times[2..];
            let mut body = Vec::from(inner);
            body.extend_from_slice(&[0x05, 0x00]); // trailing NULL
            let mut der = vec![0x30, body.len() as u8];
            der.extend(body);
            let view = cert_view_with_validity(&der);
            assert_eq!(
                verify_validity(&view, &FixedTime(T_2024_06_15_LATE)),
                Err(ValidityError::Malformed)
            );
        }

        #[test]
        fn fixed_time_is_a_timesource() {
            let t: &dyn TimeSource = &FixedTime(42);
            assert_eq!(t.now_unix_secs(), 42);
        }
    }
}
