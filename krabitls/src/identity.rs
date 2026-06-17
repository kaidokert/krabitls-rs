//! Server-identity checks against a parsed [`CertView`].
//!
//! Server-flight verification proves key possession; callers still need a
//! policy that binds that key to the intended peer. This module supports
//! pinned public keys and SAN hostname matching. It does not build or verify
//! certificate chains.

use crate::traits::cert::CertView;

/// Reasons a server-identity check may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum IdentityError {
    /// Cert had no SubjectAltName extension.
    #[error("cert had no SubjectAltName extension")]
    NoSan,
    /// None of the cert's SAN dNSName entries matched the requested hostname.
    #[error("no SAN dNSName matched the requested hostname")]
    HostnameMismatch,
    /// Cert's SAN extension was malformed (bad DER framing inside).
    #[error("cert SAN extension was malformed")]
    MalformedSan,
    /// Pinned public key doesn't match the cert's public key.
    #[error("pinned public key did not match the cert pubkey")]
    PinMismatch,
    /// Pinned-key check ran with a pin whose algorithm family didn't match
    /// the cert (e.g. Ed25519 pin against an RSA cert).
    #[error("pinned-key algorithm family did not match the cert")]
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
/// If `hostname` parses as an IPv4 or IPv6 literal, the cert must list it
/// as an `iPAddress` SAN entry (RFC 5280 §4.2.1.6 — 4 octets for IPv4,
/// 16 for IPv6, raw network-byte-order). Otherwise it's matched against
/// the cert's `dNSName` entries.
///
/// DNS matching is ASCII-case-insensitive. Wildcards are limited to the
/// leftmost label and bind exactly one candidate label. Quick examples:
///
/// - `*.example.com` matches `foo.example.com` and `BAR.example.com`,
///   but NOT `example.com` (no leftmost label) or `a.b.example.com`
///   (wildcard binds one label, not multiple).
/// - `*` alone, or wildcards in any non-leftmost position, are rejected.
pub fn verify_hostname(cert_view: &CertView<'_>, hostname: &str) -> Result<(), IdentityError> {
    let san = cert_view.san().ok_or(IdentityError::NoSan)?;

    // IP-literal hostnames must not fall through to dNSName matching —
    // a dNSName SAN like "1.1.1.1" would otherwise spuriously match the
    // IP literal `1.1.1.1`. Detect the IP shape with a cheap byte-only
    // check (no `core::net::parser`), then either parse properly
    // (`feature = "ip-host"`) or reject as `HostnameMismatch`.
    if looks_like_ip_literal(hostname) {
        #[cfg(feature = "ip-host")]
        {
            let unbracketed = hostname
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or(hostname);
            if let Ok(v4) = unbracketed.parse::<core::net::Ipv4Addr>() {
                return match_ip_address(san, &v4.octets());
            }
            if let Ok(v6) = unbracketed.parse::<core::net::Ipv6Addr>() {
                return match_ip_address(san, &v6.octets());
            }
        }
        return Err(IdentityError::HostnameMismatch);
    }

    let hostname_bytes = hostname.as_bytes();
    for entry in san_dns_names(san) {
        let entry = entry?;
        if dns_name_matches(entry, hostname_bytes) {
            return Ok(());
        }
    }
    Err(IdentityError::HostnameMismatch)
}

/// Cheap shape-only check for IP-literal hostnames. Bytes only — no
/// `core::net::parser` machinery pulled in. Used to decide whether an
/// input should take the IP path (or be rejected when that path is
/// gated off) before any actual parsing happens.
///
/// Returns true for:
/// - URL-form IPv6 (starts with `[`)
/// - Any string containing `:` (presumed IPv6)
/// - All-digits-and-dots strings with at least one `.` (presumed IPv4)
fn looks_like_ip_literal(hostname: &str) -> bool {
    let bytes = hostname.as_bytes();
    if bytes.first() == Some(&b'[') {
        return true;
    }
    let mut saw_dot = false;
    let mut all_digit_or_dot = true;
    for &b in bytes {
        if b == b':' {
            return true;
        }
        if b == b'.' {
            saw_dot = true;
        } else if !b.is_ascii_digit() {
            all_digit_or_dot = false;
        }
    }
    !bytes.is_empty() && all_digit_or_dot && saw_dot
}

#[cfg(feature = "ip-host")]
fn match_ip_address(san: &[u8], expected: &[u8]) -> Result<(), IdentityError> {
    for entry in san_ip_addresses(san) {
        if entry? == expected {
            return Ok(());
        }
    }
    Err(IdentityError::HostnameMismatch)
}

/// Iterator over dNSName entries in a SAN `GeneralNames` SEQUENCE.
pub fn san_dns_names(san_bytes: &[u8]) -> SanDnsIter<'_> {
    SanDnsIter(SanEntryWalker {
        rest: san_bytes,
        target_tag: DNS_NAME_TAG,
    })
}

/// Iterator over iPAddress entries in a SAN `GeneralNames` SEQUENCE.
/// Yields raw 4-byte (IPv4) or 16-byte (IPv6) network-byte-order octets.
#[cfg(feature = "ip-host")]
pub fn san_ip_addresses(san_bytes: &[u8]) -> SanIpAddressIter<'_> {
    SanIpAddressIter(SanEntryWalker {
        rest: san_bytes,
        target_tag: IP_ADDRESS_TAG,
    })
}

// GeneralName CHOICE tag bytes (RFC 5280 §4.2.1.6 — primitive
// context-specific): dNSName = [2] = 0x82; iPAddress = [7] = 0x87.
const DNS_NAME_TAG: u8 = crate::backends::tlv::tag_ctx_primitive(2);
#[cfg(feature = "ip-host")]
const IP_ADDRESS_TAG: u8 = crate::backends::tlv::tag_ctx_primitive(7);

pub struct SanDnsIter<'a>(SanEntryWalker<'a>);
#[cfg(feature = "ip-host")]
pub struct SanIpAddressIter<'a>(SanEntryWalker<'a>);

impl<'a> Iterator for SanDnsIter<'a> {
    type Item = Result<&'a [u8], IdentityError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

#[cfg(feature = "ip-host")]
impl<'a> Iterator for SanIpAddressIter<'a> {
    type Item = Result<&'a [u8], IdentityError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

struct SanEntryWalker<'a> {
    rest: &'a [u8],
    target_tag: u8,
}

impl<'a> SanEntryWalker<'a> {
    fn next(&mut self) -> Option<Result<&'a [u8], IdentityError>> {
        use crate::backends::tlv::read_tlv;

        while !self.rest.is_empty() {
            let t = match read_tlv(self.rest) {
                Ok(t) => t,
                Err(_) => {
                    self.rest = &[];
                    return Some(Err(IdentityError::MalformedSan));
                }
            };
            self.rest = t.rest;
            if t.tag == self.target_tag {
                // RFC 5280 §4.2.1.6: iPAddress is exactly 4 or 16 octets.
                #[cfg(feature = "ip-host")]
                if self.target_tag == IP_ADDRESS_TAG && t.body.len() != 4 && t.body.len() != 16 {
                    return Some(Err(IdentityError::MalformedSan));
                }
                return Some(Ok(t.body));
            }
            // Skip every other GeneralName variant.
        }
        None
    }
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
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ValidityError {
    /// Caller's current time is before the cert's `notBefore`.
    #[error("cert not yet valid: notBefore={not_before}, now={now}")]
    NotYetValid { not_before: u64, now: u64 },
    /// Caller's current time is past the cert's `notAfter`.
    #[error("cert expired: notAfter={not_after}, now={now}")]
    Expired { not_after: u64, now: u64 },
    /// `validity_der` didn't decode as `SEQUENCE { Time, Time }` with
    /// `Time = UTCTime | GeneralizedTime`.
    #[error("cert validity field did not decode")]
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
///
/// Delegates the `UTCTime` / `GeneralizedTime` parsing to the `der` crate's
/// built-in types (no extra feature flag — `to_unix_duration()` is on the
/// default API surface). The leap-year math, two-digit-year pivot (RFC
/// 5280 §4.1.2.5.1), and per-month day limits all live in `der` instead
/// of the previous hand-rolled `days_to_epoch_secs`.
#[cfg(feature = "validity")]
fn parse_validity_der(der_bytes: &[u8]) -> Result<(u64, u64), ValidityError> {
    use der::{Reader, SliceReader};

    let mut outer = SliceReader::new(der_bytes).map_err(|_| ValidityError::Malformed)?;
    let result: der::Result<(u64, u64)> = outer.sequence(|inner| {
        let nb = decode_time_to_unix(inner)?;
        let na = decode_time_to_unix(inner)?;
        // RFC 5280 §4.1.2.5: `Validity ::= SEQUENCE { notBefore Time, notAfter Time }`
        // is *exactly* two Time fields — reject `SEQUENCE { Time, Time, ...trailing }`
        // so a malformed encoding can't slip through as long as the first two
        // timestamps happen to bracket `now`.
        if !inner.is_finished() {
            return Err(inner.error(der::ErrorKind::TrailingData {
                decoded: 0u8.into(),
                remaining: 0u8.into(),
            }));
        }
        Ok((nb, na))
    });
    let (nb, na) = result.map_err(|_| ValidityError::Malformed)?;
    if !outer.is_finished() {
        return Err(ValidityError::Malformed);
    }
    Ok((nb, na))
}

/// Decode one X.509 `Time` value from a `der::Reader` cursor into Unix
/// epoch seconds. The CHOICE `Time ::= UTCTime | GeneralizedTime` is
/// disambiguated by the leading tag; both `der::asn1::UtcTime` and
/// `GeneralizedTime` expose `to_unix_duration() -> core::time::Duration`
/// which we narrow to `u64` seconds.
#[cfg(feature = "validity")]
fn decode_time_to_unix<'a, R: der::Reader<'a>>(r: &mut R) -> der::Result<u64> {
    use der::asn1::{GeneralizedTime, UtcTime};
    use der::{Decode, Tag};

    let tag = Tag::peek(r)?;
    let secs = match tag {
        Tag::UtcTime => UtcTime::decode(r)?.to_unix_duration().as_secs(),
        Tag::GeneralizedTime => GeneralizedTime::decode(r)?.to_unix_duration().as_secs(),
        _ => {
            return Err(r.error(der::ErrorKind::TagUnexpected {
                expected: None,
                actual: tag,
            }));
        }
    };
    Ok(secs)
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

    #[cfg(feature = "ip-host")]
    #[test]
    fn san_ip_v4_iter() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&[1, 1, 1, 1][..]]);
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn san_ip_v6_iter() {
        let v6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4];
        let san = tlv(0x87, &v6);
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&v6[..]]);
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn san_ip_iter_skips_dns() {
        let mut san = vec![];
        san.extend(tlv(0x82, b"example.com"));
        san.extend(tlv(0x87, &[1, 1, 1, 1]));
        let ips: Vec<&[u8]> = san_ip_addresses(&san).map(|r| r.unwrap()).collect();
        assert_eq!(ips, vec![&[1, 1, 1, 1][..]]);
    }

    #[cfg(feature = "ip-host")]
    fn ed25519_view_with_san<'a>(san: &'a [u8]) -> CertView<'a> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey: &[0u8; 32],
            san: Some(san),
            validity_der: &[],
        }
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn verify_hostname_ip_v4_match() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "1.1.1.1"), Ok(()));
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn verify_hostname_ip_v4_mismatch() {
        let san = tlv(0x87, &[1, 1, 1, 1]);
        let view = ed25519_view_with_san(&san);
        assert_eq!(
            verify_hostname(&view, "1.2.3.4"),
            Err(IdentityError::HostnameMismatch)
        );
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn verify_hostname_ip_literal_skips_dns_match() {
        // dNSName "1.1.1.1" must NOT match IP literal 1.1.1.1
        let san = tlv(0x82, b"1.1.1.1");
        let view = ed25519_view_with_san(&san);
        assert_eq!(
            verify_hostname(&view, "1.1.1.1"),
            Err(IdentityError::HostnameMismatch)
        );
    }

    /// `ip-host` OFF must still reject IP-literal hostnames against
    /// dNSName SAN entries — the shape detector is unconditional.
    #[test]
    fn verify_hostname_ip_literal_rejects_dns_fallback() {
        let dns_san = |s: &str| {
            let mut v = vec![0x82, s.len() as u8];
            v.extend_from_slice(s.as_bytes());
            v
        };
        fn mk_view(san: &[u8]) -> CertView<'_> {
            CertView::Ed25519 {
                tbs: &[],
                signature: &[0u8; 64],
                pubkey: &[0u8; 32],
                san: Some(san),
                validity_der: &[],
            }
        }
        // IPv4 shape
        let san = dns_san("1.1.1.1");
        assert_eq!(
            verify_hostname(&mk_view(&san), "1.1.1.1"),
            Err(IdentityError::HostnameMismatch)
        );
        // IPv6 shape (contains `:`)
        let san = dns_san("2001:db8::1");
        assert_eq!(
            verify_hostname(&mk_view(&san), "2001:db8::1"),
            Err(IdentityError::HostnameMismatch)
        );
        // URL-form bracketed IPv6
        let san = dns_san("[2001:db8::1]");
        assert_eq!(
            verify_hostname(&mk_view(&san), "[2001:db8::1]"),
            Err(IdentityError::HostnameMismatch)
        );
        // Regular DNS name still matches
        let san = dns_san("example.com");
        assert_eq!(verify_hostname(&mk_view(&san), "example.com"), Ok(()));
    }

    #[test]
    fn ip_shape_detector() {
        assert!(looks_like_ip_literal("1.1.1.1"));
        assert!(looks_like_ip_literal("2001:db8::1"));
        assert!(looks_like_ip_literal("[2001:db8::1]"));
        assert!(looks_like_ip_literal("999.999.999.999")); // shape-only
        assert!(!looks_like_ip_literal("example.com"));
        assert!(!looks_like_ip_literal("a.b.c"));
        assert!(!looks_like_ip_literal(""));
        assert!(!looks_like_ip_literal("12345")); // no dot, no colon
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn verify_hostname_ip_v6_match() {
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let san = tlv(0x87, &v6);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "2001:db8::1"), Ok(()));
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn verify_hostname_ip_v6_bracketed() {
        let v6 = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let san = tlv(0x87, &v6);
        let view = ed25519_view_with_san(&san);
        assert_eq!(verify_hostname(&view, "[2001:db8::1]"), Ok(()));
    }

    #[cfg(feature = "ip-host")]
    #[test]
    fn san_ip_wrong_length_is_malformed() {
        // tag 7 with a 5-byte payload — not 4 or 16
        let san = tlv(0x87, &[1, 2, 3, 4, 5]);
        let r = san_ip_addresses(&san).next().unwrap();
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

        /// 2030-01-15T00:00:00Z = 1894665600.
        const T_2030_01_15: u64 = 1894665600;
        /// 2024-06-15T12:34:56Z = 1718454896.
        const T_2024_06_15_LATE: u64 = 1718454896;

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
