//! Server-identity checks against a parsed [`CertView`].
//!
//! Server-flight verification proves key possession; callers still need a
//! policy that binds that key to the intended peer. This module supports
//! pinned public keys and SAN hostname matching. It does not build or verify
//! certificate chains.

use crate::backends::tlv::read_tlv;
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
    /// Raw ML-DSA public key (1312/1952/2592 B by parameter set). Available
    /// with `feature = "mldsa"`.
    #[cfg(feature = "mldsa")]
    MlDsa(&'a [u8]),
    /// Lifetime binding for the Ed25519-only variant when `feature = "rsa"`
    /// is off (and a placeholder for future borrowed variants).
    #[doc(hidden)]
    _Phantom(core::marker::PhantomData<&'a ()>),
}

impl<'a> PinnedPubkey<'a> {
    /// Convert to the owned form held by the verify strategy. Fails when an
    /// `Rsa`/`MlDsa` variant carries key material longer than the owned form's
    /// fixed buffer ([`MAX_RSA_MODULUS_BYTES`] /
    /// [`MAX_MLDSA_PUBKEY_BYTES`]). Under `not(any(feature = "rsa", feature =
    /// "mldsa"))` the error enum is uninhabited.
    ///
    /// [`MAX_RSA_MODULUS_BYTES`]: crate::backends::pin_or_self_signed::MAX_RSA_MODULUS_BYTES
    /// [`MAX_MLDSA_PUBKEY_BYTES`]: crate::backends::pin_or_self_signed::MAX_MLDSA_PUBKEY_BYTES
    pub fn to_owned_pin(
        &self,
    ) -> Result<crate::backends::PinnedPubkeyOwned, crate::backends::PinnedPubkeyOwnedError> {
        match self {
            PinnedPubkey::Ed25519(pk) => Ok(crate::backends::PinnedPubkeyOwned::ed25519(*pk)),
            #[cfg(feature = "rsa")]
            PinnedPubkey::Rsa { modulus, exponent } => {
                crate::backends::PinnedPubkeyOwned::rsa(modulus, *exponent)
            }
            #[cfg(feature = "mldsa")]
            PinnedPubkey::MlDsa(pk) => crate::backends::PinnedPubkeyOwned::mldsa(pk),
            PinnedPubkey::_Phantom(_) => unreachable!("_Phantom is not externally constructible"),
        }
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
                return ip_host::match_ip_address(san, &v4.octets());
            }
            if let Ok(v6) = unbracketed.parse::<core::net::Ipv6Addr>() {
                return ip_host::match_ip_address(san, &v6.octets());
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

/// Iterator over dNSName entries in a SAN `GeneralNames` SEQUENCE.
pub fn san_dns_names(san_bytes: &[u8]) -> SanDnsIter<'_> {
    SanDnsIter(SanEntryWalker {
        rest: san_bytes,
        target_tag: DNS_NAME_TAG,
    })
}

// GeneralName CHOICE tag byte (RFC 5280 §4.2.1.6 — primitive
// context-specific): dNSName = [2] = 0x82.
const DNS_NAME_TAG: u8 = crate::backends::tlv::tag_ctx_primitive(2);

pub struct SanDnsIter<'a>(SanEntryWalker<'a>);

impl<'a> Iterator for SanDnsIter<'a> {
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
                if self.target_tag == ip_host::IP_ADDRESS_TAG
                    && t.body.len() != 4
                    && t.body.len() != 16
                {
                    return Some(Err(IdentityError::MalformedSan));
                }
                return Some(Ok(t.body));
            }
        }
        None
    }
}

#[cfg(feature = "ip-host")]
mod ip_host {
    use super::{IdentityError, SanEntryWalker};

    pub(super) fn match_ip_address(san: &[u8], expected: &[u8]) -> Result<(), IdentityError> {
        for entry in san_ip_addresses(san) {
            if entry? == expected {
                return Ok(());
            }
        }
        Err(IdentityError::HostnameMismatch)
    }

    /// Iterator over iPAddress entries in a SAN `GeneralNames` SEQUENCE.
    /// Yields raw 4-byte (IPv4) or 16-byte (IPv6) network-byte-order octets.
    pub(super) fn san_ip_addresses(san_bytes: &[u8]) -> SanIpAddressIter<'_> {
        SanIpAddressIter(SanEntryWalker {
            rest: san_bytes,
            target_tag: IP_ADDRESS_TAG,
        })
    }

    // GeneralName CHOICE tag byte (RFC 5280 §4.2.1.6): iPAddress = [7] = 0x87.
    pub(super) const IP_ADDRESS_TAG: u8 = crate::backends::tlv::tag_ctx_primitive(7);

    pub(super) struct SanIpAddressIter<'a>(SanEntryWalker<'a>);

    impl<'a> Iterator for SanIpAddressIter<'a> {
        type Item = Result<&'a [u8], IdentityError>;
        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }
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
        if suffix.is_empty() || suffix.contains(&b'*') {
            return false;
        }
        if hostname.len() <= suffix.len() + 1 {
            return false;
        }
        let split_at = hostname.len() - suffix.len();
        let (label_with_dot, tail) = hostname.split_at(split_at);
        if !ascii_eq_ignore_case(tail, suffix) {
            return false;
        }
        if label_with_dot.last() != Some(&b'.') {
            return false;
        }
        let label = &label_with_dot[..label_with_dot.len() - 1];
        if label.is_empty() || label.contains(&b'.') {
            return false;
        }
        true
    } else {
        if pattern.contains(&b'*') {
            return false;
        }
        ascii_eq_ignore_case(pattern, hostname)
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(feature = "cert-der")]
mod validity {
    use der::asn1::{GeneralizedTime, UtcTime};
    use der::{Decode, Reader, SliceReader, Tag};

    /// Reasons the cert-validity check may reject a cert.
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
    pub fn verify_validity<T: crate::traits::time::TimeSource + ?Sized>(
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
    fn parse_validity_der(der_bytes: &[u8]) -> Result<(u64, u64), ValidityError> {
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
    fn decode_time_to_unix<'a, R: der::Reader<'a>>(r: &mut R) -> der::Result<u64> {
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
}
#[cfg(feature = "cert-der")]
pub use validity::{ValidityError, verify_validity};

#[cfg(test)]
mod tests;
