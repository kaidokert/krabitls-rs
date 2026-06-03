//! Server-identity checks against a parsed [`CertView`].
//!
//! `verify_server_flight` proves the server holds the cert's private key. It
//! does NOT prove the cert belongs to whoever the client *meant* to talk to.
//! That bridge is built here, in two shapes the embedded use case actually
//! wants:
//!
//! 1. **Pinned public key** ([`verify_pinned_pubkey`]). The caller knows
//!    which key it expects (out-of-band trust establishment — pre-shared,
//!    burned into firmware, etc.). Krabitls just byte-compares. This is the
//!    correct production answer for controlled-endpoint deployments and
//!    needs no CA bundle.
//!
//! 2. **SubjectAltName / hostname match** ([`verify_hostname`]). The caller
//!    knows a hostname; the cert's SAN dNSName entries must include it.
//!    Wildcard rules per RFC 6125 §6.4.3 (leftmost-label only). This is
//!    what's needed when you want to talk to "google.com" and trust that
//!    whoever holds a cert for that name is them.
//!
//! Neither verifies chain-to-CA — that's [`crate::PRODUCTION_GAPS`] gap
//! #24c and intentionally out of scope. The embedded answer is the pin.

use crate::traits::cert::CertView;

/// Reasons a server-identity check may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IdentityError {
    /// Cert had no SubjectAltName extension. The locked-profile assumption is
    /// that real servers always present one — bare Subject CN matching is
    /// deprecated (RFC 6125 §6.4.4, CA/Browser Forum baseline requirements).
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

/// What a caller pins out-of-band to identify the server. Shape mirrors
/// [`crate::ServerPubkey`]; the `'a` lifetime is reserved for future
/// borrowed variants.
#[derive(Debug, Clone, Copy)]
pub enum PinnedPubkey<'a> {
    /// 32-byte raw Ed25519 public key.
    Ed25519([u8; 32]),
    // Bind the `'a` lifetime parameter without contributing storage.
    // Once additional borrowed variants are implemted, this can drop.
    #[doc(hidden)]
    _Phantom(core::marker::PhantomData<&'a ()>),
}

/// Compare the cert's public key to a pinned reference. Constant-time over
/// the key bytes is **not** attempted — see the threat-model write-up for
/// why `subtle` isn't pulled in here.
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
        _ => Err(IdentityError::PinAlgorithmMismatch),
    }
}

/// Verify the cert's SubjectAltName binds the given hostname.
///
/// Walks every dNSName entry in the SAN and checks it against `hostname`.
/// Matches are ASCII-case-insensitive (per RFC 6125 §6.4.1). A SAN entry
/// of the form `*.example.com` matches exactly one extra leftmost label of
/// the candidate (RFC 6125 §6.4.3): `foo.example.com` matches, `example.com`
/// and `a.b.example.com` do not.
///
/// `hostname` should be the unqualified, undecorated DNS label sequence
/// the caller intends to reach — no scheme, no port, no trailing dot.
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

/// Iterator over dNSName entries in a SAN `GeneralNames` SEQUENCE content.
///
/// `san_bytes` is the inner DER bytes of the SAN extension's `extnValue`
/// OCTET STRING — i.e. the content of the wrapped `GeneralNames` SEQUENCE,
/// which is what [`CertView::san`] returns.
pub fn san_dns_names(san_bytes: &[u8]) -> SanDnsIter<'_> {
    SanDnsIter { rest: san_bytes }
}

pub struct SanDnsIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SanDnsIter<'a> {
    type Item = Result<&'a [u8], IdentityError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Walk DER TLVs at the GeneralName level. We're past the GeneralNames
        // outer SEQUENCE; each iteration consumes one GeneralName CHOICE.
        // We only return dNSName ([2] IMPLICIT IA5String, tag 0x82); other
        // names are skipped.
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

#[cfg(test)]
mod tests {
    use super::*;

    // ---- dns_name_matches: exact, case, wildcard ----

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

    // ---- san_dns_names: walk a hand-built GeneralNames SEQUENCE content ----

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

    // ---- verify_pinned_pubkey ----

    fn ed25519_view(pubkey: &[u8; 32]) -> CertView<'_> {
        const SIG: [u8; 64] = [0u8; 64];
        CertView::Ed25519 {
            tbs: &[],
            signature: &SIG,
            pubkey,
            san: None,
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
}
