//! [`CertParser`] impl backed by the `der` crate.
//!
//! `der` is small (zero transitive deps on `thumbv7m-none-eabi` with
//! `default-features = false`) and gives us robust DER length / tag / BIT
//! STRING handling without us writing it. Krabitls picks this implementation
//! by default; callers can plug in their own [`CertParser`] impl by
//! parameterizing [`crate::verify_server_flight`] over a different marker.

use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use der::{Decode, Reader, SliceReader, Tag, TagNumber};

use crate::traits::cert::{CertParseError, CertParser, CertView};

/// Marker type for the `der`-crate-backed [`CertParser`].
pub struct DerCert;

/// Ed25519 algorithm OID (`1.3.101.112`, RFC 8410). Used for both the
/// certificate `signatureAlgorithm` (outer + TBS) and the SPKI `algorithm`
/// field of an Ed25519 self-signed cert.
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `subjectAltName` extension OID (`2.5.29.17`, RFC 5280 §4.2.1.6). The
/// extnValue OCTET STRING wraps a `GeneralNames` SEQUENCE; we surface its
/// inner bytes on `CertView::san` for the identity-match helpers in
/// `crate::identity`.
const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// X.509 `v3` (encoded as INTEGER value `2`). RFC 5280 §4.1.2.1.
const X509_V3: u8 = 2;

/// Which algorithm family the cert's `SubjectPublicKeyInfo` carries.
/// Drives the `CertView` variant returned by the parser.
///
/// **Why SPKI and not the cert's outer `signatureAlgorithm`?** For a
/// self-signed cert (the locked-profile case) they always agree. For a
/// leaf cert signed by an intermediate CA (the public-internet case),
/// the outer signature describes the *issuer's* sig algorithm — which
/// is independent of the leaf's pubkey family and is often something
/// we don't recognize (ECDSA-P256, sha384WithRSA, etc.). Dispatching
/// on outer OID would have us reject every real-world leaf cert at
/// parse time. The leaf's identity is determined by its SPKI; the
/// outer signature is only meaningful when *we're* verifying it (i.e.
/// only in `verify_self_signed_cert`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpkiKind {
    Ed25519,
}

impl CertParser for DerCert {
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError> {
        let map_err = |_| CertParseError::Malformed;

        // ---- outer SEQUENCE: { tbs, sigAlg, signature } ----
        let outer = AnyRef::try_from(cert_der).map_err(map_err)?;
        if outer.header().tag() != Tag::Sequence {
            return Err(CertParseError::Malformed);
        }
        let mut body = SliceReader::new(outer.value()).map_err(map_err)?;

        let tbs_bytes = body.tlv_bytes().map_err(map_err)?;
        // Outer Certificate.signatureAlgorithm is captured for the TBS-
        // vs-outer symmetry check (RFC 5280 §4.1.1.2 / §4.1.2.3) below,
        // but NOT interpreted at parse time. See the SpkiKind docstring
        // for why — an issuer-signed leaf will routinely carry an outer
        // OID we don't recognize, and that's fine.
        let outer_sig_alg_bytes = body.tlv_bytes().map_err(map_err)?;

        let sig_bit = BitStringRef::decode(&mut body).map_err(map_err)?;
        if !body.is_finished() {
            return Err(CertParseError::TrailingBytes);
        }
        let sig_bytes = sig_bit
            .as_bytes()
            .ok_or(CertParseError::BitStringHasUnusedBits)?;

        // ---- step into the TBS SEQUENCE; walk to SubjectPublicKeyInfo ----
        let tbs_any = AnyRef::try_from(tbs_bytes).map_err(map_err)?;
        if tbs_any.header().tag() != Tag::Sequence {
            return Err(CertParseError::Malformed);
        }
        let mut tbs_r = SliceReader::new(tbs_any.value()).map_err(map_err)?;

        let first_tag = Tag::peek(&tbs_r).map_err(map_err)?;
        let version_present = matches!(
            first_tag,
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(0)
            }
        );
        if version_present {
            // `[0] EXPLICIT Version` wraps an INTEGER {v1=0, v2=1, v3=2}.
            let version_tlv = AnyRef::decode(&mut tbs_r).map_err(map_err)?;
            let mut vr = SliceReader::new(version_tlv.value()).map_err(map_err)?;
            let int_any = AnyRef::decode(&mut vr).map_err(map_err)?;
            if int_any.header().tag() != Tag::Integer || int_any.value().len() != 1 {
                return Err(CertParseError::Malformed);
            }
            if int_any.value()[0] != X509_V3 {
                return Err(CertParseError::UnsupportedCertVersion);
            }
            if !vr.is_finished() {
                return Err(CertParseError::Malformed);
            }
        } else {
            // DER omits `[0] EXPLICIT version` only when it carries the
            // default (v1). Our locked profile is v3-only — reject.
            return Err(CertParseError::UnsupportedCertVersion);
        }
        // serialNumber
        tbs_r.tlv_bytes().map_err(map_err)?;
        // TBS signature (AlgorithmIdentifier) — must match the outer
        // signatureAlgorithm byte-for-byte (RFC 5280 §4.1.1.2 / §4.1.2.3).
        let tbs_sig_alg_bytes = tbs_r.tlv_bytes().map_err(map_err)?;
        if tbs_sig_alg_bytes != outer_sig_alg_bytes {
            return Err(CertParseError::SignatureAlgorithmMismatch);
        }
        // issuer, validity, subject — capture the validity TLV bytes for
        // the optional `verify_validity` check (see `crate::identity`).
        // The bytes carry the DER `SEQUENCE { notBefore, notAfter }`;
        // parsing the UTCTime / GeneralizedTime → epoch seconds happens
        // on demand only when the validity check runs.
        tbs_r.tlv_bytes().map_err(map_err)?; // issuer
        let validity_der = tbs_r.tlv_bytes().map_err(map_err)?;
        tbs_r.tlv_bytes().map_err(map_err)?; // subject

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
        //                                     subjectPublicKey BIT STRING }
        let spki_bytes = tbs_r.tlv_bytes().map_err(map_err)?;
        let spki_any = AnyRef::try_from(spki_bytes).map_err(map_err)?;
        if spki_any.header().tag() != Tag::Sequence {
            return Err(CertParseError::Malformed);
        }
        let mut spki_r = SliceReader::new(spki_any.value()).map_err(map_err)?;
        let spki_alg_bytes = spki_r.tlv_bytes().map_err(map_err)?;
        let pk_bit = BitStringRef::decode(&mut spki_r).map_err(map_err)?;
        if !spki_r.is_finished() {
            return Err(CertParseError::TrailingBytes);
        }
        let pk_bytes = pk_bit
            .as_bytes()
            .ok_or(CertParseError::BitStringHasUnusedBits)?;

        // Walk the remaining TBS fields looking for the v3 extensions block
        // (`[3] EXPLICIT Extensions`). Skip past optional v2 [1]/[2] unique
        // identifiers. Inside extensions, look for the SubjectAltName OID.
        let san_bytes = walk_extensions_for_san(&mut tbs_r)?;

        // Dispatch on the SPKI algorithm — the cert kind is determined by
        // the *leaf's* pubkey family, not the issuer's signature algorithm.
        // (`outer_sig_alg_bytes` is used only for the TBS-vs-outer symmetry
        // check above; whether it's an algorithm *we* can verify is
        // checked at self-sig verification time, not here.)
        match classify_spki_algorithm(spki_alg_bytes)? {
            SpkiKind::Ed25519 => {
                if pk_bytes.len() != 32 {
                    return Err(CertParseError::WrongPubkeyLength);
                }
                let pubkey: &[u8; 32] = pk_bytes.try_into().expect("length checked above");
                if sig_bytes.len() != 64 {
                    return Err(CertParseError::WrongSignatureLength);
                }
                let signature: &[u8; 64] = sig_bytes.try_into().expect("length checked above");
                Ok(CertView::Ed25519 {
                    tbs: tbs_bytes,
                    signature,
                    pubkey,
                    san: san_bytes,
                    validity_der,
                })
            }
        }
    }
}

/// Continue reading the TBS reader past `subjectPublicKeyInfo`. Skip the
/// optional `[1] issuerUniqueID` and `[2] subjectUniqueID`. If `[3] EXPLICIT
/// Extensions` is present, walk every Extension looking for `subjectAltName`
/// (OID 2.5.29.17). Returns the inner `GeneralNames` SEQUENCE *content*
/// bytes, or `None` if there's no SAN extension (or no extensions block).
///
/// Malformed extension framing is reported as `CertParseError::Malformed`.
/// Trailing bytes after the extensions block are silently tolerated — real
/// public-internet certs occasionally append non-extension fields the spec
/// doesn't allow, and rejecting them would break interop.
fn walk_extensions_for_san<'a>(
    tbs_r: &mut SliceReader<'a>,
) -> Result<Option<&'a [u8]>, CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    while !tbs_r.is_finished() {
        let tag = Tag::peek(tbs_r).map_err(map_err)?;
        match tag {
            Tag::ContextSpecific {
                number: TagNumber(1),
                ..
            }
            | Tag::ContextSpecific {
                number: TagNumber(2),
                ..
            } => {
                // skip issuerUniqueID / subjectUniqueID
                tbs_r.tlv_bytes().map_err(map_err)?;
            }
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber(3),
            } => {
                let exts_explicit = AnyRef::decode(tbs_r).map_err(map_err)?;
                let exts_seq = AnyRef::try_from(exts_explicit.value()).map_err(map_err)?;
                if exts_seq.header().tag() != Tag::Sequence {
                    return Err(CertParseError::Malformed);
                }
                let mut exts_r = SliceReader::new(exts_seq.value()).map_err(map_err)?;
                while !exts_r.is_finished() {
                    let ext = AnyRef::decode(&mut exts_r).map_err(map_err)?;
                    if ext.header().tag() != Tag::Sequence {
                        return Err(CertParseError::Malformed);
                    }
                    let mut ext_r = SliceReader::new(ext.value()).map_err(map_err)?;
                    let ext_oid = ObjectIdentifier::decode(&mut ext_r).map_err(map_err)?;
                    // Optional `critical BOOLEAN DEFAULT FALSE` — skip if present.
                    let next_tag = Tag::peek(&ext_r).map_err(map_err)?;
                    if next_tag == Tag::Boolean {
                        ext_r.tlv_bytes().map_err(map_err)?;
                    }
                    let extn_value = AnyRef::decode(&mut ext_r).map_err(map_err)?;
                    if extn_value.header().tag() != Tag::OctetString {
                        return Err(CertParseError::Malformed);
                    }
                    if ext_oid == SAN_OID {
                        // extnValue OCTET STRING wraps `GeneralNames`.
                        let san_seq = AnyRef::try_from(extn_value.value()).map_err(map_err)?;
                        if san_seq.header().tag() != Tag::Sequence {
                            return Err(CertParseError::Malformed);
                        }
                        return Ok(Some(san_seq.value()));
                    }
                }
                return Ok(None);
            }
            _ => {
                // Unknown trailing field; tolerate.
                tbs_r.tlv_bytes().map_err(map_err)?;
            }
        }
    }
    Ok(None)
}

/// Decode the SPKI `AlgorithmIdentifier` and classify it.
/// Recognized: Ed25519 (RFC 8410). Anything else is `WrongAlgorithmOid`.
///
/// This is the *only* classification dispatch in the parser — the outer
/// `Certificate.signatureAlgorithm` describes the *issuer*'s sig alg
/// and isn't interpreted at parse time. See [`SpkiKind`].
fn classify_spki_algorithm(alg_id_bytes: &[u8]) -> Result<SpkiKind, CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    let any = AnyRef::try_from(alg_id_bytes).map_err(map_err)?;
    if any.header().tag() != Tag::Sequence {
        return Err(CertParseError::Malformed);
    }
    let mut r = SliceReader::new(any.value()).map_err(map_err)?;
    let oid = ObjectIdentifier::decode(&mut r).map_err(map_err)?;

    if oid == ED25519_OID {
        // RFC 8410 §3: parameters MUST be absent for Ed25519.
        if !r.is_finished() {
            return Err(CertParseError::AlgorithmHasParameters);
        }
        return Ok(SpkiKind::Ed25519);
    }
    Err(CertParseError::WrongAlgorithmOid)
}
