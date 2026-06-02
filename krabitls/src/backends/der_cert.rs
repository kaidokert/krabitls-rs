//! [`CertParser`] impl backed by the `der` crate.
//!
//! `der` is small (zero transitive deps on `thumbv7m-none-eabi` with
//! `default-features = false`) and gives us robust DER length / tag / BIT
//! STRING handling without us writing it. Krabitls picks this implementation
//! by default; callers can plug in their own [`CertParser`] impl by
//! parameterizing [`crate::verify_server_flight`] over a different marker.
//!
//! Ed25519 is always supported. RSA (RFC 3279 `rsaEncryption` SPKI plus
//! `sha256WithRSAEncryption` outer signature) is gated behind
//! `feature = "rsa"`.

use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use der::{Decode, Reader, SliceReader, Tag, TagNumber};

use crate::traits::cert::{CertParseError, CertParser, CertView};

/// Marker type for the `der`-crate-backed [`CertParser`].
pub struct DerCert;

/// Ed25519 algorithm OID (`1.3.101.112`, RFC 8410). Used for both the
/// certificate `signatureAlgorithm` (outer + TBS) and the SPKI `algorithm`
/// field of an Ed25519 self-signed cert.
const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// `sha256WithRSAEncryption` OID (`1.2.840.113549.1.1.11`, RFC 5754). Used
/// for the cert `signatureAlgorithm` of an RSA-PKCS#1-v1.5 self-signed cert.
#[cfg(feature = "rsa")]
const SHA256_WITH_RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// `rsaEncryption` OID (`1.2.840.113549.1.1.1`, RFC 3279). Used for the SPKI
/// algorithm of an RSA cert.
#[cfg(feature = "rsa")]
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `subjectAltName` extension OID (`2.5.29.17`, RFC 5280 §4.2.1.6). The
/// extnValue OCTET STRING wraps a `GeneralNames` SEQUENCE; we surface its
/// inner bytes on `CertView::san` for the identity-match helpers in
/// `crate::identity`.
const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// X.509 `v3` (encoded as INTEGER value `2`). RFC 5280 §4.1.2.1.
const X509_V3: u8 = 2;

/// Which algorithm family the cert was signed under. Drives the SPKI side
/// of the parse — Ed25519 cert sig must come with an Ed25519 SPKI;
/// `sha256WithRSAEncryption` cert sig must come with an `rsaEncryption` SPKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertSigKind {
    Ed25519,
    #[cfg(feature = "rsa")]
    Rsa,
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
        let outer_sig_alg_bytes = body.tlv_bytes().map_err(map_err)?;
        let sig_kind = check_cert_signature_algorithm(outer_sig_alg_bytes)?;

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
        // the optional `verify_validity` check (see `crate::identity` +
        // `crate::time`). The bytes carry the DER `SEQUENCE { notBefore,
        // notAfter }`; parsing the UTCTime / GeneralizedTime → epoch
        // seconds happens on demand only when the validity check runs.
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

        // Dispatch on the cert signature scheme. Each branch validates that
        // the SPKI algorithm + key bytes match the cert sig family.
        match sig_kind {
            CertSigKind::Ed25519 => {
                check_ed25519_spki_algorithm(spki_alg_bytes)?;
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
            #[cfg(feature = "rsa")]
            CertSigKind::Rsa => {
                check_rsa_spki_algorithm(spki_alg_bytes)?;
                let (modulus, exponent) = parse_rsa_pubkey(pk_bytes)?;
                // PKCS#1 v1.5 signature length == RSA modulus length.
                if sig_bytes.len() != modulus.len() {
                    return Err(CertParseError::WrongSignatureLength);
                }
                Ok(CertView::Rsa {
                    tbs: tbs_bytes,
                    signature: sig_bytes,
                    modulus,
                    exponent,
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

/// Decode the cert's outer / TBS `signatureAlgorithm` and classify it.
/// Recognized: Ed25519 (RFC 8410); `sha256WithRSAEncryption` (RFC 5754).
/// Anything else is rejected with `WrongAlgorithmOid`.
fn check_cert_signature_algorithm(alg_id_bytes: &[u8]) -> Result<CertSigKind, CertParseError> {
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
        return Ok(CertSigKind::Ed25519);
    }
    #[cfg(feature = "rsa")]
    if oid == SHA256_WITH_RSA_OID {
        // RFC 4055 §2.1 + RFC 5754 §3.2: parameters MUST be NULL (explicit).
        require_optional_null_params(&mut r)?;
        return Ok(CertSigKind::Rsa);
    }
    Err(CertParseError::WrongAlgorithmOid)
}

/// SPKI algorithm validator for the Ed25519 cert path: must be the Ed25519 OID
/// with absent parameters.
fn check_ed25519_spki_algorithm(alg_id_bytes: &[u8]) -> Result<(), CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    let any = AnyRef::try_from(alg_id_bytes).map_err(map_err)?;
    if any.header().tag() != Tag::Sequence {
        return Err(CertParseError::Malformed);
    }
    let mut r = SliceReader::new(any.value()).map_err(map_err)?;
    let oid = ObjectIdentifier::decode(&mut r).map_err(map_err)?;
    if oid != ED25519_OID {
        return Err(CertParseError::AlgorithmFamilyMismatch);
    }
    if !r.is_finished() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    Ok(())
}

/// SPKI algorithm validator for the RSA cert path: must be `rsaEncryption`
/// with NULL parameters (RFC 3279 §2.3.1).
#[cfg(feature = "rsa")]
fn check_rsa_spki_algorithm(alg_id_bytes: &[u8]) -> Result<(), CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    let any = AnyRef::try_from(alg_id_bytes).map_err(map_err)?;
    if any.header().tag() != Tag::Sequence {
        return Err(CertParseError::Malformed);
    }
    let mut r = SliceReader::new(any.value()).map_err(map_err)?;
    let oid = ObjectIdentifier::decode(&mut r).map_err(map_err)?;
    if oid != RSA_ENCRYPTION_OID {
        return Err(CertParseError::AlgorithmFamilyMismatch);
    }
    require_optional_null_params(&mut r)?;
    Ok(())
}

/// Helper used by both the cert-sig and SPKI checks for RSA: consume an
/// optional NULL TLV (`05 00`) and require the reader is then exhausted.
#[cfg(feature = "rsa")]
fn require_optional_null_params(r: &mut SliceReader<'_>) -> Result<(), CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    if r.is_finished() {
        return Ok(());
    }
    let any = AnyRef::decode(r).map_err(map_err)?;
    if any.header().tag() != Tag::Null || !any.value().is_empty() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    if !r.is_finished() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    Ok(())
}

/// Parse an `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent
/// INTEGER }` (RFC 8017 §A.1.1) out of the SPKI BIT STRING contents. Returns
/// the modulus as a stripped-leading-zero big-endian byte slice and the
/// exponent as a u32 (both 3 and 65537 fit comfortably).
#[cfg(feature = "rsa")]
fn parse_rsa_pubkey(bit_string: &[u8]) -> Result<(&[u8], u32), CertParseError> {
    let map_err = |_| CertParseError::BadRsaPubkey;
    let any = AnyRef::try_from(bit_string).map_err(map_err)?;
    if any.header().tag() != Tag::Sequence {
        return Err(CertParseError::BadRsaPubkey);
    }
    let mut r = SliceReader::new(any.value()).map_err(map_err)?;

    let modulus_any = AnyRef::decode(&mut r).map_err(map_err)?;
    if modulus_any.header().tag() != Tag::Integer {
        return Err(CertParseError::BadRsaPubkey);
    }
    let modulus_raw = modulus_any.value();
    // DER INTEGER encoding adds a leading 0x00 if the high bit is set
    // (to keep it positive). Strip that for the raw modulus bytes.
    let modulus = match modulus_raw {
        [0x00, rest @ ..] if !rest.is_empty() && (rest[0] & 0x80) != 0 => rest,
        b => b,
    };
    // Only support 1024-bit (128 B) and 2048-bit (256 B) moduli for now;
    // refuse anything else so the runtime dispatch in `rsa_verify::*` stays
    // mechanical.
    if modulus.len() != 128 && modulus.len() != 256 {
        return Err(CertParseError::UnsupportedRsaKeySize);
    }

    let exponent_any = AnyRef::decode(&mut r).map_err(map_err)?;
    if exponent_any.header().tag() != Tag::Integer {
        return Err(CertParseError::BadRsaPubkey);
    }
    let exponent_bytes = exponent_any.value();
    let exp_bytes = match exponent_bytes {
        [0x00, rest @ ..] if !rest.is_empty() && (rest[0] & 0x80) != 0 => rest,
        b => b,
    };
    if exp_bytes.is_empty() || exp_bytes.len() > 4 {
        return Err(CertParseError::BadRsaPubkey);
    }
    let mut exponent: u32 = 0;
    for &b in exp_bytes {
        exponent = (exponent << 8) | b as u32;
    }
    if !r.is_finished() {
        return Err(CertParseError::BadRsaPubkey);
    }
    Ok((modulus, exponent))
}
