//! [`CertParser`] implementation backed by the `der` crate.

use der::asn1::{AnyRef, BitStringRef, ObjectIdentifier};
use der::{Decode, Reader, SliceReader, Tag, TagNumber};

use crate::traits::cert::{CertParseError, CertParser, CertView};

/// Marker type for the `der`-crate-backed [`CertParser`].
pub struct DerCert;

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[cfg(feature = "rsa")]
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

const X509_V3: u8 = 2;

/// Public-key algorithm carried by SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpkiKind {
    Ed25519,
    #[cfg(feature = "rsa")]
    Rsa,
}

impl CertParser for DerCert {
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError> {
        let map_err = |_| CertParseError::Malformed;

        let outer = AnyRef::try_from(cert_der).map_err(map_err)?;
        if outer.header().tag() != Tag::Sequence {
            return Err(CertParseError::Malformed);
        }
        let mut body = SliceReader::new(outer.value()).map_err(map_err)?;

        let tbs_bytes = body.tlv_bytes().map_err(map_err)?;
        // Do not dispatch on the outer signatureAlgorithm: issuer-signed
        // leaves commonly use an algorithm unrelated to the leaf SPKI.
        let outer_sig_alg_bytes = body.tlv_bytes().map_err(map_err)?;

        let sig_bit = BitStringRef::decode(&mut body).map_err(map_err)?;
        if !body.is_finished() {
            return Err(CertParseError::TrailingBytes);
        }
        let sig_bytes = sig_bit
            .as_bytes()
            .ok_or(CertParseError::BitStringHasUnusedBits)?;

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
            // DER omits this only for v1; this client is v3-only.
            return Err(CertParseError::UnsupportedCertVersion);
        }
        // serialNumber
        tbs_r.tlv_bytes().map_err(map_err)?;
        // RFC 5280 requires TBS and outer signatureAlgorithm to match.
        let tbs_sig_alg_bytes = tbs_r.tlv_bytes().map_err(map_err)?;
        if tbs_sig_alg_bytes != outer_sig_alg_bytes {
            return Err(CertParseError::SignatureAlgorithmMismatch);
        }
        // Capture validity for optional date checks.
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
            #[cfg(feature = "rsa")]
            SpkiKind::Rsa => {
                let (modulus, exponent) = parse_rsa_pubkey(pk_bytes)?;
                // No `signature.len() == modulus.len()` check here: that
                // equality only holds for self-signed certs. A CA-issued
                // leaf cert has an outer signature produced by the
                // *issuer*'s key (possibly a different size, or even
                // ECDSA), so rejecting on mismatch at parse time would
                // block legitimate chains. The self-sig verifier
                // (`verify_self_signed_cert_with_cache`) enforces
                // signature.len() == modulus.len() via `rsa_verify`'s
                // length guard.
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
    #[cfg(feature = "rsa")]
    if oid == RSA_ENCRYPTION_OID {
        // RFC 3279 §2.3.1: parameters MUST be NULL (explicit).
        require_explicit_null_params(&mut r)?;
        return Ok(SpkiKind::Rsa);
    }
    Err(CertParseError::WrongAlgorithmOid)
}

/// Helper for the RSA `rsaEncryption` SPKI path: require an *explicit* NULL
/// TLV (`05 00`) per RFC 3279 §2.3.1, then the reader must be exhausted.
/// Absent parameters, non-NULL parameters, and trailing bytes all reject
/// with [`CertParseError::AlgorithmHasParameters`].
#[cfg(feature = "rsa")]
fn require_explicit_null_params(r: &mut SliceReader<'_>) -> Result<(), CertParseError> {
    let map_err = |_| CertParseError::Malformed;
    if r.is_finished() {
        return Err(CertParseError::AlgorithmHasParameters);
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
    // (to keep it positive). Strip that for the raw modulus bytes; reject
    // *redundant* leading zeros (a non-minimal encoding RFC 5280 §4.1.2.7
    // doesn't permit).
    let modulus = match modulus_raw {
        [0x00, rest @ ..] if !rest.is_empty() && (rest[0] & 0x80) != 0 => rest,
        b => b,
    };
    if modulus.is_empty() || modulus[0] == 0 {
        return Err(CertParseError::BadRsaPubkey);
    }
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
    if exp_bytes.is_empty() || exp_bytes.len() > 4 || exp_bytes[0] == 0 {
        return Err(CertParseError::BadRsaPubkey);
    }
    let mut exponent: u32 = 0;
    for &b in exp_bytes {
        exponent = (exponent << 8) | b as u32;
    }
    // RSA public exponent must be odd and ≥ 3 (RFC 8017 §3.1). e=1 is a
    // no-op; even e is mathematically broken. The realistic values are 3
    // and 65537, but accept anything in [3, u32::MAX] that's odd.
    // Bit-op (instead of `% 2 == 0`) sidesteps clippy::manual-is-multiple-of
    // on newer stable, which needs Rust 1.87+ for the suggested API.
    if exponent < 3 || (exponent & 1) == 0 {
        return Err(CertParseError::BadRsaPubkey);
    }
    if !r.is_finished() {
        return Err(CertParseError::BadRsaPubkey);
    }
    Ok((modulus, exponent))
}
