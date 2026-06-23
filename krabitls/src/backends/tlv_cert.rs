//! [`CertParser`] implementation backed by the hand-rolled TLV walker
//! in [`super::tlv`]. Avoids the `der` crate's generic monomorphization
//! chain.

#[cfg(feature = "rsa")]
use super::tlv::TAG_NULL;
use super::tlv::{
    TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, Tlv,
    peek_tag, read_tlv, tag_ctx_constructed, tag_ctx_primitive,
};

#[cfg(feature = "rsa")]
use crate::traits::cert::RsaCertSigAlg;
use crate::traits::cert::{CertParseError, CertParser, CertView};

/// Marker type for the hand-rolled-TLV-backed [`CertParser`].
pub struct DerCert;

// DER-encoded OID bytes (the OID body, not the TLV — the tag/length
// prefix is stripped before comparison).
//
// Encoding rule: first two arcs collapse to `40*a1 + a2`; remaining
// arcs use base-128 with the high bit set on continuation bytes.

/// `1.3.101.112` — Ed25519 (RFC 8410).
const ED25519_OID: &[u8] = &[0x2B, 0x65, 0x70];

/// `1.2.840.113549.1.1.1` — `rsaEncryption` (RFC 8017).
#[cfg(feature = "rsa")]
const RSA_ENCRYPTION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

/// `1.2.840.113549.1.1.11` — `sha256WithRSAEncryption`.
#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
const SHA256_WITH_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

/// `1.2.840.113549.1.1.10` — `id-RSASSA-PSS`.
#[cfg(feature = "rsa")]
const RSASSA_PSS_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

/// `2.5.29.17` — `id-ce-subjectAltName`.
const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];

const X509_V3: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpkiKind {
    Ed25519,
    #[cfg(feature = "rsa")]
    Rsa,
}

fn malformed<E>(_: E) -> CertParseError {
    CertParseError::Malformed
}

/// Read one TLV that must have `expected_tag`. Returns the body.
fn read_expected<'a>(buf: &'a [u8], expected_tag: u8) -> Result<Tlv<'a>, CertParseError> {
    let t = read_tlv(buf).map_err(malformed)?;
    if t.tag != expected_tag {
        return Err(CertParseError::Malformed);
    }
    Ok(t)
}

/// Read one TLV from `*cursor`, advance past it, and return the body.
fn take_tlv<'a>(cursor: &mut &'a [u8]) -> Result<Tlv<'a>, CertParseError> {
    let t = read_tlv(cursor).map_err(malformed)?;
    *cursor = t.rest;
    Ok(t)
}

/// Read a BIT STRING: the body's first byte is the unused-bits count
/// (must be 0 for our purposes), remaining bytes are the bit content.
fn take_bit_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], CertParseError> {
    let t = take_tlv(cursor)?;
    if t.tag != TAG_BIT_STRING {
        return Err(CertParseError::Malformed);
    }
    let (unused, rest) = t.body.split_first().ok_or(CertParseError::Malformed)?;
    if *unused != 0 {
        return Err(CertParseError::BitStringHasUnusedBits);
    }
    Ok(rest)
}

impl CertParser for DerCert {
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        let outer = read_expected(cert_der, TAG_SEQUENCE)?;
        let mut body = outer.body;

        // The tbsCertificate full TLV bytes are needed downstream for
        // signature verification — capture them before advancing.
        let tbs_tlv = read_tlv(body).map_err(malformed)?;
        if tbs_tlv.tag != TAG_SEQUENCE {
            return Err(CertParseError::Malformed);
        }
        let tbs_full = &body[..tbs_tlv.header_len + tbs_tlv.body.len()];
        body = tbs_tlv.rest;
        let tbs_body = tbs_tlv.body;

        // signatureAlgorithm full TLV bytes — needed for the TBS-vs-outer
        // symmetry check + RSA outer-sig-alg classification.
        let outer_alg_tlv = read_tlv(body).map_err(malformed)?;
        if outer_alg_tlv.tag != TAG_SEQUENCE {
            return Err(CertParseError::Malformed);
        }
        let outer_sig_alg_bytes = &body[..outer_alg_tlv.header_len + outer_alg_tlv.body.len()];
        body = outer_alg_tlv.rest;

        // signatureValue BIT STRING
        let sig_bytes = take_bit_string(&mut body)?;
        if !body.is_empty() {
            return Err(CertParseError::TrailingBytes);
        }

        let mut tbs_r = tbs_body;

        // [0] EXPLICIT Version DEFAULT v1 — v3-only client.
        let first_tag = peek_tag(tbs_r).map_err(malformed)?;
        if first_tag != tag_ctx_constructed(0) {
            return Err(CertParseError::UnsupportedCertVersion);
        }
        let version_tlv = take_tlv(&mut tbs_r)?;
        let int_tlv = read_expected(version_tlv.body, TAG_INTEGER)?;
        if int_tlv.body.len() != 1 {
            return Err(CertParseError::Malformed);
        }
        if int_tlv.body[0] != X509_V3 {
            return Err(CertParseError::UnsupportedCertVersion);
        }
        if !int_tlv.rest.is_empty() {
            return Err(CertParseError::Malformed);
        }

        take_tlv(&mut tbs_r)?;
        // TBS sig alg must match outer.
        let tbs_alg_tlv = read_tlv(tbs_r).map_err(malformed)?;
        let tbs_sig_alg_bytes = &tbs_r[..tbs_alg_tlv.header_len + tbs_alg_tlv.body.len()];
        tbs_r = tbs_alg_tlv.rest;
        if tbs_sig_alg_bytes != outer_sig_alg_bytes {
            return Err(CertParseError::SignatureAlgorithmMismatch);
        }
        take_tlv(&mut tbs_r)?;
        // validity SEQUENCE { notBefore, notAfter } — captured for the
        // optional `feature = "validity"` window check.
        let validity_tlv = read_tlv(tbs_r).map_err(malformed)?;
        let validity_der = &tbs_r[..validity_tlv.header_len + validity_tlv.body.len()];
        tbs_r = validity_tlv.rest;
        take_tlv(&mut tbs_r)?;

        let spki_tlv = read_expected(tbs_r, TAG_SEQUENCE)?;
        tbs_r = spki_tlv.rest;
        let mut spki_r = spki_tlv.body;
        let spki_alg_tlv = read_tlv(spki_r).map_err(malformed)?;
        let spki_alg_bytes = &spki_r[..spki_alg_tlv.header_len + spki_alg_tlv.body.len()];
        spki_r = spki_alg_tlv.rest;
        let pk_bytes = take_bit_string(&mut spki_r)?;
        if !spki_r.is_empty() {
            return Err(CertParseError::TrailingBytes);
        }

        let san_bytes = walk_extensions_for_san(tbs_r)?;

        match classify_spki_algorithm(spki_alg_bytes)? {
            SpkiKind::Ed25519 => {
                let Ok(pubkey) = <&[u8; 32]>::try_from(pk_bytes) else {
                    return Err(CertParseError::WrongPubkeyLength);
                };
                let Ok(signature) = <&[u8; 64]>::try_from(sig_bytes) else {
                    return Err(CertParseError::WrongSignatureLength);
                };
                Ok(CertView::Ed25519 {
                    tbs: tbs_full,
                    signature,
                    pubkey,
                    san: san_bytes,
                    validity_der,
                })
            }
            #[cfg(feature = "rsa")]
            SpkiKind::Rsa => {
                let (modulus, exponent) = parse_rsa_pubkey(pk_bytes)?;
                let outer_sig_alg = classify_rsa_outer_sig_alg(outer_sig_alg_bytes)?;
                Ok(CertView::Rsa {
                    tbs: tbs_full,
                    signature: sig_bytes,
                    outer_sig_alg,
                    modulus,
                    exponent,
                    san: san_bytes,
                    validity_der,
                })
            }
        }
    }
}

/// Skip past `[1]`/`[2]` unique identifiers and walk `[3] EXPLICIT
/// Extensions` if present, looking for SubjectAltName. Returns the
/// `GeneralNames` SEQUENCE body, or `None`. Trailing-tag tolerance
/// for non-spec public-internet certs.
fn walk_extensions_for_san(mut tbs_r: &[u8]) -> Result<Option<&[u8]>, CertParseError> {
    while !tbs_r.is_empty() {
        let tag = peek_tag(tbs_r).map_err(malformed)?;
        if tag == tag_ctx_primitive(1)
            || tag == tag_ctx_constructed(1)
            || tag == tag_ctx_primitive(2)
            || tag == tag_ctx_constructed(2)
        {
            take_tlv(&mut tbs_r)?;
            continue;
        }
        if tag == tag_ctx_constructed(3) {
            let exts_explicit = take_tlv(&mut tbs_r)?;
            let exts_seq = read_expected(exts_explicit.body, TAG_SEQUENCE)?;
            let mut exts_r = exts_seq.body;
            while !exts_r.is_empty() {
                let ext_tlv = take_tlv(&mut exts_r)?;
                if ext_tlv.tag != TAG_SEQUENCE {
                    return Err(CertParseError::Malformed);
                }
                let mut ext_r = ext_tlv.body;
                let oid_tlv = take_tlv(&mut ext_r)?;
                if oid_tlv.tag != TAG_OID {
                    return Err(CertParseError::Malformed);
                }
                let ext_oid = oid_tlv.body;
                // Optional `critical BOOLEAN DEFAULT FALSE` — skip.
                let next_tag = peek_tag(ext_r).map_err(malformed)?;
                if next_tag == TAG_BOOLEAN {
                    take_tlv(&mut ext_r)?;
                }
                let extn_value_tlv = take_tlv(&mut ext_r)?;
                if extn_value_tlv.tag != TAG_OCTET_STRING {
                    return Err(CertParseError::Malformed);
                }
                if ext_oid == SAN_OID {
                    let san_seq = read_expected(extn_value_tlv.body, TAG_SEQUENCE)?;
                    return Ok(Some(san_seq.body));
                }
            }
            return Ok(None);
        }
        // Unknown trailing field; tolerate.
        take_tlv(&mut tbs_r)?;
    }
    Ok(None)
}

/// Decode SPKI `AlgorithmIdentifier` and classify by OID.
fn classify_spki_algorithm(alg_id_bytes: &[u8]) -> Result<SpkiKind, CertParseError> {
    let outer = read_expected(alg_id_bytes, TAG_SEQUENCE)?;
    let mut r = outer.body;
    let oid_tlv = take_tlv(&mut r)?;
    if oid_tlv.tag != TAG_OID {
        return Err(CertParseError::Malformed);
    }
    if oid_tlv.body == ED25519_OID {
        // RFC 8410 §3: parameters MUST be absent.
        if !r.is_empty() {
            return Err(CertParseError::AlgorithmHasParameters);
        }
        return Ok(SpkiKind::Ed25519);
    }
    #[cfg(feature = "rsa")]
    if oid_tlv.body == RSA_ENCRYPTION_OID {
        require_explicit_null_params(&mut r)?;
        return Ok(SpkiKind::Rsa);
    }
    Err(CertParseError::WrongAlgorithmOid)
}

/// Classify the outer `Certificate.signatureAlgorithm` for the RSA path.
#[cfg(feature = "rsa")]
fn classify_rsa_outer_sig_alg(
    alg_id_bytes: &[u8],
) -> Result<Option<RsaCertSigAlg>, CertParseError> {
    let outer = read_expected(alg_id_bytes, TAG_SEQUENCE)?;
    let mut r = outer.body;
    let oid_tlv = take_tlv(&mut r)?;
    if oid_tlv.tag != TAG_OID {
        return Err(CertParseError::Malformed);
    }
    #[cfg(not(feature = "rsa_pss_only"))]
    if oid_tlv.body == SHA256_WITH_RSA_OID {
        require_explicit_null_params(&mut r)?;
        return Ok(Some(RsaCertSigAlg::Pkcs1v15Sha256));
    }
    if oid_tlv.body == RSASSA_PSS_OID {
        // PSS params SEQUENCE may be present or absent. Tolerate the
        // present case: well-formed TLV followed by nothing.
        if !r.is_empty() {
            let _ = take_tlv(&mut r)?;
            if !r.is_empty() {
                return Err(CertParseError::Malformed);
            }
        }
        Ok(Some(RsaCertSigAlg::PssSha256))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "rsa")]
fn require_explicit_null_params(r: &mut &[u8]) -> Result<(), CertParseError> {
    if r.is_empty() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    let null_tlv = take_tlv(r)?;
    if null_tlv.tag != TAG_NULL || !null_tlv.body.is_empty() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    if !r.is_empty() {
        return Err(CertParseError::AlgorithmHasParameters);
    }
    Ok(())
}

/// Parse `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
#[cfg(feature = "rsa")]
fn parse_rsa_pubkey(bit_string: &[u8]) -> Result<(&[u8], u32), CertParseError> {
    let map_err = |_| CertParseError::BadRsaPubkey;
    let outer = read_tlv(bit_string).map_err(map_err)?;
    if outer.tag != TAG_SEQUENCE {
        return Err(CertParseError::BadRsaPubkey);
    }
    let mut r = outer.body;

    let modulus_tlv = read_tlv(r).map_err(map_err)?;
    r = modulus_tlv.rest;
    if modulus_tlv.tag != TAG_INTEGER {
        return Err(CertParseError::BadRsaPubkey);
    }
    let modulus_raw = modulus_tlv.body;
    let modulus = match modulus_raw {
        [0x00, rest @ ..] if !rest.is_empty() && (rest[0] & 0x80) != 0 => rest,
        b => b,
    };
    if modulus.is_empty() || modulus[0] == 0 {
        return Err(CertParseError::BadRsaPubkey);
    }
    #[cfg(not(feature = "rsa_2048_only"))]
    let modulus_ok = modulus.len() == 128 || modulus.len() == 256;
    #[cfg(feature = "rsa_2048_only")]
    let modulus_ok = modulus.len() == 256;
    if !modulus_ok {
        return Err(CertParseError::UnsupportedRsaKeySize);
    }

    let exponent_tlv = read_tlv(r).map_err(map_err)?;
    r = exponent_tlv.rest;
    if exponent_tlv.tag != TAG_INTEGER {
        return Err(CertParseError::BadRsaPubkey);
    }
    let exp_bytes = match exponent_tlv.body {
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
    if exponent < 3 || (exponent & 1) == 0 {
        return Err(CertParseError::BadRsaPubkey);
    }
    if !r.is_empty() {
        return Err(CertParseError::BadRsaPubkey);
    }
    Ok((modulus, exponent))
}
