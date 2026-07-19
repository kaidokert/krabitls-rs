//! [`CertParser`] implementation backed by the hand-rolled TLV walker
//! in [`super::tlv`]. Avoids the `der` crate's generic monomorphization
//! chain.

use super::tlv::{
    TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, Tlv,
    peek_tag, read_tlv, tag_ctx_constructed, tag_ctx_primitive,
};

use crate::traits::cert::{CertParseError, CertParser, CertView};

/// Marker type for the hand-rolled-TLV-backed [`CertParser`].
#[derive(Debug, Clone, Copy)]
pub struct DerCert;

// DER-encoded OID bytes (the OID body, not the TLV — the tag/length
// prefix is stripped before comparison).
//
// Encoding rule: first two arcs collapse to `40*a1 + a2`; remaining
// arcs use base-128 with the high bit set on continuation bytes.

/// `1.3.101.112` — Ed25519 (RFC 8410).
const ED25519_OID: &[u8] = &[0x2B, 0x65, 0x70];

/// `id-ml-dsa-44/65/87` (NIST `2.16.840.1.101.3.4.3.{17,18,19}`).
#[cfg(feature = "mldsa")]
const ML_DSA_44_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
#[cfg(feature = "mldsa")]
const ML_DSA_65_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];
#[cfg(feature = "mldsa")]
const ML_DSA_87_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

/// `id-ecPublicKey` (`1.2.840.10045.2.1`) and the two namedCurves (RFC 5480).
#[cfg(feature = "ecdsa")]
const EC_PUBLIC_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `secp256r1` — `1.2.840.10045.3.1.7`.
#[cfg(feature = "ecdsa")]
const SECP256R1_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `secp384r1` — `1.3.132.0.34`.
#[cfg(feature = "ecdsa")]
const SECP384R1_OID: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];

/// SEC1 uncompressed-point byte lengths (`0x04 || X || Y`) per curve.
#[cfg(feature = "ecdsa")]
const P256_SEC1_LEN: usize = 65;
#[cfg(feature = "ecdsa")]
const P384_SEC1_LEN: usize = 97;

/// `2.5.29.17` — `id-ce-subjectAltName`.
const SAN_OID: &[u8] = &[0x55, 0x1D, 0x11];

const X509_V3: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpkiKind {
    Ed25519,
    #[cfg(feature = "rsa")]
    Rsa,
    /// ML-DSA, carrying the parameter set's required public-key byte length so
    /// the parse step can reject an OID/key-length mismatch.
    #[cfg(feature = "mldsa")]
    MlDsa(usize),
    #[cfg(feature = "ecdsa")]
    EcdsaP256,
    #[cfg(feature = "ecdsa")]
    EcdsaP384,
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

/// Same as [`take_tlv`] but rejects any tag other than `expected_tag`.
fn take_expected<'a>(cursor: &mut &'a [u8], expected_tag: u8) -> Result<Tlv<'a>, CertParseError> {
    let t = read_expected(cursor, expected_tag)?;
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

        // serialNumber INTEGER.
        take_expected(&mut tbs_r, TAG_INTEGER)?;
        // TBS sig alg must match outer.
        let tbs_alg_tlv = read_expected(tbs_r, TAG_SEQUENCE)?;
        let tbs_sig_alg_bytes = &tbs_r[..tbs_alg_tlv.header_len + tbs_alg_tlv.body.len()];
        tbs_r = tbs_alg_tlv.rest;
        if tbs_sig_alg_bytes != outer_sig_alg_bytes {
            return Err(CertParseError::SignatureAlgorithmMismatch);
        }
        // issuer Name SEQUENCE.
        take_expected(&mut tbs_r, TAG_SEQUENCE)?;
        // validity SEQUENCE { notBefore, notAfter } — captured for the
        // cert validity-window check (run by a `Clocked` strategy).
        let validity_tlv = read_expected(tbs_r, TAG_SEQUENCE)?;
        let validity_der = &tbs_r[..validity_tlv.header_len + validity_tlv.body.len()];
        tbs_r = validity_tlv.rest;
        // subject Name SEQUENCE.
        take_expected(&mut tbs_r, TAG_SEQUENCE)?;

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
            #[cfg(feature = "mldsa")]
            SpkiKind::MlDsa(pk_len) => {
                if pk_bytes.len() != pk_len {
                    return Err(CertParseError::WrongMlDsaPubkeyLength);
                }
                Ok(CertView::MlDsa {
                    tbs: tbs_full,
                    signature: sig_bytes,
                    pubkey: pk_bytes,
                    san: san_bytes,
                    validity_der,
                })
            }
            #[cfg(feature = "ecdsa")]
            SpkiKind::EcdsaP256 => {
                ec_sec1_point(pk_bytes, P256_SEC1_LEN)?;
                Ok(CertView::EcdsaP256 {
                    tbs: tbs_full,
                    signature: sig_bytes,
                    pubkey: pk_bytes,
                    #[cfg(feature = "rsa")]
                    outer_sig_alg: classify_rsa_outer_sig_alg(outer_sig_alg_bytes)?,
                    san: san_bytes,
                    validity_der,
                })
            }
            #[cfg(feature = "ecdsa")]
            SpkiKind::EcdsaP384 => {
                ec_sec1_point(pk_bytes, P384_SEC1_LEN)?;
                Ok(CertView::EcdsaP384 {
                    tbs: tbs_full,
                    signature: sig_bytes,
                    pubkey: pk_bytes,
                    #[cfg(feature = "rsa")]
                    outer_sig_alg: classify_rsa_outer_sig_alg(outer_sig_alg_bytes)?,
                    san: san_bytes,
                    validity_der,
                })
            }
        }
    }
}

/// Reject anything but a SEC1 uncompressed point (`0x04` prefix) of `expect_len`.
#[cfg(feature = "ecdsa")]
fn ec_sec1_point(pk_bytes: &[u8], expect_len: usize) -> Result<(), CertParseError> {
    if pk_bytes.len() != expect_len || pk_bytes.first() != Some(&0x04) {
        return Err(CertParseError::WrongEcdsaPubkey);
    }
    Ok(())
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
    #[cfg(feature = "mldsa")]
    {
        let pk_len = if oid_tlv.body == ML_DSA_44_OID {
            Some(krabipqc::ml_dsa_44::PK_BYTES)
        } else if oid_tlv.body == ML_DSA_65_OID {
            Some(krabipqc::ml_dsa_65::PK_BYTES)
        } else if oid_tlv.body == ML_DSA_87_OID {
            Some(krabipqc::ml_dsa_87::PK_BYTES)
        } else {
            None
        };
        if let Some(pk_len) = pk_len {
            // draft-ietf-lamps-dilithium-certificates §4: parameters MUST be absent.
            if !r.is_empty() {
                return Err(CertParseError::AlgorithmHasParameters);
            }
            return Ok(SpkiKind::MlDsa(pk_len));
        }
    }
    #[cfg(feature = "ecdsa")]
    if oid_tlv.body == EC_PUBLIC_KEY_OID {
        // RFC 5480 §2.1.1: parameters is the namedCurve OID.
        let curve_tlv = take_tlv(&mut r)?;
        if curve_tlv.tag != TAG_OID || !r.is_empty() {
            return Err(CertParseError::AlgorithmHasParameters);
        }
        if curve_tlv.body == SECP256R1_OID {
            return Ok(SpkiKind::EcdsaP256);
        }
        if curve_tlv.body == SECP384R1_OID {
            return Ok(SpkiKind::EcdsaP384);
        }
        return Err(CertParseError::WrongAlgorithmOid);
    }
    Err(CertParseError::WrongAlgorithmOid)
}

/// Classify the outer `Certificate.signatureAlgorithm` for the RSA path.
#[cfg(feature = "rsa")]
mod rsa {
    use super::*;
    use crate::backends::tlv::TAG_NULL;
    use crate::traits::cert::RsaCertSigAlg;

    /// `1.2.840.113549.1.1.1` — `rsaEncryption` (RFC 8017).
    pub(super) const RSA_ENCRYPTION_OID: &[u8] =
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

    /// `1.2.840.113549.1.1.11` — `sha256WithRSAEncryption`.
    #[cfg(not(feature = "rsa_pss_only"))]
    const SHA256_WITH_RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];

    /// `1.2.840.113549.1.1.10` — `id-RSASSA-PSS`.
    const RSASSA_PSS_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

    pub(super) fn classify_rsa_outer_sig_alg(
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

    pub(super) fn require_explicit_null_params(r: &mut &[u8]) -> Result<(), CertParseError> {
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
    pub(super) fn parse_rsa_pubkey(bit_string: &[u8]) -> Result<(&[u8], u32), CertParseError> {
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
        // Accept exactly the enabled RSA widths (2048 baseline; 1024/3072/4096
        // additive). Disabled widths fold to const `false` so LTO drops them.
        let modulus_ok = (cfg!(feature = "rsa-1024") && modulus.len() == 128)
            || modulus.len() == 256
            || (cfg!(feature = "rsa-3072") && modulus.len() == 384)
            || (cfg!(feature = "rsa-4096") && modulus.len() == 512);
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
}
#[cfg(feature = "rsa")]
use rsa::{
    RSA_ENCRYPTION_OID, classify_rsa_outer_sig_alg, parse_rsa_pubkey, require_explicit_null_params,
};
