//! Parse and verify the encrypted TLS 1.3 server flight.

#[cfg(feature = "ecdsa")]
use crate::backends::ecdsa_verify::EcdsaDerSig;
#[cfg(feature = "mldsa")]
use crate::backends::mldsa_verify::MlDsaSig;
#[cfg(feature = "rsa")]
use crate::backends::rsa_verify::RsaSig;
use crate::consts::SIG_SCHEME_ED25519;
#[cfg(feature = "rsa")]
use crate::consts::SIG_SCHEME_RSA_PSS_RSAE_SHA256;
use crate::consts::{
    EXT_SIGNATURE_ALGORITHMS, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST, HS_CERTIFICATE_VERIFY,
    HS_ENCRYPTED_EXTENSIONS, HS_FINISHED,
};
#[cfg(feature = "ecdsa")]
use crate::consts::{SIG_SCHEME_ECDSA_P256, SIG_SCHEME_ECDSA_P384};
#[cfg(feature = "mldsa")]
use crate::consts::{SIG_SCHEME_MLDSA44, SIG_SCHEME_MLDSA65, SIG_SCHEME_MLDSA87};
use crate::hkdf::{HkdfLabelError, TranscriptHash, hkdf_expand_label};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::verify_strategy::PreparedVerifier;
use crate::traits::{CertParseError, CertView, HkdfSha256, VerifierBackend};
#[cfg(feature = "mldsa")]
use krabipqc::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use signature::Verifier as _;
use subtle::ConstantTimeEq;

/// Parsed server-flight messages, borrowing into decrypted plaintext.
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightView<'a> {
    pub ee_full: &'a [u8],
    // Production reads `ee_full` (framed) for transcript hashing; only the
    // AES fixture tests inspect the body bytes directly.
    #[cfg_attr(not(all(test, feature = "cipher-aes")), allow(dead_code))]
    pub ee_body: &'a [u8],
    /// `CertificateRequest` framed bytes when the server asked for client
    /// auth (RFC 8446 §4.3.2); `None` otherwise. Carried so the transcript
    /// hashes it in its EE→Certificate position.
    pub cert_request_full: Option<&'a [u8]>,
    pub cert_full: &'a [u8],
    pub cert_body: &'a [u8],
    pub cv_full: &'a [u8],
    pub cv_body: &'a [u8],
    pub fin_full: &'a [u8],
    pub fin_body: &'a [u8],
}

/// Reasons walking or verifying the server flight may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum FlightError {
    /// A handshake message header or body claimed more bytes than remained.
    #[error("handshake header / body claimed more bytes than remained")]
    Truncated,
    /// Trailing bytes after we'd consumed all four expected messages.
    #[error("trailing bytes after the four expected handshake messages")]
    TrailingBytes,
    /// Handshake messages didn't appear in `EE -> Cert -> CV -> Finished` order.
    #[error("handshake messages out of order: expected type 0x{expected:02x}, got 0x{got:02x}")]
    UnexpectedHandshakeType { expected: u8, got: u8 },

    /// X.509 DER parse error.
    #[error("cert DER parse failed")]
    BadCert(#[from] CertParseError),
    /// `Ed25519::verify` returned false for the cert's self-signature.
    #[error("cert self-signature did not verify")]
    CertSelfSignatureInvalid,

    /// `CertificateVerify.signature_scheme` wasn't `ed25519` (0x0807).
    #[error("unexpected CertificateVerify signature_scheme 0x{0:04x}")]
    UnexpectedSignatureScheme(u16),
    /// `CertificateVerify.signature` length didn't match what the scheme
    /// requires (64 B for Ed25519; modulus byte length for RSA-PSS).
    #[error("CertificateVerify signature length did not match the scheme")]
    WrongSignatureLength,
    /// `Ed25519::verify` returned false for `CertificateVerify`.
    #[error("CertificateVerify signature did not verify")]
    CertVerifyInvalid,

    /// `Finished.verify_data` length wasn't 32 bytes.
    #[error("Finished verify_data length was not 32 bytes")]
    FinishedWrongLength,
    /// Finished MAC didn't match what we computed locally.
    #[error("Finished MAC did not match")]
    FinishedMacInvalid,
    /// Internal HKDF label encoding failed.
    #[error("HKDF label encoding failed")]
    HkdfLabel(#[from] HkdfLabelError),
    /// Internal encoding buffer overflowed. Statically unreachable for the
    /// fixed `CertificateVerify` signed-data shape we build, but the variant
    /// exists so the encoding path can propagate via `?` instead of
    /// `.expect` / panic.
    #[error("internal encoding buffer overflowed")]
    InternalEncoding,
    /// An extension type was seen more than once where the spec says at most
    /// once (e.g. duplicate `record_size_limit` in EncryptedExtensions).
    #[error("duplicate extension 0x{ext_type:04x} in handshake message")]
    DuplicateExtension { ext_type: u16 },
    /// Server's Certificate message carried more `CertificateEntry` entries
    /// than the caller-supplied `MAX_CERT_CHAIN_LEN` bound. Truncating
    /// would silently drop tail certs an attacker may have appended.
    #[error("cert chain length exceeded the configured maximum")]
    CertChainTooLong,
}

impl From<heapless::CapacityError> for FlightError {
    fn from(_: heapless::CapacityError) -> Self {
        FlightError::InternalEncoding
    }
}

/// Walk the 4-message server flight in the decrypted plaintext.
///
/// Validates ordering (`EE -> Cert -> CV -> Finished`) and message framing,
/// then returns body/full slices for each. `EncryptedExtensions` and
/// `Certificate` payloads aren't further parsed here — see
/// [`extract_chain`] / [`extract_cert_der`] for the `Certificate` body.
pub fn parse_server_flight(content: &[u8]) -> Result<ServerFlightView<'_>, FlightError> {
    let mut r = HsReader::new(content);

    let (ee_type, ee_body, ee_full) = r.next_msg()?;
    if ee_type != HS_ENCRYPTED_EXTENSIONS {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_ENCRYPTED_EXTENSIONS,
            got: ee_type,
        });
    }
    // Accept any well-formed EncryptedExtensions body for public-server interop.
    let _ = ee_body;

    // RFC 8446 §4.3.2: an optional CertificateRequest may precede Certificate
    // when the server asks the client to authenticate. We don't act on its
    // contents (the client decides whether/how to respond), but it must be
    // hashed into the transcript in this position.
    let (mut next_type, mut next_body, mut next_full) = r.next_msg()?;
    let cert_request_full = if next_type == HS_CERTIFICATE_REQUEST {
        let creq_full = next_full;
        (next_type, next_body, next_full) = r.next_msg()?;
        Some(creq_full)
    } else {
        None
    };
    let _ = next_body;
    let (cert_type, cert_body, cert_full) = (next_type, next_body, next_full);
    if cert_type != HS_CERTIFICATE {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_CERTIFICATE,
            got: cert_type,
        });
    }

    let (cv_type, cv_body, cv_full) = r.next_msg()?;
    if cv_type != HS_CERTIFICATE_VERIFY {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_CERTIFICATE_VERIFY,
            got: cv_type,
        });
    }

    let (fin_type, fin_body, fin_full) = r.next_msg()?;
    if fin_type != HS_FINISHED {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_FINISHED,
            got: fin_type,
        });
    }

    if !r.at_end() {
        return Err(FlightError::TrailingBytes);
    }

    Ok(ServerFlightView {
        ee_full,
        ee_body,
        cert_request_full,
        cert_full,
        cert_body,
        cv_full,
        cv_body,
        fin_full,
        fin_body,
    })
}

/// Validate a framed `CertificateRequest` (RFC 8446 §4.3.2) and split it into
/// the `certificate_request_context` and the trailing `extensions` vector.
/// Layout: `type(1) || u24 len || u8(ctx_len) || ctx || u16(ext_len) || exts`.
/// 16-bit-safe: every length is checked subtraction-form so an attacker-set
/// length can't overflow `usize` and slip past a bound.
fn cert_request_parts(creq_full: &[u8]) -> Result<(&[u8], &[u8]), FlightError> {
    if creq_full.first() != Some(&HS_CERTIFICATE_REQUEST) {
        return Err(FlightError::UnexpectedHandshakeType {
            expected: HS_CERTIFICATE_REQUEST,
            got: creq_full.first().copied().unwrap_or(0),
        });
    }
    let body = creq_full.get(4..).ok_or(FlightError::Truncated)?;
    let ctx_len = *body.first().ok_or(FlightError::Truncated)? as usize;
    let ctx_end = 1 + ctx_len; // ctx_len <= 255, no overflow
    let ctx = body.get(1..ctx_end).ok_or(FlightError::Truncated)?;

    // The `get` guarantees `body.len() >= ctx_end + 2`, so the subtraction is
    // safe and the `ext_len` comparison can't overflow.
    let ext_len_bytes = body
        .get(ctx_end..ctx_end + 2)
        .ok_or(FlightError::Truncated)?;
    let ext_len = u16::from_be_bytes([ext_len_bytes[0], ext_len_bytes[1]]) as usize;
    let exts_start = ctx_end + 2;
    let remaining = body.len() - exts_start;
    if remaining < ext_len {
        return Err(FlightError::Truncated);
    }
    if remaining > ext_len {
        return Err(FlightError::TrailingBytes);
    }
    Ok((ctx, &body[exts_start..]))
}

/// Extract the `certificate_request_context` so the client `Certificate` can
/// echo it (RFC 8446 §4.4.2).
pub fn certificate_request_context(creq_full: &[u8]) -> Result<&[u8], FlightError> {
    cert_request_parts(creq_full).map(|(ctx, _)| ctx)
}

/// Extract the `supported_signature_algorithms` list — the concatenated u16
/// `SignatureScheme` code points — from the `CertificateRequest`'s
/// `signature_algorithms` extension (RFC 8446 §4.3.2 / §4.2.3). An empty slice
/// means the extension was absent, i.e. the server offered no scheme the
/// client can match.
pub fn certificate_request_sig_algs(creq_full: &[u8]) -> Result<&[u8], FlightError> {
    let (_, exts) = cert_request_parts(creq_full)?;
    // Walk `Extension extension<2..2^16-1>`: u16 type || u16 data_len || data.
    let mut i = 0usize;
    while exts.len() - i >= 4 {
        let etype = u16::from_be_bytes([exts[i], exts[i + 1]]);
        let dlen = u16::from_be_bytes([exts[i + 2], exts[i + 3]]) as usize;
        let data_start = i + 4;
        if dlen > exts.len() - data_start {
            return Err(FlightError::Truncated);
        }
        let data = &exts[data_start..data_start + dlen];
        if etype == EXT_SIGNATURE_ALGORITHMS {
            // data = u16 list_len || SignatureScheme list<2..2^16-2>. The list
            // MUST span the rest of the extension exactly, be non-empty, and
            // hold whole 2-byte schemes; anything else is malformed framing,
            // not an empty offer. `& 1` over `% 2` to dodge manual_is_multiple_of.
            let llen_bytes = data.get(0..2).ok_or(FlightError::Truncated)?;
            let llen = u16::from_be_bytes([llen_bytes[0], llen_bytes[1]]) as usize;
            if llen != data.len() - 2 || llen < 2 || (llen & 1) != 0 {
                return Err(FlightError::Truncated);
            }
            return Ok(&data[2..2 + llen]);
        }
        i = data_start + dlen;
    }
    if i != exts.len() {
        return Err(FlightError::Truncated);
    }
    Ok(&[])
}

struct HsReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> HsReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn next_msg(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), FlightError> {
        if self.buf.len() < self.pos + 4 {
            return Err(FlightError::Truncated);
        }
        let msg_type = self.buf[self.pos];
        let len: usize = u32::from_be_bytes([
            0,
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ])
        .try_into()
        .map_err(|_| FlightError::Truncated)?;
        // Rewrite `body_start + len > self.buf.len()` to avoid overflow
        // on 16-bit `usize`: the `self.buf.len() < self.pos + 4` guard
        // above guarantees `self.buf.len() >= self.pos + 4`, so
        // `self.buf.len() - self.pos - 4` can't underflow.
        if len > self.buf.len() - self.pos - 4 {
            return Err(FlightError::Truncated);
        }
        let body_start = self.pos + 4;
        let body_end = body_start + len;
        let body = &self.buf[body_start..body_end];
        let full = &self.buf[self.pos..body_end];
        self.pos = body_end;
        Ok((msg_type, body, full))
    }
}

/// Walk a TLS 1.3 `Certificate` body and return every `CertificateEntry`'s
/// `cert_data` as borrowed slices, in wire order (index 0 = leaf).
/// Per-entry `Extensions` blobs are skipped.
///
/// Capacity-overflow is REJECTED (`FlightError::CertChainTooLong`), not
/// truncated — a silently-truncated tail is an MITM hook.
pub fn extract_chain<const MAX: usize>(
    cert_body: &[u8],
) -> Result<heapless::Vec<&[u8], MAX>, FlightError> {
    if cert_body.is_empty() {
        return Err(FlightError::Truncated);
    }
    let ctx_len = cert_body[0] as usize;
    let after_ctx = 1 + ctx_len;
    if cert_body.len() < after_ctx + 3 {
        return Err(FlightError::Truncated);
    }
    let list_len = usize::try_from(read_u24(&cert_body[after_ctx..after_ctx + 3]))
        .map_err(|_| FlightError::Truncated)?;
    let list_start = after_ctx + 3;
    // Subtraction safe: prior guard ensures cert_body.len() >= list_start.
    if list_len > cert_body.len() - list_start {
        return Err(FlightError::Truncated);
    }
    let list = &cert_body[list_start..list_start + list_len];

    let mut chain: heapless::Vec<&[u8], MAX> = heapless::Vec::new();
    let mut pos = 0;
    while pos < list.len() {
        if list.len() - pos < 3 {
            return Err(FlightError::Truncated);
        }
        let cert_data_len =
            usize::try_from(read_u24(&list[pos..pos + 3])).map_err(|_| FlightError::Truncated)?;
        let cert_start = pos + 3;
        // Need cert_data_len bytes for cert + 2 bytes for the extensions length.
        if list.len() - cert_start < cert_data_len || list.len() - cert_start - cert_data_len < 2 {
            return Err(FlightError::Truncated);
        }
        let cert_end = cert_start + cert_data_len;
        chain
            .push(&list[cert_start..cert_end])
            .map_err(|_| FlightError::CertChainTooLong)?;
        let exts_len = u16::from_be_bytes([list[cert_end], list[cert_end + 1]]) as usize;
        if list.len() - cert_end - 2 < exts_len {
            return Err(FlightError::Truncated);
        }
        pos = cert_end + 2 + exts_len;
    }
    Ok(chain)
}

/// Read a big-endian 24-bit length without truncating on 16-bit targets.
fn read_u24(b: &[u8]) -> u32 {
    debug_assert!(b.len() == 3);
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

/// Verify `CertificateVerify` against a prepared verifier handed back by
/// the strategy. The stack has already cross-checked that `prepared`
/// matches the leaf's SPKI ([`PreparedVerifier::matches_cert`]), so the
/// `(scheme, prepared)` pairing here suffices to bind the signature to
/// the certified leaf.
pub(crate) fn verify_certificate_verify_with_prepared<P: VerifierBackend>(
    prepared: &PreparedVerifier<P>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
) -> Result<(), FlightError> {
    if cv_body.len() < 4 {
        return Err(FlightError::Truncated);
    }
    let scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() - 4 != sig_len {
        return Err(FlightError::TrailingBytes);
    }
    let sig_bytes = &cv_body[4..];

    const CTX: &[u8] = b"TLS 1.3, server CertificateVerify";
    const SIGNED_LEN: usize = 64 + CTX.len() + 1 + 32;
    let mut signed: heapless::Vec<u8, SIGNED_LEN> = heapless::Vec::new();
    signed.extend_from_slice(&[0x20u8; 64])?;
    signed.extend_from_slice(CTX)?;
    signed.extend_from_slice(&[0u8])?;
    signed.extend_from_slice(transcript_hash_ch_through_cert.as_bytes())?;

    match (scheme, prepared) {
        (SIG_SCHEME_ED25519, PreparedVerifier::Ed25519(v)) => {
            let Ok(signature) = <&[u8; 64]>::try_from(sig_bytes) else {
                return Err(FlightError::WrongSignatureLength);
            };
            v.verify(&signed, signature)
                .map_err(|_| FlightError::CertVerifyInvalid)
        }
        #[cfg(feature = "rsa")]
        (SIG_SCHEME_RSA_PSS_RSAE_SHA256, PreparedVerifier::Rsa(v)) => v
            .verify(
                &signed,
                &RsaSig {
                    scheme: crate::traits::cert::RsaCertSigAlg::PssSha256,
                    bytes: sig_bytes,
                },
            )
            .map_err(|_| FlightError::CertVerifyInvalid),
        // Bind each scheme codepoint to its parameter set: a peer must not label
        // the CertificateVerify with a different ML-DSA scheme than the leaf key
        // signs. The leaf key's genuine signature length reflects its parameter
        // set, so a scheme whose expected length differs is rejected as an
        // unexpected scheme before the verify.
        #[cfg(feature = "mldsa")]
        (
            SIG_SCHEME_MLDSA44 | SIG_SCHEME_MLDSA65 | SIG_SCHEME_MLDSA87,
            PreparedVerifier::MlDsa(v),
        ) => {
            let expected = match scheme {
                SIG_SCHEME_MLDSA44 => ml_dsa_44::SIG_BYTES,
                SIG_SCHEME_MLDSA65 => ml_dsa_65::SIG_BYTES,
                _ => ml_dsa_87::SIG_BYTES,
            };
            if sig_bytes.len() != expected {
                return Err(FlightError::UnexpectedSignatureScheme(scheme));
            }
            v.verify(&signed, &MlDsaSig(sig_bytes))
                .map_err(|_| FlightError::CertVerifyInvalid)
        }
        // ECDSA prehashes the signed content internally (SHA-256 for P-256,
        // SHA-384 for P-384); `sig_bytes` is the DER `ECDSA-Sig-Value`.
        #[cfg(feature = "ecdsa")]
        (SIG_SCHEME_ECDSA_P256, PreparedVerifier::EcdsaP256(v)) => v
            .verify(&signed, &EcdsaDerSig(sig_bytes))
            .map_err(|_| FlightError::CertVerifyInvalid),
        #[cfg(feature = "ecdsa")]
        (SIG_SCHEME_ECDSA_P384, PreparedVerifier::EcdsaP384(v)) => v
            .verify(&signed, &EcdsaDerSig(sig_bytes))
            .map_err(|_| FlightError::CertVerifyInvalid),
        _ => Err(FlightError::UnexpectedSignatureScheme(scheme)),
    }
}

/// Verify a server `Finished` body.
pub(crate) fn verify_server_finished<H: HkdfSha256>(
    s_hs_traffic_secret: &Secret,
    transcript_hash_ch_through_cv: &TranscriptDigest,
    finished_body: &[u8],
) -> Result<(), FlightError> {
    if finished_body.len() != 32 {
        return Err(FlightError::FinishedWrongLength);
    }
    let mut finished_key = ZeroBuf::<32>::new([0; 32]);
    hkdf_expand_label::<H>(
        s_hs_traffic_secret.as_bytes(),
        b"finished",
        &[],
        &mut finished_key[..],
    )
    .map_err(FlightError::HkdfLabel)?;
    let expected = H::extract(&finished_key[..], transcript_hash_ch_through_cv.as_bytes());
    // `subtle::ct_eq` is the canonical CT primitive. A hand-rolled `diff |=`
    // loop is legal for LLVM to vectorize / lower to `memcmp`, which would
    // destroy the constant-time property.
    if bool::from(expected.as_slice().ct_eq(finished_body)) {
        Ok(())
    } else {
        Err(FlightError::FinishedMacInvalid)
    }
}

pub use crate::traits::ServerPubkey;

/// End-to-end result of `verify_server_flight`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerFlightVerified<'a> {
    pub server_pubkey: ServerPubkey<'a>,
}

/// Verify the server flight and advance the caller's transcript.
///
/// The caller (typically [`crate::client::TlsStream`]) has already run the
/// trust-root decision via its [`crate::traits::verify_strategy::VerifyStrategy`]
/// and produced `prepared` + `leaf_view`. This function does protocol
/// invariants only: transcript advance for EE/Cert, CertificateVerify
/// against `prepared`, and Server Finished MAC.
// `inline(never)`: keeps this phase's large verify working set (cert parse +
// signature verify) in its own frame so it does not union into the handshake
// driver's frame and inflate peak stack.
#[inline(never)]
pub(crate) fn verify_server_flight<'a, H: HkdfSha256, P: VerifierBackend>(
    transcript: &mut TranscriptHash<H>,
    plaintext: &'a [u8],
    s_hs_traffic_secret: &Secret,
    prepared: &PreparedVerifier<P>,
    leaf_view: &CertView<'a>,
) -> Result<ServerFlightVerified<'a>, FlightError> {
    let flight = parse_server_flight(plaintext)?;

    transcript.update(flight.ee_full);
    if let Some(creq) = flight.cert_request_full {
        transcript.update(creq);
    }
    transcript.update(flight.cert_full);
    let th_after_cert = transcript.snapshot();
    verify_certificate_verify_with_prepared::<P>(prepared, &th_after_cert, flight.cv_body)?;

    transcript.update(flight.cv_full);
    let th_after_cv = transcript.snapshot();
    verify_server_finished::<H>(s_hs_traffic_secret, &th_after_cv, flight.fin_body)?;

    transcript.update(flight.fin_full);

    let server_pubkey = match leaf_view {
        CertView::Ed25519 { pubkey, .. } => ServerPubkey::ed25519(**pubkey),
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => ServerPubkey::Rsa {
            modulus,
            exponent: *exponent,
        },
        #[cfg(feature = "mldsa")]
        CertView::MlDsa { pubkey, .. } => ServerPubkey::MlDsa(pubkey),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP256 { pubkey, .. } => ServerPubkey::EcdsaP256(pubkey),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP384 { pubkey, .. } => ServerPubkey::EcdsaP384(pubkey),
    };
    Ok(ServerFlightVerified { server_pubkey })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn framed(ty: u8, body: &[u8]) -> heapless::Vec<u8, 64> {
        let mut v = heapless::Vec::<u8, 64>::new();
        v.push(ty).unwrap();
        let l = body.len();
        v.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8])
            .unwrap();
        v.extend_from_slice(body).unwrap();
        v
    }

    #[test]
    fn parse_consumes_optional_certificate_request() {
        let mut with = heapless::Vec::<u8, 256>::new();
        with.extend_from_slice(&framed(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]))
            .unwrap();
        with.extend_from_slice(&framed(HS_CERTIFICATE_REQUEST, &[0xAA; 5]))
            .unwrap();
        with.extend_from_slice(&framed(HS_CERTIFICATE, &[0xBB; 8]))
            .unwrap();
        with.extend_from_slice(&framed(HS_CERTIFICATE_VERIFY, &[0xCC; 4]))
            .unwrap();
        with.extend_from_slice(&framed(HS_FINISHED, &[0xDD; 32]))
            .unwrap();
        let v = parse_server_flight(&with).unwrap();
        let creq = v.cert_request_full.expect("CertificateRequest captured");
        assert_eq!(creq[0], HS_CERTIFICATE_REQUEST);
        assert_eq!(v.cert_full[0], HS_CERTIFICATE);
        assert_eq!(v.cv_full[0], HS_CERTIFICATE_VERIFY);
        assert_eq!(v.fin_full[0], HS_FINISHED);

        // Without one, the field is None and EE -> Certificate still parses.
        let mut without = heapless::Vec::<u8, 256>::new();
        without
            .extend_from_slice(&framed(HS_ENCRYPTED_EXTENSIONS, &[0x00, 0x00]))
            .unwrap();
        without
            .extend_from_slice(&framed(HS_CERTIFICATE, &[0xBB; 8]))
            .unwrap();
        without
            .extend_from_slice(&framed(HS_CERTIFICATE_VERIFY, &[0xCC; 4]))
            .unwrap();
        without
            .extend_from_slice(&framed(HS_FINISHED, &[0xDD; 32]))
            .unwrap();
        assert!(
            parse_server_flight(&without)
                .unwrap()
                .cert_request_full
                .is_none()
        );
    }

    #[test]
    fn certificate_request_context_extracts_echo() {
        // body = u8(ctx_len) ctx u16(ext_len) exts
        let creq = framed(HS_CERTIFICATE_REQUEST, &[0x02, 0xCA, 0xFE, 0x00, 0x00]);
        assert_eq!(certificate_request_context(&creq).unwrap(), &[0xCA, 0xFE]);

        let empty = framed(HS_CERTIFICATE_REQUEST, &[0x00, 0x00, 0x00]);
        assert_eq!(certificate_request_context(&empty).unwrap(), &[] as &[u8]);

        // ctx_len overruns the message.
        let bad = framed(HS_CERTIFICATE_REQUEST, &[0x05, 0xAA]);
        assert_eq!(
            certificate_request_context(&bad),
            Err(FlightError::Truncated)
        );

        // Wrong handshake type.
        let wrong = framed(HS_CERTIFICATE, &[0x00, 0x00, 0x00]);
        assert!(matches!(
            certificate_request_context(&wrong),
            Err(FlightError::UnexpectedHandshakeType { .. })
        ));

        // Missing the u16 extensions-length field after the context.
        let no_ext_len = framed(HS_CERTIFICATE_REQUEST, &[0x00]);
        assert_eq!(
            certificate_request_context(&no_ext_len),
            Err(FlightError::Truncated)
        );

        // Trailing bytes past the declared extensions vector.
        let trailing = framed(HS_CERTIFICATE_REQUEST, &[0x00, 0x00, 0x00, 0xFF]);
        assert_eq!(
            certificate_request_context(&trailing),
            Err(FlightError::TrailingBytes)
        );
    }

    #[test]
    fn certificate_request_sig_algs_extracts_scheme_list() {
        // body = ctx_len(0) || ext_len || [ ext_type(13) || data_len || list_len || schemes ]
        // schemes = ed25519 (0x0807) + ecdsa_secp256r1_sha256 (0x0403)
        let creq = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x0a, // ext_len = 10
                0x00, 0x0d, // ext_type = signature_algorithms
                0x00, 0x06, // ext_data_len = 6
                0x00, 0x04, // list_len = 4
                0x08, 0x07, // ed25519
                0x04, 0x03, // ecdsa_secp256r1_sha256
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&creq).unwrap(),
            &[0x08, 0x07, 0x04, 0x03]
        );

        // A CertReq carrying only some *other* extension yields an empty list
        // (signature_algorithms absent).
        let other_ext = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x04, // ext_len = 4
                0x00, 0x2f, // some other ext_type
                0x00, 0x00, // ext_data_len = 0
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&other_ext).unwrap(),
            &[] as &[u8]
        );

        // An extension whose data_len overruns the vector is rejected.
        let bad = framed(
            HS_CERTIFICATE_REQUEST,
            &[0x00, 0x00, 0x04, 0x00, 0x0d, 0xff, 0xff],
        );
        assert_eq!(
            certificate_request_sig_algs(&bad),
            Err(FlightError::Truncated)
        );

        // list_len shorter than the extension payload (trailing scheme bytes).
        let trailing = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x0a, // ext_len = 10
                0x00, 0x0d, // ext_type = signature_algorithms
                0x00, 0x06, // ext_data_len = 6
                0x00, 0x02, // list_len = 2 (claims one scheme, two trail)
                0x08, 0x07, 0x04, 0x03,
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&trailing),
            Err(FlightError::Truncated)
        );

        // Odd list_len can't hold whole 2-byte schemes.
        let odd = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x09, // ext_len = 9
                0x00, 0x0d, // ext_type = signature_algorithms
                0x00, 0x05, // ext_data_len = 5
                0x00, 0x03, // list_len = 3 (odd)
                0x08, 0x07, 0x04,
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&odd),
            Err(FlightError::Truncated)
        );

        // Empty list_len is malformed framing, not an absent offer.
        let empty_list = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x06, // ext_len = 6
                0x00, 0x0d, // ext_type = signature_algorithms
                0x00, 0x02, // ext_data_len = 2
                0x00, 0x00, // list_len = 0
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&empty_list),
            Err(FlightError::Truncated)
        );

        // 1-3 dangling bytes after a whole extension (too short for a header).
        let dangling = framed(
            HS_CERTIFICATE_REQUEST,
            &[
                0x00, // empty context
                0x00, 0x05, // ext_len = 5
                0x00, 0x2f, // some other ext_type
                0x00, 0x00, // ext_data_len = 0
                0x00, // one dangling byte
            ],
        );
        assert_eq!(
            certificate_request_sig_algs(&dangling),
            Err(FlightError::Truncated)
        );
    }

    /// Default `CertificateEntry`-count bound for the leaf-only
    /// [`extract_cert_der`] convenience. Production threads `MAX_CHAIN` from
    /// `TlsStream` and calls [`extract_chain`] directly.
    const MAX_CERT_CHAIN_LEN: usize = 8;
    #[cfg(feature = "cipher-aes")]
    use crate::traits::CertParser;

    /// Pull the leaf DER bytes out of a TLS 1.3 `Certificate` body.
    /// Leaf-only convenience over [`extract_chain`]; inherits its
    /// overflow-rejection. Test-only — production goes through
    /// [`extract_chain`] with the caller's `MAX_CHAIN` budget.
    pub(crate) fn extract_cert_der(cert_body: &[u8]) -> Result<&[u8], FlightError> {
        let chain = extract_chain::<MAX_CERT_CHAIN_LEN>(cert_body)?;
        chain.first().copied().ok_or(FlightError::Truncated)
    }

    /// Parse + verify a self-signed cert in one shot. Test-only helper: a
    /// self-signed cert is its own issuer, so the outer-signature check reuses
    /// [`verify_link`] against the leaf itself.
    #[cfg(feature = "cipher-aes")]
    pub(crate) fn verify_self_signed_cert<C: CertParser, P: VerifierBackend>(
        cert_der: &[u8],
    ) -> Result<CertView<'_>, FlightError> {
        let view = C::parse(cert_der)?;
        crate::traits::verify_strategy::verify_link::<P>(&view, &view)
            .map_err(|_| FlightError::CertSelfSignatureInvalid)?;
        Ok(view)
    }

    /// Verify a `CertificateVerify` body against a cert's SPKI. Test-only wrapper
    /// that prepares the leaf verifier then defers to
    /// [`verify_certificate_verify_with_prepared`].
    pub(crate) fn verify_certificate_verify<P: VerifierBackend>(
        cert_view: &CertView<'_>,
        transcript_hash_ch_through_cert: &TranscriptDigest,
        cv_body: &[u8],
    ) -> Result<(), FlightError> {
        let prepared = crate::traits::verify_strategy::prepare_leaf::<P>(cert_view)
            .map_err(|_| FlightError::CertVerifyInvalid)?;
        verify_certificate_verify_with_prepared::<P>(
            &prepared,
            transcript_hash_ch_through_cert,
            cv_body,
        )
    }

    #[cfg(feature = "mldsa")]
    mod mldsa {
        use super::*;
        use crate::backends::RustCrypto;
        use crate::backends::mldsa_verify::MlDsaVerifierKey;
        use krabipqc::{KeyGenSeed, SigningRandomness};

        /// Reconstruct the TLS 1.3 server CertificateVerify signed content for a
        /// known transcript-hash digest, matching the production builder.
        fn signed_content(digest: &[u8; 32]) -> heapless::Vec<u8, 130> {
            let mut signed = heapless::Vec::<u8, 130>::new();
            signed.extend_from_slice(&[0x20u8; 64]).unwrap();
            signed
                .extend_from_slice(b"TLS 1.3, server CertificateVerify")
                .unwrap();
            signed.push(0).unwrap();
            signed.extend_from_slice(digest).unwrap();
            signed
        }

        fn cv_body(scheme: u16, sig: &[u8]) -> heapless::Vec<u8, 4640> {
            let mut b = heapless::Vec::<u8, 4640>::new();
            b.extend_from_slice(&scheme.to_be_bytes()).unwrap();
            b.extend_from_slice(&(sig.len() as u16).to_be_bytes())
                .unwrap();
            b.extend_from_slice(sig).unwrap();
            b
        }

        macro_rules! cv_roundtrip {
            ($name:ident, $facade:ident, $scheme:expr) => {
                #[test]
                fn $name() {
                    let digest = [0x5au8; 32];
                    let td = TranscriptDigest::new(digest);
                    let signed = signed_content(&digest);

                    let (pk, sk) =
                        krabipqc::$facade::keygen_from_seed(&KeyGenSeed([7; 32])).unwrap();
                    let sig =
                        krabipqc::$facade::sign(&sk, &signed, &[], &SigningRandomness([9; 32]))
                            .unwrap();

                    let prepared: PreparedVerifier<RustCrypto> =
                        PreparedVerifier::MlDsa(MlDsaVerifierKey::new(&pk).unwrap());

                    let body = cv_body($scheme, &sig);
                    verify_certificate_verify_with_prepared::<RustCrypto>(&prepared, &td, &body)
                        .expect("ML-DSA CertificateVerify verifies");

                    let mut tampered = body.clone();
                    *tampered.last_mut().unwrap() ^= 0xFF;
                    assert!(matches!(
                        verify_certificate_verify_with_prepared::<RustCrypto>(
                            &prepared, &td, &tampered
                        ),
                        Err(FlightError::CertVerifyInvalid)
                    ));

                    let wrong_scheme = cv_body(SIG_SCHEME_ED25519, &sig);
                    assert!(matches!(
                        verify_certificate_verify_with_prepared::<RustCrypto>(
                            &prepared,
                            &td,
                            &wrong_scheme
                        ),
                        Err(FlightError::UnexpectedSignatureScheme(_))
                    ));
                }
            };
        }

        cv_roundtrip!(cv_mldsa44, ml_dsa_44, SIG_SCHEME_MLDSA44);
        cv_roundtrip!(cv_mldsa65, ml_dsa_65, SIG_SCHEME_MLDSA65);
        cv_roundtrip!(cv_mldsa87, ml_dsa_87, SIG_SCHEME_MLDSA87);

        /// A valid ML-DSA-44 signature labelled `mldsa87` must be rejected by
        /// the scheme↔key-parameter binding, not accepted by length inference.
        #[test]
        fn cv_rejects_scheme_param_set_mismatch() {
            let digest = [0x5au8; 32];
            let td = TranscriptDigest::new(digest);
            let signed = signed_content(&digest);

            let (pk, sk) = krabipqc::ml_dsa_44::keygen_from_seed(&KeyGenSeed([7; 32])).unwrap();
            let sig =
                krabipqc::ml_dsa_44::sign(&sk, &signed, &[], &SigningRandomness([9; 32])).unwrap();

            let prepared: PreparedVerifier<RustCrypto> =
                PreparedVerifier::MlDsa(MlDsaVerifierKey::new(&pk).unwrap());

            let mislabelled = cv_body(SIG_SCHEME_MLDSA87, &sig);
            assert!(matches!(
                verify_certificate_verify_with_prepared::<RustCrypto>(&prepared, &td, &mislabelled),
                Err(FlightError::UnexpectedSignatureScheme(_))
            ));
        }
    }
}
