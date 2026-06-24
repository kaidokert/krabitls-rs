//! Parse and verify the encrypted TLS 1.3 server flight.

#[cfg(all(test, feature = "rsa", not(feature = "rsa_pss_only")))]
use crate::backends::rsa_verify::RsaPkcs1Sig;
#[cfg(feature = "rsa")]
use crate::backends::rsa_verify::RsaPssSig;
use crate::consts::SIG_SCHEME_ED25519;
#[cfg(feature = "rsa")]
use crate::consts::SIG_SCHEME_RSA_PSS_RSAE_SHA256;
use crate::hkdf::{HkdfLabelError, TranscriptHash, hkdf_expand_label};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
#[cfg(test)]
use crate::traits::CertParser;
#[cfg(all(test, feature = "rsa"))]
use crate::traits::cert::RsaCertSigAlg;
use crate::traits::verify_strategy::PreparedVerifier;
use crate::traits::{
    CertParseError, CertView, Ed25519VerifierProvider, HkdfSha256, RsaVerifierProvider,
};
use signature::Verifier as _;
use subtle::ConstantTimeEq;

const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// Parsed server-flight messages, borrowing into decrypted plaintext.
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightView<'a> {
    pub ee_full: &'a [u8],
    // Production reads `ee_full` (framed) for transcript hashing; only
    // tests inspect the body bytes directly.
    #[cfg_attr(not(test), allow(dead_code))]
    pub ee_body: &'a [u8],
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

    let (cert_type, cert_body, cert_full) = r.next_msg()?;
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
        cert_full,
        cert_body,
        cv_full,
        cv_body,
        fin_full,
        fin_body,
    })
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

/// Default upper bound on `CertificateEntry` count, used by the test-only
/// [`extract_cert_der`] convenience. Production callers thread `MAX_CHAIN`
/// through from `TlsStream` and call [`extract_chain`] directly.
#[cfg(test)]
pub const MAX_CERT_CHAIN_LEN: usize = 8;

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

/// Pull the leaf DER bytes out of a TLS 1.3 `Certificate` body.
/// Leaf-only convenience over [`extract_chain`]; inherits its
/// overflow-rejection. Test-only — production goes through
/// [`extract_chain`] with the caller's `MAX_CHAIN` budget.
#[cfg(test)]
pub fn extract_cert_der(cert_body: &[u8]) -> Result<&[u8], FlightError> {
    let chain = extract_chain::<MAX_CERT_CHAIN_LEN>(cert_body)?;
    chain.first().copied().ok_or(FlightError::Truncated)
}

/// Read a big-endian 24-bit length without truncating on 16-bit targets.
fn read_u24(b: &[u8]) -> u32 {
    debug_assert!(b.len() == 3);
    u32::from_be_bytes([0, b[0], b[1], b[2]])
}

/// Parse + verify a self-signed cert in one shot. Test-only helper.
#[cfg(all(test, feature = "cipher-aes"))]
pub(crate) fn verify_self_signed_cert<
    C: CertParser,
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
>(
    cert_der: &[u8],
) -> Result<CertView<'_>, FlightError> {
    let view = C::parse(cert_der)?;
    let ed25519_v = match &view {
        CertView::Ed25519 { pubkey, .. } => Some(E::prepare_ed25519(pubkey)),
        #[cfg(feature = "rsa")]
        CertView::Rsa { .. } => None,
    };
    #[cfg(feature = "rsa")]
    let rsa_v = match &view {
        CertView::Rsa {
            modulus, exponent, ..
        } => Some(
            R::prepare_rsa(modulus, *exponent)
                .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
        ),
        _ => None,
    };
    verify_self_signed_cert_with_cache::<E, R>(
        &view,
        ed25519_v.as_ref(),
        #[cfg(feature = "rsa")]
        rsa_v.as_ref(),
    )?;
    Ok(view)
}

/// Verify the cert's outer self-signature against its own pubkey.
/// Test-only — production uses
/// [`crate::backends::PinOrSelfSigned`] via the strategy.
#[cfg(test)]
pub(crate) fn verify_self_signed_cert_with_cache<
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
>(
    view: &CertView<'_>,
    ed25519_v: Option<&E::Verifier>,
    #[cfg(feature = "rsa")] rsa_v: Option<&R::Verifier>,
) -> Result<(), FlightError> {
    // `R` is bound even without `feature = "rsa"` so callers can specify a
    // backend choice once at the typestate boundary. The bound is satisfiable
    // trivially since the trait is empty in that configuration.
    let _ = core::marker::PhantomData::<R>;
    match view {
        CertView::Ed25519 { tbs, signature, .. } => {
            let v = ed25519_v.ok_or(FlightError::CertSelfSignatureInvalid)?;
            v.verify(tbs, signature)
                .map_err(|_| FlightError::CertSelfSignatureInvalid)?;
        }
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            tbs,
            signature,
            outer_sig_alg,
            ..
        } => {
            // `outer_sig_alg = None` means the cert's outer signatureAlgorithm
            // isn't one we know how to verify (e.g. RSA leaf signed by an
            // ECDSA issuer). Self-sig verify can't proceed.
            let alg = outer_sig_alg.ok_or(FlightError::CertSelfSignatureInvalid)?;
            let v = rsa_v.ok_or(FlightError::CertSelfSignatureInvalid)?;
            match alg {
                #[cfg(not(feature = "rsa_pss_only"))]
                RsaCertSigAlg::Pkcs1v15Sha256 => v
                    .verify(tbs, &RsaPkcs1Sig(signature))
                    .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
                RsaCertSigAlg::PssSha256 => v
                    .verify(tbs, &RsaPssSig(signature))
                    .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
            }
        }
    }
    Ok(())
}

/// Verify a `CertificateVerify` body against the transcript hash and public key.
/// Non-cached CertificateVerify wrapper. Test-only.
#[cfg(test)]
pub(crate) fn verify_certificate_verify<E: Ed25519VerifierProvider, R: RsaVerifierProvider>(
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
) -> Result<(), FlightError> {
    let ed25519_v = match cert_view {
        CertView::Ed25519 { pubkey, .. } => Some(E::prepare_ed25519(pubkey)),
        #[cfg(feature = "rsa")]
        CertView::Rsa { .. } => None,
    };
    #[cfg(feature = "rsa")]
    let rsa_v = match cert_view {
        CertView::Rsa {
            modulus, exponent, ..
        } => Some(R::prepare_rsa(modulus, *exponent).map_err(|_| FlightError::CertVerifyInvalid)?),
        _ => None,
    };
    verify_certificate_verify_with_cache::<E, R>(
        cert_view,
        transcript_hash_ch_through_cert,
        cv_body,
        ed25519_v.as_ref(),
        #[cfg(feature = "rsa")]
        rsa_v.as_ref(),
    )
}

/// Test-only — production uses [`verify_certificate_verify_with_prepared`]
/// against a strategy-supplied prepared verifier.
#[cfg(test)]
pub(crate) fn verify_certificate_verify_with_cache<
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
>(
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
    ed25519_v: Option<&E::Verifier>,
    #[cfg(feature = "rsa")] rsa_v: Option<&R::Verifier>,
) -> Result<(), FlightError> {
    let _ = core::marker::PhantomData::<R>;
    if cv_body.len() < 4 {
        return Err(FlightError::Truncated);
    }
    let scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() - 4 != sig_len {
        return Err(FlightError::TrailingBytes);
    }
    let sig_bytes = &cv_body[4..];

    // Domain separation for TLS 1.3 CertificateVerify.
    const CTX: &[u8] = b"TLS 1.3, server CertificateVerify";
    const SIGNED_LEN: usize = 64 + CTX.len() + 1 + 32;
    let mut signed: heapless::Vec<u8, SIGNED_LEN> = heapless::Vec::new();
    signed.extend_from_slice(&[0x20u8; 64])?;
    signed.extend_from_slice(CTX)?;
    signed.extend_from_slice(&[0u8])?;
    signed.extend_from_slice(transcript_hash_ch_through_cert.as_bytes())?;

    match (scheme, cert_view) {
        (SIG_SCHEME_ED25519, CertView::Ed25519 { .. }) => {
            let Ok(signature) = <&[u8; 64]>::try_from(sig_bytes) else {
                return Err(FlightError::WrongSignatureLength);
            };
            let v = ed25519_v.ok_or(FlightError::CertVerifyInvalid)?;
            v.verify(&signed, signature)
                .map_err(|_| FlightError::CertVerifyInvalid)?;
            Ok(())
        }
        #[cfg(feature = "rsa")]
        (SIG_SCHEME_RSA_PSS_RSAE_SHA256, CertView::Rsa { modulus, .. }) => {
            // PSS signature length equals the RSA modulus length.
            if sig_len != modulus.len() {
                return Err(FlightError::WrongSignatureLength);
            }
            let v = rsa_v.ok_or(FlightError::CertVerifyInvalid)?;
            v.verify(&signed, &RsaPssSig(sig_bytes))
                .map_err(|_| FlightError::CertVerifyInvalid)?;
            Ok(())
        }
        _ => Err(FlightError::UnexpectedSignatureScheme(scheme)),
    }
}

/// Verify `CertificateVerify` against a prepared verifier handed back by
/// the strategy. The stack has already cross-checked that `prepared`
/// matches the leaf's SPKI ([`PreparedVerifier::matches_cert`]), so the
/// `(scheme, prepared)` pairing here suffices to bind the signature to
/// the certified leaf.
pub(crate) fn verify_certificate_verify_with_prepared<
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
>(
    prepared: &PreparedVerifier<E, R>,
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
        (SIG_SCHEME_ED25519, PreparedVerifier::Ed25519(v, _)) => {
            let Ok(signature) = <&[u8; 64]>::try_from(sig_bytes) else {
                return Err(FlightError::WrongSignatureLength);
            };
            v.verify(&signed, signature)
                .map_err(|_| FlightError::CertVerifyInvalid)
        }
        #[cfg(feature = "rsa")]
        (SIG_SCHEME_RSA_PSS_RSAE_SHA256, PreparedVerifier::Rsa(v)) => v
            .verify(&signed, &RsaPssSig(sig_bytes))
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
pub(crate) fn verify_server_flight<'a, H: HkdfSha256, E, R>(
    transcript: &mut TranscriptHash<H>,
    plaintext: &'a [u8],
    s_hs_traffic_secret: &Secret,
    prepared: &PreparedVerifier<E, R>,
    leaf_view: &CertView<'a>,
) -> Result<ServerFlightVerified<'a>, FlightError>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    let flight = parse_server_flight(plaintext)?;

    transcript.update(flight.ee_full);
    transcript.update(flight.cert_full);
    let th_after_cert = transcript.snapshot();
    verify_certificate_verify_with_prepared::<E, R>(prepared, &th_after_cert, flight.cv_body)?;

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
    };
    Ok(ServerFlightVerified { server_pubkey })
}
