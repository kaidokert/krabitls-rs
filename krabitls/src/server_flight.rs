//! Parse and verify the encrypted TLS 1.3 server flight.

use crate::consts::SIG_SCHEME_ED25519;
#[cfg(feature = "rsa")]
use crate::consts::SIG_SCHEME_RSA_PSS_RSAE_SHA256;
use crate::hkdf::{HkdfLabelError, TranscriptHash, hkdf_expand_label};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::{CertParseError, CertParser, CertView, Ed25519Verify, HkdfSha256};

const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

/// Parsed server-flight messages, borrowing into decrypted plaintext.
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightView<'a> {
    pub ee_full: &'a [u8],
    pub ee_body: &'a [u8],
    pub cert_full: &'a [u8],
    pub cert_body: &'a [u8],
    pub cv_full: &'a [u8],
    pub cv_body: &'a [u8],
    pub fin_full: &'a [u8],
    pub fin_body: &'a [u8],
}

/// Reasons walking or verifying the server flight may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FlightError {
    /// A handshake message header or body claimed more bytes than remained.
    Truncated,
    /// Trailing bytes after we'd consumed all four expected messages.
    TrailingBytes,
    /// Handshake messages didn't appear in `EE -> Cert -> CV -> Finished` order.
    UnexpectedHandshakeType { expected: u8, got: u8 },

    /// X.509 DER parse error.
    BadCert(CertParseError),
    /// `Ed25519::verify` returned false for the cert's self-signature.
    CertSelfSignatureInvalid,

    /// `CertificateVerify.signature_scheme` wasn't `ed25519` (0x0807).
    UnexpectedSignatureScheme(u16),
    /// `CertificateVerify.signature` length didn't match what the scheme
    /// requires (64 B for Ed25519; modulus byte length for RSA-PSS).
    WrongSignatureLength,
    /// `Ed25519::verify` returned false for `CertificateVerify`.
    CertVerifyInvalid,

    /// `Finished.verify_data` length wasn't 32 bytes.
    FinishedWrongLength,
    /// Finished MAC didn't match what we computed locally.
    FinishedMacInvalid,
    /// Internal HKDF label encoding failed.
    HkdfLabel(HkdfLabelError),
    /// Internal encoding buffer overflowed. Statically unreachable for the
    /// fixed `CertificateVerify` signed-data shape we build, but the variant
    /// exists so the encoding path can propagate via `?` instead of
    /// `.expect` / panic.
    InternalEncoding,
}

impl From<heapless::CapacityError> for FlightError {
    fn from(_: heapless::CapacityError) -> Self {
        FlightError::InternalEncoding
    }
}

impl From<CertParseError> for FlightError {
    fn from(e: CertParseError) -> Self {
        FlightError::BadCert(e)
    }
}

impl core::fmt::Display for FlightError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => {
                f.write_str("handshake header / body claimed more bytes than remained")
            }
            Self::TrailingBytes => {
                f.write_str("trailing bytes after the four expected handshake messages")
            }
            Self::UnexpectedHandshakeType { expected, got } => {
                write!(
                    f,
                    "handshake messages out of order: expected type 0x{expected:02x}, got 0x{got:02x}"
                )
            }
            Self::BadCert(_) => f.write_str("cert DER parse failed"),
            Self::CertSelfSignatureInvalid => f.write_str("cert self-signature did not verify"),
            Self::UnexpectedSignatureScheme(v) => {
                write!(f, "unexpected CertificateVerify signature_scheme 0x{v:04x}")
            }
            Self::WrongSignatureLength => {
                f.write_str("CertificateVerify signature length did not match the scheme")
            }
            Self::CertVerifyInvalid => f.write_str("CertificateVerify signature did not verify"),
            Self::FinishedWrongLength => {
                f.write_str("Finished verify_data length was not 32 bytes")
            }
            Self::FinishedMacInvalid => f.write_str("Finished MAC did not match"),
            Self::HkdfLabel(_) => f.write_str("HKDF label encoding failed"),
            Self::InternalEncoding => f.write_str("internal encoding buffer overflowed"),
        }
    }
}

impl core::error::Error for FlightError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::BadCert(e) => Some(e),
            Self::HkdfLabel(e) => Some(e),
            _ => None,
        }
    }
}

/// Walk the 4-message server flight in the decrypted plaintext.
///
/// Validates ordering (`EE -> Cert -> CV -> Finished`) and message framing,
/// then returns body/full slices for each. The `EncryptedExtensions` and
/// `Certificate` payloads are *not* further parsed here — `extract_cert_der`
/// handles the leaf-extraction tolerance for public-server chains.
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

/// Pull the leaf DER bytes out of a TLS 1.3 `Certificate` body.
///
/// Leaf-only: returns the first `CertificateEntry`'s `cert_data`. Per-entry
/// extensions and any chain entries that follow are tolerated and ignored.
pub fn extract_cert_der(cert_body: &[u8]) -> Result<&[u8], FlightError> {
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
    // `list_start + list_len > cert_body.len()` reformulated to avoid
    // overflow on 16-bit `usize`: the `cert_body.len() < after_ctx + 3`
    // check above guarantees `cert_body.len() >= list_start`, so the
    // subtraction is safe.
    if list_len > cert_body.len() - list_start {
        return Err(FlightError::Truncated);
    }
    let list_end = list_start + list_len;
    let list = &cert_body[list_start..list_end];

    // Use the leaf only; tolerate chain entries and per-entry extensions.
    if list.len() < 3 {
        return Err(FlightError::Truncated);
    }
    let cert_data_len =
        usize::try_from(read_u24(&list[0..3])).map_err(|_| FlightError::Truncated)?;
    // `cert_end + 2 = 3 + cert_data_len + 2 = 5 + cert_data_len > list.len()`
    // reformulated to avoid overflow on 16-bit `usize`: bail if the list
    // is too short for the 3+2 framing bytes or if cert_data_len doesn't
    // fit the remaining window.
    if list.len() < 5 || cert_data_len > list.len() - 5 {
        return Err(FlightError::Truncated);
    }
    let cert_end = 3 + cert_data_len;
    let exts_len = u16::from_be_bytes([list[cert_end], list[cert_end + 1]]) as usize;
    // `cert_end + 2 + exts_len > list.len()` reformulated against
    // overflow: the previous guard ensures `list.len() >= cert_end + 2`.
    if exts_len > list.len() - cert_end - 2 {
        return Err(FlightError::Truncated);
    }
    Ok(&list[3..cert_end])
}

/// Read a big-endian 24-bit length without truncating on 16-bit targets.
fn read_u24(b: &[u8]) -> u32 {
    debug_assert!(b.len() == 3);
    ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32)
}

/// Verify a self-signed certificate and return its parsed view.
pub fn verify_self_signed_cert<C: CertParser, E: Ed25519Verify>(
    cert_der: &[u8],
) -> Result<CertView<'_>, FlightError> {
    let cache = E::new_cache();
    let view = C::parse(cert_der)?;
    verify_self_signed_cert_with_cache::<E>(
        &cache,
        &view,
        #[cfg(feature = "rsa")]
        None,
    )?;
    Ok(view)
}

/// Cached variant of [`verify_self_signed_cert`].
pub fn verify_self_signed_cert_with_cache<E: Ed25519Verify>(
    cache: &E::Cache,
    view: &CertView<'_>,
    #[cfg(feature = "rsa")] rsa_cache: Option<&crate::backends::rsa_verify::RsaVerifierKey>,
) -> Result<(), FlightError> {
    match view {
        CertView::Ed25519 {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            if !E::verify_with_cache(cache, pubkey, tbs, signature) {
                return Err(FlightError::CertSelfSignatureInvalid);
            }
        }
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            tbs,
            signature,
            outer_sig_alg,
            modulus,
            exponent,
            ..
        } => {
            use crate::traits::cert::RsaCertSigAlg;
            if let Some(rk) = rsa_cache {
                match outer_sig_alg {
                    #[cfg(not(feature = "rsa_pss_only"))]
                    RsaCertSigAlg::Pkcs1v15Sha256 => rk
                        .verify_pkcs1v15_sha256(tbs, signature)
                        .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
                    RsaCertSigAlg::PssSha256 => rk
                        .verify_pss_sha256(tbs, signature)
                        .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
                }
            } else {
                match outer_sig_alg {
                    #[cfg(not(feature = "rsa_pss_only"))]
                    RsaCertSigAlg::Pkcs1v15Sha256 => {
                        crate::backends::rsa_verify::verify_pkcs1v15_sha256(
                            modulus, *exponent, tbs, signature,
                        )
                        .map_err(|_| FlightError::CertSelfSignatureInvalid)?
                    }
                    RsaCertSigAlg::PssSha256 => crate::backends::rsa_verify::verify_pss_sha256(
                        modulus, *exponent, tbs, signature,
                    )
                    .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
                }
            }
        }
    }
    Ok(())
}

/// Verify a `CertificateVerify` body against the transcript hash and public key.
pub fn verify_certificate_verify<E: Ed25519Verify>(
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
) -> Result<(), FlightError> {
    let cache = E::new_cache();
    verify_certificate_verify_with_cache::<E>(
        &cache,
        cert_view,
        transcript_hash_ch_through_cert,
        cv_body,
        #[cfg(feature = "rsa")]
        None,
    )
}

/// Cached variant of [`verify_certificate_verify`].
pub fn verify_certificate_verify_with_cache<E: Ed25519Verify>(
    cache: &E::Cache,
    cert_view: &CertView<'_>,
    transcript_hash_ch_through_cert: &TranscriptDigest,
    cv_body: &[u8],
    #[cfg(feature = "rsa")] rsa_cache: Option<&crate::backends::rsa_verify::RsaVerifierKey>,
) -> Result<(), FlightError> {
    if cv_body.len() < 4 {
        return Err(FlightError::Truncated);
    }
    let scheme = u16::from_be_bytes([cv_body[0], cv_body[1]]);
    let sig_len = u16::from_be_bytes([cv_body[2], cv_body[3]]) as usize;
    if cv_body.len() != 4 + sig_len {
        return Err(FlightError::TrailingBytes);
    }
    let sig_bytes = &cv_body[4..4 + sig_len];

    // Domain separation for TLS 1.3 CertificateVerify.
    const CTX: &[u8] = b"TLS 1.3, server CertificateVerify";
    const SIGNED_LEN: usize = 64 + CTX.len() + 1 + 32;
    let mut signed: heapless::Vec<u8, SIGNED_LEN> = heapless::Vec::new();
    signed.extend_from_slice(&[0x20u8; 64])?;
    signed.extend_from_slice(CTX)?;
    signed.extend_from_slice(&[0u8])?;
    signed.extend_from_slice(transcript_hash_ch_through_cert.as_bytes())?;

    match (scheme, cert_view) {
        (SIG_SCHEME_ED25519, CertView::Ed25519 { pubkey, .. }) => {
            let Ok(signature) = <&[u8; 64]>::try_from(sig_bytes) else {
                return Err(FlightError::WrongSignatureLength);
            };
            if !E::verify_with_cache(cache, pubkey, &signed, signature) {
                return Err(FlightError::CertVerifyInvalid);
            }
            Ok(())
        }
        #[cfg(feature = "rsa")]
        (
            SIG_SCHEME_RSA_PSS_RSAE_SHA256,
            CertView::Rsa {
                modulus, exponent, ..
            },
        ) => {
            // PSS signature length equals the RSA modulus length.
            if sig_len != modulus.len() {
                return Err(FlightError::WrongSignatureLength);
            }
            if let Some(rk) = rsa_cache {
                rk.verify_pss_sha256(&signed, sig_bytes)
                    .map_err(|_| FlightError::CertVerifyInvalid)?;
            } else {
                crate::backends::rsa_verify::verify_pss_sha256(
                    modulus, *exponent, &signed, sig_bytes,
                )
                .map_err(|_| FlightError::CertVerifyInvalid)?;
            }
            Ok(())
        }
        _ => Err(FlightError::UnexpectedSignatureScheme(scheme)),
    }
}

/// Verify a server `Finished` body.
pub fn verify_server_finished<H: HkdfSha256>(
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
    // Avoid early-exit on the first mismatching byte.
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= expected[i] ^ finished_body[i];
    }
    if diff != 0 {
        return Err(FlightError::FinishedMacInvalid);
    }
    Ok(())
}

/// The server public key carried by the verified certificate.
#[derive(Debug, Clone, Copy)]
pub enum ServerPubkey<'a> {
    /// 32-byte Ed25519 pubkey.
    Ed25519([u8; 32], core::marker::PhantomData<&'a ()>),
    /// RSA modulus + exponent.
    #[cfg(feature = "rsa")]
    Rsa { modulus: &'a [u8], exponent: u32 },
}

impl<'a> ServerPubkey<'a> {
    /// Construct an Ed25519 variant. Hides the `PhantomData` plumbing.
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        ServerPubkey::Ed25519(pubkey, core::marker::PhantomData)
    }

    /// If the variant is Ed25519, return the 32-byte pubkey.
    pub fn as_ed25519(&self) -> Option<[u8; 32]> {
        match self {
            ServerPubkey::Ed25519(pk, _) => Some(*pk),
            #[cfg(feature = "rsa")]
            ServerPubkey::Rsa { .. } => None,
        }
    }

    /// If the variant is RSA, return the `(modulus, exponent)` pair.
    #[cfg(feature = "rsa")]
    pub fn as_rsa(&self) -> Option<(&'a [u8], u32)> {
        match self {
            ServerPubkey::Rsa { modulus, exponent } => Some((*modulus, *exponent)),
            ServerPubkey::Ed25519(_, _) => None,
        }
    }
}

/// End-to-end result of `verify_server_flight`.
#[derive(Debug, Clone, Copy)]
pub struct ServerFlightVerified<'a> {
    pub server_pubkey: ServerPubkey<'a>,
}

/// Verify the server flight and advance the caller's transcript.
pub fn verify_server_flight<'a, H: HkdfSha256, C: CertParser, E: Ed25519Verify>(
    transcript: &mut TranscriptHash<H>,
    plaintext: &'a [u8],
    s_hs_traffic_secret: &Secret,
) -> Result<ServerFlightVerified<'a>, FlightError> {
    let flight = parse_server_flight(plaintext)?;

    // Share backend precomputation across cert and CertificateVerify checks.
    let ed_cache = E::new_cache();

    let cert_der = extract_cert_der(flight.cert_body)?;
    let cert_view = C::parse(cert_der)?;

    // RSA modular precomputation is expensive enough to share.
    #[cfg(feature = "rsa")]
    let rsa_cache: Option<crate::backends::rsa_verify::RsaVerifierKey> = match &cert_view {
        CertView::Rsa {
            modulus, exponent, ..
        } => Some(
            crate::backends::rsa_verify::RsaVerifierKey::new(modulus, *exponent)
                .map_err(|_| FlightError::CertSelfSignatureInvalid)?,
        ),
        _ => None,
    };

    verify_self_signed_cert_with_cache::<E>(
        &ed_cache,
        &cert_view,
        #[cfg(feature = "rsa")]
        rsa_cache.as_ref(),
    )?;

    transcript.update(flight.ee_full);
    transcript.update(flight.cert_full);
    let th_after_cert = transcript.snapshot();
    verify_certificate_verify_with_cache::<E>(
        &ed_cache,
        &cert_view,
        &th_after_cert,
        flight.cv_body,
        #[cfg(feature = "rsa")]
        rsa_cache.as_ref(),
    )?;

    transcript.update(flight.cv_full);
    let th_after_cv = transcript.snapshot();
    verify_server_finished::<H>(s_hs_traffic_secret, &th_after_cv, flight.fin_body)?;

    transcript.update(flight.fin_full);

    let server_pubkey = match cert_view {
        CertView::Ed25519 { pubkey, .. } => ServerPubkey::ed25519(*pubkey),
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => ServerPubkey::Rsa { modulus, exponent },
    };
    Ok(ServerFlightVerified { server_pubkey })
}
