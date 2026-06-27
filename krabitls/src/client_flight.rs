//! Build the client's second flight: the optional `Certificate` +
//! `CertificateVerify` (mutual auth) and the always-present `Finished`.

use crate::aead::{CipherSuite, EncryptError, RecordKeys};
use crate::consts::{CT_HANDSHAKE, HS_CERTIFICATE, HS_CERTIFICATE_VERIFY, HS_FINISHED};
use crate::hkdf::{HkdfLabelError, TranscriptHash, finished_mac};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::HkdfSha256;
use crate::traits::client_auth::{ClientAuth, ClientAuthError, MAX_CLIENT_SIG_LEN};

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ClientFinishedError {
    #[error("record-layer encrypt step failed")]
    Encrypt(#[from] EncryptError),
    #[error("HKDF-Expand-Label rejected a key-schedule derivation")]
    Hkdf(#[from] HkdfLabelError),
}

/// Build the `Finished` handshake message bytes (`u8(20) || u24(32) || verify_data`)
/// keyed by `c_hs_traffic_secret`. Held in a `ZeroBuf` so the inline verify_data wipes on drop.
pub(crate) fn build_finished_plaintext<H: HkdfSha256>(
    c_hs_traffic_secret: &Secret,
    transcript_hash_through_server_finished: &TranscriptDigest,
) -> Result<ZeroBuf<{ 4 + 32 }>, ClientFinishedError> {
    let verify_data =
        finished_mac::<H>(c_hs_traffic_secret, transcript_hash_through_server_finished)?;
    let mut finished_msg = ZeroBuf::<{ 4 + 32 }>::new([0; 4 + 32]);
    finished_msg[0] = HS_FINISHED;
    finished_msg[1..4].copy_from_slice(&[0x00, 0x00, 0x20]);
    finished_msg[4..].copy_from_slice(&verify_data[..]);
    Ok(finished_msg)
}

impl<S: CipherSuite> RecordKeys<S> {
    /// Build the client `Finished` record. Associated function — no
    /// existing `RecordKeys` instance is required at the call site.
    pub fn build_client_finished<'a, H: HkdfSha256>(
        c_hs_traffic_secret: &Secret,
        transcript_hash_through_server_finished: &TranscriptDigest,
        seq: u64,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], ClientFinishedError> {
        let finished_msg = build_finished_plaintext::<H>(
            c_hs_traffic_secret,
            transcript_hash_through_server_finished,
        )?;
        let keys = Self::derive::<H>(c_hs_traffic_secret)?;
        let record = keys.encrypt_record(&finished_msg[..], CT_HANDSHAKE, seq, out_buf)?;
        Ok(record)
    }
}

/// Exact serialized size of `build_client_finished`'s output.
pub const CLIENT_FINISHED_LEN: usize = 58;

/// Failure building the client `Certificate` / `CertificateVerify` messages.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ClientAuthFlightError {
    #[error("output buffer too small for the client auth handshake message")]
    BufferTooSmall,
    #[error("caller-supplied signer failed")]
    Sign(#[from] ClientAuthError),
    #[error("client Finished derivation failed")]
    Finished(#[from] ClientFinishedError),
    #[error("server requested a client certificate but none is configured")]
    CertificateRequested,
    #[error("client certificate DER is empty")]
    EmptyCertificate,
    #[error("client auth flight exceeds the peer's record_size_limit")]
    FlightExceedsPeerLimit,
}

/// Largest client leaf DER the coalesced second-flight scratch holds. An
/// Ed25519 self-signed leaf is ~300-600 B; this leaves headroom. A larger
/// cert yields [`ClientAuthFlightError::BufferTooSmall`].
pub const MAX_CLIENT_CERT_DER: usize = 1024;

/// Upper bound on the coalesced `Certificate || CertificateVerify ||
/// Finished` plaintext the client emits for mutual auth. Sizes the
/// connection-layer scratch.
pub const MAX_CLIENT_AUTH_FLIGHT: usize =
    // Certificate: 4 hdr + 1 ctx_len + 255 ctx + 3 list_len + 3 cert_len + DER + 2 ext_len
    (4 + 1 + 255 + 3 + 3 + MAX_CLIENT_CERT_DER + 2)
    // CertificateVerify: 4 hdr + 2 scheme + 2 sig_len + sig
    + (4 + 2 + 2 + MAX_CLIENT_SIG_LEN)
    // Finished: 4 hdr + 32 verify_data
    + (4 + 32);

const CLIENT_CV_CTX: &[u8] = b"TLS 1.3, client CertificateVerify";
/// 64-space pad || context string || 0x00 separator || 32-byte transcript hash.
const CLIENT_CV_SIGNED_LEN: usize = 64 + CLIENT_CV_CTX.len() + 1 + 32;

/// Assemble the `CertificateVerify` signed-content (RFC 8446 §4.4.3) the
/// caller's signer feeds to its private key.
fn certificate_verify_signed_content(
    transcript_hash_through_client_cert: &TranscriptDigest,
) -> [u8; CLIENT_CV_SIGNED_LEN] {
    let mut buf = [0u8; CLIENT_CV_SIGNED_LEN];
    buf[..64].fill(0x20);
    buf[64..64 + CLIENT_CV_CTX.len()].copy_from_slice(CLIENT_CV_CTX);
    buf[64 + CLIENT_CV_CTX.len()] = 0x00; // explicit context/hash separator
    let hash_at = 64 + CLIENT_CV_CTX.len() + 1;
    buf[hash_at..].copy_from_slice(transcript_hash_through_client_cert.as_bytes());
    buf
}

/// Serialize the client `Certificate` handshake message (RFC 8446 §4.4.2):
/// a single-entry chain holding `cert_der`, echoing the server's
/// `certificate_request_context`. Returns the plaintext handshake bytes —
/// the caller hashes them into the transcript and encrypts the record.
pub fn build_client_certificate<'a>(
    cert_der: &[u8],
    cert_request_context: &[u8],
    out: &'a mut [u8],
) -> Result<&'a [u8], ClientAuthFlightError> {
    // A zero-length leaf is the *empty* Certificate message (a distinct
    // builder); reject it here so a misbehaving signer can't emit a malformed
    // single-entry chain with no cert_data.
    if cert_der.is_empty() {
        return Err(ClientAuthFlightError::EmptyCertificate);
    }
    // body = u8(ctx_len) ctx u24(list_len) [ u24(cert_len) cert u16(ext_len) ]
    let entry_len = 3 + cert_der.len() + 2;
    let list_len = 3 + entry_len;
    let body_len = 1 + cert_request_context.len() + list_len;
    let total = 4 + body_len;
    let out = out
        .get_mut(..total)
        .ok_or(ClientAuthFlightError::BufferTooSmall)?;

    out[0] = HS_CERTIFICATE;
    out[1..4].copy_from_slice(&u24(body_len));
    let mut p = 4;
    out[p] = u8::try_from(cert_request_context.len())
        .map_err(|_| ClientAuthFlightError::BufferTooSmall)?;
    p += 1;
    out[p..p + cert_request_context.len()].copy_from_slice(cert_request_context);
    p += cert_request_context.len();
    out[p..p + 3].copy_from_slice(&u24(entry_len));
    p += 3;
    out[p..p + 3].copy_from_slice(&u24(cert_der.len()));
    p += 3;
    out[p..p + cert_der.len()].copy_from_slice(cert_der);
    p += cert_der.len();
    out[p..p + 2].copy_from_slice(&[0x00, 0x00]); // empty CertificateEntry extensions
    Ok(out)
}

/// Serialize an *empty* client `Certificate` (zero-entry `certificate_list`),
/// echoing `cert_request_context`. RFC 8446 §4.4.2 requires this when the
/// server requested a certificate the client cannot supply; no
/// `CertificateVerify` follows.
pub fn build_client_empty_certificate<'a>(
    cert_request_context: &[u8],
    out: &'a mut [u8],
) -> Result<&'a [u8], ClientAuthFlightError> {
    let body_len = 1 + cert_request_context.len() + 3; // ctx_len + ctx + u24(0) list
    let total = 4 + body_len;
    let out = out
        .get_mut(..total)
        .ok_or(ClientAuthFlightError::BufferTooSmall)?;

    out[0] = HS_CERTIFICATE;
    out[1..4].copy_from_slice(&u24(body_len));
    out[4] = u8::try_from(cert_request_context.len())
        .map_err(|_| ClientAuthFlightError::BufferTooSmall)?;
    out[5..5 + cert_request_context.len()].copy_from_slice(cert_request_context);
    let list_at = 5 + cert_request_context.len();
    out[list_at..list_at + 3].copy_from_slice(&[0, 0, 0]); // empty certificate_list
    Ok(out)
}

/// Serialize the client `CertificateVerify` handshake message (RFC 8446
/// §4.4.3): sign the transcript-bound content with the caller's signer, then
/// frame `scheme || signature`. Returns the plaintext handshake bytes.
pub fn build_client_certificate_verify<'a>(
    auth: &dyn ClientAuth,
    transcript_hash_through_client_cert: &TranscriptDigest,
    out: &'a mut [u8],
) -> Result<&'a [u8], ClientAuthFlightError> {
    let signed = certificate_verify_signed_content(transcript_hash_through_client_cert);
    let sig = auth.sign(&signed)?;

    let body_len = 2 + 2 + sig.len();
    let total = 4 + body_len;
    let out = out
        .get_mut(..total)
        .ok_or(ClientAuthFlightError::BufferTooSmall)?;

    out[0] = HS_CERTIFICATE_VERIFY;
    out[1..4].copy_from_slice(&u24(body_len));
    out[4..6].copy_from_slice(&auth.scheme().to_be_bytes());
    out[6..8].copy_from_slice(
        &u16::try_from(sig.len())
            .map_err(|_| ClientAuthFlightError::BufferTooSmall)?
            .to_be_bytes(),
    );
    out[8..].copy_from_slice(&sig);
    Ok(out)
}

/// Compile-time client-authentication policy. The connection dispatches to
/// [`build_flight`](ClientAuthPolicy::build_flight) *only* when the server
/// sends a `CertificateRequest`. Because the dispatch is statically
/// monomorphized over the policy type, a binary that only ever uses
/// [`NoClientAuth`] never instantiates the certificate/signing builders —
/// they are not codegened, so client-auth costs nothing unless a real policy
/// is wired in.
pub trait ClientAuthPolicy {
    /// Whether this policy can answer a server `CertificateRequest`. `false`
    /// (the [`NoClientAuth`] default) lets the engine const-fold the entire
    /// certificate-response path out of the monomorphization — a server
    /// request then aborts the handshake without any builder being codegened.
    const ACCEPT_CERT_REQUEST: bool;

    /// Build the coalesced client second-flight plaintext (`Certificate [||
    /// CertificateVerify] || Finished`) in response to a `CertificateRequest`,
    /// folding each message into `transcript`. `transcript` is positioned at
    /// the server `Finished` on entry; the caller snapshots it for the
    /// application-traffic-secret derivation first. `out` is scratch sized by
    /// [`MAX_CLIENT_AUTH_FLIGHT`]. `Err` aborts the handshake — e.g. the
    /// policy has no certificate to offer.
    fn build_flight<'a, H: HkdfSha256>(
        &self,
        cert_request_context: &[u8],
        c_hs_traffic_secret: &Secret,
        transcript: &mut TranscriptHash<H>,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], ClientAuthFlightError>;
}

/// Default policy: never authenticate. A server `CertificateRequest` aborts
/// the handshake (the behavior before mutual auth existed). Zero-sized and
/// emits no certificate-building code.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoClientAuth;

impl ClientAuthPolicy for NoClientAuth {
    const ACCEPT_CERT_REQUEST: bool = false;
    // `#[inline]` so the unconditional `Err` propagates into
    // `finish_handshake_with_policy::<NoClientAuth>` and lets the optimizer
    // drop the second-flight scratch buffer + encrypt path — the no-auth
    // binary then links none of it.
    #[inline]
    fn build_flight<'a, H: HkdfSha256>(
        &self,
        _cert_request_context: &[u8],
        _c_hs_traffic_secret: &Secret,
        _transcript: &mut TranscriptHash<H>,
        _out: &'a mut [u8],
    ) -> Result<&'a [u8], ClientAuthFlightError> {
        Err(ClientAuthFlightError::CertificateRequested)
    }
}

/// Decline politely: send an empty `Certificate` (RFC 8446 §4.4.2) so an
/// *optional*-mutual-auth server proceeds without a client certificate.
/// Zero-sized; links the empty-certificate builder but no signing.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeclineClientAuth;

impl ClientAuthPolicy for DeclineClientAuth {
    const ACCEPT_CERT_REQUEST: bool = true;
    fn build_flight<'a, H: HkdfSha256>(
        &self,
        cert_request_context: &[u8],
        c_hs_traffic_secret: &Secret,
        transcript: &mut TranscriptHash<H>,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], ClientAuthFlightError> {
        let cert_end = build_client_empty_certificate(cert_request_context, out)?.len();
        transcript.update(&out[..cert_end]);
        append_finished::<H>(c_hs_traffic_secret, transcript, out, cert_end)
    }
}

/// Mutual authentication with a caller-supplied signer. The private key never
/// leaves the [`ClientAuth`] implementation.
#[derive(Clone, Copy)]
pub struct WithClientAuth<'a>(pub &'a dyn ClientAuth);

impl ClientAuthPolicy for WithClientAuth<'_> {
    const ACCEPT_CERT_REQUEST: bool = true;

    fn build_flight<'a, H: HkdfSha256>(
        &self,
        cert_request_context: &[u8],
        c_hs_traffic_secret: &Secret,
        transcript: &mut TranscriptHash<H>,
        out: &'a mut [u8],
    ) -> Result<&'a [u8], ClientAuthFlightError> {
        // `Certificate(leaf)` — the CertificateVerify then signs the
        // transcript through it, and the Finished MAC covers through the CV.
        let cert_end =
            build_client_certificate(self.0.cert_der(), cert_request_context, out)?.len();
        transcript.update(&out[..cert_end]);
        let th_through_cert = transcript.snapshot();
        let cv_end = cert_end
            + build_client_certificate_verify(self.0, &th_through_cert, &mut out[cert_end..])?
                .len();
        transcript.update(&out[cert_end..cv_end]);
        append_finished::<H>(c_hs_traffic_secret, transcript, out, cv_end)
    }
}

/// Append the client `Finished` over the transcript-so-far and return the
/// full coalesced second-flight plaintext.
fn append_finished<'a, H: HkdfSha256>(
    c_hs_traffic_secret: &Secret,
    transcript: &mut TranscriptHash<H>,
    out: &'a mut [u8],
    head_end: usize,
) -> Result<&'a [u8], ClientAuthFlightError> {
    let th = transcript.snapshot();
    let finished = build_finished_plaintext::<H>(c_hs_traffic_secret, &th)?;
    let fin_end = head_end + finished.len();
    out.get_mut(head_end..fin_end)
        .ok_or(ClientAuthFlightError::BufferTooSmall)?
        .copy_from_slice(&finished[..]);
    transcript.update(&out[head_end..fin_end]);
    Ok(&out[..fin_end])
}

/// Big-endian u24 of a length that fits in 24 bits. Lengths here are bounded
/// by buffer sizes far below 2^24, so the truncation is unreachable.
fn u24(n: usize) -> [u8; 3] {
    let b = (n as u32).to_be_bytes();
    [b[1], b[2], b[3]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::Ed25519ClientAuth;
    use crate::consts::SIG_SCHEME_ED25519;
    use crate::newtype::TranscriptDigest;

    /// Verify backend mirrors the `RustCrypto` provider (non-CT, 512-bit).
    type VerifyBn = fixed_bigint::FixedUInt<u32, 16>;

    fn read_u24(b: &[u8]) -> usize {
        u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize
    }

    #[test]
    fn certificate_message_framing() {
        let der = [0xABu8; 5];
        let mut out = [0u8; 64];
        let msg = build_client_certificate(&der, &[], &mut out).unwrap();

        assert_eq!(msg[0], HS_CERTIFICATE);
        assert_eq!(read_u24(&msg[1..4]), msg.len() - 4);
        assert_eq!(msg[4], 0, "empty certificate_request_context");
        assert_eq!(read_u24(&msg[5..8]), 3 + der.len() + 2, "cert_list length");
        assert_eq!(read_u24(&msg[8..11]), der.len(), "cert_data length");
        assert_eq!(&msg[11..11 + der.len()], &der);
        assert_eq!(
            &msg[11 + der.len()..],
            &[0x00, 0x00],
            "empty entry extensions"
        );
    }

    #[test]
    fn certificate_message_echoes_request_context() {
        let der = [0x11u8; 4];
        let ctx = [0xCA, 0xFE];
        let mut out = [0u8; 64];
        let msg = build_client_certificate(&der, &ctx, &mut out).unwrap();
        assert_eq!(msg[4], ctx.len() as u8);
        assert_eq!(&msg[5..5 + ctx.len()], &ctx);
    }

    #[test]
    fn empty_certificate_framing() {
        let mut out = [0u8; 32];
        let msg = build_client_empty_certificate(&[], &mut out).unwrap();
        assert_eq!(msg[0], HS_CERTIFICATE);
        assert_eq!(read_u24(&msg[1..4]), msg.len() - 4);
        assert_eq!(msg[4], 0, "empty context");
        assert_eq!(read_u24(&msg[5..8]), 0, "empty certificate_list");
        assert_eq!(msg.len(), 8);
    }

    #[test]
    fn certificate_message_rejects_empty_der() {
        let mut out = [0u8; 32];
        assert_eq!(
            build_client_certificate(&[], &[], &mut out),
            Err(ClientAuthFlightError::EmptyCertificate)
        );
    }

    #[test]
    fn certificate_message_buffer_too_small() {
        let der = [0u8; 5];
        let mut out = [0u8; 8];
        assert_eq!(
            build_client_certificate(&der, &[], &mut out),
            Err(ClientAuthFlightError::BufferTooSmall)
        );
    }

    #[test]
    fn certificate_verify_signature_round_trips() {
        let seed = [7u8; 32];
        let der = [0x55u8; 16];
        let auth = Ed25519ClientAuth::from_seed(&seed, &der).unwrap();
        let pubkey = auth.public_key();

        let th = TranscriptDigest::new([0x42u8; 32]);
        let mut out = [0u8; 128];
        let cv = build_client_certificate_verify(&auth, &th, &mut out).unwrap();

        assert_eq!(cv[0], HS_CERTIFICATE_VERIFY);
        assert_eq!(read_u24(&cv[1..4]), cv.len() - 4);
        assert_eq!(u16::from_be_bytes([cv[4], cv[5]]), SIG_SCHEME_ED25519);
        let sig_len = u16::from_be_bytes([cv[6], cv[7]]) as usize;
        assert_eq!(sig_len, 64);
        let sig: [u8; 64] = cv[8..8 + 64].try_into().unwrap();

        // The signature must verify over the exact signed-content krabitls
        // builds (RFC 8446 §4.4.3), proving the sign/verify loop agrees on
        // the domain-separation framing.
        let signed = certificate_verify_signed_content(&th);
        assert!(ed25519_heapless::verify::<VerifyBn>(pubkey, &signed, sig));

        // A different transcript must not verify against this signature.
        let other = certificate_verify_signed_content(&TranscriptDigest::new([0x43u8; 32]));
        assert!(!ed25519_heapless::verify::<VerifyBn>(pubkey, &other, sig));
    }

    #[test]
    fn signed_content_layout() {
        let th = TranscriptDigest::new([0x99u8; 32]);
        let signed = certificate_verify_signed_content(&th);
        assert_eq!(signed.len(), CLIENT_CV_SIGNED_LEN);
        assert!(signed[..64].iter().all(|&b| b == 0x20));
        assert_eq!(&signed[64..64 + CLIENT_CV_CTX.len()], CLIENT_CV_CTX);
        assert_eq!(signed[64 + CLIENT_CV_CTX.len()], 0x00);
        assert_eq!(&signed[CLIENT_CV_SIGNED_LEN - 32..], th.as_bytes());
    }
}
