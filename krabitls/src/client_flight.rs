//! Build the client's response after the server flight verifies.
//!
//! In our locked profile that response is one encrypted record carrying a
//! single `Finished` handshake message. Application traffic secrets are
//! derived separately via [`crate::application_traffic_secrets`] using the
//! `master_secret` and the transcript hash through the *server's* Finished.

use crate::aead::{EncryptError, encrypt_record};
use crate::consts::CT_HANDSHAKE;
use crate::hkdf::{HkdfLabelError, finished_mac, traffic_keys};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::{Aes128GcmAead, HkdfSha256};

const HS_FINISHED: u8 = 20;

/// Reasons [`build_client_finished`] may fail. Wraps the two
/// underlying error families — record-layer encrypt and HKDF label
/// encoding — so the caller doesn't have to thread both manually.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientFinishedError {
    /// The record-layer encrypt step failed (output buffer too small,
    /// record too large for the §5.2 cap, etc.).
    Encrypt(EncryptError),
    /// HKDF-Expand-Label rejected one of the key-schedule derivations.
    /// Statically unreachable for the fixed TLS 1.3 labels this function
    /// uses, but the error is propagated rather than swallowed so the
    /// public API stays uniformly fallible.
    Hkdf(HkdfLabelError),
}

impl From<EncryptError> for ClientFinishedError {
    fn from(e: EncryptError) -> Self {
        ClientFinishedError::Encrypt(e)
    }
}

impl From<HkdfLabelError> for ClientFinishedError {
    fn from(e: HkdfLabelError) -> Self {
        ClientFinishedError::Hkdf(e)
    }
}

/// Build the client `Finished` record.
///
/// Returns the bytes of the full TLS record (header + ciphertext + tag) ready
/// to put on the wire.
///
/// * `c_hs_traffic_secret` — the client handshake traffic secret derived
///   right after ServerHello.
/// * `transcript_hash_through_server_finished` — `SHA-256(CH || SH || EE ||
///   Cert || CertVerify || ServerFinished)`. Obtained by calling
///   `transcript.snapshot()` on the caller-owned [`crate::TranscriptHash`]
///   after [`crate::verify_server_flight`] returns (the verifier hashes
///   the inner-handshake messages forward through `ServerFinished`).
/// * `seq` — record sequence number under `c_hs_traffic_secret` (= 0 for the
///   first client record, which is the typical case).
/// * `out_buf` — caller-provided scratch. Must hold at least 58 bytes
///   (`5 record header + 4 Finished header + 32 verify_data + 1 content_type + 16 tag`).
pub fn build_client_finished<'a, H: HkdfSha256, A: Aes128GcmAead>(
    c_hs_traffic_secret: &Secret,
    transcript_hash_through_server_finished: &TranscriptDigest,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], ClientFinishedError> {
    // verify_data = HMAC-SHA256(finished_key, transcript_hash). Wrap so
    // the MAC bytes get wiped when this function returns (including via
    // `?` early-return through encrypt_record below).
    let verify_data = ZeroBuf::<32>::new(finished_mac::<H>(
        c_hs_traffic_secret,
        transcript_hash_through_server_finished,
    )?);

    // Finished handshake message = u8(20) || u24(32) || verify_data.
    // Holds the verify_data inline, so the buffer itself is sensitive.
    let mut finished_msg = ZeroBuf::<{ 4 + 32 }>::new([0; 4 + 32]);
    finished_msg[0] = HS_FINISHED;
    finished_msg[1..4].copy_from_slice(&[0x00, 0x00, 0x20]); // length = 32 (big-endian u24)
    finished_msg[4..].copy_from_slice(&verify_data[..]);

    let (key, iv) = traffic_keys::<H>(c_hs_traffic_secret)?;
    let record = encrypt_record::<A>(&finished_msg[..], CT_HANDSHAKE, &key, &iv, seq, out_buf)?;
    Ok(record)
}

/// Exact serialized size of `build_client_finished`'s output:
/// 5 (record hdr) + 4 (hs hdr) + 32 (verify_data) + 1 (content_type) + 16 (tag).
pub const CLIENT_FINISHED_LEN: usize = 58;
