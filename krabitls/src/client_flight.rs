//! Build the client's encrypted TLS 1.3 Finished record.

#[cfg(feature = "chacha20")]
use crate::aead::ChaCha20Poly1305Sha256;
use crate::aead::{Aes128GcmSha256, EncryptError, RecordKeys};
use crate::consts::CT_HANDSHAKE;
use crate::hkdf::{HkdfLabelError, finished_mac};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;
use crate::traits::{Aes128GcmAead, HkdfSha256};

const HS_FINISHED: u8 = 20;

/// Reasons [`build_client_finished`] may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ClientFinishedError {
    /// The record-layer encrypt step failed.
    #[error("record-layer encrypt step failed")]
    Encrypt(#[from] EncryptError),
    /// HKDF-Expand-Label rejected a key-schedule derivation.
    #[error("HKDF-Expand-Label rejected a key-schedule derivation")]
    Hkdf(#[from] HkdfLabelError),
}

/// Build the `Finished` handshake message bytes (`u8(20) || u24(32) || verify_data`)
/// keyed by `c_hs_traffic_secret`. Held in a `ZeroBuf` so the inline verify_data wipes on drop.
fn build_finished_plaintext<H: HkdfSha256>(
    c_hs_traffic_secret: &Secret,
    transcript_hash_through_server_finished: &TranscriptDigest,
) -> Result<ZeroBuf<{ 4 + 32 }>, ClientFinishedError> {
    let verify_data =
        finished_mac::<H>(c_hs_traffic_secret, transcript_hash_through_server_finished)?;
    let mut finished_msg = ZeroBuf::<{ 4 + 32 }>::new([0; 4 + 32]);
    finished_msg[0] = HS_FINISHED;
    finished_msg[1..4].copy_from_slice(&[0x00, 0x00, 0x20]); // length = 32 (big-endian u24)
    finished_msg[4..].copy_from_slice(&verify_data[..]);
    Ok(finished_msg)
}

impl RecordKeys<Aes128GcmSha256> {
    /// Build the client `Finished` record under AES-128-GCM-SHA256.
    /// Derives the encryption keys from `c_hs_traffic_secret` and emits the
    /// AEAD-sealed handshake record. Associated function: no existing
    /// `RecordKeys` instance is required at the call site.
    pub fn build_client_finished<'a, H: HkdfSha256, C: Aes128GcmAead>(
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
        let record = keys.encrypt_record::<C>(&finished_msg[..], CT_HANDSHAKE, seq, out_buf)?;
        Ok(record)
    }
}

#[cfg(feature = "chacha20")]
impl RecordKeys<ChaCha20Poly1305Sha256> {
    /// Build the client `Finished` record under ChaCha20-Poly1305-SHA256.
    pub fn build_client_finished<'a, H: HkdfSha256, C: ChaCha20Poly1305Aead>(
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
        let record = keys.encrypt_record::<C>(&finished_msg[..], CT_HANDSHAKE, seq, out_buf)?;
        Ok(record)
    }
}

/// Exact serialized size of `build_client_finished`'s output.
pub const CLIENT_FINISHED_LEN: usize = 58;
