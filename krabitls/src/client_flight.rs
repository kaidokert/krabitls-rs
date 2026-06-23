//! Build the client's encrypted TLS 1.3 Finished record.

use crate::aead::{CipherSuite, EncryptError, RecordKeys};
use crate::consts::CT_HANDSHAKE;
use crate::hkdf::{HkdfLabelError, finished_mac};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::HkdfSha256;

const HS_FINISHED: u8 = 20;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ClientFinishedError {
    #[error("record-layer encrypt step failed")]
    Encrypt(#[from] EncryptError),
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
