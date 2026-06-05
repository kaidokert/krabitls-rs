//! Build the client's encrypted TLS 1.3 Finished record.

use crate::aead::{EncryptError, encrypt_record};
use crate::consts::CT_HANDSHAKE;
use crate::hkdf::{HkdfLabelError, finished_mac, traffic_keys};
use crate::newtype::{Secret, TranscriptDigest, ZeroBuf};
use crate::traits::{Aes128GcmAead, HkdfSha256};

const HS_FINISHED: u8 = 20;

/// Reasons [`build_client_finished`] may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientFinishedError {
    /// The record-layer encrypt step failed.
    Encrypt(EncryptError),
    /// HKDF-Expand-Label rejected a key-schedule derivation.
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
pub fn build_client_finished<'a, H: HkdfSha256, A: Aes128GcmAead>(
    c_hs_traffic_secret: &Secret,
    transcript_hash_through_server_finished: &TranscriptDigest,
    seq: u64,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], ClientFinishedError> {
    let verify_data =
        finished_mac::<H>(c_hs_traffic_secret, transcript_hash_through_server_finished)?;

    // Sensitive because it holds Finished.verify_data inline.
    let mut finished_msg = ZeroBuf::<{ 4 + 32 }>::new([0; 4 + 32]);
    finished_msg[0] = HS_FINISHED;
    finished_msg[1..4].copy_from_slice(&[0x00, 0x00, 0x20]); // length = 32 (big-endian u24)
    finished_msg[4..].copy_from_slice(&verify_data[..]);

    let (key, iv) = traffic_keys::<H>(c_hs_traffic_secret)?;
    let record = encrypt_record::<A>(&finished_msg[..], CT_HANDSHAKE, &key, &iv, seq, out_buf)?;
    Ok(record)
}

/// Exact serialized size of `build_client_finished`'s output.
pub const CLIENT_FINISHED_LEN: usize = 58;
