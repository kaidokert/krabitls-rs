//! DTLS 1.3 handshake key schedule — the epoch-2 (handshake) traffic keys.
//!
//! Identical math to TLS 1.3 (RFC 8446 §7): X25519 ECDHE → `handshake_secret`
//! → client/server handshake traffic secrets → per-suite AEAD + record-number
//! keys. Only the record framing that consumes these keys is DTLS-specific, so
//! everything here is reused from [`crate::hkdf`] and PR1's [`EpochKeys`].

use crate::bigint::Curve25519CtBn as Bn;
use crate::dtls::record::{DtlsSuite, EpochKeys};
use crate::hkdf::{HkdfLabelError, handshake_secret, handshake_traffic_secrets};
use crate::newtype::{Secret, TranscriptDigest};
use crate::traits::HkdfSha256;
use subtle::ConstantTimeEq;

#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub(crate) enum KeyScheduleError {
    #[error("X25519 produced an all-zero shared secret (low-order server share)")]
    DhAllZero,
    #[error("HKDF label error")]
    Hkdf,
}

impl From<HkdfLabelError> for KeyScheduleError {
    fn from(_: HkdfLabelError) -> Self {
        KeyScheduleError::Hkdf
    }
}

/// Epoch-2 handshake keys plus the traffic secrets retained for the Finished
/// MACs and the later application-secret derivation.
pub(crate) struct HandshakeKeys<S: DtlsSuite> {
    pub(crate) client: EpochKeys<S>,
    pub(crate) server: EpochKeys<S>,
    pub(crate) client_hs_ts: Secret,
    pub(crate) server_hs_ts: Secret,
    pub(crate) hs_secret: Secret,
}

/// Derive the handshake-epoch keys from the client's X25519 private key, the
/// server's key share, and `transcript_hash(ClientHello…ServerHello)` (with the
/// HRR/message-hash substitution already folded in by the caller).
pub(crate) fn derive_handshake_keys<S: DtlsSuite, H: HkdfSha256>(
    x25519_priv: &[u8; 32],
    server_pubkey: &[u8; 32],
    transcript_hash_ch_sh: &TranscriptDigest,
) -> Result<HandshakeKeys<S>, KeyScheduleError> {
    let ss = zeroize::Zeroizing::new(
        ed25519_heapless::x25519::<Bn>(x25519_priv, server_pubkey)
            .map_err(|_| KeyScheduleError::DhAllZero)?,
    );
    // RFC 8446 §7.4.2.1: an all-zero X25519 output MUST abort.
    if bool::from(ss.ct_eq(&[0u8; 32])) {
        return Err(KeyScheduleError::DhAllZero);
    }

    let hs = handshake_secret::<H>(&ss[..])?;
    let (client_hs_ts, server_hs_ts) = handshake_traffic_secrets::<H>(&hs, transcript_hash_ch_sh)?;
    Ok(HandshakeKeys {
        client: EpochKeys::<S>::derive::<H>(&client_hs_ts)?,
        server: EpochKeys::<S>::derive::<H>(&server_hs_ts)?,
        client_hs_ts,
        server_hs_ts,
        hs_secret: hs,
    })
}

#[cfg(all(test, feature = "cipher-aes"))]
mod tests {
    use super::*;
    use crate::aead::Aes128GcmSha256 as Suite;
    use crate::backends::RustCrypto;
    use crate::consts::CT_HANDSHAKE;
    use crate::dtls::record::{SealHeader, SeqNumLen};
    use crate::hkdf::EMPTY_TRANSCRIPT_HASH;

    /// The X25519 basepoint (u = 9): a scalar mult against it yields a valid,
    /// non-low-order public key to stand in for a server share.
    fn basepoint() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 9;
        b
    }

    #[test]
    fn derives_distinct_epoch_keys_that_self_round_trip() {
        let priv_key = [7u8; 32];
        let server_pub = ed25519_heapless::x25519::<Bn>(&[9u8; 32], &basepoint()).unwrap();

        let hk = derive_handshake_keys::<Suite, RustCrypto>(
            &priv_key,
            &server_pub,
            &EMPTY_TRANSCRIPT_HASH,
        )
        .unwrap();

        // "c hs traffic" and "s hs traffic" diverge.
        assert_ne!(hk.client_hs_ts.as_bytes(), hk.server_hs_ts.as_bytes());

        // The client epoch keys are internally consistent (seal then open).
        let mut buf = [0u8; 64];
        let hdr = SealHeader {
            epoch: 2,
            seq: 0,
            seq_len: SeqNumLen::Two,
            cid: None,
        };
        let n = hk
            .client
            .seal(hdr, b"finflight", CT_HANDSHAKE, &mut buf)
            .unwrap()
            .len();
        assert_eq!(
            hk.client.open(0, 0, &mut buf[..n]).unwrap().content,
            b"finflight"
        );
    }

    #[test]
    fn all_zero_server_share_is_rejected() {
        // u=0 is a low-order point; X25519 yields all-zero → must abort.
        let err = derive_handshake_keys::<Suite, RustCrypto>(
            &[7u8; 32],
            &[0u8; 32],
            &EMPTY_TRANSCRIPT_HASH,
        );
        assert_eq!(err.err(), Some(KeyScheduleError::DhAllZero));
    }
}
