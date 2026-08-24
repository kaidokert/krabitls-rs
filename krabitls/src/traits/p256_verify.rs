//! Pluggable P-256 signature-verification operation.

#[cfg(feature = "ecdsa")]
use crate::backends::ecdsa_verify::EcdsaVerifyError;

/// Verify fixed-width P-256 ECDSA signatures.
///
/// KrabiTLS retains TLS/X.509 hashing and strict DER decoding. Providers see
/// an uncompressed SEC1 point, a SHA-256 prehash, and IEEE P1363 `r || s`.
pub trait P256VerifierProvider {
    #[cfg(feature = "ecdsa")]
    fn verify_p256(
        public_key_sec1: &[u8; 65],
        prehash: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), EcdsaVerifyError>;
}
