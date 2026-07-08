//! Default [`crate::HkdfSha256`] backend on the RustCrypto crates.

use ::hkdf::Hkdf;
use sha2::Sha256;

use zeroize::Zeroizing;

use crate::bigint::Curve25519VerifyBn as Bn;
use crate::traits::ed25519_verify::Ed25519VerifierProvider;
use crate::traits::{HkdfExpandError, HkdfSha256};
use signature::Verifier;
use subtle::ConstantTimeEq;

pub struct RustCrypto;

impl HkdfSha256 for RustCrypto {
    type Hasher = Sha256;

    fn hasher() -> Self::Hasher {
        digest::Digest::new()
    }

    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        Zeroizing::new(prk.into())
    }

    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| HkdfExpandError::InvalidPrk)?;
        hk.expand(info, out)
            .map_err(|_| HkdfExpandError::OutputTooLong)
    }
}

/// `Ed25519` verifying key with the curve precompute bundled in. Construct
/// once per cert via [`RustCrypto::prepare_ed25519`]; subsequent
/// `signature::Verifier::verify` calls reuse the precompute (~100-150 k cycles
/// on M3 to build, amortized across the 2 verifies per TLS handshake).
pub struct PreparedEd25519 {
    pubkey: [u8; 32],
    // `Curve25519Field::curve25519()` is fallible since ed25519_heapless 0.2.1
    // (errors only when the bigint backend is < 256 bits — impossible for the
    // 512-bit `Bn` here). Stored as `Option` so `prepare_ed25519` stays
    // infallible and no setup panic is linked; the unreachable failure
    // fails the verify closed instead.
    field: Option<ed25519_heapless::Curve25519Field<Bn>>,
}

impl Verifier<[u8; 64]> for PreparedEd25519 {
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        let Some(field) = self.field.as_ref() else {
            return Err(signature::Error::new());
        };
        if ed25519_heapless::verify_with_field::<Bn>(field, self.pubkey, msg, *signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl crate::traits::verify_strategy::VerifierKeyMaterial<[u8; 32]> for PreparedEd25519 {
    fn matches(&self, candidate: [u8; 32]) -> subtle::Choice {
        self.pubkey.ct_eq(&candidate)
    }
}

impl crate::traits::RsaVerifierProvider for RustCrypto {
    // `RsaVerifierKey` enums over modulus size and impls
    // `signature::Verifier<RsaPssSig<'_>>` (always) plus
    // `signature::Verifier<RsaPkcs1Sig<'_>>` (unless `rsa_pss_only`).
    #[cfg(feature = "rsa")]
    type Verifier = crate::backends::rsa_verify::RsaVerifierKey;

    #[cfg(feature = "rsa")]
    fn prepare_rsa(
        modulus: &[u8],
        exponent: u32,
    ) -> Result<Self::Verifier, crate::backends::rsa_verify::RsaVerifyError> {
        crate::backends::rsa_verify::RsaVerifierKey::new(modulus, exponent)
    }
}

impl Ed25519VerifierProvider for RustCrypto {
    // Despite the marker name, the Ed25519 verify wired here is
    // `ed25519_heapless` (not from the RustCrypto org). Bundled with the
    // default `RustCrypto` marker because that's the "pick the defaults"
    // ergonomic entry point — pairing `verify_server_flight::<RustCrypto,
    // RustCrypto, DerCert>(...)` with the existing HKDF + AEAD impls.
    type Verifier = PreparedEd25519;

    fn prepare_ed25519(pubkey: &[u8; 32]) -> Self::Verifier {
        PreparedEd25519 {
            pubkey: *pubkey,
            field: ed25519_heapless::Curve25519Field::<Bn>::curve25519().ok(),
        }
    }
}
