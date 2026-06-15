//! Default [`crate::HkdfSha256`] + [`crate::Aes128GcmAead`] backend wired to
//! the RustCrypto crates (`sha2 + hmac + hkdf + aes-gcm`).
//!
//! The cert-parsing backend lives in [`crate::der_cert`] — that one only uses
//! the `der` crate, which is its own thing despite being authored by the
//! RustCrypto org. Keep the markers separate so the dependency split is
//! visible at call sites (`verify_server_flight::<RustCrypto, DerCert>`).

use ::hkdf::Hkdf;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{Aes128Gcm, KeyInit};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use crate::traits::ed25519_verify::Ed25519VerifierProvider;
use crate::traits::{AeadError, RecordAead};
use crate::traits::{HkdfExpandError, HkdfSha256, Sha256Hasher};
use signature::Verifier;

/// Marker type holding the HKDF + AES-GCM impls. Pair with [`crate::DerCert`]
/// for the cert-parsing side.
pub struct RustCrypto;

impl Sha256Hasher for Sha256 {
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data)
    }

    fn finalize(self) -> [u8; 32] {
        Digest::finalize(self).into()
    }
}

impl HkdfSha256 for RustCrypto {
    type Hasher = Sha256;

    fn hasher() -> Self::Hasher {
        Sha256::new()
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

impl RecordAead<[u8; 16]> for RustCrypto {
    fn decrypt(
        key: &Zeroizing<[u8; 16]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError> {
        // `GenericArray::from([u8; N])` is a compile-time conversion (N is
        // already a const generic) and links no panic site, unlike the
        // length-checked `from_slice` / `new_from_slice`.
        let cipher = Aes128Gcm::new(&GenericArray::from(**key));
        let nonce = GenericArray::from(**nonce);
        let tag = GenericArray::from(*tag);
        cipher
            .decrypt_in_place_detached(&nonce, aad, buffer, &tag)
            .map_err(|_| AeadError)
    }

    fn encrypt(
        key: &Zeroizing<[u8; 16]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], AeadError> {
        let cipher = Aes128Gcm::new(&GenericArray::from(**key));
        let nonce = GenericArray::from(**nonce);
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, buffer)
            .map_err(|_| AeadError)?;
        Ok(tag.into())
    }
}

#[cfg(feature = "chacha20")]
impl RecordAead<[u8; 32]> for RustCrypto {
    fn decrypt(
        key: &Zeroizing<[u8; 32]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError> {
        use chacha20poly1305::aead::generic_array::GenericArray as CpGenericArray;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, aead::AeadInPlace as _};
        let cipher = ChaCha20Poly1305::new(&CpGenericArray::from(**key));
        let nonce = CpGenericArray::from(**nonce);
        let tag = CpGenericArray::from(*tag);
        cipher
            .decrypt_in_place_detached(&nonce, aad, buffer, &tag)
            .map_err(|_| AeadError)
    }

    fn encrypt(
        key: &Zeroizing<[u8; 32]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], AeadError> {
        use chacha20poly1305::aead::generic_array::GenericArray as CpGenericArray;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, aead::AeadInPlace as _};
        let cipher = ChaCha20Poly1305::new(&CpGenericArray::from(**key));
        let nonce = CpGenericArray::from(**nonce);
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, buffer)
            .map_err(|_| AeadError)?;
        Ok(tag.into())
    }
}

/// Bigint backend the RustCrypto bundle uses for Ed25519 / X25519.
type Bn = fixed_bigint::FixedUInt<u32, 16>;

/// `Ed25519` verifying key with the curve precompute bundled in. Construct
/// once per cert via [`RustCrypto::prepare_ed25519`]; subsequent
/// `signature::Verifier::verify` calls reuse the precompute (~100-150 k cycles
/// on M3 to build, amortized across the 2 verifies per TLS handshake).
pub struct PreparedEd25519 {
    pubkey: [u8; 32],
    field: ed25519_heapless::Curve25519Field<Bn>,
}

impl Verifier<[u8; 64]> for PreparedEd25519 {
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        if ed25519_heapless::verify_with_field::<Bn>(&self.field, self.pubkey, msg, *signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
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
            field: ed25519_heapless::Curve25519Field::<Bn>::curve25519(),
        }
    }
}
