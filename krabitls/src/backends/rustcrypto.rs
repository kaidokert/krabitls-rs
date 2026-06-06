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

#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;
use crate::traits::ed25519_verify::Ed25519Verify;
use crate::traits::{AeadError, Aes128GcmAead};
use crate::traits::{HkdfExpandError, HkdfSha256, Sha256Hasher};

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
        let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK is always valid for SHA-256");
        hk.expand(info, out)
            .map_err(|_| HkdfExpandError::OutputTooLong)
    }
}

impl Aes128GcmAead for RustCrypto {
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
    ) -> [u8; 16] {
        let cipher = Aes128Gcm::new(&GenericArray::from(**key));
        let nonce = GenericArray::from(**nonce);
        // `encrypt_in_place_detached` only errors past AES-GCM's 2^36-byte cap
        // (RFC 5288 §3). TLS 1.3 enforces a `2^14 + 256` cap upstream
        // (RFC 8446 §5.2, `crate::aead::encrypt_record`), so this is
        // statically unreachable. A silent zero-tag fallback would still
        // produce a record the peer rejects as `bad_record_mac`.
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, buffer)
            .expect("TLS record below AES-GCM 2^36-byte cap");
        tag.into()
    }
}

#[cfg(feature = "chacha20")]
impl ChaCha20Poly1305Aead for RustCrypto {
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
    ) -> [u8; 16] {
        use chacha20poly1305::aead::generic_array::GenericArray as CpGenericArray;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, aead::AeadInPlace as _};
        let cipher = ChaCha20Poly1305::new(&CpGenericArray::from(**key));
        let nonce = CpGenericArray::from(**nonce);
        // Same `2^14 + 256` upstream cap as the AES path; the size-overflow
        // branch of `encrypt_in_place_detached` is statically unreachable.
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, buffer)
            .expect("TLS record below ChaCha20-Poly1305 cap");
        tag.into()
    }
}

/// Bigint backend the RustCrypto bundle uses for Ed25519 / X25519.
type Bn = fixed_bigint::FixedUInt<u32, 16>;

impl Ed25519Verify for RustCrypto {
    // Despite the marker name, the Ed25519 verify wired here is
    // `ed25519_heapless` (not from the RustCrypto org). Bundled with the
    // default `RustCrypto` marker because that's the "pick the defaults"
    // ergonomic entry point — pairing `verify_server_flight::<RustCrypto,
    // RustCrypto, DerCert>(...)` with the existing HKDF + AEAD impls.

    // The `Curve25519Field` carries the precomputed Montgomery params for
    // the curve modulus. Construction does the expensive `compute_r_mod_n`
    // + `compute_r2_mod_n` (~100-150k cycles on M3); reuse across multiple
    // verifies amortizes that.
    type Cache = ed25519_heapless::Curve25519Field<Bn>;

    fn new_cache() -> Self::Cache {
        ed25519_heapless::Curve25519Field::<Bn>::curve25519()
    }

    fn verify(pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
        ed25519_heapless::verify::<Bn>(*pubkey, msg, *signature)
    }

    fn verify_with_cache(
        cache: &Self::Cache,
        pubkey: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        ed25519_heapless::verify_with_field::<Bn>(cache, *pubkey, msg, *signature)
    }
}
