//! Alternate [`crate::HkdfSha256`] backend wired to jedisct1's `hmac-sha256`
//! crate (a standalone all-in-one SHA-256 + HMAC + HKDF impl, no `digest` /
//! `crypto-common` / `generic-array` deps).
//!
//! When this is the picked HKDF backend, the binary can drop the entire
//! RustCrypto `sha2 + hmac + hkdf + digest + crypto-common + generic-array`
//! chain (the linker takes care of removing the now-unused impls under LTO).
//! AEAD stays on `aes-gcm` regardless — jedisct1 has no AES-GCM equivalent
//! in the same family.

use hmac_sha256::{HKDF, Hash};

use crate::traits::{HkdfExpandError, HkdfSha256, Sha256Hasher};

/// Marker type holding the jedisct1-backed HKDF impl. Pair with
/// [`crate::RustCrypto`] for AEAD on the call site:
///
/// ```ignore
/// build_client_finished::<JedisctCrypto, RustCrypto>(...)
/// ```
pub struct JedisctCrypto;

impl Sha256Hasher for Hash {
    fn update(&mut self, data: &[u8]) {
        Hash::update(self, data)
    }

    fn finalize(self) -> [u8; 32] {
        Hash::finalize(self)
    }
}

impl HkdfSha256 for JedisctCrypto {
    type Hasher = Hash;

    fn hasher() -> Self::Hasher {
        Hash::new()
    }

    fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        HKDF::extract(salt, ikm)
    }

    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError> {
        // jedisct1's HKDF::expand asserts `out.len() < 255 * 32`; check
        // upfront so we report the limit cleanly instead of panicking.
        if out.len() >= 255 * 32 {
            return Err(HkdfExpandError::OutputTooLong);
        }
        HKDF::expand(out, prk.as_slice(), info);
        Ok(())
    }
}
