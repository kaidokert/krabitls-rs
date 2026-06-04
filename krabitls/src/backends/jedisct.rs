//! Alternate [`crate::HkdfSha256`] backend wired to jedisct1's `hmac-sha256`
//! crate (a standalone all-in-one SHA-256 + HMAC + HKDF impl, no `digest` /
//! `crypto-common` / `generic-array` deps).
//!
//! Useful when the consumer wants a SHA/HKDF impl outside RustCrypto's
//! `digest 0.10` trait family — e.g. to avoid version-mismatch friction
//! with another crate in the tree, or to use a single dep instead of the
//! `sha2 + hmac + hkdf + digest + crypto-common + generic-array` chain.
//!
//! Note: just enabling `--features jedisct` does *not* by itself shrink the
//! binary, because the [`crate::RustCrypto`] backend (and its `sha2` /
//! `hmac` / `hkdf` deps) is still compiled in. To actually drop the
//! RustCrypto SHA chain, the consumer also has to avoid referencing
//! `RustCrypto` anywhere in their call sites — which today means giving
//! up AES-GCM (jedisct1 has no equivalent in the same family) or
//! supplying their own [`crate::Aes128GcmAead`] impl.

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

    fn extract(salt: &[u8], ikm: &[u8]) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(HKDF::extract(salt, ikm))
    }

    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError> {
        // RFC 5869 §2.3 permits Expand output up to `255 * HashLen` *inclusive*
        // (8160 B for SHA-256), and the RustCrypto backend honors that. jedisct1's
        // `HKDF::expand` asserts `out.len() < 0xff * 32` (strict), so it panics
        // at exactly 8160 bytes. Guard with `>=` so this backend cleanly rejects
        // the boundary case rather than panicking — a slight contract bend
        // versus RustCrypto, but TLS 1.3 never requests that much from a single
        // expand and the alternative is a reachable panic from a public API.
        if out.len() >= 255 * 32 {
            return Err(HkdfExpandError::OutputTooLong);
        }
        HKDF::expand(out, prk.as_slice(), info);
        Ok(())
    }
}
