//! Pluggable AEAD backends for the TLS 1.3 record layer.
//!
//! - [`RecordAead<T>`] — the shared shape: 12-byte nonce, 16-byte tag,
//!   in-place buffer. `T` is the key buffer (`[u8; 16]` for AES, `[u8; 32]`
//!   for ChaCha).
//! - [`Aes128GcmAead`] / [`ChaCha20Poly1305Aead`] — marker subtraits that
//!   pin `T` at the call site.

use zeroize::{Zeroize, Zeroizing};

/// Shared AEAD shape used by every TLS 1.3 record-layer suite.
/// `T = [u8; 16]` (AES) / `[u8; 32]` (ChaCha). Nonce 12 B, tag 16 B.
pub trait RecordAead<T: Zeroize> {
    /// Verify the 16-byte `tag` and decrypt `buffer` in place.
    ///
    /// On entry, `buffer` contains the ciphertext (no tag). On `Ok`, `buffer`
    /// contains the plaintext of the same length. On `Err`, `buffer` is
    /// trashed and MUST NOT be used.
    fn decrypt(
        key: &Zeroizing<T>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError>;

    /// Encrypt `buffer` in place and return the 16-byte authentication tag.
    ///
    /// `Err` is reserved for over-cap inputs; statically unreachable for
    /// TLS-bounded sizes.
    fn encrypt(
        key: &Zeroizing<T>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; 16], AeadError>;
}

/// `TLS_AES_128_GCM_SHA256` AEAD: 16-byte key, 12-byte nonce, 16-byte tag.
pub trait Aes128GcmAead: RecordAead<[u8; 16]> {}
impl<T: ?Sized + RecordAead<[u8; 16]>> Aes128GcmAead for T {}

/// `TLS_CHACHA20_POLY1305_SHA256` AEAD: 32-byte key, 12-byte nonce, 16-byte tag.
#[cfg(feature = "chacha20")]
pub trait ChaCha20Poly1305Aead: RecordAead<[u8; 32]> {}
#[cfg(feature = "chacha20")]
impl<T: ?Sized + RecordAead<[u8; 32]>> ChaCha20Poly1305Aead for T {}

/// Authentication-tag verification failed. Per RFC 8446 §5.2 the connection
/// MUST be torn down with a `bad_record_mac` alert when this happens.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AeadError;
