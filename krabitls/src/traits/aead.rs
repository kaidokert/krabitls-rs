//! Pluggable AEAD backends for the TLS 1.3 record layer.
//!
//! - [`Aes128GcmAead`] — `TLS_AES_128_GCM_SHA256` (always compiled in).
//! - [`ChaCha20Poly1305Aead`] — `TLS_CHACHA20_POLY1305_SHA256`
//!   (gated on `feature = "chacha20"`; 32-byte key, otherwise same shape).

use zeroize::Zeroizing;

/// AES-128-GCM AEAD with a fixed 16-byte key, 12-byte nonce, and 16-byte tag.
pub trait Aes128GcmAead {
    /// Verify the 16-byte `tag` and decrypt `buffer` in place.
    ///
    /// On entry, `buffer` contains the ciphertext (no tag). On `Ok`, `buffer`
    /// contains the plaintext of the same length. On `Err`, `buffer` is
    /// trashed and MUST NOT be used.
    fn decrypt(
        key: &Zeroizing<[u8; 16]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError>;

    /// Encrypt `buffer` in place and return the 16-byte authentication tag.
    ///
    /// On entry, `buffer` contains the plaintext. On return, `buffer` contains
    /// the ciphertext of the same length and the caller appends the returned
    /// tag.
    fn encrypt(
        key: &Zeroizing<[u8; 16]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; 16];
}

/// ChaCha20-Poly1305 AEAD with a fixed 32-byte key, 12-byte nonce, and 16-byte tag.
#[cfg(feature = "chacha20")]
pub trait ChaCha20Poly1305Aead {
    /// Verify the 16-byte `tag` and decrypt `buffer` in place.
    ///
    /// On entry, `buffer` contains the ciphertext (no tag). On `Ok`, `buffer`
    /// contains the plaintext of the same length. On `Err`, `buffer` is
    /// trashed and MUST NOT be used.
    fn decrypt(
        key: &Zeroizing<[u8; 32]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError>;

    /// Encrypt `buffer` in place and return the 16-byte authentication tag.
    ///
    /// On entry, `buffer` contains the plaintext. On return, `buffer` contains
    /// the ciphertext of the same length and the caller appends the returned tag.
    fn encrypt(
        key: &Zeroizing<[u8; 32]>,
        nonce: &Zeroizing<[u8; 12]>,
        aad: &[u8],
        buffer: &mut [u8],
    ) -> [u8; 16];
}

/// Authentication-tag verification failed. Per RFC 8446 §5.2 the connection
/// MUST be torn down with a `bad_record_mac` alert when this happens.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AeadError;
