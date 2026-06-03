//! `Aes128GcmAead` abstraction trait.
//!
//! Thin abstraction so the AEAD backend can be swapped (RustCrypto's
//! `aes-gcm` by default; future contenders could plug in their own AES +
//! GCM impls — e.g. a hardware-AES peripheral on Cortex-M33+, which is
//! the canonical answer to the "AES-GCM software impl is not CT" caveat
//! in `THREAT_MODEL.md`).
//!
//! The TLS 1.3 record-layer code that builds on top of this trait —
//! `decrypt_record`, `encrypt_record`, `aead_nonce`, plus the
//! `EncryptError` / `DecryptError` enums — lives in [`crate::aead`].

use zeroize::Zeroizing;

/// AES-128-GCM AEAD with a fixed 16-byte key, 12-byte nonce, 16-byte tag.
///
/// `key` and `nonce` are passed as `&Zeroizing<[u8; N]>` so the trait
/// contract makes the caller's hygiene obligations explicit at the
/// type level. The wrapper type is the canonical `zeroize` crate
/// primitive, not a krabitls-internal type — any backend implementor
/// can read the bytes via `&**key` to feed into its underlying crypto
/// implementation.
///
/// The tag is intentionally bare bytes (`&[u8; 16]` on decrypt,
/// `[u8; 16]` returned from encrypt) — it's a public AEAD
/// authentication tag, transmitted on the wire, not secret.
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

/// Authentication-tag verification failed. Per RFC 8446 §5.2 the connection
/// MUST be torn down with a `bad_record_mac` alert when this happens.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AeadError;
