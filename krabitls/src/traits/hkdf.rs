//! `HkdfSha256` + `Sha256Hasher` abstraction traits.
//!
//! TLS 1.3 derives every key in the handshake from an HKDF chain
//! (RFC 8446 §7.1). Different deployments may want different HKDF
//! implementations — RustCrypto, jedisct1, hand-rolled, vendor libs —
//! so the trait is the swap point.
//!
//! Trait is fixed to SHA-256 (the hash bound to our locked cipher suite
//! `TLS_AES_128_GCM_SHA256`); generalizing to other hashes is a future
//! concern.
//!
//! The TLS 1.3 key-schedule helpers built on top — `early_secret`,
//! `handshake_secret`, `derive_secret`, `traffic_keys`,
//! `application_traffic_secrets`, `finished_mac`, the `TranscriptHash`
//! wrapper, and `hkdf_expand_label` — live in [`crate::hkdf`].

/// HKDF over SHA-256 (RFC 5869) plus an associated incremental SHA-256
/// hasher.
///
/// The hasher is here so krabitls can stay on *one* SHA-256 implementation per
/// build: both the HKDF chain and the transcript hash (RFC 8446 §4.4.1) go
/// through the same backend. Without that coupling, krabitls's direct uses of
/// `sha2::Sha256` would keep `sha2` linked even when the HKDF backend
/// changes, defeating any swap.
pub trait HkdfSha256 {
    /// Incremental SHA-256 hasher type — must be `Clone` so the transcript
    /// hash can be snapshotted between TLS handshake messages.
    type Hasher: Sha256Hasher;

    /// Spawn a fresh hasher.
    fn hasher() -> Self::Hasher;

    /// `HKDF-Extract(salt, IKM)` → 32-byte PRK.
    ///
    /// Per RFC 5869, an empty `salt` is equivalent to a 32-byte zero salt;
    /// implementors should handle both.
    ///
    /// Returned wrapped in `Zeroizing` — the PRK is secret keying
    /// material. Wrapping at the trait level makes the hygiene
    /// contract explicit; the wrapper type comes from the canonical
    /// `zeroize` crate, no krabitls-internal types involved.
    fn extract(salt: &[u8], ikm: &[u8]) -> zeroize::Zeroizing<[u8; 32]>;

    /// `HKDF-Expand(PRK, info, out.len())` → writes `out.len()` derived bytes
    /// into `out`. Returns [`HkdfExpandError::OutputTooLong`] if `out.len()`
    /// exceeds RFC 5869's `255 * hash_len` cap (for SHA-256 that's 8160
    /// bytes; TLS 1.3 never asks for that much, but the trait shouldn't lie
    /// about what an implementation might reject).
    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError>;
}

/// Errors a [`HkdfSha256::expand`] implementation may return.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HkdfExpandError {
    /// `out.len() > 255 * hash_len`. For SHA-256 that's 8160 bytes
    /// (RFC 5869's hard cap on HKDF-Expand output).
    OutputTooLong,
}

/// Incremental SHA-256 hash state.
///
/// `Clone` is required: the TLS 1.3 transcript hash is updated as each
/// handshake message arrives, and intermediate hash values get finalized at
/// the points where signatures and MACs are computed
/// (`SHA-256(CH || SH)`, `…|| EE || Cert`, etc.) without consuming the
/// running state.
pub trait Sha256Hasher: Clone {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; 32];
}
