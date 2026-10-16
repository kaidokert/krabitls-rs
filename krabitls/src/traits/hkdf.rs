//! `HkdfSha256` abstraction trait.
//!
//! TLS 1.3 derives every key in the handshake from an HKDF chain
//! (RFC 8446 §7.1). Different deployments may want different HKDF
//! implementations — RustCrypto, jedisct1, hand-rolled, vendor libs —
//! so the trait is the swap point.
//!
//! Trait is fixed to SHA-256 (the hash bound to our locked cipher suite
//! `TLS_AES_128_GCM_SHA256`).
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
    /// Incremental SHA-256 hasher. `Clone` is required so the TLS 1.3
    /// transcript hash can be snapshotted without consuming the live state.
    type Hasher: Sha256 + Clone;

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
    fn extract(salt: &[u8], ikm: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, HkdfBackendError>;

    /// `HKDF-Expand(PRK, info, out.len())` → writes `out.len()` derived bytes
    /// into `out`. Returns [`HkdfExpandError::OutputTooLong`] if `out.len()`
    /// exceeds RFC 5869's `255 * hash_len` cap (for SHA-256 that's 8160
    /// bytes; TLS 1.3 never asks for that much, but the trait shouldn't lie
    /// about what an implementation might reject).
    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError>;
}

/// Fallible incremental SHA-256 used by the TLS transcript.
///
/// Hardware engines can time out, reject a DMA buffer, or report a command
/// failure. Keeping those failures in the contract prevents a backend from
/// substituting a synthetic digest and continuing with predictable keys.
pub trait Sha256 {
    /// Feed bytes into the running hash.
    /// Implementations retain a sticky failure if the underlying operation
    /// fails; [`Sha256::snapshot`] then reports it before any digest is used.
    fn update(&mut self, data: &[u8]);

    /// Finalize a snapshot without consuming the live hash state.
    fn snapshot(&self) -> Result<[u8; 32], HkdfBackendError>;
}

/// The portable error exposed when a SHA-256/HKDF engine fails.
///
/// Hardware adapters retain their device-specific diagnostic separately; the
/// TLS core only needs to distinguish a backend failure from input sizing.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum HkdfBackendError {
    /// The selected SHA-256/HKDF backend could not complete the operation.
    #[error("SHA-256/HKDF backend failed")]
    Failed,
}

/// Errors a [`HkdfSha256::expand`] implementation may return.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum HkdfExpandError {
    /// `out.len() > 255 * hash_len`. For SHA-256 that's 8160 bytes
    /// (RFC 5869's hard cap on HKDF-Expand output).
    #[error("HKDF-Expand output exceeds 255 * hash_len")]
    OutputTooLong,
    /// PRK was rejected by the backend (e.g. wrong size). The trait's
    /// `prk: &[u8; 32]` type makes this statically unreachable for
    /// well-behaved backends, but the variant exists so impls don't have
    /// to `.expect()` the underlying crate's fallible constructor.
    #[error("HKDF backend rejected the PRK")]
    InvalidPrk,
    /// The backend could not complete the operation.
    #[error(transparent)]
    Backend(#[from] HkdfBackendError),
}
