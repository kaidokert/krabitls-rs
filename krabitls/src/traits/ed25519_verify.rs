//! Pluggable backend for Ed25519 signature verification.

/// Verify Ed25519 signatures, optionally with caller-managed precomputation.
pub trait Ed25519Verify {
    /// Amortizable per-backend precompute. `()` for backends with no cache.
    type Cache;

    /// Build a fresh cache.
    fn new_cache() -> Self::Cache;

    /// One-shot verify.
    fn verify(pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool;

    /// Verify using a caller-supplied cache.
    fn verify_with_cache(
        cache: &Self::Cache,
        pubkey: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> bool;
}
