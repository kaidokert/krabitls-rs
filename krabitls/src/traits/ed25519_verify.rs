//! Pluggable backend for Ed25519 signature verification.
//!
//! Krabitls's locked profile uses Ed25519 in two places: the cert's own
//! self-signature (verified in `verify_self_signed_cert`) and the
//! TLS 1.3 `CertificateVerify` message (in `verify_certificate_verify`).
//! Until this trait landed, both call sites instantiated
//! `ed25519_heapless::verify::<fixed_bigint::FixedUInt<u32, 16>>(...)`
//! directly — every byte of the bigint backend was baked into krabitls
//! at compile time, leaving no room for callers with hardware-accelerated
//! ASN.1 / bigint blocks (Cortex-M33 CryptoCell, NXP PKA, STM32 PKA, etc.)
//! to plug in their own implementation.
//!
//! The trait is intentionally a *closed-over* signature with no bigint
//! generic parameter: each implementor picks its own backend internally
//! and presents the byte-level Ed25519 verify primitive to krabitls. This
//! keeps `ed25519_heapless`'s `UnsignedModularInt` bound forest out of
//! krabitls's public surface — callers see one method, not a dozen trait
//! bounds.

/// Verify an Ed25519 signature.
///
/// Returns `true` if the 64-byte `signature` is a valid Ed25519 signature
/// over `msg` under the 32-byte `pubkey`, `false` otherwise. Implementors
/// are responsible for the full RFC 8032 verification — point decoding,
/// SHA-512 over `R || A || msg`, scalar reduction, and the Schnorr-equation
/// check.
///
/// The default impl is on [`crate::RustCrypto`], wrapping
/// `ed25519_heapless::verify::<fixed_bigint::FixedUInt<u32, 16>>`.
/// Backends with hardware-assisted bigint or different bound forests
/// (crypto-bigint, bnum, etc.) implement this trait on their own marker
/// type and pass that as the `E` type parameter to `verify_self_signed_cert`,
/// `verify_certificate_verify`, and `verify_server_flight`.
///
/// # Amortizing the per-call precompute
///
/// `ed25519::verify` internally constructs a `Curve25519Field` on every
/// call, which is a ~100-150k-cycle precompute on M3. Callers verifying
/// multiple signatures back-to-back (e.g. cert self-sig + CertificateVerify
/// in [`crate::verify_server_flight`]) should:
///
/// 1. Call [`Ed25519Verify::new_cache`] once at the top of the verify
///    pipeline.
/// 2. Use [`Ed25519Verify::verify_with_cache`] in place of
///    [`Ed25519Verify::verify`] at every callsite that has the cache in
///    scope.
///
/// Backends without an amortizable cache implement `Cache = ()` and have
/// `verify_with_cache` ignore the cache argument.
pub trait Ed25519Verify {
    /// Amortizable per-curve precompute (e.g. `Curve25519Field` for the
    /// `ed25519_heapless` backend). `()` for backends with no cache concept.
    type Cache;

    /// Build a fresh cache. Called once per verify pipeline (or once at
    /// program start, then stashed).
    fn new_cache() -> Self::Cache;

    /// One-shot verify. Internally rebuilds the cache; cheap for callers
    /// that only verify one signature.
    fn verify(pubkey: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool;

    /// Verify using a caller-supplied cache. Skips the per-call precompute
    /// when the implementor can take advantage of it.
    fn verify_with_cache(
        cache: &Self::Cache,
        pubkey: &[u8; 32],
        msg: &[u8],
        signature: &[u8; 64],
    ) -> bool;
}
