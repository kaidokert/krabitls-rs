//! Pluggable backend for Ed25519 signature verification.

/// Build per-key Ed25519 verifiers.
///
/// The returned `Verifier` implements the canonical [`signature::Verifier`]
/// trait against `[u8; 64]`-sized signatures, so once constructed it can be
/// handed to any code that bounds on `signature::Verifier`. krabitls's
/// `verify_server_flight` calls `prepare_ed25519` once per cert and reuses
/// the result across the cert-self-sig and `CertificateVerify` checks; the
/// `Verifier` type is expected to bundle the per-curve precompute internally
/// so this reuse stays cheap.
pub trait Ed25519VerifierProvider {
    /// Per-key prepared form, ready to verify `[u8; 64]` Ed25519 signatures.
    /// Also implements `VerifierKeyMaterial<[u8; 32]>` for the strategy /
    /// stack SPKI cross-check.
    type Verifier: signature::Verifier<[u8; 64]>
        + crate::traits::verify_strategy::VerifierKeyMaterial<[u8; 32]>;

    /// Build a verifier bound to `pubkey`. Expected to do any expensive
    /// precompute (Montgomery curve params, etc.) once per call.
    fn prepare_ed25519(pubkey: &[u8; 32]) -> Self::Verifier;
}
