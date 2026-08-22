//! Caller-supplied client authentication for TLS 1.3 mutual auth.

use heapless::Vec;
use rand_core::TryCryptoRng;

/// Largest client-auth signature krabitls buffers. RSA-PSS is modulus-width, so
/// this tracks the widest enabled RSA width (512 for 4096, 384 for 3072, 256 for
/// 2048); an `ecdsa` build needs 104 for a DER-encoded P-384 `ECDSA-Sig-Value`
/// (SEQUENCE of two ≤49-byte INTEGERs); with both off only Ed25519 (64 B) signs.
pub const MAX_CLIENT_SIG_LEN: usize = if cfg!(feature = "rsa-4096") {
    512
} else if cfg!(feature = "rsa-3072") {
    384
} else if cfg!(feature = "rsa") {
    256
} else if cfg!(feature = "client-auth-ecdsa") {
    112
} else {
    64
};

/// A `CertificateVerify` signature produced by a [`ClientAuth`] implementation.
/// Length depends on the scheme (64 B for ed25519).
pub type ClientSignature = Vec<u8, MAX_CLIENT_SIG_LEN>;

/// A [`ClientAuth`] implementation could not produce a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("client signer failed to produce a signature")]
pub struct ClientAuthError;

/// Client authentication material, supplied by the caller when the server
/// sends a `CertificateRequest` (RFC 8446 §4.3.2).
///
/// The private key never enters krabitls: implement [`ClientAuth::sign`]
/// against an in-memory key, an HSM, a secure element, etc. Single-certificate
/// chains only for now (one leaf, no intermediates).
///
/// `R` is the connection's RNG type. The trait is parameterized over it (rather
/// than taking a generic `sign<R>` method) so it stays object-safe: the engine
/// erases the signer behind `dyn ClientAuth<R>` for one fixed `R` per binary, so
/// wiring a signer doesn't monomorphize the handshake per key type.
pub trait ClientAuth<R: TryCryptoRng + ?Sized> {
    /// DER of the client's leaf certificate, sent in the client `Certificate`
    /// message.
    fn cert_der(&self) -> &[u8];

    /// The TLS 1.3 `SignatureScheme` code point this signer produces for
    /// `CertificateVerify` (e.g. `0x0807` = ed25519).
    fn scheme(&self) -> u16;

    /// Sign the `CertificateVerify` signed-content (RFC 8446 §4.4.3) — the
    /// 64-space pad, the `"TLS 1.3, client CertificateVerify"` context, a
    /// separator, and the handshake transcript hash, assembled by krabitls.
    ///
    /// `rng` is the live connection RNG. Every bundled signer — RSA-PSS, ECDSA,
    /// and Ed25519 (via `RandomizedSigner`) — draws its nonce hedge / PSS salt /
    /// DPA blinder from it, so a failing `rng` yields `ClientAuthError`. A custom
    /// deterministic impl may ignore it.
    fn sign(&self, content: &[u8], rng: &mut R) -> Result<ClientSignature, ClientAuthError>;
}
