//! Caller-supplied client authentication for TLS 1.3 mutual auth.

use heapless::Vec;

/// Largest client-auth signature krabitls buffers. Ed25519 = 64 B; an RSA-2048
/// PSS signature (a future scheme) = 256 B.
pub const MAX_CLIENT_SIG_LEN: usize = 256;

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
pub trait ClientAuth {
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
    /// `entropy` is fresh output of the connection's RNG, passed as bytes so
    /// the trait stays dyn-compatible. Randomized schemes consume it (RSA-PSS
    /// uses it as the salt); deterministic schemes (ed25519) ignore it.
    fn sign(&self, content: &[u8], entropy: &[u8; 32]) -> Result<ClientSignature, ClientAuthError>;
}
