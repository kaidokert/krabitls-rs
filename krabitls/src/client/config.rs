//! `ClientConfig` trait + bundled `DefaultConfig` / `AesOnlyConfig`.
//! Buffer sizes live on [`super::Scratch`], not here.

use crate::backends::{DerCert, RustCrypto};
use crate::traits::{CertParser, Ed25519VerifierProvider, HkdfSha256, RsaVerifierProvider};

/// AES-128-GCM implementation usable by the TLS 1.3 record layer.
///
/// This is a blanket marker over the standard `aead 0.6` traits. Set
/// [`ClientConfig::Aes`] to a hardware-backed type to use it for handshake and
/// application records; it defaults to the bundled RustCrypto AES-128-GCM.
pub trait Aes128Gcm:
    aead::AeadInOut
    + aead::KeyInit
    + aead::KeySizeUser<KeySize = aead::consts::U16>
    + aead::AeadCore<NonceSize = aead::consts::U12, TagSize = aead::consts::U16>
{
}

impl<T> Aes128Gcm for T where
    T: aead::AeadInOut
        + aead::KeyInit
        + aead::KeySizeUser<KeySize = aead::consts::U16>
        + aead::AeadCore<NonceSize = aead::consts::U12, TagSize = aead::consts::U16>
{
}

/// Compile-time suite policy. Each variant exists only when its
/// corresponding `feature = "cipher-aes"` / `feature = "chacha20"`
/// pair is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSuitePolicy {
    /// AES-128-GCM only.
    #[cfg(feature = "cipher-aes")]
    AesOnly,
    /// Both suites; ChaCha advertised first.
    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    AesAndChaCha,
    /// ChaCha20-Poly1305 only.
    #[cfg(feature = "chacha20")]
    ChaChaOnly,
}

pub trait ClientConfig {
    /// HKDF / SHA-256 backend.
    type Hkdf: HkdfSha256;
    /// Cert DER parser (extracts SAN, validity, subject pubkey).
    type CertParser: CertParser;
    /// Ed25519 verifier backend.
    type Ed25519: Ed25519VerifierProvider;
    /// RSA verifier backend. Without `feature = "rsa"` the trait is empty
    /// and any marker type satisfies it.
    type Rsa: RsaVerifierProvider;
    /// AES-128-GCM record backend, present on any `cipher-aes` build. Defaults
    /// to the bundled RustCrypto `aes_gcm::Aes128Gcm` (see `DefaultConfig`); set
    /// it to a hardware-backed [`Aes128Gcm`] to offload the record layer.
    #[cfg(feature = "cipher-aes")]
    type Aes: Aes128Gcm;

    const SUITES: ConfigSuitePolicy;
}

/// Bundled default: `RustCrypto` for all slots; suite policy follows `chacha20`.
#[derive(Debug, Clone, Copy)]
pub struct DefaultConfig;

impl ClientConfig for DefaultConfig {
    type Hkdf = RustCrypto;
    type CertParser = DerCert;
    type Ed25519 = RustCrypto;
    type Rsa = RustCrypto;
    #[cfg(feature = "cipher-aes")]
    type Aes = aes_gcm::Aes128Gcm;

    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesAndChaCha;
    #[cfg(all(feature = "cipher-aes", not(feature = "chacha20")))]
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesOnly;
    #[cfg(all(not(feature = "cipher-aes"), feature = "chacha20"))]
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::ChaChaOnly;
}
