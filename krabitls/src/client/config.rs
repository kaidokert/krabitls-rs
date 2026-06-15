//! `ClientConfig` trait + bundled `DefaultConfig` / `AesOnlyConfig`.
//! Buffer sizes live on [`super::Scratch`], not here.

use crate::backends::{DerCert, RustCrypto};
use crate::traits::{
    Aes128GcmAead, CertParser, Ed25519VerifierProvider, HkdfSha256, RsaVerifierProvider,
};

#[cfg(feature = "chacha20")]
use crate::traits::ChaCha20Poly1305Aead;

/// Compile-time suite policy. AesOnly statically prunes ChaCha branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSuitePolicy {
    /// AES-128-GCM only.
    AesOnly,
    /// Both suites; ChaCha advertised first.
    #[cfg(feature = "chacha20")]
    AesAndChaCha,
}

/// Backend + compile-time-policy bundle the facade is parameterized over.
#[cfg(not(feature = "chacha20"))]
pub trait ClientConfig {
    /// HKDF / SHA-256 backend.
    type Hkdf: HkdfSha256;
    /// Record-layer AEAD backend.
    type Record: Aes128GcmAead;
    /// Cert DER parser (extracts SAN, validity, subject pubkey).
    type CertParser: CertParser;
    /// Ed25519 verifier backend (used for self-signed and pinned Ed25519 trust).
    type Ed25519: Ed25519VerifierProvider;
    /// RSA verifier backend. Without `feature = "rsa"` the trait is
    /// empty and any marker type satisfies it.
    type Rsa: RsaVerifierProvider;

    /// Compile-time suite policy. See [`ConfigSuitePolicy`].
    const SUITES: ConfigSuitePolicy;
}

#[cfg(feature = "chacha20")]
pub trait ClientConfig {
    /// HKDF / SHA-256 backend.
    type Hkdf: HkdfSha256;
    /// Record-layer AEAD; bound widens to both AEADs under `chacha20`.
    type Record: Aes128GcmAead + ChaCha20Poly1305Aead;
    /// Cert DER parser (extracts SAN, validity, subject pubkey).
    type CertParser: CertParser;
    /// Ed25519 verifier backend (used for self-signed and pinned Ed25519 trust).
    type Ed25519: Ed25519VerifierProvider;
    /// RSA verifier backend. Without `feature = "rsa"` the trait is
    /// empty and any marker type satisfies it.
    type Rsa: RsaVerifierProvider;

    /// Compile-time suite policy. See [`ConfigSuitePolicy`].
    const SUITES: ConfigSuitePolicy;
}

/// Bundled default: `RustCrypto` for all slots; suite policy follows `chacha20`.
#[derive(Debug, Clone, Copy)]
pub struct DefaultConfig;

impl ClientConfig for DefaultConfig {
    type Hkdf = RustCrypto;
    type Record = RustCrypto;
    type CertParser = DerCert;
    type Ed25519 = RustCrypto;
    type Rsa = RustCrypto;

    #[cfg(feature = "chacha20")]
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesAndChaCha;
    #[cfg(not(feature = "chacha20"))]
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesOnly;
}

/// Compile-time AES-only config; suppresses ChaCha dispatch even with `feature = "chacha20"`.
#[derive(Debug, Clone, Copy)]
pub struct AesOnlyConfig;

impl ClientConfig for AesOnlyConfig {
    type Hkdf = RustCrypto;
    type Record = RustCrypto;
    type CertParser = DerCert;
    type Ed25519 = RustCrypto;
    type Rsa = RustCrypto;
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesOnly;
}
