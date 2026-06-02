//! Default + optional backend implementations of the
//! [`crate::traits`] swap-point interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`JedisctCrypto`] — alternate `HkdfSha256` impl wired to
//!   jedisct1's `hmac-sha256` crate (drops the entire RustCrypto
//!   `sha2 + hmac + hkdf + digest + crypto-common + generic-array`
//!   chain under LTO).
//! - [`DerCert`] — `CertParser` impl backed by the `der` crate.
//! - [`rsa_verify`] (under `feature = "rsa"`) — RSA-PSS-SHA256 +
//!   PKCS#1-v1.5-SHA-256 verify support, including the cached
//!   `RsaVerifierKey` that amortizes `ModMathParams::new` across
//!   self-sig + CertificateVerify in [`crate::verify_server_flight`].

pub mod der_cert;
pub mod jedisct;
#[cfg(feature = "rsa")]
pub mod rsa_verify;
pub mod rustcrypto;

pub use der_cert::DerCert;
pub use jedisct::JedisctCrypto;
pub use rustcrypto::RustCrypto;
