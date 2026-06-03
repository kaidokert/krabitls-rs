//! Default backend implementations of the [`crate::traits`] swap-point
//! interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`DerCert`] — `CertParser` impl backed by the `der` crate.

pub mod der_cert;
pub mod rustcrypto;

pub use der_cert::DerCert;
pub use rustcrypto::RustCrypto;
