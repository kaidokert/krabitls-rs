//! Default backend implementations of the [`crate::traits`] swap-point
//! interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`DerCert`] — `CertParser` impl backed by the `der` crate.
//! - [`jedisct::JedisctCrypto`] (feature `jedisct`) — alternate
//!   [`crate::HkdfSha256`] backend using jedisct1's `hmac-sha256`, useful
//!   when dropping the RustCrypto SHA-256/HKDF chain from the binary.

pub mod der_cert;
#[cfg(feature = "jedisct")]
pub mod jedisct;
pub mod rustcrypto;

pub use der_cert::DerCert;
#[cfg(feature = "jedisct")]
pub use jedisct::JedisctCrypto;
pub use rustcrypto::RustCrypto;
