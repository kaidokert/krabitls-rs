//! Default backend implementations of the [`crate::traits`] swap-point
//! interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`DerCert`] — `CertParser` impl. Default: backed by the `der` crate.
//!   With `feature = "cert-tlv"` (off by default), backed by the
//!   hand-rolled TLV walker in [`tlv`] — drops the `der` dependency at
//!   the cost of using a parser that hasn't been independently audited.
//! - [`jedisct::JedisctCrypto`] (feature `jedisct`) — alternate
//!   [`crate::HkdfSha256`] backend using jedisct1's `hmac-sha256`, useful
//!   when dropping the RustCrypto SHA-256/HKDF chain from the binary.

#[cfg(not(feature = "cert-tlv"))]
pub mod der_cert;
#[cfg(feature = "jedisct")]
pub mod jedisct;
#[cfg(feature = "rsa")]
pub mod rsa_verify;
pub mod rustcrypto;
pub(crate) mod tlv;
#[cfg(feature = "cert-tlv")]
pub mod tlv_cert;

#[cfg(not(feature = "cert-tlv"))]
pub use der_cert::DerCert;
#[cfg(feature = "jedisct")]
pub use jedisct::JedisctCrypto;
#[cfg(feature = "rsa")]
pub use rsa_verify::{RsaVerifierKey, RsaVerifyError};
pub use rustcrypto::RustCrypto;
#[cfg(feature = "cert-tlv")]
pub use tlv_cert::DerCert;
