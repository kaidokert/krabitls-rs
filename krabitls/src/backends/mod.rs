//! Default backend implementations of the [`crate::traits`] swap-point
//! interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`DerCert`] — `CertParser` impl. With `feature = "cert-der"`
//!   (default), backed by the `der` crate. Without it, backed by the
//!   hand-rolled TLV walker in [`tlv`] — drops the `der` dependency at
//!   the cost of an unaudited parser.
//! - [`jedisct::JedisctCrypto`] (feature `jedisct`) — alternate
//!   [`crate::HkdfSha256`] backend using jedisct1's `hmac-sha256`, useful
//!   when dropping the RustCrypto SHA-256/HKDF chain from the binary.

// `cert-der` toggles which backend is compiled in: on → `der`-crate,
// off → in-tree TLV walker. Exactly one is always active.
#[cfg(feature = "cert-der")]
pub mod der_cert;
#[cfg(not(feature = "cert-der"))]
pub mod tlv_cert;

#[cfg(feature = "jedisct")]
pub mod jedisct;
#[cfg(feature = "rsa")]
pub mod rsa_verify;
pub mod rustcrypto;
pub(crate) mod tlv;

#[cfg(feature = "cert-der")]
pub use der_cert::DerCert;
#[cfg(feature = "jedisct")]
pub use jedisct::JedisctCrypto;
#[cfg(feature = "rsa")]
pub use rsa_verify::{RsaVerifierKey, RsaVerifyError};
pub use rustcrypto::RustCrypto;
#[cfg(not(feature = "cert-der"))]
pub use tlv_cert::DerCert;
