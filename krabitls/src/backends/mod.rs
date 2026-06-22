//! Default backend implementations of the crate-internal swap-point
//! interfaces.
//!
//! - [`RustCrypto`] — bundled defaults wired to the RustCrypto crates
//!   (`sha2 + hmac + hkdf + aes-gcm`) for HKDF + AEAD, and to
//!   `ed25519_heapless` for `Ed25519Verify`. Pick this marker when you
//!   want "the obvious thing." Most callers do.
//! - [`DerCert`] — `CertParser` impl. With `feature = "cert-der"`
//!   (default), backed by the `der` crate. Without it, backed by an
//!   in-tree hand-rolled TLV walker — drops the `der` dependency at the
//!   cost of an unaudited parser.
//! - `JedisctCrypto` (feature `jedisct`) — alternate `HkdfSha256`
//!   backend using jedisct1's `hmac-sha256`, useful when dropping the
//!   RustCrypto SHA-256/HKDF chain from the binary.

// Backend submodules are private; reach the public markers via the
// re-exports at this level (`krabitls::backends::{RustCrypto, ...}`).
#[cfg(feature = "cert-der")]
pub(crate) mod der_cert;
#[cfg(feature = "jedisct")]
pub(crate) mod jedisct;
pub(crate) mod pin_or_self_signed;
#[cfg(feature = "rsa")]
pub(crate) mod rsa_verify;
pub(crate) mod rustcrypto;
pub(crate) mod tlv;
#[cfg(not(feature = "cert-der"))]
pub(crate) mod tlv_cert;

#[cfg(feature = "cert-der")]
pub use der_cert::DerCert;
#[cfg(feature = "jedisct")]
pub use jedisct::JedisctCrypto;
// Re-exports purely for the external API surface — nothing in-crate
// uses these paths, so silence the unused-import lint.
#[cfg(feature = "rsa")]
pub use pin_or_self_signed::PinnedPubkeyOwnedError;
pub use pin_or_self_signed::{PinOrSelfSigned, PinOrSelfSignedError, PinnedPubkeyOwned};
#[allow(unused_imports)]
#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
pub use rsa_verify::RsaPkcs1Sig;
#[allow(unused_imports)]
#[cfg(feature = "rsa")]
pub use rsa_verify::RsaPssSig;
#[cfg(feature = "rsa")]
pub use rsa_verify::{RsaVerifierKey, RsaVerifyError};
pub use rustcrypto::RustCrypto;
#[cfg(not(feature = "cert-der"))]
pub use tlv_cert::DerCert;
