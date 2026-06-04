//! Backend-abstraction traits.
//!
//! These traits define the swap points where krabitls hands work off to
//! pluggable implementations. Each is a small, closed-over interface:
//! callers pick a type that implements the trait and pass it as the
//! corresponding generic parameter to [`crate::verify_server_flight`],
//! [`crate::write_client_hello`], etc.
//!
//! - [`HkdfSha256`] + [`Sha256Hasher`] — HKDF over SHA-256 and the
//!   matching incremental hasher (default: [`crate::RustCrypto`]).
//! - [`Aes128GcmAead`] — record-layer AEAD (default:
//!   [`crate::RustCrypto`]).
//! - [`CertParser`] — X.509 DER parser (default: [`crate::DerCert`]).
//! - [`Ed25519Verify`] — Ed25519 signature verify (default:
//!   [`crate::RustCrypto`] wrapping `ed25519_heapless`).
//! - [`TimeSource`] — wall-clock for cert validity checks (gated on
//!   `feature = "validity"`).

pub mod aead;
pub mod cert;
pub mod ed25519_verify;
pub mod hkdf;
#[cfg(feature = "validity")]
pub mod time;

pub use aead::{AeadError, Aes128GcmAead};
pub use cert::{CertParseError, CertParser, CertView};
pub use ed25519_verify::Ed25519Verify;
pub use hkdf::{HkdfExpandError, HkdfSha256, Sha256Hasher};
#[cfg(feature = "validity")]
pub use time::{FixedTime, TimeSource};
