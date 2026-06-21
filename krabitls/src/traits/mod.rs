//! Backend-abstraction traits.
//!
//! These traits define the swap points where krabitls hands work off to
//! pluggable implementations. Each is a small, closed-over interface:
//! callers pick a type that implements the trait and pass it as the
//! corresponding generic parameter to [`crate::verify_server_flight`],
//! [`crate::write_client_hello`], etc.
//!
//! - [`HkdfSha256`] — HKDF over SHA-256 and the
//!   matching incremental hasher (default: [`crate::RustCrypto`]).
//! - [`CertParser`] — X.509 DER parser (default: [`crate::DerCert`]).
//! - [`Ed25519VerifierProvider`] — builds per-key Ed25519 verifiers
//!   (`signature::Verifier<[u8; 64]>`); default
//!   [`crate::RustCrypto`] wraps `ed25519_heapless`.
//! - [`TimeSource`] — wall-clock for cert validity checks (gated on
//!   `feature = "validity"`).

pub mod aead;
pub mod cert;
pub mod ed25519_verify;
pub mod hkdf;
pub mod rsa_verify;
#[cfg(feature = "validity")]
pub mod time;

pub use aead::AeadError;
pub use cert::{CertParseError, CertParser, CertView};
// Used internally by der_cert.rs (the cert-parser backend); nothing
// external uses the `crate::traits::RsaCertSigAlg` re-export path
// because backends reach for `crate::traits::cert::RsaCertSigAlg`
// directly. Re-export here for documentation symmetry with the other
// cert types — `#[allow(unused_imports)]` suppresses the lint that
// fires because no in-crate code resolves through `traits::`.
#[allow(unused_imports)]
#[cfg(feature = "rsa")]
pub use cert::RsaCertSigAlg;
pub use ed25519_verify::Ed25519VerifierProvider;
pub use hkdf::{HkdfExpandError, HkdfSha256};
pub use rsa_verify::RsaVerifierProvider;
#[cfg(feature = "validity")]
pub use time::TimeSource;
