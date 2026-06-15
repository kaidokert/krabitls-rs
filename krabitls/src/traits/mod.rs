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
//! - [`RecordAead`] — record-layer AEAD; one impl per key-buffer type
//!   ([`u8; 16`] for AES, [`u8; 32`] for ChaCha). Marker subtraits
//!   [`Aes128GcmAead`] / [`ChaCha20Poly1305Aead`] pin the key length so
//!   call sites keep their suite-named bounds.
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

#[cfg(feature = "chacha20")]
pub use aead::ChaCha20Poly1305Aead;
pub use aead::{AeadError, Aes128GcmAead, RecordAead};
#[cfg(feature = "rsa")]
pub use cert::RsaCertSigAlg;
pub use cert::{CertParseError, CertParser, CertView};
pub use ed25519_verify::Ed25519VerifierProvider;
pub use hkdf::{HkdfExpandError, HkdfSha256, Sha256Hasher};
pub use rsa_verify::RsaVerifierProvider;
#[cfg(feature = "validity")]
pub use time::{FixedTime, TimeSource};
