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
//! - [`SigVerifierProvider`] — builds per-key verifiers for one algorithm
//!   ([`SigAlgo`]); [`VerifierBackend`] aggregates all algorithms behind one
//!   type param. Default [`crate::RustCrypto`] wires every algorithm.
//! - [`TimeSource`] — wall-clock for cert validity checks (supply one via a
//!   `Clocked` strategy; the default `NoClock` skips the check).

pub mod aead;
pub mod cert;
pub mod client_auth;
pub mod hkdf;
pub mod time;
pub mod verify_provider;
pub mod verify_strategy;

pub use aead::{AeadBackend, AeadError};
pub use cert::{CertParseError, CertParser, CertView};
pub use client_auth::{ClientAuth, ClientAuthError};
// Used internally by der_cert.rs (the cert-parser backend); nothing
// external uses the `crate::traits::RsaCertSigAlg` re-export path
// because backends reach for `crate::traits::cert::RsaCertSigAlg`
// directly. Re-export here for documentation symmetry with the other
// cert types — `#[allow(unused_imports)]` suppresses the lint that
// fires because no in-crate code resolves through `traits::`.
#[allow(unused_imports)]
#[cfg(feature = "rsa")]
pub use cert::RsaCertSigAlg;
pub use hkdf::{HkdfExpandError, HkdfSha256};
pub use time::TimeSource;
pub use verify_provider::{
    Ed25519, SigAlgo, SigVerifierProvider, VerifierBackend, VerifyProviderError,
};
// The per-algorithm markers are part of the public custom-backend surface but
// in-crate code reaches them via `verify_provider::` directly, so silence the
// unused-import lint (same pattern as `RsaCertSigAlg` above).
#[allow(unused_imports)]
#[cfg(feature = "mldsa")]
pub use verify_provider::MlDsa;
#[allow(unused_imports)]
#[cfg(feature = "rsa")]
pub use verify_provider::Rsa;
#[allow(unused_imports)]
#[cfg(feature = "ecdsa")]
pub use verify_provider::{EcdsaP256, EcdsaP384};
pub use verify_strategy::ServerPubkey;
