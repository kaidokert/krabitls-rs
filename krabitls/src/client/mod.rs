//! High-level TLS 1.3 client facade.
//!
//! User-facing entry point for a no-`std`, no-alloc TLS 1.3
//! connection: bring a [`Transport`], a caller-owned [`Scratch`], an
//! RNG, and a [`ClientParams`] — get a connected [`TlsStream`] back.

mod config;
mod engine;
/// Error types that can surface through the facade.
pub mod error;
mod params;
mod scratch;
mod stream;
mod transport;

// Public facade surface — what real clients reach for to make a connection.
pub use config::{ClientConfig, ConfigSuitePolicy, DefaultConfig};
// Top-level convenience: outer error + the two it wraps + the
// connection-level enum callers match on to distinguish parse / decrypt
// / flight failures. Inner leaves stay under `client::error::*`.
pub use error::{ConfigError, ConnectError, ConnectionError, HandshakeError};
#[cfg(feature = "cert-der")]
pub use params::ClockedVerify;
pub use params::{ClientParams, DefaultVerify, RuntimeSuitePolicy};
pub use scratch::{DefaultScratch, MIN_RECV, MIN_SEND_STANDARD, Scratch};
pub use stream::{DefaultStream, DefaultStreamWith, StreamError, TlsStream};
pub use transport::Transport;

// Re-export PinnedPubkey at this level so callers don't have to import
// from the crate root.
pub use crate::identity::PinnedPubkey;
pub use crate::traits::TimeSource;

// Client (mutual) authentication — the compile-time policy (default
// `NoClientAuth` links no cert-emission code), the caller-supplied signer
// trait, the bundled Ed25519 implementation, and its error.
pub use crate::backends::Ed25519ClientAuth;
pub use crate::client_flight::{
    ClientAuthPolicy, DeclineClientAuth, MAX_CLIENT_CERT_DER, NoClientAuth, WithClientAuth,
};
pub use crate::traits::{ClientAuth, ClientAuthError};

// Strategy surface — what custom-verifier callers need to roll their own
// trust-root decision (or instantiate the bundled `SafeStrategy`).
pub use crate::backends::{PinOrSelfSigned, PinnedPubkeyOwned};
// Provider traits are part of the strategy's generic bounds — custom
// `VerifyStrategy<E, R>` impls have to name `Ed25519VerifierProvider` /
// `RsaVerifierProvider` in their `where` clauses.
#[cfg(feature = "cert-der")]
pub use crate::traits::verify_strategy::Clocked;
pub use crate::traits::verify_strategy::{
    CertChainView, NoClock, PreparedVerifier, SafeStrategy, SafeStrategyError, TrustRootDecision,
    Trusted, VerifierKeyMaterial, VerifyStrategy,
};
pub use crate::traits::{Ed25519VerifierProvider, RsaVerifierProvider};

// In-crate-only: alternate config impls (samples, callers write their own),
// the WriteAppError plumbing type, the InternalError variant the engine
// surfaces upstream, the scratch-tuning knobs, and the in-progress
// hostname cap.
pub(crate) use error::WriteAppError;

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_io::{ErrorType, Read, ReadExactError, Write};

    // Compile-time smoke tests: these don't assert anything at runtime,
    // they just force the type system to confirm the public surface
    // resolves cleanly under the cfg combinations the per-feature CI
    // matrix exercises.

    /// `DefaultScratch::new()` is `const`, so we can place one in a
    /// `static`. This is the canonical embedded usage pattern; the test
    /// would fail to compile if `Scratch::new()` lost its `const`
    /// qualifier.
    #[allow(dead_code)]
    static _DEFAULT_SCRATCH_FITS_IN_STATIC: DefaultScratch = DefaultScratch::new();

    #[test]
    fn default_config_satisfies_client_config() {
        // Force trait resolution: if `DefaultConfig` ever stops
        // satisfying `ClientConfig` (e.g. a backend bound changes),
        // this stops compiling.
        fn assert_impl<C: ClientConfig>() {}
        assert_impl::<DefaultConfig>();
    }

    #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
    #[test]
    fn default_config_advertises_both_under_chacha20() {
        assert_eq!(DefaultConfig::SUITES, ConfigSuitePolicy::AesAndChaCha);
    }

    #[cfg(all(feature = "cipher-aes", not(feature = "chacha20")))]
    #[test]
    fn default_config_falls_back_to_aes_only_without_chacha20() {
        assert_eq!(DefaultConfig::SUITES, ConfigSuitePolicy::AesOnly);
    }

    #[test]
    fn client_params_ed25519_pin_constructs_cleanly() {
        let pin = PinnedPubkey::Ed25519([0u8; 32]);
        ClientParams::pinned("example.com", pin).expect("Ed25519 pin");
        let _self_signed = ClientParams::self_signed("example.com");
    }

    #[test]
    fn client_params_builder_chains() {
        let pin = PinnedPubkey::Ed25519([0u8; 32]);
        let params = ClientParams::pinned("example.com", pin)
            .expect("Ed25519 pin")
            .suite_policy(RuntimeSuitePolicy::AesOnly);
        assert_eq!(params.suite_policy, RuntimeSuitePolicy::AesOnly);
        assert_eq!(params.hostname(), "example.com");
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn client_params_rsa_pin_with_oversized_modulus_errors() {
        // 257-byte modulus exceeds MAX_RSA_MODULUS_BYTES (256) — must
        // surface as `ModulusTooLong`, never panic.
        let oversize = [0u8; 257];
        let pin = PinnedPubkey::Rsa {
            modulus: &oversize,
            exponent: 65537,
        };
        let err = ClientParams::pinned("example.com", pin).expect_err("oversize must reject");
        assert_eq!(err, crate::backends::PinnedPubkeyOwnedError::ModulusTooLong);
    }

    #[test]
    fn runtime_suite_policy_default_is_default_variant() {
        assert_eq!(RuntimeSuitePolicy::default(), RuntimeSuitePolicy::Default);
    }

    // Constant-value invariants pinned as compile-time `const _ = assert!(…)`
    // items: stronger than runtime tests because the compile fails if any
    // of these drifts. (`assert_eq!` in a `#[test]` would be flagged by
    // clippy's `assertions_on_constants` lint anyway.)

    /// Dominated by the 95-byte locked-profile ServerHello; the
    /// MIN_RECORD_SIZE_LIMIT + RECORD_OVERHEAD floor (85) is smaller. Under
    /// `mlkem` the `X25519MLKEM768` server key_share adds the ML-KEM ciphertext.
    #[cfg(not(feature = "mlkem"))]
    const _: () = assert!(MIN_RECV == 95);
    #[cfg(feature = "mlkem")]
    const _: () = assert!(MIN_RECV == 95 + crate::backends::mlkem::MLKEM768_CT_BYTES);
    /// `MIN_SEND_STANDARD` must accommodate the largest engine-internal
    /// send (Client Finished today).
    const _: () = assert!(MIN_SEND_STANDARD >= crate::client_flight::CLIENT_FINISHED_LEN);

    // Manual stub avoids pulling in `embedded_io_adapters` for a
    // compile-time-only trait resolution check.
    #[test]
    fn embedded_io_blanket_impl_resolves() {
        #[derive(Debug)]
        struct Stub;

        #[derive(Debug)]
        struct StubError;

        impl core::fmt::Display for StubError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("stub")
            }
        }
        impl core::error::Error for StubError {}

        impl embedded_io::Error for StubError {
            fn kind(&self) -> embedded_io::ErrorKind {
                embedded_io::ErrorKind::Other
            }
        }

        impl ErrorType for Stub {
            type Error = StubError;
        }

        impl Read for Stub {
            fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
                Ok(0)
            }
        }

        impl Write for Stub {
            fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        fn assert_transport<T: Transport>() {}
        assert_transport::<Stub>();

        // Sanity-check the unused-import linter against the upstream
        // re-exports we lean on here. (Lints would otherwise prune
        // `ReadExactError` if we ever stop referencing it.)
        let _ = core::mem::size_of::<ReadExactError<StubError>>();
    }

    #[test]
    fn error_display_round_trips() {
        let e: ConnectError<core::convert::Infallible> = ConnectError::UnexpectedEof;
        assert!(format!("{e}").contains("transport"));
        let e: ConnectError<core::convert::Infallible> = ConnectError::Closed;
        assert!(format!("{e}").contains("closed"));
        let e = HandshakeError::Busy;
        assert!(format!("{e}").contains("Busy") || format!("{e}").contains("pending"));
        let e = HandshakeError::RecordTooLarge {
            limit: 1024,
            got: 2048,
        };
        let s = format!("{e}");
        assert!(s.contains("1024"));
        assert!(s.contains("2048"));
        let e = ConfigError::HostnameTooLong;
        assert!(format!("{e}").contains("hostname"));
        let e = ConfigError::BufferTooSmall {
            needed: 100,
            got: 50,
        };
        let s = format!("{e}");
        assert!(s.contains("100"));
        assert!(s.contains("50"));
        let e = error::InternalError::RecvBufferEmptyOnRecvEvent;
        assert!(!format!("{e}").is_empty());
    }
}
