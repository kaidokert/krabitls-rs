//! High-level TLS 1.3 client facade.
//!
//! User-facing entry point for a no-`std`, no-alloc TLS 1.3
//! connection: bring a [`Transport`], a caller-owned [`Scratch`], an
//! RNG, and a [`ClientParams`] — get a connected [`TlsStream`] back.

#[cfg(feature = "canned-replay")]
pub mod canned;
mod config;
mod engine;
mod error;
mod params;
mod scratch;
mod stream;
mod transport;

pub use config::{AesOnlyConfig, ClientConfig, ConfigSuitePolicy, DefaultConfig};
pub(crate) use error::WriteAppError;
pub use error::{ConfigError, ConnectError, HandshakeError, InternalError};
pub use params::{ClientParams, RuntimeSuitePolicy};
pub use scratch::{
    CustomFlight, CustomRecv, CustomSend, DefaultScratch, EmbeddedEd25519Scratch,
    FACADE_HOSTNAME_MAX, MIN_RECV, MIN_SEND_STANDARD, MinimalScratch, Scratch,
};
pub use stream::{DefaultStream, StreamError, TlsStream};
pub use transport::Transport;

// Convenience re-exports — let facade users `use krabitls::client::*` without
// also pulling in the typestate crate root.
pub use crate::{ClientHelloOptions, PinnedPubkey, SuiteList};

#[cfg(test)]
mod tests {
    use super::*;

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
    #[allow(dead_code)]
    static _MINIMAL_SCRATCH_FITS_IN_STATIC: MinimalScratch = MinimalScratch::new();

    #[test]
    fn default_config_satisfies_client_config() {
        // Force trait resolution: if `DefaultConfig` ever stops
        // satisfying `ClientConfig` (e.g. a backend bound changes),
        // this stops compiling.
        fn assert_impl<C: ClientConfig>() {}
        assert_impl::<DefaultConfig>();
        assert_impl::<AesOnlyConfig>();
    }

    #[test]
    fn aes_only_config_advertises_aes_only_at_compile_time() {
        assert_eq!(AesOnlyConfig::SUITES, ConfigSuitePolicy::AesOnly);
    }

    #[cfg(feature = "chacha20")]
    #[test]
    fn default_config_advertises_both_under_chacha20() {
        assert_eq!(DefaultConfig::SUITES, ConfigSuitePolicy::AesAndChaCha);
    }

    #[cfg(not(feature = "chacha20"))]
    #[test]
    fn default_config_falls_back_to_aes_only_without_chacha20() {
        assert_eq!(DefaultConfig::SUITES, ConfigSuitePolicy::AesOnly);
    }

    #[test]
    fn client_params_constructors_are_infallible() {
        let pin = PinnedPubkey::Ed25519([0u8; 32]);
        let _pinned = ClientParams::pinned("example.com", pin);
        let _self_signed = ClientParams::self_signed("example.com");
    }

    #[test]
    fn client_params_builder_chains() {
        let pin = PinnedPubkey::Ed25519([0u8; 32]);
        let params =
            ClientParams::pinned("example.com", pin).suite_policy(RuntimeSuitePolicy::AesOnly);
        assert_eq!(params.suite_policy, RuntimeSuitePolicy::AesOnly);
        assert_eq!(params.hostname(), "example.com");
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
    /// MIN_RECORD_SIZE_LIMIT + RECORD_OVERHEAD floor (85) is smaller.
    const _: () = assert!(MIN_RECV == 95);
    /// `MIN_SEND_STANDARD` must accommodate the largest engine-internal
    /// send (Client Finished today).
    const _: () = assert!(MIN_SEND_STANDARD >= crate::CLIENT_FINISHED_LEN);
    /// Facade hostname cap is DNS-compatible (longest legal FQDN is 253;
    /// 255 leaves room for the trailing `.` callers occasionally include).
    const _: () = assert!(FACADE_HOSTNAME_MAX == 255);

    // Manual stub avoids pulling in `embedded_io_adapters` for a
    // compile-time-only trait resolution check.
    #[test]
    fn embedded_io_blanket_impl_resolves() {
        use embedded_io::{ErrorType, Read, ReadExactError, Write};

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
        let e = InternalError::RecvBufferEmptyOnRecvEvent;
        assert!(!format!("{e}").is_empty());
    }
}
