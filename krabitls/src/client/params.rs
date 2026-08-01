//! Per-connection trust + policy. Constructors couple trust mode to its material.

use crate::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwnedError};
use crate::client_flight::{DeclineClientAuth, NoClientAuth, WithClientAuth};
use crate::identity::PinnedPubkey;
use crate::traits::client_auth::ClientAuth;
#[cfg(feature = "cert-der")]
use crate::traits::time::TimeSource;
#[cfg(feature = "cert-der")]
use crate::traits::verify_strategy::Clocked;
use crate::traits::verify_strategy::SafeStrategy;

/// Default `V` for [`ClientParams`] / [`super::DefaultStream`]: pin or
/// self-signed via the bundled `SafeStrategy<PinOrSelfSigned, DerCert>`. Uses
/// the default `NoClock`, so cert validity-window checks are skipped unless the
/// caller opts in via `ClientParams::clocked`.
pub type DefaultVerify = SafeStrategy<PinOrSelfSigned, DerCert>;

/// Runtime narrowing of the compile-time suite advertisement.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSuitePolicy {
    #[default]
    Default,
    AesOnly,
    #[cfg(feature = "chacha20")]
    ChaChaOnly,
}

/// Per-connection trust + policy bundle. Construct via [`Self::pinned`] /
/// [`Self::self_signed`].
///
/// `A` is the compile-time [`ClientAuthPolicy`](crate::client::ClientAuthPolicy):
/// the default [`NoClientAuth`] links no certificate-emission code, so a
/// non-mTLS client pays nothing. [`Self::with_client_auth`] switches it to
/// mutual auth.
#[derive(Clone)]
pub struct ClientParams<'a, V = DefaultVerify, A = NoClientAuth> {
    pub(crate) hostname: &'a str,
    pub(crate) verify: V,
    pub(crate) suite_policy: RuntimeSuitePolicy,
    pub(crate) client_auth: A,
    /// Send a random 32-byte `legacy_session_id` for TLS 1.3 middlebox-
    /// compatibility mode (RFC 8446 §D.4). Off by default; enable for peers
    /// behind TLS-terminating load balancers / CDNs that expect it.
    pub(crate) middlebox_compat: bool,
    /// ALPN protocol names to advertise, in preference order. `None` omits
    /// the extension. Required by endpoints that gate on ALPN (e.g. `b"h2"`).
    pub(crate) alpn: Option<&'a [&'a [u8]]>,
}

impl<'a, V, A> core::fmt::Debug for ClientParams<'a, V, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientParams")
            .field("hostname", &self.hostname)
            .field("suite_policy", &self.suite_policy)
            .finish()
    }
}

impl<'a> ClientParams<'a, DefaultVerify, NoClientAuth> {
    /// Pin-based trust. Verification at `connect()`:
    /// 1. `CertificateVerify` signature
    /// 2. Cert pubkey matches `pin`
    /// 3. SAN `dNSName` / `iPAddress` matches `hostname`
    /// 4. Cert validity window (when built with a `Clocked` strategy)
    /// 5. Server Finished MAC
    ///
    /// `hostname` is also used as the SNI value in ClientHello.
    ///
    /// Returns `Err(ModulusTooLong)` for an `Rsa` pin whose modulus
    /// exceeds `MAX_RSA_MODULUS_BYTES` (the supported RSA-1024 /
    /// RSA-2048 sizes always fit). Under `not(feature = "rsa")` the
    /// error enum is uninhabited.
    pub fn pinned(
        hostname: &'a str,
        pin: PinnedPubkey<'a>,
    ) -> Result<Self, PinnedPubkeyOwnedError> {
        let owned = pin.to_owned_pin()?;
        Ok(Self {
            hostname,
            verify: SafeStrategy::new(PinOrSelfSigned::pinned(owned)),
            suite_policy: RuntimeSuitePolicy::Default,
            client_auth: NoClientAuth,
            middlebox_compat: false,
            alpn: None,
        })
    }

    /// Self-signed trust for controlled-peer deployments. Verification at
    /// `connect()`:
    /// 1. `CertificateVerify` signature
    /// 2. Outer cert's self-signature (cert signed by its own key)
    /// 3. SAN match
    /// 4. Cert validity window (when built with a `Clocked` strategy)
    /// 5. Server Finished MAC
    ///
    /// Use only when the peer's certificate is under your control or
    /// inspected out-of-band; not safe against public-internet MITM.
    pub fn self_signed(hostname: &'a str) -> Self {
        Self {
            hostname,
            verify: SafeStrategy::new(PinOrSelfSigned::self_signed()),
            suite_policy: RuntimeSuitePolicy::Default,
            client_auth: NoClientAuth,
            middlebox_compat: false,
            alpn: None,
        }
    }
}

impl<'a, A> ClientParams<'a, DefaultVerify, A> {
    /// Enable the cert validity-window (`notBefore` / `notAfter`) check by
    /// attaching a clock. Swaps the default [`NoClock`](crate::client::NoClock)
    /// strategy for a [`Clocked`] one, so the returned params carry a new
    /// verify type — spell it via [`ClockedVerify`] if you need to name the
    /// resulting stream. The client-auth policy is preserved. Without this,
    /// validity is skipped.
    #[cfg(feature = "cert-der")]
    pub fn clocked<T: TimeSource>(
        self,
        clock: T,
    ) -> ClientParams<'a, SafeStrategy<PinOrSelfSigned, DerCert, Clocked<T>>, A> {
        ClientParams {
            hostname: self.hostname,
            verify: SafeStrategy::with_clock(self.verify.decision, Clocked(clock)),
            suite_policy: self.suite_policy,
            middlebox_compat: self.middlebox_compat,
            alpn: self.alpn,
            client_auth: self.client_auth,
        }
    }
}

/// The verify strategy [`ClientParams::clocked`] produces — the bundled
/// pin/self-signed decision plus a real clock for the validity check.
#[cfg(feature = "cert-der")]
pub type ClockedVerify<T> = SafeStrategy<PinOrSelfSigned, DerCert, Clocked<T>>;

impl<'a, V> ClientParams<'a, V, NoClientAuth> {
    /// Construct with a caller-supplied verify strategy. Use this when
    /// the bundled [`DefaultVerify`] (pin / self-signed) doesn't fit —
    /// e.g. a WebPKI-style trust store or any third-party
    /// [`VerifyStrategy`](crate::traits::verify_strategy::VerifyStrategy) impl.
    pub fn with_strategy(hostname: &'a str, verify: V) -> Self {
        Self {
            hostname,
            verify,
            suite_policy: RuntimeSuitePolicy::Default,
            client_auth: NoClientAuth,
            middlebox_compat: false,
            alpn: None,
        }
    }
}

impl<'a, V, A> ClientParams<'a, V, A> {
    /// Narrow the runtime suite advertisement. See
    /// [`RuntimeSuitePolicy`].
    pub fn suite_policy(mut self, p: RuntimeSuitePolicy) -> Self {
        self.suite_policy = p;
        self
    }

    /// Switch on mutual TLS: when the server sends a `CertificateRequest`,
    /// answer with a client `Certificate` + `CertificateVerify` signed by
    /// `auth` (the private key stays inside the caller's [`ClientAuth`] impl).
    /// Changes the params' policy type to
    /// [`WithClientAuth`](crate::client::WithClientAuth) — name it via the
    /// stream's `A` parameter if you need to spell the resulting type.
    ///
    /// Only Ed25519 client certificates are supported today. krabitls inspects
    /// the server's `CertificateRequest.signature_algorithms` and declines the
    /// request (no `Certificate`/`CertificateVerify`) when the signer's
    /// [`scheme`](ClientAuth::scheme) isn't among those advertised, rather than
    /// sending a flight the server rejects with an opaque `handshake_failure`.
    ///
    /// The signer's lifetime is independent of the hostname's, so a
    /// shorter-lived signer is fine.
    pub fn with_client_auth<'b, T: ClientAuth + ?Sized>(
        self,
        auth: &'b T,
    ) -> ClientParams<'a, V, WithClientAuth<'b, T>> {
        ClientParams {
            hostname: self.hostname,
            verify: self.verify,
            suite_policy: self.suite_policy,
            middlebox_compat: self.middlebox_compat,
            alpn: self.alpn,
            client_auth: WithClientAuth(auth),
        }
    }

    /// Decline client authentication *politely*: when the server sends a
    /// `CertificateRequest`, answer with an empty `Certificate` so an
    /// optional-mTLS server proceeds. (The default [`NoClientAuth`] instead
    /// aborts the handshake — choose this only when you specifically need to
    /// interop with optional-mutual-auth servers.)
    pub fn decline_client_auth(self) -> ClientParams<'a, V, DeclineClientAuth> {
        ClientParams {
            hostname: self.hostname,
            verify: self.verify,
            suite_policy: self.suite_policy,
            middlebox_compat: self.middlebox_compat,
            alpn: self.alpn,
            client_auth: DeclineClientAuth,
        }
    }

    /// Send a random 32-byte `legacy_session_id` for TLS 1.3 middlebox-
    /// compatibility mode (RFC 8446 §D.4). Enable for endpoints behind
    /// TLS-terminating load balancers or CDNs; off by default. This only sets
    /// the id; the dummy ChangeCipherSpec of full compat mode is not sent.
    pub fn middlebox_compat(mut self, on: bool) -> Self {
        self.middlebox_compat = on;
        self
    }

    /// Advertise ALPN protocol names (RFC 7301), in preference order. Each
    /// name is 1..=255 bytes. Off by default; required by endpoints that
    /// gate on ALPN (e.g. `b"h2"`).
    pub fn alpn(mut self, protocols: &'a [&'a [u8]]) -> Self {
        self.alpn = Some(protocols);
        self
    }

    /// Hostname (SNI + cert-identity check).
    pub fn hostname(&self) -> &'a str {
        self.hostname
    }
}
