//! Per-connection trust + policy. Constructors couple trust mode to its material.

use crate::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwnedError};
use crate::identity::PinnedPubkey;
use crate::traits::verify_strategy::SafeStrategy;

#[cfg(feature = "validity")]
use crate::traits::TimeSource;

/// Default `V` for [`ClientParams`] / [`super::DefaultStream`]: pin or
/// self-signed via the bundled `SafeStrategy<PinOrSelfSigned, DerCert>`.
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

/// Trust root. `pub(crate)`; constructors are the only way in.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TrustRoot<'a> {
    Pinned(PinnedPubkey<'a>),
    SelfSigned,
}

/// Per-connection trust + policy bundle. Construct via [`Self::pinned`] / [`Self::self_signed`].
#[derive(Clone)]
pub struct ClientParams<'a, V = DefaultVerify> {
    pub(crate) hostname: &'a str,
    pub(crate) trust: TrustRoot<'a>,
    // `verify` is the new strategy holder; constructed here but not yet
    // read by the verify path (that's the follow-on change). `allow` until
    // the verify path moves over.
    #[allow(dead_code)]
    pub(crate) verify: V,
    #[cfg(feature = "validity")]
    pub(crate) time: Option<&'a dyn TimeSource>,
    pub(crate) suite_policy: RuntimeSuitePolicy,
}

// Manual `Debug` impl: `dyn TimeSource` doesn't carry a `Debug` bound, so
// derive doesn't work. Stub the time field out — `Some`/`None` is the
// only useful signal anyway.
impl<'a, V> core::fmt::Debug for ClientParams<'a, V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("ClientParams");
        d.field("hostname", &self.hostname)
            .field("trust", &self.trust)
            .field("suite_policy", &self.suite_policy);
        #[cfg(feature = "validity")]
        d.field("time", &self.time.map(|_| "<TimeSource>"));
        d.finish()
    }
}

impl<'a> ClientParams<'a, DefaultVerify> {
    /// Pin-based trust. Verification at `connect()`:
    /// 1. `CertificateVerify` signature
    /// 2. Cert pubkey matches `pin`
    /// 3. SAN `dNSName` / `iPAddress` matches `hostname`
    /// 4. Validity dates (if `validity` feature + `.time(_)` set)
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
            trust: TrustRoot::Pinned(pin),
            verify: SafeStrategy::new(PinOrSelfSigned::pinned(owned)),
            #[cfg(feature = "validity")]
            time: None,
            suite_policy: RuntimeSuitePolicy::Default,
        })
    }

    /// Self-signed trust for controlled-peer deployments. Verification at
    /// `connect()`:
    /// 1. `CertificateVerify` signature
    /// 2. Outer cert's self-signature (cert signed by its own key)
    /// 3. SAN match
    /// 4. Validity dates (with `validity` feature + `.time(_)`)
    /// 5. Server Finished MAC
    ///
    /// Use only when the peer's certificate is under your control or
    /// inspected out-of-band; not safe against public-internet MITM.
    pub fn self_signed(hostname: &'a str) -> Self {
        Self {
            hostname,
            trust: TrustRoot::SelfSigned,
            verify: SafeStrategy::new(PinOrSelfSigned::self_signed()),
            #[cfg(feature = "validity")]
            time: None,
            suite_policy: RuntimeSuitePolicy::Default,
        }
    }
}

impl<'a, V> ClientParams<'a, V> {
    /// Attach a [`TimeSource`] to enable certificate validity-window
    /// (`notBefore` / `notAfter`) checks during handshake. Without this,
    /// validity check is skipped.
    #[cfg(feature = "validity")]
    pub fn time(mut self, t: &'a dyn TimeSource) -> Self {
        self.time = Some(t);
        self
    }

    /// Narrow the runtime suite advertisement. See
    /// [`RuntimeSuitePolicy`].
    pub fn suite_policy(mut self, p: RuntimeSuitePolicy) -> Self {
        self.suite_policy = p;
        self
    }

    /// Hostname (SNI + cert-identity check).
    pub fn hostname(&self) -> &'a str {
        self.hostname
    }
}
