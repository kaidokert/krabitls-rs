//! Per-connection trust + policy. Constructors couple trust mode to its material.

use crate::identity::PinnedPubkey;

#[cfg(feature = "validity")]
use crate::traits::TimeSource;

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
#[derive(Clone, Copy)]
pub struct ClientParams<'a> {
    pub(crate) hostname: &'a str,
    pub(crate) trust: TrustRoot<'a>,
    #[cfg(feature = "validity")]
    pub(crate) time: Option<&'a dyn TimeSource>,
    pub(crate) suite_policy: RuntimeSuitePolicy,
}

// Manual `Debug` impl: `dyn TimeSource` doesn't carry a `Debug` bound, so
// derive doesn't work. Stub the time field out — `Some`/`None` is the
// only useful signal anyway.
impl<'a> core::fmt::Debug for ClientParams<'a> {
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

impl<'a> ClientParams<'a> {
    /// Pin-based trust. Verification at `connect()`:
    /// 1. `CertificateVerify` signature
    /// 2. Cert pubkey matches `pin`
    /// 3. SAN `dNSName` / `iPAddress` matches `hostname`
    /// 4. Validity dates (if `validity` feature + `.time(_)` set)
    /// 5. Server Finished MAC
    ///
    /// `hostname` is also used as the SNI value in ClientHello.
    pub fn pinned(hostname: &'a str, pin: PinnedPubkey<'a>) -> Self {
        Self {
            hostname,
            trust: TrustRoot::Pinned(pin),
            #[cfg(feature = "validity")]
            time: None,
            suite_policy: RuntimeSuitePolicy::Default,
        }
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
            #[cfg(feature = "validity")]
            time: None,
            suite_policy: RuntimeSuitePolicy::Default,
        }
    }

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
