//! Caller-supplied "current time" abstraction for the cert validity check.
//!
//! krabitls is sans-io and has no clock of its own. When a caller wants to
//! enforce a cert's `notBefore` / `notAfter` window (RFC 5280 §4.1.2.5) it
//! provides a [`TimeSource`] — usually backed by `std::time::SystemTime`
//! on hosts, an RTC peripheral on embedded targets, or a hardcoded
//! deployment timestamp on devices that don't have any clock at all.
//!
//! The `TimeSource` trait is always compiled; the
//! [`crate::identity::verify_validity`] check it feeds is gated on
//! `feature = "cert-der"` (it decodes UTCTime / GeneralizedTime through `der`).
//! A stream built with the default `NoClock` strategy never references the
//! check, so it dead-code-eliminates to zero on clock-less builds.

/// Caller-supplied current time, expressed as seconds since the Unix
/// epoch (1970-01-01T00:00:00Z, UTC).
///
/// X.509 cert validity uses UTC, and `u64` covers far past the year-9999
/// `GeneralizedTime` cap (which itself is far past anything any real
/// cert specifies — `notAfter = 9999-12-31T23:59:59Z` is the "never
/// expires" placeholder some PKIs use).
pub trait TimeSource {
    fn now_unix_secs(&self) -> u64;
}

/// [`TimeSource`] impl that always returns the same value. Useful for tests,
/// for embedded deployments that pin to firmware build time, and for the
/// "we know the device was last in contact with NTP at T, treat that as
/// our floor" pattern. Test-only in this crate; sample for downstream.
#[cfg(test)]
pub struct FixedTime(pub u64);

#[cfg(test)]
impl TimeSource for FixedTime {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_time_returns_constant() {
        let t = FixedTime(1_700_000_000);
        assert_eq!(t.now_unix_secs(), 1_700_000_000);
        assert_eq!(t.now_unix_secs(), 1_700_000_000);
    }
}
