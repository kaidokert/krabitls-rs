//! Test-only alternate bigint carriers — not a production capability.
//!
//! `cargo test --features carrier-crypto-bigint` (or `carrier-bnum`) recompiles
//! the library's unit tests with [`crate::bigint`] re-pointed at the fork,
//! running the bigint-critical paths — verify, sign, mTLS, X25519 — on the
//! swapped carrier so a backend regression is caught in CI. The forks are git
//! dev-deps and this is `cfg(test)`-gated, so no shippable or published build
//! sees them; fixed-bigint stays the only carrier krabitls ships.
//!
//! Scope: `cfg(test)` reaches only the in-crate unit tests. Integration tests
//! under `tests/` compile krabitls as an ordinary dependency, so they keep the
//! shipped carrier — a dev-dep can't reach that build.
//!
//! Nct roles use the plain `U…`; Ct roles the `Ct<U…>` wrapper.

#[cfg(all(feature = "carrier-bnum", feature = "carrier-crypto-bigint"))]
compile_error!("carrier-bnum and carrier-crypto-bigint are mutually exclusive; enable one");

// crypto-bigint carries every width krabitls needs. `not(carrier-bnum)` so the
// mutual-exclusion violation surfaces as the compile_error above, not a
// duplicate-`carrier` error.
#[cfg(all(feature = "carrier-crypto-bigint", not(feature = "carrier-bnum")))]
mod carrier {
    use crypto_bigint_patched as cb;

    pub(crate) type Curve25519VerifyBn = cb::U512;
    pub(crate) type Curve25519CtBn = cb::Ct<cb::U512>;

    #[cfg(feature = "rsa-1024")]
    pub(crate) type RsaU1024 = cb::U1024;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = cb::U2048;
    #[cfg(feature = "rsa-3072")]
    pub(crate) type RsaU3072 = cb::U3072;
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaU4096 = cb::U4096;
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaSignBn = cb::Ct<cb::U4096>;
    #[cfg(all(feature = "rsa-3072", not(feature = "rsa-4096")))]
    pub(crate) type RsaSignBn = cb::Ct<cb::U3072>;
    #[cfg(all(feature = "rsa", not(any(feature = "rsa-3072", feature = "rsa-4096"))))]
    pub(crate) type RsaSignBn = cb::Ct<cb::U2048>;

    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256Bn = cb::U256;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384Bn = cb::U384;
}

// bnum ships only power-of-two widths, so P-384 and RSA-3072 (no bnum type) are
// steered to crypto-bigint; carrier-bnum covers curve + Ed25519 + RSA {1024,
// 2048, 4096}.
#[cfg(all(feature = "carrier-bnum", any(feature = "ecdsa", feature = "rsa-3072")))]
compile_error!(
    "carrier-bnum has no bnum width for P-384 / RSA-3072; use carrier-crypto-bigint for those"
);

#[cfg(feature = "carrier-bnum")]
mod carrier {
    use bnum_patched::Ct;
    use bnum_patched::types as bt;

    pub(crate) type Curve25519VerifyBn = bt::U512;
    pub(crate) type Curve25519CtBn = Ct<bt::U512>;

    #[cfg(feature = "rsa-1024")]
    pub(crate) type RsaU1024 = bt::U1024;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = bt::U2048;
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaU4096 = bt::U4096;
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaSignBn = Ct<bt::U4096>;
    #[cfg(all(feature = "rsa", not(feature = "rsa-4096")))]
    pub(crate) type RsaSignBn = Ct<bt::U2048>;
}

pub(crate) use carrier::*;
