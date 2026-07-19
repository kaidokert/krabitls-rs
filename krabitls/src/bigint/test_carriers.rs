//! Test-only alternate bigint carriers — **not a production capability.**
//!
//! Recompiles the entire stack on bnum or crypto-bigint (from the git dev-dep
//! forks) so `cargo test --features carrier-crypto-bigint` / `carrier-bnum` runs
//! the full unit suite on a swapped [`crate::bigint`] — a continuously-checked
//! proof that the carrier can be re-pointed at another backend. Everything here
//! is `cfg(test)`-gated and dev-dep-only, so none of it reaches a shippable or
//! published build; the fixed-bigint / heapless carriers in the parent module
//! are the only ones krabitls actually ships.
//!
//! Nct roles use the plain `U…`; Ct roles use the `Ct<U…>` personality wrapper.

// crypto-bigint carries every width krabitls needs.
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
