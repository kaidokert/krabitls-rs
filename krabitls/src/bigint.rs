//! Central bigint carrier selection — one of two build-time configs, chosen by
//! a cargo feature (not a type parameter; the public API stays monomorphic).
//!
//! * **default** (no `bigint-heapless`): per-role compile-time
//!   `FixedUInt<u32, N>` fitted to each algorithm's exact width. One
//!   monomorphization per width — smallest per-algo `.text`, best for
//!   one-or-few algorithms.
//! * **`bigint-heapless`** (opt-in): a single runtime-length
//!   `HeaplessBigInt<u32, CAP>` (2048-bit `CAP`) with separate Nct + Ct
//!   carriers — two monomorphizations total. `len` tracks used limbs, so one
//!   width holds a 256-bit ECDSA scalar, a 512-bit curve value and a 2048-bit
//!   RSA modulus alike. Trades a wider per-value footprint for far less `.text`
//!   on multi-algorithm builds.
//!
//! Both draw from fixed-bigint 0.6; the swap point is this one module. Fixed is
//! the absence of `bigint-heapless`, so `--no-default-features` still has a
//! carrier and the two are never both selected.

/// Config A — per-role compile-time `FixedUInt` widths (the default).
#[cfg(not(feature = "bigint-heapless"))]
mod carrier {
    use fixed_bigint::FixedUInt;

    /// 512-bit vartime carrier for Ed25519 *verification*.
    pub(crate) type Curve25519VerifyBn = FixedUInt<u32, 16>;
    /// 512-bit constant-time carrier for X25519 + Ed25519 *signing* (secret scalar).
    pub(crate) type Curve25519CtBn = FixedUInt<u32, 16, const_num_traits::Ct>;

    /// 1024-bit RSA *verification* carrier.
    #[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
    pub(crate) type RsaU1024 = FixedUInt<u32, 32>;
    /// 2048-bit RSA *verification* carrier.
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = FixedUInt<u32, 64>;
    /// 2048-bit constant-time carrier for RSA *signing* (private `d`).
    #[cfg(feature = "rsa")]
    pub(crate) type RsaSignBn = FixedUInt<u32, 64, const_num_traits::Ct>;

    /// 256-bit vartime carrier for ECDSA P-256 *verification*.
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256Bn = FixedUInt<u32, 8>;
    /// 384-bit vartime carrier for ECDSA P-384 *verification*.
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384Bn = FixedUInt<u32, 12>;
}

/// Config B — one runtime-length `HeaplessBigInt`, separate Nct + Ct.
#[cfg(feature = "bigint-heapless")]
mod carrier {
    use fixed_bigint::HeaplessBigInt;

    /// Unified 2048-bit-capacity vartime carrier — every Nct role.
    type UnifiedBn = HeaplessBigInt<u32, 64>;
    /// Unified 2048-bit-capacity constant-time carrier — every Ct role.
    type UnifiedCtBn = HeaplessBigInt<u32, 64, const_num_traits::Ct>;

    pub(crate) type Curve25519VerifyBn = UnifiedBn;
    pub(crate) type Curve25519CtBn = UnifiedCtBn;

    #[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
    pub(crate) type RsaU1024 = UnifiedBn;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = UnifiedBn;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaSignBn = UnifiedCtBn;

    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256Bn = UnifiedBn;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384Bn = UnifiedBn;
}

pub(crate) use carrier::*;
