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
//! Fixed is the *absence* of `bigint-heapless`, so `--no-default-features`
//! still selects a carrier — no explicit `bigint-fixed` feature to keep in sync.

/// Config A — per-role compile-time `FixedUInt` widths (the default).
#[cfg(all(
    not(feature = "bigint-heapless"),
    not(all(test, any(feature = "carrier-bnum", feature = "carrier-crypto-bigint")))
))]
mod carrier {
    use fixed_bigint::FixedUInt;

    /// 512-bit vartime carrier for Ed25519 *verification*.
    pub(crate) type Curve25519VerifyBn = FixedUInt<u32, 16>;
    /// 512-bit constant-time carrier for X25519 + Ed25519 *signing* (secret scalar).
    pub(crate) type Curve25519CtBn = FixedUInt<u32, 16, const_num_traits::Ct>;

    /// 1024-bit RSA *verification* carrier.
    #[cfg(feature = "rsa-1024")]
    pub(crate) type RsaU1024 = FixedUInt<u32, 32>;
    /// 2048-bit RSA *verification* carrier.
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = FixedUInt<u32, 64>;
    /// 3072-bit RSA *verification* carrier.
    #[cfg(feature = "rsa-3072")]
    pub(crate) type RsaU3072 = FixedUInt<u32, 96>;
    /// 4096-bit RSA *verification* carrier.
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaU4096 = FixedUInt<u32, 128>;
    /// Constant-time carrier for RSA *signing* (private `d`). One carrier sized
    /// to the widest enabled width; narrower keys sign sub-capacity, so the sign
    /// path stays a single monomorphization across all widths.
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaSignBn = FixedUInt<u32, 128, const_num_traits::Ct>;
    #[cfg(all(feature = "rsa-3072", not(feature = "rsa-4096")))]
    pub(crate) type RsaSignBn = FixedUInt<u32, 96, const_num_traits::Ct>;
    #[cfg(all(feature = "rsa", not(any(feature = "rsa-3072", feature = "rsa-4096"))))]
    pub(crate) type RsaSignBn = FixedUInt<u32, 64, const_num_traits::Ct>;

    /// 256-bit vartime carrier for ECDSA P-256 *verification*.
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256Bn = FixedUInt<u32, 8>;
    /// 384-bit vartime carrier for ECDSA P-384 *verification*.
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384Bn = FixedUInt<u32, 12>;
    /// 256-/384-bit constant-time carriers for ECDSA *signing* (secret scalar +
    /// RFC 6979 nonce), matching the widths krabiecdsa's Ct sign path expects.
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256CtBn = FixedUInt<u32, 8, const_num_traits::Ct>;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384CtBn = FixedUInt<u32, 12, const_num_traits::Ct>;
}

/// Config B — one runtime-length `HeaplessBigInt`, separate Nct + Ct.
#[cfg(all(
    feature = "bigint-heapless",
    not(all(test, any(feature = "carrier-bnum", feature = "carrier-crypto-bigint")))
))]
mod carrier {
    use fixed_bigint::HeaplessBigInt;

    /// Unified vartime carrier — every Nct role. CAP follows the widest enabled
    /// RSA width so a 3072/4096-bit modulus still fits.
    #[cfg(feature = "rsa-4096")]
    type UnifiedBn = HeaplessBigInt<u32, 128>;
    #[cfg(all(feature = "rsa-3072", not(feature = "rsa-4096")))]
    type UnifiedBn = HeaplessBigInt<u32, 96>;
    #[cfg(not(any(feature = "rsa-3072", feature = "rsa-4096")))]
    type UnifiedBn = HeaplessBigInt<u32, 64>;
    /// Unified constant-time carrier — every Ct role. CAP follows the widest
    /// enabled RSA width (mirrors `UnifiedBn`) so RSA signing at 3072/4096 fits.
    #[cfg(feature = "rsa-4096")]
    type UnifiedCtBn = HeaplessBigInt<u32, 128, const_num_traits::Ct>;
    #[cfg(all(feature = "rsa-3072", not(feature = "rsa-4096")))]
    type UnifiedCtBn = HeaplessBigInt<u32, 96, const_num_traits::Ct>;
    #[cfg(not(any(feature = "rsa-3072", feature = "rsa-4096")))]
    type UnifiedCtBn = HeaplessBigInt<u32, 64, const_num_traits::Ct>;

    pub(crate) type Curve25519VerifyBn = UnifiedBn;
    pub(crate) type Curve25519CtBn = UnifiedCtBn;

    #[cfg(feature = "rsa-1024")]
    pub(crate) type RsaU1024 = UnifiedBn;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaU2048 = UnifiedBn;
    #[cfg(feature = "rsa-3072")]
    pub(crate) type RsaU3072 = UnifiedBn;
    #[cfg(feature = "rsa-4096")]
    pub(crate) type RsaU4096 = UnifiedBn;
    #[cfg(feature = "rsa")]
    pub(crate) type RsaSignBn = UnifiedCtBn;

    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256Bn = UnifiedBn;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384Bn = UnifiedBn;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP256CtBn = UnifiedCtBn;
    #[cfg(feature = "ecdsa")]
    pub(crate) type EcdsaP384CtBn = UnifiedCtBn;
}

// Test-only alternate carriers for the carrier-swap proof (see the submodule);
// the two above are the only ones krabitls ships.
#[cfg(all(test, any(feature = "carrier-bnum", feature = "carrier-crypto-bigint")))]
mod test_carriers;

#[cfg(not(all(test, any(feature = "carrier-bnum", feature = "carrier-crypto-bigint"))))]
pub(crate) use carrier::*;
#[cfg(all(test, any(feature = "carrier-bnum", feature = "carrier-crypto-bigint")))]
pub(crate) use test_carriers::*;
