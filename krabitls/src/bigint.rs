//! Central bigint-backend selection. Every bignum carrier krabitls
//! instantiates is named here, by role — swapping the backend (or a width /
//! personality policy) starts and mostly ends in this file.
//!
//! A replacement backend must satisfy the trait surfaces the aliases feed:
//! `ed25519_heapless`'s verify/sign generics for the curve types, and
//! `rsa_heapless::modmath_support::ModMathInt` (`Nct`) / the CT signing
//! bounds for the RSA types. `const_num_traits::{Nct, Ct}` select between
//! vartime and constant-time arithmetic per alias.

/// 512-bit vartime carrier for Ed25519 *verification* — public data, so the
/// faster non-CT personality.
pub(crate) type Curve25519VerifyBn = fixed_bigint::FixedUInt<u32, 16>;

/// 512-bit constant-time carrier for the X25519 shared-secret computation
/// and Ed25519 *signing* — the scalar is secret, so `ed25519_heapless`'s
/// sign/DH bounds require CT field arithmetic.
pub(crate) type Curve25519CtBn = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;

/// 1024-bit vartime carrier for RSA-1024 *verification*. Compiled out under
/// `feature = "rsa_2048_only"`.
#[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
pub(crate) type RsaU1024 = fixed_bigint::FixedUInt<u32, 32>;

/// 2048-bit vartime carrier for RSA-2048 *verification* — the modexp
/// exponent is the public `e`.
#[cfg(feature = "rsa")]
pub(crate) type RsaU2048 = fixed_bigint::FixedUInt<u32, 64>;

/// 2048-bit constant-time carrier for RSA-2048 *signing* — the modexp
/// exponent is the private `d`.
#[cfg(feature = "rsa")]
pub(crate) type RsaSignBn = fixed_bigint::FixedUInt<u32, 64, const_num_traits::Ct>;

/// 256-bit vartime carrier for ECDSA P-256 *verification* — the signature is
/// public data, so the faster non-CT personality.
#[cfg(feature = "ecdsa")]
#[allow(dead_code)] // consumed by the ECDSA cert/CV dispatch (later slice)
pub(crate) type EcdsaP256Bn = fixed_bigint::FixedUInt<u32, 8>;

/// 384-bit vartime carrier for ECDSA P-384 *verification*.
#[cfg(feature = "ecdsa")]
#[allow(dead_code)]
pub(crate) type EcdsaP384Bn = fixed_bigint::FixedUInt<u32, 12>;
