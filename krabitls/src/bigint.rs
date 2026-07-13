//! Central bigint-backend selection. EXPERIMENT (branch
//! `experiment/bigint-heapless-runtime-len`): the carriers are fixed-bigint
//! 0.6's runtime-length `HeaplessBigInt<u32, CAP, P>` instead of the
//! compile-time `FixedUInt<u32, N>`. `CAP` is the max limb count (== the old
//! `N`); `len` tracks the used limbs at runtime. `const_num_traits::{Nct, Ct}`
//! select the personality exactly as before. A backend-swap probe — never for
//! merge.

use fixed_bigint::HeaplessBigInt;

/// 512-bit vartime carrier for Ed25519 *verification*.
pub(crate) type Curve25519VerifyBn = HeaplessBigInt<u32, 16>;

/// 512-bit constant-time carrier for X25519 + Ed25519 *signing* — secret scalar.
pub(crate) type Curve25519CtBn = HeaplessBigInt<u32, 16, const_num_traits::Ct>;

/// 1024-bit RSA-1024 *verification* carrier.
#[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
pub(crate) type RsaU1024 = HeaplessBigInt<u32, 32>;

/// 2048-bit RSA-2048 *verification* carrier — the modexp exponent is public.
#[cfg(feature = "rsa")]
pub(crate) type RsaU2048 = HeaplessBigInt<u32, 64>;

/// 2048-bit constant-time carrier for RSA-2048 *signing* — the exponent is the
/// private `d`.
#[cfg(feature = "rsa")]
pub(crate) type RsaSignBn = HeaplessBigInt<u32, 64, const_num_traits::Ct>;

/// 256-bit vartime carrier for ECDSA P-256 *verification*.
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP256Bn = HeaplessBigInt<u32, 8>;

/// 384-bit vartime carrier for ECDSA P-384 *verification*.
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP384Bn = HeaplessBigInt<u32, 12>;
