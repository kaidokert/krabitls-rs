//! Central bigint-backend selection. EXPERIMENT (branch
//! `experiment/bigint-heapless-unified-cap64`): every carrier collapses to a
//! SINGLE runtime-length `HeaplessBigInt<u32, 64, P>` capacity (2048 bits).
//! Because the carrier is runtime-*length* (`len` tracks used limbs, `CAP` is
//! only the max), a 256-bit ECDSA scalar, a 512-bit curve value, and a 2048-bit
//! RSA modulus all live in the same `CAP=64` type at different `len`. The bet:
//! one monomorphization instead of five (CAP 8/12/16/32/64) shrinks `.text` at
//! the cost of every value carrying a 256-byte footprint. Correctness rides
//! entirely on the value-width arithmetic being CAP-independent — never for merge.

use fixed_bigint::HeaplessBigInt;

/// Unified 2048-bit-capacity vartime carrier — one type for every Nct role.
pub(crate) type UnifiedBn = HeaplessBigInt<u32, 64>;

/// Unified 2048-bit-capacity constant-time carrier — one type for every Ct role.
pub(crate) type UnifiedCtBn = HeaplessBigInt<u32, 64, const_num_traits::Ct>;

/// Ed25519 *verification* carrier (held at `len` 8 in CAP 64).
pub(crate) type Curve25519VerifyBn = UnifiedBn;

/// Constant-time carrier for X25519 + Ed25519 *signing* — secret scalar.
pub(crate) type Curve25519CtBn = UnifiedCtBn;

/// RSA-1024 *verification* carrier.
#[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
pub(crate) type RsaU1024 = UnifiedBn;

/// RSA-2048 *verification* carrier — the modexp exponent is public.
#[cfg(feature = "rsa")]
pub(crate) type RsaU2048 = UnifiedBn;

/// Constant-time carrier for RSA-2048 *signing* — the exponent is the private `d`.
#[cfg(feature = "rsa")]
pub(crate) type RsaSignBn = UnifiedCtBn;

/// ECDSA P-256 *verification* carrier (held at `len` 8 in CAP 64).
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP256Bn = UnifiedBn;

/// ECDSA P-384 *verification* carrier (held at `len` 12 in CAP 64).
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP384Bn = UnifiedBn;
