//! Central bigint-backend selection. EXPERIMENT (branch `experiment/bigint-bnum`):
//! the carriers are `bnum` (u64-digit const-generic ints) instead of
//! `fixed-bigint`. `bnum::Ct<U>` wraps a carrier and projects
//! `HasPersonality<P = Ct>`, which the constant-time roles require —
//! `rsa_heapless`'s signing (`ModMathParams<_, Ct>`) and `ed25519_heapless`'s
//! `SignBackend` (X25519 secret scalar, Ed25519 signing). The wrapper's limb ops
//! still delegate to bnum's vartime code, so the CT personality is type-level
//! only for now — a footprint experiment, never for merge.
//!
//! Widths match the fixed-bigint originals bit-for-bit; the difference is the
//! digit size (bnum `u64` vs fixed-bigint `u32`), which is the whole point of
//! the measurement on 32-bit Cortex-M.

/// 512-bit carrier for Ed25519 *verification*.
pub(crate) type Curve25519VerifyBn = bnum::types::U512;

/// 512-bit constant-time carrier for X25519 + Ed25519 *signing* — the scalar
/// is secret, so the `Ct` personality (`SignBackend`).
pub(crate) type Curve25519CtBn = bnum::Ct<bnum::types::U512>;

/// 1024-bit RSA-1024 *verification* carrier.
#[cfg(all(feature = "rsa", not(feature = "rsa_2048_only")))]
pub(crate) type RsaU1024 = bnum::types::U1024;

/// 2048-bit RSA-2048 *verification* carrier — the modexp exponent is public.
#[cfg(feature = "rsa")]
pub(crate) type RsaU2048 = bnum::types::U2048;

/// 2048-bit constant-time carrier for RSA-2048 *signing* — the exponent is the
/// private `d`. `Ct<U2048>` projects `HasPersonality<P = Ct>` so
/// `ModMathParams<_, Ct>` resolves.
#[cfg(feature = "rsa")]
pub(crate) type RsaSignBn = bnum::Ct<bnum::types::U2048>;

/// 256-bit vartime carrier for ECDSA P-256 *verification* — the signature is
/// public data, so the faster non-CT personality (krabiecdsa over bnum).
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP256Bn = bnum::types::U256;

/// 384-bit vartime carrier for ECDSA P-384 *verification*.
#[cfg(feature = "ecdsa")]
pub(crate) type EcdsaP384Bn = bnum::types::U384;
