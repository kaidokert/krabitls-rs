//! RSA verify glue (PKCS#1 v1.5 + RSA-PSS, SHA-256). Feature-gated, no_alloc.
//!
//! Wires `rsa_heapless` 0.3 (verify-only on the heapless path) into krabitls.
//! Entry point: [`RsaVerifierKey`] — built once via `new(modulus, exponent)`,
//! verifies both schemes via inherent methods or the
//! [`signature::Verifier<RsaPssSig>`] / [`signature::Verifier<RsaPkcs1Sig>`]
//! impls.
//!
//! Used by:
//! * `sha256WithRSAEncryption` (PKCS#1-v1.5) — self-signed RSA cert outer sigs (RFC 5754)
//! * `rsassa-pss` (PSS-SHA-256) — `CertificateVerify` (`rsa_pss_rsae_sha256`,
//!   TLS 1.3 §4.4.3, RFC 8017 §8.1) and PSS-signed cert outer sigs
//!
//! Dispatch on modulus length: 128 B → RSA-1024, 256 B → RSA-2048. Bigint
//! backend: `fixed_bigint::FixedUInt<u32, N>`.
//!
//! No alloc anywhere. The no_alloc path in rsa_heapless type-aliases
//! `ModMathValue<T>` to `T`, so the verifying key's bigint type is just the
//! raw `FixedUInt`. We use `PrehashVerifier::verify_prehash` (the hazmat
//! entry point) and feed in a pre-computed SHA-256 hash so the digest type
//! sits behind the trait bound without needing a `Digest::digest(...)` call
//! that would link more of the digest 0.11 machinery.
//!
//! sha2 0.11 is pulled in here because rsa_heapless 0.3 builds on the
//! digest 0.11 trait line, one major ahead of the sha2 0.10 we use for
//! HKDF + transcript hashing. Two sha2 versions sit side-by-side in an
//! rsa-enabled build; that's the cost of opting into RSA and is gated
//! behind `feature = "rsa"`.

use const_num_traits::{HasPersonality, Nct};
use fixed_bigint::FixedUInt;
use rsa::modmath_support::{ModMathParams, ModMathValue, public_key_from_be_bytes};
#[cfg(not(feature = "rsa_pss_only"))]
use rsa::pkcs1v15::{GenericSignature as Pkcs1Sig, GenericVerifyingKey as Pkcs1Vk};
use rsa::pss::{GenericSignature as PssSig, GenericVerifyingKey as PssVk};
use rsa::signature::hazmat::PrehashVerifier;
use sha2_v11::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Verification failure (kept opaque on purpose — surfaces as
/// `FlightError::CertSelfSignatureInvalid` or `CertVerifyInvalid` upstream).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RsaVerifyError;

/// RSA-PSS signature wrapper for the canonical [`signature::Verifier`]
/// interface. Borrows the raw signature bytes; length must match the
/// modulus (128 B for RSA-1024, 256 B for RSA-2048).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPssSig<'a>(pub &'a [u8]);

/// RSA-PKCS#1-v1.5 signature wrapper for [`signature::Verifier`].
#[cfg(not(feature = "rsa_pss_only"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsaPkcs1Sig<'a>(pub &'a [u8]);

/// 1024-bit RSA modulus carrier — `FixedUInt<u32, 32>` = 32 × 32 bits.
/// Compiled out under `feature = "rsa_2048_only"`.
#[cfg(not(feature = "rsa_2048_only"))]
type U1024 = FixedUInt<u32, 32>;
/// 2048-bit RSA modulus carrier — `FixedUInt<u32, 64>` = 64 × 32 bits.
type U2048 = FixedUInt<u32, 64>;

/// Pre-built PKCS#1-v1.5 + RSA-PSS verifying keys for one RSA pubkey.
///
/// Construction triggers `ModMathParams::new` once (the expensive
/// `compute_r_mod_n` + `compute_r2_mod_n` precompute — for U2048 on M3
/// saving ~400-800k cycles per call). Both verify methods on the cached
/// struct reuse that precompute; second-and-onward verifies are
/// O(verify-only cost).
///
/// Use this when you're going to verify ≥2 signatures against the same
/// RSA key — e.g. the cert's own self-signature (PKCS#1) and the TLS
/// `CertificateVerify` (PSS). The typestate path threads one of these
/// through the server-flight verify automatically; downstream callers can
/// build one via [`Self::new`] and verify either via the inherent
/// `verify_pkcs1v15_sha256` / `verify_pss_sha256` methods or via the
/// `signature::Verifier<RsaPssSig>` / `signature::Verifier<RsaPkcs1Sig>`
/// trait impls.
// no_alloc: keep the large variant inline rather than boxing it.
// Retains modulus + exponent so the SPKI cross-check is a byte-compare
// rather than a re-serialization from the FixedUInt limbs.
#[allow(clippy::large_enum_variant)]
pub enum RsaVerifierKey {
    /// 1024-bit RSA key. Compiled out under `feature = "rsa_2048_only"`.
    #[cfg(not(feature = "rsa_2048_only"))]
    U1024 {
        vk: VkPair<U1024>,
        modulus_be: [u8; 128],
        exponent: u32,
    },
    /// 2048-bit RSA key.
    U2048 {
        vk: VkPair<U2048>,
        modulus_be: [u8; 256],
        exponent: u32,
    },
}

/// Pre-built PKCS#1-v1.5 + PSS verifying keys at a single modulus size.
/// Built once via `RsaVerifierKey::new`; one of the two is selected
/// per verify call depending on the signature scheme.
pub struct VkPair<T>
where
    T: rsa::modmath_support::ModMathInt + HasPersonality<P = Nct>,
{
    #[cfg(not(feature = "rsa_pss_only"))]
    pkcs1: Pkcs1Vk<Sha256, ModMathValue<T>, ModMathParams<T>>,
    pss: PssVk<Sha256, ModMathValue<T>, ModMathParams<T>>,
}

/// Generate a per-scheme verify method. The two schemes (PKCS#1-v1.5, PSS)
/// share an identical U1024/U2048 dispatch and differ only in the cached
/// `VkPair` field and the signature wrapper. Deliberately a `macro_rules!`,
/// not a generic fn: the expansion is token-identical to the hand-written
/// form, so codegen does not shift — this file is the thumbv7m Bug-2 trigger
/// zone and a new monomorphization could re-trip the `-Oz` miscompile.
macro_rules! verify_scheme {
    ($(#[$meta:meta])* $name:ident => $field:ident, $sig:ident) => {
        $(#[$meta])*
        pub fn $name(&self, message: &[u8], signature: &[u8]) -> Result<(), RsaVerifyError> {
            let prehash = Sha256::digest(message);
            match self {
                #[cfg(not(feature = "rsa_2048_only"))]
                RsaVerifierKey::U1024 { vk, .. } => {
                    if signature.len() != 128 {
                        return Err(RsaVerifyError);
                    }
                    let sig = $sig::from(U1024::from_be_bytes(signature));
                    vk.$field
                        .verify_prehash(&prehash, &sig)
                        .map_err(|_| RsaVerifyError)
                }
                RsaVerifierKey::U2048 { vk, .. } => {
                    if signature.len() != 256 {
                        return Err(RsaVerifyError);
                    }
                    let sig = $sig::from(U2048::from_be_bytes(signature));
                    vk.$field
                        .verify_prehash(&prehash, &sig)
                        .map_err(|_| RsaVerifyError)
                }
            }
        }
    };
}

impl RsaVerifierKey {
    /// Build cached verifying keys for one RSA public key.
    pub fn new(modulus: &[u8], exponent: u32) -> Result<Self, RsaVerifyError> {
        match modulus.len() {
            #[cfg(not(feature = "rsa_2048_only"))]
            128 => {
                let mut modulus_be = [0u8; 128];
                modulus_be.copy_from_slice(modulus);
                Ok(RsaVerifierKey::U1024 {
                    vk: build_vk_pair::<U1024>(modulus, exponent)?,
                    modulus_be,
                    exponent,
                })
            }
            256 => {
                let mut modulus_be = [0u8; 256];
                modulus_be.copy_from_slice(modulus);
                Ok(RsaVerifierKey::U2048 {
                    vk: build_vk_pair::<U2048>(modulus, exponent)?,
                    modulus_be,
                    exponent,
                })
            }
            _ => Err(RsaVerifyError),
        }
    }

    verify_scheme!(
        /// Verify a PKCS#1-v1.5-SHA-256 signature against this cached key.
        #[cfg(not(feature = "rsa_pss_only"))]
        verify_pkcs1v15_sha256 => pkcs1, Pkcs1Sig
    );

    verify_scheme!(
        /// Verify an RSA-PSS-SHA-256 signature against this cached key.
        /// salt_len = hash output (32 bytes) matches `rsa_pss_rsae_sha256`.
        verify_pss_sha256 => pss, PssSig
    );
}

impl
    crate::traits::verify_strategy::VerifierKeyMaterial<
        crate::traits::verify_strategy::RsaKeyMaterial<'_>,
    > for RsaVerifierKey
{
    fn matches(
        &self,
        candidate: crate::traits::verify_strategy::RsaKeyMaterial<'_>,
    ) -> subtle::Choice {
        let (mod_bytes, exp) = match self {
            #[cfg(not(feature = "rsa_2048_only"))]
            RsaVerifierKey::U1024 {
                modulus_be,
                exponent,
                ..
            } => (&modulus_be[..], *exponent),
            RsaVerifierKey::U2048 {
                modulus_be,
                exponent,
                ..
            } => (&modulus_be[..], *exponent),
        };
        // Key size is public — length mismatch short-circuits before the
        // CT body compare. CT only matters for equal-length inputs.
        if candidate.modulus.len() != mod_bytes.len() {
            return subtle::Choice::from(0);
        }
        // `&` (not `&&`): bitwise on `Choice`, both halves always run.
        mod_bytes.ct_eq(candidate.modulus) & exp.ct_eq(&candidate.exponent)
    }
}

impl<'a> signature::Verifier<RsaPssSig<'a>> for RsaVerifierKey {
    fn verify(&self, msg: &[u8], sig: &RsaPssSig<'a>) -> Result<(), signature::Error> {
        self.verify_pss_sha256(msg, sig.0)
            .map_err(|_| signature::Error::new())
    }
}

#[cfg(not(feature = "rsa_pss_only"))]
impl<'a> signature::Verifier<RsaPkcs1Sig<'a>> for RsaVerifierKey {
    fn verify(&self, msg: &[u8], sig: &RsaPkcs1Sig<'a>) -> Result<(), signature::Error> {
        self.verify_pkcs1v15_sha256(msg, sig.0)
            .map_err(|_| signature::Error::new())
    }
}

// `#[inline(never)]` is a load-bearing workaround for TWO distinct
// thumbv7m `opt-level=z` rustc miscompiles, both reproducing on stable
// 1.96. Adding an inline barrier here at the krabitls call site shifts
// the codegen LLVM sees through the entire chain down into
// `rsa_heapless::cios_mont_mul`, dodging both at once.
//
// Bug 1 — `rsa_heapless::cios_mont_mul` infinite loop at -Oz. Bisected
// to rust-lang/rust#142531 ("Remove fewer Storage calls in CopyProp
// and GVN"), merged 2026-04-18.
//
// Bug 2 — inlining `build_vk_pair` into `RsaVerifierKey::new` at -Oz
// on thumbv7m produces wrong arithmetic; RSA-PSS verify rejects valid
// signatures at the very end of modexp (3-5M cycles in).
//
// Cost on the M3 RSA binary (default features + rsa + canned-replay):
//   * with `#[inline(never)]` only:        65896 B .text, 3274 kcycles
//   * also forcing rsa_heapless@-O2:       65580 B .text, 2731 kcycles
// 316 bytes / 20% verify perf to keep one workaround instead of two.
#[inline(never)]
fn build_vk_pair<T>(modulus: &[u8], exponent: u32) -> Result<VkPair<T>, RsaVerifyError>
where
    T: rsa::modmath_support::ModMathInt + HasPersonality<P = Nct>,
{
    let key = public_key_from_be_bytes::<T>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    // Clone reuses RSA precomputation instead of rebuilding it.
    #[cfg(not(feature = "rsa_pss_only"))]
    let pkcs1 = Pkcs1Vk::<Sha256, _, _>::new(key.clone());
    let pss = PssVk::<Sha256, _, _>::new(key);
    Ok(VkPair {
        #[cfg(not(feature = "rsa_pss_only"))]
        pkcs1,
        pss,
    })
}
