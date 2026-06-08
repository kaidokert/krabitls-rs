//! RSA verify glue (PKCS#1 v1.5 + RSA-PSS, SHA-256). Feature-gated, no_alloc.
//!
//! Wires `rsa_heapless` 0.2 (verify-only on the heapless path) into krabitls.
//! Two entry points:
//!
//! * [`verify_pkcs1v15_sha256`] — for the self-signed RSA cert's outer
//!   signature (`sha256WithRSAEncryption`, RFC 5754).
//! * [`verify_pss_sha256`] — for the `CertificateVerify` body's
//!   `rsa_pss_rsae_sha256` signature (TLS 1.3 §4.4.3, RFC 8017 §8.1).
//!
//! Both functions dispatch on modulus length: 128 B → RSA-1024,
//! 256 B → RSA-2048. The bigint backend is `fixed_bigint::FixedUInt<u32, N>`
//! to match the family we use for X25519 / Ed25519.
//!
//! No alloc anywhere. The no_alloc path in rsa_heapless type-aliases
//! `ModMathValue<T>` to `T`, so the verifying key's bigint type is just the
//! raw `FixedUInt`. We use `PrehashVerifier::verify_prehash` (the hazmat
//! entry point) and feed in a pre-computed SHA-256 hash so the digest type
//! sits behind the trait bound without needing a `Digest::digest(...)` call
//! that would link more of the digest 0.11 machinery.
//!
//! sha2 0.11 is pulled in here because rsa_heapless 0.2 builds on the
//! digest 0.11 trait line, one major ahead of the sha2 0.10 we use for
//! HKDF + transcript hashing. Two sha2 versions sit side-by-side in an
//! rsa-enabled build; that's the cost of opting into RSA and is gated
//! behind `feature = "rsa"`.

use fixed_bigint::FixedUInt;
use rsa::modmath_support::{ModMathParams, ModMathValue, public_key_from_be_bytes};
use rsa::pkcs1v15::{GenericSignature as Pkcs1Sig, GenericVerifyingKey as Pkcs1Vk};
use rsa::pss::{GenericSignature as PssSig, GenericVerifyingKey as PssVk};
use rsa::signature::hazmat::PrehashVerifier;
use sha2_v11::{Digest, Sha256};

/// Verification failure (kept opaque on purpose — surfaces as
/// `FlightError::CertSelfSignatureInvalid` or `CertVerifyInvalid` upstream).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RsaVerifyError;

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
/// that's the ~400-800k cycles the per-call entry points were eating
/// every time). Both verify methods on the cached struct reuse that
/// precompute; second-and-onward verifies are O(verify-only cost).
///
/// Use this when you're going to verify ≥2 signatures against the same
/// RSA key — e.g. the cert's own self-signature (PKCS#1) and the TLS
/// `CertificateVerify` (PSS). [`crate::verify_server_flight`] threads
/// one of these through `verify_self_signed_cert_with_cache` +
/// `verify_certificate_verify_with_cache` automatically.
///
/// For single-shot callers, the free functions
/// ([`verify_pkcs1v15_sha256`] / [`verify_pss_sha256`]) still work and
/// are simpler — they just construct + verify in one go.
// no_alloc: keep the large variant inline rather than boxing it.
#[allow(clippy::large_enum_variant)]
pub enum RsaVerifierKey {
    /// 1024-bit RSA key. Compiled out under `feature = "rsa_2048_only"`.
    #[cfg(not(feature = "rsa_2048_only"))]
    U1024(VkPair<U1024>),
    /// 2048-bit RSA key.
    U2048(VkPair<U2048>),
}

/// Pre-built PKCS#1-v1.5 + PSS verifying keys at a single modulus size.
/// Built once via `RsaVerifierKey::new`; one of the two is selected
/// per verify call depending on the signature scheme.
pub struct VkPair<T>
where
    T: rsa::modmath_support::ModMathInt,
{
    pkcs1: Pkcs1Vk<Sha256, ModMathValue<T>, ModMathParams<T>>,
    pss: PssVk<Sha256, ModMathValue<T>, ModMathParams<T>>,
}

impl RsaVerifierKey {
    /// Build cached verifying keys for one RSA public key.
    pub fn new(modulus: &[u8], exponent: u32) -> Result<Self, RsaVerifyError> {
        match modulus.len() {
            #[cfg(not(feature = "rsa_2048_only"))]
            128 => Ok(RsaVerifierKey::U1024(build_vk_pair::<U1024>(
                modulus, exponent,
            )?)),
            256 => Ok(RsaVerifierKey::U2048(build_vk_pair::<U2048>(
                modulus, exponent,
            )?)),
            _ => Err(RsaVerifyError),
        }
    }

    /// Verify a PKCS#1-v1.5-SHA-256 signature against this cached key.
    pub fn verify_pkcs1v15_sha256(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaVerifyError> {
        let prehash = Sha256::digest(message);
        match self {
            #[cfg(not(feature = "rsa_2048_only"))]
            RsaVerifierKey::U1024(vks) => {
                if signature.len() != 128 {
                    return Err(RsaVerifyError);
                }
                let sig = Pkcs1Sig::from(U1024::from_be_bytes(signature));
                vks.pkcs1
                    .verify_prehash(&prehash, &sig)
                    .map_err(|_| RsaVerifyError)
            }
            RsaVerifierKey::U2048(vks) => {
                if signature.len() != 256 {
                    return Err(RsaVerifyError);
                }
                let sig = Pkcs1Sig::from(U2048::from_be_bytes(signature));
                vks.pkcs1
                    .verify_prehash(&prehash, &sig)
                    .map_err(|_| RsaVerifyError)
            }
        }
    }

    /// Verify an RSA-PSS-SHA-256 signature against this cached key.
    /// salt_len = hash output (32 bytes) matches `rsa_pss_rsae_sha256`.
    pub fn verify_pss_sha256(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaVerifyError> {
        let prehash = Sha256::digest(message);
        match self {
            #[cfg(not(feature = "rsa_2048_only"))]
            RsaVerifierKey::U1024(vks) => {
                if signature.len() != 128 {
                    return Err(RsaVerifyError);
                }
                let sig = PssSig::from(U1024::from_be_bytes(signature));
                vks.pss
                    .verify_prehash(&prehash, &sig)
                    .map_err(|_| RsaVerifyError)
            }
            RsaVerifierKey::U2048(vks) => {
                if signature.len() != 256 {
                    return Err(RsaVerifyError);
                }
                let sig = PssSig::from(U2048::from_be_bytes(signature));
                vks.pss
                    .verify_prehash(&prehash, &sig)
                    .map_err(|_| RsaVerifyError)
            }
        }
    }
}

fn build_vk_pair<T>(modulus: &[u8], exponent: u32) -> Result<VkPair<T>, RsaVerifyError>
where
    T: rsa::modmath_support::ModMathInt,
{
    let key = public_key_from_be_bytes::<T>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    // Clone reuses RSA precomputation instead of rebuilding it.
    let pkcs1 = Pkcs1Vk::<Sha256, _, _>::new(key.clone());
    let pss = PssVk::<Sha256, _, _>::new(key);
    Ok(VkPair { pkcs1, pss })
}

/// Verify an RSASSA-PKCS#1-v1.5 SHA-256 signature.
pub fn verify_pkcs1v15_sha256(
    modulus: &[u8],
    exponent: u32,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    // `FixedUInt::from_be_bytes` requires an exact-length slice.
    if signature.len() != modulus.len() {
        return Err(RsaVerifyError);
    }
    let prehash = Sha256::digest(message);
    match modulus.len() {
        #[cfg(not(feature = "rsa_2048_only"))]
        128 => verify_pkcs1v15_1024(modulus, exponent, &prehash, signature),
        256 => verify_pkcs1v15_2048(modulus, exponent, &prehash, signature),
        _ => Err(RsaVerifyError),
    }
}

/// Verify an RSASSA-PSS-MGF1 SHA-256 signature with salt_len = hash output
/// (32 bytes). This matches `rsa_pss_rsae_sha256` in TLS 1.3.
pub fn verify_pss_sha256(
    modulus: &[u8],
    exponent: u32,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    // `FixedUInt::from_be_bytes` requires an exact-length slice.
    if signature.len() != modulus.len() {
        return Err(RsaVerifyError);
    }
    let prehash = Sha256::digest(message);
    match modulus.len() {
        #[cfg(not(feature = "rsa_2048_only"))]
        128 => verify_pss_1024(modulus, exponent, &prehash, signature),
        256 => verify_pss_2048(modulus, exponent, &prehash, signature),
        _ => Err(RsaVerifyError),
    }
}

#[cfg(not(feature = "rsa_2048_only"))]
fn verify_pkcs1v15_1024(
    modulus: &[u8],
    exponent: u32,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let key = public_key_from_be_bytes::<U1024>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    let vk = Pkcs1Vk::<Sha256, _, _>::new(key);
    let sig = Pkcs1Sig::from(U1024::from_be_bytes(signature));
    vk.verify_prehash(prehash, &sig).map_err(|_| RsaVerifyError)
}

fn verify_pkcs1v15_2048(
    modulus: &[u8],
    exponent: u32,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let key = public_key_from_be_bytes::<U2048>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    let vk = Pkcs1Vk::<Sha256, _, _>::new(key);
    let sig = Pkcs1Sig::from(U2048::from_be_bytes(signature));
    vk.verify_prehash(prehash, &sig).map_err(|_| RsaVerifyError)
}

#[cfg(not(feature = "rsa_2048_only"))]
fn verify_pss_1024(
    modulus: &[u8],
    exponent: u32,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let key = public_key_from_be_bytes::<U1024>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    // salt_len = hash output (32 bytes) matches rsa_pss_rsae_sha256 per TLS 1.3.
    let vk = PssVk::<Sha256, _, _>::new(key);
    let sig = PssSig::from(U1024::from_be_bytes(signature));
    vk.verify_prehash(prehash, &sig).map_err(|_| RsaVerifyError)
}

fn verify_pss_2048(
    modulus: &[u8],
    exponent: u32,
    prehash: &[u8],
    signature: &[u8],
) -> Result<(), RsaVerifyError> {
    let key = public_key_from_be_bytes::<U2048>(modulus, exponent).map_err(|_| RsaVerifyError)?;
    let vk = PssVk::<Sha256, _, _>::new(key);
    let sig = PssSig::from(U2048::from_be_bytes(signature));
    vk.verify_prehash(prehash, &sig).map_err(|_| RsaVerifyError)
}
