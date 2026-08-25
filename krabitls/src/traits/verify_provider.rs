//! Unified per-algorithm signature-verification backend surface.
//!
//! One [`SigVerifierProvider`] per algorithm ([`SigAlgo`]) routes every cert /
//! CertificateVerify signature through the same prepare→`Verifier` shape, so
//! the verify stack threads a single [`VerifierBackend`] type param rather than
//! one provider param per algorithm.

use crate::traits::verify_strategy::VerifierKeyMaterial;
use signature::Verifier;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("verifier backend rejected the public key material")]
pub struct VerifyProviderError;

/// An algorithm's borrowed signature / public-key / SPKI-cross-check material,
/// expressed as GATs so one backend can serve every algorithm.
pub trait SigAlgo {
    type Sig<'a>;
    type Pubkey<'a>: Copy;
    type KeyMat<'a>;
}

/// A backend that prepares a per-key verifier for algorithm `A`. The prepared
/// verifier is a standard [`signature::Verifier`] over `A::Sig` and exposes its
/// key material for the SPKI cross-check.
pub trait SigVerifierProvider<A: SigAlgo> {
    type Verifier: for<'a> Verifier<A::Sig<'a>> + for<'a> VerifierKeyMaterial<A::KeyMat<'a>>;
    fn prepare(pubkey: A::Pubkey<'_>) -> Result<Self::Verifier, VerifyProviderError>;
}

pub struct Ed25519;
impl SigAlgo for Ed25519 {
    type Sig<'a> = [u8; 64];
    type Pubkey<'a> = &'a [u8; 32];
    type KeyMat<'a> = [u8; 32];
}

#[cfg(feature = "rsa")]
pub struct Rsa;
#[cfg(feature = "rsa")]
impl SigAlgo for Rsa {
    type Sig<'a> = crate::backends::rsa_verify::RsaSig<'a>;
    type Pubkey<'a> = crate::traits::verify_strategy::RsaKeyMaterial<'a>;
    type KeyMat<'a> = crate::traits::verify_strategy::RsaKeyMaterial<'a>;
}

#[cfg(feature = "ecdsa")]
pub struct EcdsaP256;
#[cfg(feature = "ecdsa")]
impl SigAlgo for EcdsaP256 {
    type Sig<'a> = crate::backends::ecdsa_verify::EcdsaDerSig<'a>;
    type Pubkey<'a> = &'a [u8; 65];
    type KeyMat<'a> = [u8; 65];
}

#[cfg(feature = "ecdsa")]
pub struct EcdsaP384;
#[cfg(feature = "ecdsa")]
impl SigAlgo for EcdsaP384 {
    type Sig<'a> = crate::backends::ecdsa_verify::EcdsaDerSig<'a>;
    type Pubkey<'a> = &'a [u8; 97];
    type KeyMat<'a> = [u8; 97];
}

#[cfg(feature = "mldsa")]
pub struct MlDsa;
#[cfg(feature = "mldsa")]
impl SigAlgo for MlDsa {
    type Sig<'a> = crate::backends::mldsa_verify::MlDsaSig<'a>;
    type Pubkey<'a> = &'a [u8];
    type KeyMat<'a> = crate::traits::verify_strategy::MlDsaKeyMaterial<'a>;
}

// Per-feature gating lives in these empty helper traits so [`VerifierBackend`]'s
// supertrait list stays cfg-free: each is `: SigVerifierProvider<Algo>` when the
// feature is on and empty otherwise, with a blanket impl either way.
#[cfg(feature = "rsa")]
pub trait MaybeRsaBackend: SigVerifierProvider<Rsa> {}
#[cfg(feature = "rsa")]
impl<T: SigVerifierProvider<Rsa>> MaybeRsaBackend for T {}
#[cfg(not(feature = "rsa"))]
pub trait MaybeRsaBackend {}
#[cfg(not(feature = "rsa"))]
impl<T> MaybeRsaBackend for T {}

#[cfg(feature = "ecdsa")]
pub trait MaybeEcdsaBackend:
    SigVerifierProvider<EcdsaP256> + SigVerifierProvider<EcdsaP384>
{
}
#[cfg(feature = "ecdsa")]
impl<T: SigVerifierProvider<EcdsaP256> + SigVerifierProvider<EcdsaP384>> MaybeEcdsaBackend for T {}
#[cfg(not(feature = "ecdsa"))]
pub trait MaybeEcdsaBackend {}
#[cfg(not(feature = "ecdsa"))]
impl<T> MaybeEcdsaBackend for T {}

#[cfg(feature = "mldsa")]
pub trait MaybeMlDsaBackend: SigVerifierProvider<MlDsa> {}
#[cfg(feature = "mldsa")]
impl<T: SigVerifierProvider<MlDsa>> MaybeMlDsaBackend for T {}
#[cfg(not(feature = "mldsa"))]
pub trait MaybeMlDsaBackend {}
#[cfg(not(feature = "mldsa"))]
impl<T> MaybeMlDsaBackend for T {}

/// The single backend type the verify stack threads: one type param that
/// supplies a verifier for every algorithm at once. Ed25519 is mandatory; RSA,
/// ECDSA, and ML-DSA gate in via the `Maybe*` supertraits.
pub trait VerifierBackend:
    SigVerifierProvider<Ed25519> + MaybeRsaBackend + MaybeEcdsaBackend + MaybeMlDsaBackend
{
}
impl<T> VerifierBackend for T where
    T: SigVerifierProvider<Ed25519> + MaybeRsaBackend + MaybeEcdsaBackend + MaybeMlDsaBackend
{
}
