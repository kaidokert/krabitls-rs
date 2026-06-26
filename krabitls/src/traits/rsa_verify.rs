//! Pluggable backend for RSA signature verification (PSS + PKCS#1-v1.5).
//!
//! Build a per-key verifier via [`RsaVerifierProvider::prepare_rsa`]; the
//! returned `Verifier` implements [`signature::Verifier`] for both PSS and
//! PKCS#1-v1.5 signatures (wrapped in `RsaPssSig` / `RsaPkcs1Sig`) so the
//! same prepared key handles a cert's outer signature AND the
//! `CertificateVerify` body without rebuilding the modular precompute.
//!
//! Under `feature = "rsa_pss_only"` only the PSS impl is required. Without
//! `feature = "rsa"` at all the trait still exists (empty) so consumers
//! threading it through generic code don't have to cfg-split call sites.

#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
use crate::backends::rsa_verify::RsaPkcs1Sig;
#[cfg(feature = "rsa")]
use crate::backends::rsa_verify::{RsaPssSig, RsaVerifyError};
#[cfg(feature = "rsa")]
use crate::traits::cert::RsaCertSigAlg;

/// Build per-key RSA verifiers. Empty trait without `feature = "rsa"`.
pub trait RsaVerifierProvider {
    /// Per-key prepared form. Implements `signature::Verifier<RsaPssSig<'_>>`
    /// (always) plus `signature::Verifier<RsaPkcs1Sig<'_>>` (unless
    /// `feature = "rsa_pss_only"` is on).
    #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
    type Verifier: for<'a> signature::Verifier<RsaPssSig<'a>>
        + for<'a> signature::Verifier<RsaPkcs1Sig<'a>>
        + for<'a> crate::traits::verify_strategy::VerifierKeyMaterial<
            crate::traits::verify_strategy::RsaKeyMaterial<'a>,
        >;

    /// PSS-only build (rsa_pss_only feature).
    #[cfg(all(feature = "rsa", feature = "rsa_pss_only"))]
    type Verifier: for<'a> signature::Verifier<RsaPssSig<'a>>
        + for<'a> crate::traits::verify_strategy::VerifierKeyMaterial<
            crate::traits::verify_strategy::RsaKeyMaterial<'a>,
        >;

    /// Build a verifier from raw RSA pubkey bytes. Expected to do the
    /// modular precompute (Montgomery params) once.
    #[cfg(feature = "rsa")]
    fn prepare_rsa(modulus: &[u8], exponent: u32) -> Result<Self::Verifier, RsaVerifyError>;
}

/// Verify a cert outer signature: `tbs`, signed as `sig` under `alg`, against
/// the key prepared in `verifier`. Centralizes the PKCS#1-v1.5 / PSS dispatch
/// (and the `rsa_pss_only` gate) shared by the self-signed, chain-link, and
/// pin verify paths. `Ok(())` on a valid signature; the caller maps the error.
#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
pub(crate) fn verify_cert_sig<V>(
    verifier: &V,
    tbs: &[u8],
    sig: &[u8],
    alg: RsaCertSigAlg,
) -> Result<(), signature::Error>
where
    V: for<'a> signature::Verifier<RsaPssSig<'a>> + for<'a> signature::Verifier<RsaPkcs1Sig<'a>>,
{
    match alg {
        RsaCertSigAlg::Pkcs1v15Sha256 => verifier.verify(tbs, &RsaPkcs1Sig(sig)),
        RsaCertSigAlg::PssSha256 => verifier.verify(tbs, &RsaPssSig(sig)),
    }
}

/// PSS-only build: `RsaCertSigAlg` has only the PSS variant.
#[cfg(all(feature = "rsa", feature = "rsa_pss_only"))]
pub(crate) fn verify_cert_sig<V>(
    verifier: &V,
    tbs: &[u8],
    sig: &[u8],
    alg: RsaCertSigAlg,
) -> Result<(), signature::Error>
where
    V: for<'a> signature::Verifier<RsaPssSig<'a>>,
{
    match alg {
        RsaCertSigAlg::PssSha256 => verifier.verify(tbs, &RsaPssSig(sig)),
    }
}
