//! Bundled cert-verification strategy: pin-or-self-signed.
//!
//! `pinned(pin)` accepts a leaf whose SPKI byte-matches `pin`. `self_signed()`
//! accepts a leaf whose outer signature verifies against its own pubkey.
//! Both are single-cert-chain only; rejects anything longer.

#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
use crate::backends::rsa_verify::RsaPkcs1Sig;
#[cfg(feature = "rsa")]
use crate::backends::rsa_verify::RsaPssSig;
use crate::traits::cert::CertView;
#[cfg(feature = "rsa")]
use crate::traits::cert::RsaCertSigAlg;
#[cfg(feature = "validity")]
use crate::traits::time::TimeSource;
use crate::traits::verify_strategy::TrustRootDecision;
use crate::traits::{Ed25519VerifierProvider, RsaVerifierProvider};
use signature::Verifier;
use subtle::ConstantTimeEq;

/// Owned pinned pubkey material. Held by [`PinOrSelfSigned`] so the pin
/// outlives the per-handshake borrows.
// no_alloc: keep the RSA variant inline rather than boxing it (Box isn't
// available in no_std/no_alloc builds).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum PinnedPubkeyOwned {
    Ed25519([u8; 32]),
    #[cfg(feature = "rsa")]
    Rsa {
        modulus: heapless::Vec<u8, { MAX_RSA_MODULUS_BYTES }>,
        exponent: u32,
    },
}

/// Maximum RSA modulus size accepted in [`PinnedPubkeyOwned::Rsa`]
/// (256 = RSA-2048; 128 = RSA-1024 fits too).
#[cfg(feature = "rsa")]
pub const MAX_RSA_MODULUS_BYTES: usize = 256;

impl PinnedPubkeyOwned {
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        PinnedPubkeyOwned::Ed25519(pubkey)
    }

    /// RSA constructor: copies `modulus` into a heapless buffer. Errors
    /// when `modulus.len() > MAX_RSA_MODULUS_BYTES`.
    #[cfg(feature = "rsa")]
    pub fn rsa(modulus: &[u8], exponent: u32) -> Result<Self, PinnedPubkeyOwnedError> {
        let mut v: heapless::Vec<u8, { MAX_RSA_MODULUS_BYTES }> = heapless::Vec::new();
        v.extend_from_slice(modulus)
            .map_err(|_| PinnedPubkeyOwnedError::ModulusTooLong)?;
        Ok(PinnedPubkeyOwned::Rsa {
            modulus: v,
            exponent,
        })
    }
}

/// Errors constructing [`PinnedPubkeyOwned`]. Always-present so the
/// fallible `to_owned_pin` / `ClientParams::pinned` return type is
/// stable across feature sets; under `not(feature = "rsa")` the enum
/// is uninhabited and the `Result` always succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PinnedPubkeyOwnedError {
    #[cfg(feature = "rsa")]
    #[error("RSA modulus exceeds MAX_RSA_MODULUS_BYTES")]
    ModulusTooLong,
}

// Same reason as PinnedPubkeyOwned — Box isn't available no_alloc.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum Mode {
    Pinned(PinnedPubkeyOwned),
    SelfSigned,
}

/// The bundled cert-verification strategy.
///
/// `PinOrSelfSigned::pinned(pin)` for pin-based trust;
/// `PinOrSelfSigned::self_signed()` for self-signed-cert trust.
#[derive(Debug, Clone)]
pub struct PinOrSelfSigned {
    mode: Mode,
}

impl PinOrSelfSigned {
    pub fn pinned(pin: PinnedPubkeyOwned) -> Self {
        Self {
            mode: Mode::Pinned(pin),
        }
    }

    pub fn self_signed() -> Self {
        Self {
            mode: Mode::SelfSigned,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinOrSelfSignedError {
    /// Chain wasn't single-leaf (`PinOrSelfSigned` doesn't walk chains).
    #[error("PinOrSelfSigned expects a single-cert chain")]
    MultiCertChain,
    /// Pinned pubkey didn't match the leaf's SPKI.
    #[error("pinned pubkey did not match leaf SPKI")]
    PinMismatch,
    /// Pinned key type didn't match the leaf cert's key type.
    #[error("pinned key algorithm did not match leaf algorithm")]
    PinAlgorithmMismatch,
    /// Self-signed cert's outer signature didn't verify.
    #[error("self-signed cert signature did not verify")]
    SelfSignatureInvalid,
    /// RSA verifier construction failed (modulus length / exponent invalid).
    #[cfg(feature = "rsa")]
    #[error("RSA verifier construction failed")]
    RsaVerifierInvalid,
    /// `feature = "validity"` is on but no `TimeSource` was supplied.
    #[cfg(feature = "validity")]
    #[error("validity check requested but no TimeSource supplied")]
    MissingClock,
    /// Cert's validity window doesn't include `now`.
    #[cfg(feature = "validity")]
    #[error("cert outside validity window")]
    ValidityFailed,
    /// Cert outer signatureAlgorithm wasn't one we recognize (Ed25519 /
    /// PKCS#1-v1.5 / PSS).
    #[cfg(feature = "rsa")]
    #[error("unrecognized cert outer signatureAlgorithm")]
    UnknownSigAlg,
}

impl<E, R> TrustRootDecision<E, R> for PinOrSelfSigned
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    type Error = PinOrSelfSignedError;

    fn accept_chain<'src>(
        &self,
        chain: &[CertView<'src>],
        #[cfg(feature = "validity")] time: Option<&dyn TimeSource>,
    ) -> Result<(), Self::Error> {
        if chain.len() != 1 {
            return Err(PinOrSelfSignedError::MultiCertChain);
        }
        let leaf = &chain[0];

        match &self.mode {
            Mode::Pinned(pin) => verify_pin(leaf, pin)?,
            Mode::SelfSigned => verify_self_sig::<E, R>(leaf)?,
        }

        #[cfg(feature = "validity")]
        check_validity(leaf, time)?;

        Ok(())
    }
}

fn verify_pin(leaf: &CertView<'_>, pin: &PinnedPubkeyOwned) -> Result<(), PinOrSelfSignedError> {
    match (leaf, pin) {
        (CertView::Ed25519 { pubkey, .. }, PinnedPubkeyOwned::Ed25519(expected)) => {
            if bool::from((**pubkey).ct_eq(expected)) {
                Ok(())
            } else {
                Err(PinOrSelfSignedError::PinMismatch)
            }
        }
        #[cfg(feature = "rsa")]
        (
            CertView::Rsa {
                modulus, exponent, ..
            },
            PinnedPubkeyOwned::Rsa {
                modulus: pm,
                exponent: pe,
            },
        ) => {
            if modulus.len() != pm.len() {
                return Err(PinOrSelfSignedError::PinMismatch);
            }
            if bool::from(modulus.ct_eq(pm.as_slice()) & exponent.ct_eq(pe)) {
                Ok(())
            } else {
                Err(PinOrSelfSignedError::PinMismatch)
            }
        }
        #[cfg(feature = "rsa")]
        _ => Err(PinOrSelfSignedError::PinAlgorithmMismatch),
    }
}

fn verify_self_sig<E, R>(leaf: &CertView<'_>) -> Result<(), PinOrSelfSignedError>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    match leaf {
        CertView::Ed25519 {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            let v = E::prepare_ed25519(pubkey);
            v.verify(tbs, signature)
                .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid)
        }
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            tbs,
            signature,
            outer_sig_alg,
            modulus,
            exponent,
            ..
        } => {
            let alg = outer_sig_alg.ok_or(PinOrSelfSignedError::UnknownSigAlg)?;
            let v = R::prepare_rsa(modulus, *exponent)
                .map_err(|_| PinOrSelfSignedError::RsaVerifierInvalid)?;
            match alg {
                #[cfg(not(feature = "rsa_pss_only"))]
                RsaCertSigAlg::Pkcs1v15Sha256 => v
                    .verify(tbs, &RsaPkcs1Sig(signature))
                    .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid),
                RsaCertSigAlg::PssSha256 => v
                    .verify(tbs, &RsaPssSig(signature))
                    .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid),
            }
        }
    }
}

#[cfg(feature = "validity")]
fn check_validity(
    leaf: &CertView<'_>,
    time: Option<&dyn TimeSource>,
) -> Result<(), PinOrSelfSignedError> {
    let time = time.ok_or(PinOrSelfSignedError::MissingClock)?;
    crate::identity::verify_validity(leaf, time).map_err(|_| PinOrSelfSignedError::ValidityFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::RustCrypto;

    const PK_A: [u8; 32] = [0xAA; 32];
    const PK_B: [u8; 32] = [0xBB; 32];

    /// DER-encoded `Validity ::= SEQUENCE { UTCTime "260101000000Z",
    /// UTCTime "300101000000Z" }`. Satisfies the validity check when
    /// `NOW` falls within 2026..2030.
    #[cfg(feature = "validity")]
    const VALID_BEFORE_2030_GEN: &[u8] = &[
        0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a, 0x17, 0x0d, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x5a,
    ];

    fn ed25519_view(pubkey: &[u8; 32]) -> CertView<'_> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey,
            san: None,
            #[cfg(feature = "validity")]
            validity_der: VALID_BEFORE_2030_GEN,
            #[cfg(not(feature = "validity"))]
            validity_der: &[],
        }
    }

    #[cfg(feature = "validity")]
    struct FixedTime(u64);
    #[cfg(feature = "validity")]
    impl TimeSource for FixedTime {
        fn now_unix_secs(&self) -> u64 {
            self.0
        }
    }
    /// 2027-06-01T00:00:00Z — within VALID_BEFORE_2030_GEN's window.
    #[cfg(feature = "validity")]
    const NOW: u64 = 1_811_894_400;

    #[test]
    fn pinned_ed25519_accepts_matching_leaf() {
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let leaf = ed25519_view(&PK_A);
        let chain = [leaf];
        let result = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy,
            &chain,
            #[cfg(feature = "validity")]
            Some(&FixedTime(NOW)),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn pinned_ed25519_rejects_mismatched_leaf() {
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let leaf = ed25519_view(&PK_B);
        let chain = [leaf];
        let err = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy,
            &chain,
            #[cfg(feature = "validity")]
            Some(&FixedTime(NOW)),
        )
        .expect_err("must reject mismatched pin");
        assert_eq!(err, PinOrSelfSignedError::PinMismatch);
    }

    #[test]
    fn pin_algorithm_mismatch_rejects() {
        #[cfg(feature = "rsa")]
        {
            let pin = PinnedPubkeyOwned::rsa(&[0xCCu8; 256], 65537).unwrap();
            let strategy = PinOrSelfSigned::pinned(pin);
            let leaf = ed25519_view(&PK_A);
            let chain = [leaf];
            let err = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
                &strategy,
                &chain,
                #[cfg(feature = "validity")]
                None,
            )
            .expect_err("must reject algorithm mismatch");
            assert_eq!(err, PinOrSelfSignedError::PinAlgorithmMismatch);
        }
    }

    #[test]
    fn rejects_multi_cert_chain() {
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let v1 = ed25519_view(&PK_A);
        let v2 = ed25519_view(&PK_B);
        let chain = [v1, v2];
        let err = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy,
            &chain,
            #[cfg(feature = "validity")]
            Some(&FixedTime(NOW)),
        )
        .expect_err("must reject multi-cert chain");
        assert_eq!(err, PinOrSelfSignedError::MultiCertChain);
    }
}
