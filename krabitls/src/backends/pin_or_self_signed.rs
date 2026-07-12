//! Bundled cert-verification strategy: pin-or-self-signed.
//!
//! `pinned(pin)` accepts a leaf whose SPKI byte-matches `pin`. `self_signed()`
//! accepts a leaf whose outer signature verifies against its own pubkey.
//! Both are single-cert-chain only; rejects anything longer.

use crate::traits::cert::CertView;
use crate::traits::verify_strategy::TrustRootDecision;
use crate::traits::{Ed25519VerifierProvider, RsaVerifierProvider};
#[cfg(feature = "ecdsa")]
use sha2::{Digest, Sha256, Sha384};
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
    #[cfg(feature = "mldsa")]
    MlDsa(heapless::Vec<u8, { MAX_MLDSA_PUBKEY_BYTES }>),
    #[cfg(feature = "ecdsa")]
    EcdsaP256([u8; 65]),
    #[cfg(feature = "ecdsa")]
    EcdsaP384([u8; 97]),
}

/// Maximum RSA modulus size accepted in [`PinnedPubkeyOwned::Rsa`]
/// (256 = RSA-2048; 128 = RSA-1024 fits too).
#[cfg(feature = "rsa")]
pub const MAX_RSA_MODULUS_BYTES: usize = 256;

/// Maximum ML-DSA public-key size accepted in [`PinnedPubkeyOwned::MlDsa`]
/// (2592 = ML-DSA-87; the smaller parameter sets fit too).
#[cfg(feature = "mldsa")]
pub const MAX_MLDSA_PUBKEY_BYTES: usize = 2592;

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

    /// ML-DSA constructor: copies the raw public key into a heapless buffer.
    /// Errors when `pubkey.len() > MAX_MLDSA_PUBKEY_BYTES`.
    #[cfg(feature = "mldsa")]
    pub fn mldsa(pubkey: &[u8]) -> Result<Self, PinnedPubkeyOwnedError> {
        let mut v: heapless::Vec<u8, { MAX_MLDSA_PUBKEY_BYTES }> = heapless::Vec::new();
        v.extend_from_slice(pubkey)
            .map_err(|_| PinnedPubkeyOwnedError::PubkeyTooLong)?;
        Ok(PinnedPubkeyOwned::MlDsa(v))
    }

    #[cfg(feature = "ecdsa")]
    pub fn ecdsa_p256(pubkey: [u8; 65]) -> Self {
        PinnedPubkeyOwned::EcdsaP256(pubkey)
    }

    #[cfg(feature = "ecdsa")]
    pub fn ecdsa_p384(pubkey: [u8; 97]) -> Self {
        PinnedPubkeyOwned::EcdsaP384(pubkey)
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
    #[cfg(feature = "mldsa")]
    #[error("ML-DSA public key exceeds MAX_MLDSA_PUBKEY_BYTES")]
    PubkeyTooLong,
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
    /// ML-DSA verifier construction failed (bad public-key length).
    #[cfg(feature = "mldsa")]
    #[error("ML-DSA verifier construction failed")]
    MlDsaVerifierInvalid,
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

    fn accept_chain<'src>(&self, chain: &[CertView<'src>]) -> Result<(), Self::Error> {
        // SafeStrategy guarantees non-empty (its own `EmptyChain` guard
        // fires first); `first()` is defense in depth for any
        // hand-rolled non-SafeStrategy wrapper.
        let leaf = chain.first().ok_or(PinOrSelfSignedError::MultiCertChain)?;

        match &self.mode {
            Mode::Pinned(pin) => {
                // Pin constrains the leaf; chain depth is irrelevant.
                // SafeStrategy already chain-verified `chain[0..n-1]`
                // links, so a `[leaf, intermediate, root]` chain
                // reaches here with the link structure validated.
                verify_pin(leaf, pin)?;
            }
            Mode::SelfSigned => {
                // Self-sig semantics only make sense for a length-1
                // chain: a self-signed leaf has no upstream signer, so
                // any additional entry is contradictory. (Link verify
                // would also reject, but this lets us return a more
                // specific error.)
                if chain.len() != 1 {
                    return Err(PinOrSelfSignedError::MultiCertChain);
                }
                verify_self_sig::<E, R>(leaf)?;
            }
        }

        Ok(())
    }
}

/// Constant-time SEC1-point pin compare (both sides are fixed-length here).
#[cfg(feature = "ecdsa")]
fn ct_eq_pin(pubkey: &[u8], pin: &[u8]) -> Result<(), PinOrSelfSignedError> {
    if pubkey.len() == pin.len() && bool::from(pubkey.ct_eq(pin)) {
        Ok(())
    } else {
        Err(PinOrSelfSignedError::PinMismatch)
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
        #[cfg(feature = "mldsa")]
        (CertView::MlDsa { pubkey, .. }, PinnedPubkeyOwned::MlDsa(pin)) => {
            if pubkey.len() != pin.len() {
                return Err(PinOrSelfSignedError::PinMismatch);
            }
            if bool::from(pubkey.ct_eq(pin.as_slice())) {
                Ok(())
            } else {
                Err(PinOrSelfSignedError::PinMismatch)
            }
        }
        #[cfg(feature = "ecdsa")]
        (CertView::EcdsaP256 { pubkey, .. }, PinnedPubkeyOwned::EcdsaP256(pin)) => {
            ct_eq_pin(pubkey, pin)
        }
        #[cfg(feature = "ecdsa")]
        (CertView::EcdsaP384 { pubkey, .. }, PinnedPubkeyOwned::EcdsaP384(pin)) => {
            ct_eq_pin(pubkey, pin)
        }
        #[cfg(any(feature = "rsa", feature = "mldsa", feature = "ecdsa"))]
        _ => Err(PinOrSelfSignedError::PinAlgorithmMismatch),
    }
}

fn verify_self_sig<E, R>(leaf: &CertView<'_>) -> Result<(), PinOrSelfSignedError>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    // `R` is bound even without `feature = "rsa"` so callers can specify
    // both backends in one go; mark it used so clippy's
    // `extra_unused_type_parameters` doesn't fire under non-rsa builds.
    let _ = core::marker::PhantomData::<R>;
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
            crate::traits::rsa_verify::verify_cert_sig(&v, tbs, signature, alg)
                .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid)
        }
        #[cfg(feature = "mldsa")]
        CertView::MlDsa {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            // Pure ML-DSA over the TBS, empty context — no outer-alg to classify.
            let v = crate::backends::mldsa_verify::MlDsaVerifierKey::new(pubkey)
                .map_err(|_| PinOrSelfSignedError::MlDsaVerifierInvalid)?;
            v.verify(tbs, &crate::backends::mldsa_verify::MlDsaSig(signature))
                .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid)
        }
        // Curve fixes the conventional CertVerify/cert-sig hash pairing
        // (P-256↔SHA-256, P-384↔SHA-384); a non-conventional hash fails closed.
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP256 {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            let digest = Sha256::digest(tbs);
            crate::backends::ecdsa_verify::verify_p256(pubkey, &digest, signature)
                .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid)
        }
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP384 {
            tbs,
            signature,
            pubkey,
            ..
        } => {
            let digest = Sha384::digest(tbs);
            crate::backends::ecdsa_verify::verify_p384(pubkey, &digest, signature)
                .map_err(|_| PinOrSelfSignedError::SelfSignatureInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::RustCrypto;

    const PK_A: [u8; 32] = [0xAA; 32];
    const PK_B: [u8; 32] = [0xBB; 32];

    fn ed25519_view(pubkey: &[u8; 32]) -> CertView<'_> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey,
            san: None,
            validity_der: &[],
        }
    }

    #[cfg(feature = "mldsa")]
    fn mldsa_view<'a>(pubkey: &'a [u8], signature: &'a [u8], tbs: &'a [u8]) -> CertView<'a> {
        CertView::MlDsa {
            tbs,
            signature,
            pubkey,
            san: None,
            validity_der: &[],
        }
    }

    #[test]
    fn pinned_ed25519_accepts_matching_leaf() {
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let leaf = ed25519_view(&PK_A);
        let chain = [leaf];
        let result = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy, &chain,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn pinned_ed25519_rejects_mismatched_leaf() {
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let leaf = ed25519_view(&PK_B);
        let chain = [leaf];
        let err = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy, &chain,
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
                &strategy, &chain,
            )
            .expect_err("must reject algorithm mismatch");
            assert_eq!(err, PinOrSelfSignedError::PinAlgorithmMismatch);
        }
    }

    #[test]
    fn pinned_accepts_multi_cert_chain_when_leaf_matches() {
        // Real-world public-server pinning sees `leaf + intermediate(s)`;
        // the pin only constrains `chain[0]`, so the strategy must
        // accept and only check the leaf SPKI.
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(PK_A));
        let v1 = ed25519_view(&PK_A);
        let v2 = ed25519_view(&PK_B);
        let chain = [v1, v2];
        let result = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy, &chain,
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn pinned_mldsa_accepts_matching_and_rejects_other() {
        use krabipqc::{KeyGenSeed, ml_dsa_44};

        let (pk, _) = ml_dsa_44::keygen_from_seed(&KeyGenSeed([3; 32])).unwrap();
        let strategy = PinOrSelfSigned::pinned(PinnedPubkeyOwned::mldsa(&pk).unwrap());
        let leaf = mldsa_view(&pk, &[], &[]);
        assert!(
            <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
                &strategy,
                &[leaf],
            )
            .is_ok()
        );

        let (other, _) = ml_dsa_44::keygen_from_seed(&KeyGenSeed([4; 32])).unwrap();
        let mismatch = mldsa_view(&other, &[], &[]);
        assert_eq!(
            <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
                &strategy,
                &[mismatch],
            )
            .expect_err("pin mismatch"),
            PinOrSelfSignedError::PinMismatch
        );
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn self_signed_mldsa_verifies_and_rejects_tamper() {
        use krabipqc::{KeyGenSeed, SigningRandomness, ml_dsa_44};

        let (pk, sk) = ml_dsa_44::keygen_from_seed(&KeyGenSeed([5; 32])).unwrap();
        let tbs: &[u8] = b"synthetic TBSCertificate bytes for ml-dsa self-sig";
        let sig = ml_dsa_44::sign(&sk, tbs, &[], &SigningRandomness([6; 32])).unwrap();
        let strategy = PinOrSelfSigned::self_signed();

        let leaf = mldsa_view(&pk, &sig, tbs);
        assert!(
            <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
                &strategy,
                &[leaf],
            )
            .is_ok()
        );

        let tampered = mldsa_view(&pk, &sig, b"different tbs");
        assert_eq!(
            <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
                &strategy,
                &[tampered],
            )
            .expect_err("self-sig over wrong tbs"),
            PinOrSelfSignedError::SelfSignatureInvalid
        );
    }

    #[test]
    fn self_signed_rejects_multi_cert_chain() {
        // Self-sig semantics only apply to a length-1 chain.
        let strategy = PinOrSelfSigned::self_signed();
        let v1 = ed25519_view(&PK_A);
        let v2 = ed25519_view(&PK_B);
        let chain = [v1, v2];
        let err = <PinOrSelfSigned as TrustRootDecision<RustCrypto, RustCrypto>>::accept_chain(
            &strategy, &chain,
        )
        .expect_err("self-signed must reject multi-cert");
        assert_eq!(err, PinOrSelfSignedError::MultiCertChain);
    }
}
