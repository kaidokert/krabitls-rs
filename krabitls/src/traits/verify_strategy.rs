//! Pluggable cert-verification surface.
//!
//! Strategies decide which cert chains they accept; the TLS stack owns
//! identity binding (SAN match) and protocol invariants (CertificateVerify,
//! Finished MAC).

/// The server public key carried by the verified certificate.
#[derive(Debug, Clone, Copy)]
pub enum ServerPubkey<'a> {
    Ed25519([u8; 32], core::marker::PhantomData<&'a ()>),
    #[cfg(feature = "rsa")]
    Rsa {
        modulus: &'a [u8],
        exponent: u32,
    },
    #[cfg(feature = "mldsa")]
    MlDsa(&'a [u8]),
    /// 65-byte SEC1 uncompressed point.
    #[cfg(feature = "ecdsa")]
    EcdsaP256(&'a [u8]),
    /// 97-byte SEC1 uncompressed point.
    #[cfg(feature = "ecdsa")]
    EcdsaP384(&'a [u8]),
}

impl<'a> ServerPubkey<'a> {
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        ServerPubkey::Ed25519(pubkey, core::marker::PhantomData)
    }
}

/// Borrowed view of the server's TLS 1.3 `Certificate` handshake message.
/// `certs[0]` is always the leaf; `certs[1..]` are upstream signers.
pub struct CertChainView<'chain, 'src: 'chain> {
    pub certs: &'chain [&'src [u8]],
}

/// RSA key material handed to [`VerifierKeyMaterial::matches`] for the
/// SPKI cross-check that follows a successful strategy verdict.
#[cfg(feature = "rsa")]
#[derive(Debug, Clone, Copy)]
pub struct RsaKeyMaterial<'a> {
    pub modulus: &'a [u8],
    pub exponent: u32,
}

/// ML-DSA public-key bytes handed to [`VerifierKeyMaterial::matches`] for the
/// SPKI cross-check. Same role as [`RsaKeyMaterial`]; the param set is implicit
/// in the byte length.
#[cfg(feature = "mldsa")]
#[derive(Debug, Clone, Copy)]
pub struct MlDsaKeyMaterial<'a>(pub &'a [u8]);

/// Constant-time compare of a prepared verifier's stored key material
/// against `candidate`. Returning `Choice::from(1)` MUST imply the
/// verifier was built from material that matches — the SPKI cross-check
/// in `verify_server_flight` trusts this. A lying impl is an MITM vector.
pub trait VerifierKeyMaterial<K> {
    fn matches(&self, candidate: K) -> subtle::Choice;
}

use crate::traits::cert::{CertParseError, CertParser, CertView};
use crate::traits::ed25519_verify::Ed25519VerifierProvider;
use crate::traits::rsa_verify::RsaVerifierProvider;
#[cfg(feature = "cert-der")]
use crate::traits::time::TimeSource;
#[cfg(feature = "ecdsa")]
use sha2::{Digest, Sha256, Sha384};
use signature::Verifier;
#[cfg(feature = "ecdsa")]
use subtle::ConstantTimeEq;

/// Constant-time equality of a stored SEC1 point against a candidate. Length
/// mismatch short-circuits to `Choice::from(0)`.
#[cfg(feature = "ecdsa")]
fn ct_eq_sec1(stored: &[u8], candidate: &[u8]) -> subtle::Choice {
    if stored.len() != candidate.len() {
        return subtle::Choice::from(0);
    }
    stored.ct_eq(candidate)
}

/// Prepared verifier the strategy hands back for the TLS stack to use in
/// CertificateVerify. Stored by value in a caller-supplied slot so the
/// `Trusted` return can borrow it.
// no_alloc: the ML-DSA variant inlines a ~2.6 KiB public key; Box isn't
// available to shrink it.
#[allow(clippy::large_enum_variant)]
pub enum PreparedVerifier<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    Ed25519(E::Verifier, core::marker::PhantomData<fn() -> R>),
    #[cfg(feature = "rsa")]
    Rsa(R::Verifier),
    /// ML-DSA has a single backend (krabipqc), so unlike Ed25519/RSA it isn't
    /// parameterized by a provider — the concrete verifier is held directly.
    #[cfg(feature = "mldsa")]
    MlDsa(crate::backends::mldsa_verify::MlDsaVerifierKey),
    /// ECDSA has a single backend (krabiecdsa); the leaf/pinned SEC1 point is
    /// held inline by value.
    #[cfg(feature = "ecdsa")]
    EcdsaP256([u8; 65]),
    #[cfg(feature = "ecdsa")]
    EcdsaP384([u8; 97]),
}

impl<E, R> PreparedVerifier<E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    pub fn ed25519(verifier: E::Verifier) -> Self {
        PreparedVerifier::Ed25519(verifier, core::marker::PhantomData)
    }
}

impl<E, R> PreparedVerifier<E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    /// Cross-check this prepared verifier matches `view`'s pubkey. The stack
    /// runs this after the strategy returns — a lying strategy can't sneak in
    /// a verifier built from non-chain bytes. Algorithm mismatch (rsa / mldsa
    /// builds) returns `Choice::from(0)`. Under
    /// `not(any(feature = "rsa", feature = "mldsa"))` the leaf match is
    /// exhaustive (Ed25519 only), so no catch-all is needed.
    pub fn matches_cert(&self, view: &CertView<'_>) -> subtle::Choice {
        match (self, view) {
            (Self::Ed25519(v, _), CertView::Ed25519 { pubkey, .. }) => v.matches(**pubkey),
            #[cfg(feature = "rsa")]
            (
                Self::Rsa(v),
                CertView::Rsa {
                    modulus, exponent, ..
                },
            ) => v.matches(RsaKeyMaterial {
                modulus,
                exponent: *exponent,
            }),
            #[cfg(feature = "mldsa")]
            (Self::MlDsa(v), CertView::MlDsa { pubkey, .. }) => v.matches(MlDsaKeyMaterial(pubkey)),
            #[cfg(feature = "ecdsa")]
            (Self::EcdsaP256(pk), CertView::EcdsaP256 { pubkey, .. }) => ct_eq_sec1(pk, pubkey),
            #[cfg(feature = "ecdsa")]
            (Self::EcdsaP384(pk), CertView::EcdsaP384 { pubkey, .. }) => ct_eq_sec1(pk, pubkey),
            #[cfg(any(feature = "rsa", feature = "mldsa", feature = "ecdsa"))]
            _ => subtle::Choice::from(0),
        }
    }
}

/// Strategy verdict — the TLS stack uses `prepared` for CertificateVerify
/// after a [`PreparedVerifier::matches_cert`] cross-check against chain[0].
pub struct Trusted<'slot, E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    prepared: &'slot PreparedVerifier<E, R>,
}

impl<'slot, E, R> Trusted<'slot, E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    pub fn new(prepared: &'slot PreparedVerifier<E, R>) -> Self {
        Self { prepared }
    }

    pub fn prepared(&self) -> &PreparedVerifier<E, R> {
        self.prepared
    }
}

/// The pluggable verification surface.
///
/// Strategies decide chain trust. SAN hostname matching is NOT part of
/// the strategy's job — the TLS stack runs `verify_hostname` against
/// `chain[0]` unconditionally after the strategy returns. The trait
/// omits `hostname` from the signature so this is enforced structurally.
pub trait VerifyStrategy<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    type Error: core::error::Error + Clone + PartialEq;

    /// Inspect `chain` and decide whether to accept it. On Ok, write the
    /// leaf's prepared verifier into `slot` and return a [`Trusted`]
    /// borrowing from it.
    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<E, R>>,
    ) -> Result<Trusted<'slot, E, R>, Self::Error>;
}

/// The safe path: answer "do I accept this chain" and let
/// [`SafeStrategy`] handle the per-link signature verification and the
/// leaf pubkey prep generically.
///
/// Implementing this and wrapping in `SafeStrategy<Self, C>` avoids
/// three classes of mistake the direct [`VerifyStrategy`] path can hit:
/// returning a [`PreparedVerifier`] built from material outside the
/// chain, forgetting to verify per-link signatures, and tangling the
/// slot-lifetime plumbing.
pub trait TrustRootDecision<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    type Error: core::error::Error + Clone + PartialEq;

    /// `chain` has already been parsed and structurally validated by
    /// [`SafeStrategy`] (each link `chain[i]`'s outer sig verified
    /// against `chain[i+1]`'s pubkey). Return Ok if `chain[chain.len()-1]`
    /// is an acceptable trust root.
    ///
    /// Cert time-validity is NOT decided here: it's a separate `Clock` slot
    /// owned by `SafeStrategy`, evaluated over the whole chain only after
    /// `accept_chain` returns Ok.
    fn accept_chain<'src>(&self, chain: &[CertView<'src>]) -> Result<(), Self::Error>;
}

/// Cert time-validity check folded into the strategy as a type-level slot.
/// A `NoClock` monomorphization has an empty `check_validity`, so nothing
/// references `verify_validity` and the `der` time-decode is DCE'd to zero.
///
/// This is a validity-window *policy hook*, not a general trust gate: it runs
/// per-cert after `TrustRootDecision::accept_chain`, so a custom `Clock` can
/// only add a rejection on top of the trust-root verdict — never relax one.
pub trait Clock {
    fn check_validity(&self, leaf: &CertView<'_>) -> Result<(), ValidityRejected>;
}

/// Cert validity-window check rejected the leaf. Deliberately detail-free so
/// the always-compiled `Clock` surface carries no `der`-gated `ValidityError`
/// — keeps the no-`cert-der` build der-free. The concrete `ValidityError`
/// could be surfaced by a custom `Clock` impl before it's erased here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityRejected;

/// ZST clock: validity skipped. Empty body → no edge to `verify_validity`.
#[derive(Debug, Clone, Copy)]
pub struct NoClock;

impl Clock for NoClock {
    #[inline(always)]
    fn check_validity(&self, _leaf: &CertView<'_>) -> Result<(), ValidityRejected> {
        Ok(())
    }
}

/// Real clock: runs the `notBefore`/`notAfter` window check.
#[cfg(feature = "cert-der")]
#[derive(Debug, Clone, Copy)]
pub struct Clocked<T: TimeSource>(pub T);

#[cfg(feature = "cert-der")]
impl<T: TimeSource> Clock for Clocked<T> {
    fn check_validity(&self, leaf: &CertView<'_>) -> Result<(), ValidityRejected> {
        crate::identity::verify_validity(leaf, &self.0).map_err(|_| ValidityRejected)
    }
}

/// Adapter from [`TrustRootDecision`] to [`VerifyStrategy`].
#[derive(Debug, Clone)]
pub struct SafeStrategy<T, C: CertParser, K = NoClock> {
    pub decision: T,
    pub clock: K,
    _parser: core::marker::PhantomData<C>,
}

impl<T, C: CertParser> SafeStrategy<T, C> {
    pub fn new(decision: T) -> Self {
        Self {
            decision,
            clock: NoClock,
            _parser: core::marker::PhantomData,
        }
    }
}

impl<T, C: CertParser, K> SafeStrategy<T, C, K> {
    pub fn with_clock(decision: T, clock: K) -> Self {
        Self {
            decision,
            clock,
            _parser: core::marker::PhantomData,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafeStrategyError<TE> {
    #[error("cert parse failed: {0}")]
    Parse(#[from] CertParseError),
    #[error("chain exceeded SafeStrategy's per-call capacity")]
    ChainTooLong,
    #[error("chain is empty")]
    EmptyChain,
    #[error("per-link signature did not verify")]
    LinkSignatureInvalid,
    #[cfg(feature = "rsa")]
    #[error("intermediate cert outer signatureAlgorithm not recognized")]
    UnknownLinkSigAlg,
    #[cfg(feature = "rsa")]
    #[error("RSA verifier construction failed for intermediate cert")]
    RsaVerifierInvalid,
    #[cfg(feature = "mldsa")]
    #[error("ML-DSA verifier construction failed (bad public-key length)")]
    MlDsaVerifierInvalid,
    #[cfg(feature = "ecdsa")]
    #[error("ECDSA verifier construction failed (bad SEC1 point length)")]
    EcdsaVerifierInvalid,
    /// Trust-root decision returned an error.
    #[error("trust root rejected: {0}")]
    Decision(TE),
    /// Cert validity-window check rejected the leaf.
    #[error("cert validity-window check failed")]
    Validity,
}

/// Per-call cap on parsed `CertView`s. Real chains rarely exceed 4
/// (leaf + intermediate + cross-sign + root); 8 leaves slack.
const SAFE_STRATEGY_CHAIN_CAP: usize = 8;

impl<T, C, K, E, R> VerifyStrategy<E, R> for SafeStrategy<T, C, K>
where
    T: TrustRootDecision<E, R>,
    C: CertParser,
    K: Clock,
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    type Error = SafeStrategyError<T::Error>;

    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<E, R>>,
    ) -> Result<Trusted<'slot, E, R>, Self::Error> {
        // Reject empty chains up front. Without this guard a permissive
        // `TrustRootDecision::accept_chain(&[])` would let the `&views[0]`
        // access below panic.
        if chain.certs.is_empty() {
            return Err(SafeStrategyError::EmptyChain);
        }
        // Cap upfront so we don't parse certs we'd reject at push time.
        if chain.certs.len() > SAFE_STRATEGY_CHAIN_CAP {
            return Err(SafeStrategyError::ChainTooLong);
        }

        let mut views: heapless::Vec<CertView<'src>, SAFE_STRATEGY_CHAIN_CAP> =
            heapless::Vec::new();
        for cert_der in chain.certs {
            let view = C::parse(cert_der).map_err(SafeStrategyError::Parse)?;
            views
                .push(view)
                .map_err(|_| SafeStrategyError::ChainTooLong)?;
        }

        for i in 0..views.len().saturating_sub(1) {
            verify_link::<E, R>(&views[i], &views[i + 1])?;
        }

        self.decision
            .accept_chain(&views)
            .map_err(SafeStrategyError::Decision)?;

        // Validity applies to the whole presented path, mirroring the per-link
        // signature check above: an expired/not-yet-valid intermediate fails
        // the chain, not just the leaf. Empty under `NoClock`, so DCE'd to zero.
        for cert in views.iter() {
            self.clock
                .check_validity(cert)
                .map_err(|_| SafeStrategyError::Validity)?;
        }

        let leaf_prepared = prepare_leaf::<E, R>(&views[0])?;
        *slot = Some(leaf_prepared);
        Ok(Trusted::new(slot.as_ref().unwrap()))
    }
}

/// Failure building a [`PreparedVerifier`] from a leaf's SPKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrepareLeafErr {
    #[cfg(feature = "rsa")]
    RsaVerifierInvalid,
    #[cfg(feature = "mldsa")]
    MlDsaVerifierInvalid,
    #[cfg(feature = "ecdsa")]
    EcdsaVerifierInvalid,
}

impl<TE> From<PrepareLeafErr> for SafeStrategyError<TE> {
    fn from(e: PrepareLeafErr) -> Self {
        match e {
            #[cfg(feature = "rsa")]
            PrepareLeafErr::RsaVerifierInvalid => SafeStrategyError::RsaVerifierInvalid,
            #[cfg(feature = "mldsa")]
            PrepareLeafErr::MlDsaVerifierInvalid => SafeStrategyError::MlDsaVerifierInvalid,
            #[cfg(feature = "ecdsa")]
            PrepareLeafErr::EcdsaVerifierInvalid => SafeStrategyError::EcdsaVerifierInvalid,
        }
    }
}

/// Build the `PreparedVerifier` for a leaf from its parsed SPKI. Shared by
/// [`SafeStrategy`] and [`PinnedRoots`](crate::backends::PinnedRoots) so both
/// hand the stack a verifier the engine's `matches_cert` cross-check accepts.
pub(crate) fn prepare_leaf<E, R>(
    leaf: &CertView<'_>,
) -> Result<PreparedVerifier<E, R>, PrepareLeafErr>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    Ok(match leaf {
        CertView::Ed25519 { pubkey, .. } => PreparedVerifier::ed25519(E::prepare_ed25519(pubkey)),
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => PreparedVerifier::Rsa(
            R::prepare_rsa(modulus, *exponent).map_err(|_| PrepareLeafErr::RsaVerifierInvalid)?,
        ),
        #[cfg(feature = "mldsa")]
        CertView::MlDsa { pubkey, .. } => PreparedVerifier::MlDsa(
            crate::backends::mldsa_verify::MlDsaVerifierKey::new(pubkey)
                .map_err(|_| PrepareLeafErr::MlDsaVerifierInvalid)?,
        ),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP256 { pubkey, .. } => PreparedVerifier::EcdsaP256(
            (*pubkey)
                .try_into()
                .map_err(|_| PrepareLeafErr::EcdsaVerifierInvalid)?,
        ),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP384 { pubkey, .. } => PreparedVerifier::EcdsaP384(
            (*pubkey)
                .try_into()
                .map_err(|_| PrepareLeafErr::EcdsaVerifierInvalid)?,
        ),
    })
}

/// Per-link verify failure. Wider [`SafeStrategyError`] converts via `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkErr {
    LinkSignatureInvalid,
    #[cfg(feature = "rsa")]
    UnknownLinkSigAlg,
    #[cfg(feature = "rsa")]
    RsaVerifierInvalid,
    #[cfg(feature = "mldsa")]
    MlDsaVerifierInvalid,
}

impl<TE> From<LinkErr> for SafeStrategyError<TE> {
    fn from(e: LinkErr) -> Self {
        match e {
            LinkErr::LinkSignatureInvalid => SafeStrategyError::LinkSignatureInvalid,
            #[cfg(feature = "rsa")]
            LinkErr::UnknownLinkSigAlg => SafeStrategyError::UnknownLinkSigAlg,
            #[cfg(feature = "rsa")]
            LinkErr::RsaVerifierInvalid => SafeStrategyError::RsaVerifierInvalid,
            #[cfg(feature = "mldsa")]
            LinkErr::MlDsaVerifierInvalid => SafeStrategyError::MlDsaVerifierInvalid,
        }
    }
}

/// Verify `child`'s outer signature against `parent`'s public key. `parent` is
/// any parsed cert — a chain entry or a `PinnedRoots` stored anchor parsed from
/// flash — the dispatch is on `parent`'s key family, nothing is bound to "self".
pub(crate) fn verify_link<E, R>(child: &CertView<'_>, parent: &CertView<'_>) -> Result<(), LinkErr>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    let _ = core::marker::PhantomData::<R>;
    let (child_tbs, child_sig): (&[u8], &[u8]) = match child {
        CertView::Ed25519 { tbs, signature, .. } => (*tbs, &signature[..]),
        #[cfg(feature = "rsa")]
        CertView::Rsa { tbs, signature, .. } => (*tbs, *signature),
        #[cfg(feature = "mldsa")]
        CertView::MlDsa { tbs, signature, .. } => (*tbs, *signature),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP256 { tbs, signature, .. } => (*tbs, *signature),
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP384 { tbs, signature, .. } => (*tbs, *signature),
    };
    match parent {
        CertView::Ed25519 { pubkey, .. } => {
            let v = E::prepare_ed25519(pubkey);
            let sig: &[u8; 64] = child_sig
                .try_into()
                .map_err(|_| LinkErr::LinkSignatureInvalid)?;
            v.verify(child_tbs, sig)
                .map_err(|_| LinkErr::LinkSignatureInvalid)
        }
        #[cfg(feature = "mldsa")]
        CertView::MlDsa { pubkey, .. } => {
            // ML-DSA cert sigs are pure ML-DSA over the child TBS, empty
            // context — no padding/hash discriminator to classify (unlike RSA).
            let v = crate::backends::mldsa_verify::MlDsaVerifierKey::new(pubkey)
                .map_err(|_| LinkErr::MlDsaVerifierInvalid)?;
            v.verify(
                child_tbs,
                &crate::backends::mldsa_verify::MlDsaSig(child_sig),
            )
            .map_err(|_| LinkErr::LinkSignatureInvalid)
        }
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => {
            // Padding scheme is identified by the CHILD's signatureAlgorithm
            // (the alg the parent USED to sign the child) — decoupled from the
            // child's own SPKI kind, so an ECDSA cert under an RSA issuer works.
            let alg = match child {
                CertView::Rsa { outer_sig_alg, .. } => {
                    outer_sig_alg.ok_or(LinkErr::UnknownLinkSigAlg)?
                }
                #[cfg(feature = "ecdsa")]
                CertView::EcdsaP256 { outer_sig_alg, .. }
                | CertView::EcdsaP384 { outer_sig_alg, .. } => {
                    outer_sig_alg.ok_or(LinkErr::UnknownLinkSigAlg)?
                }
                _ => return Err(LinkErr::UnknownLinkSigAlg),
            };
            let v = R::prepare_rsa(modulus, *exponent).map_err(|_| LinkErr::RsaVerifierInvalid)?;
            crate::traits::rsa_verify::verify_cert_sig(&v, child_tbs, child_sig, alg)
                .map_err(|_| LinkErr::LinkSignatureInvalid)
        }
        // ECDSA cert outer sigs carry no padding/hash discriminator in the
        // CertView; the issuer's curve fixes the conventional hash pairing
        // (P-256↔SHA-256, P-384↔SHA-384), matching real CA chains. A cert
        // signed under a non-conventional hash fails closed here.
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP256 { pubkey, .. } => {
            let digest = Sha256::digest(child_tbs);
            crate::backends::ecdsa_verify::verify_p256(pubkey, &digest, child_sig)
                .map_err(|_| LinkErr::LinkSignatureInvalid)
        }
        #[cfg(feature = "ecdsa")]
        CertView::EcdsaP384 { pubkey, .. } => {
            let digest = Sha384::digest(child_tbs);
            crate::backends::ecdsa_verify::verify_p384(pubkey, &digest, child_sig)
                .map_err(|_| LinkErr::LinkSignatureInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cipher-aes")]
    impl ServerPubkey<'_> {
        /// Test-only accessor; production paths match on the enum directly.
        pub(crate) fn as_ed25519(&self) -> Option<[u8; 32]> {
            match self {
                ServerPubkey::Ed25519(pk, _) => Some(*pk),
                #[cfg(feature = "rsa")]
                ServerPubkey::Rsa { .. } => None,
                #[cfg(feature = "mldsa")]
                ServerPubkey::MlDsa(_) => None,
                #[cfg(feature = "ecdsa")]
                ServerPubkey::EcdsaP256(_) | ServerPubkey::EcdsaP384(_) => None,
            }
        }
    }
    use crate::backends::RustCrypto;
    use crate::traits::CertView;

    const LEAF_PUBKEY: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];

    struct ProduceEd25519 {
        pubkey: [u8; 32],
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[error("ProduceEd25519 only takes single-cert chains")]
    struct ProduceErr;

    impl VerifyStrategy<RustCrypto, RustCrypto> for ProduceEd25519 {
        type Error = ProduceErr;

        fn verify_chain<'chain, 'src, 'slot>(
            &self,
            chain: CertChainView<'chain, 'src>,
            slot: &'slot mut Option<PreparedVerifier<RustCrypto, RustCrypto>>,
        ) -> Result<Trusted<'slot, RustCrypto, RustCrypto>, ProduceErr> {
            if chain.certs.len() != 1 {
                return Err(ProduceErr);
            }
            let prepared = PreparedVerifier::ed25519(
                <RustCrypto as Ed25519VerifierProvider>::prepare_ed25519(&self.pubkey),
            );
            *slot = Some(prepared);
            Ok(Trusted::new(slot.as_ref().unwrap()))
        }
    }

    fn make_view(pubkey: &[u8; 32]) -> CertView<'_> {
        CertView::Ed25519 {
            tbs: &[],
            signature: &[0u8; 64],
            pubkey,
            san: None,
            validity_der: &[],
        }
    }

    #[cfg(feature = "cert-der")]
    mod clock {
        use super::*;
        use crate::traits::time::tests::FixedTime;

        // `Validity ::= SEQUENCE { UTCTime "260101000000Z",
        // UTCTime "300101000000Z" }` — window 2026-01-01 .. 2030-01-01.
        const VALIDITY_2026_2030: &[u8] = &[
            0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x5a,
        ];
        const T_IN_WINDOW: u64 = 1_800_000_000; // 2027
        const T_BEFORE: u64 = 1_700_000_000; // 2023
        const T_AFTER: u64 = 2_000_000_000; // 2033

        fn leaf(validity_der: &[u8]) -> CertView<'_> {
            CertView::Ed25519 {
                tbs: &[],
                signature: &[0u8; 64],
                pubkey: &LEAF_PUBKEY,
                san: None,
                validity_der,
            }
        }

        // Run a `Clocked` strategy's window check against the 2026..2030 leaf.
        fn clocked_check(now: u64) -> Result<(), ValidityRejected> {
            Clocked(FixedTime(now)).check_validity(&leaf(VALIDITY_2026_2030))
        }

        #[test]
        fn noclock_skips_the_window_check() {
            // NoClock accepts regardless of the window (even an empty DER).
            assert!(NoClock.check_validity(&leaf(VALIDITY_2026_2030)).is_ok());
            assert!(NoClock.check_validity(&leaf(&[])).is_ok());
        }

        #[test]
        fn clocked_accepts_in_window() {
            assert!(clocked_check(T_IN_WINDOW).is_ok());
        }

        #[test]
        fn clocked_rejects_not_yet_valid() {
            assert_eq!(clocked_check(T_BEFORE), Err(ValidityRejected));
        }

        #[test]
        fn clocked_rejects_expired() {
            assert_eq!(clocked_check(T_AFTER), Err(ValidityRejected));
        }
    }

    #[test]
    fn slot_pattern_yields_borrow_of_written_verifier() {
        let leaf_bytes = [0u8; 100];
        let chain: [&[u8]; 1] = [&leaf_bytes[..]];
        let view = CertChainView { certs: &chain };

        let strategy = ProduceEd25519 {
            pubkey: LEAF_PUBKEY,
        };
        let mut slot: Option<PreparedVerifier<RustCrypto, RustCrypto>> = None;

        let trusted = strategy
            .verify_chain(view, &mut slot)
            .expect("strategy accepts");

        let cert = make_view(&LEAF_PUBKEY);
        assert!(bool::from(trusted.prepared().matches_cert(&cert)));
    }

    #[test]
    fn matches_cert_rejects_when_strategy_lies_about_pubkey() {
        let leaf_bytes = [0u8; 100];
        let chain: [&[u8]; 1] = [&leaf_bytes[..]];
        let view = CertChainView { certs: &chain };

        let attacker_pubkey = [0xAAu8; 32];
        let strategy = ProduceEd25519 {
            pubkey: attacker_pubkey,
        };
        let mut slot: Option<PreparedVerifier<RustCrypto, RustCrypto>> = None;

        let trusted = strategy
            .verify_chain(view, &mut slot)
            .expect("strategy returns");

        let real_leaf = make_view(&LEAF_PUBKEY);
        assert!(!bool::from(trusted.prepared().matches_cert(&real_leaf)));
    }

    #[test]
    fn verify_chain_rejects_multi_cert_chain() {
        let leaf_bytes = [0u8; 50];
        let other_bytes = [0u8; 60];
        let chain: [&[u8]; 2] = [&leaf_bytes[..], &other_bytes[..]];
        let view = CertChainView { certs: &chain };

        let strategy = ProduceEd25519 {
            pubkey: LEAF_PUBKEY,
        };
        let mut slot: Option<PreparedVerifier<RustCrypto, RustCrypto>> = None;

        let result = strategy.verify_chain(view, &mut slot);
        match result {
            Err(ProduceErr) => {}
            Ok(_) => panic!("strategy should reject 2-cert chain"),
        }
    }

    #[cfg(all(feature = "ecdsa", feature = "cert-der"))]
    mod ecdsa_links {
        use super::super::verify_link;
        use crate::backends::{DerCert, RustCrypto};
        use crate::traits::CertParser;

        const P384_SELF_SIGNED: [u8; 494] = crate::hex_decode(include_str!(
            "../../../testdata/certs_ecdsa/p384_self_signed.hex"
        ));

        #[test]
        fn p384_self_signature_links() {
            // A self-signed cert is its own issuer; exercises the EcdsaP384
            // SPKI parse + the conventional P-384 ↔ SHA-384 outer-sig pairing.
            let leaf = DerCert::parse(&P384_SELF_SIGNED).expect("parse P-384 self-signed leaf");
            assert!(verify_link::<RustCrypto, RustCrypto>(&leaf, &leaf).is_ok());
        }

        // An ECDSA leaf whose outer signature is RSA (real chains put ECDSA
        // leaves under RSA intermediates) must link via the issuer's RSA key
        // and the leaf's carried `outer_sig_alg`, not its ECDSA SPKI kind. The
        // fixture leaf is `sha256WithRSAEncryption`-signed (PKCS#1-v1.5), which
        // the `rsa_pss_only` build intentionally drops.
        #[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
        mod under_rsa_issuer {
            use super::*;

            const LEAF_ECDSA_RSA_SIGNED: [u8; 617] = crate::hex_decode(include_str!(
                "../../../testdata/certs_ecdsa/leaf256_ecdsa_rsa_signed.hex"
            ));
            const RSA_CA: [u8; 795] =
                crate::hex_decode(include_str!("../../../testdata/certs_ecdsa/rsa_ca.hex"));

            #[test]
            fn ecdsa_leaf_under_rsa_issuer_links() {
                let leaf =
                    DerCert::parse(&LEAF_ECDSA_RSA_SIGNED).expect("parse RSA-signed ECDSA leaf");
                let ca = DerCert::parse(&RSA_CA).expect("parse RSA CA");
                assert!(verify_link::<RustCrypto, RustCrypto>(&leaf, &ca).is_ok());
            }

            #[test]
            fn tampered_ecdsa_leaf_under_rsa_issuer_fails() {
                let ca = DerCert::parse(&RSA_CA).expect("parse RSA CA");
                let mut der = LEAF_ECDSA_RSA_SIGNED;
                der[30] ^= 0x01;
                // The mutated TBS must be rejected whether it fails to parse or
                // parses but the RSA issuer signature no longer covers it — a
                // silent parse failure must not vacuously pass the test.
                let verified = DerCert::parse(&der).map_err(|_| ()).and_then(|leaf| {
                    verify_link::<RustCrypto, RustCrypto>(&leaf, &ca).map_err(|_| ())
                });
                assert!(verified.is_err());
            }
        }
    }
}
