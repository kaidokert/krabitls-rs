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
}

impl<'a> ServerPubkey<'a> {
    pub fn ed25519(pubkey: [u8; 32]) -> Self {
        ServerPubkey::Ed25519(pubkey, core::marker::PhantomData)
    }

    /// Test-only accessor; production paths match on the enum directly.
    #[cfg(all(test, feature = "cipher-aes"))]
    pub fn as_ed25519(&self) -> Option<[u8; 32]> {
        match self {
            ServerPubkey::Ed25519(pk, _) => Some(*pk),
            #[cfg(feature = "rsa")]
            ServerPubkey::Rsa { .. } => None,
        }
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

/// Constant-time compare of a prepared verifier's stored key material
/// against `candidate`. Returning `Choice::from(1)` MUST imply the
/// verifier was built from material that matches — the SPKI cross-check
/// in `verify_server_flight` trusts this. A lying impl is an MITM vector.
pub trait VerifierKeyMaterial<K> {
    fn matches(&self, candidate: K) -> subtle::Choice;
}

#[cfg(all(feature = "rsa", not(feature = "rsa_pss_only")))]
use crate::backends::rsa_verify::RsaPkcs1Sig;
#[cfg(feature = "rsa")]
use crate::backends::rsa_verify::RsaPssSig;
#[cfg(feature = "rsa")]
use crate::traits::cert::RsaCertSigAlg;
use crate::traits::cert::{CertParseError, CertParser, CertView};
use crate::traits::ed25519_verify::Ed25519VerifierProvider;
use crate::traits::rsa_verify::RsaVerifierProvider;
#[cfg(feature = "cert-der")]
use crate::traits::time::TimeSource;
use signature::Verifier;

/// Prepared verifier the strategy hands back for the TLS stack to use in
/// CertificateVerify. Stored by value in a caller-supplied slot so the
/// `Trusted` return can borrow it.
pub enum PreparedVerifier<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    Ed25519(E::Verifier, core::marker::PhantomData<fn() -> R>),
    #[cfg(feature = "rsa")]
    Rsa(R::Verifier),
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

#[cfg(not(feature = "rsa"))]
impl<E, R> PreparedVerifier<E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    /// Cross-check this prepared verifier matches `view`'s pubkey. The
    /// stack runs this after the strategy returns — a lying strategy
    /// can't sneak in a verifier built from non-chain bytes.
    pub fn matches_cert(&self, view: &CertView<'_>) -> subtle::Choice {
        match (self, view) {
            (Self::Ed25519(v, _), CertView::Ed25519 { pubkey, .. }) => v.matches(**pubkey),
        }
    }
}

#[cfg(feature = "rsa")]
impl<E, R> PreparedVerifier<E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    /// Cross-check this prepared verifier matches `view`'s pubkey.
    /// Algorithm mismatch returns `Choice::from(0)`.
    pub fn matches_cert(&self, view: &CertView<'_>) -> subtle::Choice {
        match (self, view) {
            (Self::Ed25519(v, _), CertView::Ed25519 { pubkey, .. }) => v.matches(**pubkey),
            (
                Self::Rsa(v),
                CertView::Rsa {
                    modulus, exponent, ..
                },
            ) => v.matches(RsaKeyMaterial {
                modulus,
                exponent: *exponent,
            }),
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

        let leaf_prepared: PreparedVerifier<E, R> = match &views[0] {
            CertView::Ed25519 { pubkey, .. } => {
                PreparedVerifier::ed25519(E::prepare_ed25519(pubkey))
            }
            #[cfg(feature = "rsa")]
            CertView::Rsa {
                modulus, exponent, ..
            } => PreparedVerifier::Rsa(
                R::prepare_rsa(modulus, *exponent)
                    .map_err(|_| SafeStrategyError::RsaVerifierInvalid)?,
            ),
        };
        *slot = Some(leaf_prepared);
        Ok(Trusted::new(slot.as_ref().unwrap()))
    }
}

/// Per-link verify failure. Wider [`SafeStrategyError`] converts via `From`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkErr {
    LinkSignatureInvalid,
    #[cfg(feature = "rsa")]
    UnknownLinkSigAlg,
    #[cfg(feature = "rsa")]
    RsaVerifierInvalid,
}

impl<TE> From<LinkErr> for SafeStrategyError<TE> {
    fn from(e: LinkErr) -> Self {
        match e {
            LinkErr::LinkSignatureInvalid => SafeStrategyError::LinkSignatureInvalid,
            #[cfg(feature = "rsa")]
            LinkErr::UnknownLinkSigAlg => SafeStrategyError::UnknownLinkSigAlg,
            #[cfg(feature = "rsa")]
            LinkErr::RsaVerifierInvalid => SafeStrategyError::RsaVerifierInvalid,
        }
    }
}

fn verify_link<E, R>(child: &CertView<'_>, parent: &CertView<'_>) -> Result<(), LinkErr>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    let _ = core::marker::PhantomData::<R>;
    let (child_tbs, child_sig): (&[u8], &[u8]) = match child {
        CertView::Ed25519 { tbs, signature, .. } => (*tbs, &signature[..]),
        #[cfg(feature = "rsa")]
        CertView::Rsa { tbs, signature, .. } => (*tbs, *signature),
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
        #[cfg(feature = "rsa")]
        CertView::Rsa {
            modulus, exponent, ..
        } => {
            // Padding scheme is identified by the CHILD's signatureAlgorithm
            // (the alg the parent USED to sign the child).
            let alg = match child {
                CertView::Ed25519 { .. } => return Err(LinkErr::UnknownLinkSigAlg),
                CertView::Rsa { outer_sig_alg, .. } => {
                    outer_sig_alg.ok_or(LinkErr::UnknownLinkSigAlg)?
                }
            };
            let v = R::prepare_rsa(modulus, *exponent).map_err(|_| LinkErr::RsaVerifierInvalid)?;
            match alg {
                #[cfg(not(feature = "rsa_pss_only"))]
                RsaCertSigAlg::Pkcs1v15Sha256 => v
                    .verify(child_tbs, &RsaPkcs1Sig(child_sig))
                    .map_err(|_| LinkErr::LinkSignatureInvalid),
                RsaCertSigAlg::PssSha256 => v
                    .verify(child_tbs, &RsaPssSig(child_sig))
                    .map_err(|_| LinkErr::LinkSignatureInvalid),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
