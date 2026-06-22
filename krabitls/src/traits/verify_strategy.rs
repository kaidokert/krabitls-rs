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
    #[cfg(test)]
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
#[allow(dead_code)]
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
#[cfg(feature = "validity")]
use crate::traits::time::TimeSource;
use signature::Verifier;

/// Prepared verifier the strategy hands back for the TLS stack to use in
/// CertificateVerify. Stored by value in a caller-supplied slot so the
/// `Trusted` return can borrow it.
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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
#[allow(dead_code)]
pub struct Trusted<'slot, E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    prepared: &'slot PreparedVerifier<E, R>,
}

impl<'slot, E, R> Trusted<'slot, E, R>
where
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    #[allow(dead_code)]
    pub fn new(prepared: &'slot PreparedVerifier<E, R>) -> Self {
        Self { prepared }
    }

    #[allow(dead_code)]
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
#[allow(dead_code)]
pub trait VerifyStrategy<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    type Error: core::error::Error + Clone + PartialEq;

    /// Inspect `chain` and decide whether to accept it. On Ok, write the
    /// leaf's prepared verifier into `slot` and return a [`Trusted`]
    /// borrowing from it.
    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<E, R>>,
        #[cfg(feature = "validity")] time: Option<&dyn TimeSource>,
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
    fn accept_chain<'src>(
        &self,
        chain: &[CertView<'src>],
        #[cfg(feature = "validity")] time: Option<&dyn TimeSource>,
    ) -> Result<(), Self::Error>;
}

/// Adapter from [`TrustRootDecision`] to [`VerifyStrategy`].
pub struct SafeStrategy<T, C: CertParser> {
    pub decision: T,
    _parser: core::marker::PhantomData<C>,
}

impl<T, C: CertParser> SafeStrategy<T, C> {
    #[allow(dead_code)]
    pub fn new(decision: T) -> Self {
        Self {
            decision,
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
}

/// Per-call cap on parsed `CertView`s. Real chains rarely exceed 4
/// (leaf + intermediate + cross-sign + root); 8 leaves slack.
const SAFE_STRATEGY_CHAIN_CAP: usize = 8;

impl<T, C, E, R> VerifyStrategy<E, R> for SafeStrategy<T, C>
where
    T: TrustRootDecision<E, R>,
    C: CertParser,
    E: Ed25519VerifierProvider,
    R: RsaVerifierProvider,
{
    type Error = SafeStrategyError<T::Error>;

    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<E, R>>,
        #[cfg(feature = "validity")] time: Option<&dyn TimeSource>,
    ) -> Result<Trusted<'slot, E, R>, Self::Error> {
        // Reject empty chains up front. Without this guard a permissive
        // `TrustRootDecision::accept_chain(&[])` would let the `&views[0]`
        // access below panic.
        if chain.certs.is_empty() {
            return Err(SafeStrategyError::EmptyChain);
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
            .accept_chain(
                &views,
                #[cfg(feature = "validity")]
                time,
            )
            .map_err(SafeStrategyError::Decision)?;

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
            #[cfg(feature = "validity")] _time: Option<&dyn TimeSource>,
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
            .verify_chain(
                view,
                &mut slot,
                #[cfg(feature = "validity")]
                None,
            )
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
            .verify_chain(
                view,
                &mut slot,
                #[cfg(feature = "validity")]
                None,
            )
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

        let result = strategy.verify_chain(
            view,
            &mut slot,
            #[cfg(feature = "validity")]
            None,
        );
        match result {
            Err(ProduceErr) => {}
            Ok(_) => panic!("strategy should reject 2-cert chain"),
        }
    }
}
