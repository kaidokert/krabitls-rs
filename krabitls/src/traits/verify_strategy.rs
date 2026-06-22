//! Pluggable cert-verification surface.
//!
//! Strategies decide which cert chains they accept; the TLS stack owns
//! identity binding (SAN match) and protocol invariants (CertificateVerify,
//! Finished MAC). The bundled default strategy reproducing today's
//! pin-or-self-signed behavior lives alongside the wiring; users with
//! different trust policies implement [`VerifyStrategy`] themselves.

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
///
/// `certs[0]` is always the leaf; `certs[1..]` are upstream signers.
/// The slice itself lives in the caller's stack frame; the inner byte
/// slices borrow into the handshake reassembler.
///
/// Both lifetimes are explicit because the outer slice and the inner
/// slices have different scopes — the outer slice's `heapless::Vec`
/// is built inside `verify_server_flight`, the inner bytes live in
/// the longer-lived reassembler buffer.
// Inline tests exercise `CertChainView`, `PreparedVerifier`, `Trusted`,
// and `VerifyStrategy` — `dead_code` doesn't see test-module usage, so
// the staged items wear `allow(dead_code)` until `verify_server_flight`
// (next change) wires them through production paths.
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
/// against the bytes the TLS stack just re-parsed from `chain[0]`.
///
/// Implemented per algorithm: Ed25519 verifiers carry the 32-byte
/// pubkey by value; RSA verifiers carry `(modulus, exponent)` and the
/// comparison is byte-wise CT (after a public length short-circuit).
///
/// **The contract MUST hold: returning `Choice::from(1)` implies the
/// verifier was built from key material that matches `candidate`.** A
/// buggy impl that lies here makes the SPKI cross-check a no-op, which
/// makes a buggy [`VerifyStrategy`] able to MITM the connection by
/// returning a prepared verifier sourced from outside the chain.
pub trait VerifierKeyMaterial<K> {
    fn matches(&self, candidate: K) -> subtle::Choice;
}

use crate::traits::cert::CertView;
use crate::traits::ed25519_verify::Ed25519VerifierProvider;
use crate::traits::rsa_verify::RsaVerifierProvider;
#[cfg(feature = "validity")]
use crate::traits::time::TimeSource;

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
    /// Build an Ed25519 variant. Hides the `PhantomData<R>` plumbing
    /// needed to thread `R` through the type signature when `feature = "rsa"`
    /// is off.
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
    /// Constant-time compare this verifier's stored key material against
    /// what `view` decodes to. The TLS stack runs this after the strategy
    /// returns so a buggy strategy can't pass off a verifier built from
    /// outside the chain.
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
    /// Constant-time compare this verifier's stored key material against
    /// what `view` decodes to. The TLS stack runs this after the strategy
    /// returns so a buggy strategy can't pass off a verifier built from
    /// outside the chain. Algorithm-mismatched arms return `Choice::from(0)`.
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
    /// Constructor — strategies build this from the slot they just wrote.
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
/// Strategies decide which cert chains they trust. They DO NOT do SAN
/// hostname matching — the TLS stack runs `verify_hostname` against
/// `chain[0]` after a successful strategy return, unconditionally.
/// The trait deliberately omits `hostname` from the signature so the
/// invariant is structural rather than disciplinary.
#[allow(dead_code)]
pub trait VerifyStrategy<E: Ed25519VerifierProvider, R: RsaVerifierProvider> {
    type Error: core::error::Error + Clone + PartialEq;

    /// Inspect `chain` and decide whether to accept it. On Ok, write the
    /// leaf's prepared verifier into `slot` (by value) and return a
    /// [`Trusted`] borrowing from it.
    ///
    /// `time` is `Option` because not every deployment has a clock.
    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<E, R>>,
        #[cfg(feature = "validity")] time: Option<&dyn TimeSource>,
    ) -> Result<Trusted<'slot, E, R>, Self::Error>;
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

    /// Minimal strategy: returns an Ed25519 `PreparedVerifier` built from
    /// the caller-supplied pubkey. Lets each test drive what the strategy
    /// "claims" the leaf pubkey is, so the cross-check against `chain[0]`'s
    /// actual pubkey can be exercised both ways.
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
