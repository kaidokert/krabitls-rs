//! Chain-validation strategy: trust a server cert chain that walks up to a
//! pinned anchor.
//!
//! [`PinnedRoots`] holds a small ledger of [`Anchor`]s and validates the
//! presented chain leaf→up: each issuer→subject signature is verified (reusing
//! [`verify_link`]), issuers must be CAs (basicConstraints + keyUsage), and the
//! walk accepts at the first cert whose SHA-256 fingerprint is pinned, or — for
//! a stored [`Anchor::Cert`] — when the topmost presented cert is signed by that
//! stored anchor's key. The walk is iterative (one link's frame reused per
//! step), so a deep chain costs the same stack as a shallow one; peak tracks the
//! most expensive single link's verify.
//!
//! Trust flows down from the pinned fingerprint / stored anchor through
//! signatures; there is no CA-bundle path building and no revocation (CRL/OCSP)
//! — the ledger is updated out-of-band.

use core::marker::PhantomData;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::traits::cert::{CertParseError, CertParser, CertView};
use crate::traits::verify_provider::VerifierBackend;
use crate::traits::verify_strategy::{
    CertChainView, Clock, LinkErr, NoClock, PrepareLeafErr, PreparedVerifier, Trusted,
    VerifyStrategy, prepare_leaf, verify_link,
};

/// A trust anchor in the on-board ledger.
#[derive(Debug, Clone, Copy)]
pub enum Anchor<'a> {
    /// SHA-256 fingerprint of the full DER of a cert the server transmits
    /// (`openssl x509 -fingerprint -sha256`). The walk accepts at the first
    /// presented cert whose fingerprint matches; certs above it are ignored.
    /// Identifies the cert *document*, so it changes when the anchor is
    /// renewed/reissued even with the same key — use [`Anchor::SpkiFingerprint`]
    /// to survive rotation.
    Fingerprint([u8; 32]),
    /// SHA-256 of a transmitted cert's `SubjectPublicKeyInfo` (RFC 7469 key
    /// pin). Identifies the public *key*, so it keeps matching across cert
    /// renewal, reissue, or cross-signing as long as the key is unchanged.
    SpkiFingerprint([u8; 32]),
    /// A stored anchor certificate (full DER, e.g. in flash). The topmost
    /// presented cert is verified against this cert's public key, so the anchor
    /// need not be transmitted — the durable posture for roots the server omits.
    Cert(&'a [u8]),
}

/// Default per-call chain-depth cap. Real chains rarely exceed 4; 8 leaves slack.
pub const DEFAULT_CHAIN_DEPTH: usize = 8;

/// Chain-validation [`VerifyStrategy`] anchored in a fingerprint/cert ledger.
///
/// `C` is the [`CertParser`], `K` the validity [`Clock`] (default [`NoClock`] =
/// validity skipped), `CAP` the max presented-chain depth. Construct with
/// [`PinnedRoots::new`] (or [`with_clock`](PinnedRoots::with_clock)) and plug in
/// via [`ClientParams::with_strategy`](crate::client::ClientParams::with_strategy).
#[derive(Debug, Clone)]
pub struct PinnedRoots<'a, C, K = NoClock, const CAP: usize = DEFAULT_CHAIN_DEPTH> {
    anchors: &'a [Anchor<'a>],
    clock: K,
    /// When `true`, the pinned anchor's own validity window is checked too. Off
    /// by default: an operator's pin is the trust statement, and an expired
    /// pinned anchor should not brick a device (WebPKI ignores trust-anchor
    /// expiry for the same reason). Below-anchor certs are always checked.
    enforce_anchor_expiry: bool,
    _parser: PhantomData<C>,
}

impl<'a, C, const CAP: usize> PinnedRoots<'a, C, NoClock, CAP> {
    /// Ledger-only strategy; cert validity windows are not checked (no clock).
    pub fn new(anchors: &'a [Anchor<'a>]) -> Self {
        Self {
            anchors,
            clock: NoClock,
            enforce_anchor_expiry: false,
            _parser: PhantomData,
        }
    }
}

impl<'a, C, K, const CAP: usize> PinnedRoots<'a, C, K, CAP> {
    /// Attach a validity [`Clock`] so below-anchor certs are `notBefore`/
    /// `notAfter`-checked. The clock's type fixes `K`.
    pub fn with_clock(anchors: &'a [Anchor<'a>], clock: K) -> Self {
        Self {
            anchors,
            clock,
            enforce_anchor_expiry: false,
            _parser: PhantomData,
        }
    }

    /// Also enforce the pinned anchor's own validity window. Off by default;
    /// only meaningful with a real clock. Enable when the anchor's expiry must
    /// be honored despite the self-brick risk.
    pub fn enforce_anchor_expiry(mut self, on: bool) -> Self {
        self.enforce_anchor_expiry = on;
        self
    }
}

/// Reasons [`PinnedRoots`] rejects a chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinnedRootsError {
    #[error("chain is empty")]
    EmptyChain,
    #[error("chain exceeded the configured depth cap")]
    ChainTooLong,
    #[error("cert parse failed: {0}")]
    Parse(#[from] CertParseError),
    #[error("per-link signature did not verify")]
    LinkSignatureInvalid,
    #[cfg(feature = "rsa")]
    #[error("intermediate cert outer signatureAlgorithm not recognized")]
    UnknownLinkSigAlg,
    #[cfg(feature = "rsa")]
    #[error("RSA verifier construction failed for an issuer cert")]
    RsaVerifierInvalid,
    #[cfg(feature = "mldsa")]
    #[error("ML-DSA verifier construction failed for an issuer cert")]
    MlDsaVerifierInvalid,
    #[error("a cert used as an issuer is not a CA (basicConstraints cA=FALSE / absent)")]
    IssuerNotCa,
    #[error("a cert used as an issuer has keyUsage without keyCertSign")]
    IssuerKeyUsageForbidsCertSign,
    #[error("issuer pathLenConstraint exceeded")]
    PathLenExceeded,
    #[error("no pinned anchor found in or above the presented chain")]
    UntrustedRoot,
    #[error("a cert's validity window check failed")]
    Validity,
    #[error("building the leaf verifier from its SPKI failed")]
    LeafVerifierInvalid,
}

impl From<LinkErr> for PinnedRootsError {
    fn from(e: LinkErr) -> Self {
        match e {
            LinkErr::LinkSignatureInvalid => PinnedRootsError::LinkSignatureInvalid,
            #[cfg(feature = "rsa")]
            LinkErr::UnknownLinkSigAlg => PinnedRootsError::UnknownLinkSigAlg,
            #[cfg(feature = "rsa")]
            LinkErr::RsaVerifierInvalid => PinnedRootsError::RsaVerifierInvalid,
            #[cfg(feature = "mldsa")]
            LinkErr::MlDsaVerifierInvalid => PinnedRootsError::MlDsaVerifierInvalid,
        }
    }
}

impl From<PrepareLeafErr> for PinnedRootsError {
    fn from(_: PrepareLeafErr) -> Self {
        PinnedRootsError::LeafVerifierInvalid
    }
}

impl<C: CertParser, K, const CAP: usize> PinnedRoots<'_, C, K, CAP> {
    /// True when `cert_der` matches a `Fingerprint` (full-cert SHA-256) or
    /// `SpkiFingerprint` (SPKI SHA-256) anchor. The SPKI hash is only computed
    /// when at least one such anchor is present, so a fingerprint-only ledger
    /// pays nothing.
    fn anchor_matches(&self, cert_der: &[u8]) -> Result<bool, PinnedRootsError> {
        if self
            .anchors
            .iter()
            .any(|a| matches!(a, Anchor::Fingerprint(_)))
        {
            let full = Sha256::digest(cert_der);
            for a in self.anchors {
                if let Anchor::Fingerprint(fp) = a {
                    if bool::from(full.as_slice().ct_eq(&fp[..])) {
                        return Ok(true);
                    }
                }
            }
        }
        if self
            .anchors
            .iter()
            .any(|a| matches!(a, Anchor::SpkiFingerprint(_)))
        {
            let spki = Sha256::digest(C::spki_der(cert_der)?);
            for a in self.anchors {
                if let Anchor::SpkiFingerprint(fp) = a {
                    if bool::from(spki.as_slice().ct_eq(&fp[..])) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// True when `cert_der` is byte-identical to a stored [`Anchor::Cert`].
    fn is_stored_cert_anchor(&self, cert_der: &[u8]) -> bool {
        self.anchors
            .iter()
            .any(|a| matches!(a, Anchor::Cert(d) if *d == cert_der))
    }

    /// Whether a cert on the path should have its validity window checked. A
    /// stored `Anchor::Cert` is exempt by default (the "expired pinned anchor
    /// must not brick a device" rule applies consistently whether the server
    /// transmits it or omits it) unless `enforce_anchor_expiry`; every other
    /// cert — including a fingerprint/SPKI-matched leaf or intermediate, which
    /// is a live transmitted cert — is always checked.
    fn check_validity_of(
        &self,
        cert_der: &[u8],
        view: &CertView<'_>,
    ) -> Result<(), PinnedRootsError>
    where
        K: Clock,
    {
        if self.enforce_anchor_expiry || !self.is_stored_cert_anchor(cert_der) {
            self.clock
                .check_validity(view)
                .map_err(|_| PinnedRootsError::Validity)?;
        }
        Ok(())
    }
}

/// Verify an issuer cert is eligible: a CA, with keyUsage permitting cert
/// signing, and pathLen room for `intermediates_below` CAs beneath it.
fn require_issuer_ca<C: CertParser>(
    issuer_der: &[u8],
    intermediates_below: usize,
) -> Result<(), PinnedRootsError> {
    let ca = C::parse_ca_constraints(issuer_der)?;
    if !ca.is_ca {
        return Err(PinnedRootsError::IssuerNotCa);
    }
    if ca.key_cert_sign == Some(false) {
        return Err(PinnedRootsError::IssuerKeyUsageForbidsCertSign);
    }
    if let Some(p) = ca.path_len {
        if (p as usize) < intermediates_below {
            return Err(PinnedRootsError::PathLenExceeded);
        }
    }
    Ok(())
}

impl<'a, C, K, P, const CAP: usize> VerifyStrategy<P> for PinnedRoots<'a, C, K, CAP>
where
    C: CertParser,
    K: Clock,
    P: VerifierBackend,
{
    type Error = PinnedRootsError;

    // Outlined so the walk's working set (cert parse + per-link verify) is a
    // sibling frame of `verify_server_flight` / the client-sign phase rather than
    // unioning into the handshake driver's frame — the walk shares, not adds to,
    // the handshake stack peak.
    #[inline(never)]
    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<P>>,
    ) -> Result<Trusted<'slot, P>, Self::Error> {
        let certs = chain.certs;
        if certs.is_empty() {
            return Err(PinnedRootsError::EmptyChain);
        }
        if certs.len() > CAP {
            return Err(PinnedRootsError::ChainTooLong);
        }

        // The leaf is prepared for the CertificateVerify path at the end; parse
        // it once and keep it (CertView is Copy, borrowing the flight buffer).
        let leaf_view = C::parse(certs[0])?;

        // Walk leaf→up holding only the current cert's view — no chain-wide
        // buffer. `child` is always the view of `certs[i]`.
        let mut child = leaf_view;
        let mut anchored = false;
        let mut i = 0usize;
        while i < certs.len() {
            if self.anchor_matches(certs[i])? {
                // Anchor reached: links below are already verified, its own
                // signature is irrelevant (the pin is the trust). A transmitted
                // fingerprint/SPKI-matched cert is still validity-checked; a
                // stored `Anchor::Cert` is exempt by default (`check_validity_of`).
                self.check_validity_of(certs[i], &child)?;
                anchored = true;
                break;
            }
            // Below the anchor: this cert must be time-valid.
            self.check_validity_of(certs[i], &child)?;
            if i + 1 == certs.len() {
                // Reached the top with no fingerprint match; a stored cert
                // anchor (if any) must vouch for this top cert.
                break;
            }
            let parent = C::parse(certs[i + 1])?;
            verify_link::<P>(&child, &parent)?;
            require_issuer_ca::<C>(certs[i + 1], i)?;
            child = parent;
            i += 1;
        }

        if !anchored {
            // `child` is the top presented cert. Accept if a stored anchor cert
            // signed it (a CA with pathLen room for the `i` intermediates below).
            // A malformed / unsupported / rejected anchor is skipped so a later
            // good anchor in the ledger still gets its chance — every step is
            // fail-soft (`is_ok`), never `?`, to keep the ledger order-independent.
            for anchor in self.anchors {
                let Anchor::Cert(anchor_der) = anchor else {
                    continue;
                };
                let Ok(anchor_view) = C::parse(anchor_der) else {
                    continue;
                };
                if require_issuer_ca::<C>(anchor_der, i).is_ok()
                    && verify_link::<P>(&child, &anchor_view).is_ok()
                    && self.check_validity_of(anchor_der, &anchor_view).is_ok()
                {
                    anchored = true;
                    break;
                }
            }
            if !anchored {
                return Err(PinnedRootsError::UntrustedRoot);
            }
        }

        *slot = Some(prepare_leaf::<P>(&leaf_view)?);
        Ok(Trusted::new(slot.as_ref().unwrap()))
    }
}

// Not `cert-der`-gated: the core walk tests exercise the default-shipped `tlv`
// parser too (via `--no-default-features`). Only the clock tests need `der`.
#[cfg(all(test, feature = "ecdsa"))]
mod tests {
    use super::*;
    use crate::backends::{DerCert, RustCrypto};
    use crate::traits::cert::CertParseError;
    #[cfg(feature = "cert-der")]
    use crate::traits::time::tests::FixedTime;
    #[cfg(feature = "cert-der")]
    use crate::traits::verify_strategy::Clocked;

    // A locally-minted ECDSA-P256 chain: ca0 (self-signed root) → ca1 … ca8
    // (intermediates) → leaf. Regenerate via testdata/certs_chain (openssl).
    const ROOT: &[u8] = include_bytes!("../../../testdata/certs_chain/ca0.der");
    const CA1: &[u8] = include_bytes!("../../../testdata/certs_chain/ca1.der");
    const CA2: &[u8] = include_bytes!("../../../testdata/certs_chain/ca2.der");
    const CA3: &[u8] = include_bytes!("../../../testdata/certs_chain/ca3.der");
    const CA4: &[u8] = include_bytes!("../../../testdata/certs_chain/ca4.der");
    const CA5: &[u8] = include_bytes!("../../../testdata/certs_chain/ca5.der");
    const CA6: &[u8] = include_bytes!("../../../testdata/certs_chain/ca6.der");
    const CA7: &[u8] = include_bytes!("../../../testdata/certs_chain/ca7.der");
    const CA8: &[u8] = include_bytes!("../../../testdata/certs_chain/ca8.der");
    const LEAF: &[u8] = include_bytes!("../../../testdata/certs_chain/leaf.der");
    // Forgery: evil_leaf (CA:FALSE, signed by ca8) is used to sign `forged`.
    const EVIL_LEAF: &[u8] = include_bytes!("../../../testdata/certs_chain/evil_leaf.der");
    const FORGED: &[u8] = include_bytes!("../../../testdata/certs_chain/forged.der");
    // pathLen: p0 (CA, pathlen:0, under root) → cx (CA) → leafx.
    const PATHLEN0: &[u8] = include_bytes!("../../../testdata/certs_chain/pathlen0_ca.der");
    const CX: &[u8] = include_bytes!("../../../testdata/certs_chain/cx_ca.der");
    const LEAFX: &[u8] = include_bytes!("../../../testdata/certs_chain/leafx.der");
    // The root reissued from the SAME key (new serial + validity): different
    // full-cert bytes, identical SubjectPublicKeyInfo.
    const ROOT_RENEWED: &[u8] = include_bytes!("../../../testdata/certs_chain/ca0_renewed.der");
    // An intermediate with a CRITICAL nameConstraints (an extension the validator
    // does not process) + a leaf issued under it.
    const CRIT_CA: &[u8] = include_bytes!("../../../testdata/certs_chain/crit_ca.der");
    const CRIT_LEAF: &[u8] = include_bytes!("../../../testdata/certs_chain/crit_leaf.der");

    /// Wire order (leaf first) for the full 10-deep chain including the root.
    const FULL_CHAIN: [&[u8]; 10] = [LEAF, CA8, CA7, CA6, CA5, CA4, CA3, CA2, CA1, ROOT];
    /// Same, but the root is not transmitted (the AWS-shaped case).
    const NO_ROOT_CHAIN: [&[u8]; 9] = [LEAF, CA8, CA7, CA6, CA5, CA4, CA3, CA2, CA1];

    fn fp(der: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(der));
        out
    }

    fn spki_fp(der: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(DerCert::spki_der(der).expect("spki")));
        out
    }

    fn run<const CAP: usize>(
        anchors: &[Anchor<'_>],
        chain: &[&[u8]],
    ) -> Result<(), PinnedRootsError> {
        let pr: PinnedRoots<DerCert, NoClock, CAP> = PinnedRoots::new(anchors);
        let mut slot: Option<PreparedVerifier<RustCrypto>> = None;
        VerifyStrategy::<RustCrypto>::verify_chain(&pr, CertChainView { certs: chain }, &mut slot)
            .map(|_| ())
    }

    #[test]
    fn parse_ca_constraints_reads_basic_constraints_and_key_usage() {
        let root = DerCert::parse_ca_constraints(ROOT).unwrap();
        assert!(root.is_ca);
        assert_eq!(root.key_cert_sign, Some(true));
        let leaf = DerCert::parse_ca_constraints(LEAF).unwrap();
        assert!(!leaf.is_ca);
        assert_eq!(leaf.key_cert_sign, Some(false));
        let p0 = DerCert::parse_ca_constraints(PATHLEN0).unwrap();
        assert!(p0.is_ca);
        assert_eq!(p0.path_len, Some(0));
    }

    // A stored anchor cert parsed from a (here `&'static`) slice serves as
    // `verify_link`'s parent unchanged, so the top transmitted cert verifies
    // against a root the server never sent.
    #[test]
    fn cert_anchor_from_flash_verifies_top_of_untransmitted_root_chain() {
        let anchors = [Anchor::Cert(ROOT)];
        assert!(run::<10>(&anchors, &NO_ROOT_CHAIN).is_ok());
    }

    #[test]
    fn cert_anchor_accepts_root_transmitted_and_omitted() {
        // One stored root anchors both the root-omitted presentation (verify the
        // top intermediate against it) and the full chain that also transmits the
        // root. (The same-key reissue case is covered by the SPKI-renewal test.)
        assert!(run::<10>(&[Anchor::Cert(ROOT)], &NO_ROOT_CHAIN).is_ok());
        assert!(run::<10>(&[Anchor::Cert(ROOT)], &FULL_CHAIN).is_ok());
    }

    #[test]
    fn fingerprint_root_accepts_full_chain() {
        assert!(run::<10>(&[Anchor::Fingerprint(fp(ROOT))], &FULL_CHAIN).is_ok());
    }

    #[test]
    fn spki_der_matches_openssl_pubkey_hash() {
        // `openssl x509 -pubkey | openssl pkey -pubin -outform DER | dgst -sha256`
        // over ca0 — confirms spki_der extracts the exact SubjectPublicKeyInfo.
        let expected: [u8; 32] =
            crate::hex_decode("3ce71d66d717437828a5b2098957db83042822c6d574c1b1d5e11cd3bea87245");
        assert_eq!(spki_fp(ROOT), expected);
    }

    #[test]
    fn spki_fingerprint_root_accepts_full_chain() {
        assert!(run::<10>(&[Anchor::SpkiFingerprint(spki_fp(ROOT))], &FULL_CHAIN).is_ok());
    }

    #[test]
    fn spki_pin_survives_root_renewal_but_full_cert_pin_does_not() {
        // Same chain, but the top cert is the reissued root (same key, new bytes).
        let renewed: [&[u8]; 10] = [LEAF, CA8, CA7, CA6, CA5, CA4, CA3, CA2, CA1, ROOT_RENEWED];
        // SPKI pin of the ORIGINAL root still accepts — the key didn't move.
        assert!(run::<10>(&[Anchor::SpkiFingerprint(spki_fp(ROOT))], &renewed).is_ok());
        // Full-cert pin of the original root no longer matches the reissued bytes.
        assert_eq!(
            run::<10>(&[Anchor::Fingerprint(fp(ROOT))], &renewed),
            Err(PinnedRootsError::UntrustedRoot)
        );
    }

    #[test]
    fn fingerprint_intermediate_accepts_and_ignores_certs_above() {
        // Pin ca8; a two-cert presentation stops at ca8 after one link.
        assert!(run::<8>(&[Anchor::Fingerprint(fp(CA8))], &[LEAF, CA8]).is_ok());
    }

    #[test]
    fn leaf_fingerprint_accepts_with_garbage_above_and_zero_links() {
        // Degenerate leaf-pin: the first-match rule
        // accepts at the leaf before parsing or verifying anything above it.
        let garbage: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert!(run::<8>(&[Anchor::Fingerprint(fp(LEAF))], &[LEAF, garbage]).is_ok());
    }

    #[test]
    fn non_ca_issuer_is_rejected_the_basic_constraints_forgery() {
        // forged ← evil_leaf(CA:FALSE) ← ca8 … ← root. The link signatures all
        // verify; the CA-bit check is what stops a server leaf minting sub-certs.
        let chain = [
            FORGED, EVIL_LEAF, CA8, CA7, CA6, CA5, CA4, CA3, CA2, CA1, ROOT,
        ];
        assert_eq!(
            run::<12>(&[Anchor::Fingerprint(fp(ROOT))], &chain),
            Err(PinnedRootsError::IssuerNotCa)
        );
    }

    #[test]
    fn pathlen_constraint_is_enforced() {
        // p0 permits 0 intermediates below it, but cx sits between it and leafx.
        let chain = [LEAFX, CX, PATHLEN0, ROOT];
        assert_eq!(
            run::<8>(&[Anchor::Fingerprint(fp(ROOT))], &chain),
            Err(PinnedRootsError::PathLenExceeded)
        );
    }

    #[test]
    fn issuer_with_unrecognized_critical_extension_is_rejected() {
        // crit_ca carries a critical nameConstraints the validator can't process;
        // RFC 5280 §4.2 requires rejecting it, not silently ignoring the limit.
        assert_eq!(
            DerCert::parse_ca_constraints(CRIT_CA),
            Err(CertParseError::UnhandledCriticalExtension)
        );
        assert_eq!(
            run::<10>(
                &[Anchor::Fingerprint(fp(ROOT))],
                &[CRIT_LEAF, CRIT_CA, ROOT]
            ),
            Err(PinnedRootsError::Parse(
                CertParseError::UnhandledCriticalExtension
            ))
        );
    }

    #[test]
    fn unpinned_chain_is_rejected() {
        assert_eq!(
            run::<10>(&[Anchor::Fingerprint([0x11; 32])], &FULL_CHAIN),
            Err(PinnedRootsError::UntrustedRoot)
        );
    }

    #[test]
    fn chain_exceeding_depth_cap_is_rejected() {
        assert_eq!(
            run::<8>(&[Anchor::Fingerprint(fp(ROOT))], &FULL_CHAIN),
            Err(PinnedRootsError::ChainTooLong)
        );
    }

    #[test]
    fn tampered_intermediate_is_rejected() {
        let mut ca4 = CA4.to_vec();
        ca4[40] ^= 0x01;
        let chain: [&[u8]; 9] = [LEAF, CA8, CA7, CA6, CA5, &ca4, CA3, CA2, CA1];
        assert!(run::<10>(&[Anchor::Cert(ROOT)], &chain).is_err());
    }

    #[cfg(feature = "cert-der")]
    #[test]
    fn clocked_rejects_expired_below_anchor_but_default_skips_anchor() {
        // The fixtures are valid ~2026..2126; 1.8e9 ≈ 2027 (in window), 6e9 ≈
        // 2160 (past notAfter).
        let anchors = [Anchor::Cert(ROOT)];
        let in_window: PinnedRoots<DerCert, _, 10> =
            PinnedRoots::with_clock(&anchors, Clocked(FixedTime(1_800_000_000)));
        let expired: PinnedRoots<DerCert, _, 10> =
            PinnedRoots::with_clock(&anchors, Clocked(FixedTime(6_000_000_000)));
        let mut slot: Option<PreparedVerifier<RustCrypto>> = None;
        assert!(
            VerifyStrategy::<RustCrypto>::verify_chain(
                &in_window,
                CertChainView {
                    certs: &NO_ROOT_CHAIN
                },
                &mut slot,
            )
            .is_ok()
        );
        let mut slot2: Option<PreparedVerifier<RustCrypto>> = None;
        assert_eq!(
            VerifyStrategy::<RustCrypto>::verify_chain(
                &expired,
                CertChainView {
                    certs: &NO_ROOT_CHAIN
                },
                &mut slot2,
            )
            .map(|_| ()),
            Err(PinnedRootsError::Validity)
        );
    }

    #[test]
    fn multi_anchor_ledger_is_order_independent() {
        // A malformed / unsupported Anchor::Cert must be skipped, not abort the
        // whole verification — a later good anchor still matches, either order.
        const BOGUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        assert!(run::<10>(&[Anchor::Cert(BOGUS), Anchor::Cert(ROOT)], &NO_ROOT_CHAIN).is_ok());
        assert!(run::<10>(&[Anchor::Cert(ROOT), Anchor::Cert(BOGUS)], &NO_ROOT_CHAIN).is_ok());
    }

    #[cfg(feature = "cert-der")]
    #[test]
    fn leaf_fingerprint_pin_still_validity_checks_the_leaf_under_a_clock() {
        // A pinned end-entity leaf is a live transmitted cert: with a clock its
        // expiry IS checked (unlike a stored Cert anchor, which is exempt).
        let anchors = [Anchor::Fingerprint(fp(LEAF))];
        let expired: PinnedRoots<DerCert, _, 10> =
            PinnedRoots::with_clock(&anchors, Clocked(FixedTime(6_000_000_000)));
        let mut slot: Option<PreparedVerifier<RustCrypto>> = None;
        assert_eq!(
            VerifyStrategy::<RustCrypto>::verify_chain(
                &expired,
                CertChainView { certs: &FULL_CHAIN },
                &mut slot,
            )
            .map(|_| ()),
            Err(PinnedRootsError::Validity)
        );
        let in_window: PinnedRoots<DerCert, _, 10> =
            PinnedRoots::with_clock(&anchors, Clocked(FixedTime(1_800_000_000)));
        let mut slot2: Option<PreparedVerifier<RustCrypto>> = None;
        assert!(
            VerifyStrategy::<RustCrypto>::verify_chain(
                &in_window,
                CertChainView { certs: &FULL_CHAIN },
                &mut slot2,
            )
            .is_ok()
        );
    }
}
