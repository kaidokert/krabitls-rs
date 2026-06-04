//! Cert-parsing abstraction for the TLS 1.3 server flight.
//!
//! Krabitls's locked profile only needs three things out of the server's
//! self-signed certificate: the bytes that were signed (`tbs`), the signature
//! itself, and the SubjectPublicKey to verify them with. We abstract that
//! with a one-method trait so the backend (today: the `der` crate; tomorrow:
//! maybe something hand-rolled) can be swapped without touching the
//! verification pipeline in `server_flight.rs`.

/// Trait the verification pipeline uses to extract the byte slices it needs
/// from an X.509 cert.
pub trait CertParser {
    /// Parse a DER-encoded X.509 certificate and return borrows into
    /// `cert_der`. Implementations should validate enough structure that:
    ///
    /// * `tbs` is exactly the byte range the signature was computed over
    ///   (i.e., the full TBSCertificate TLV including its outer SEQUENCE
    ///   header and length);
    /// * pubkey + signature slices are stripped of any BIT STRING
    ///   `unused_bits` prefix and are the raw payloads consumers expect.
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError>;
}

/// Parsed view of a self-signed X.509 cert. Variants reflect the public-key
/// algorithm carried by the SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy)]
pub enum CertView<'a> {
    /// Ed25519 server identity (RFC 8410). The standard krabitls profile.
    Ed25519 {
        /// TBSCertificate bytes the cert's signature was computed over.
        tbs: &'a [u8],
        /// 64-byte Ed25519 signature.
        signature: &'a [u8; 64],
        /// 32-byte Ed25519 SubjectPublicKey.
        pubkey: &'a [u8; 32],
        /// Inner DER bytes of the SubjectAltName extension's `extnValue`
        /// OCTET STRING, i.e. the `GeneralNames` SEQUENCE *content*. `None`
        /// if the cert doesn't carry a SAN extension. Use
        /// [`crate::identity::san_dns_names`] to iterate the dNSName entries.
        san: Option<&'a [u8]>,
        /// DER bytes of the `Validity SEQUENCE { notBefore, notAfter }`
        /// from TBSCertificate. Always captured (cheap); the actual
        /// notBefore / notAfter dates are parsed on demand by
        /// [`crate::identity::verify_validity`] under `feature = "validity"`.
        validity_der: &'a [u8],
    },
}

impl<'a> CertView<'a> {
    /// Borrow the bytes that were signed.
    pub fn tbs(&self) -> &'a [u8] {
        match self {
            CertView::Ed25519 { tbs, .. } => tbs,
        }
    }

    /// Borrow the SubjectAltName extension content if present.
    pub fn san(&self) -> Option<&'a [u8]> {
        match self {
            CertView::Ed25519 { san, .. } => *san,
        }
    }

    /// Borrow the raw DER bytes of the `Validity` SEQUENCE
    /// (`SEQUENCE { notBefore, notAfter }`). The
    /// [`crate::identity::verify_validity`] helper (under
    /// `feature = "validity"`) parses these into Unix-epoch seconds and
    /// compares against a caller-supplied [`crate::traits::TimeSource`].
    pub fn validity_der(&self) -> &'a [u8] {
        match self {
            CertView::Ed25519 { validity_der, .. } => validity_der,
        }
    }
}

/// Reasons cert parsing may fail. Deliberately small — debugging a wire-format
/// problem doesn't need a taxonomy of every ASN.1 sin.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertParseError {
    /// Underlying DER parse / length / tag error.
    Malformed,
    /// `Ed25519` `SubjectPublicKey` wasn't 32 bytes.
    WrongPubkeyLength,
    /// Cert signature wasn't 64 bytes (Ed25519).
    WrongSignatureLength,
    /// A `BIT STRING` came in with non-zero unused-bits prefix (we don't
    /// expect that for cert signatures or Ed25519 keys).
    BitStringHasUnusedBits,
    /// Bytes left over after the outer SEQUENCE.
    TrailingBytes,
    /// The leaf's `SubjectPublicKeyInfo` `AlgorithmIdentifier` names an OID
    /// we don't recognize. The known set is Ed25519 (`1.3.101.112`).
    /// The cert's *outer* `signatureAlgorithm` (issuer's signature) is not
    /// interpreted at parse time, so unknown values there don't trigger
    /// this variant; they only matter when self-sig verification runs.
    WrongAlgorithmOid,
    /// An Ed25519 `AlgorithmIdentifier` carried a non-empty `parameters`
    /// field (RFC 8410 §3 requires it absent).
    AlgorithmHasParameters,
    /// The outer `Certificate.signatureAlgorithm` and `TBSCertificate.signature`
    /// don't carry identical bytes. RFC 5280 §4.1.1.2 / §4.1.2.3 require them
    /// to match exactly.
    SignatureAlgorithmMismatch,
    /// `TBSCertificate.version` is present but doesn't decode to `v3` (the
    /// only version this client accepts), or absent (DER omits the field
    /// only for the default `v1`, which this client doesn't accept).
    UnsupportedCertVersion,
}
