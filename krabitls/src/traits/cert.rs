//! Cert-parsing abstraction for the TLS 1.3 server flight.

/// Extract the X.509 fields needed by server-flight verification.
pub trait CertParser {
    /// Parse a DER-encoded X.509 certificate and return borrows into `cert_der`.
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError>;
}

/// Parsed view of a self-signed X.509 cert.
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
        /// Inner DER bytes of the SubjectAltName `GeneralNames` SEQUENCE.
        san: Option<&'a [u8]>,
        /// DER bytes of the `Validity SEQUENCE { notBefore, notAfter }`.
        validity_der: &'a [u8],
    },
    /// RSA server identity (RFC 3279). Available with `feature = "rsa"`.
    #[cfg(feature = "rsa")]
    Rsa {
        /// TBSCertificate bytes the cert's signature was computed over.
        tbs: &'a [u8],
        /// RSA signature bytes (size equals the RSA modulus); padding/hash
        /// scheme identified by `outer_sig_alg`.
        signature: &'a [u8],
        /// Padding scheme used to sign `tbs`.
        outer_sig_alg: RsaCertSigAlg,
        /// RSA modulus, big-endian. Length is the RSA key size in bytes:
        /// 128 for RSA-1024, 256 for RSA-2048, etc.
        modulus: &'a [u8],
        /// RSA public exponent. Both common values (3 and 65537) fit in u32.
        exponent: u32,
        /// SubjectAltName extension content; same shape and meaning as the
        /// Ed25519 variant's `san` field.
        san: Option<&'a [u8]>,
        /// Validity-SEQUENCE DER bytes; same as the Ed25519 variant.
        validity_der: &'a [u8],
    },
}

/// RSA cert outer-signature padding scheme. Only sha256-based variants are
/// recognized; krabitls doesn't advertise other hashes.
#[cfg(feature = "rsa")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaCertSigAlg {
    /// `sha256WithRSAEncryption` (PKCS#1-v1.5, OID 1.2.840.113549.1.1.11).
    /// Compiled out under `feature = "rsa_pss_only"` — that build accepts
    /// PSS-signed cert outer sigs only.
    #[cfg(not(feature = "rsa_pss_only"))]
    Pkcs1v15Sha256,
    /// `rsassa-pss` with SHA-256 + MGF1-SHA-256 + 32-byte salt
    /// (OID 1.2.840.113549.1.1.10).
    PssSha256,
}

impl<'a> CertView<'a> {
    /// Borrow the bytes that were signed.
    pub fn tbs(&self) -> &'a [u8] {
        match self {
            CertView::Ed25519 { tbs, .. } => tbs,
            #[cfg(feature = "rsa")]
            CertView::Rsa { tbs, .. } => tbs,
        }
    }

    /// Borrow the SubjectAltName extension content if present.
    pub fn san(&self) -> Option<&'a [u8]> {
        match self {
            CertView::Ed25519 { san, .. } => *san,
            #[cfg(feature = "rsa")]
            CertView::Rsa { san, .. } => *san,
        }
    }

    /// Borrow the raw DER bytes of the `Validity` SEQUENCE.
    pub fn validity_der(&self) -> &'a [u8] {
        match self {
            CertView::Ed25519 { validity_der, .. } => validity_der,
            #[cfg(feature = "rsa")]
            CertView::Rsa { validity_der, .. } => validity_der,
        }
    }
}

/// Reasons cert parsing may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertParseError {
    /// Underlying DER parse / length / tag error.
    Malformed,
    /// `Ed25519` `SubjectPublicKey` wasn't 32 bytes.
    WrongPubkeyLength,
    /// Cert signature wasn't 64 bytes (Ed25519) or didn't match the RSA modulus length.
    WrongSignatureLength,
    /// A `BIT STRING` came in with non-zero unused-bits prefix (we don't
    /// expect that for cert signatures, Ed25519 keys, or RSA pubkey blobs).
    BitStringHasUnusedBits,
    /// Bytes left over after the outer SEQUENCE.
    TrailingBytes,
    /// The leaf's `SubjectPublicKeyInfo` `AlgorithmIdentifier` names an OID
    /// we don't recognize. The known set is Ed25519 (`1.3.101.112`, always)
    /// and `rsaEncryption` (`1.2.840.113549.1.1.1`, under `feature = "rsa"`).
    /// The cert's *outer* `signatureAlgorithm` (issuer's signature) is not
    /// interpreted at parse time, so unknown values there don't trigger
    /// this variant; they only matter when self-sig verification runs.
    WrongAlgorithmOid,
    /// `AlgorithmIdentifier.parameters` violated the spec for the algorithm:
    /// Ed25519 requires absent (RFC 8410 §3); `rsaEncryption` requires an
    /// explicit NULL TLV per RFC 3279 §2.3.1. Any other shape — Ed25519 with
    /// a non-empty parameter, RSA with absent / non-NULL / extra bytes —
    /// surfaces here.
    AlgorithmHasParameters,
    /// The outer `Certificate.signatureAlgorithm` and `TBSCertificate.signature`
    /// don't carry identical bytes. RFC 5280 §4.1.1.2 / §4.1.2.3 require them
    /// to match exactly.
    SignatureAlgorithmMismatch,
    /// `TBSCertificate.version` is present but doesn't decode to `v3` (the
    /// only version this client accepts), or absent (DER omits the field
    /// only for the default `v1`, which this client doesn't accept).
    UnsupportedCertVersion,
    /// RSA pubkey SPKI bit string didn't decode as `SEQUENCE { INTEGER
    /// modulus, INTEGER exponent }` with valid DER framing — wrong tags,
    /// truncated body, non-minimal INTEGER encoding (redundant leading
    /// zeros), exponent that doesn't fit in `u32`, or exponent that's
    /// even or less than 3 (RFC 8017 §3.1).
    #[cfg(feature = "rsa")]
    BadRsaPubkey,
    /// RSA modulus length wasn't in the 128 B (RSA-1024) or 256 B
    /// (RSA-2048) set this crate's `rsa_verify` dispatch supports.
    #[cfg(feature = "rsa")]
    UnsupportedRsaKeySize,
}

impl core::fmt::Display for CertParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Malformed => "malformed cert DER",
            Self::WrongPubkeyLength => "Ed25519 SubjectPublicKey was not 32 bytes",
            Self::WrongSignatureLength => "cert signature length did not match the algorithm",
            Self::BitStringHasUnusedBits => "BIT STRING had non-zero unused-bits prefix",
            Self::TrailingBytes => "bytes left over after the outer SEQUENCE",
            Self::WrongAlgorithmOid => "SubjectPublicKeyInfo named an unsupported algorithm OID",
            Self::AlgorithmHasParameters => {
                "AlgorithmIdentifier.parameters violated the per-algorithm rule"
            }
            Self::SignatureAlgorithmMismatch => {
                "outer signatureAlgorithm did not match TBSCertificate.signature"
            }
            Self::UnsupportedCertVersion => "TBSCertificate.version was not v3",
            #[cfg(feature = "rsa")]
            Self::BadRsaPubkey => "RSA pubkey SPKI did not decode as SEQUENCE { INTEGER, INTEGER }",
            #[cfg(feature = "rsa")]
            Self::UnsupportedRsaKeySize => {
                "RSA modulus length was not 128 B (RSA-1024) or 256 B (RSA-2048)"
            }
        };
        f.write_str(s)
    }
}

impl core::error::Error for CertParseError {}
