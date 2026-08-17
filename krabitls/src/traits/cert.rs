//! Cert-parsing abstraction for the TLS 1.3 server flight.

/// Extract the X.509 fields needed by server-flight verification.
pub trait CertParser {
    /// Parse a DER-encoded X.509 certificate and return borrows into `cert_der`.
    fn parse<'a>(cert_der: &'a [u8]) -> Result<CertView<'a>, CertParseError>;

    /// Extract the issuer-eligibility fields a chain validator needs:
    /// basicConstraints (`cA`, `pathLenConstraint`) and keyUsage `keyCertSign`.
    /// An absent extension yields the conservative default (`is_ca = false`,
    /// `key_cert_sign = None`) so a cert that doesn't assert CA rights can't
    /// serve as a chain issuer. Only compiled for the chain-verify strategy.
    ///
    /// A default-provided body returns `is_ca = false` so a `CertParser` that
    /// doesn't override it fails every chain closed rather than breaking the
    /// build — enabling `chain-verify` (which Cargo may unify onto a downstream
    /// impl) stays additive. The bundled `DerCert` overrides it.
    #[cfg(feature = "chain-verify")]
    fn parse_ca_constraints(_cert_der: &[u8]) -> Result<CaConstraints, CertParseError> {
        Ok(CaConstraints::default())
    }

    /// Return the raw `SubjectPublicKeyInfo` DER (the full `SEQUENCE { algorithm,
    /// subjectPublicKey }` TLV) so a chain validator can pin an anchor by its
    /// SPKI SHA-256 — a key fingerprint (RFC 7469 shape) that survives cert
    /// renewal/reissue, unlike a full-cert-DER fingerprint. Only compiled for the
    /// chain-verify strategy.
    ///
    /// The default body errors (no SPKI extracted → SPKI pins never match),
    /// keeping the feature additive for a non-overriding `CertParser`. The
    /// bundled `DerCert` overrides it.
    #[cfg(feature = "chain-verify")]
    fn spki_der(_cert_der: &[u8]) -> Result<&[u8], CertParseError> {
        Err(CertParseError::Malformed)
    }
}

/// Issuer-eligibility fields read from a cert's X.509v3 extensions, used by
/// [`PinnedRoots`](crate::backends::PinnedRoots) to reject a non-CA (or
/// pathLen-exhausted) cert being used as a chain issuer.
#[cfg(feature = "chain-verify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaConstraints {
    /// basicConstraints `cA` (DEFAULT FALSE — `false` when absent).
    pub is_ca: bool,
    /// basicConstraints `pathLenConstraint`, if present. Bounds how many
    /// intermediates may appear below this CA.
    pub path_len: Option<u32>,
    /// keyUsage `keyCertSign` bit. `None` when no keyUsage extension is present
    /// (unconstrained); `Some(false)` when keyUsage is present but the bit is
    /// not asserted (issuance forbidden).
    pub key_cert_sign: Option<bool>,
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
        /// scheme identified by `outer_sig_alg` (or `None` if the outer
        /// algorithm isn't one krabitls recognizes — see field below).
        signature: &'a [u8],
        /// Padding scheme used to sign `tbs`, or `None` if the cert's outer
        /// signatureAlgorithm OID isn't `sha256WithRSAEncryption` /
        /// `rsassa-pss`. Real-world chains often have RSA leaves signed
        /// by an issuer using ECDSA / RSA-SHA384 / etc.; parser stays
        /// permissive so those certs reach `verify_certificate_verify`
        /// for CV-only checks. Self-sig / per-link verify (inside the
        /// configured [`VerifyStrategy`](crate::traits::verify_strategy::VerifyStrategy))
        /// errors on `None`.
        outer_sig_alg: Option<RsaCertSigAlg>,
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
    /// ML-DSA server identity (FIPS 204). Available with `feature = "mldsa"`.
    /// The parameter set (ML-DSA-44/65/87) is implicit in the pubkey/signature
    /// byte lengths, so — unlike the RSA variant — no outer-sig discriminator
    /// is needed: cert signatures are always pure ML-DSA over the TBS.
    #[cfg(feature = "mldsa")]
    MlDsa {
        /// TBSCertificate bytes the cert's signature was computed over.
        tbs: &'a [u8],
        /// ML-DSA signature bytes (2420/3309/4627 B by parameter set).
        signature: &'a [u8],
        /// Raw ML-DSA SubjectPublicKey (1312/1952/2592 B by parameter set).
        pubkey: &'a [u8],
        /// SubjectAltName extension content; same shape as the other variants.
        san: Option<&'a [u8]>,
        /// Validity-SEQUENCE DER bytes; same as the other variants.
        validity_der: &'a [u8],
    },
    /// ECDSA P-256 server identity (RFC 5480). Available with `feature = "ecdsa"`.
    /// The curve (and thus the CertificateVerify hash) is fixed by the variant;
    /// like ML-DSA, no outer-sig discriminator is carried.
    #[cfg(feature = "ecdsa")]
    EcdsaP256 {
        /// TBSCertificate bytes the cert's signature was computed over.
        tbs: &'a [u8],
        /// Cert outer signature, a DER `ECDSA-Sig-Value`.
        signature: &'a [u8],
        /// 65-byte SEC1 uncompressed point (`0x04 || X || Y`).
        pubkey: &'a [u8],
        /// RSA padding scheme when this cert's outer signature is RSA, i.e. an
        /// ECDSA leaf/intermediate signed by an RSA issuer — a real chain shape
        /// the ECDSA SPKI kind alone doesn't reveal. `None` for the conventional
        /// ECDSA-issuer case (issuer curve fixes the hash at verify time).
        #[cfg(feature = "rsa")]
        outer_sig_alg: Option<RsaCertSigAlg>,
        /// SubjectAltName extension content; same shape as the other variants.
        san: Option<&'a [u8]>,
        /// Validity-SEQUENCE DER bytes; same as the other variants.
        validity_der: &'a [u8],
    },
    /// ECDSA P-384 server identity (RFC 5480). Available with `feature = "ecdsa"`.
    #[cfg(feature = "ecdsa")]
    EcdsaP384 {
        /// TBSCertificate bytes the cert's signature was computed over.
        tbs: &'a [u8],
        /// Cert outer signature, a DER `ECDSA-Sig-Value`.
        signature: &'a [u8],
        /// 97-byte SEC1 uncompressed point (`0x04 || X || Y`).
        pubkey: &'a [u8],
        /// Outer RSA padding scheme when signed by an RSA issuer; see
        /// [`CertView::EcdsaP256`].
        #[cfg(feature = "rsa")]
        outer_sig_alg: Option<RsaCertSigAlg>,
        /// SubjectAltName extension content; same shape as the other variants.
        san: Option<&'a [u8]>,
        /// Validity-SEQUENCE DER bytes; same as the other variants.
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
            #[cfg(feature = "mldsa")]
            CertView::MlDsa { tbs, .. } => tbs,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP256 { tbs, .. } => tbs,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP384 { tbs, .. } => tbs,
        }
    }

    /// Borrow the SubjectAltName extension content if present.
    pub fn san(&self) -> Option<&'a [u8]> {
        match self {
            CertView::Ed25519 { san, .. } => *san,
            #[cfg(feature = "rsa")]
            CertView::Rsa { san, .. } => *san,
            #[cfg(feature = "mldsa")]
            CertView::MlDsa { san, .. } => *san,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP256 { san, .. } => *san,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP384 { san, .. } => *san,
        }
    }

    /// Borrow the raw DER bytes of the `Validity` SEQUENCE.
    pub fn validity_der(&self) -> &'a [u8] {
        match self {
            CertView::Ed25519 { validity_der, .. } => validity_der,
            #[cfg(feature = "rsa")]
            CertView::Rsa { validity_der, .. } => validity_der,
            #[cfg(feature = "mldsa")]
            CertView::MlDsa { validity_der, .. } => validity_der,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP256 { validity_der, .. } => validity_der,
            #[cfg(feature = "ecdsa")]
            CertView::EcdsaP384 { validity_der, .. } => validity_der,
        }
    }
}

/// Reasons cert parsing may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum CertParseError {
    /// Underlying DER parse / length / tag error.
    #[error("malformed cert DER")]
    Malformed,
    /// `Ed25519` `SubjectPublicKey` wasn't 32 bytes.
    #[error("Ed25519 SubjectPublicKey was not 32 bytes")]
    WrongPubkeyLength,
    /// Cert signature wasn't 64 bytes (Ed25519) or didn't match the RSA modulus length.
    #[error("cert signature length did not match the algorithm")]
    WrongSignatureLength,
    /// A `BIT STRING` came in with non-zero unused-bits prefix (we don't
    /// expect that for cert signatures, Ed25519 keys, or RSA pubkey blobs).
    #[error("BIT STRING had non-zero unused-bits prefix")]
    BitStringHasUnusedBits,
    /// Bytes left over after the outer SEQUENCE.
    #[error("bytes left over after the outer SEQUENCE")]
    TrailingBytes,
    /// The leaf's `SubjectPublicKeyInfo` `AlgorithmIdentifier` names an OID
    /// we don't recognize. The known set is Ed25519 (`1.3.101.112`, always)
    /// and `rsaEncryption` (`1.2.840.113549.1.1.1`, under `feature = "rsa"`).
    /// The cert's *outer* `signatureAlgorithm` (issuer's signature) is not
    /// interpreted at parse time, so unknown values there don't trigger
    /// this variant; they only matter when self-sig verification runs.
    #[error("SubjectPublicKeyInfo named an unsupported algorithm OID")]
    WrongAlgorithmOid,
    /// `AlgorithmIdentifier.parameters` violated the spec for the algorithm:
    /// Ed25519 requires absent (RFC 8410 §3); `rsaEncryption` requires an
    /// explicit NULL TLV per RFC 3279 §2.3.1. Any other shape — Ed25519 with
    /// a non-empty parameter, RSA with absent / non-NULL / extra bytes —
    /// surfaces here.
    #[error("AlgorithmIdentifier.parameters violated the per-algorithm rule")]
    AlgorithmHasParameters,
    /// The outer `Certificate.signatureAlgorithm` and `TBSCertificate.signature`
    /// don't carry identical bytes. RFC 5280 §4.1.1.2 / §4.1.2.3 require them
    /// to match exactly.
    #[error("outer signatureAlgorithm did not match TBSCertificate.signature")]
    SignatureAlgorithmMismatch,
    /// `TBSCertificate.version` is present but doesn't decode to `v3` (the
    /// only version this client accepts), or absent (DER omits the field
    /// only for the default `v1`, which this client doesn't accept).
    #[error("TBSCertificate.version was not v3")]
    UnsupportedCertVersion,
    /// RSA pubkey SPKI bit string didn't decode as `SEQUENCE { INTEGER
    /// modulus, INTEGER exponent }` with valid DER framing — wrong tags,
    /// truncated body, non-minimal INTEGER encoding (redundant leading
    /// zeros), exponent that doesn't fit in `u32`, or exponent that's
    /// even or less than 3 (RFC 8017 §3.1).
    #[cfg(feature = "rsa")]
    #[error("RSA pubkey SPKI did not decode as SEQUENCE {{ INTEGER, INTEGER }}")]
    BadRsaPubkey,
    /// RSA modulus length wasn't in the 128 B (RSA-1024) or 256 B
    /// (RSA-2048) set this crate's `rsa_verify` dispatch supports.
    #[cfg(feature = "rsa")]
    #[error("RSA modulus length was not 128 B (RSA-1024) or 256 B (RSA-2048)")]
    UnsupportedRsaKeySize,
    /// The ML-DSA SubjectPublicKey length didn't match the byte length the
    /// SPKI `id-ml-dsa-44/65/87` OID's parameter set requires (1312/1952/2592).
    /// Keeps the OID-declared parameter set and the key authoritative together.
    #[cfg(feature = "mldsa")]
    #[error("ML-DSA SubjectPublicKey length did not match the OID's parameter set")]
    WrongMlDsaPubkeyLength,
    /// The EC SubjectPublicKey wasn't a SEC1 uncompressed point (`0x04` prefix)
    /// of the length the namedCurve requires (65 B for P-256, 97 B for P-384).
    #[cfg(feature = "ecdsa")]
    #[error("EC SubjectPublicKey was not a 65/97-byte SEC1 uncompressed point")]
    WrongEcdsaPubkey,
}
