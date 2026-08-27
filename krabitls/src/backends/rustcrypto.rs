//! Default [`crate::HkdfSha256`] backend on the RustCrypto crates.

use ::hkdf::Hkdf;
use sha2::Sha256;

#[cfg(any(feature = "x25519-kx", feature = "p256-kx", feature = "mlkem"))]
use crate::traits::kx::{ClientShareBuf, KxGroup, SharedSecretBuf};
#[cfg(any(feature = "x25519-kx", feature = "p256-kx", feature = "mlkem"))]
use rand_core::TryCryptoRng;

use zeroize::Zeroizing;

use crate::bigint::Curve25519VerifyBn as Bn;
use crate::traits::verify_provider::{Ed25519, SigVerifierProvider, VerifyProviderError};
use crate::traits::{HkdfExpandError, HkdfSha256};
use signature::Verifier;
use subtle::ConstantTimeEq;

pub struct RustCrypto;

impl crate::traits::AeadBackend for RustCrypto {
    #[cfg(feature = "cipher-aes")]
    type Aes = crate::aead::Aes128GcmSha256;
    #[cfg(feature = "chacha20")]
    type ChaCha = crate::aead::ChaCha20Poly1305Sha256;
}

// ============================================================================
// Key-exchange groups
// ============================================================================

/// X25519 (0x001d), delegating to [`crate::backends::ecdhe_x25519::EcdheX25519`].
#[cfg(feature = "x25519-kx")]
pub struct X25519Group;

#[cfg(feature = "x25519-kx")]
impl KxGroup for X25519Group {
    const NAMED_GROUP: u16 = crate::consts::NAMED_GROUP_X25519;
    const CLIENT_SHARE_LEN: usize = crate::backends::ecdhe_x25519::X25519_SHARE_BYTES;
    const SHARED_SECRET_LEN: usize = crate::backends::ecdhe_x25519::X25519_SS_BYTES;
    type Secret = crate::backends::ecdhe_x25519::EcdheX25519;
    type Error = crate::backends::ecdhe_x25519::EcdheX25519Error;

    fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let (secret, pubkey) = crate::backends::ecdhe_x25519::EcdheX25519::generate(rng)?;
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&pubkey)
            .map_err(|_| crate::backends::ecdhe_x25519::EcdheX25519Error)?;
        Ok((secret, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let peer: &[u8; crate::backends::ecdhe_x25519::X25519_SHARE_BYTES] = server_share
            .try_into()
            .map_err(|_| crate::backends::ecdhe_x25519::EcdheX25519Error)?;
        let ss = secret.agree(peer)?;
        Ok(SharedSecretBuf::from_slice(ss.as_slice()))
    }
}

/// secp256r1 (0x0017), delegating to [`crate::backends::ecdhe::EcdheP256`].
#[cfg(feature = "p256-kx")]
pub struct P256Group;

#[cfg(feature = "p256-kx")]
impl KxGroup for P256Group {
    const NAMED_GROUP: u16 = crate::consts::NAMED_GROUP_SECP256R1;
    const CLIENT_SHARE_LEN: usize = crate::backends::ecdhe::P256_SHARE_BYTES;
    const SHARED_SECRET_LEN: usize = crate::backends::ecdhe::P256_SS_BYTES;
    type Secret = crate::backends::ecdhe::EcdheP256;
    type Error = crate::backends::ecdhe::EcdheP256Error;

    fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let (secret, sec1) = crate::backends::ecdhe::EcdheP256::generate(rng)?;
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&sec1)
            .map_err(|_| crate::backends::ecdhe::EcdheP256Error)?;
        Ok((secret, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let peer: &[u8; crate::backends::ecdhe::P256_SHARE_BYTES] = server_share
            .try_into()
            .map_err(|_| crate::backends::ecdhe::EcdheP256Error)?;
        let ss = secret.agree(peer)?;
        Ok(SharedSecretBuf::from_slice(ss.as_slice()))
    }
}

/// X25519MLKEM768 hybrid (0x11ec) as one composite group. The secret bundles
/// the X25519 and ML-KEM ephemerals; `generate`/`derive` order the components
/// per draft-ietf-tls-ecdhe-mlkem (ML-KEM component first on the wire, ML-KEM
/// secret first in the IKM).
#[cfg(feature = "mlkem")]
pub struct X25519MlKem768Group;

#[cfg(feature = "mlkem")]
pub struct X25519MlKem768Secret {
    x25519: crate::backends::ecdhe_x25519::EcdheX25519,
    mlkem: crate::backends::mlkem::MlKem768,
}

/// Which component of the hybrid rejected the exchange.
#[cfg(feature = "mlkem")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X25519MlKem768Error {
    /// X25519 agreement failed (low-order / all-zero server share).
    X25519,
    /// ML-KEM decapsulation failed (structurally unreachable — implicit rejection).
    MlKem,
    /// The `key_share` bytes were the wrong length for the hybrid.
    Malformed,
}

#[cfg(feature = "mlkem")]
impl KxGroup for X25519MlKem768Group {
    const NAMED_GROUP: u16 = crate::consts::NAMED_GROUP_X25519MLKEM768;
    const CLIENT_SHARE_LEN: usize = crate::backends::mlkem::MLKEM768_EK_BYTES
        + crate::backends::ecdhe_x25519::X25519_SHARE_BYTES;
    const SHARED_SECRET_LEN: usize =
        crate::backends::mlkem::MLKEM768_SS_BYTES + crate::backends::ecdhe_x25519::X25519_SS_BYTES;
    type Secret = X25519MlKem768Secret;
    type Error = X25519MlKem768Error;

    fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        // Draw the X25519 scalar before the ML-KEM keypair — the fixed order the
        // deterministic-RNG canned handshakes were captured against.
        let (x25519, x25519_pub) = crate::backends::ecdhe_x25519::EcdheX25519::generate(rng)
            .map_err(|_| X25519MlKem768Error::X25519)?;
        let (mlkem, ek) = crate::backends::mlkem::MlKem768::generate(rng)
            .map_err(|_| X25519MlKem768Error::MlKem)?;
        // Wire order: ML-KEM ek ‖ X25519 pub.
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&ek)
            .map_err(|_| X25519MlKem768Error::Malformed)?;
        share
            .extend_from_slice(&x25519_pub)
            .map_err(|_| X25519MlKem768Error::Malformed)?;
        Ok((X25519MlKem768Secret { x25519, mlkem }, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        // Server share: ML-KEM ct ‖ X25519 pub.
        let (ct, x) = server_share
            .split_at_checked(crate::backends::mlkem::MLKEM768_CT_BYTES)
            .ok_or(X25519MlKem768Error::Malformed)?;
        let ct: &[u8; crate::backends::mlkem::MLKEM768_CT_BYTES] =
            ct.try_into().map_err(|_| X25519MlKem768Error::Malformed)?;
        let x: &[u8; crate::backends::ecdhe_x25519::X25519_SHARE_BYTES] =
            x.try_into().map_err(|_| X25519MlKem768Error::Malformed)?;
        // X25519 first, matching the pre-refactor abort precedence: a low-order
        // server point aborts before ML-KEM decapsulation runs.
        let x25519_ss = secret
            .x25519
            .agree(x)
            .map_err(|_| X25519MlKem768Error::X25519)?;
        let mlkem_ss = secret
            .mlkem
            .decapsulate(ct)
            .map_err(|_| X25519MlKem768Error::MlKem)?;
        // IKM: ML-KEM ss ‖ X25519 ss.
        let mut ikm = Zeroizing::new(
            [0u8; crate::backends::mlkem::MLKEM768_SS_BYTES
                + crate::backends::ecdhe_x25519::X25519_SS_BYTES],
        );
        let split = crate::backends::mlkem::MLKEM768_SS_BYTES;
        ikm[..split].copy_from_slice(mlkem_ss.as_slice());
        ikm[split..].copy_from_slice(x25519_ss.as_slice());
        Ok(SharedSecretBuf::from_slice(ikm.as_slice()))
    }
}

impl crate::traits::kx::KxBackend for RustCrypto {
    #[cfg(feature = "x25519-kx")]
    type X25519 = X25519Group;
    #[cfg(feature = "p256-kx")]
    type P256 = P256Group;
    #[cfg(feature = "mlkem")]
    type X25519MlKem768 = X25519MlKem768Group;
}

impl HkdfSha256 for RustCrypto {
    type Hasher = Sha256;

    fn hasher() -> Self::Hasher {
        digest::Digest::new()
    }

    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        Zeroizing::new(prk.into())
    }

    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError> {
        let hk = Hkdf::<Sha256>::from_prk(prk).map_err(|_| HkdfExpandError::InvalidPrk)?;
        hk.expand(info, out)
            .map_err(|_| HkdfExpandError::OutputTooLong)
    }
}

/// `Ed25519` verifying key with the curve precompute bundled in. Construct
/// once per cert via [`SigVerifierProvider::prepare`]; subsequent
/// `signature::Verifier::verify` calls reuse the precompute (~100-150 k cycles
/// on M3 to build, amortized across the 2 verifies per TLS handshake).
pub struct PreparedEd25519 {
    pubkey: [u8; 32],
    // `Curve25519Field::curve25519()` is fallible since ed25519_heapless 0.2.1
    // (errors only when the bigint backend is < 256 bits — impossible for the
    // 512-bit `Bn` here). Stored as `Option` so `prepare_ed25519` stays
    // infallible and no setup panic is linked; the unreachable failure
    // fails the verify closed instead.
    field: Option<ed25519_heapless::Curve25519Field<Bn>>,
}

impl PreparedEd25519 {
    // Outlined so the curve precompute stays one shared symbol across the leaf-
    // prep and self-sig-verify call sites rather than duplicating when `prepare`
    // inlines.
    #[inline(never)]
    fn build(pubkey: &[u8; 32]) -> Self {
        PreparedEd25519 {
            pubkey: *pubkey,
            field: ed25519_heapless::Curve25519Field::<Bn>::curve25519().ok(),
        }
    }
}

impl Verifier<[u8; 64]> for PreparedEd25519 {
    fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<(), signature::Error> {
        let Some(field) = self.field.as_ref() else {
            return Err(signature::Error::new());
        };
        if ed25519_heapless::hazmat::verify_with_field(field, self.pubkey, msg, *signature) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

impl crate::traits::verify_strategy::VerifierKeyMaterial<[u8; 32]> for PreparedEd25519 {
    fn matches(&self, candidate: [u8; 32]) -> subtle::Choice {
        self.pubkey.ct_eq(&candidate)
    }
}

// Despite the marker name, the Ed25519 verify wired here is `ed25519_heapless`
// (not from the RustCrypto org). Bundled with the default `RustCrypto` marker
// because that's the "pick the defaults" ergonomic entry point — pairing
// `TlsStream::connect` with the existing HKDF + AEAD impls.
impl SigVerifierProvider<Ed25519> for RustCrypto {
    type Verifier = PreparedEd25519;

    #[inline]
    fn prepare(pubkey: &[u8; 32]) -> Result<Self::Verifier, VerifyProviderError> {
        Ok(PreparedEd25519::build(pubkey))
    }
}

// PSS vs PKCS#1-v1.5 is chosen from the sig's carried scheme, not the key.
#[cfg(feature = "rsa")]
impl SigVerifierProvider<crate::traits::verify_provider::Rsa> for RustCrypto {
    type Verifier = crate::backends::rsa_verify::RsaVerifierKey;

    fn prepare(
        pubkey: crate::traits::verify_strategy::RsaKeyMaterial<'_>,
    ) -> Result<Self::Verifier, VerifyProviderError> {
        crate::backends::rsa_verify::RsaVerifierKey::new(pubkey.modulus, pubkey.exponent)
            .map_err(|_| VerifyProviderError)
    }
}

#[cfg(feature = "ecdsa")]
impl SigVerifierProvider<crate::traits::verify_provider::EcdsaP256> for RustCrypto {
    type Verifier = crate::backends::ecdsa_verify::PreparedEcdsaP256;

    fn prepare(pubkey: &[u8; 65]) -> Result<Self::Verifier, VerifyProviderError> {
        Ok(crate::backends::ecdsa_verify::PreparedEcdsaP256(*pubkey))
    }
}

#[cfg(feature = "ecdsa")]
impl SigVerifierProvider<crate::traits::verify_provider::EcdsaP384> for RustCrypto {
    type Verifier = crate::backends::ecdsa_verify::PreparedEcdsaP384;

    fn prepare(pubkey: &[u8; 97]) -> Result<Self::Verifier, VerifyProviderError> {
        Ok(crate::backends::ecdsa_verify::PreparedEcdsaP384(*pubkey))
    }
}

#[cfg(feature = "mldsa")]
impl SigVerifierProvider<crate::traits::verify_provider::MlDsa> for RustCrypto {
    type Verifier = crate::backends::mldsa_verify::MlDsaVerifierKey;

    fn prepare(pubkey: &[u8]) -> Result<Self::Verifier, VerifyProviderError> {
        crate::backends::mldsa_verify::MlDsaVerifierKey::new(pubkey)
            .map_err(|_| VerifyProviderError)
    }
}
