//! A downstream custom backend built against krabitls's public API only —
//! nothing here uses a `krabitls::`-internal path. If any type a real hardware
//! integrator needs stops being publicly reachable, this crate fails to
//! compile, which is the whole point: the in-crate test suite reaches these
//! types via `crate::` and never proves the export surface.
#![no_std]
#![forbid(unsafe_code)]

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use rand_core::TryCryptoRng;
use sha2::Sha256;
use zeroize::Zeroizing;

// The backend-author surface, entirely through the public facade.
use krabitls::backends::{DerCert, RustCrypto};
use krabitls::client::{
    AeadBackend, Aes128GcmSha256, ClientAuth, ClientAuthError, ClientConfig, ClientSignature,
    ConfigSuitePolicy, HkdfExpandError, HkdfSha256,
};

// The types are `pub` so the impls (the actual export test) are reachable and
// never flagged dead under `-D warnings`. Compiling the impl blocks is what
// proves every named public type resolves.

/// A hardware AEAD stands in here as a delegating wrapper: the point is that an
/// externally-defined `aead 0.6` cipher substitutes into the suite marker, not
/// the cryptography.
pub struct ProbeAes(aes_gcm::Aes128Gcm);

impl KeySizeUser for ProbeAes {
    type KeySize = U16;
}
impl KeyInit for ProbeAes {
    fn new(key: &Key<Self>) -> Self {
        Self(aes_gcm::Aes128Gcm::new(&Array::from(<[u8; 16]>::from(
            *key,
        ))))
    }
}
impl AeadCore for ProbeAes {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}
impl AeadInOut for ProbeAes {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, aead::Error> {
        self.0.encrypt_inout_detached(
            &Nonce::<aes_gcm::Aes128Gcm>::from(<[u8; 12]>::from(*nonce)),
            associated_data,
            buffer,
        )
    }
    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), aead::Error> {
        self.0.decrypt_inout_detached(
            &Nonce::<aes_gcm::Aes128Gcm>::from(<[u8; 12]>::from(*nonce)),
            associated_data,
            buffer,
            tag,
        )
    }
}

/// Substitute the hardware cipher into the AES suite (this build is AES-only, so
/// the trait has no `ChaCha` associated type).
pub struct ProbeAead;
impl AeadBackend for ProbeAead {
    type Aes = Aes128GcmSha256<ProbeAes>;
}

/// A custom HKDF/transcript backend — the shape a hardware SHA-256 slots into.
pub struct ProbeHkdf;
impl HkdfSha256 for ProbeHkdf {
    type Hasher = Sha256;
    fn hasher() -> Self::Hasher {
        <Sha256 as sha2::Digest>::new()
    }
    fn extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
        // HMAC pads a short/empty key to the block with zeros, so an empty salt
        // already matches RFC 5869's zero-salt default.
        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), ikm);
        let mut out = [0u8; 32];
        out.copy_from_slice(&prk);
        Zeroizing::new(out)
    }
    fn expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) -> Result<(), HkdfExpandError> {
        let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).map_err(|_| HkdfExpandError::InvalidPrk)?;
        hk.expand(info, out)
            .map_err(|_| HkdfExpandError::OutputTooLong)
    }
}

/// A custom client-auth signer — must be able to name and build the public
/// `ClientSignature` heapless buffer.
pub struct ProbeSigner {
    cert: [u8; 4],
}
impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for ProbeSigner {
    fn cert_der(&self) -> &[u8] {
        &self.cert
    }
    fn scheme(&self) -> u16 {
        0x0807 // ed25519
    }
    fn sign(&self, _content: &[u8], _rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        let mut sig = ClientSignature::new();
        sig.extend_from_slice(&[0u8; 64])
            .map_err(|_| ClientAuthError)?;
        Ok(sig)
    }
}

/// The whole reason for the crate: a downstream `ClientConfig` mixing a custom
/// AEAD + custom HKDF with the bundled verifier/parser defaults. Compiling this
/// impl forces every named public type to resolve.
pub struct ProbeConfig;
impl ClientConfig for ProbeConfig {
    type Hkdf = ProbeHkdf;
    type CertParser = DerCert;
    type Verifiers = RustCrypto;
    type Aead = ProbeAead;
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesOnly;
}
