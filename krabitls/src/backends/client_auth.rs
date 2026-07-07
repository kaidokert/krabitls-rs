//! Default Ed25519 [`ClientAuth`] implementation for mutual TLS.

use ed25519_heapless::SigningKey;

use crate::consts::SIG_SCHEME_ED25519;
use crate::traits::client_auth::{ClientAuth, ClientAuthError, ClientSignature};

/// Bigint backend the signing key runs on. Same 512-bit width as the verify
/// path, but the constant-time `Ct` personality — `ed25519_heapless`'s
/// `SignBackend` bound requires CT field arithmetic for the secret scalar.
type Bn = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;

/// Ed25519 client authenticator: a seed-derived signing key (long-term
/// secret wiped on drop inside [`SigningKey`]) paired with the leaf
/// certificate it authenticates.
pub struct Ed25519ClientAuth<'a> {
    signing_key: SigningKey<Bn>,
    cert_der: &'a [u8],
}

impl<'a> Ed25519ClientAuth<'a> {
    /// Build from a 32-byte Ed25519 seed (RFC 8032 §5.1.5) and the DER leaf
    /// certifying the matching public key. The seed is expanded into the key
    /// and not retained; zeroize the caller's copy after this returns.
    pub fn from_seed(seed: &[u8; 32], cert_der: &'a [u8]) -> Result<Self, ClientAuthError> {
        let signing_key = SigningKey::<Bn>::from_seed(seed).map_err(|_| ClientAuthError)?;
        Ok(Self {
            signing_key,
            cert_der,
        })
    }

    /// Compressed Ed25519 public key, so callers can check it matches the
    /// certified leaf before handing this to the handshake.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.public_key()
    }
}

impl ClientAuth for Ed25519ClientAuth<'_> {
    fn cert_der(&self) -> &[u8] {
        self.cert_der
    }

    fn scheme(&self) -> u16 {
        SIG_SCHEME_ED25519
    }

    fn sign(&self, content: &[u8]) -> Result<ClientSignature, ClientAuthError> {
        let sig =
            ed25519_heapless::sign(&self.signing_key, content).map_err(|_| ClientAuthError)?;
        let mut out = ClientSignature::new();
        out.extend_from_slice(&sig).map_err(|_| ClientAuthError)?;
        Ok(out)
    }
}
