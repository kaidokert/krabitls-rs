//! Default Ed25519 (and, under `feature = "rsa"`, RSA-PSS)
//! [`ClientAuth`] implementations for mutual TLS.

use ed25519_heapless::SigningKey;

#[cfg(feature = "rsa")]
use {
    crate::consts::SIG_SCHEME_RSA_PSS_RSAE_SHA256,
    crate::traits::client_auth::MAX_CLIENT_SIG_LEN,
    rsa::{
        GenericRsaPrivateKey,
        modmath_support::{ModMathParams, public_key_ct_from_be_bytes},
        pss::GenericSigningKey,
        traits::FixedWidthUnsignedInt,
    },
    sha2::{Digest, Sha256},
};

use crate::bigint::Curve25519CtBn as Bn;
#[cfg(feature = "rsa")]
use crate::bigint::RsaSignBn as SignBn;
use crate::consts::SIG_SCHEME_ED25519;
use crate::traits::client_auth::{ClientAuth, ClientAuthError, ClientSignature};

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

    // Ed25519 is deterministic (RFC 8032) — no draw, no entropy dependence.
    fn needs_entropy(&self) -> bool {
        false
    }

    fn sign(
        &self,
        content: &[u8],
        _entropy: &[u8; 32],
    ) -> Result<ClientSignature, ClientAuthError> {
        let sig =
            ed25519_heapless::sign(&self.signing_key, content).map_err(|_| ClientAuthError)?;
        let mut out = ClientSignature::new();
        out.extend_from_slice(&sig).map_err(|_| ClientAuthError)?;
        Ok(out)
    }
}

/// RSA client authenticator producing `rsa_pss_rsae_sha256` (0x0804)
/// `CertificateVerify` signatures, paired with the leaf certificate it
/// authenticates. Handles every enabled RSA width (2048 baseline; 1024/3072/
/// 4096 additive) through a single signing-key monomorphization: `SignBn` is
/// sized to the widest enabled width and narrower keys sign sub-capacity.
/// (Verify uses a per-width enum instead — exact-width carriers matter on the
/// hot server-cert path; signing is rare enough that the one-carrier trade wins.)
///
/// Unblinded modexp: the exponentiation is constant-time in `d`, but there
/// is no base blinding, so power/EM side channels are out of scope (same
/// threat-model line as the x25519 ladder — network attackers only).
#[cfg(feature = "rsa")]
pub struct RsaClientAuth<'a> {
    signing_key: GenericSigningKey<Sha256, SignBn, ModMathParams<SignBn, const_num_traits::Ct>>,
    cert_der: &'a [u8],
}

#[cfg(feature = "rsa")]
impl<'a> RsaClientAuth<'a> {
    /// Build from raw big-endian RSA components: the modulus `n` (any enabled
    /// width — 128/256/384/512 B), public exponent `e`, private exponent `d`
    /// (≤ `n.len()` bytes), and the DER leaf certifying the matching public
    /// key. `d` is not validated against `(n, e)` — a mismatched exponent
    /// yields signatures the server rejects. The private exponent wipes on drop
    /// inside the key; zeroize the caller's copy after this returns.
    pub fn from_components(
        n: &[u8],
        e: u32,
        d: &[u8],
        cert_der: &'a [u8],
    ) -> Result<Self, ClientAuthError> {
        // Accept exactly the enabled RSA widths (2048 baseline; 1024/3072/4096
        // additive), matching the verifier + cert parsers. `d` zero-extends up
        // to the modulus width.
        let width_ok = (cfg!(feature = "rsa-1024") && n.len() == 128)
            || n.len() == 256
            || (cfg!(feature = "rsa-3072") && n.len() == 384)
            || (cfg!(feature = "rsa-4096") && n.len() == 512);
        if !width_ok || d.is_empty() || d.len() > n.len() {
            return Err(ClientAuthError);
        }
        let pubkey = public_key_ct_from_be_bytes::<SignBn>(n, e).map_err(|_| ClientAuthError)?;
        // A `d` shorter than the modulus is legitimate (DER strips leading zero
        // bytes off INTEGERs); `try_from_be_bytes_vartime` zero-extends it.
        let d = <SignBn as FixedWidthUnsignedInt>::try_from_be_bytes_vartime(d)
            .map_err(|_| ClientAuthError)?;
        let priv_key = GenericRsaPrivateKey::from_public_and_d(pubkey, d);
        Ok(Self {
            // TLS 1.3 §4.2.3: rsa_pss_rsae_sha256 requires saltLen == hashLen.
            signing_key: GenericSigningKey::new_with_salt_len(priv_key, 32),
            cert_der,
        })
    }
}

#[cfg(feature = "rsa")]
impl ClientAuth for RsaClientAuth<'_> {
    fn cert_der(&self) -> &[u8] {
        self.cert_der
    }

    fn scheme(&self) -> u16 {
        SIG_SCHEME_RSA_PSS_RSAE_SHA256
    }

    fn sign(&self, content: &[u8], entropy: &[u8; 32]) -> Result<ClientSignature, ClientAuthError> {
        let prehash = Sha256::digest(content);
        // EM scratch + signature output; both public once the signature is
        // released, no wipe needed.
        let mut em = [0u8; MAX_CLIENT_SIG_LEN];
        let mut sig = [0u8; MAX_CLIENT_SIG_LEN];
        let sig_slice = self
            .signing_key
            .try_sign_prehash_with_salt_into(&prehash, entropy, &mut em, &mut sig)
            .map_err(|_| ClientAuthError)?;
        let mut out = ClientSignature::new();
        out.extend_from_slice(sig_slice)
            .map_err(|_| ClientAuthError)?;
        Ok(out)
    }
}
