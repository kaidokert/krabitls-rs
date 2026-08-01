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

// ECDSA client-auth signing draws RFC 6979's HMAC-DRBG through krabiecdsa's
// `digest 0.10`-line bound, so `Hmac<Sha256/384>` here is the 0.10/0.12 crates;
// the prehash uses the crate's own `sha2 0.11`. `Digest as _` pulls the trait
// method without a name that could clash with the `rsa` block's import.
#[cfg(feature = "ecdsa-sign")]
use {
    crate::bigint::{EcdsaP256CtBn, EcdsaP384CtBn},
    crate::consts::{SIG_SCHEME_ECDSA_P256, SIG_SCHEME_ECDSA_P384},
    hmac_v10::Hmac,
    krabiecdsa::{dangerous::SigningKey as EcdsaSigningKey, p256::P256, p384::P384},
    sha2::{Digest as _, Sha256 as Sha256v11, Sha384 as Sha384v11},
    sha2_v10::{Sha256 as Sha256v10, Sha384 as Sha384v10},
};

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

/// ECDSA client authenticator (P-256 / P-384) producing DER `ECDSA-Sig-Value`
/// `CertificateVerify` signatures with an RFC 6979 deterministic nonce.
///
/// **Experimental** (`feature = "ecdsa-sign"`): krabiecdsa's sign path is
/// constant-time but unaudited — do not use it on keys you care about. The
/// secret scalar wipes on drop inside the [`SigningKey`].
#[cfg(feature = "ecdsa-sign")]
pub struct EcdsaClientAuth<'a>(EcdsaKey<'a>);

/// Curve-tagged key + leaf, kept private so callers can't destructure the
/// public authenticator and move the secret [`EcdsaSigningKey`] out of it.
#[cfg(feature = "ecdsa-sign")]
enum EcdsaKey<'a> {
    P256 {
        key: EcdsaSigningKey<P256>,
        cert_der: &'a [u8],
    },
    P384 {
        key: EcdsaSigningKey<P384>,
        cert_der: &'a [u8],
    },
}

#[cfg(feature = "ecdsa-sign")]
impl<'a> EcdsaClientAuth<'a> {
    /// Build from a 32-byte big-endian P-256 private scalar and the DER leaf
    /// certifying the matching public key. Zeroize the caller's copy after.
    pub fn p256_from_scalar(
        scalar: &[u8; 32],
        cert_der: &'a [u8],
    ) -> Result<Self, ClientAuthError> {
        let key = EcdsaSigningKey::<P256>::from_bytes(scalar).ok_or(ClientAuthError)?;
        Ok(Self(EcdsaKey::P256 { key, cert_der }))
    }

    /// Build from a 48-byte big-endian P-384 private scalar and the DER leaf.
    pub fn p384_from_scalar(
        scalar: &[u8; 48],
        cert_der: &'a [u8],
    ) -> Result<Self, ClientAuthError> {
        let key = EcdsaSigningKey::<P384>::from_bytes(scalar).ok_or(ClientAuthError)?;
        Ok(Self(EcdsaKey::P384 { key, cert_der }))
    }

    /// SEC1-uncompressed public key (`0x04 || X || Y`) derived from the scalar,
    /// so callers can check it against the certified leaf. `out` must be 65
    /// (P-256) or 97 (P-384) bytes.
    pub fn public_key_sec1(&self, out: &mut [u8]) -> Result<(), ClientAuthError> {
        let ok = match &self.0 {
            EcdsaKey::P256 { key, .. } => key.verifying_key_sec1::<EcdsaP256CtBn>(out),
            EcdsaKey::P384 { key, .. } => key.verifying_key_sec1::<EcdsaP384CtBn>(out),
        };
        if ok { Ok(()) } else { Err(ClientAuthError) }
    }
}

/// Append `bytes` (a big-endian scalar half) as a minimal DER INTEGER.
#[cfg(feature = "ecdsa-sign")]
fn der_int(bytes: &[u8], out: &mut ClientSignature) -> Result<(), ClientAuthError> {
    let mut v = bytes;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    // A leading 0x80+ byte reads as a negative INTEGER; prepend 0x00 to keep it
    // positive, per DER.
    let pad = v[0] & 0x80 != 0;
    out.push(0x02).map_err(|_| ClientAuthError)?;
    out.push((v.len() + pad as usize) as u8)
        .map_err(|_| ClientAuthError)?;
    if pad {
        out.push(0x00).map_err(|_| ClientAuthError)?;
    }
    out.extend_from_slice(v).map_err(|_| ClientAuthError)?;
    Ok(())
}

/// DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` from the P1363
/// halves. P-256/P-384 bodies stay < 128 bytes, so the SEQUENCE length is one
/// byte.
#[cfg(feature = "ecdsa-sign")]
fn der_ecdsa_sig(r: &[u8], s: &[u8]) -> Result<ClientSignature, ClientAuthError> {
    let mut body = ClientSignature::new();
    der_int(r, &mut body)?;
    der_int(s, &mut body)?;
    let mut out = ClientSignature::new();
    out.push(0x30).map_err(|_| ClientAuthError)?;
    out.push(body.len() as u8).map_err(|_| ClientAuthError)?;
    out.extend_from_slice(&body).map_err(|_| ClientAuthError)?;
    Ok(out)
}

#[cfg(feature = "ecdsa-sign")]
impl ClientAuth for EcdsaClientAuth<'_> {
    fn cert_der(&self) -> &[u8] {
        match &self.0 {
            EcdsaKey::P256 { cert_der, .. } | EcdsaKey::P384 { cert_der, .. } => cert_der,
        }
    }

    fn scheme(&self) -> u16 {
        match &self.0 {
            EcdsaKey::P256 { .. } => SIG_SCHEME_ECDSA_P256,
            EcdsaKey::P384 { .. } => SIG_SCHEME_ECDSA_P384,
        }
    }

    // RFC 6979 deterministic nonce — no entropy draw.
    fn needs_entropy(&self) -> bool {
        false
    }

    fn sign(
        &self,
        content: &[u8],
        _entropy: &[u8; 32],
    ) -> Result<ClientSignature, ClientAuthError> {
        match &self.0 {
            EcdsaKey::P256 { key, .. } => {
                let digest = Sha256v11::digest(content);
                let (mut r, mut s) = ([0u8; 32], [0u8; 32]);
                if !key.sign_prehashed::<EcdsaP256CtBn, Hmac<Sha256v10>>(
                    digest.as_slice(),
                    &mut r,
                    &mut s,
                ) {
                    return Err(ClientAuthError);
                }
                der_ecdsa_sig(&r, &s)
            }
            EcdsaKey::P384 { key, .. } => {
                let digest = Sha384v11::digest(content);
                let (mut r, mut s) = ([0u8; 48], [0u8; 48]);
                if !key.sign_prehashed::<EcdsaP384CtBn, Hmac<Sha384v10>>(
                    digest.as_slice(),
                    &mut r,
                    &mut s,
                ) {
                    return Err(ClientAuthError);
                }
                der_ecdsa_sig(&r, &s)
            }
        }
    }
}

#[cfg(all(test, feature = "ecdsa-sign"))]
mod ecdsa_sign_tests {
    use super::*;
    use crate::backends::ecdsa_verify::{verify_p256, verify_p384};

    const CONTENT: &[u8] = b"TLS 1.3, client CertificateVerify\x00<transcript-hash>";

    #[test]
    fn p256_sign_round_trips_through_own_verifier() {
        let auth = EcdsaClientAuth::p256_from_scalar(&[0x11u8; 32], b"leaf-der").unwrap();
        let mut pk = [0u8; 65];
        auth.public_key_sec1(&mut pk).unwrap();
        let der = auth.sign(CONTENT, &[0u8; 32]).unwrap();
        let prehash = Sha256v11::digest(CONTENT);
        assert!(verify_p256(&pk, prehash.as_slice(), &der).is_ok());
        // A signature over one content must not verify against another's digest.
        let other = Sha256v11::digest(b"tampered");
        assert!(verify_p256(&pk, other.as_slice(), &der).is_err());
    }

    #[test]
    fn p384_sign_round_trips_through_own_verifier() {
        let auth = EcdsaClientAuth::p384_from_scalar(&[0x22u8; 48], b"leaf-der").unwrap();
        let mut pk = [0u8; 97];
        auth.public_key_sec1(&mut pk).unwrap();
        let der = auth.sign(CONTENT, &[0u8; 32]).unwrap();
        let prehash = Sha384v11::digest(CONTENT);
        assert!(verify_p384(&pk, prehash.as_slice(), &der).is_ok());
    }

    #[test]
    fn scheme_and_rfc6979_determinism() {
        let auth = EcdsaClientAuth::p256_from_scalar(&[0x11u8; 32], b"c").unwrap();
        assert_eq!(auth.scheme(), SIG_SCHEME_ECDSA_P256);
        assert!(!auth.needs_entropy());
        // RFC 6979: deterministic — the (ignored) entropy can't change the output.
        let a = auth.sign(CONTENT, &[0u8; 32]).unwrap();
        let b = auth.sign(CONTENT, &[0xffu8; 32]).unwrap();
        assert_eq!(a, b);
    }
}
