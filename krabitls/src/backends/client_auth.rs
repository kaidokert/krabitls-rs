//! Default Ed25519 (and, under `feature = "rsa"`, RSA-PSS)
//! [`ClientAuth`] implementations for mutual TLS.

use ed25519_heapless::SigningKey;
use rand_core::TryCryptoRng;
#[cfg(feature = "blinding")]
use signature::RandomizedSigner;

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
    sha2::Sha256,
};

// `sha2::Digest` brings the prehash `.digest()` into scope for both the RSA and
// ECDSA signers; shared so it isn't imported twice when both features are on.
#[cfg(any(feature = "rsa", feature = "ecdsa"))]
use sha2::Digest as _;

use crate::bigint::Curve25519CtBn as Bn;
#[cfg(feature = "rsa")]
use crate::bigint::RsaSignBn as SignBn;
use crate::consts::SIG_SCHEME_ED25519;
use crate::traits::client_auth::{ClientAuth, ClientAuthError, ClientSignature};

// ECDSA client-auth signing: the RFC 6979 HMAC-DRBG and the message prehash
// both ride the crate's own `sha2 0.11` / `hmac 0.13` (digest 0.11). `Sha256`/
// `Sha384` are aliased so they don't collide with the `rsa` block's `Sha256`
// import when both features are on.
#[cfg(feature = "ecdsa")]
use {
    crate::bigint::{EcdsaP256Bn, EcdsaP256CtBn, EcdsaP384Bn, EcdsaP384CtBn},
    crate::consts::{SIG_SCHEME_ECDSA_P256, SIG_SCHEME_ECDSA_P384},
    hmac::Hmac,
    krabiecdsa::{p256::P256, p384::P384},
    sha2::{Sha256 as EcdsaSha256, Sha384 as EcdsaSha384},
};
#[cfg(all(feature = "ecdsa", feature = "blinding"))]
use {krabiecdsa::signing::RandomizedSigningKey, signature::hazmat::RandomizedPrehashSigner};
#[cfg(all(feature = "ecdsa", not(feature = "blinding")))]
use {krabiecdsa::signing::PrehashSigningKey, signature::hazmat::PrehashSigner};

// P-256/P-384 signers, fully monomorphized (constant-time sign backend,
// variable-time verify backend for the verify-after-sign fault check). With
// `blinding` on, the RFC 6979 nonce is hedged (§3.6) and `k·G` is scalar/
// coordinate-blinded from the connection RNG; off, it's plain deterministic
// RFC 6979.
#[cfg(all(feature = "ecdsa", feature = "blinding"))]
type P256Signer = RandomizedSigningKey<P256, EcdsaP256CtBn, EcdsaP256Bn, Hmac<EcdsaSha256>>;
#[cfg(all(feature = "ecdsa", feature = "blinding"))]
type P384Signer = RandomizedSigningKey<P384, EcdsaP384CtBn, EcdsaP384Bn, Hmac<EcdsaSha384>>;
#[cfg(all(feature = "ecdsa", not(feature = "blinding")))]
type P256Signer = PrehashSigningKey<P256, EcdsaP256CtBn, EcdsaP256Bn, Hmac<EcdsaSha256>>;
#[cfg(all(feature = "ecdsa", not(feature = "blinding")))]
type P384Signer = PrehashSigningKey<P384, EcdsaP384CtBn, EcdsaP384Bn, Hmac<EcdsaSha384>>;

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

impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for Ed25519ClientAuth<'_> {
    fn cert_der(&self) -> &[u8] {
        self.cert_der
    }

    fn scheme(&self) -> u16 {
        SIG_SCHEME_ED25519
    }

    // `blinding` on: hedged + blinded (RandomizedSigner) — `rng` drives the nonce
    // hedge and the scalar/coordinate blinding; output is non-deterministic.
    // Off: plain deterministic RFC 8032. Either way a standard signature.
    #[cfg(feature = "blinding")]
    fn sign(&self, content: &[u8], rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        let sig = self
            .signing_key
            .try_sign_with_rng(rng, content)
            .map_err(|_| ClientAuthError)?;
        let mut out = ClientSignature::new();
        out.extend_from_slice(&sig).map_err(|_| ClientAuthError)?;
        Ok(out)
    }

    #[cfg(not(feature = "blinding"))]
    fn sign(&self, content: &[u8], _rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
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
/// The modexp is constant-time in `d` and base-blinded: a random `r` drawn from
/// the connection RNG masks the base (`(m·rᵉ)ᵈ·r⁻¹`), with a verify-after-sign
/// fault check, so it resists the power/EM DPA the unblinded ladder can't.
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
impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for RsaClientAuth<'_> {
    fn cert_der(&self) -> &[u8] {
        self.cert_der
    }

    fn scheme(&self) -> u16 {
        SIG_SCHEME_RSA_PSS_RSAE_SHA256
    }

    fn sign(&self, content: &[u8], rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        let prehash = Sha256::digest(content);
        // EM scratch + signature output; both public once released, no wipe.
        // `salt` is the 32-byte PSS salt (saltLen == hashLen), drawn from `rng`
        // either way. `blinding` on additionally masks the modexp base from the
        // same rng — the signature bytes are identical, only the side channel
        // differs.
        let mut em = [0u8; MAX_CLIENT_SIG_LEN];
        let mut sig = [0u8; MAX_CLIENT_SIG_LEN];
        let mut salt = [0u8; 32];
        #[cfg(feature = "blinding")]
        let sig_slice = self
            .signing_key
            .try_sign_prehash_with_rng_into(rng, &prehash, &mut em, &mut sig, &mut salt)
            .map_err(|_| ClientAuthError)?;
        #[cfg(not(feature = "blinding"))]
        let sig_slice = {
            rng.try_fill_bytes(&mut salt).map_err(|_| ClientAuthError)?;
            self.signing_key
                .try_sign_prehash_with_salt_into(&prehash, &salt, &mut em, &mut sig)
                .map_err(|_| ClientAuthError)?
        };
        let mut out = ClientSignature::new();
        out.extend_from_slice(sig_slice)
            .map_err(|_| ClientAuthError)?;
        Ok(out)
    }
}

/// ECDSA client authenticator (P-256 / P-384) producing DER `ECDSA-Sig-Value`
/// `CertificateVerify` signatures.
///
/// The nonce is RFC 6979 hedged with fresh connection-RNG entropy (§3.6), and
/// the `k·G` multiply is scalar- (`k + r·n`) and coordinate- (λ) blinded from
/// the same rng, with a verify-after-sign fault check. The signing scalar and
/// nonce math are constant-time (krabiecdsa's Ct path), and the secret scalar
/// wipes on drop inside the signing key. A weak rng draw degrades to plain
/// RFC 6979 determinism, never to nonce reuse.
#[cfg(feature = "ecdsa")]
pub struct EcdsaClientAuth<'a>(EcdsaKey<'a>);

/// Curve-tagged key + leaf, kept private so callers can't destructure the
/// public authenticator and move the secret signing key out of it.
#[cfg(feature = "ecdsa")]
enum EcdsaKey<'a> {
    P256 { key: P256Signer, cert_der: &'a [u8] },
    P384 { key: P384Signer, cert_der: &'a [u8] },
}

#[cfg(feature = "ecdsa")]
impl<'a> EcdsaClientAuth<'a> {
    /// Build from a 32-byte big-endian P-256 private scalar and the DER leaf
    /// certifying the matching public key. Zeroize the caller's copy after.
    pub fn p256_from_scalar(
        scalar: &[u8; 32],
        cert_der: &'a [u8],
    ) -> Result<Self, ClientAuthError> {
        let key = P256Signer::from_bytes(scalar).ok_or(ClientAuthError)?;
        Ok(Self(EcdsaKey::P256 { key, cert_der }))
    }

    /// Build from a 48-byte big-endian P-384 private scalar and the DER leaf.
    pub fn p384_from_scalar(
        scalar: &[u8; 48],
        cert_der: &'a [u8],
    ) -> Result<Self, ClientAuthError> {
        let key = P384Signer::from_bytes(scalar).ok_or(ClientAuthError)?;
        Ok(Self(EcdsaKey::P384 { key, cert_der }))
    }

    /// SEC1-uncompressed public key (`0x04 || X || Y`) derived from the scalar,
    /// so callers can check it against the certified leaf. `out` must be 65
    /// (P-256) or 97 (P-384) bytes.
    pub fn public_key_sec1(&self, out: &mut [u8]) -> Result<(), ClientAuthError> {
        let ok = match &self.0 {
            EcdsaKey::P256 { key, .. } => key.verifying_key_sec1(out),
            EcdsaKey::P384 { key, .. } => key.verifying_key_sec1(out),
        };
        if ok { Ok(()) } else { Err(ClientAuthError) }
    }
}

/// Append `bytes` (a big-endian scalar half) as a minimal DER INTEGER.
#[cfg(feature = "ecdsa")]
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
#[cfg(feature = "ecdsa")]
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

#[cfg(feature = "ecdsa")]
impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for EcdsaClientAuth<'_> {
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

    // The signer returns the fixed-width P1363 `r || s`; split at the element
    // width and re-encode as the DER `ECDSA-Sig-Value` TLS wants. `blinding` on
    // hedges the nonce from `rng`; off is plain deterministic RFC 6979.
    #[cfg(feature = "blinding")]
    fn sign(&self, content: &[u8], rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        match &self.0 {
            EcdsaKey::P256 { key, .. } => {
                let digest = EcdsaSha256::digest(content);
                let sig = key
                    .sign_prehash_with_rng(rng, digest.as_slice())
                    .map_err(|_| ClientAuthError)?;
                let (r, s) = sig.split_at(32);
                der_ecdsa_sig(r, s)
            }
            EcdsaKey::P384 { key, .. } => {
                let digest = EcdsaSha384::digest(content);
                let sig = key
                    .sign_prehash_with_rng(rng, digest.as_slice())
                    .map_err(|_| ClientAuthError)?;
                let (r, s) = sig.split_at(48);
                der_ecdsa_sig(r, s)
            }
        }
    }

    #[cfg(not(feature = "blinding"))]
    fn sign(&self, content: &[u8], _rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        match &self.0 {
            EcdsaKey::P256 { key, .. } => {
                let digest = EcdsaSha256::digest(content);
                let sig = key.sign_prehash(digest.as_slice()).map_err(|_| ClientAuthError)?;
                let (r, s) = sig.split_at(32);
                der_ecdsa_sig(r, s)
            }
            EcdsaKey::P384 { key, .. } => {
                let digest = EcdsaSha384::digest(content);
                let sig = key.sign_prehash(digest.as_slice()).map_err(|_| ClientAuthError)?;
                let (r, s) = sig.split_at(48);
                der_ecdsa_sig(r, s)
            }
        }
    }
}

#[cfg(all(test, feature = "ecdsa"))]
mod ecdsa_sign_tests {
    use super::*;
    use crate::backends::ecdsa_verify::{verify_p256, verify_p384};
    use core::convert::Infallible;

    const CONTENT: &[u8] = b"TLS 1.3, client CertificateVerify\x00<transcript-hash>";

    /// Constant-fill test RNG: a fixed byte is a valid hedge/blind draw, so the
    /// signer accepts it and the output is reproducible per byte. Not a CSPRNG.
    struct FixedRng(u8);
    impl rand_core::TryRng for FixedRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(u32::from_le_bytes([self.0; 4]))
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(u64::from_le_bytes([self.0; 8]))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for FixedRng {}

    #[test]
    fn p256_sign_round_trips_through_own_verifier() {
        let auth = EcdsaClientAuth::p256_from_scalar(&[0x11u8; 32], b"leaf-der").unwrap();
        let mut pk = [0u8; 65];
        auth.public_key_sec1(&mut pk).unwrap();
        let der = auth.sign(CONTENT, &mut FixedRng(0x42)).unwrap();
        let prehash = EcdsaSha256::digest(CONTENT);
        assert!(verify_p256(&pk, prehash.as_slice(), &der).is_ok());
        // A signature over one content must not verify against another's digest.
        let other = EcdsaSha256::digest(b"tampered");
        assert!(verify_p256(&pk, other.as_slice(), &der).is_err());
    }

    #[test]
    fn p384_sign_round_trips_through_own_verifier() {
        let auth = EcdsaClientAuth::p384_from_scalar(&[0x22u8; 48], b"leaf-der").unwrap();
        let mut pk = [0u8; 97];
        auth.public_key_sec1(&mut pk).unwrap();
        let der = auth.sign(CONTENT, &mut FixedRng(0x42)).unwrap();
        let prehash = EcdsaSha384::digest(CONTENT);
        assert!(verify_p384(&pk, prehash.as_slice(), &der).is_ok());
    }

    #[test]
    fn scheme_and_hedged_nonce() {
        let auth = EcdsaClientAuth::p256_from_scalar(&[0x11u8; 32], b"c").unwrap();
        assert_eq!(ClientAuth::<FixedRng>::scheme(&auth), SIG_SCHEME_ECDSA_P256);
        let mut pk = [0u8; 65];
        auth.public_key_sec1(&mut pk).unwrap();
        let prehash = EcdsaSha256::digest(CONTENT);
        // Hedged (RFC 6979 §3.6): distinct rng streams yield distinct signatures
        // over the same content, both valid.
        let a = auth.sign(CONTENT, &mut FixedRng(0x01)).unwrap();
        let b = auth.sign(CONTENT, &mut FixedRng(0x02)).unwrap();
        assert_ne!(a, b);
        assert!(verify_p256(&pk, prehash.as_slice(), &a).is_ok());
        assert!(verify_p256(&pk, prehash.as_slice(), &b).is_ok());
    }
}
