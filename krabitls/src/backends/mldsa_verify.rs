//! ML-DSA (FIPS 204) verification backend on krabipqc.
//!
//! [`MlDsaVerifierKey`] enums over the three FIPS 204 parameter sets and
//! implements [`signature::Verifier`] against [`MlDsaSig`] (borrowed signature
//! bytes), mirroring [`super::rsa_verify::RsaVerifierKey`]. The parameter set
//! is chosen from the public-key length at construction.

use kem::KeyInit;
use krabipqc::{MlDsa44, MlDsa65, MlDsa87, MlDsaSignature, MlDsaVerifier};
use signature::{Error as SigError, Verifier};

/// Borrowed ML-DSA signature bytes, newtyped so a prepared [`MlDsaVerifierKey`]
/// implements [`signature::Verifier`] without copying the 2–4.6 KiB signature
/// into an owned buffer.
pub struct MlDsaSig<'a>(pub &'a [u8]);

/// Public-key bytes matched no FIPS 204 parameter set's encoded length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsaVerifyError;

/// Prepared ML-DSA verifying key, dispatched over the parameter set selected
/// from the public-key length at [`MlDsaVerifierKey::new`].
// Variant size is the parameter set's public key (1312–2592 B); no-alloc, so
// the larger keys can't be boxed away.
#[allow(clippy::large_enum_variant)]
pub enum MlDsaVerifierKey {
    MlDsa44(MlDsaVerifier<MlDsa44>),
    MlDsa65(MlDsaVerifier<MlDsa65>),
    MlDsa87(MlDsaVerifier<MlDsa87>),
}

impl MlDsaVerifierKey {
    /// FIPS 204 Table 2 public-key byte lengths.
    const PK_LEN_44: usize = 1312;
    const PK_LEN_65: usize = 1952;
    const PK_LEN_87: usize = 2592;

    pub fn new(pubkey: &[u8]) -> Result<Self, MlDsaVerifyError> {
        match pubkey.len() {
            Self::PK_LEN_44 => MlDsaVerifier::<MlDsa44>::new_from_slice(pubkey).map(Self::MlDsa44),
            Self::PK_LEN_65 => MlDsaVerifier::<MlDsa65>::new_from_slice(pubkey).map(Self::MlDsa65),
            Self::PK_LEN_87 => MlDsaVerifier::<MlDsa87>::new_from_slice(pubkey).map(Self::MlDsa87),
            _ => return Err(MlDsaVerifyError),
        }
        .map_err(|_| MlDsaVerifyError)
    }
}

impl Verifier<MlDsaSig<'_>> for MlDsaVerifierKey {
    fn verify(&self, msg: &[u8], signature: &MlDsaSig<'_>) -> Result<(), SigError> {
        match self {
            Self::MlDsa44(v) => v.verify(msg, &MlDsaSignature::try_from(signature.0)?),
            Self::MlDsa65(v) => v.verify(msg, &MlDsaSignature::try_from(signature.0)?),
            Self::MlDsa87(v) => v.verify(msg, &MlDsaSignature::try_from(signature.0)?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use kem::{Generate, KeyExport};
    use krabipqc::{MlDsaParams, MlDsaSigner};
    use signature::{Keypair, RandomizedSigner};

    /// Fixed-byte RNG so keygen/sign stay reproducible.
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

    fn roundtrip<P: MlDsaParams>() {
        let signer = MlDsaSigner::<P>::try_generate_from_rng(&mut FixedRng(0x42)).unwrap();
        let pk = KeyExport::to_bytes(&signer.verifying_key());
        let msg = b"krabitls ml-dsa kat";
        let sig: MlDsaSignature<P> = signer.sign_with_rng(&mut FixedRng(0x55), msg);

        let prepared = MlDsaVerifierKey::new(pk.as_ref()).unwrap();
        prepared
            .verify(msg, &MlDsaSig(sig.as_ref()))
            .expect("valid signature verifies");
        prepared
            .verify(b"tampered", &MlDsaSig(sig.as_ref()))
            .expect_err("wrong message rejected");
    }

    #[test]
    fn roundtrip_mldsa44() {
        roundtrip::<MlDsa44>();
    }

    #[test]
    fn roundtrip_mldsa65() {
        roundtrip::<MlDsa65>();
    }

    #[test]
    fn roundtrip_mldsa87() {
        roundtrip::<MlDsa87>();
    }

    #[test]
    fn rejects_unknown_pubkey_length() {
        assert!(MlDsaVerifierKey::new(&[0u8; 10]).is_err());
    }
}
