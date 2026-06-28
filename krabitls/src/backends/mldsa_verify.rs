//! ML-DSA (FIPS 204) verification backend on krabipqc.
//!
//! [`MlDsaVerifierKey`] enums over the three FIPS 204 parameter sets and
//! implements [`signature::Verifier`] against [`MlDsaSig`] (borrowed signature
//! bytes), mirroring [`super::rsa_verify::RsaVerifierKey`]. The parameter set
//! is chosen from the public-key length at construction.

use krabipqc::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use signature::{Error as SigError, Verifier};

/// Borrowed ML-DSA signature bytes. Newtyped so a prepared [`MlDsaVerifierKey`]
/// implements [`signature::Verifier`]; the bytes stay borrowed through the
/// facade verify, so the 2–4.6 KiB signature is never copied onto the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsaSig<'a>(pub &'a [u8]);

/// Public-key bytes matched no FIPS 204 parameter set's encoded length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlDsaVerifyError;

/// Prepared ML-DSA verifying key: the raw public key, with its parameter set
/// (selected from the key length at [`MlDsaVerifierKey::new`]) carried by the
/// variant. Verifying reuses the inline key without re-parsing.
// Variant size is the parameter set's public key (1312–2592 B); no-alloc, so
// the larger keys can't be boxed away.
#[allow(clippy::large_enum_variant)]
pub enum MlDsaVerifierKey {
    MlDsa44([u8; ml_dsa_44::PK_BYTES]),
    MlDsa65([u8; ml_dsa_65::PK_BYTES]),
    MlDsa87([u8; ml_dsa_87::PK_BYTES]),
}

impl MlDsaVerifierKey {
    pub fn new(pubkey: &[u8]) -> Result<Self, MlDsaVerifyError> {
        match pubkey.len() {
            ml_dsa_44::PK_BYTES => pubkey
                .try_into()
                .map(Self::MlDsa44)
                .map_err(|_| MlDsaVerifyError),
            ml_dsa_65::PK_BYTES => pubkey
                .try_into()
                .map(Self::MlDsa65)
                .map_err(|_| MlDsaVerifyError),
            ml_dsa_87::PK_BYTES => pubkey
                .try_into()
                .map(Self::MlDsa87)
                .map_err(|_| MlDsaVerifyError),
            _ => Err(MlDsaVerifyError),
        }
    }
}

impl Verifier<MlDsaSig<'_>> for MlDsaVerifierKey {
    fn verify(&self, msg: &[u8], signature: &MlDsaSig<'_>) -> Result<(), SigError> {
        // A wrong-length signature fails the `&[u8; SIG_BYTES]` borrow, which
        // collapses to a verify failure rather than a panic.
        let verified = match self {
            Self::MlDsa44(pk) => <&[u8; ml_dsa_44::SIG_BYTES]>::try_from(signature.0)
                .is_ok_and(|sig| ml_dsa_44::verify(pk, msg, &[], sig)),
            Self::MlDsa65(pk) => <&[u8; ml_dsa_65::SIG_BYTES]>::try_from(signature.0)
                .is_ok_and(|sig| ml_dsa_65::verify(pk, msg, &[], sig)),
            Self::MlDsa87(pk) => <&[u8; ml_dsa_87::SIG_BYTES]>::try_from(signature.0)
                .is_ok_and(|sig| ml_dsa_87::verify(pk, msg, &[], sig)),
        };
        if verified {
            Ok(())
        } else {
            Err(SigError::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krabipqc::{KeyGenSeed, SigningRandomness};

    macro_rules! roundtrip_test {
        ($name:ident, $facade:ident) => {
            #[test]
            fn $name() {
                let (pk, sk) =
                    krabipqc::$facade::keygen_from_seed(&KeyGenSeed([0x42; 32])).unwrap();
                let msg = b"krabitls ml-dsa kat";
                let sig =
                    krabipqc::$facade::sign(&sk, msg, &[], &SigningRandomness([0x55; 32])).unwrap();

                let prepared = MlDsaVerifierKey::new(&pk).unwrap();
                prepared
                    .verify(msg, &MlDsaSig(&sig))
                    .expect("valid signature verifies");
                prepared
                    .verify(b"tampered", &MlDsaSig(&sig))
                    .expect_err("wrong message rejected");
                prepared
                    .verify(msg, &MlDsaSig(&sig[..sig.len() - 1]))
                    .expect_err("short signature rejected");
            }
        };
    }

    roundtrip_test!(roundtrip_mldsa44, ml_dsa_44);
    roundtrip_test!(roundtrip_mldsa65, ml_dsa_65);
    roundtrip_test!(roundtrip_mldsa87, ml_dsa_87);

    #[test]
    fn rejects_unknown_pubkey_length() {
        assert!(MlDsaVerifierKey::new(&[0u8; 10]).is_err());
    }
}
