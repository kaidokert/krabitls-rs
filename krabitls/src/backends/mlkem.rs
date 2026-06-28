//! ML-KEM-768 (FIPS 203) key encapsulation on krabipqc — the client side of an
//! `X25519MLKEM768` hybrid TLS 1.3 key exchange: generate an ephemeral
//! keypair, advertise the encapsulation key in the client key_share, and
//! decapsulate the server's ciphertext into a shared secret.

use krabipqc::ml_kem_768;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// Encapsulation-key byte length sent in the client key_share.
pub const MLKEM768_EK_BYTES: usize = ml_kem_768::EK_BYTES;
/// Ciphertext byte length received in the server key_share.
pub const MLKEM768_CT_BYTES: usize = ml_kem_768::CT_BYTES;
/// Shared-secret byte length.
pub const MLKEM768_SS_BYTES: usize = ml_kem_768::SHARED_SECRET_BYTES;

/// ML-KEM operation failed: an RNG error during keygen, or a structurally
/// unreachable encoding error. FIPS 203 decapsulation never fails
/// cryptographically (implicit rejection yields a deterministic secret), so a
/// failure here is never a peer-controlled rejection signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlKem768Error;

/// Client-side ML-KEM-768 ephemeral: holds the secret decapsulation key
/// (zeroized on drop) until the server's ciphertext arrives.
pub struct MlKem768 {
    dk: Zeroizing<[u8; ml_kem_768::DK_BYTES]>,
}

impl MlKem768 {
    /// Generate an ephemeral keypair. Returns the decapsulation-key holder plus
    /// the public encapsulation key to advertise in the client key_share.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self, [u8; MLKEM768_EK_BYTES]), MlKem768Error> {
        let (ek, dk) = ml_kem_768::keygen(rng).map_err(|_| MlKem768Error)?;
        Ok((
            Self {
                dk: Zeroizing::new(dk),
            },
            ek,
        ))
    }

    /// Decapsulate the server's ciphertext into the shared secret.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8; MLKEM768_CT_BYTES],
    ) -> Result<Zeroizing<[u8; MLKEM768_SS_BYTES]>, MlKem768Error> {
        ml_kem_768::decaps(&self.dk, ciphertext)
            .map(Zeroizing::new)
            .map_err(|_| MlKem768Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

    /// Fixed-byte RNG so keygen/encaps stay reproducible.
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
    fn generate_then_decapsulate_round_trips() {
        let (kem, ek) = MlKem768::generate(&mut FixedRng(0x42)).unwrap();
        // Server side: encapsulate to the advertised key.
        let (ss_server, ct) = ml_kem_768::encaps(&ek, &mut FixedRng(0x77)).unwrap();
        let ss_client = kem.decapsulate(&ct).unwrap();
        assert_eq!(ss_client.as_slice(), ss_server.as_slice());
    }

    /// Cross-implementation: krabipqc reproduces openssl's encapsulation key
    /// from openssl's seed, and decapsulates openssl's ciphertext to openssl's
    /// shared secret — the exact interop a hybrid handshake needs (server
    /// encapsulates, client decapsulates).
    #[test]
    fn matches_openssl_kat() {
        const KAT: [u8; 2368] = crate::hex_decode(include_str!(
            "../../../testdata/mlkem/mlkem768_openssl_kat.hex"
        ));
        let (d, rest) = KAT.split_at(32);
        let (z, rest) = rest.split_at(32);
        let (ek_expected, rest) = rest.split_at(MLKEM768_EK_BYTES);
        let (ct, ss_expected) = rest.split_at(MLKEM768_CT_BYTES);

        let (ek, dk) =
            ml_kem_768::keygen_from_seed(d.try_into().unwrap(), z.try_into().unwrap()).unwrap();
        assert_eq!(&ek[..], ek_expected, "keygen diverged from openssl");

        let ss = ml_kem_768::decaps(&dk, ct.try_into().unwrap()).unwrap();
        assert_eq!(&ss[..], ss_expected, "decapsulated secret diverged");
    }
}
