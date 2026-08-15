//! Classical secp256r1 (P-256) ECDHE for the TLS 1.3 `key_share`: generate an
//! ephemeral keypair, advertise the SEC1 public point, and agree on the shared
//! secret against the server's point. Wraps krabiecdsa's constant-time ECDH-as-
//! KEM; the `blinding` feature selects the `Blinded` personality (scalar/
//! coordinate blinder drawn at keygen, spent once) over the default `Unblinded`.
//! The public point and shared secret are identical either way.

use crate::bigint::EcdsaP256CtBn;
use kem::common::array::Array;
use kem::{Ciphertext, Decapsulator, Generate, KeyExport, TryDecapsulate};
use krabiecdsa::ecdh::{DecapsulationKey, EcdhKem};
use krabiecdsa::p256::P256;
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "blinding")]
use krabiecdsa::ecdh::Blinded as P256Blinding;
#[cfg(not(feature = "blinding"))]
use krabiecdsa::ecdh::Unblinded as P256Blinding;

type P256Kem = EcdhKem<P256, EcdsaP256CtBn, P256Blinding>;
type P256DecapKey = DecapsulationKey<P256, EcdsaP256CtBn, P256Blinding>;

/// SEC1-uncompressed public point (`0x04 || X || Y`) sent in the key_share, and
/// the length of the server's P-256 share.
pub const P256_SHARE_BYTES: usize = 65;
/// ECDH shared-secret length: the 32-byte affine X-coordinate of `d·P`.
pub const P256_SS_BYTES: usize = 32;

/// P-256 ECDHE failed: an RNG error during keygen, or a malformed / off-curve /
/// identity server point during agreement (the latter aborts the handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdheP256Error;

/// Client-side P-256 ECDHE ephemeral: holds the decapsulation key until the
/// server's share arrives (secret zeroized on drop inside the krabiecdsa type).
pub struct EcdheP256 {
    secret: P256DecapKey,
}

impl EcdheP256 {
    /// Generate an ephemeral keypair. Returns the secret holder plus the
    /// SEC1-uncompressed public point (`d·G`) to advertise in the key_share.
    /// Under `blinding` the DPA blinder is drawn from `rng` alongside the scalar.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self, [u8; P256_SHARE_BYTES]), EcdheP256Error> {
        let secret = P256DecapKey::try_generate_from_rng(rng).map_err(|_| EcdheP256Error)?;
        let sec1 = secret.encapsulation_key().to_bytes();
        if sec1.len() != P256_SHARE_BYTES {
            return Err(EcdheP256Error);
        }
        let mut out = [0u8; P256_SHARE_BYTES];
        out.copy_from_slice(sec1.as_slice());
        Ok((Self { secret }, out))
    }

    /// Agree on the shared secret `x(d·P)` from the server's SEC1 point. Consumes
    /// `self` (one-shot — under `blinding` the generation-time blinder is
    /// single-use). `Err` if the point is malformed, off-curve, or identity.
    pub fn agree(
        self,
        peer_share: &[u8; P256_SHARE_BYTES],
    ) -> Result<Zeroizing<[u8; P256_SS_BYTES]>, EcdheP256Error> {
        let ct: Ciphertext<P256Kem> =
            Array::try_from(&peer_share[..]).map_err(|_| EcdheP256Error)?;
        let mut shared = self
            .secret
            .try_decapsulate(&ct)
            .map_err(|_| EcdheP256Error)?;
        if shared.len() != P256_SS_BYTES {
            shared.zeroize();
            return Err(EcdheP256Error);
        }
        let mut out = Zeroizing::new([0u8; P256_SS_BYTES]);
        out.copy_from_slice(shared.as_slice());
        // The `kem` SharedKey is a plain array (not Zeroizing) — wipe it.
        shared.zeroize();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use krabiecdsa::ecdh::{Blinded, Unblinded};

    /// Fixed-byte RNG — a constant fill is a valid in-range P-256 scalar, so
    /// rejection sampling accepts it first try; distinct constants give distinct
    /// ephemerals. Reproducible, NOT a CSPRNG.
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
    fn p256_ecdhe_round_trips() {
        let (a, a_pub) = EcdheP256::generate(&mut FixedRng(0x42)).unwrap();
        let (b, b_pub) = EcdheP256::generate(&mut FixedRng(0x77)).unwrap();
        assert_eq!(a_pub[0], 0x04);
        assert_eq!(b_pub[0], 0x04);
        assert_ne!(a_pub, b_pub);
        let ss_ab = a.agree(&b_pub).unwrap();
        let ss_ba = b.agree(&a_pub).unwrap();
        assert_eq!(ss_ab.as_slice(), ss_ba.as_slice());
    }

    /// The `Blinded` and `Unblinded` P-256 personalities agree on the same shared
    /// secret for the same scalar — the blinder is output-transparent. Names both
    /// markers explicitly, so it gives the blinded path coverage in every build.
    #[test]
    fn p256_blinded_matches_unblinded() {
        let (_b, b_pub) = EcdheP256::generate(&mut FixedRng(0x77)).unwrap();
        let unblinded = {
            let dk = DecapsulationKey::<P256, EcdsaP256CtBn, Unblinded>::try_generate_from_rng(
                &mut FixedRng(0x42),
            )
            .unwrap();
            let ct: Ciphertext<EcdhKem<P256, EcdsaP256CtBn, Unblinded>> =
                Array::try_from(&b_pub[..]).unwrap();
            dk.try_decapsulate(&ct).unwrap()
        };
        let blinded = {
            let dk = DecapsulationKey::<P256, EcdsaP256CtBn, Blinded>::try_generate_from_rng(
                &mut FixedRng(0x42),
            )
            .unwrap();
            let ct: Ciphertext<EcdhKem<P256, EcdsaP256CtBn, Blinded>> =
                Array::try_from(&b_pub[..]).unwrap();
            dk.try_decapsulate(&ct).unwrap()
        };
        assert_eq!(unblinded.as_slice(), blinded.as_slice());
    }

    #[test]
    fn p256_ecdhe_rejects_off_curve_peer() {
        let (a, _) = EcdheP256::generate(&mut FixedRng(0x11)).unwrap();
        let mut bad = [0u8; P256_SHARE_BYTES];
        bad[0] = 0x04; // uncompressed tag, but X/Y all-zero → not on curve
        assert!(a.agree(&bad).is_err());
    }
}
