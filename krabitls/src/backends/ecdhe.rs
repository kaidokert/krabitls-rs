//! Classical secp256r1 (P-256) ECDHE for the TLS 1.3 `key_share`: generate an
//! ephemeral keypair, advertise the SEC1 public point, and agree on the shared
//! secret against the server's point. Wraps krabiecdsa's constant-time `ecdh`
//! primitive over the shared CT carrier.

use crate::bigint::EcdsaP256CtBn;
use krabiecdsa::ecdh::EphemeralSecret;
use krabiecdsa::p256::P256;
use rand_core::TryCryptoRng;
use zeroize::Zeroizing;

/// SEC1-uncompressed public point (`0x04 || X || Y`) sent in the key_share, and
/// the length of the server's P-256 share.
pub const P256_SHARE_BYTES: usize = 65;
/// ECDH shared-secret length: the 32-byte affine X-coordinate of `d·P`.
pub const P256_SS_BYTES: usize = 32;

/// P-256 ECDHE failed: an RNG error during keygen, or a malformed / off-curve /
/// identity server point during agreement (the latter aborts the handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdheP256Error;

/// Client-side P-256 ECDHE ephemeral: holds the secret scalar (zeroized on drop
/// inside the krabiecdsa secret) until the server's share arrives.
pub struct EcdheP256 {
    secret: EphemeralSecret<P256, EcdsaP256CtBn>,
}

impl EcdheP256 {
    /// Generate an ephemeral keypair. Returns the secret holder plus the
    /// SEC1-uncompressed public point (`d·G`) to advertise in the key_share.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self, [u8; P256_SHARE_BYTES]), EcdheP256Error> {
        let secret = EphemeralSecret::random(rng).map_err(|_| EcdheP256Error)?;
        let pk = secret.public_key().ok_or(EcdheP256Error)?;
        let sec1 = pk.as_sec1_bytes();
        if sec1.len() != P256_SHARE_BYTES {
            return Err(EcdheP256Error);
        }
        let mut out = [0u8; P256_SHARE_BYTES];
        out.copy_from_slice(sec1);
        Ok((Self { secret }, out))
    }

    /// Agree on the shared secret `x(d·P)` from the server's SEC1 point,
    /// consuming the ephemeral (one-shot, matching krabiecdsa's `diffie_hellman`).
    /// `None` (mapped to `Err`) if the point is malformed, off-curve, or identity.
    pub fn agree(
        self,
        peer_share: &[u8; P256_SHARE_BYTES],
    ) -> Result<Zeroizing<[u8; P256_SS_BYTES]>, EcdheP256Error> {
        let ss = self
            .secret
            .diffie_hellman(peer_share)
            .ok_or(EcdheP256Error)?;
        let bytes = ss.as_bytes();
        if bytes.len() != P256_SS_BYTES {
            return Err(EcdheP256Error);
        }
        let mut out = Zeroizing::new([0u8; P256_SS_BYTES]);
        out.copy_from_slice(bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::Infallible;

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

    #[test]
    fn p256_ecdhe_rejects_off_curve_peer() {
        let (a, _) = EcdheP256::generate(&mut FixedRng(0x11)).unwrap();
        let mut bad = [0u8; P256_SHARE_BYTES];
        bad[0] = 0x04; // uncompressed tag, but X/Y all-zero → not on curve
        assert!(a.agree(&bad).is_err());
    }
}
