//! X25519 (Curve25519) ECDHE for the TLS 1.3 `key_share`: generate an ephemeral
//! keypair, advertise the 32-byte Montgomery point, and agree on the shared
//! secret against the server's point. Wraps ed25519_heapless's constant-time
//! X25519-as-KEM; the `blinding` feature selects the `Blinded` personality
//! (scalar/coordinate blinder drawn at keygen, spent once) over the default
//! `Unblinded`. The public point and shared secret are identical either way, and
//! the KEM rejects a low-order / all-zero shared secret (RFC 7748 §6.1) internally.

use crate::bigint::Curve25519CtBn as Bn;
use ed25519_heapless::x25519_kem::{DecapsulationKey, X25519Kem};
use kem::common::array::Array;
use kem::{Ciphertext, Decapsulator, Generate, KeyExport, TryDecapsulate};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "blinding")]
use ed25519_heapless::x25519_kem::Blinded as X25519Blinding;
#[cfg(not(feature = "blinding"))]
use ed25519_heapless::x25519_kem::Unblinded as X25519Blinding;

type X25519KemT = X25519Kem<Bn, X25519Blinding>;
type X25519DecapKey = DecapsulationKey<Bn, X25519Blinding>;

/// X25519 key_share length (the Montgomery u-coordinate) and shared-secret length.
pub const X25519_SHARE_BYTES: usize = 32;
/// ECDH shared-secret length.
pub const X25519_SS_BYTES: usize = 32;

/// X25519 ECDHE failed: an RNG error during keygen, or a malformed / low-order /
/// all-zero server point during agreement (the latter aborts the handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcdheX25519Error;

/// Client-side X25519 ECDHE ephemeral (secret zeroized on drop inside the
/// ed25519_heapless type), held until the server's share arrives.
pub struct EcdheX25519 {
    secret: X25519DecapKey,
}

// `secret` clears itself when the struct drops, so the marker is honest — it
// lets `KxGroup::Secret` require zeroize-on-drop of every backend.
impl zeroize::ZeroizeOnDrop for EcdheX25519 {}

impl EcdheX25519 {
    /// Generate an ephemeral keypair. Returns the secret holder plus the 32-byte
    /// public point (`d·G`) to advertise in the key_share. Under `blinding` the
    /// DPA blinder is drawn from `rng` after the scalar.
    pub fn generate<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self, [u8; X25519_SHARE_BYTES]), EcdheX25519Error> {
        let secret = X25519DecapKey::try_generate_from_rng(rng).map_err(|_| EcdheX25519Error)?;
        let pk = secret.encapsulation_key().to_bytes();
        if pk.len() != X25519_SHARE_BYTES {
            return Err(EcdheX25519Error);
        }
        let mut out = [0u8; X25519_SHARE_BYTES];
        out.copy_from_slice(pk.as_slice());
        Ok((Self { secret }, out))
    }

    /// Construct from a known 32-byte secret scalar, for fixture replay. Feeds
    /// `sk` as the KEM's scalar via a one-shot RNG; under `blinding` the blinder
    /// bytes that follow are zero (they don't affect the shared secret).
    #[cfg(test)]
    #[allow(dead_code)] // used by connection fixture tests, gated out in some feature combos
    pub(crate) fn from_secret_bytes(sk: &[u8; 32]) -> Result<Self, EcdheX25519Error> {
        struct OneShot<'a> {
            bytes: &'a [u8; 32],
            pos: usize,
        }
        impl rand_core::TryRng for OneShot<'_> {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(0)
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for b in dst {
                    *b = self.bytes.get(self.pos).copied().unwrap_or(0);
                    self.pos += 1;
                }
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for OneShot<'_> {}
        let (me, _pub) = Self::generate(&mut OneShot { bytes: sk, pos: 0 })?;
        Ok(me)
    }

    /// Agree on the shared secret from the server's 32-byte point. Consumes `self`
    /// (one-shot — under `blinding` the generation-time blinder is single-use).
    /// `Err` on a malformed, low-order, or all-zero result.
    pub fn agree(
        self,
        peer_share: &[u8; X25519_SHARE_BYTES],
    ) -> Result<Zeroizing<[u8; X25519_SS_BYTES]>, EcdheX25519Error> {
        let ct: Ciphertext<X25519KemT> =
            Array::try_from(&peer_share[..]).map_err(|_| EcdheX25519Error)?;
        let mut shared = self
            .secret
            .try_decapsulate(&ct)
            .map_err(|_| EcdheX25519Error)?;
        if shared.len() != X25519_SS_BYTES {
            shared.zeroize();
            return Err(EcdheX25519Error);
        }
        let mut out = Zeroizing::new([0u8; X25519_SS_BYTES]);
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
    use ed25519_heapless::x25519_kem::{Blinded, DecapsulationKey, Unblinded, X25519Kem};

    /// Fixed-byte RNG — reproducible, NOT a CSPRNG.
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
    fn x25519_ecdhe_round_trips() {
        let (a, a_pub) = EcdheX25519::generate(&mut FixedRng(0x42)).unwrap();
        let (b, b_pub) = EcdheX25519::generate(&mut FixedRng(0x77)).unwrap();
        assert_ne!(a_pub, b_pub);
        let ss_ab = a.agree(&b_pub).unwrap();
        let ss_ba = b.agree(&a_pub).unwrap();
        assert_eq!(ss_ab.as_slice(), ss_ba.as_slice());
    }

    #[test]
    fn x25519_ecdhe_rejects_low_order_peer() {
        let (a, _) = EcdheX25519::generate(&mut FixedRng(0x11)).unwrap();
        // All-zero u yields the all-zero shared secret → rejected.
        assert!(a.agree(&[0u8; X25519_SHARE_BYTES]).is_err());
    }

    /// RNG that pins the KEM's ephemeral scalar to a fixed 32-byte value, then —
    /// for `Blinded` — supplies deterministic NON-zero blinder bytes (the 32-bit
    /// scalar blind `r` and the 32-byte coordinate blind `λ`), so the KAT exercises
    /// a real blind rather than the degenerate all-zero one.
    struct ScalarRng([u8; 32], usize);
    impl rand_core::TryRng for ScalarRng {
        type Error = Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for b in dst {
                *b = if self.1 < 32 {
                    self.0[self.1]
                } else {
                    // High bit set → always non-zero; deterministic per position.
                    (self.1 as u8) | 0x80
                };
                self.1 += 1;
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for ScalarRng {}

    /// RFC 7748 §5.2 X25519 known-answer (`X25519(scalar, u) = out`). Assert BOTH
    /// the `Unblinded` and `Blinded` KEM personalities produce the standard shared
    /// secret — proving the blinder is output-transparent against a reference
    /// vector. Uses both markers explicitly, so it runs in every build (not only
    /// `blinding`) and gives the blinded math CI coverage.
    #[test]
    fn x25519_rfc7748_kat_both_personalities() {
        const SCALAR: [u8; 32] =
            crate::hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const PEER_U: [u8; 32] =
            crate::hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const EXPECTED: [u8; 32] =
            crate::hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let unblinded = {
            let dk =
                DecapsulationKey::<Bn, Unblinded>::try_generate_from_rng(&mut ScalarRng(SCALAR, 0))
                    .unwrap();
            let ct: Ciphertext<X25519Kem<Bn, Unblinded>> = Array::try_from(&PEER_U[..]).unwrap();
            dk.try_decapsulate(&ct).unwrap()
        };
        assert_eq!(unblinded.as_slice(), &EXPECTED, "unblinded KEM ≠ RFC 7748");

        let blinded = {
            let dk =
                DecapsulationKey::<Bn, Blinded>::try_generate_from_rng(&mut ScalarRng(SCALAR, 0))
                    .unwrap();
            let ct: Ciphertext<X25519Kem<Bn, Blinded>> = Array::try_from(&PEER_U[..]).unwrap();
            dk.try_decapsulate(&ct).unwrap()
        };
        assert_eq!(blinded.as_slice(), &EXPECTED, "blinded KEM ≠ RFC 7748");
    }
}
