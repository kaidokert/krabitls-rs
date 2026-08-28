//! P-256 key exchange through the SAM D5x/E5x PUKCL ROM service.

use krabitls::client::{ClientShareBuf, KxBackend, KxGroup, SharedSecretBuf};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::pukcc;

const P256_BASE: [u8; 65] = hex_literal::hex!(
    "04\
     6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
     4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
);

/// P-256 ECDH group backed by the SAM D5x/E5x PUKCC point multiplier.
pub struct Same5xP256KxGroup;

/// KrabiTLS backend selecting hardware P-256 key exchange.
pub struct Same5xKx;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Same5xKxError {
    Rng,
    MalformedShare,
    Hardware,
    LowOrderPoint,
}

impl KxGroup for Same5xP256KxGroup {
    const NAMED_GROUP: u16 = 0x0017;
    const CLIENT_SHARE_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;
    type Secret = Zeroizing<[u8; 32]>;
    type Error = Same5xKxError;

    fn generate<R: rand_core::TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let mut scalar = Zeroizing::new([0; 32]);
        let mut public = [0; 65];

        for _ in 0..8 {
            rand_core::TryRng::try_fill_bytes(rng, &mut scalar[..])
                .map_err(|_| Same5xKxError::Rng)?;
            match pukcc::p256_scalar_mult(&scalar, &P256_BASE, &mut public) {
                Ok(()) => {
                    let mut share = ClientShareBuf::new();
                    share
                        .extend_from_slice(&public)
                        .map_err(|_| Same5xKxError::MalformedShare)?;
                    return Ok((scalar, share));
                }
                Err(pukcc::Error::InvalidOperand) => {}
                Err(_) => return Err(Same5xKxError::Hardware),
            }
        }

        Err(Same5xKxError::Rng)
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let peer: &[u8; 65] = server_share
            .try_into()
            .map_err(|_| Same5xKxError::MalformedShare)?;
        let mut point = Zeroizing::new([0; 65]);
        pukcc::p256_scalar_mult(&secret, peer, &mut point).map_err(|_| Same5xKxError::Hardware)?;
        let shared = &point[1..33];
        if bool::from(shared.ct_eq(&[0; 32])) {
            return Err(Same5xKxError::LowOrderPoint);
        }
        Ok(SharedSecretBuf::from_slice(shared))
    }
}

impl KxBackend for Same5xKx {
    type P256 = Same5xP256KxGroup;
}
