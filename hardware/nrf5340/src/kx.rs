use krabitls::client::{ClientShareBuf, KxBackend, KxGroup, SharedSecretBuf};
use zeroize::Zeroizing;

use crate::{CryptoCellError, ffi};

const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Nrf5340KxError {
    Rng,
    InvalidScalar,
    MalformedShare,
    CryptoCell(CryptoCellError),
}

pub struct Nrf5340P256Group;
pub struct Nrf5340Kx;

impl KxGroup for Nrf5340P256Group {
    const NAMED_GROUP: u16 = 0x0017;
    const CLIENT_SHARE_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;
    type Secret = Zeroizing<[u8; 32]>;
    type Error = Nrf5340KxError;

    fn generate<R: rand_core::TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let mut private_key = Zeroizing::new([0; 32]);
        let mut valid = false;
        for _ in 0..16 {
            rand_core::TryRng::try_fill_bytes(rng, &mut private_key[..])
                .map_err(|_| Nrf5340KxError::Rng)?;
            if private_scalar_is_valid(&private_key) {
                valid = true;
                break;
            }
        }
        if !valid {
            return Err(Nrf5340KxError::InvalidScalar);
        }

        let mut public_key = [0; 65];
        ffi::p256_public(&private_key, &mut public_key).map_err(Nrf5340KxError::CryptoCell)?;
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&public_key)
            .map_err(|_| Nrf5340KxError::MalformedShare)?;
        Ok((private_key, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let public_key: &[u8; 65] = server_share
            .try_into()
            .map_err(|_| Nrf5340KxError::MalformedShare)?;
        let mut shared = Zeroizing::new([0; 32]);
        ffi::p256_ecdh(&secret, public_key, &mut shared).map_err(Nrf5340KxError::CryptoCell)?;
        Ok(SharedSecretBuf::from_slice(&shared[..]))
    }
}

impl KxBackend for Nrf5340Kx {
    type X25519 = krabitls::client::X25519Group;
    type P256 = Nrf5340P256Group;
}

fn private_scalar_is_valid(candidate: &[u8; 32]) -> bool {
    let mut nonzero = 0;
    for byte in candidate {
        nonzero |= *byte;
    }
    let mut borrow = 0u16;
    for index in (0..candidate.len()).rev() {
        let difference = 0x100 + candidate[index] as u16 - P256_ORDER[index] as u16 - borrow;
        borrow = 1 ^ (difference >> 8);
    }
    nonzero != 0 && borrow == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_scalar_in_range_only() {
        let mut one = [0; 32];
        one[31] = 1;
        assert!(private_scalar_is_valid(&one));
        assert!(!private_scalar_is_valid(&[0; 32]));
        let mut order_minus_one = P256_ORDER;
        order_minus_one[31] -= 1;
        assert!(private_scalar_is_valid(&order_minus_one));
        assert!(!private_scalar_is_valid(&P256_ORDER));
        assert!(!private_scalar_is_valid(&[0xff; 32]));
    }
}
