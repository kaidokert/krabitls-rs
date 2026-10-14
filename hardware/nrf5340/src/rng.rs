use crate::{CryptoCellError, ffi};

/// CryptoCell TRNG exposed through `rand_core`'s fallible RNG contract.
pub struct Nrf5340Rng;

impl rand_core::TryRng for Nrf5340Rng {
    type Error = CryptoCellError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        ffi::entropy(destination)
    }
}

impl rand_core::TryCryptoRng for Nrf5340Rng {}
