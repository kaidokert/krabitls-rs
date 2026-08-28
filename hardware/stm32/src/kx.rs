use krabitls::client::{ClientShareBuf, KxBackend, KxGroup, SharedSecretBuf};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H533KxError {
    Rng,
    MalformedShare,
    Hardware,
    LowOrderPoint,
    InvalidScalar,
    P256Derive,
}

pub struct H533X25519Group;
pub struct H533P256Group;
pub struct H533Kx;

impl KxGroup for H533X25519Group {
    const NAMED_GROUP: u16 = 0x001d;
    const CLIENT_SHARE_LEN: usize = 32;
    const SHARED_SECRET_LEN: usize = 32;
    type Secret = Zeroizing<[u8; 32]>;
    type Error = H533KxError;

    fn generate<R: rand_core::TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let mut scalar = Zeroizing::new([0; 32]);
        rand_core::TryRng::try_fill_bytes(rng, &mut scalar[..]).map_err(|_| H533KxError::Rng)?;
        let mut base = [0; 32];
        base[0] = 9;
        let mut public = [0; 32];
        if !crate::pka::x25519(&scalar, &base, &mut public) {
            return Err(H533KxError::Hardware);
        }
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&public)
            .map_err(|_| H533KxError::MalformedShare)?;
        Ok((scalar, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let peer: &[u8; 32] = server_share
            .try_into()
            .map_err(|_| H533KxError::MalformedShare)?;
        let mut shared = Zeroizing::new([0; 32]);
        if !crate::pka::x25519(&secret, peer, &mut shared) {
            return Err(H533KxError::Hardware);
        }
        if shared.iter().fold(0, |acc, byte| acc | byte) == 0 {
            return Err(H533KxError::LowOrderPoint);
        }
        Ok(SharedSecretBuf::from_slice(&shared[..]))
    }
}

impl KxGroup for H533P256Group {
    const NAMED_GROUP: u16 = 0x0017;
    const CLIENT_SHARE_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;
    type Secret = Zeroizing<[u8; 32]>;
    type Error = H533KxError;

    fn generate<R: rand_core::TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let mut scalar = Zeroizing::new([0; 32]);
        let mut valid = false;
        for _ in 0..16 {
            rand_core::TryRng::try_fill_bytes(rng, &mut scalar[..])
                .map_err(|_| H533KxError::Rng)?;
            if crate::pka::p256_private_scalar_is_valid(&scalar) {
                valid = true;
                break;
            }
        }
        if !valid {
            return Err(H533KxError::InvalidScalar);
        }
        let mut public = [0; 65];
        if !crate::pka::p256_public_from_secret(&scalar, &mut public) {
            return Err(H533KxError::Hardware);
        }
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&public)
            .map_err(|_| H533KxError::MalformedShare)?;
        Ok((scalar, share))
    }

    fn derive(secret: Self::Secret, server_share: &[u8]) -> Result<SharedSecretBuf, Self::Error> {
        let peer: &[u8; 65] = server_share
            .try_into()
            .map_err(|_| H533KxError::MalformedShare)?;
        let mut shared = Zeroizing::new([0; 32]);
        if !crate::pka::p256_ecdh(&secret, peer, &mut shared) {
            return Err(H533KxError::P256Derive);
        }
        Ok(SharedSecretBuf::from_slice(&shared[..]))
    }
}

impl KxBackend for H533Kx {
    type X25519 = H533X25519Group;
    type P256 = H533P256Group;
}
