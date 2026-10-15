#![no_std]

//! Renesas RA6M5 SCE9 protected-mode backend for KrabiTLS.
//!
//! SCE9's protected API executes opaque Renesas command sequences. Board code
//! supplies a reset deadline that remains live across every C call; if a
//! command does not return, that deadline must reset the MCU before any
//! stack-backed argument can escape its lifetime.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use krabitls::client::{
    ClientAuth, ClientAuthError, ClientSignature, HkdfBackendError, HkdfExpandError, HkdfSha256,
    Sha256,
};
use rand_core::{TryCryptoRng, TryRng};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const AES_WRAPPED_WORDS: usize = 17;
const P256_PAIR_WORDS: usize = 48;
const P256_PRIVATE_WORDS: usize = 18;
const ECDH_HANDLE_WORDS: usize = 5;
const ECDH_WRAPPED_WORDS: usize = 14;
const SHA_STATE_WORDS: usize = 44;
#[cfg(any(target_arch = "arm", test))]
const FSP_FAIL: u32 = 0x0001_0002;

/// Board-owned independent reset deadline used to bound opaque SCE9 calls.
#[derive(Clone, Copy)]
pub struct Sce9Deadline {
    arm: fn(),
    disarm: fn(),
}

impl Sce9Deadline {
    /// Build a deadline from non-blocking board callbacks. `arm` must arrange
    /// an MCU reset independently of SCE9 execution; `disarm` cancels it.
    pub const fn new(arm: fn(), disarm: fn()) -> Self {
        Self { arm, disarm }
    }
}

/// Exclusive ownership token for the RA6M5 SCE9 peripheral.
pub struct Sce9Crypto {
    entropy_seen: AtomicBool,
    previous_entropy: AtomicU32,
}

/// A device-bound SCE9 AES-128 key index. Plain key bytes never exist in RAM.
pub struct WrappedAes128Key(Zeroizing<[u32; AES_WRAPPED_WORDS]>);

/// A device-bound P-256 pair containing a wrapped private scalar and public key.
pub struct WrappedP256KeyPair {
    pair: Zeroizing<[u32; P256_PAIR_WORDS]>,
    public: [u8; 64],
}

/// Single-use-style ECDHE state with a dedicated SCE9 wrapped scalar.
pub struct WrappedP256Ephemeral {
    handle: Zeroizing<[u32; ECDH_HANDLE_WORDS]>,
    private: Zeroizing<[u32; P256_PRIVATE_WORDS]>,
    public: [u8; 64],
    #[cfg(feature = "qualification")]
    signature: [u8; 64],
}

/// A device-bound ECDH shared secret and its single active SCE9 context.
/// SCE9 does not permit exporting the secret bytes.
pub struct WrappedEcdhSecret {
    handle: Zeroizing<[u32; ECDH_HANDLE_WORDS]>,
    secret: Zeroizing<[u32; ECDH_WRAPPED_WORDS]>,
}

/// SHA-256/HMAC/HKDF implementation using SCE9's compression engine.
pub struct Sce9Hkdf;

/// Cloneable incremental SCE9 SHA-256 state used by the TLS transcript.
#[derive(Clone)]
pub struct Sce9Sha256 {
    state: [u32; SHA_STATE_WORDS],
    failed: bool,
}

/// True-random generator tied to the active SCE9 ownership period.
pub struct Sce9Rng<'a> {
    owner: &'a Sce9Crypto,
}

/// TLS client signer backed by a wrapped SCE9 P-256 private key.
pub struct Sce9P256Signer<'a> {
    key: &'a WrappedP256KeyPair,
    cert_der: &'a [u8],
}

/// Detailed failures retained at the hardware adapter boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sce9Error {
    NotClaimed,
    Busy,
    ResourceConflict,
    Internal,
    EntropyRetry,
    InvalidWrappedKey,
    Authentication,
    InvalidParameter,
    Prohibited,
    InvalidPeer,
    InvalidLength,
    EntropyHealth,
    Unknown(u32),
}

impl core::fmt::Display for Sce9Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "RA6M5 SCE9 failure: {self:?}")
    }
}

impl core::error::Error for Sce9Error {}

#[cfg(feature = "qualification")]
pub mod qualification {
    use super::*;

    /// Exercise the same zeroization carried by both parts of a wrapped ECDH
    /// secret without exposing either part through the public API.
    pub fn wrapped_secret_wipes() -> bool {
        let mut secret = WrappedEcdhSecret {
            handle: Zeroizing::new([0xa5a5_a5a5; ECDH_HANDLE_WORDS]),
            secret: Zeroizing::new([0x5a5a_5a5a; ECDH_WRAPPED_WORDS]),
        };
        secret.handle.zeroize();
        secret.secret.zeroize();
        secret.handle.iter().all(|word| *word == 0) && secret.secret.iter().all(|word| *word == 0)
    }
}

static CLAIMED: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch = "arm")]
static BUSY: AtomicBool = AtomicBool::new(false);
static DEADLINE_ARM: AtomicUsize = AtomicUsize::new(0);
static DEADLINE_DISARM: AtomicUsize = AtomicUsize::new(0);

impl Sce9Crypto {
    /// Claim SCE9 after board clock, security attribution, and reset-deadline
    /// setup are complete.
    ///
    /// # Safety
    ///
    /// No interrupt, ROM service, other core, or firmware may touch SCE9 until
    /// this token is dropped. The deadline callbacks must remain valid forever
    /// and must not call SCE9 themselves.
    pub unsafe fn claim_after_board_init(deadline: Sce9Deadline) -> Result<Self, Sce9Error> {
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| Sce9Error::Busy)?;
        DEADLINE_ARM.store(deadline.arm as usize, Ordering::Release);
        DEADLINE_DISARM.store(deadline.disarm as usize, Ordering::Release);

        initialize_hardware()?;

        Ok(Self {
            entropy_seen: AtomicBool::new(false),
            previous_entropy: AtomicU32::new(0),
        })
    }

    pub fn rng(&self) -> Sce9Rng<'_> {
        Sce9Rng { owner: self }
    }

    pub fn sha256(&self, message: &[u8]) -> Result<[u8; 32], Sce9Error> {
        let mut digest = [0; 32];
        with_hardware(|hardware| hardware.sha256(message, &mut digest))?;
        Ok(digest)
    }

    pub fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> Result<[u8; 32], Sce9Error> {
        hmac_parts(key, &[message])
    }

    pub fn hkdf_sha256(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Sce9Error> {
        let prk = extract(salt, ikm)?;
        expand(&prk, info, output)
    }

    pub fn generate_aes128_key(&self) -> Result<WrappedAes128Key, Sce9Error> {
        let mut key = Zeroizing::new([0; AES_WRAPPED_WORDS]);
        with_hardware(|hardware| hardware.aes128_generate(&mut key))?;
        Ok(WrappedAes128Key(key))
    }

    pub fn generate_p256_key_pair(&self) -> Result<WrappedP256KeyPair, Sce9Error> {
        let mut pair = Zeroizing::new([0; P256_PAIR_WORDS]);
        let mut public = [0; 64];
        with_hardware(|hardware| hardware.p256_generate(&mut pair, &mut public))?;
        Ok(WrappedP256KeyPair { pair, public })
    }
}

impl Drop for Sce9Crypto {
    fn drop(&mut self) {
        self.previous_entropy.store(0, Ordering::Release);
        self.entropy_seen.store(false, Ordering::Release);
        #[cfg(target_arch = "arm")]
        let _ = with_hardware(|hardware| hardware.close());
        CLAIMED.store(false, Ordering::Release);
        DEADLINE_ARM.store(0, Ordering::Release);
        DEADLINE_DISARM.store(0, Ordering::Release);
    }
}

impl WrappedAes128Key {
    pub fn encrypt_gcm(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Sce9Error> {
        if ciphertext.len() != plaintext.len() {
            return Err(Sce9Error::InvalidLength);
        }
        with_hardware(|hardware| {
            hardware.gcm_encrypt(&self.0, nonce, aad, plaintext, ciphertext, tag)
        })
    }

    pub fn decrypt_gcm(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Sce9Error> {
        if plaintext.len() != ciphertext.len() {
            return Err(Sce9Error::InvalidLength);
        }
        with_hardware(|hardware| {
            hardware.gcm_decrypt(&self.0, nonce, aad, ciphertext, plaintext, tag)
        })
    }
}

impl ZeroizeOnDrop for WrappedAes128Key {}
impl ZeroizeOnDrop for WrappedP256KeyPair {}
impl ZeroizeOnDrop for WrappedP256Ephemeral {}
impl ZeroizeOnDrop for WrappedEcdhSecret {}

impl WrappedP256KeyPair {
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let mut output = [0; 65];
        output[0] = 4;
        output[1..].copy_from_slice(&self.public);
        output
    }

    /// Generate the dedicated wrapped private index required by SCE9's ECDHE
    /// path. This key pair signs the ephemeral public key inside SCE9; the
    /// signature is not needed by TLS because its transcript authenticates the
    /// ServerHello key share.
    pub fn generate_ephemeral(&self) -> Result<WrappedP256Ephemeral, Sce9Error> {
        let mut handle = Zeroizing::new([0; ECDH_HANDLE_WORDS]);
        let mut private = Zeroizing::new([0; P256_PRIVATE_WORDS]);
        let mut public = [0; 64];
        let mut signature = [0; 64];
        with_hardware(|hardware| {
            hardware.p256_ecdh_generate(
                &self.pair,
                &mut handle,
                &mut private,
                &mut public,
                &mut signature,
            )
        })?;
        Ok(WrappedP256Ephemeral {
            handle,
            private,
            public,
            #[cfg(feature = "qualification")]
            signature,
        })
    }

    pub fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], Sce9Error> {
        let mut signature = [0; 64];
        with_hardware(|hardware| hardware.p256_sign(&self.pair, hash, &mut signature))?;
        Ok(signature)
    }

    pub fn verify_hash(&self, hash: &[u8; 32], signature: &[u8; 64]) -> Result<(), Sce9Error> {
        with_hardware(|hardware| hardware.p256_verify(&self.pair, hash, signature))
    }

    pub fn signer<'a>(&'a self, cert_der: &'a [u8]) -> Sce9P256Signer<'a> {
        Sce9P256Signer {
            key: self,
            cert_der,
        }
    }
}

impl WrappedP256Ephemeral {
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let mut output = [0; 65];
        output[0] = 4;
        output[1..].copy_from_slice(&self.public);
        output
    }

    /// Import an unauthenticated peer point through the corresponding FSP API.
    /// The qualified RA6M5 rejects the resulting wrapper during agreement; this
    /// method remains available so callers receive that hardware error and the
    /// qualification image can guard against accidental acceptance.
    pub fn derive_unverified(mut self, peer_sec1: &[u8]) -> Result<WrappedEcdhSecret, Sce9Error> {
        let peer: &[u8; 64] = peer_sec1
            .strip_prefix(&[4])
            .and_then(|value| value.try_into().ok())
            .ok_or(Sce9Error::InvalidPeer)?;
        let mut secret = Zeroizing::new([0; ECDH_WRAPPED_WORDS]);
        with_hardware(|hardware| {
            hardware.p256_ecdh_ephemeral(&mut self.handle, &self.private, peer, &mut secret)
        })?;
        Ok(WrappedEcdhSecret {
            handle: self.handle,
            secret,
        })
    }

    #[cfg(feature = "qualification")]
    pub fn derive_authenticated(
        mut self,
        peer: &WrappedP256Ephemeral,
        peer_signer: &WrappedP256KeyPair,
    ) -> Result<WrappedEcdhSecret, Sce9Error> {
        let mut secret = Zeroizing::new([0; ECDH_WRAPPED_WORDS]);
        with_hardware(|hardware| {
            hardware.p256_ecdh_authenticated(
                &mut self.handle,
                &self.private,
                &peer.public,
                &peer.signature,
                &peer_signer.pair,
                &mut secret,
            )
        })?;
        Ok(WrappedEcdhSecret {
            handle: self.handle,
            secret,
        })
    }
}

impl WrappedEcdhSecret {
    /// The wrapped secret deliberately has no byte-export API.
    pub fn wrapped_len(&self) -> usize {
        self.secret.len() * 4
    }

    /// Derive a device-bound AES-128 key with SCE9's SP800-56C one-step KDF.
    /// This is not the TLS 1.3 HKDF key schedule.
    pub fn derive_aes128(mut self, other_info: &[u8]) -> Result<WrappedAes128Key, Sce9Error> {
        if other_info.len() > 147 {
            return Err(Sce9Error::InvalidLength);
        }
        let mut key = Zeroizing::new([0; AES_WRAPPED_WORDS]);
        with_hardware(|hardware| {
            hardware.p256_ecdh_derive_aes128(&mut self.handle, &self.secret, other_info, &mut key)
        })?;
        Ok(WrappedAes128Key(key))
    }
}

impl TryRng for Sce9Rng<'_> {
    type Error = Sce9Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        if let Err(error) = with_hardware(|hardware| hardware.random(destination)) {
            destination.zeroize();
            return Err(error);
        }
        for chunk in destination.chunks(4) {
            if chunk.len() == 4 {
                let word = u32::from_ne_bytes(chunk.try_into().expect("four-byte chunk"));
                let previous = self.owner.previous_entropy.swap(word, Ordering::AcqRel);
                if self.owner.entropy_seen.swap(true, Ordering::AcqRel) && previous == word {
                    destination.zeroize();
                    return Err(Sce9Error::EntropyHealth);
                }
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for Sce9Rng<'_> {}

impl Default for Sce9Sha256 {
    fn default() -> Self {
        let mut state = [0; SHA_STATE_WORDS];
        let failed = with_hardware(|hardware| hardware.sha_init(&mut state)).is_err();
        Self { state, failed }
    }
}

impl Sha256 for Sce9Sha256 {
    fn update(&mut self, data: &[u8]) {
        if !self.failed
            && with_hardware(|hardware| hardware.sha_update(&mut self.state, data)).is_err()
        {
            self.failed = true;
        }
    }

    fn snapshot(&self) -> Result<[u8; 32], HkdfBackendError> {
        if self.failed {
            return Err(HkdfBackendError::Failed);
        }
        let mut digest = [0; 32];
        with_hardware(|hardware| hardware.sha_snapshot(&self.state, &mut digest))
            .map_err(|_| HkdfBackendError::Failed)?;
        Ok(digest)
    }
}

impl HkdfSha256 for Sce9Hkdf {
    type Hasher = Sce9Sha256;

    fn hasher() -> Self::Hasher {
        Sce9Sha256::default()
    }

    fn extract(salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, HkdfBackendError> {
        extract(salt, ikm).map_err(|_| HkdfBackendError::Failed)
    }

    fn expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), HkdfExpandError> {
        expand(prk, info, output).map_err(|error| match error {
            Sce9Error::InvalidLength => HkdfExpandError::OutputTooLong,
            _ => HkdfExpandError::Backend(HkdfBackendError::Failed),
        })
    }
}

impl<R: TryCryptoRng + ?Sized> ClientAuth<R> for Sce9P256Signer<'_> {
    fn cert_der(&self) -> &[u8] {
        self.cert_der
    }

    fn scheme(&self) -> u16 {
        0x0403
    }

    fn sign(&self, content: &[u8], _rng: &mut R) -> Result<ClientSignature, ClientAuthError> {
        let mut digest = [0; 32];
        with_hardware(|hardware| hardware.sha256(content, &mut digest))
            .map_err(|_| ClientAuthError)?;
        let signature = self.key.sign_hash(&digest).map_err(|_| ClientAuthError)?;
        der_ecdsa_signature(&signature)
    }
}

fn extract(salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, Sce9Error> {
    let zero_salt = [0; 32];
    let key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    Ok(Zeroizing::new(hmac_parts(key, &[ikm])?))
}

fn expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), Sce9Error> {
    if output.len() > 255 * 32 {
        return Err(Sce9Error::InvalidLength);
    }
    let mut previous = Zeroizing::new([0; 32]);
    let mut previous_len = 0;
    for (index, chunk) in output.chunks_mut(32).enumerate() {
        let counter = [(index + 1) as u8];
        *previous = hmac_parts(prk, &[&previous[..previous_len], info, &counter])?;
        chunk.copy_from_slice(&previous[..chunk.len()]);
        previous_len = 32;
    }
    Ok(())
}

fn hmac_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Sce9Error> {
    with_hardware(|hardware| {
        let mut normalized = Zeroizing::new([0; 64]);
        if key.len() > 64 {
            let mut digest = [0; 32];
            hardware.sha256(key, &mut digest)?;
            normalized[..32].copy_from_slice(&digest);
            digest.zeroize();
        } else {
            normalized[..key.len()].copy_from_slice(key);
        }
        let mut inner_pad = Zeroizing::new([0x36; 64]);
        let mut outer_pad = Zeroizing::new([0x5c; 64]);
        for index in 0..64 {
            inner_pad[index] ^= normalized[index];
            outer_pad[index] ^= normalized[index];
        }

        let mut state = Zeroizing::new([0; SHA_STATE_WORDS]);
        hardware.sha_init(&mut state)?;
        hardware.sha_update(&mut state, &inner_pad[..])?;
        for part in parts {
            hardware.sha_update(&mut state, part)?;
        }
        let mut inner = Zeroizing::new([0; 32]);
        hardware.sha_snapshot(&state, &mut inner)?;

        hardware.sha_init(&mut state)?;
        hardware.sha_update(&mut state, &outer_pad[..])?;
        hardware.sha_update(&mut state, &inner[..])?;
        let mut output = [0; 32];
        hardware.sha_snapshot(&state, &mut output)?;
        Ok(output)
    })
}

fn der_ecdsa_signature(raw: &[u8; 64]) -> Result<ClientSignature, ClientAuthError> {
    let mut body = ClientSignature::new();
    der_integer(&raw[..32], &mut body)?;
    der_integer(&raw[32..], &mut body)?;
    let mut output = ClientSignature::new();
    output.push(0x30).map_err(|_| ClientAuthError)?;
    output.push(body.len() as u8).map_err(|_| ClientAuthError)?;
    output
        .extend_from_slice(&body)
        .map_err(|_| ClientAuthError)?;
    Ok(output)
}

fn der_integer(value: &[u8], output: &mut ClientSignature) -> Result<(), ClientAuthError> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[first..];
    let prefix = usize::from(value[0] & 0x80 != 0);
    output.push(0x02).map_err(|_| ClientAuthError)?;
    output
        .push((value.len() + prefix) as u8)
        .map_err(|_| ClientAuthError)?;
    if prefix != 0 {
        output.push(0).map_err(|_| ClientAuthError)?;
    }
    output.extend_from_slice(value).map_err(|_| ClientAuthError)
}

#[cfg(any(target_arch = "arm", test))]
fn decode_status(status: u32) -> Result<(), Sce9Error> {
    match status {
        0 => Ok(()),
        0x0001_0001 => Err(Sce9Error::ResourceConflict),
        FSP_FAIL => Err(Sce9Error::Internal),
        0x0001_0004 => Err(Sce9Error::EntropyRetry),
        0x0001_0012 => Err(Sce9Error::InvalidWrappedKey),
        0x0001_0013 => Err(Sce9Error::Authentication),
        0x0001_0014 => Err(Sce9Error::InvalidParameter),
        0x0001_0015 => Err(Sce9Error::Prohibited),
        other => Err(Sce9Error::Unknown(other)),
    }
}

struct Hardware;

#[cfg(target_arch = "arm")]
fn initialize_hardware() -> Result<(), Sce9Error> {
    if let Err(error) = with_hardware(|hardware| hardware.open()) {
        CLAIMED.store(false, Ordering::Release);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(target_arch = "arm"))]
fn initialize_hardware() -> Result<(), Sce9Error> {
    CLAIMED.store(false, Ordering::Release);
    Err(Sce9Error::NotClaimed)
}

#[cfg(target_arch = "arm")]
impl Hardware {
    fn open(&mut self) -> Result<(), Sce9Error> {
        decode_status(unsafe { ffi::krabitls_sce9_open() })
    }

    fn close(&mut self) -> Result<(), Sce9Error> {
        decode_status(unsafe { ffi::krabitls_sce9_close() })
    }

    fn random(&mut self, output: &mut [u8]) -> Result<(), Sce9Error> {
        let length = u32::try_from(output.len()).map_err(|_| Sce9Error::InvalidLength)?;
        decode_status(unsafe { ffi::krabitls_sce9_random(output.as_mut_ptr(), length) })
    }

    fn sha256(&mut self, message: &[u8], output: &mut [u8; 32]) -> Result<(), Sce9Error> {
        let length = u32::try_from(message.len()).map_err(|_| Sce9Error::InvalidLength)?;
        decode_status(unsafe {
            ffi::krabitls_sce9_sha256(message.as_ptr(), length, output.as_mut_ptr())
        })
    }

    fn sha_init(&mut self, state: &mut [u32; SHA_STATE_WORDS]) -> Result<(), Sce9Error> {
        decode_status(unsafe { ffi::krabitls_sce9_sha256_init(state.as_mut_ptr().cast()) })
    }

    fn sha_update(
        &mut self,
        state: &mut [u32; SHA_STATE_WORDS],
        message: &[u8],
    ) -> Result<(), Sce9Error> {
        let length = u32::try_from(message.len()).map_err(|_| Sce9Error::InvalidLength)?;
        decode_status(unsafe {
            ffi::krabitls_sce9_sha256_update(state.as_mut_ptr().cast(), message.as_ptr(), length)
        })
    }

    fn sha_snapshot(
        &mut self,
        state: &[u32; SHA_STATE_WORDS],
        output: &mut [u8; 32],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_sha256_snapshot(state.as_ptr().cast(), output.as_mut_ptr())
        })
    }

    fn aes128_generate(&mut self, key: &mut [u32; AES_WRAPPED_WORDS]) -> Result<(), Sce9Error> {
        decode_status(unsafe { ffi::krabitls_sce9_aes128_generate(key.as_mut_ptr().cast()) })
    }

    fn gcm_encrypt(
        &mut self,
        key: &[u32; AES_WRAPPED_WORDS],
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Sce9Error> {
        let aad_len = u32::try_from(aad.len()).map_err(|_| Sce9Error::InvalidLength)?;
        let length = u32::try_from(input.len()).map_err(|_| Sce9Error::InvalidLength)?;
        decode_status(unsafe {
            ffi::krabitls_sce9_aes128_gcm_encrypt(
                key.as_ptr().cast(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad_len,
                input.as_ptr(),
                output.as_mut_ptr(),
                length,
                tag.as_mut_ptr(),
            )
        })
    }

    fn gcm_decrypt(
        &mut self,
        key: &[u32; AES_WRAPPED_WORDS],
        nonce: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Sce9Error> {
        let aad_len = u32::try_from(aad.len()).map_err(|_| Sce9Error::InvalidLength)?;
        let length = u32::try_from(input.len()).map_err(|_| Sce9Error::InvalidLength)?;
        let status = unsafe {
            ffi::krabitls_sce9_aes128_gcm_decrypt(
                key.as_ptr().cast(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad_len,
                input.as_ptr(),
                output.as_mut_ptr(),
                length,
                tag.as_ptr(),
            )
        };
        if status == FSP_FAIL {
            Err(Sce9Error::Authentication)
        } else {
            decode_status(status)
        }
    }

    fn p256_generate(
        &mut self,
        pair: &mut [u32; P256_PAIR_WORDS],
        public: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_generate(pair.as_mut_ptr().cast(), public.as_mut_ptr())
        })
    }

    fn p256_ecdh_generate(
        &mut self,
        pair: &[u32; P256_PAIR_WORDS],
        handle: &mut [u32; ECDH_HANDLE_WORDS],
        private: &mut [u32; P256_PRIVATE_WORDS],
        public: &mut [u8; 64],
        signature: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_ecdh_generate(
                pair.as_ptr().cast(),
                handle.as_mut_ptr().cast(),
                private.as_mut_ptr().cast(),
                public.as_mut_ptr(),
                signature.as_mut_ptr(),
            )
        })
    }

    #[cfg(feature = "qualification")]
    fn p256_ecdh_authenticated(
        &mut self,
        handle: &mut [u32; ECDH_HANDLE_WORDS],
        private: &[u32; P256_PRIVATE_WORDS],
        peer: &[u8; 64],
        peer_signature: &[u8; 64],
        peer_signer: &[u32; P256_PAIR_WORDS],
        secret: &mut [u32; ECDH_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_ecdh_authenticated(
                handle.as_mut_ptr().cast(),
                private.as_ptr().cast(),
                peer.as_ptr(),
                peer_signature.as_ptr(),
                peer_signer.as_ptr().cast(),
                secret.as_mut_ptr().cast(),
            )
        })
    }

    fn p256_ecdh_ephemeral(
        &mut self,
        handle: &mut [u32; ECDH_HANDLE_WORDS],
        private: &[u32; P256_PRIVATE_WORDS],
        peer: &[u8; 64],
        secret: &mut [u32; ECDH_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_ecdh_ephemeral(
                handle.as_mut_ptr().cast(),
                private.as_ptr().cast(),
                peer.as_ptr(),
                secret.as_mut_ptr().cast(),
            )
        })
    }

    fn p256_ecdh_derive_aes128(
        &mut self,
        handle: &mut [u32; ECDH_HANDLE_WORDS],
        secret: &[u32; ECDH_WRAPPED_WORDS],
        other_info: &[u8],
        key: &mut [u32; AES_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        let length = u32::try_from(other_info.len()).map_err(|_| Sce9Error::InvalidLength)?;
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_ecdh_derive_aes128(
                handle.as_mut_ptr().cast(),
                secret.as_ptr().cast(),
                other_info.as_ptr(),
                length,
                key.as_mut_ptr().cast(),
            )
        })
    }

    fn p256_sign(
        &mut self,
        pair: &[u32; P256_PAIR_WORDS],
        hash: &[u8; 32],
        signature: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        decode_status(unsafe {
            ffi::krabitls_sce9_p256_sign_hash(
                pair.as_ptr().cast(),
                hash.as_ptr(),
                signature.as_mut_ptr(),
            )
        })
    }

    fn p256_verify(
        &mut self,
        pair: &[u32; P256_PAIR_WORDS],
        hash: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), Sce9Error> {
        let status = unsafe {
            ffi::krabitls_sce9_p256_verify_hash(
                pair.as_ptr().cast(),
                hash.as_ptr(),
                signature.as_ptr(),
            )
        };
        if status == FSP_FAIL {
            Err(Sce9Error::Authentication)
        } else {
            decode_status(status)
        }
    }
}

#[cfg(not(target_arch = "arm"))]
impl Hardware {
    fn random(&mut self, _output: &mut [u8]) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }

    #[cfg(feature = "qualification")]
    fn p256_ecdh_authenticated(
        &mut self,
        _handle: &mut [u32; ECDH_HANDLE_WORDS],
        _private: &[u32; P256_PRIVATE_WORDS],
        _peer: &[u8; 64],
        _peer_signature: &[u8; 64],
        _peer_signer: &[u32; P256_PAIR_WORDS],
        _secret: &mut [u32; ECDH_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn sha256(&mut self, _message: &[u8], _output: &mut [u8; 32]) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn sha_init(&mut self, _state: &mut [u32; SHA_STATE_WORDS]) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn sha_update(
        &mut self,
        _state: &mut [u32; SHA_STATE_WORDS],
        _message: &[u8],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn sha_snapshot(
        &mut self,
        _state: &[u32; SHA_STATE_WORDS],
        _output: &mut [u8; 32],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn aes128_generate(&mut self, _key: &mut [u32; AES_WRAPPED_WORDS]) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn gcm_encrypt(
        &mut self,
        _key: &[u32; AES_WRAPPED_WORDS],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _input: &[u8],
        _output: &mut [u8],
        _tag: &mut [u8; 16],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn gcm_decrypt(
        &mut self,
        _key: &[u32; AES_WRAPPED_WORDS],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _input: &[u8],
        _output: &mut [u8],
        _tag: &[u8; 16],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn p256_generate(
        &mut self,
        _pair: &mut [u32; P256_PAIR_WORDS],
        _public: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn p256_ecdh_generate(
        &mut self,
        _pair: &[u32; P256_PAIR_WORDS],
        _handle: &mut [u32; ECDH_HANDLE_WORDS],
        _private: &mut [u32; P256_PRIVATE_WORDS],
        _public: &mut [u8; 64],
        _signature: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn p256_ecdh_ephemeral(
        &mut self,
        _handle: &mut [u32; ECDH_HANDLE_WORDS],
        _private: &[u32; P256_PRIVATE_WORDS],
        _peer: &[u8; 64],
        _secret: &mut [u32; ECDH_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }

    fn p256_ecdh_derive_aes128(
        &mut self,
        _handle: &mut [u32; ECDH_HANDLE_WORDS],
        _secret: &[u32; ECDH_WRAPPED_WORDS],
        _other_info: &[u8],
        _key: &mut [u32; AES_WRAPPED_WORDS],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn p256_sign(
        &mut self,
        _pair: &[u32; P256_PAIR_WORDS],
        _hash: &[u8; 32],
        _signature: &mut [u8; 64],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
    fn p256_verify(
        &mut self,
        _pair: &[u32; P256_PAIR_WORDS],
        _hash: &[u8; 32],
        _signature: &[u8; 64],
    ) -> Result<(), Sce9Error> {
        Err(Sce9Error::NotClaimed)
    }
}

#[cfg(target_arch = "arm")]
fn with_hardware<T>(
    operation: impl FnOnce(&mut Hardware) -> Result<T, Sce9Error>,
) -> Result<T, Sce9Error> {
    if !CLAIMED.load(Ordering::Acquire) {
        return Err(Sce9Error::NotClaimed);
    }
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Sce9Error::Busy)?;
    let arm = DEADLINE_ARM.load(Ordering::Acquire);
    let disarm = DEADLINE_DISARM.load(Ordering::Acquire);
    if arm == 0 || disarm == 0 {
        BUSY.store(false, Ordering::Release);
        return Err(Sce9Error::NotClaimed);
    }
    let arm: fn() = unsafe { core::mem::transmute(arm) };
    let disarm: fn() = unsafe { core::mem::transmute(disarm) };
    arm();
    let result = operation(&mut Hardware);
    disarm();
    BUSY.store(false, Ordering::Release);
    result
}

#[cfg(not(target_arch = "arm"))]
fn with_hardware<T>(
    _operation: impl FnOnce(&mut Hardware) -> Result<T, Sce9Error>,
) -> Result<T, Sce9Error> {
    Err(Sce9Error::NotClaimed)
}

#[cfg(target_arch = "arm")]
mod ffi {
    unsafe extern "C" {
        pub fn krabitls_sce9_open() -> u32;
        pub fn krabitls_sce9_close() -> u32;
        pub fn krabitls_sce9_random(output: *mut u8, length: u32) -> u32;
        pub fn krabitls_sce9_sha256(message: *const u8, length: u32, output: *mut u8) -> u32;
        pub fn krabitls_sce9_sha256_init(state: *mut u8) -> u32;
        pub fn krabitls_sce9_sha256_update(state: *mut u8, message: *const u8, length: u32) -> u32;
        pub fn krabitls_sce9_sha256_snapshot(state: *const u8, output: *mut u8) -> u32;
        pub fn krabitls_sce9_aes128_generate(key: *mut u8) -> u32;
        pub fn krabitls_sce9_aes128_gcm_encrypt(
            key: *const u8,
            nonce: *const u8,
            aad: *const u8,
            aad_length: u32,
            input: *const u8,
            output: *mut u8,
            length: u32,
            tag: *mut u8,
        ) -> u32;
        pub fn krabitls_sce9_aes128_gcm_decrypt(
            key: *const u8,
            nonce: *const u8,
            aad: *const u8,
            aad_length: u32,
            input: *const u8,
            output: *mut u8,
            length: u32,
            tag: *const u8,
        ) -> u32;
        pub fn krabitls_sce9_p256_generate(pair: *mut u8, public_key: *mut u8) -> u32;
        pub fn krabitls_sce9_p256_ecdh_generate(
            signing_pair: *const u8,
            ecdh_handle: *mut u8,
            ephemeral_private: *mut u8,
            public_key: *mut u8,
            public_signature: *mut u8,
        ) -> u32;
        #[cfg(feature = "qualification")]
        pub fn krabitls_sce9_p256_ecdh_authenticated(
            ecdh_handle: *mut u8,
            ephemeral_private: *const u8,
            peer_public: *const u8,
            peer_signature: *const u8,
            peer_signing_pair: *const u8,
            wrapped_secret: *mut u8,
        ) -> u32;
        pub fn krabitls_sce9_p256_ecdh_ephemeral(
            ecdh_handle: *mut u8,
            ephemeral_private: *const u8,
            peer_public: *const u8,
            wrapped_secret: *mut u8,
        ) -> u32;
        pub fn krabitls_sce9_p256_ecdh_derive_aes128(
            ecdh_handle: *mut u8,
            wrapped_secret: *const u8,
            other_info: *const u8,
            other_info_length: u32,
            wrapped_key: *mut u8,
        ) -> u32;
        pub fn krabitls_sce9_p256_sign_hash(
            pair: *const u8,
            hash: *const u8,
            signature: *mut u8,
        ) -> u32;
        pub fn krabitls_sce9_p256_verify_hash(
            pair: *const u8,
            hash: *const u8,
            signature: *const u8,
        ) -> u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_refuses_hardware_claim() {
        let deadline = Sce9Deadline::new(|| {}, || {});
        assert!(matches!(
            unsafe { Sce9Crypto::claim_after_board_init(deadline) },
            Err(Sce9Error::NotClaimed)
        ));
    }

    #[test]
    fn wrapped_types_have_only_opaque_device_storage() {
        assert_eq!(core::mem::size_of::<WrappedAes128Key>(), 68);
        assert_eq!(core::mem::size_of::<WrappedP256KeyPair>(), 256);
        assert_eq!(core::mem::size_of::<WrappedEcdhSecret>(), 76);
        assert!(core::mem::needs_drop::<WrappedP256KeyPair>());
        assert!(core::mem::needs_drop::<WrappedP256Ephemeral>());
        assert!(core::mem::needs_drop::<WrappedEcdhSecret>());
    }

    #[test]
    fn status_mapping_preserves_unknown_codes() {
        assert_eq!(decode_status(0), Ok(()));
        assert_eq!(decode_status(0x0001_0013), Err(Sce9Error::Authentication));
        assert_eq!(
            decode_status(0xfeed_beef),
            Err(Sce9Error::Unknown(0xfeed_beef))
        );
    }

    #[test]
    fn ecdsa_der_encoding_handles_sign_bits_and_zeroes() {
        let mut raw = [0; 64];
        raw[31] = 1;
        raw[32] = 0x80;
        let der = der_ecdsa_signature(&raw).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..5], &[0x02, 0x01, 0x01]);
        assert_eq!(&der[5..8], &[0x02, 0x21, 0x00]);
        assert_eq!(der.len(), 40);
    }

    #[test]
    fn backend_type_satisfies_krabitls_hkdf_contract() {
        fn hkdf<T: HkdfSha256>() {}
        hkdf::<Sce9Hkdf>();
    }

    #[test]
    fn malformed_peer_is_rejected_before_hardware_access() {
        let ephemeral = WrappedP256Ephemeral {
            handle: Zeroizing::new([0; ECDH_HANDLE_WORDS]),
            private: Zeroizing::new([0; P256_PRIVATE_WORDS]),
            public: [0; 64],
            #[cfg(feature = "qualification")]
            signature: [0; 64],
        };
        assert!(matches!(
            ephemeral.derive_unverified(&[4; 64]),
            Err(Sce9Error::InvalidPeer)
        ));
    }

    #[test]
    fn local_length_contracts_fail_before_hardware_access() {
        let key = WrappedAes128Key(Zeroizing::new([0; AES_WRAPPED_WORDS]));
        assert_eq!(
            key.encrypt_gcm(&[0; 12], &[], &[1], &mut [], &mut [0; 16]),
            Err(Sce9Error::InvalidLength)
        );

        let secret = WrappedEcdhSecret {
            handle: Zeroizing::new([0; ECDH_HANDLE_WORDS]),
            secret: Zeroizing::new([0; ECDH_WRAPPED_WORDS]),
        };
        assert!(matches!(
            secret.derive_aes128(&[0; 148]),
            Err(Sce9Error::InvalidLength)
        ));

        let mut oversized = [0; 255 * 32 + 1];
        assert!(matches!(
            Sce9Hkdf::expand(&[0; 32], &[], &mut oversized),
            Err(HkdfExpandError::OutputTooLong)
        ));
    }
}
