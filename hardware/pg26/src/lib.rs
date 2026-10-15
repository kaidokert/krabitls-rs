#![no_std]

//! Direct-register EFM32PG26 Secure Engine backend for KrabiTLS.
//!
//! Board code owns SEMAILBOX clocking, TrustZone attribution, interrupt policy,
//! and linker placement. After those prerequisites are established it may
//! claim [`Pg26Crypto`]. This crate serializes the mailbox, bounds every wait,
//! decodes SE responses, and clears software-held secrets and failed outputs.

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use krabitls::client::{ClientShareBuf, HkdfBackendError, HkdfExpandError, KxGroup};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(target_arch = "arm")]
mod raw;

/// Exclusive ownership token for the PG26 Secure Engine mailbox.
pub struct Pg26Crypto {
    entropy_seen: AtomicBool,
    previous_entropy: AtomicU32,
}

/// AES-128-GCM provider backed by the PG26 Secure Engine.
pub struct Aes128GcmHw {
    key: Zeroizing<[u8; 16]>,
}

/// KrabiTLS AEAD backend selecting PG26 hardware for AES-GCM records.
pub struct Pg26Aead;

/// P-256 ECDHE group with a PUF-wrapped, non-exportable ephemeral scalar.
pub struct Pg26P256Group;

/// SHA-256/HMAC/HKDF backend backed by the PG26 Secure Engine.
pub struct Pg26Hkdf;

/// Incremental PG26 SHA-256 state. Cloning copies only the chaining state,
/// byte count, and partial block; no secret key material is involved.
#[derive(Clone)]
pub struct Pg26Sha256 {
    state: [u8; 32],
    buffer: [u8; 64],
    total: u32,
    failed: bool,
}

/// Fallible TRNG borrowing the claimed mailbox lifetime.
pub struct Pg26Rng<'a> {
    owner: &'a Pg26Crypto,
}

/// Decoded adapter and Secure Engine failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pg26Error {
    NotClaimed,
    Busy,
    Poisoned,
    Timeout,
    MailboxProtocol,
    InvalidCommand,
    Authorization,
    Authentication,
    Bus,
    Internal,
    Crypto,
    InvalidParameter,
    NotInitialized,
    Aborted,
    InvalidLength,
    InvalidPeer,
    EntropyHealth,
    UnknownResponse(u32),
}

impl core::fmt::Display for Pg26Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PG26 Secure Engine failure: {self:?}")
    }
}

impl core::error::Error for Pg26Error {}

static CLAIMED: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
static POISONED: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: AtomicU8 = AtomicU8::new(0);

impl Pg26Crypto {
    /// Claim SEMAILBOX after board code enabled its clock and established the
    /// intended Secure/Non-secure attribution.
    ///
    /// # Safety
    ///
    /// No other firmware, interrupt handler, ROM service, or core may access
    /// SEMAILBOX until this token is dropped.
    pub unsafe fn claim_after_board_init() -> Result<Self, Pg26Error> {
        if POISONED.load(Ordering::Acquire) {
            return Err(Pg26Error::Poisoned);
        }
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .map_err(|_| Pg26Error::Busy)?;
        let owner = Self {
            entropy_seen: AtomicBool::new(false),
            previous_entropy: AtomicU32::new(0),
        };
        if let Err(error) = with_hardware(|hardware| hardware.probe()) {
            CLAIMED.store(false, Ordering::Release);
            return Err(error);
        }
        Ok(owner)
    }

    /// Clear the adapter poison only after the board has reset the host and SE
    /// command context, and no pre-reset DMA descriptor can remain live.
    ///
    /// # Safety
    ///
    /// The caller must establish that reset boundary and exclusive mailbox
    /// ownership before another claim.
    pub unsafe fn recover_after_board_reset() {
        BUSY.store(false, Ordering::Release);
        CLAIMED.store(false, Ordering::Release);
        POISONED.store(false, Ordering::Release);
    }

    pub fn rng(&self) -> Pg26Rng<'_> {
        Pg26Rng { owner: self }
    }

    pub fn sha256(&self, message: &[u8]) -> Result<[u8; 32], Pg26Error> {
        let mut output = Zeroizing::new([0u8; 32]);
        with_hardware(|hardware| hardware.sha256(message, &mut output))?;
        Ok(*output)
    }

    pub fn hmac_sha256(&self, key: &[u8], message: &[u8]) -> Result<[u8; 32], Pg26Error> {
        hmac(key, &[message])
    }

    pub fn hkdf_sha256(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<(), Pg26Error> {
        let prk = extract(salt, ikm)?;
        expand(&prk, info, output)
    }
}

impl Drop for Pg26Crypto {
    fn drop(&mut self) {
        self.previous_entropy.store(0, Ordering::Release);
        self.entropy_seen.store(false, Ordering::Release);
        CLAIMED.store(false, Ordering::Release);
    }
}

impl krabitls::client::AeadBackend for Pg26Aead {
    type Aes = krabitls::client::Aes128GcmSha256<Aes128GcmHw>;
}

impl KeySizeUser for Aes128GcmHw {
    type KeySize = U16;
}

impl KeyInit for Aes128GcmHw {
    fn new(key: &Key<Self>) -> Self {
        Self {
            key: Zeroizing::new((*key).into()),
        }
    }
}

impl Zeroize for Aes128GcmHw {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for Aes128GcmHw {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AeadCore for Aes128GcmHw {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for Aes128GcmHw {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        let output = buffer.into_out_with_copied_in();
        let nonce: [u8; 12] = (*nonce).into();
        let mut tag = [0u8; 16];
        match with_hardware(|hardware| {
            hardware.gcm_encrypt(&self.key, &nonce, associated_data, output, &mut tag)
        }) {
            Ok(()) => {
                LAST_ERROR.store(0, Ordering::Release);
                Ok(Array::from(tag))
            }
            Err(error) => {
                output.zeroize();
                tag.zeroize();
                Err(record_error(error))
            }
        }
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        let output = buffer.into_out_with_copied_in();
        let nonce: [u8; 12] = (*nonce).into();
        let tag: [u8; 16] = (*tag).into();
        match with_hardware(|hardware| {
            hardware.gcm_decrypt(&self.key, &nonce, associated_data, output, &tag)
        }) {
            Ok(()) => {
                LAST_ERROR.store(0, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                output.zeroize();
                Err(record_error(error))
            }
        }
    }
}

/// Wrapped P-256 private material. The 60-byte blob is the 32-byte scalar
/// encrypted and authenticated under the device PUF key plus the SE's 28-byte
/// wrapping overhead. It is unusable off-device and wiped on every drop path.
pub struct WrappedP256Secret(Zeroizing<[u8; 60]>);

impl ZeroizeOnDrop for WrappedP256Secret {}

impl KxGroup for Pg26P256Group {
    const NAMED_GROUP: u16 = 0x0017;
    const CLIENT_SHARE_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;

    type Secret = WrappedP256Secret;
    type Error = Pg26Error;

    fn generate<R: rand_core::TryCryptoRng + ?Sized>(
        _rng: &mut R,
    ) -> Result<(Self::Secret, ClientShareBuf), Self::Error> {
        let mut wrapped = Zeroizing::new([0u8; 60]);
        let mut public = [0u8; 64];
        with_hardware(|hardware| {
            hardware.generate_p256_wrapped(&mut wrapped)?;
            hardware.p256_public(&wrapped, &mut public)
        })?;
        let mut share = ClientShareBuf::new();
        share
            .extend_from_slice(&[4])
            .map_err(|_| Pg26Error::InvalidLength)?;
        share
            .extend_from_slice(&public)
            .map_err(|_| Pg26Error::InvalidLength)?;
        public.zeroize();
        Ok((WrappedP256Secret(wrapped), share))
    }

    fn derive(
        secret: Self::Secret,
        server_share: &[u8],
    ) -> Result<krabitls::client::SharedSecretBuf, Self::Error> {
        let peer: &[u8; 64] = server_share
            .strip_prefix(&[4])
            .and_then(|point| point.try_into().ok())
            .ok_or(Pg26Error::InvalidPeer)?;
        let mut full = Zeroizing::new([0u8; 64]);
        with_hardware(|hardware| hardware.p256_ecdh(&secret.0, peer, &mut full))?;
        Ok(krabitls::client::SharedSecretBuf::from_slice(&full[..32]))
    }
}

impl Default for Pg26Sha256 {
    fn default() -> Self {
        Self {
            state: [
                0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
                0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
                0x5b, 0xe0, 0xcd, 0x19,
            ],
            buffer: [0; 64],
            total: 0,
            failed: false,
        }
    }
}

impl krabitls::client::Sha256 for Pg26Sha256 {
    fn update(&mut self, mut data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }
        let Some(new_total) = self.total.checked_add(data.len() as u32) else {
            self.failed = true;
            return;
        };
        let pending = self.total as usize & 63;
        if pending != 0 {
            let take = (64 - pending).min(data.len());
            self.buffer[pending..pending + take].copy_from_slice(&data[..take]);
            data = &data[take..];
            if pending + take == 64 {
                if let Err(error) =
                    with_hardware(|hardware| hardware.sha256_update(&mut self.state, &self.buffer))
                {
                    record_pg26_error(error);
                    self.failed = true;
                    return;
                }
            }
        }
        let blocks = data.len() & !63;
        if blocks != 0 {
            if let Err(error) =
                with_hardware(|hardware| hardware.sha256_update(&mut self.state, &data[..blocks]))
            {
                record_pg26_error(error);
                self.failed = true;
                return;
            }
            data = &data[blocks..];
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.total = new_total;
    }

    fn snapshot(&self) -> Result<[u8; 32], HkdfBackendError> {
        if self.failed {
            return Err(HkdfBackendError::Failed);
        }
        let mut output = [0u8; 32];
        let tail = &self.buffer[..self.total as usize & 63];
        with_hardware(|hardware| {
            hardware.sha256_finish(&self.state, tail, self.total, &mut output)
        })
        .map_err(|error| {
            record_pg26_error(error);
            HkdfBackendError::Failed
        })?;
        Ok(output)
    }
}

impl krabitls::client::HkdfSha256 for Pg26Hkdf {
    type Hasher = Pg26Sha256;

    fn hasher() -> Self::Hasher {
        Pg26Sha256::default()
    }

    fn extract(salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, HkdfBackendError> {
        extract(salt, ikm).map_err(hkdf_error)
    }

    fn expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), HkdfExpandError> {
        if output.len() > 255 * 32 {
            return Err(HkdfExpandError::OutputTooLong);
        }
        expand(prk, info, output).map_err(|error| HkdfExpandError::Backend(hkdf_error(error)))
    }
}

impl rand_core::TryRng for Pg26Rng<'_> {
    type Error = Pg26Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        if let Err(error) = with_hardware(|hardware| hardware.random(output)) {
            output.zeroize();
            return Err(error);
        }
        for chunk in output.chunks_exact(4) {
            let word = u32::from_le_bytes(chunk.try_into().expect("four-byte chunk"));
            let previous = self.owner.previous_entropy.swap(word, Ordering::AcqRel);
            if self.owner.entropy_seen.swap(true, Ordering::AcqRel) && previous == word {
                output.zeroize();
                return Err(Pg26Error::EntropyHealth);
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Pg26Rng<'_> {}

fn extract(salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<[u8; 32]>, Pg26Error> {
    let zero_salt = [0u8; 32];
    let key = if salt.is_empty() {
        &zero_salt[..]
    } else {
        salt
    };
    Ok(Zeroizing::new(hmac(key, &[ikm])?))
}

fn expand(prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), Pg26Error> {
    if output.len() > 255 * 32 {
        return Err(Pg26Error::InvalidLength);
    }
    let result = (|| {
        let mut previous = Zeroizing::new([0u8; 32]);
        let mut previous_len = 0;
        for (index, chunk) in output.chunks_mut(32).enumerate() {
            let counter = [(index + 1) as u8];
            previous = Zeroizing::new(hmac(prk, &[&previous[..previous_len], info, &counter])?);
            chunk.copy_from_slice(&previous[..chunk.len()]);
            previous_len = 32;
        }
        Ok(())
    })();
    if result.is_err() {
        output.zeroize();
    }
    result
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], Pg26Error> {
    let zero_key = [0u8; 32];
    let key = if key.is_empty() { &zero_key[..] } else { key };
    let mut output = Zeroizing::new([0u8; 32]);
    with_hardware(|hardware| hardware.hmac_sha256_parts(key, parts, &mut output))?;
    Ok(*output)
}

fn hkdf_error(error: Pg26Error) -> HkdfBackendError {
    record_pg26_error(error);
    HkdfBackendError::Failed
}

pub fn last_error() -> Option<Pg26Error> {
    match LAST_ERROR.load(Ordering::Acquire) {
        1 => Some(Pg26Error::NotClaimed),
        2 => Some(Pg26Error::Busy),
        3 => Some(Pg26Error::Poisoned),
        4 => Some(Pg26Error::Timeout),
        5 => Some(Pg26Error::MailboxProtocol),
        6 => Some(Pg26Error::InvalidCommand),
        7 => Some(Pg26Error::Authorization),
        8 => Some(Pg26Error::Authentication),
        9 => Some(Pg26Error::Bus),
        10 => Some(Pg26Error::Internal),
        11 => Some(Pg26Error::Crypto),
        12 => Some(Pg26Error::InvalidParameter),
        13 => Some(Pg26Error::NotInitialized),
        14 => Some(Pg26Error::Aborted),
        15 => Some(Pg26Error::InvalidLength),
        16 => Some(Pg26Error::InvalidPeer),
        17 => Some(Pg26Error::EntropyHealth),
        _ => None,
    }
}

#[cfg(feature = "qualification")]
pub mod qualification {
    use super::*;

    /// Exercises the same zeroization carried by a wrapped ephemeral secret.
    pub fn wrapped_secret_wipes() -> bool {
        let mut secret = WrappedP256Secret(Zeroizing::new([0xa5; 60]));
        secret.0.zeroize();
        secret.0.iter().all(|byte| *byte == 0)
    }

    /// Exercises the cross-call continuous entropy test without consuming SE
    /// output and restores the token's health-test state afterwards.
    pub fn entropy_continuous_test(owner: &Pg26Crypto) -> bool {
        owner.entropy_seen.store(false, Ordering::Release);
        owner.previous_entropy.store(0, Ordering::Release);
        let first = accept_entropy(owner, 0x1234_5678).is_ok();
        let repeated = accept_entropy(owner, 0x1234_5678) == Err(Pg26Error::EntropyHealth);
        owner.entropy_seen.store(false, Ordering::Release);
        owner.previous_entropy.store(0, Ordering::Release);
        first && repeated
    }

    /// Verify that an ordinary rejected command releases the serialization
    /// guard and does not poison later operations. Timeouts deliberately need
    /// the stronger board-reset recovery boundary.
    #[cfg(target_arch = "arm")]
    pub fn command_error_recovery(owner: &Pg26Crypto) -> bool {
        let rejected = with_hardware(|_| raw::qualification_invalid_command())
            == Err(Pg26Error::InvalidCommand);
        rejected
            && owner.sha256(b"abc")
                == Ok([
                    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d,
                    0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10,
                    0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                ])
    }

    fn accept_entropy(owner: &Pg26Crypto, word: u32) -> Result<(), Pg26Error> {
        let previous = owner.previous_entropy.swap(word, Ordering::AcqRel);
        if owner.entropy_seen.swap(true, Ordering::AcqRel) && previous == word {
            Err(Pg26Error::EntropyHealth)
        } else {
            Ok(())
        }
    }
}

fn record_error(error: Pg26Error) -> Error {
    record_pg26_error(error);
    Error
}

fn record_pg26_error(error: Pg26Error) {
    let code = match error {
        Pg26Error::NotClaimed => 1,
        Pg26Error::Busy => 2,
        Pg26Error::Poisoned => 3,
        Pg26Error::Timeout => 4,
        Pg26Error::MailboxProtocol => 5,
        Pg26Error::InvalidCommand => 6,
        Pg26Error::Authorization => 7,
        Pg26Error::Authentication => 8,
        Pg26Error::Bus => 9,
        Pg26Error::Internal => 10,
        Pg26Error::Crypto => 11,
        Pg26Error::InvalidParameter => 12,
        Pg26Error::NotInitialized => 13,
        Pg26Error::Aborted => 14,
        Pg26Error::InvalidLength => 15,
        Pg26Error::InvalidPeer => 16,
        Pg26Error::EntropyHealth => 17,
        Pg26Error::UnknownResponse(_) => 18,
    };
    LAST_ERROR.store(code, Ordering::Release);
}

trait Engine {
    fn probe(&mut self) -> Result<(), Pg26Error>;
    fn random(&mut self, output: &mut [u8]) -> Result<(), Pg26Error>;
    fn sha256(&mut self, message: &[u8], output: &mut [u8; 32]) -> Result<(), Pg26Error>;
    fn sha256_update(&mut self, state: &mut [u8; 32], blocks: &[u8]) -> Result<(), Pg26Error>;
    fn sha256_finish(
        &mut self,
        state: &[u8; 32],
        tail: &[u8],
        total: u32,
        output: &mut [u8; 32],
    ) -> Result<(), Pg26Error>;
    fn hmac_sha256_parts(
        &mut self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 32],
    ) -> Result<(), Pg26Error>;
    fn gcm_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Pg26Error>;
    fn gcm_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Pg26Error>;
    fn generate_p256_wrapped(&mut self, output: &mut [u8; 60]) -> Result<(), Pg26Error>;
    fn p256_public(&mut self, wrapped: &[u8; 60], output: &mut [u8; 64]) -> Result<(), Pg26Error>;
    fn p256_ecdh(
        &mut self,
        wrapped: &[u8; 60],
        peer: &[u8; 64],
        output: &mut [u8; 64],
    ) -> Result<(), Pg26Error>;
}

struct Hardware;

#[cfg(target_arch = "arm")]
impl Engine for Hardware {
    fn probe(&mut self) -> Result<(), Pg26Error> {
        raw::probe_mailbox()
    }
    fn random(&mut self, output: &mut [u8]) -> Result<(), Pg26Error> {
        raw::random(output)
    }
    fn sha256(&mut self, message: &[u8], output: &mut [u8; 32]) -> Result<(), Pg26Error> {
        raw::sha256(message, output)
    }
    fn sha256_update(&mut self, state: &mut [u8; 32], blocks: &[u8]) -> Result<(), Pg26Error> {
        raw::sha256_update(state, blocks)
    }
    fn sha256_finish(
        &mut self,
        state: &[u8; 32],
        tail: &[u8],
        total: u32,
        output: &mut [u8; 32],
    ) -> Result<(), Pg26Error> {
        raw::sha256_finish(state, tail, total, output)
    }
    fn hmac_sha256_parts(
        &mut self,
        key: &[u8],
        parts: &[&[u8]],
        output: &mut [u8; 32],
    ) -> Result<(), Pg26Error> {
        raw::hmac_sha256_parts(key, parts, output)
    }
    fn gcm_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), Pg26Error> {
        raw::gcm_encrypt(key, nonce, aad, data, tag)
    }
    fn gcm_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Pg26Error> {
        raw::gcm_decrypt(key, nonce, aad, data, tag)
    }
    fn generate_p256_wrapped(&mut self, output: &mut [u8; 60]) -> Result<(), Pg26Error> {
        raw::generate_p256_wrapped(output)
    }
    fn p256_public(&mut self, wrapped: &[u8; 60], output: &mut [u8; 64]) -> Result<(), Pg26Error> {
        raw::p256_public(wrapped, output)
    }
    fn p256_ecdh(
        &mut self,
        wrapped: &[u8; 60],
        peer: &[u8; 64],
        output: &mut [u8; 64],
    ) -> Result<(), Pg26Error> {
        raw::p256_ecdh(wrapped, peer, output)
    }
}

#[cfg(not(target_arch = "arm"))]
impl Engine for Hardware {
    fn probe(&mut self) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn random(&mut self, _output: &mut [u8]) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn sha256(&mut self, _message: &[u8], _output: &mut [u8; 32]) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn sha256_update(&mut self, _state: &mut [u8; 32], _blocks: &[u8]) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn sha256_finish(
        &mut self,
        _state: &[u8; 32],
        _tail: &[u8],
        _total: u32,
        _output: &mut [u8; 32],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn hmac_sha256_parts(
        &mut self,
        _key: &[u8],
        _parts: &[&[u8]],
        _output: &mut [u8; 32],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn gcm_encrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _data: &mut [u8],
        _tag: &mut [u8; 16],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn gcm_decrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _data: &mut [u8],
        _tag: &[u8; 16],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn generate_p256_wrapped(&mut self, _output: &mut [u8; 60]) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn p256_public(
        &mut self,
        _wrapped: &[u8; 60],
        _output: &mut [u8; 64],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
    fn p256_ecdh(
        &mut self,
        _wrapped: &[u8; 60],
        _peer: &[u8; 64],
        _output: &mut [u8; 64],
    ) -> Result<(), Pg26Error> {
        Err(Pg26Error::NotClaimed)
    }
}

#[cfg(target_arch = "arm")]
fn with_hardware<T>(f: impl FnOnce(&mut Hardware) -> Result<T, Pg26Error>) -> Result<T, Pg26Error> {
    if POISONED.load(Ordering::Acquire) {
        return Err(Pg26Error::Poisoned);
    }
    if !CLAIMED.load(Ordering::Acquire) {
        return Err(Pg26Error::NotClaimed);
    }
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Pg26Error::Busy)?;
    let mut hardware = Hardware;
    let result = f(&mut hardware);
    if matches!(&result, Err(Pg26Error::Timeout)) {
        POISONED.store(true, Ordering::Release);
    }
    BUSY.store(false, Ordering::Release);
    result
}

#[cfg(not(target_arch = "arm"))]
fn with_hardware<T>(
    _f: impl FnOnce(&mut Hardware) -> Result<T, Pg26Error>,
) -> Result<T, Pg26Error> {
    Err(Pg26Error::NotClaimed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_refuses_unavailable_hardware() {
        unsafe { Pg26Crypto::recover_after_board_reset() };
        assert_eq!(
            unsafe { Pg26Crypto::claim_after_board_init() }.err(),
            Some(Pg26Error::NotClaimed)
        );
        assert!(!CLAIMED.load(Ordering::Acquire));
    }

    #[test]
    fn wrapped_secret_has_only_wrapped_storage() {
        assert_eq!(core::mem::size_of::<WrappedP256Secret>(), 60);
        assert!(core::mem::needs_drop::<WrappedP256Secret>());
    }

    #[test]
    fn backend_types_satisfy_krabitls_contracts() {
        fn aead<T: krabitls::client::AeadBackend>() {}
        fn hkdf<T: krabitls::client::HkdfSha256>() {}
        fn group<T: krabitls::client::KxGroup>() {}
        aead::<Pg26Aead>();
        hkdf::<Pg26Hkdf>();
        group::<Pg26P256Group>();
    }

    #[test]
    fn transcript_hash_retains_sticky_hardware_failure() {
        use krabitls::client::Sha256 as _;

        unsafe { Pg26Crypto::recover_after_board_reset() };
        let mut hash = Pg26Sha256::default();
        hash.update(&[0xa5; 64]);
        assert_eq!(hash.snapshot(), Err(HkdfBackendError::Failed));
        assert_eq!(last_error(), Some(Pg26Error::NotClaimed));
    }
}
