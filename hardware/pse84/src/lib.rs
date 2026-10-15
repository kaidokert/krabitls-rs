#![no_std]

//! PSoC Edge E84 AES-128-GCM and true-random backends for KrabiTLS.
//!
//! Board code owns clocking, TrustZone attribution, and interrupt policy. It
//! must establish those prerequisites before claiming [`Pse84Crypto`]. The
//! adapter then exclusively serializes CRYPTO, bounds every hardware wait,
//! resets the engine after failures, and clears its register file after use.

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_arch = "arm")]
mod raw;

/// Exclusive lifetime token for the E84 CRYPTO peripheral.
pub struct Pse84Crypto {
    _private: (),
}

/// Hardware AES-128-GCM provider for PSoC Edge E84.
pub struct Aes128GcmHw {
    key: Zeroizing<[u8; 16]>,
}

/// KrabiTLS backend selecting E84 CRYPTO for TLS AES-128-GCM records.
pub struct Pse84Aead;

impl krabitls::client::AeadBackend for Pse84Aead {
    type Aes = krabitls::client::Aes128GcmSha256<Aes128GcmHw>;
}

/// Fallible true-random generator borrowing the exclusive CRYPTO token.
pub struct Pse84Rng<'a> {
    _owner: &'a Pse84Crypto,
}

/// Detailed adapter failure retained across the `aead::Error` boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pse84CryptoError {
    NotClaimed,
    Busy,
    Timeout,
    Hardware,
    EntropyHealth,
    InvalidLength,
    Authentication,
}

impl core::fmt::Display for Pse84CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PSoC E84 CRYPTO failure: {self:?}")
    }
}

impl core::error::Error for Pse84CryptoError {}

static CLAIMED: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
static LAST_ERROR: AtomicU8 = AtomicU8::new(0);

type SecretBlock = Zeroizing<[u8; 16]>;

impl Pse84Crypto {
    /// Claims CRYPTO after board code has enabled its clock and established
    /// the intended security attribution.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no firmware, interrupt handler, ROM service,
    /// or other core accesses CRYPTO for the returned token's lifetime.
    pub unsafe fn claim_after_board_init() -> Result<Self, Pse84CryptoError> {
        BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Pse84CryptoError::Busy)?;
        let claimed = CLAIMED.compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed);
        BUSY.store(false, Ordering::Release);
        claimed.map_err(|_| Pse84CryptoError::Busy)?;
        Ok(Self { _private: () })
    }

    /// Returns an RNG tied to this peripheral ownership period.
    pub fn rng(&self) -> Pse84Rng<'_> {
        Pse84Rng { _owner: self }
    }
}

impl Drop for Pse84Crypto {
    fn drop(&mut self) {
        // Stop new callers first. If an operation owns BUSY, its mandatory
        // finish path resets the engine; otherwise token destruction does it.
        CLAIMED.store(false, Ordering::Release);
        if BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            #[cfg(target_arch = "arm")]
            raw::force_reset();
            BUSY.store(false, Ordering::Release);
        }
    }
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
        let result =
            with_engine(|engine| gcm_encrypt(engine, &self.key, &nonce, associated_data, output));
        match result {
            Ok(tag) => {
                LAST_ERROR.store(0, Ordering::Release);
                Ok(Array::from(tag))
            }
            Err(error) => {
                output.zeroize();
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
        let expected: [u8; 16] = (*tag).into();
        let result = with_engine(|engine| {
            gcm_decrypt(
                engine,
                &self.key,
                &nonce,
                associated_data,
                output,
                &expected,
            )
        });
        match result {
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

impl rand_core::TryRng for Pse84Rng<'_> {
    type Error = Pse84CryptoError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        with_engine(|engine| engine.random_word())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let low = self.try_next_u32()? as u64;
        let high = self.try_next_u32()? as u64;
        Ok(low | (high << 32))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        with_engine(|engine| {
            for chunk in destination.chunks_mut(4) {
                let word = engine.random_word()?.to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
            Ok(())
        })
    }
}

impl rand_core::TryCryptoRng for Pse84Rng<'_> {}

/// Returns the detailed cause of the latest failed adapter operation.
pub fn last_error() -> Option<Pse84CryptoError> {
    match LAST_ERROR.load(Ordering::Acquire) {
        1 => Some(Pse84CryptoError::NotClaimed),
        2 => Some(Pse84CryptoError::Busy),
        3 => Some(Pse84CryptoError::Timeout),
        4 => Some(Pse84CryptoError::Hardware),
        5 => Some(Pse84CryptoError::EntropyHealth),
        6 => Some(Pse84CryptoError::InvalidLength),
        7 => Some(Pse84CryptoError::Authentication),
        _ => None,
    }
}

#[cfg(feature = "qualification")]
pub mod qualification {
    use super::*;

    /// Routes the next AES block through timeout recovery without waiting.
    pub fn force_next_timeout() {
        raw::force_next_timeout();
    }

    /// Confirms that the same wipe used by `Drop` clears adapter key storage.
    pub fn exercise_key_wipe(cipher: &mut Aes128GcmHw) -> bool {
        cipher.zeroize();
        cipher.key.iter().all(|byte| *byte == 0)
    }

    /// Checks the externally visible post-operation power state.
    pub fn peripheral_disabled() -> bool {
        raw::peripheral_disabled()
    }
}

fn record_error(error: Pse84CryptoError) -> Error {
    let code = match error {
        Pse84CryptoError::NotClaimed => 1,
        Pse84CryptoError::Busy => 2,
        Pse84CryptoError::Timeout => 3,
        Pse84CryptoError::Hardware => 4,
        Pse84CryptoError::EntropyHealth => 5,
        Pse84CryptoError::InvalidLength => 6,
        Pse84CryptoError::Authentication => 7,
    };
    LAST_ERROR.store(code, Ordering::Release);
    Error
}

trait Engine {
    fn encrypt_block(
        &mut self,
        key: &[u8; 16],
        block: &[u8; 16],
    ) -> Result<[u8; 16], Pse84CryptoError>;

    fn random_word(&mut self) -> Result<u32, Pse84CryptoError> {
        Err(Pse84CryptoError::Hardware)
    }
}

#[cfg(target_arch = "arm")]
fn with_engine<T>(
    f: impl FnOnce(&mut raw::Hardware) -> Result<T, Pse84CryptoError>,
) -> Result<T, Pse84CryptoError> {
    if !CLAIMED.load(Ordering::Acquire) {
        return Err(Pse84CryptoError::NotClaimed);
    }
    BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .map_err(|_| Pse84CryptoError::Busy)?;
    if !CLAIMED.load(Ordering::Acquire) {
        BUSY.store(false, Ordering::Release);
        return Err(Pse84CryptoError::NotClaimed);
    }
    let result = match raw::Hardware::start() {
        Ok(mut hardware) => {
            let result = f(&mut hardware);
            let cleanup = hardware.finish();
            match (result, cleanup) {
                (Err(error), _) | (Ok(_), Err(error)) => Err(error),
                (Ok(value), Ok(())) => Ok(value),
            }
        }
        Err(error) => Err(error),
    };
    BUSY.store(false, Ordering::Release);
    result
}

#[cfg(not(target_arch = "arm"))]
fn with_engine<T>(
    _f: impl FnOnce(&mut HostUnavailable) -> Result<T, Pse84CryptoError>,
) -> Result<T, Pse84CryptoError> {
    Err(Pse84CryptoError::NotClaimed)
}

#[cfg(not(target_arch = "arm"))]
struct HostUnavailable;

#[cfg(not(target_arch = "arm"))]
impl Engine for HostUnavailable {
    fn encrypt_block(&mut self, _: &[u8; 16], _: &[u8; 16]) -> Result<[u8; 16], Pse84CryptoError> {
        Err(Pse84CryptoError::NotClaimed)
    }
}

fn gcm_encrypt<E: Engine>(
    engine: &mut E,
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; 16], Pse84CryptoError> {
    let (h, tag_mask) = gcm_keys(engine, key, nonce)?;
    apply_ctr(engine, key, nonce, buffer)?;
    Ok(xor(*tag_mask, ghash(*h, aad, buffer)?))
}

fn gcm_decrypt<E: Engine>(
    engine: &mut E,
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    expected: &[u8; 16],
) -> Result<(), Pse84CryptoError> {
    let (h, tag_mask) = gcm_keys(engine, key, nonce)?;
    let actual = Zeroizing::new(xor(*tag_mask, ghash(*h, aad, buffer)?));
    if !constant_time_eq(&actual, expected) {
        return Err(Pse84CryptoError::Authentication);
    }
    apply_ctr(engine, key, nonce, buffer)
}

fn gcm_keys<E: Engine>(
    engine: &mut E,
    key: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<(SecretBlock, SecretBlock), Pse84CryptoError> {
    let h = Zeroizing::new(engine.encrypt_block(key, &[0; 16])?);
    let mut j0 = [0; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let tag_mask = Zeroizing::new(engine.encrypt_block(key, &j0)?);
    Ok((h, tag_mask))
}

fn apply_ctr<E: Engine>(
    engine: &mut E,
    key: &[u8; 16],
    nonce: &[u8; 12],
    buffer: &mut [u8],
) -> Result<(), Pse84CryptoError> {
    let blocks = buffer
        .len()
        .checked_add(15)
        .ok_or(Pse84CryptoError::InvalidLength)?
        / 16;
    if blocks > (u32::MAX - 1) as usize {
        return Err(Pse84CryptoError::InvalidLength);
    }
    for (index, chunk) in buffer.chunks_mut(16).enumerate() {
        let mut counter = [0; 16];
        counter[..12].copy_from_slice(nonce);
        counter[12..].copy_from_slice(&(index as u32 + 2).to_be_bytes());
        let stream = Zeroizing::new(engine.encrypt_block(key, &counter)?);
        for (byte, mask) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= *mask;
        }
    }
    Ok(())
}

fn ghash(h: [u8; 16], aad: &[u8], text: &[u8]) -> Result<[u8; 16], Pse84CryptoError> {
    let aad_bits = u64::try_from(aad.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(Pse84CryptoError::InvalidLength)?;
    let text_bits = u64::try_from(text.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or(Pse84CryptoError::InvalidLength)?;
    let mut y = [0; 16];
    ghash_bytes(&mut y, h, aad);
    ghash_bytes(&mut y, h, text);
    let mut lengths = [0; 16];
    lengths[..8].copy_from_slice(&aad_bits.to_be_bytes());
    lengths[8..].copy_from_slice(&text_bits.to_be_bytes());
    Ok(gf_mul(xor(y, lengths), h))
}

fn ghash_bytes(y: &mut [u8; 16], h: [u8; 16], bytes: &[u8]) {
    for chunk in bytes.chunks(16) {
        let mut block = [0; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        *y = gf_mul(xor(*y, block), h);
    }
}

fn gf_mul(x: [u8; 16], h: [u8; 16]) -> [u8; 16] {
    let x = u128::from_be_bytes(x);
    let mut v = u128::from_be_bytes(h);
    let mut z = 0u128;
    for bit in 0..128 {
        z ^= v & 0u128.wrapping_sub((x >> (127 - bit)) & 1);
        let low = v & 1;
        v >>= 1;
        v ^= 0xe100_0000_0000_0000_0000_0000_0000_0000u128 & 0u128.wrapping_sub(low);
    }
    z.to_be_bytes()
}

fn xor(mut left: [u8; 16], right: [u8; 16]) -> [u8; 16] {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= right;
    }
    left
}

fn constant_time_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use aes::cipher::BlockCipherEncrypt;

    struct SoftwareEngine;
    static STATE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl Engine for SoftwareEngine {
        fn encrypt_block(
            &mut self,
            key: &[u8; 16],
            block: &[u8; 16],
        ) -> Result<[u8; 16], Pse84CryptoError> {
            let cipher = aes::Aes128::new(key.into());
            let mut output = (*block).into();
            cipher.encrypt_block(&mut output);
            Ok(output.into())
        }
    }

    #[test]
    fn nist_empty_and_single_block_vectors() {
        let mut engine = SoftwareEngine;
        let key = [0; 16];
        let nonce = [0; 12];
        let mut empty = [];
        assert_eq!(
            gcm_encrypt(&mut engine, &key, &nonce, b"", &mut empty).unwrap(),
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
        let mut block = [0; 16];
        let tag = gcm_encrypt(&mut engine, &key, &nonce, b"", &mut block).unwrap();
        assert_eq!(
            block,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ]
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ]
        );
        gcm_decrypt(&mut engine, &key, &nonce, b"", &mut block, &tag).unwrap();
        assert_eq!(block, [0; 16]);
    }

    #[test]
    fn varied_shapes_and_authentication_rejection() {
        let key = [0x42; 16];
        let nonce = [0x24; 12];
        for length in [0, 1, 15, 16, 17, 31, 32, 63, 257] {
            let mut plaintext = std::vec![0u8; length];
            for (index, byte) in plaintext.iter_mut().enumerate() {
                *byte = index as u8;
            }
            let mut encrypted = plaintext.clone();
            let tag = gcm_encrypt(
                &mut SoftwareEngine,
                &key,
                &nonce,
                b"non-block aad",
                &mut encrypted,
            )
            .unwrap();
            gcm_decrypt(
                &mut SoftwareEngine,
                &key,
                &nonce,
                b"non-block aad",
                &mut encrypted,
                &tag,
            )
            .unwrap();
            assert_eq!(encrypted, plaintext);
            let mut altered = tag;
            altered[7] ^= 1;
            assert_eq!(
                gcm_decrypt(
                    &mut SoftwareEngine,
                    &key,
                    &nonce,
                    b"non-block aad",
                    &mut encrypted,
                    &altered
                ),
                Err(Pse84CryptoError::Authentication)
            );
        }
    }

    #[test]
    fn public_backend_rejects_use_without_claim() {
        let _guard = STATE_TEST_LOCK.lock().unwrap();
        CLAIMED.store(false, Ordering::Release);
        BUSY.store(false, Ordering::Release);
        let cipher = Aes128GcmHw::new(&[0; 16].into());
        let mut block = [0xa5; 16];
        let result = cipher.encrypt_inout_detached(
            &Nonce::<Aes128GcmHw>::from([0; 12]),
            b"",
            InOutBuf::from(&mut block[..]),
        );
        assert!(result.is_err());
        assert_eq!(block, [0; 16]);
        assert_eq!(last_error(), Some(Pse84CryptoError::NotClaimed));
    }

    #[test]
    fn token_drop_defers_to_an_active_operation() {
        let _guard = STATE_TEST_LOCK.lock().unwrap();
        CLAIMED.store(false, Ordering::Release);
        BUSY.store(false, Ordering::Release);

        let token = unsafe { Pse84Crypto::claim_after_board_init() }.unwrap();
        BUSY.store(true, Ordering::Release);
        drop(token);
        assert!(!CLAIMED.load(Ordering::Acquire));
        assert!(BUSY.load(Ordering::Acquire));
        assert!(matches!(
            unsafe { Pse84Crypto::claim_after_board_init() },
            Err(Pse84CryptoError::Busy)
        ));

        // Model the active operation's mandatory finish/release path.
        BUSY.store(false, Ordering::Release);
        let replacement = unsafe { Pse84Crypto::claim_after_board_init() }.unwrap();
        drop(replacement);
        assert!(!CLAIMED.load(Ordering::Acquire));
        assert!(!BUSY.load(Ordering::Acquire));
    }
}
