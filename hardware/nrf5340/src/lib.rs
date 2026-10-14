#![no_std]

//! AES-128-GCM using the nRF5340 application core's CryptoCell-312.
//!
//! The adapter owns no board initialization. It serializes the shared
//! CryptoCell symmetric engines for each blocking record operation, powers the
//! block only while it is in use, and bounds every hardware wait.

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use zeroize::{Zeroize, Zeroizing};

mod raw;

/// Hardware AES-128-GCM provider for the nRF5340 CryptoCell-312.
pub struct Aes128GcmHw {
    key: Zeroizing<[u8; 16]>,
}

/// KrabiTLS backend selecting CryptoCell-312 for TLS AES-128-GCM records.
pub struct Nrf5340Aead;

impl krabitls::client::AeadBackend for Nrf5340Aead {
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
        let nonce: [u8; 12] = (*nonce).into();
        let output = buffer.into_out_with_copied_in();
        let tag = match raw::gcm(
            &self.key,
            &nonce,
            associated_data,
            output,
            raw::Direction::Encrypt,
        ) {
            Ok(tag) => tag,
            Err(error) => {
                output.zeroize();
                return Err(record_error(error));
            }
        };
        LAST_ERROR.store(0, Ordering::Release);
        Ok(Array::from(tag))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        let nonce: [u8; 12] = (*nonce).into();
        let expected: [u8; 16] = (*tag).into();
        let output = buffer.into_out_with_copied_in();
        let computed = match raw::gcm(
            &self.key,
            &nonce,
            associated_data,
            output,
            raw::Direction::Decrypt,
        ) {
            Ok(tag) => tag,
            Err(error) => {
                output.zeroize();
                return Err(record_error(error));
            }
        };
        if constant_time_eq(&computed, &expected) {
            LAST_ERROR.store(0, Ordering::Release);
            Ok(())
        } else {
            output.zeroize();
            LAST_ERROR.store(CryptoCellError::Authentication.code(), Ordering::Release);
            Err(Error)
        }
    }
}

fn constant_time_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
    let mut difference = 0u8;
    for index in 0..16 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

/// Detailed failure retained after the RustCrypto `aead::Error` boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoCellError {
    Busy,
    Timeout,
    Hardware,
    Authentication,
}

impl CryptoCellError {
    const fn code(self) -> u8 {
        match self {
            Self::Busy => 1,
            Self::Timeout => 2,
            Self::Hardware => 3,
            Self::Authentication => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Busy),
            2 => Some(Self::Timeout),
            3 => Some(Self::Hardware),
            4 => Some(Self::Authentication),
            _ => None,
        }
    }
}

static LAST_ERROR: AtomicU8 = AtomicU8::new(0);

fn record_error(error: CryptoCellError) -> Error {
    LAST_ERROR.store(error.code(), Ordering::Release);
    Error
}

/// Returns the detailed cause of the most recent failed adapter operation.
///
/// `AeadInOut` deliberately exposes only `aead::Error`; this diagnostic keeps
/// timeout and ownership failures observable without changing KrabiTLS's
/// record-layer contract.
pub fn last_error() -> Option<CryptoCellError> {
    CryptoCellError::from_code(LAST_ERROR.load(Ordering::Acquire))
}

static ENGINE_LOCKED: AtomicBool = AtomicBool::new(false);
static CLEANUP_COUNT: AtomicU32 = AtomicU32::new(0);

struct EngineGuard;

impl EngineGuard {
    fn acquire() -> Result<Self, CryptoCellError> {
        ENGINE_LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| CryptoCellError::Busy)
    }
}

impl Drop for EngineGuard {
    fn drop(&mut self) {
        raw::cleanup();
        CLEANUP_COUNT.fetch_add(1, Ordering::Relaxed);
        ENGINE_LOCKED.store(false, Ordering::Release);
    }
}

#[cfg(feature = "qualification")]
pub mod qualification {
    use super::*;

    /// Makes the next hardware wait traverse the production timeout path.
    pub fn force_next_timeout() {
        raw::FORCE_TIMEOUT.store(true, Ordering::Release);
    }

    /// Counts completed peripheral cleanup paths, including failed operations.
    pub fn cleanup_count() -> u32 {
        CLEANUP_COUNT.load(Ordering::Acquire)
    }

    /// Checks the key buffer after invoking the same wipe used by `Drop`.
    pub fn exercise_key_wipe(cipher: &mut Aes128GcmHw) -> bool {
        cipher.zeroize();
        cipher.key.iter().all(|byte| *byte == 0)
    }

    /// Checks cleanup state exposed by readable peripheral registers.
    ///
    /// CryptoCell's AES key and GHASH subkey registers are write-only, so the
    /// qualification image can directly read back only the accumulator and
    /// subsystem power state.
    pub fn peripheral_state_cleared() -> bool {
        raw::observable_state_cleared()
    }
}
