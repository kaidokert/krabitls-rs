#![no_std]

//! AES-128-GCM using the nRF52833 ECB peripheral and software GHASH.

use core::sync::atomic::{Ordering, compiler_fence};

use cipher::consts::{U1, U16};
use cipher::{
    Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InOut,
    Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use nrf52833_hal::pac;
use zeroize::Zeroize;

/// AES-128-GCM whose AES block primitive is executed by the nRF52833 ECB engine.
pub type NrfAes128Gcm = aes_gcm::AesGcm<NrfAes128, cipher::consts::U12>;

/// KrabiTLS backend selecting the nRF52833 AES peripheral for TLS records.
pub struct NrfAead;

impl krabitls::client::AeadBackend for NrfAead {
    type Aes = krabitls::client::Aes128GcmSha256<NrfAes128Gcm>;
}

/// AES-128 encryption-only block cipher backed by the nRF52833 ECB peripheral.
///
/// The ECB, CCM, and AAR peripherals share hardware resources. The application
/// must ensure no CCM or AAR operation overlaps an encryption call.
pub struct NrfAes128 {
    key: [u8; 16],
}

impl Drop for NrfAes128 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl KeySizeUser for NrfAes128 {
    type KeySize = U16;
}

impl KeyInit for NrfAes128 {
    fn new(key: &Key<Self>) -> Self {
        Self { key: (*key).into() }
    }
}

impl BlockSizeUser for NrfAes128 {
    type BlockSize = U16;
}

impl BlockCipherEncrypt for NrfAes128 {
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(&NrfAesBackend(self));
    }
}

struct NrfAesBackend<'a>(&'a NrfAes128);

impl BlockSizeUser for NrfAesBackend<'_> {
    type BlockSize = U16;
}

impl ParBlocksSizeUser for NrfAesBackend<'_> {
    type ParBlocksSize = U1;
}

impl BlockCipherEncBackend for NrfAesBackend<'_> {
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let clear_text: [u8; 16] = block.clone_in().into();
        *block.get_out() = encrypt_block(self.0.key, clear_text).into();
    }
}

#[repr(C)]
struct EcbData {
    key: [u8; 16],
    clear_text: [u8; 16],
    cipher_text: [u8; 16],
}

fn encrypt_block(key: [u8; 16], clear_text: [u8; 16]) -> [u8; 16] {
    let mut data = EcbData {
        key,
        clear_text,
        cipher_text: [0; 16],
    };

    // SAFETY: the application reserves ECB for this synchronous provider.
    // The DMA buffer remains live until ENDECB or ERRORECB is observed.
    let ecb = unsafe { &*pac::ECB::ptr() };
    ecb.intenclr
        .write(|w| w.endecb().clear().errorecb().clear());
    ecb.tasks_stopecb.write(|w| unsafe { w.bits(1) });
    ecb.ecbdataptr
        .write(|w| unsafe { w.bits(&mut data as *mut EcbData as u32) });
    ecb.events_endecb.reset();
    ecb.events_errorecb.reset();

    compiler_fence(Ordering::Release);
    ecb.tasks_startecb.write(|w| unsafe { w.bits(1) });
    while ecb.events_endecb.read().bits() == 0 && ecb.events_errorecb.read().bits() == 0 {}
    compiler_fence(Ordering::Acquire);

    if ecb.events_errorecb.read().bits() != 0 {
        // The cipher traits are infallible. A resource conflict is therefore a
        // fatal provider-contract violation rather than an authentication error.
        loop {
            cortex_m::asm::nop();
        }
    }

    data.key.zeroize();
    data.clear_text.zeroize();
    data.cipher_text
}
