//! AES-128-GCM with SAM D5x/E5x hardware AES and software GHASH.

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use atsamd_hal::pac::{Aes, aes::ctrla::Keysizeselect};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use zeroize::Zeroizing;

static COUNTERMEASURE_SEED: AtomicU32 = AtomicU32::new(0);
static COUNTERMEASURES_SEEDED: AtomicBool = AtomicBool::new(false);

/// KrabiTLS backend selecting the SAM D5x/E5x AES peripheral.
pub struct Same5xAead;

impl krabitls::client::AeadBackend for Same5xAead {
    type Aes = krabitls::client::Aes128GcmSha256<Aes128GcmHw>;
}

/// Seed the AES peripheral's DPA-countermeasure generator.
///
/// Call this once with a word from the hardware TRNG before constructing TLS
/// state. Operations fail closed until a seed has been installed.
pub fn seed_countermeasures(seed: u32) {
    COUNTERMEASURE_SEED.store(seed, Ordering::Relaxed);
    COUNTERMEASURES_SEEDED.store(true, Ordering::Release);
}

/// Hybrid AES-128-GCM provider for KrabiTLS's standard `aead` seam.
///
/// AES counter-mode operations use the peripheral. GHASH uses a fixed-iteration
/// software implementation because the peripheral's partial-block path is not
/// correct for every payload length. The application must enable the AES APB
/// clock and grant exclusive peripheral access for each blocking operation.
pub struct Aes128GcmHw {
    key: Zeroizing<[u8; 16]>,
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
        Ok(Array::from(run(
            &self.key,
            &nonce,
            associated_data,
            output,
            true,
        )?))
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
        let computed = run(&self.key, &nonce, associated_data, output, false)?;
        if tag_eq(&computed, &expected) {
            Ok(())
        } else {
            output.fill(0);
            Err(Error)
        }
    }
}

/// One-shot AES-128-GCM using a 96-bit IV.
///
/// The application owns the peripheral clock and exclusive-access contract.
fn run(
    key: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    encrypt: bool,
) -> Result<[u8; 16], Error> {
    let countermeasure_seed = next_countermeasure_seed().ok_or(Error)?;
    // SAFETY: the provider's application-level contract grants exclusive AES
    // access for this blocking operation. The cipher value itself stores only
    // key material, because KrabiTLS constructs several record keys at once.
    let aes = unsafe { Aes::steal() };
    let hashkey = generate_hashkey(&aes, key, countermeasure_seed);

    aes.ctrla().modify(|_, w| w.enable().clear_bit());
    aes.ctrla().write(|w| {
        w.aesmode()
            .gcm()
            .cipher()
            .bit(encrypt)
            .keysize()
            .variant(Keysizeselect::_128bit)
            .enable()
            .set_bit()
    });
    write_key(&aes, key);
    for (index, word) in hashkey.iter().enumerate() {
        aes.hashkey(index).write(|w| unsafe { w.bits(*word) });
    }

    let ghash = if encrypt {
        process_payload(&aes, iv, data);
        compute_ghash(&hashkey, aad, data)
    } else {
        let ghash = compute_ghash(&hashkey, aad, data);
        process_payload(&aes, iv, data);
        ghash
    };
    Ok(generate_tag(&aes, iv, ghash))
}

fn generate_hashkey(aes: &Aes, key: &[u8; 16], countermeasure_seed: u32) -> [u32; 4] {
    reset(aes);
    aes.ctrla().write(|w| {
        w.aesmode()
            .ecb()
            .cipher()
            .enc()
            .keysize()
            .variant(Keysizeselect::_128bit)
            .enable()
            .set_bit()
    });
    // CTYPE's reset value keeps all four countermeasures enabled. They become
    // effective only after RANDSEED is written.
    aes.randseed()
        .write(|w| unsafe { w.bits(countermeasure_seed) });
    aes.ciplen().write(|w| unsafe { w.bits(0) });
    write_key(aes, key);
    write_data(aes, &[0; 16]);
    clear_enccmp(aes);
    aes.ctrlb().write(|w| w.start().set_bit());
    wait_enccmp(aes);

    let mut hashkey = [0u32; 4];
    for (index, word) in hashkey.iter_mut().enumerate() {
        *word = aes.hashkey(index).read().bits();
    }
    hashkey
}

fn process_payload(aes: &Aes, iv: &[u8; 12], data: &mut [u8]) {
    aes.ciplen().write(|w| unsafe { w.bits(data.len() as u32) });
    let mut counter = [0u8; 16];
    counter[..12].copy_from_slice(iv);
    counter[15] = 2;
    write_iv(aes, &counter);
    aes.ctrlb().write(|w| w.newmsg().set_bit());
    aes.ctrlb().modify(|_, w| w.gfmul().clear_bit());

    let block_count = data.len().div_ceil(16);
    for (block_index, chunk) in data.chunks_mut(16).enumerate() {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        if block_index + 1 == block_count {
            aes.ctrlb().modify(|_, w| w.eom().set_bit());
        }
        write_data(aes, &block);
        clear_enccmp(aes);
        aes.ctrlb().modify(|_, w| w.start().set_bit());
        wait_enccmp(aes);
        let output = read_data(aes);
        chunk.copy_from_slice(&output[..chunk.len()]);
    }
}

fn compute_ghash(hashkey: &[u32; 4], aad: &[u8], data: &[u8]) -> [u32; 4] {
    let mut hashkey_bytes = [0u8; 16];
    for (index, word) in hashkey.iter().enumerate() {
        hashkey_bytes[index * 4..][..4].copy_from_slice(&word.to_le_bytes());
    }
    let hashkey = u128::from_be_bytes(hashkey_bytes);
    let mut accumulator = 0u128;
    for input in [aad, data] {
        for chunk in input.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            accumulator = multiply_ghash(accumulator ^ u128::from_be_bytes(block), hashkey);
        }
    }
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lengths[8..].copy_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    accumulator = multiply_ghash(accumulator ^ u128::from_be_bytes(lengths), hashkey);
    let bytes = accumulator.to_be_bytes();
    let mut result = [0u32; 4];
    for (index, word) in result.iter_mut().enumerate() {
        *word = u32::from_le_bytes(bytes[index * 4..][..4].try_into().unwrap());
    }
    result
}

fn generate_tag(aes: &Aes, iv: &[u8; 12], ghash: [u32; 4]) -> [u8; 16] {
    aes.ctrla().modify(|_, w| w.enable().clear_bit());
    aes.ctrla().modify(|_, w| w.aesmode().counter());
    aes.ctrla().modify(|_, w| w.enable().set_bit());

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[15] = 1;
    write_iv(aes, &j0);
    for word in ghash {
        aes.indata().write(|w| unsafe { w.bits(word) });
    }
    clear_enccmp(aes);
    aes.ctrlb()
        .write(|w| w.newmsg().set_bit().start().set_bit());
    wait_enccmp(aes);
    read_data(aes)
}

fn reset(aes: &Aes) {
    aes.ctrla().write(|w| w.swrst().set_bit());
    while aes.ctrla().read().swrst().bit_is_set() {}
}

fn write_key(aes: &Aes, key: &[u8; 16]) {
    write_words(
        |index, word| aes.keyword(index).write(|w| unsafe { w.bits(word) }),
        key,
    );
}

fn write_iv(aes: &Aes, iv: &[u8; 16]) {
    write_words(
        |index, word| aes.intvectv(index).write(|w| unsafe { w.bits(word) }),
        iv,
    );
}

fn write_data(aes: &Aes, bytes: &[u8; 16]) {
    for chunk in bytes.chunks_exact(4) {
        aes.indata()
            .write(|w| unsafe { w.bits(u32::from_le_bytes(chunk.try_into().unwrap())) });
    }
}

fn read_data(aes: &Aes) -> [u8; 16] {
    let mut output = [0u8; 16];
    for chunk in output.chunks_exact_mut(4) {
        chunk.copy_from_slice(&aes.indata().read().bits().to_le_bytes());
    }
    output
}

fn multiply_ghash(x: u128, hashkey: u128) -> u128 {
    let mut v = hashkey;
    let mut product = 0u128;
    for bit in 0..128 {
        let selected = 0u128.wrapping_sub((x >> (127 - bit)) & 1);
        product ^= v & selected;
        let reduce = 0u128.wrapping_sub(v & 1) & (0xe1u128 << 120);
        v = (v >> 1) ^ reduce;
    }
    product
}

fn write_words(mut write: impl FnMut(usize, u32), bytes: &[u8; 16]) {
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        write(index, u32::from_le_bytes(chunk.try_into().unwrap()));
    }
}

fn clear_enccmp(aes: &Aes) {
    aes.intflag().write(|w| w.enccmp().set_bit());
}

fn wait_enccmp(aes: &Aes) {
    while aes.intflag().read().enccmp().bit_is_clear() {}
}

fn tag_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut difference = 0u8;
    for index in 0..16 {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

fn next_countermeasure_seed() -> Option<u32> {
    if !COUNTERMEASURES_SEEDED.load(Ordering::Acquire) {
        return None;
    }
    let seed = COUNTERMEASURE_SEED.load(Ordering::Relaxed);
    let mut next = seed;
    next ^= next << 13;
    next ^= next >> 17;
    next ^= next << 5;
    if next == 0 {
        next = 0x9e37_79b9;
    }
    COUNTERMEASURE_SEED.store(next, Ordering::Relaxed);
    Some(seed)
}
