use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Error, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use zeroize::{Zeroize, Zeroizing};

/// Hardware AES-128-GCM. Holds the 128-bit key; the peripheral is shared.
pub struct Aes128GcmHw {
    key: Zeroizing<[u8; 16]>,
}

/// KrabiTLS backend selecting the H533 AES peripheral for
/// `TLS_AES_128_GCM_SHA256` records.
pub struct H533Aead;

impl krabitls::client::AeadBackend for H533Aead {
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

impl AeadCore for Aes128GcmHw {
    type NonceSize = U12; // TLS 1.3 / GCM 96-bit nonce
    type TagSize = U16; // 128-bit tag
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for Aes128GcmHw {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, Error> {
        let iv: [u8; 12] = (*nonce).into();
        let buf = buffer.into_out_with_copied_in();
        let tag = gcm_hw::gcm(&self.key, &iv, associated_data, buf, true).map_err(|_| Error)?;
        Ok(Array::from(tag))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), Error> {
        let iv: [u8; 12] = (*nonce).into();
        // Copy ciphertext into the output buffer, decrypt in place; the tag
        // is computed over aad||ciphertext regardless of direction.
        let buf = buffer.into_out_with_copied_in();
        // NOTE: `gcm` overwrites `buf` (CT->PT); it GHASHes the ciphertext it
        // read, so the returned tag authenticates the original ciphertext.
        let computed =
            gcm_hw::gcm(&self.key, &iv, associated_data, buf, false).map_err(|_| Error)?;
        let expected: [u8; 16] = (*tag).into();
        if ct_eq(&computed, &expected) {
            Ok(())
        } else {
            buf.zeroize();
            Err(Error)
        }
    }
}

/// Constant-time 16-byte tag comparison.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Raw STM32H533 AES-128-GCM register driver (used by the `aes_gcm` adapter).
///
/// Sequence per RM0481: init (compute H + tag mask, no data), header (AAD),
/// payload (CTR encrypt/decrypt + GHASH), final (length block -> tag). 96-bit IV
/// loads as `IV || 0x00000002` (the first payload counter). DATATYPE=0, so words
/// are the big-endian view of the byte stream. AES bus clock must be enabled.
///
/// HW gotcha (verified on H533): the AES peripheral **clears `CR.EN` at the end
/// of the init phase**, so `EN` must be re-asserted on every phase transition
/// (header/payload/final) or the CCF wait hangs with the engine disabled.
mod gcm_hw {
    use stm32h5::stm32h533 as pac;

    const SPIN_LIMIT: u32 = 20_000_000;

    fn wait_ccf(aes: &pac::AES) -> Result<(), ()> {
        let mut spins = 0;
        while aes.isr().read().ccf().bit_is_clear() {
            if spins == SPIN_LIMIT {
                aes.cr().modify(|_, w| w.en().clear_bit());
                return Err(());
            }
            spins += 1;
        }
        aes.icr().write(|w| w.ccf().set_bit()); // write-1-to-clear
        Ok(())
    }

    fn din_block(aes: &pac::AES, b: &[u8; 16]) {
        let mut i = 0;
        while i < 16 {
            aes.dinr().write(|w| unsafe {
                w.din()
                    .bits(u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]))
            });
            i += 4;
        }
    }

    fn dout_block(aes: &pac::AES, o: &mut [u8; 16]) {
        let mut i = 0;
        while i < 16 {
            let word = aes.doutr().read().dout().bits();
            o[i..i + 4].copy_from_slice(&word.to_be_bytes());
            i += 4;
        }
    }

    /// AES-128-GCM one-shot. Processes `buf` in place (plaintext->ciphertext when
    /// `encrypt`, ciphertext->plaintext otherwise) and returns the 16-byte tag
    /// computed over `aad || ciphertext`.
    pub fn gcm(
        key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        encrypt: bool,
    ) -> Result<[u8; 16], ()> {
        // Shared peripheral; caller enabled the AES clock. Exclusive for the
        // duration of this blocking call.
        let aes = unsafe { pac::AES::steal() };

        // --- init phase (EN=0 while configuring) ---
        aes.cr().write(|w| {
            unsafe {
                w.chmod().bits(0b11); // CHMOD[1:0]
                w.datatype().bits(0b00); // no swap
                w.mode().bits(if encrypt { 0b00 } else { 0b10 });
                w.gcmph().bits(0b00); // init
                w.npblb().bits(0);
            }
            w.chmod_1().clear_bit(); // CHMOD[2]=0 -> CHMOD=0b011 (GCM)
            w.keysize().clear_bit(); // 128-bit
            w.en().clear_bit()
        });
        aes.keyr3().write(|w| unsafe {
            w.key()
                .bits(u32::from_be_bytes([key[0], key[1], key[2], key[3]]))
        });
        aes.keyr2().write(|w| unsafe {
            w.key()
                .bits(u32::from_be_bytes([key[4], key[5], key[6], key[7]]))
        });
        aes.keyr1().write(|w| unsafe {
            w.key()
                .bits(u32::from_be_bytes([key[8], key[9], key[10], key[11]]))
        });
        aes.keyr0().write(|w| unsafe {
            w.key()
                .bits(u32::from_be_bytes([key[12], key[13], key[14], key[15]]))
        });
        aes.ivr3().write(|w| unsafe {
            w.ivi()
                .bits(u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]))
        });
        aes.ivr2().write(|w| unsafe {
            w.ivi()
                .bits(u32::from_be_bytes([iv[4], iv[5], iv[6], iv[7]]))
        });
        aes.ivr1().write(|w| unsafe {
            w.ivi()
                .bits(u32::from_be_bytes([iv[8], iv[9], iv[10], iv[11]]))
        });
        aes.ivr0().write(|w| unsafe { w.ivi().bits(0x0000_0002) }); // ICB counter = 2
        aes.cr().modify(|_, w| w.en().set_bit());
        wait_ccf(&aes)?;

        // --- header phase (AAD) ---
        if !aad.is_empty() {
            aes.cr()
                .modify(|_, w| unsafe { w.gcmph().bits(0b01) }.en().set_bit());
            let full = aad.len() / 16;
            for i in 0..full {
                let mut b = [0u8; 16];
                b.copy_from_slice(&aad[i * 16..i * 16 + 16]);
                din_block(&aes, &b);
                wait_ccf(&aes)?;
            }
            let rem = aad.len() % 16;
            if rem != 0 {
                let mut b = [0u8; 16];
                b[..rem].copy_from_slice(&aad[full * 16..]);
                din_block(&aes, &b);
                wait_ccf(&aes)?;
            }
        }

        // --- payload phase (in place) ---
        let data_len = buf.len();
        if data_len != 0 {
            aes.cr()
                .modify(|_, w| unsafe { w.gcmph().bits(0b10) }.en().set_bit());
            let full = data_len / 16;
            for i in 0..full {
                let mut b = [0u8; 16];
                b.copy_from_slice(&buf[i * 16..i * 16 + 16]);
                din_block(&aes, &b);
                wait_ccf(&aes)?;
                let mut o = [0u8; 16];
                dout_block(&aes, &mut o);
                buf[i * 16..i * 16 + 16].copy_from_slice(&o);
            }
            let rem = data_len % 16;
            if rem != 0 {
                aes.cr()
                    .modify(|_, w| unsafe { w.npblb().bits((16 - rem) as u8) });
                let mut b = [0u8; 16];
                b[..rem].copy_from_slice(&buf[full * 16..]);
                din_block(&aes, &b);
                wait_ccf(&aes)?;
                let mut o = [0u8; 16];
                dout_block(&aes, &mut o);
                buf[full * 16..].copy_from_slice(&o[..rem]);
                aes.cr().modify(|_, w| unsafe { w.npblb().bits(0) });
            }
        }

        // --- final phase (length block -> tag) ---
        aes.cr()
            .modify(|_, w| unsafe { w.gcmph().bits(0b11) }.en().set_bit());
        let aad_bits = (aad.len() as u64) * 8;
        let data_bits = (data_len as u64) * 8;
        aes.dinr()
            .write(|w| unsafe { w.din().bits((aad_bits >> 32) as u32) });
        aes.dinr()
            .write(|w| unsafe { w.din().bits(aad_bits as u32) });
        aes.dinr()
            .write(|w| unsafe { w.din().bits((data_bits >> 32) as u32) });
        aes.dinr()
            .write(|w| unsafe { w.din().bits(data_bits as u32) });
        wait_ccf(&aes)?;
        let mut tag = [0u8; 16];
        dout_block(&aes, &mut tag);
        aes.cr().modify(|_, w| w.en().clear_bit());
        Ok(tag)
    }
}
