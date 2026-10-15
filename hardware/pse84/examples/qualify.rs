#![no_std]
#![no_main]

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit, Nonce, Tag};
use cortex_m_rt::entry;
use defmt_rtt as _;
use krabitls_hw_pse84::{
    Aes128GcmHw, Pse84Aead, Pse84Crypto, Pse84CryptoError, last_error, qualification,
};
use panic_probe as _;
use rand_core::TryRng;

const ZERO_KEY: [u8; 16] = [0; 16];
const ZERO_IV: [u8; 12] = [0; 12];
const BLOCK_CIPHERTEXT: [u8; 16] = [
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
];
const BLOCK_TAG: [u8; 16] = [
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
];
const EMPTY_TAG: [u8; 16] = [
    0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
];

#[entry]
fn main() -> ! {
    // The ROM reset path supplies clk_sys to CRYPTO. This all-Secure image
    // deliberately leaves PPC attribution unchanged. Those are board-policy
    // decisions and are not performed by the reusable adapter.
    let crypto = unsafe { Pse84Crypto::claim_after_board_init() }
        .unwrap_or_else(|_| fail("claim CRYPTO ownership"));
    defmt::info!("PSoC Edge E84 CRYPTO qualification");

    let mut entropy = [0u8; 64];
    crypto
        .rng()
        .try_fill_bytes(&mut entropy)
        .unwrap_or_else(|_| fail("TRNG output"));
    check(
        entropy.iter().any(|byte| *byte != 0) && entropy[..32] != entropy[32..],
        "TRNG repeated entropy",
    );
    check(
        qualification::exercise_entropy_continuous_test(&crypto),
        "TRNG continuous-test rejection",
    );

    let cipher = Aes128GcmHw::new(&ZERO_KEY.into());
    let mut empty = [];
    let empty_tag =
        encrypt(&cipher, &ZERO_IV, b"", &mut empty).unwrap_or_else(|_| fail("empty NIST vector"));
    check(empty_tag.as_slice() == EMPTY_TAG, "NIST empty tag");

    let mut block = [0u8; 16];
    let tag =
        encrypt(&cipher, &ZERO_IV, b"", &mut block).unwrap_or_else(|_| fail("block NIST vector"));
    check(block == BLOCK_CIPHERTEXT, "NIST block ciphertext");
    check(tag.as_slice() == BLOCK_TAG, "NIST block tag");
    decrypt(&cipher, &ZERO_IV, b"", &mut block, &tag).unwrap_or_else(|_| fail("NIST decrypt"));
    check(block == [0; 16], "NIST encrypt/decrypt agreement");

    for length in [1usize, 15, 16, 17, 31, 32, 63, 95] {
        let mut original = [0u8; 95];
        for (index, byte) in original[..length].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut varied = original;
        let tag = encrypt(&cipher, &ZERO_IV, b"non-block AAD", &mut varied[..length])
            .unwrap_or_else(|_| fail("varied-shape encrypt"));
        decrypt(
            &cipher,
            &ZERO_IV,
            b"non-block AAD",
            &mut varied[..length],
            &tag,
        )
        .unwrap_or_else(|_| fail("varied-shape decrypt"));
        check(
            varied[..length] == original[..length],
            "varied buffer shape",
        );
    }

    let mut rejected = BLOCK_CIPHERTEXT;
    let mut bad_tag = BLOCK_TAG;
    bad_tag[0] ^= 1;
    check(
        decrypt(&cipher, &ZERO_IV, b"", &mut rejected, &bad_tag.into()).is_err(),
        "authentication rejection",
    );
    check(rejected == [0; 16], "rejected plaintext clearing");
    check(
        last_error() == Some(Pse84CryptoError::Authentication),
        "authentication diagnostic",
    );

    qualification::force_next_timeout();
    let mut timed_out = [0xa5; 16];
    check(
        encrypt(&cipher, &ZERO_IV, b"", &mut timed_out).is_err(),
        "injected timeout rejected",
    );
    check(timed_out == [0; 16], "timeout output clearing");
    check(
        last_error() == Some(Pse84CryptoError::Timeout),
        "timeout diagnostic",
    );
    let mut recovered = [0u8; 16];
    let recovered_tag = encrypt(&cipher, &ZERO_IV, b"", &mut recovered)
        .unwrap_or_else(|_| fail("post-timeout recovery"));
    check(
        recovered == BLOCK_CIPHERTEXT && recovered_tag.as_slice() == BLOCK_TAG,
        "post-timeout recovery",
    );
    check(
        qualification::peripheral_disabled(),
        "post-operation peripheral power-down",
    );

    let mut disposable = Aes128GcmHw::new(&[0xa5; 16].into());
    check(
        qualification::exercise_key_wipe(&mut disposable),
        "adapter key wipe",
    );

    krabitls::client::qualify_aes_record_backend::<Pse84Aead>()
        .unwrap_or_else(|_| fail("KrabiTLS key schedule and record path"));
    check(true, "KrabiTLS key schedule and record round trip");

    defmt::info!("PSE84 CRYPTO QUALIFICATION PASS");
    loop {
        cortex_m::asm::wfi();
    }
}

fn encrypt(
    cipher: &Aes128GcmHw,
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<Tag<Aes128GcmHw>, aead::Error> {
    cipher.encrypt_inout_detached(
        &Nonce::<Aes128GcmHw>::from(*nonce),
        aad,
        InOutBuf::from(buffer),
    )
}

fn decrypt(
    cipher: &Aes128GcmHw,
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &Tag<Aes128GcmHw>,
) -> Result<(), aead::Error> {
    cipher.decrypt_inout_detached(
        &Nonce::<Aes128GcmHw>::from(*nonce),
        aad,
        InOutBuf::from(buffer),
        tag,
    )
}

fn check(condition: bool, name: &'static str) {
    if !condition {
        fail(name);
    }
    defmt::info!("PASS: {}", name);
}

fn fail(name: &'static str) -> ! {
    defmt::error!("FAIL: {}", name);
    loop {
        cortex_m::asm::bkpt();
    }
}
