#![no_std]
#![no_main]

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit, Nonce, Tag};
use cortex_m_rt::entry;
use krabitls_hw_nrf5340::{
    Aes128GcmHw, CryptoCellError, Nrf5340Aead, last_error, qualification, shutdown,
};
use panic_halt as _;
use rtt_target::{ChannelMode, rprintln, rtt_init_print};

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

const PARTIAL_KEY: [u8; 16] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
];
const PARTIAL_IV: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];
const PARTIAL_AAD: [u8; 20] = [
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
];
const PARTIAL_PLAINTEXT: [u8; 60] = [
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
];
const PARTIAL_CIPHERTEXT: [u8; 60] = [
    0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
    0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
    0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
    0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91,
];
const PARTIAL_TAG: [u8; 16] = [
    0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,
];

#[entry]
fn main() -> ! {
    rtt_init_print!(ChannelMode::BlockIfFull, 1024);
    rprintln!("nRF5340 CryptoCell-312 AES-GCM qualification");

    let cipher = Aes128GcmHw::new(&ZERO_KEY.into());
    let mut empty: [u8; 0] = [];
    let tag =
        encrypt(&cipher, &ZERO_IV, b"", &mut empty).unwrap_or_else(|_| fail("empty encryption"));
    check(tag.as_slice() == EMPTY_TAG, "NIST empty tag");

    let mut block = [0u8; 16];
    let tag =
        encrypt(&cipher, &ZERO_IV, b"", &mut block).unwrap_or_else(|_| fail("block encryption"));
    check(block == BLOCK_CIPHERTEXT, "NIST block ciphertext");
    check(tag.as_slice() == BLOCK_TAG, "NIST block tag");
    decrypt(&cipher, &ZERO_IV, b"", &mut block, &tag).unwrap_or_else(|_| fail("block decryption"));
    check(block == [0; 16], "NIST block round trip");

    let partial_cipher = Aes128GcmHw::new(&PARTIAL_KEY.into());
    let mut partial = PARTIAL_PLAINTEXT;
    let partial_tag = encrypt(&partial_cipher, &PARTIAL_IV, &PARTIAL_AAD, &mut partial)
        .unwrap_or_else(|_| fail("partial encryption"));
    check(partial == PARTIAL_CIPHERTEXT, "NIST partial ciphertext");
    check(partial_tag.as_slice() == PARTIAL_TAG, "NIST partial tag");
    decrypt(
        &partial_cipher,
        &PARTIAL_IV,
        &PARTIAL_AAD,
        &mut partial,
        &partial_tag,
    )
    .unwrap_or_else(|_| fail("partial decryption"));
    check(partial == PARTIAL_PLAINTEXT, "NIST partial round trip");

    let mut rejected = BLOCK_CIPHERTEXT;
    let mut bad_tag = BLOCK_TAG;
    bad_tag[0] ^= 1;
    check(
        decrypt(&cipher, &ZERO_IV, b"", &mut rejected, &bad_tag.into()).is_err(),
        "bad tag rejected",
    );
    check(rejected == [0; 16], "unauthenticated plaintext erased");
    check(
        last_error() == Some(CryptoCellError::Authentication),
        "authentication diagnostic",
    );

    let cleanups_before = qualification::cleanup_count();
    qualification::force_next_timeout();
    let mut timed_out = [0xa5; 16];
    check(
        encrypt(&cipher, &ZERO_IV, b"", &mut timed_out).is_err(),
        "injected timeout rejected",
    );
    check(timed_out == [0; 16], "timeout output erased");
    check(
        last_error() == Some(CryptoCellError::Timeout),
        "timeout diagnostic",
    );
    check(
        qualification::cleanup_count() == cleanups_before + 1,
        "timeout cleanup executed",
    );
    let mut recovered = [0u8; 16];
    let recovered_tag = encrypt(&cipher, &ZERO_IV, b"", &mut recovered)
        .unwrap_or_else(|_| fail("post-timeout recovery"));
    check(recovered == BLOCK_CIPHERTEXT, "post-timeout ciphertext");
    check(recovered_tag.as_slice() == BLOCK_TAG, "post-timeout tag");
    check(
        qualification::peripheral_state_cleared(),
        "peripheral accumulator cleared and host idle",
    );

    let mut disposable = Aes128GcmHw::new(&[0xa5; 16].into());
    check(
        qualification::exercise_key_wipe(&mut disposable),
        "key buffer wipe",
    );

    krabitls::client::qualify_aes_record_backend::<Nrf5340Aead>()
        .unwrap_or_else(|_| fail("KrabiTLS TLS record path"));
    rprintln!("PASS: KrabiTLS TLS record encrypt/decrypt and bad-tag rejection");

    shutdown().unwrap_or_else(|_| fail("terminal power-down handshake"));
    check(
        qualification::subsystem_disabled(),
        "terminal power-down handshake",
    );
    let mut after_shutdown = [0xa5; 16];
    check(
        encrypt(&cipher, &ZERO_IV, b"", &mut after_shutdown).is_err(),
        "post-shutdown operation rejected",
    );
    check(
        last_error() == Some(CryptoCellError::PoweredDown),
        "post-shutdown diagnostic",
    );
    rprintln!("CRYPTOCELL QUALIFICATION PASS");
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

fn check(condition: bool, name: &str) {
    if !condition {
        fail(name);
    }
    rprintln!("PASS: {}", name);
}

fn fail(name: &str) -> ! {
    rprintln!("FAIL: {}", name);
    loop {
        cortex_m::asm::bkpt();
    }
}
