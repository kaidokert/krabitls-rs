#![no_std]
#![no_main]

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit, Nonce, Tag};
use cortex_m_rt::entry;
use krabitls::client::KxGroup;
use krabitls_hw_nrf5340::{
    Aes128GcmHw, CryptoCellError, Nrf5340Aead, Nrf5340P256Group, Nrf5340Rng, last_error,
    qualification, shutdown,
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

const RFC5903_I_PRIVATE: [u8; 32] = [
    0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31, 0x6d, 0xe5,
    0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57, 0x86, 0x2d, 0x14, 0x33,
];
const RFC5903_I_PUBLIC: [u8; 65] = [
    0x04, 0xda, 0xd0, 0xb6, 0x53, 0x94, 0x22, 0x1c, 0xf9, 0xb0, 0x51, 0xe1, 0xfe, 0xca, 0x57, 0x87,
    0xd0, 0x98, 0xdf, 0xe6, 0x37, 0xfc, 0x90, 0xb9, 0xef, 0x94, 0x5d, 0x0c, 0x37, 0x72, 0x58, 0x11,
    0x80, 0x52, 0x71, 0xa0, 0x46, 0x1c, 0xdb, 0x82, 0x52, 0xd6, 0x1f, 0x1c, 0x45, 0x6f, 0xa3, 0xe5,
    0x9a, 0xb1, 0xf4, 0x5b, 0x33, 0xac, 0xcf, 0x5f, 0x58, 0x38, 0x9e, 0x05, 0x77, 0xb8, 0x99, 0x0b,
    0xb3,
];
const RFC5903_R_PUBLIC: [u8; 65] = [
    0x04, 0xd1, 0x2d, 0xfb, 0x52, 0x89, 0xc8, 0xd4, 0xf8, 0x12, 0x08, 0xb7, 0x02, 0x70, 0x39, 0x8c,
    0x34, 0x22, 0x96, 0x97, 0x0a, 0x0b, 0xcc, 0xb7, 0x4c, 0x73, 0x6f, 0xc7, 0x55, 0x44, 0x94, 0xbf,
    0x63, 0x56, 0xfb, 0xf3, 0xca, 0x36, 0x6c, 0xc2, 0x3e, 0x81, 0x57, 0x85, 0x4c, 0x13, 0xc5, 0x8d,
    0x6a, 0xac, 0x23, 0xf0, 0x46, 0xad, 0xa3, 0x0f, 0x83, 0x53, 0xe7, 0x4f, 0x33, 0x03, 0x98, 0x72,
    0xab,
];
const RFC5903_SHARED: [u8; 32] = [
    0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25, 0x65, 0x20,
    0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0, 0x4b, 0x94, 0x42, 0xde,
];

#[entry]
fn main() -> ! {
    rtt_init_print!(ChannelMode::BlockIfFull, 1024);
    rprintln!("nRF5340 CryptoCell-312 AES-GCM/TRNG/P-256 qualification");

    let mut entropy = [0; 64];
    rand_core::TryRng::try_fill_bytes(&mut Nrf5340Rng, &mut entropy)
        .unwrap_or_else(|_| fail("CryptoCell entropy"));
    check(
        entropy.iter().any(|byte| *byte != 0) && entropy[..32] != entropy[32..],
        "CryptoCell entropy output",
    );

    let (rfc_secret, rfc_public) = Nrf5340P256Group::generate(&mut FixedRng(RFC5903_I_PRIVATE))
        .unwrap_or_else(|_| fail("RFC 5903 public key"));
    check(
        rfc_public.as_slice() == RFC5903_I_PUBLIC,
        "RFC 5903 public key",
    );
    let rfc_shared = Nrf5340P256Group::derive(rfc_secret, &RFC5903_R_PUBLIC)
        .unwrap_or_else(|_| fail("RFC 5903 shared secret"));
    check(
        rfc_shared.as_slice() == RFC5903_SHARED,
        "RFC 5903 shared secret",
    );

    for _ in 0..8 {
        let (left_secret, left_public) = Nrf5340P256Group::generate(&mut Nrf5340Rng)
            .unwrap_or_else(|_| fail("generated left key"));
        let (right_secret, right_public) = Nrf5340P256Group::generate(&mut Nrf5340Rng)
            .unwrap_or_else(|_| fail("generated right key"));
        let left_shared = Nrf5340P256Group::derive(left_secret, right_public.as_slice())
            .unwrap_or_else(|_| fail("generated left agreement"));
        let right_shared = Nrf5340P256Group::derive(right_secret, left_public.as_slice())
            .unwrap_or_else(|_| fail("generated right agreement"));
        check(
            left_shared.as_slice() == right_shared.as_slice(),
            "generated-key agreement",
        );
    }

    let (invalid_secret, _) =
        Nrf5340P256Group::generate(&mut Nrf5340Rng).unwrap_or_else(|_| fail("invalid-peer setup"));
    check(
        Nrf5340P256Group::derive(invalid_secret, &[0; 65]).is_err(),
        "invalid peer rejected",
    );

    qualification::force_next_vendor_timeout();
    check(
        Nrf5340P256Group::generate(&mut FixedRng(RFC5903_I_PRIVATE)).is_err(),
        "injected PKA timeout rejected",
    );
    let (_, recovered_public) = Nrf5340P256Group::generate(&mut FixedRng(RFC5903_I_PRIVATE))
        .unwrap_or_else(|_| fail("post-timeout PKA recovery"));
    check(
        recovered_public.as_slice() == RFC5903_I_PUBLIC,
        "post-timeout PKA recovery",
    );
    check(
        qualification::exercise_p256_secret_wipe(),
        "P-256 secret buffer wipe",
    );

    krabitls::client::qualify_p256_aes_backends::<Nrf5340P256Group, Nrf5340Aead, _>(
        &mut Nrf5340Rng,
    )
    .unwrap_or_else(|_| fail("KrabiTLS P-256/key-schedule/record path"));
    rprintln!("PASS: KrabiTLS P-256, TLS 1.3 key schedule, and record round trip");

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

struct FixedRng([u8; 32]);

impl rand_core::TryRng for FixedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(self.0[..4].try_into().unwrap()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(self.0[..8].try_into().unwrap()))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for (index, byte) in destination.iter_mut().enumerate() {
            *byte = self.0[index % self.0.len()];
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for FixedRng {}

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
