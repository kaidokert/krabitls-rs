#![no_std]
#![no_main]

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit, Nonce, Tag};
use core::ptr::write_volatile;
use cortex_m_rt::entry;
use krabitls::client::{HkdfSha256, KxGroup, Sha256};
use krabitls_hw_pg26::{Aes128GcmHw, Pg26Aead, Pg26Crypto, Pg26Hkdf, Pg26P256Group, qualification};
use panic_halt as _;
use rtt_target::{ChannelMode, rprintln, rtt_init_print};

const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];
const HMAC_RFC4231: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
];
const HKDF_RFC5869: [u8; 42] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
];
const GCM_CIPHERTEXT: [u8; 16] = [
    0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
];
const GCM_TAG: [u8; 16] = [
    0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
];

#[entry]
fn main() -> ! {
    rtt_init_print!(ChannelMode::BlockIfFull, 1024);
    rprintln!("PG26 Secure Engine KrabiTLS qualification");

    // Qualification harness owns board setup. CMU.CLKEN1_SET, bit 10, enables
    // SEMAILBOXHOST on EFM32PG26 Series-2 configuration 6.
    unsafe { write_volatile(0x4000_9068 as *mut u32, 1 << 10) };
    let crypto = unsafe { Pg26Crypto::claim_after_board_init() }
        .unwrap_or_else(|_| fail("mailbox claim/probe"));

    check(
        crypto.sha256(b"abc").unwrap_or_else(|_| fail("SHA-256")) == SHA256_ABC,
        "SHA-256 KAT",
    );
    let stream_input = [0xa5; 130];
    let mut hardware_hash = Pg26Hkdf::hasher();
    hardware_hash.update(&stream_input[..70]);
    hardware_hash.update(&stream_input[70..]);
    let software_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(stream_input).into();
    check(
        hardware_hash
            .snapshot()
            .unwrap_or_else(|_| fail("streaming SHA-256"))
            == software_hash,
        "streaming SHA-256 cross-agreement",
    );
    check(
        crypto
            .hmac_sha256(&[0x0b; 20], b"Hi There")
            .unwrap_or_else(|_| fail("HMAC"))
            == HMAC_RFC4231,
        "HMAC-SHA-256 RFC 4231",
    );
    let mut okm = [0u8; 42];
    if let Err(error) = crypto.hkdf_sha256(
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ],
        &[0x0b; 22],
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        &mut okm,
    ) {
        rprintln!("HKDF error: {:?}", error);
        fail("HKDF");
    }
    check(okm == HKDF_RFC5869, "HKDF-SHA-256 RFC 5869");

    let mut entropy = [0u8; 64];
    let mut rng = crypto.rng();
    rand_core::TryRng::try_fill_bytes(&mut rng, &mut entropy).unwrap_or_else(|_| fail("TRNG"));
    check(
        entropy.iter().any(|byte| *byte != 0) && entropy[..32] != entropy[32..],
        "TRNG output",
    );
    let mut partial_entropy = [0u8; 3];
    rand_core::TryRng::try_fill_bytes(&mut rng, &mut partial_entropy)
        .unwrap_or_else(|_| fail("sub-word TRNG request"));
    check(
        partial_entropy.iter().any(|byte| *byte != 0),
        "sub-word TRNG request",
    );
    check(
        qualification::entropy_continuous_test(&crypto),
        "continuous entropy rejection",
    );
    check(
        qualification::command_error_recovery(&crypto),
        "rejected-command recovery",
    );

    let cipher = Aes128GcmHw::new(&[0u8; 16].into());
    let mut block = [0u8; 16];
    let tag =
        encrypt(&cipher, &[0u8; 12], b"", &mut block).unwrap_or_else(|_| fail("AES-GCM encrypt"));
    check(block == GCM_CIPHERTEXT, "AES-GCM ciphertext KAT");
    check(tag.as_slice() == GCM_TAG, "AES-GCM tag KAT");
    decrypt(&cipher, &[0u8; 12], b"", &mut block, &tag).unwrap_or_else(|_| fail("AES-GCM decrypt"));
    check(block == [0; 16], "AES-GCM round trip");
    let mut rejected = GCM_CIPHERTEXT;
    let mut bad_tag = GCM_TAG;
    bad_tag[0] ^= 1;
    check(
        decrypt(&cipher, &[0u8; 12], b"", &mut rejected, &bad_tag.into()).is_err(),
        "AES-GCM bad tag rejected",
    );
    check(rejected == [0; 16], "unauthenticated plaintext wiped");

    let (left_secret, left_public) =
        Pg26P256Group::generate(&mut rng).unwrap_or_else(|_| fail("P-256 left generate"));
    let (right_secret, right_public) =
        Pg26P256Group::generate(&mut rng).unwrap_or_else(|_| fail("P-256 right generate"));
    let left = Pg26P256Group::derive(left_secret, right_public.as_slice())
        .unwrap_or_else(|_| fail("P-256 left derive"));
    let right = Pg26P256Group::derive(right_secret, left_public.as_slice())
        .unwrap_or_else(|_| fail("P-256 right derive"));
    check(
        left.as_slice() == right.as_slice(),
        "wrapped P-256 agreement",
    );
    let (invalid_secret, _) =
        Pg26P256Group::generate(&mut rng).unwrap_or_else(|_| fail("P-256 invalid-peer setup"));
    check(
        Pg26P256Group::derive(invalid_secret, &[0; 65]).is_err(),
        "invalid P-256 peer rejected",
    );
    check(qualification::wrapped_secret_wipes(), "wrapped secret wipe");

    krabitls::client::qualify_p256_aes_hkdf_backends::<Pg26P256Group, Pg26Aead, Pg26Hkdf, _>(
        &mut rng,
    )
    .unwrap_or_else(|_| fail("KrabiTLS combined hardware path"));
    rprintln!("PASS: wrapped P-256 + hardware key schedule + authenticated record");
    rprintln!("PG26 QUALIFICATION COMPLETE");
    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    loop {
        cortex_m::asm::wfi();
    }
}

fn encrypt(
    cipher: &Aes128GcmHw,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
) -> Result<Tag<Aes128GcmHw>, aead::Error> {
    cipher.encrypt_inout_detached(
        &Nonce::<Aes128GcmHw>::from(*nonce),
        aad,
        InOutBuf::from(data),
    )
}

fn decrypt(
    cipher: &Aes128GcmHw,
    nonce: &[u8; 12],
    aad: &[u8],
    data: &mut [u8],
    tag: &Tag<Aes128GcmHw>,
) -> Result<(), aead::Error> {
    cipher.decrypt_inout_detached(
        &Nonce::<Aes128GcmHw>::from(*nonce),
        aad,
        InOutBuf::from(data),
        tag,
    )
}

fn check(condition: bool, name: &str) {
    if condition {
        rprintln!("PASS: {}", name);
    } else {
        fail(name);
    }
}

fn fail(name: &str) -> ! {
    rprintln!("FAIL: {}", name);
    loop {
        cortex_m::asm::bkpt();
    }
}
