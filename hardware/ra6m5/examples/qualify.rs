#![no_std]
#![no_main]

use cortex_m_rt::{entry, exception};
use krabitls::client::{ClientAuth, HkdfSha256, Sha256};
use krabitls_hw_ra6m5::{Sce9Crypto, Sce9Deadline, Sce9Error, Sce9Hkdf};
use panic_halt as _;
use rand_core::TryRng;
use rtt_target::{rprintln, rtt_init_print};
use zeroize::Zeroize;

const SYSTEM: usize = 0x4001_e000;
const PRCR: usize = SYSTEM + 0x3fe;
const SCKDIVCR: usize = SYSTEM + 0x20;
const SCKSCR: usize = SYSTEM + 0x26;
const HOCOCR: usize = SYSTEM + 0x36;
const OSCSF: usize = SYSTEM + 0x3c;
const SYST_CSR: *mut u32 = 0xe000_e010 as *mut u32;
const SYST_RVR: *mut u32 = 0xe000_e014 as *mut u32;
const SYST_CVR: *mut u32 = 0xe000_e018 as *mut u32;

fn arm_deadline() {
    unsafe {
        core::ptr::write_volatile(SYST_RVR, 0x00ff_ffff);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0x7);
    }
}

fn disarm_deadline() {
    unsafe {
        core::ptr::write_volatile(SYST_CSR, 0);
        core::ptr::write_volatile(SYST_CVR, 0);
    }
}

fn configure_20mhz_hoco() {
    unsafe {
        core::ptr::write_volatile(PRCR as *mut u16, 0xa501);
        core::ptr::write_volatile(HOCOCR as *mut u8, 0);
    }
    let mut remaining = 2_000_000;
    while unsafe { core::ptr::read_volatile(OSCSF as *const u8) } & 1 == 0 {
        remaining -= 1;
        if remaining == 0 {
            fail_text("HOCO stabilization timeout");
        }
    }
    unsafe {
        core::ptr::write_volatile(SCKDIVCR as *mut u32, 0);
        core::ptr::write_volatile(SCKSCR as *mut u8, 0);
        core::ptr::write_volatile(PRCR as *mut u16, 0xa500);
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

#[exception]
fn SysTick() {
    cortex_m::peripheral::SCB::sys_reset()
}

#[entry]
fn main() -> ! {
    rtt_init_print!();
    rprintln!("RA6M5 SCE9 qualification start");
    configure_20mhz_hoco();

    let deadline = Sce9Deadline::new(arm_deadline, disarm_deadline);
    let sce = match unsafe { Sce9Crypto::claim_after_board_init(deadline) } {
        Ok(sce) => sce,
        Err(error) => fail("open", error),
    };

    let mut rng = sce.rng();
    let mut entropy = [0; 64];
    if let Err(error) = rng.try_fill_bytes(&mut entropy) {
        fail("entropy", error);
    }
    if entropy.iter().all(|byte| *byte == entropy[0]) {
        fail_text("entropy constant");
    }
    entropy.zeroize();
    let mut short_entropy = [0; 1];
    if let Err(error) = rng.try_fill_bytes(&mut short_entropy) {
        fail("short entropy fill", error);
    }
    short_entropy.zeroize();
    if !krabitls_hw_ra6m5::qualification::wrapped_secret_wipes() {
        fail_text("wrapped secret zeroization");
    }
    if !krabitls_hw_ra6m5::qualification::entropy_continuous_test(&sce) {
        fail_text("entropy continuous test");
    }
    rprintln!("PASS entropy");

    let mut sha_input = [0; 7];
    let sha_offset = unaligned_offset(sha_input.as_ptr());
    sha_input[sha_offset..sha_offset + 3].copy_from_slice(b"abc");
    let digest = match sce.sha256(&sha_input[sha_offset..sha_offset + 3]) {
        Ok(digest) => digest,
        Err(error) => fail("sha256", error),
    };
    assert_bytes(
        "sha256 KAT",
        &digest,
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ],
    );

    let mut transcript = <Sce9Hkdf as HkdfSha256>::hasher();
    transcript.update(b"a");
    let saved = transcript.clone();
    transcript.update(b"bc");
    assert_bytes("incremental SHA", &transcript.snapshot().unwrap(), &digest);
    assert_bytes(
        "cloneable SHA",
        &saved.snapshot().unwrap(),
        &[
            0xca, 0x97, 0x81, 0x12, 0xca, 0x1b, 0xbd, 0xca, 0xfa, 0xc2, 0x31, 0xb3, 0x9a, 0x23,
            0xdc, 0x4d, 0xa7, 0x86, 0xef, 0xf8, 0x14, 0x7c, 0x4e, 0x72, 0xb9, 0x80, 0x77, 0x85,
            0xaf, 0xee, 0x48, 0xbb,
        ],
    );
    rprintln!("PASS SHA-256 incremental/clone");

    let hmac = match sce.hmac_sha256(&[0x0b; 20], b"Hi There") {
        Ok(mac) => mac,
        Err(error) => fail("HMAC", error),
    };
    assert_bytes(
        "HMAC KAT",
        &hmac,
        &[
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ],
    );

    let mut okm = [0; 42];
    if let Err(error) = sce.hkdf_sha256(
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ],
        &[0x0b; 22],
        &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        &mut okm,
    ) {
        fail("HKDF", error);
    }
    assert_bytes(
        "HKDF KAT",
        &okm,
        &[
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ],
    );
    okm.zeroize();
    rprintln!("PASS HMAC/HKDF vectors");

    let aes = sce
        .generate_aes128_key()
        .unwrap_or_else(|error| fail("AES keygen", error));
    let nonce = [0xa5; 12];
    let aad = b"KrabiTLS SCE9 qualification AAD";
    let plaintext = b"SCE9 wrapped-key authenticated record";
    let mut ciphertext = [0; 37];
    let mut tag_storage = [0; 19];
    let tag_offset = unaligned_offset(tag_storage.as_ptr());
    let tag: &mut [u8; 16] = (&mut tag_storage[tag_offset..tag_offset + 16])
        .try_into()
        .unwrap_or_else(|_| fail_text("unaligned tag view"));
    aes.encrypt_gcm(&nonce, aad, plaintext, &mut ciphertext, tag)
        .unwrap_or_else(|error| fail("AES-GCM encrypt", error));
    let mut opened = [0; 37];
    aes.decrypt_gcm(&nonce, aad, &ciphertext, &mut opened, &*tag)
        .unwrap_or_else(|error| fail("AES-GCM decrypt", error));
    assert_bytes("AES-GCM round trip", &opened, plaintext);
    tag[0] ^= 1;
    match aes.decrypt_gcm(&nonce, aad, &ciphertext, &mut opened, &*tag) {
        Err(Sce9Error::Authentication) => {}
        Err(error) => fail("AES-GCM invalid-tag status", error),
        Ok(()) => fail_text("AES-GCM accepted invalid tag"),
    }
    if opened.iter().any(|byte| *byte != 0) {
        fail_text("AES-GCM failure retained plaintext");
    }
    tag[0] ^= 1;
    aes.decrypt_gcm(&nonce, aad, &ciphertext, &mut opened, &*tag)
        .unwrap_or_else(|error| fail("AES-GCM recovery", error));
    rprintln!("PASS wrapped AES-GCM reject/recovery");

    let key_a = sce
        .generate_p256_key_pair()
        .unwrap_or_else(|error| fail("P-256 A", error));
    let key_b = sce
        .generate_p256_key_pair()
        .unwrap_or_else(|error| fail("P-256 B", error));
    let ephemeral_b = key_b
        .generate_ephemeral()
        .unwrap_or_else(|error| fail("ECDHE generate B", error));
    let ephemeral_a = key_a
        .generate_ephemeral()
        .unwrap_or_else(|error| fail("ECDHE generate A", error));
    let secret = ephemeral_a
        .derive_authenticated(&ephemeral_b, &key_b)
        .unwrap_or_else(|error| fail("ECDH AB", error));
    if secret.wrapped_len() != 56 {
        fail_text("wrapped ECDH secret length");
    }
    let ecdh_aes = secret
        .derive_aes128(b"KrabiTLS RA6M5 protected-path qualification")
        .unwrap_or_else(|error| fail("ECDH KDF", error));
    let protected_plaintext = b"wrapped ECDH to wrapped AES";
    let mut protected_ciphertext = [0; 27];
    let mut protected_tag = [0; 16];
    ecdh_aes
        .encrypt_gcm(
            &nonce,
            b"SP800-56C",
            protected_plaintext,
            &mut protected_ciphertext,
            &mut protected_tag,
        )
        .unwrap_or_else(|error| fail("ECDH-derived AES encrypt", error));
    let mut protected_opened = [0; 27];
    ecdh_aes
        .decrypt_gcm(
            &nonce,
            b"SP800-56C",
            &protected_ciphertext,
            &mut protected_opened,
            &protected_tag,
        )
        .unwrap_or_else(|error| fail("ECDH-derived AES decrypt", error));
    assert_bytes(
        "ECDH-derived AES round trip",
        &protected_opened,
        protected_plaintext,
    );
    let mut invalid_peer = [0; 65];
    invalid_peer[0] = 4;
    let invalid_trial = key_a
        .generate_ephemeral()
        .unwrap_or_else(|error| fail("ECDHE invalid trial", error));
    if invalid_trial.derive_unverified(&invalid_peer).is_ok() {
        fail_text("ECDH accepted invalid peer");
    }
    rprintln!("PASS wrapped P-256 ECDH/KDF/AES and invalid peer");

    let signature = key_a
        .sign_hash(&digest)
        .unwrap_or_else(|error| fail("ECDSA sign", error));
    key_a
        .verify_hash(&digest, &signature)
        .unwrap_or_else(|error| fail("ECDSA verify", error));
    let mut bad_signature = signature;
    bad_signature[7] ^= 1;
    if key_a.verify_hash(&digest, &bad_signature).is_ok() {
        fail_text("ECDSA accepted invalid signature");
    }

    let signer = key_a.signer(b"qualification certificate");
    let der = signer
        .sign(
            b"TLS 1.3, client CertificateVerify\0qualification",
            &mut rng,
        )
        .unwrap_or_else(|_| fail_text("ClientAuth sign"));
    let raw = parse_p256_der(&der).unwrap_or_else(|| fail_text("ClientAuth DER"));
    let signed_digest = sce
        .sha256(b"TLS 1.3, client CertificateVerify\0qualification")
        .unwrap_or_else(|error| fail("ClientAuth hash", error));
    key_a
        .verify_hash(&signed_digest, &raw)
        .unwrap_or_else(|error| fail("ClientAuth verify", error));
    rprintln!("PASS ECDSA raw and KrabiTLS ClientAuth flow");

    rprintln!("START KrabiTLS TLS 1.3 fallback flow");
    krabitls::client::qualify_p256_aes_hkdf_backends::<
        krabitls::backends::P256Group,
        krabitls::backends::RustCrypto,
        Sce9Hkdf,
        _,
    >(&mut rng)
    .unwrap_or_else(|_| fail_text("KrabiTLS TLS 1.3 fallback flow"));
    rprintln!("PASS KrabiTLS P-256 + SCE9 key schedule + record flow");

    rprintln!("RA6M5 SCE9 QUALIFICATION PASS");
    loop {
        cortex_m::asm::wfi();
    }
}

fn assert_bytes(name: &str, actual: &[u8], expected: &[u8]) {
    if actual != expected {
        rprintln!("FAIL {}", name);
        loop {
            cortex_m::asm::bkpt();
        }
    }
}

fn unaligned_offset(pointer: *const u8) -> usize {
    usize::from(pointer.addr() & 3 == 0)
}

fn parse_p256_der(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 8 || der[0] != 0x30 || der[1] as usize + 2 != der.len() {
        return None;
    }
    let mut cursor = 2;
    let mut raw = [0; 64];
    let (r, s) = raw.split_at_mut(32);
    for output in [r, s] {
        if der.get(cursor) != Some(&0x02) {
            return None;
        }
        let length = *der.get(cursor + 1)? as usize;
        cursor += 2;
        let integer = der.get(cursor..cursor + length)?;
        let integer = integer.strip_prefix(&[0]).unwrap_or(integer);
        if integer.len() > 32 {
            return None;
        }
        output[32 - integer.len()..].copy_from_slice(integer);
        cursor += length;
    }
    (cursor == der.len()).then_some(raw)
}

fn fail(name: &str, error: impl core::fmt::Debug) -> ! {
    rprintln!("FAIL {}: {:?}", name, error);
    loop {
        cortex_m::asm::bkpt();
    }
}

fn fail_text(name: &str) -> ! {
    rprintln!("FAIL {}", name);
    loop {
        cortex_m::asm::bkpt();
    }
}
