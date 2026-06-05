#![no_std]

use cortex_m_semihosting::{debug, hprintln};

pub mod cyclecount;
pub mod stack;

// Re-export `hex_decode` from krabitls so the rest of this crate (and any
// downstream examples) can use it without picking a new import path.
pub use krabitls::hex_decode;

// ClientHello inputs + reference bytes, from tls_fixture seed=0.
pub const CLIENT_RANDOM: [u8; 32] = [
    0xed, 0xe5, 0x7b, 0xa2, 0x43, 0x3a, 0xd5, 0xa3, 0x4d, 0x05, 0x50, 0x3a, 0xfe, 0x4f, 0xc2, 0x89,
    0xdf, 0xd9, 0xe9, 0x53, 0x57, 0xd8, 0x16, 0x36, 0x80, 0x24, 0xe7, 0x3f, 0xbf, 0xa6, 0xfa, 0xf5,
];
pub const CLIENT_X25519_PUB: [u8; 32] = [
    0x82, 0x46, 0xe7, 0x35, 0x8f, 0x0a, 0xf7, 0xf3, 0x31, 0x7d, 0xca, 0xf6, 0x88, 0xd0, 0x34, 0xc9,
    0x5d, 0x5a, 0x2b, 0x54, 0xbf, 0x66, 0xc8, 0x95, 0x0e, 0xb8, 0x7a, 0x5f, 0x47, 0x93, 0x96, 0x0d,
];
/// Seed-0 ed25519-mode ClientHello bytes from the Python fixture (117 B).
/// Decoded from the readable hex fixture at compile time.
pub const EXPECTED_CLIENT_HELLO: [u8; 117] = hex_decode(include_str!(
    "../../testdata/packets/001_c2s_ClientHello.hex"
));

/// Seed-0 ServerHello bytes (95 B) — input to `parse_server_hello`.
pub const SERVER_HELLO_BYTES: [u8; 95] = hex_decode(include_str!(
    "../../testdata/packets/002_s2c_ServerHello.hex"
));
pub const SERVER_RANDOM: [u8; 32] = [
    0x64, 0x1c, 0x5b, 0xd9, 0x34, 0xab, 0xe1, 0xc5, 0x98, 0xa9, 0xc9, 0x61, 0xf7, 0xcb, 0x1e, 0x06,
    0x28, 0x0b, 0x4a, 0x5e, 0x88, 0x0c, 0x1c, 0x19, 0xd2, 0xfe, 0x9e, 0xef, 0x33, 0x48, 0x0c, 0xae,
];
pub const SERVER_X25519_PUB: [u8; 32] = [
    0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d, 0x3a,
    0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06, 0xdb, 0x7e,
];

// The X25519 shared secret the tls_fixture computed at seed 0, plus the
// handshake_secret derived from it. Both pulled from packets/002 dump notes.
pub const FIXTURE_DHE: [u8; 32] = [
    0xd6, 0xe8, 0x68, 0xc2, 0x71, 0xfa, 0x06, 0x2a, 0x48, 0xab, 0x2a, 0xcc, 0x32, 0xfe, 0x98, 0x58,
    0x0d, 0x48, 0x77, 0x00, 0x91, 0x1f, 0x47, 0xad, 0x94, 0xcb, 0xb3, 0xb5, 0x35, 0x58, 0xea, 0x51,
];
pub const FIXTURE_HANDSHAKE_SECRET: [u8; 32] = [
    0x67, 0x4c, 0x4a, 0x90, 0x69, 0x17, 0x0e, 0xcd, 0x7a, 0xc6, 0x92, 0x5e, 0x96, 0x22, 0x49, 0xa2,
    0xa8, 0x6d, 0x22, 0x50, 0xc1, 0x2f, 0x21, 0x7a, 0x2c, 0x2a, 0x28, 0x3c, 0x64, 0xbf, 0x28, 0x7f,
];
// SHA-256("") — used by Derive-Secret(., "derived", "") on initial Early Secret.
pub const EMPTY_SHA256: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

// Client X25519 private key + the expected s_hs_traffic_secret from the
// fixture's seed-0 chain (state/client.json + packets/002 notes).
pub const CLIENT_X25519_PRIV: [u8; 32] = [
    0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf, 0xe8,
    0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c, 0x28, 0x28,
];
// Kept as bare `[u8; 32]` because the post-refactor `Secret::new` takes
// `Zeroizing<[u8; 32]>` (not const-constructible). Callers wrap into
// `Secret` at use site; the resulting non-const value drop-zeroes.
pub const FIXTURE_S_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
    0x55, 0x59, 0xd1, 0xcf, 0x33, 0x31, 0x9c, 0x4b, 0x46, 0x2a, 0x11, 0x42, 0x92, 0x90, 0x2d, 0x05,
    0xb8, 0xcc, 0x08, 0xbc, 0x5a, 0xa5, 0xdd, 0x8e, 0x59, 0x84, 0x8b, 0xd0, 0x8d, 0xb2, 0x82, 0x9b,
];

/// packets/003: encrypted server flight (380 bytes).
pub const FIXTURE_PACKET_3: [u8; 380] = hex_decode(include_str!(
    "../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
));

/// packets/004: encrypted client Finished (58 bytes).
pub const FIXTURE_PACKET_4: [u8; 58] = hex_decode(include_str!(
    "../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
));

/// Client handshake traffic secret from packets/002 notes — used to validate
/// the derived `c_hs_ts` produced by the chosen HKDF backend.
pub const FIXTURE_C_HS_TRAFFIC_SECRET_BYTES: [u8; 32] = [
    0xa4, 0xfa, 0x72, 0xf0, 0xcc, 0x9e, 0xef, 0xe8, 0xb1, 0xcb, 0x2a, 0x53, 0x3e, 0x40, 0x82, 0x14,
    0x65, 0x32, 0x95, 0x4a, 0x6d, 0x25, 0x57, 0x14, 0xa1, 0x7c, 0x2c, 0xef, 0x69, 0x08, 0xa7, 0x8d,
];

/// packets/005: c→s app data record #0 (52 bytes including record header).
pub const FIXTURE_PACKET_5: [u8; 52] = hex_decode(include_str!(
    "../../testdata/packets/005_c2s_AppData_send_0.hex"
));

/// packets/006: s→c app data reply #0 (48 bytes including record header).
pub const FIXTURE_PACKET_6: [u8; 48] = hex_decode(include_str!(
    "../../testdata/packets/006_s2c_AppData_reply_0.hex"
));

/// Plaintext that the Python fixture put through `encrypt_record` to produce
/// `FIXTURE_PACKET_5`. The handshake harness re-encrypts this under the
/// derived c_ap key/iv and checks the output matches byte-for-byte.
pub const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";

/// Inner plaintext we expect to recover after decrypting `FIXTURE_PACKET_6`
/// under the derived s_ap key/iv. The em-dash is the UTF-8 sequence
/// `\xe2\x80\x94`.
pub const PACKET_6_PLAINTEXT: &[u8] = b"hello back \xe2\x80\x94 server here";

use cyclecount::CycleCounter;
use krabitls::{
    CLIENT_FINISHED_LEN, DerCert, HkdfSha256, RustCrypto, TranscriptHash,
    application_traffic_secrets, build_client_finished, decrypt_record, encrypt_record,
    handshake_secret, handshake_traffic_secrets, master_secret, split_inner_plaintext,
    traffic_keys, verify_server_flight,
};
use stack::{check_stack_high_water_mark, paint_stack};

/// Generic over the HKDF / SHA-256 backend so the same handshake body
/// is shared by `examples/krabitls.rs` (uses `RustCrypto`) and
/// `examples/krabitls_jedisct.rs` (uses `JedisctCrypto`). AEAD stays on
/// `RustCrypto` and cert parsing on `DerCert` either way.
///
/// Returns `Err(())` on any step's failure; callers surface that as the
/// example's `false` test result. The `()` error type plus `.map_err(|_| ())?`
/// keeps the body `?`-driven without dragging every krabitls error enum
/// into scope just to discriminate them.
// `Result<(), ()>` is intentional — the caller surfaces failure as `false`
// (see `test_fixture`'s contract); naming an error enum here would drag every
// krabitls error variant into scope just to discriminate them at the binding.
#[allow(clippy::result_unit_err)]
pub fn run_handshake<H: HkdfSha256>() -> Result<(), ()> {
    // ---- ClientHello writer ----
    let mut buf = [0u8; krabitls::CLIENT_HELLO_LEN];
    let mut cursor: &mut [u8] = &mut buf;
    let written =
        krabitls::write_client_hello(&mut cursor, &CLIENT_RANDOM, &CLIENT_X25519_PUB, None)
            .map_err(|_| ())?;
    if written != krabitls::CLIENT_HELLO_LEN {
        return Err(());
    }
    // Byte-identity against the 117-byte seed-0 fixture only holds when our
    // CH advertises ed25519 alone. With `feature = "rsa"` we also advertise
    // rsa_pss_rsae_sha256, so the CH is 119 B and the array sizes don't match.
    #[cfg(not(feature = "rsa"))]
    if buf != EXPECTED_CLIENT_HELLO {
        return Err(());
    }

    // ---- ServerHello parser ----
    let view = krabitls::parse_server_hello(&SERVER_HELLO_BYTES).map_err(|_| ())?;
    if view.random != &SERVER_RANDOM
        || view.x25519_share != &SERVER_X25519_PUB
        || !view.session_id_echo.is_empty()
        || view.cipher_suite != krabitls::consts::CIPHER_AES_128_GCM_SHA256
        || view.selected_version != krabitls::consts::TLS_1_3
    {
        return Err(());
    }

    // ---- Full key schedule + decrypt of packet 003 ----
    //   DHE  = X25519(client_priv, server_pub)
    //   hs   = handshake_secret(DHE)
    //   th   = SHA-256(CH || SH)                 (handshake bodies, no record headers)
    //   s_ts = Derive-Secret(hs, "s hs traffic", th)
    //   key  = HKDF-Expand-Label(s_ts, "key", "", 16)
    //   iv   = HKDF-Expand-Label(s_ts, "iv",  "", 12)
    //   plaintext = AES-128-GCM-decrypt(packet_3, key, iv, seq=0)
    type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
    let dhe = ed25519_heapless::x25519::<Bn>(&CLIENT_X25519_PRIV, &SERVER_X25519_PUB);
    let hs = handshake_secret::<H>(&dhe).map_err(|_| ())?;
    let mut transcript = TranscriptHash::<H>::new();
    transcript
        .update_record(&EXPECTED_CLIENT_HELLO)
        .map_err(|_| ())?;
    transcript
        .update_record(&SERVER_HELLO_BYTES)
        .map_err(|_| ())?;
    let (c_ts, s_ts) =
        handshake_traffic_secrets::<H>(&hs, &transcript.snapshot()).map_err(|_| ())?;
    // Validate the client-side `"c hs traffic"` derivation against the
    // Python fixture before we use it. Otherwise a regression in the
    // backend's client-secret derivation would still pass the
    // ClientFinished comparison, because we'd be feeding the fixture
    // bytes into `build_client_finished` instead of the derived secret.
    if c_ts.as_bytes() != &FIXTURE_C_HS_TRAFFIC_SECRET_BYTES {
        return Err(());
    }
    let (key, iv) = traffic_keys::<H>(&s_ts).map_err(|_| ())?;

    let mut pt_buf = [0u8; 400];
    let pt = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf)
        .map_err(|_| ())?;
    let (content, content_type) = split_inner_plaintext(pt).map_err(|_| ())?;
    if content_type != krabitls::consts::CT_HANDSHAKE {
        return Err(());
    }

    let verified = verify_server_flight::<H, DerCert, RustCrypto>(&mut transcript, content, &s_ts)
        .map_err(|_| ())?;
    const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];
    if verified.server_pubkey.as_ed25519() != Some(EXPECTED_SERVER_ID_PUB) {
        return Err(());
    }

    let th_through_sf = transcript.snapshot();
    let mut out = [0u8; 64];
    let record = build_client_finished::<H, RustCrypto>(&c_ts, &th_through_sf, 0, &mut out)
        .map_err(|_| ())?;
    if record.len() != CLIENT_FINISHED_LEN || record != &FIXTURE_PACKET_4[..] {
        return Err(());
    }

    // ---- App-data round trip ----
    //   ms      = HKDF-Extract(Derive-Secret(hs, "derived", ""), 0^32)
    //   c_ap_ts = Derive-Secret(ms, "c ap traffic", th_through_sf)
    //   s_ap_ts = Derive-Secret(ms, "s ap traffic", th_through_sf)
    //   (RFC 8446 §7.1; the AP traffic secrets use the transcript through the
    //   *server's* Finished, not the client's.)
    //
    // (1) re-encrypt PACKET_5_PLAINTEXT under c_ap, seq=0 → must equal FIXTURE_PACKET_5
    // (2) decrypt FIXTURE_PACKET_6 under s_ap, seq=0 → must yield PACKET_6_PLAINTEXT
    //
    // Both calls pass `seq = 0` because the fixture only replays the *first*
    // record under each freshly-installed traffic key. RFC 8446 §5.3 resets
    // record numbering to 0 whenever a new key/IV pair is installed, and
    // c_ap / s_ap each get a fresh pair here, so this is the correct seq.
    let ms = master_secret::<H>(&hs).map_err(|_| ())?;
    let (c_ap_ts, s_ap_ts) =
        application_traffic_secrets::<H>(&ms, &th_through_sf).map_err(|_| ())?;
    let (c_ap_key, c_ap_iv) = traffic_keys::<H>(&c_ap_ts).map_err(|_| ())?;
    let (s_ap_key, s_ap_iv) = traffic_keys::<H>(&s_ap_ts).map_err(|_| ())?;

    // Reuse the 400-byte `pt_buf` from the server-flight decrypt above for
    // both the encrypt and the decrypt — `pt_buf` is no longer live and the
    // 52 / 48 byte app-data records fit comfortably.
    let sent = encrypt_record::<RustCrypto>(
        PACKET_5_PLAINTEXT,
        krabitls::consts::CT_APPLICATION_DATA,
        &c_ap_key,
        &c_ap_iv,
        0,
        &mut pt_buf,
    )
    .map_err(|_| ())?;
    if sent != &FIXTURE_PACKET_5[..] {
        return Err(());
    }

    let inner =
        decrypt_record::<RustCrypto>(&FIXTURE_PACKET_6, &s_ap_key, &s_ap_iv, 0, &mut pt_buf)
            .map_err(|_| ())?;
    let (content, ct) = split_inner_plaintext(inner).map_err(|_| ())?;
    if ct != krabitls::consts::CT_APPLICATION_DATA || content != PACKET_6_PLAINTEXT {
        return Err(());
    }

    Ok(())
}

pub fn target_arch_name() -> &'static str {
    #[cfg(thumbv6m)]
    {
        "thumbv6m"
    }
    #[cfg(thumbv7m)]
    {
        "thumbv7m"
    }
    #[cfg(thumbv7em)]
    {
        "thumbv7em"
    }
    #[cfg(not(any(thumbv6m, thumbv7m, thumbv7em)))]
    {
        compile_error!(
            "cortex_m_demo only targets thumbv6m-none-eabi / thumbv7m-none-eabi / thumbv7em-none-eabi; see .cargo/config.toml"
        )
    }
}

/// Baseline stub for `examples/krabitls.rs --features baseline`: touches every
/// fixture buffer the real pipeline would consume so rodata stays alive, but
/// performs no actual crypto / protocol work. The `.text` delta between this
/// and the real build is the honest cost of krabitls + ed25519 + AES-GCM.
#[inline(never)]
pub fn fake_krabitls_pipeline() -> bool {
    use core::hint::black_box;
    // `&ARR` forces LTO to materialize the address, keeping the full rodata
    // payload alive — so the baseline has the same data layout as the real
    // build and only differs in executable code.
    black_box(&CLIENT_RANDOM);
    black_box(&CLIENT_X25519_PUB);
    black_box(&CLIENT_X25519_PRIV);
    black_box(&SERVER_RANDOM);
    black_box(&SERVER_X25519_PUB);
    black_box(&EXPECTED_CLIENT_HELLO);
    black_box(&SERVER_HELLO_BYTES);
    black_box(&FIXTURE_PACKET_3);
    black_box(&FIXTURE_PACKET_4);
    black_box(&FIXTURE_PACKET_5);
    black_box(&FIXTURE_PACKET_6);
    black_box(PACKET_5_PLAINTEXT);
    black_box(PACKET_6_PLAINTEXT);
    black_box(&FIXTURE_DHE);
    black_box(&FIXTURE_HANDSHAKE_SECRET);
    black_box(&FIXTURE_S_HS_TRAFFIC_SECRET_BYTES);
    black_box(&FIXTURE_C_HS_TRAFFIC_SECRET_BYTES);
    black_box(&EMPTY_SHA256);
    true
}

pub fn test_fixture(testable: fn() -> bool, name: &str) {
    // paint_stack MUST be the first call — anything (even hprintln) inlined ahead
    // of it inflates test_fixture's frame past the 256-byte safe zone and paint
    // ends up clobbering live stack.
    paint_stack();
    let counter = CycleCounter::new();
    let result = testable();
    let elapsed_kcycles = counter.elapsed() / 1000;
    let stack = check_stack_high_water_mark();
    if result {
        hprintln!("{} ACCEPT", name);
    } else {
        hprintln!("{} REJECT", name);
    }
    hprintln!(
        "METRIC stack:{} kcycles:{} target:{} name:{}",
        stack,
        elapsed_kcycles,
        target_arch_name(),
        name,
    );
    if result {
        debug::exit(debug::EXIT_SUCCESS);
    } else {
        debug::exit(debug::EXIT_FAILURE);
    }
}

use panic_semihosting as _;
