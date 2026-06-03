#![no_main]
#![no_std]

#[cfg(not(feature = "baseline"))]
use cortex_m_demo::{
    CLIENT_RANDOM, CLIENT_X25519_PRIV, CLIENT_X25519_PUB, EXPECTED_CLIENT_HELLO,
    FIXTURE_C_HS_TRAFFIC_SECRET_BYTES, FIXTURE_PACKET_3, FIXTURE_PACKET_4, SERVER_HELLO_BYTES,
    SERVER_RANDOM, SERVER_X25519_PUB,
};
use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use krabitls::newtype::Secret;
#[cfg(not(feature = "baseline"))]
use krabitls::{
    CLIENT_FINISHED_LEN, DerCert, RustCrypto, TranscriptHash, ZeroBuf, build_client_finished,
    decrypt_record, handshake_secret, handshake_traffic_secrets, split_inner_plaintext,
    traffic_keys, verify_server_flight,
};

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        #[cfg(feature = "baseline")]
        || cortex_m_demo::fake_krabitls_pipeline(),
        #[cfg(not(feature = "baseline"))]
        || run_handshake().is_ok(),
        "krabitls",
    );
    // test_fixture always exits via cortex_m_semihosting::debug::exit, so we
    // never get here; satisfies cortex_m_rt's `fn() -> !` requirement without
    // clippy's empty_loop warning.
    unreachable!()
}

/// Run the full handshake check. Returns `Err(())` on any failure; the
/// caller surfaces that as a `false` test result. Using a `()` error type
/// plus `.map_err(|_| ())?` lets the body stay `?`-driven without
/// dragging every krabitls error enum into scope just to discriminate
/// them.
#[cfg(not(feature = "baseline"))]
fn run_handshake() -> Result<(), ()> {
    // ---- ClientHello writer ----
    let mut buf = [0u8; krabitls::CLIENT_HELLO_LEN];
    let mut cursor: &mut [u8] = &mut buf;
    let written =
        krabitls::write_client_hello(&mut cursor, &CLIENT_RANDOM, &CLIENT_X25519_PUB, None)
            .map_err(|_| ())?;
    if written != krabitls::CLIENT_HELLO_LEN {
        return Err(());
    }
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
    let hs = handshake_secret::<RustCrypto>(&dhe).map_err(|_| ())?;
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript
        .update_record(&EXPECTED_CLIENT_HELLO)
        .map_err(|_| ())?;
    transcript
        .update_record(&SERVER_HELLO_BYTES)
        .map_err(|_| ())?;
    let (_c_ts, s_ts) =
        handshake_traffic_secrets::<RustCrypto>(&hs, &transcript.snapshot()).map_err(|_| ())?;
    let (key, iv) = traffic_keys::<RustCrypto>(&s_ts).map_err(|_| ())?;

    let mut pt_buf = [0u8; 400];
    let pt = decrypt_record::<RustCrypto>(&FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf)
        .map_err(|_| ())?;
    let (content, content_type) = split_inner_plaintext(pt).map_err(|_| ())?;
    if content_type != krabitls::consts::CT_HANDSHAKE {
        return Err(());
    }

    // Walk EE/Cert/CertVerify/Finished, verify cert self-sig, CertVerify
    // signature against the running transcript, and Finished MAC.
    let verified =
        verify_server_flight::<RustCrypto, DerCert, RustCrypto>(&mut transcript, content, &s_ts)
            .map_err(|_| ())?;
    // Spot-check the server's Ed25519 identity pubkey we extracted.
    const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
        0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6, 0x61,
        0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39, 0xe0, 0x53,
        0x4c, 0x3f,
    ];
    if verified.server_pubkey.as_ed25519() != Some(EXPECTED_SERVER_ID_PUB) {
        return Err(());
    }

    // ---- Build the client Finished record and compare to fixture ----
    //
    // `FIXTURE_C_HS_TRAFFIC_SECRET_BYTES` lives in lib.rs as a bare
    // `[u8; 32]` because `Zeroizing::new` isn't const-stable. Wrap here
    // at the consumer; the resulting `Secret` drop-zeroes at scope exit.
    let c_hs_ts = Secret::new(ZeroBuf::<32>::new(FIXTURE_C_HS_TRAFFIC_SECRET_BYTES));
    let th_through_sf = transcript.snapshot();
    let mut out = [0u8; 64];
    let record =
        build_client_finished::<RustCrypto, RustCrypto>(&c_hs_ts, &th_through_sf, 0, &mut out)
            .map_err(|_| ())?;
    if record.len() != CLIENT_FINISHED_LEN || record != &FIXTURE_PACKET_4[..] {
        return Err(());
    }

    // Handshake fully verified on both sides. App-data round-trip
    // (encrypt/decrypt under c_ap/s_ap keys) is exercised by the
    // host-side library tests and dropped from this M3 demo to keep
    // the example minimal.
    Ok(())
}
