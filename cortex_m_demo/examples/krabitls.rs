#![no_main]
#![no_std]

#[cfg(not(feature = "baseline"))]
use cortex_m_demo::{
    CLIENT_RANDOM, CLIENT_X25519_PRIV, CLIENT_X25519_PUB, EXPECTED_CLIENT_HELLO,
    FIXTURE_C_HS_TRAFFIC_SECRET, FIXTURE_PACKET_3, FIXTURE_PACKET_4, FIXTURE_PACKET_5,
    FIXTURE_PACKET_6, PACKET_5_PLAINTEXT, PACKET_6_PLAINTEXT, SERVER_HELLO_BYTES, SERVER_RANDOM,
    SERVER_X25519_PUB,
};
use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use krabitls::{
    CLIENT_FINISHED_LEN, DerCert, RustCrypto, TranscriptHash, application_traffic_secrets,
    build_client_finished, decrypt_record, encrypt_record, handshake_secret,
    handshake_traffic_secrets, master_secret, split_inner_plaintext, traffic_keys,
    verify_server_flight,
};

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        #[cfg(feature = "baseline")]
        || cortex_m_demo::fake_krabitls_pipeline(),
        #[cfg(not(feature = "baseline"))]
        || {
            // ---- ClientHello writer ----
            let mut buf = [0u8; krabitls::CLIENT_HELLO_LEN];
            let mut cursor: &mut [u8] = &mut buf;
            let written = match krabitls::write_client_hello(
                &mut cursor,
                &CLIENT_RANDOM,
                &CLIENT_X25519_PUB,
                None,
            ) {
                Ok(n) => n,
                Err(_) => return false,
            };
            if written != krabitls::CLIENT_HELLO_LEN {
                return false;
            }
            // Byte-identity vs the seed-0 ed25519-mode fixture only holds in
            // the default build. With feature = "rsa" krabitls emits 119 bytes
            // (extra sig_algs scheme) and the 117-byte fixture won't match.
            #[cfg(not(feature = "rsa"))]
            if buf != EXPECTED_CLIENT_HELLO {
                return false;
            }

            // ---- ServerHello parser ----
            let view = match krabitls::parse_server_hello(&SERVER_HELLO_BYTES) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if view.random != &SERVER_RANDOM {
                return false;
            }
            if view.x25519_share != &SERVER_X25519_PUB {
                return false;
            }
            if !view.session_id_echo.is_empty() {
                return false;
            }
            if view.cipher_suite != krabitls::consts::CIPHER_AES_128_GCM_SHA256 {
                return false;
            }
            if view.selected_version != krabitls::consts::TLS_1_3 {
                return false;
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
            let hs = handshake_secret::<RustCrypto>(&dhe);
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            if transcript.update_record(&EXPECTED_CLIENT_HELLO).is_err() {
                return false;
            }
            if transcript.update_record(&SERVER_HELLO_BYTES).is_err() {
                return false;
            }
            let (_c_ts, s_ts) =
                handshake_traffic_secrets::<RustCrypto>(&hs, &transcript.snapshot());
            let (key, iv) = traffic_keys::<RustCrypto>(&s_ts);

            let mut pt_buf = [0u8; 400];
            let pt = match decrypt_record::<RustCrypto>(FIXTURE_PACKET_3, &key, &iv, 0, &mut pt_buf)
            {
                Ok(p) => p,
                Err(_) => return false,
            };
            let (content, content_type) = match split_inner_plaintext(pt) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if content_type != krabitls::consts::CT_HANDSHAKE {
                return false;
            }

            // Walk EE/Cert/CertVerify/Finished, verify cert self-sig, CertVerify
            // signature against the running transcript, and Finished MAC.
            let verified = match verify_server_flight::<RustCrypto, DerCert, RustCrypto>(
                &mut transcript,
                content,
                &s_ts,
            ) {
                Ok(v) => v,
                Err(_) => return false,
            };
            // Spot-check the server's Ed25519 identity pubkey we extracted.
            const EXPECTED_SERVER_ID_PUB: [u8; 32] = [
                0x9d, 0xfe, 0x2a, 0xb0, 0x3e, 0x35, 0x70, 0x4b, 0x9c, 0xfb, 0x93, 0xb6, 0x03, 0xa6,
                0x61, 0x18, 0x82, 0x17, 0xa6, 0xb5, 0xfd, 0x6a, 0x1f, 0x75, 0xe6, 0x16, 0x1a, 0x39,
                0xe0, 0x53, 0x4c, 0x3f,
            ];
            if verified.server_pubkey.as_ed25519() != Some(EXPECTED_SERVER_ID_PUB) {
                return false;
            }

            // ---- Build the client Finished record and compare to fixture ----
            let th_through_sf = transcript.snapshot();
            let mut out = [0u8; 64];
            let record = match build_client_finished::<RustCrypto, RustCrypto>(
                &FIXTURE_C_HS_TRAFFIC_SECRET,
                &th_through_sf,
                0,
                &mut out,
            ) {
                Ok(r) => r,
                Err(_) => return false,
            };
            if record.len() != CLIENT_FINISHED_LEN {
                return false;
            }
            if record != FIXTURE_PACKET_4 {
                return false;
            }

            // ---- App data round trip ----
            //
            // master_secret -> (c_ap_ts, s_ap_ts) -> (c_ap_key/iv, s_ap_key/iv)
            // 1. Encrypt PACKET_5_PLAINTEXT under c_ap, seq=0 -> must match FIXTURE_PACKET_5
            // 2. Decrypt FIXTURE_PACKET_6 under s_ap, seq=0 -> must yield PACKET_6_PLAINTEXT
            let ms = master_secret::<RustCrypto>(&hs);
            let (c_ap_ts, s_ap_ts) = application_traffic_secrets::<RustCrypto>(&ms, &th_through_sf);
            let (c_ap_key, c_ap_iv) = traffic_keys::<RustCrypto>(&c_ap_ts);
            let (s_ap_key, s_ap_iv) = traffic_keys::<RustCrypto>(&s_ap_ts);

            // (1) c->s app data
            let mut send_buf = [0u8; 80];
            let sent = match encrypt_record::<RustCrypto>(
                PACKET_5_PLAINTEXT,
                krabitls::consts::CT_APPLICATION_DATA,
                &c_ap_key,
                &c_ap_iv,
                0,
                &mut send_buf,
            ) {
                Ok(r) => r,
                Err(_) => return false,
            };
            if sent != FIXTURE_PACKET_5 {
                return false;
            }

            // (2) s->c app data
            let mut recv_buf = [0u8; 64];
            let inner = match decrypt_record::<RustCrypto>(
                FIXTURE_PACKET_6,
                &s_ap_key,
                &s_ap_iv,
                0,
                &mut recv_buf,
            ) {
                Ok(r) => r,
                Err(_) => return false,
            };
            let (content, ct) = match split_inner_plaintext(inner) {
                Ok(v) => v,
                Err(_) => return false,
            };
            if ct != krabitls::consts::CT_APPLICATION_DATA {
                return false;
            }
            if content != PACKET_6_PLAINTEXT {
                return false;
            }

            true
        },
        "krabitls",
    );
    // test_fixture always exits via cortex_m_semihosting::debug::exit, so we
    // never get here; satisfies cortex_m_rt's `fn() -> !` requirement without
    // clippy's empty_loop warning.
    unreachable!()
}
