//! Host integration test: X25519MLKEM768 + AES-128-GCM + Ed25519 facade
//! end-to-end through the seed-0 fixtures, captured from openssl 3.6 (see
//! `gen_mlkem_fixtures`). The only coverage that exercises the real hybrid
//! key schedule: ML-KEM decapsulation, the `mlkem_ss || x25519_ss` combined
//! secret, and the transcript over the 1216-byte hybrid key_share. Gated to
//! `mlkem` + `cipher-aes` to match the captured ClientHello (which advertises
//! only X25519MLKEM768).

#![cfg(all(
    feature = "cipher-aes",
    feature = "mlkem",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    // Blinding draws extra keygen entropy, shifting the seed-0 wire bytes off the
    // capture; this byte-golden fixture only reproduces with blinding off.
    not(feature = "blinding")
))]

mod common;

use common::parse_hex;
use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};
use krabitls_fixtures::{CannedTransport, SeededRng};

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets_mlkem/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets_mlkem/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_mlkem/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets_mlkem/004_c2s_ClientFinished_encrypted.hex");
const APP_DATA_SEND_HEX: &str =
    include_str!("../../testdata/packets_mlkem/005_c2s_AppData_send_0.hex");
const APP_DATA_REPLY_HEX: &str =
    include_str!("../../testdata/packets_mlkem/006_s2c_AppData_reply_0.hex");

/// The plaintext the seed-0 client sent at capture (`gen_mlkem_fixtures`).
const APP_DATA_SEND_PLAINTEXT: &[u8] = b"krabitls roundtrip probe\n";
/// The capture server's fixed reply.
const APP_DATA_REPLY_PLAINTEXT: &[u8] = b"hello back from the test server";

#[test]
fn facade_completes_hybrid_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = server_hello;
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 X25519MLKEM768 handshake against canned fixtures");

    // Captured TX must be CH || CF — byte-identical to the fixtures. The CH
    // carries the 1216-byte hybrid key_share; matching it proves the seed-0
    // ML-KEM ek is reproduced exactly.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "hybrid wire bytes diverged from the captured fixtures",
    );
}

#[test]
fn facade_round_trips_first_app_record_pair() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let app_reply = parse_hex(APP_DATA_REPLY_HEX);

    let mut server_stream =
        Vec::with_capacity(server_hello.len() + server_flight.len() + app_reply.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);
    server_stream.extend_from_slice(&app_reply);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let mut tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("handshake against canned hybrid fixtures");

    tls.write_all(APP_DATA_SEND_PLAINTEXT)
        .expect("write_all on freshly-connected stream");

    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).expect("read reply");
    assert_eq!(
        &buf[..n],
        APP_DATA_REPLY_PLAINTEXT,
        "decrypted reply must match the captured server plaintext",
    );

    // Captured TX = CH || CF || encrypted-AppData-005 — byte-identical.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let expected_app = parse_hex(APP_DATA_SEND_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    expected_tx.extend_from_slice(&expected_app);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "facade-encrypted hybrid app record must byte-match the captured 005",
    );
}
