//! Host integration test: AES-128-GCM + ECDSA-P256 server-cert facade
//! end-to-end through the seed-0 fixtures (captured from openssl 3.6, see
//! `gen_ecdsa_fixtures`). Exercises the ECDSA verify path with no network:
//! self-signed P-256 leaf verify + the ECDSA-P256 CertificateVerify. Gated to
//! `ecdsa` + `cipher-aes` to match the captured ClientHello (its two ECDSA
//! signature_algorithms entries shift the bytes vs the Ed25519 fixtures).

#![cfg(all(
    feature = "cipher-aes",
    feature = "ecdsa",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "mlkem")
))]

mod common;

use common::parse_hex;
use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};
use krabitls_fixtures::{CannedTransport, SeededRng};

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets_ecdsa/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets_ecdsa/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_ecdsa/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets_ecdsa/004_c2s_ClientFinished_encrypted.hex");
const APP_DATA_SEND_HEX: &str =
    include_str!("../../testdata/packets_ecdsa/005_c2s_AppData_send_0.hex");
const APP_DATA_REPLY_HEX: &str =
    include_str!("../../testdata/packets_ecdsa/006_s2c_AppData_reply_0.hex");

/// The plaintext the seed-0 client sent at capture (`gen_ecdsa_fixtures`).
const APP_DATA_SEND_PLAINTEXT: &[u8] = b"krabitls roundtrip probe\n";
/// The capture server's fixed reply.
const APP_DATA_REPLY_PLAINTEXT: &[u8] = b"hello back from the test server";

#[test]
fn facade_completes_ecdsa_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = Vec::with_capacity(server_hello.len() + server_flight.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<1024>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 ECDSA handshake against canned fixtures");

    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "ECDSA wire bytes diverged from the captured fixtures",
    );
}

#[test]
fn facade_round_trips_first_ecdsa_app_record_pair() {
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
    let transport = CannedTransport::<1024>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let mut tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("handshake against canned ECDSA fixtures");

    tls.write_all(APP_DATA_SEND_PLAINTEXT)
        .expect("write_all on freshly-connected stream");

    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).expect("read reply");
    assert_eq!(
        &buf[..n],
        APP_DATA_REPLY_PLAINTEXT,
        "decrypted ECDSA reply must match the captured server plaintext",
    );

    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let expected_app = parse_hex(APP_DATA_SEND_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    expected_tx.extend_from_slice(&expected_app);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "facade-encrypted ECDSA app record must byte-match the captured 005",
    );
}
