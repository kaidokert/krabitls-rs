//! Host integration test that drives `DefaultStream::connect` end-to-end
//! through the seed-0 fixtures — no real transport, no OS RNG.

// Gated to the AES-128-GCM + Ed25519 suite the seed-0 fixtures were captured
// under. `mldsa` is excluded because its ML-DSA signature_algorithms entries
// shift the ClientHello bytes (the inner `rsa` fixtures shift too — they have
// their own captured variant). The default strategy is `NoClock`, so cert
// validity is skipped here; the `Clocked` path is unit-tested in `identity.rs`.
#![cfg(all(
    feature = "cipher-aes",
    not(feature = "chacha20"),
    not(feature = "mldsa")
))]

use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};
use krabitls_fixtures::{CannedTransport, SeededRng};

mod common;
use common::parse_hex;

#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets/001_c2s_ClientHello.hex");
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets/002_s2c_ServerHello.hex");
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets/003_s2c_ServerFlight_encrypted.hex");
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets/004_c2s_ClientFinished_encrypted.hex");
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const APP_DATA_SEND_HEX: &str = include_str!("../../testdata/packets/005_c2s_AppData_send_0.hex");
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const APP_DATA_REPLY_HEX: &str = include_str!("../../testdata/packets/006_s2c_AppData_reply_0.hex");

#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_CLIENT_HELLO_HEX: &str =
    include_str!("../../testdata/packets_rsa/001_c2s_ClientHello.hex");
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_SERVER_HELLO_HEX: &str =
    include_str!("../../testdata/packets_rsa/002_s2c_ServerHello.hex");
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_rsa/003_s2c_ServerFlight_encrypted.hex");
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets_rsa/004_c2s_ClientFinished_encrypted.hex");
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_APP_DATA_SEND_HEX: &str =
    include_str!("../../testdata/packets_rsa/005_c2s_AppData_send_0.hex");
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_APP_DATA_REPLY_HEX: &str =
    include_str!("../../testdata/packets_rsa/006_s2c_AppData_reply_0.hex");
/// Plaintext the seed-0 client sent at capture (`gen_rsa_fixtures`).
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_APP_DATA_SEND_PLAINTEXT: &[u8] = b"krabitls roundtrip probe\n";
/// The capture server's fixed reply.
#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
const RSA_APP_DATA_REPLY_PLAINTEXT: &[u8] = b"hello back from the test server";

/// First app-data plaintext the Python client sent at seed 0.
/// Matches `tls_fixture/demo.sh`: `cli.py --send "hello from the embedded client"`.
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const APP_DATA_SEND_PLAINTEXT: &[u8] = b"hello from the embedded client";
/// First app-data plaintext the Python server replied with at seed 0.
#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
const APP_DATA_REPLY_PLAINTEXT: &[u8] = "hello back \u{2014} server here".as_bytes();

#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
#[test]
fn facade_completes_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = Vec::with_capacity(server_hello.len() + server_flight.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 handshake against canned fixtures");

    // Captured TX must be CH || CF — byte-identical to the fixtures.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = Vec::with_capacity(expected_ch.len() + expected_cf.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "wire bytes diverged from the Python reference",
    );
}

#[cfg(all(not(feature = "rsa"), not(feature = "chacha20")))]
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
    let transport = CannedTransport::<1024>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let mut tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("handshake against canned fixtures");

    tls.write_all(APP_DATA_SEND_PLAINTEXT)
        .expect("write_all on freshly-connected stream");

    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).expect("read reply");
    assert_eq!(
        &buf[..n],
        APP_DATA_REPLY_PLAINTEXT,
        "decrypted reply must match the Python server's plaintext",
    );

    // Captured TX = CH || CF || encrypted-AppData-005 — byte-identical
    // to the Python reference for seed 0.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let expected_app = parse_hex(APP_DATA_SEND_HEX);
    let mut expected_tx =
        Vec::with_capacity(expected_ch.len() + expected_cf.len() + expected_app.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_cf);
    expected_tx.extend_from_slice(&expected_app);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "facade-encrypted record must byte-match Python's seed-0 packet 005",
    );
}

#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
#[test]
fn facade_completes_rsa_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(RSA_SERVER_HELLO_HEX);
    let server_flight = parse_hex(RSA_SERVER_FLIGHT_HEX);
    let mut server_stream = Vec::with_capacity(server_hello.len() + server_flight.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 RSA handshake against canned fixtures");

    let expected_ch = parse_hex(RSA_CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(RSA_CLIENT_FINISHED_HEX);
    let mut expected_tx = Vec::with_capacity(expected_ch.len() + expected_cf.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "RSA wire bytes diverged from the captured fixtures",
    );
}

#[cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]
#[test]
fn facade_round_trips_first_rsa_app_record_pair() {
    let server_hello = parse_hex(RSA_SERVER_HELLO_HEX);
    let server_flight = parse_hex(RSA_SERVER_FLIGHT_HEX);
    let app_reply = parse_hex(RSA_APP_DATA_REPLY_HEX);

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
        .expect("handshake against canned RSA fixtures");

    tls.write_all(RSA_APP_DATA_SEND_PLAINTEXT)
        .expect("write_all on freshly-connected stream");

    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).expect("read reply");
    assert_eq!(
        &buf[..n],
        RSA_APP_DATA_REPLY_PLAINTEXT,
        "decrypted RSA reply must match the captured server plaintext",
    );

    let expected_ch = parse_hex(RSA_CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(RSA_CLIENT_FINISHED_HEX);
    let expected_app = parse_hex(RSA_APP_DATA_SEND_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    expected_tx.extend_from_slice(&expected_app);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "facade-encrypted RSA app record must byte-match the captured 005",
    );
}
