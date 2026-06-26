//! Host integration test: ChaCha20-Poly1305 + Ed25519 facade end-to-end
//! through the seed-0 fixtures. Mirrors `canned_handshake.rs` (AES) for the
//! ChaCha-only build — the ClientHello advertises only ChaCha, so this is
//! gated to `chacha20` without `cipher-aes` to match the captured fixtures.

#![cfg(all(
    feature = "chacha20",
    not(feature = "cipher-aes"),
    not(feature = "rsa")
))]

mod common;

use common::parse_hex;
use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};
use krabitls_fixtures::{CannedTransport, SeededRng};

const CLIENT_HELLO_HEX: &str =
    include_str!("../../testdata/packets_chacha/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str =
    include_str!("../../testdata/packets_chacha/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_chacha/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets_chacha/004_c2s_ClientFinished_encrypted.hex");

#[test]
fn facade_completes_chacha_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = server_hello;
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 ChaCha handshake against canned fixtures");

    // Captured TX must be CH || CF — byte-identical to the fixtures.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = expected_ch;
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "ChaCha wire bytes diverged from the Python reference",
    );
}
