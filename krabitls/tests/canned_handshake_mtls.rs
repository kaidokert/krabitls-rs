//! Hermetic mutual-TLS regression test: drives `DefaultStream::connect`
//! end-to-end through a seed-0 fixture whose server flight carries a
//! `CertificateRequest`, exercising the full `WithClientAuth` path (client
//! `Certificate` + `CertificateVerify` + `Finished`) with no network and no
//! OS RNG. Fixtures captured against a local `openssl s_server -tls1_3
//! -Verify` — see `testdata/packets_mtls/GENERATION.md`.

// AES-128-GCM + Ed25519, the suite the seed-0 fixtures were captured under.
// `rsa` would add rsa_pss to the ClientHello's signature_algorithms and shift
// the captured bytes, so it's excluded like the sibling AES fixture.
#![cfg(all(
    feature = "cipher-aes",
    not(feature = "chacha20"),
    not(feature = "rsa")
))]

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, Ed25519ClientAuth, RuntimeSuitePolicy,
};
use krabitls_fixtures::{CannedTransport, SeededRng};

mod common;
use common::parse_hex;

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets_mtls/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets_mtls/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_mtls/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_mtls/004_c2s_ClientSecondFlight_encrypted.hex");

/// The client's Ed25519 leaf, sent in the client `Certificate`.
const CLIENT_LEAF_DER: &[u8] = include_bytes!("../../testdata/packets_mtls/client_leaf.der");

/// Throwaway Ed25519 seed the fixture client signs `CertificateVerify` with —
/// a test vector, not a real credential. Derives the public key in
/// `client_leaf.der`.
const CLIENT_SEED: [u8; 32] = [
    0xf2, 0x7f, 0x8c, 0xfc, 0xe9, 0x94, 0x5f, 0x91, 0x13, 0xab, 0xbb, 0xd4, 0x1a, 0x35, 0x94, 0x91,
    0xe6, 0x95, 0xaf, 0x92, 0x35, 0x65, 0xf8, 0xda, 0xc6, 0x25, 0xd1, 0xdd, 0x98, 0x80, 0x1b, 0xc9,
];

#[test]
fn facade_completes_mtls_handshake_against_canned_fixtures() {
    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = Vec::with_capacity(server_hello.len() + server_flight.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);

    let signer = Ed25519ClientAuth::from_seed(&CLIENT_SEED, CLIENT_LEAF_DER)
        .expect("seed derives the fixture client key");
    let params = ClientParams::self_signed("mtls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 mTLS handshake against canned fixtures");

    // The client's protected TX is `ClientHello` followed by the coalesced
    // second flight (`Certificate || CertificateVerify || Finished`) — byte
    // identical to the captured reference, which proves the engine parsed the
    // CertificateRequest and emitted a conformant, correctly-signed flight.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_flight = parse_hex(CLIENT_FLIGHT_HEX);
    let mut expected_tx = Vec::with_capacity(expected_ch.len() + expected_flight.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_flight);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "client mTLS second flight diverged from the captured reference",
    );
}
