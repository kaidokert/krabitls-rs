//! Host integration test: secp256r1 (P-256) ECDHE + AES-128-GCM + Ed25519
//! facade end-to-end through seed-0 fixtures captured from a P-256-only openssl
//! server (see `gen_p256_fixtures`). The only offline coverage that exercises
//! the real classical key exchange: the ephemeral `d·G` in the ClientHello
//! key_share, the `x(d·P)` shared secret against the server's secp256r1 share,
//! and the key schedule / transcript over the 65-byte P-256 key_share. Gated to
//! the exact feature set the fixtures were captured under (ed25519-only
//! sig_algs, AES-only) so the replayed transcript matches.

#![cfg(all(
    feature = "cipher-aes",
    feature = "p256-kx",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]

mod common;

use common::parse_hex;
use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};
use krabitls_fixtures::{CannedTransport, SeededRng};

const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets_p256/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_p256/003_s2c_ServerFlight_encrypted.hex");

#[test]
fn facade_completes_p256_ecdhe_handshake_against_canned_fixtures() {
    let mut server_stream = parse_hex(SERVER_HELLO_HEX);
    server_stream.extend_from_slice(&parse_hex(SERVER_FLIGHT_HEX));

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 P-256 ECDHE handshake against canned fixtures");
}
