//! One-shot regenerator for the Ed25519 mTLS client second flight
//! (`testdata/packets_mtls/004_...encrypted.hex`), consumed by
//! `canned_handshake_mtls.rs`. `#[ignore]`d — not a CI test.
//!
//! Unlike the RSA harness this needs no live server: the client flight is fully
//! determined by the already-captured server flight (002 + 003), so it replays
//! the canned fixture and records krabitls's own protected TX. Rerun after any
//! change to the Ed25519 `CertificateVerify` (e.g. the hedged `RandomizedSigner`
//! path), whose signature is byte-stable under the fixed seed 0.
//!
//! ```text
//! cargo test --test gen_mtls_fixtures -- --ignored --nocapture regenerate_client_flight
//! ```

#![cfg(all(
    feature = "cipher-aes",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem"),
    not(feature = "p256-kx"),
    not(feature = "blinding")
))]

use core::fmt::Write as _;

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

const CLIENT_LEAF_DER: &[u8] = include_bytes!("../../testdata/packets_mtls/client_leaf.der");

const CLIENT_SEED: [u8; 32] = [
    0xf2, 0x7f, 0x8c, 0xfc, 0xe9, 0x94, 0x5f, 0x91, 0x13, 0xab, 0xbb, 0xd4, 0x1a, 0x35, 0x94, 0x91,
    0xe6, 0x95, 0xaf, 0x92, 0x35, 0x65, 0xf8, 0xda, 0xc6, 0x25, 0xd1, 0xdd, 0x98, 0x80, 0x1b, 0xc9,
];

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

#[test]
#[ignore = "regenerates a committed fixture; run manually"]
fn regenerate_client_flight() {
    let mut server_stream = parse_hex(SERVER_HELLO_HEX);
    server_stream.extend_from_slice(&parse_hex(SERVER_FLIGHT_HEX));

    let signer = Ed25519ClientAuth::from_seed(&CLIENT_SEED, CLIENT_LEAF_DER)
        .expect("seed derives the fixture client key");
    let params = ClientParams::self_signed("mtls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("replayed mTLS handshake must complete");

    let ch = parse_hex(CLIENT_HELLO_HEX);
    let tx = tls.transport().captured_tx();
    assert_eq!(
        &tx[..ch.len()],
        ch.as_slice(),
        "emitted ClientHello diverged from 001 — regenerate that too",
    );
    let flight = &tx[ch.len()..];

    let body = format!(
        "# krabitls mTLS fixture (seed 0): encrypted client second flight\n\
         # (Certificate + CertificateVerify + Finished, {} bytes). Regenerate with\n\
         # the `#[ignore]`d `gen_mtls_fixtures` test; do not hand-edit.\n\
         {}\n",
        flight.len(),
        to_hex(flight),
    );
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/packets_mtls/004_c2s_ClientSecondFlight_encrypted.hex"
    );
    std::fs::write(path, body).expect("write 004 fixture");
    eprintln!("wrote client second flight: {} bytes", flight.len());
}
