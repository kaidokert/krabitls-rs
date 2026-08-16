//! Byte-golden replay of the deep-chain handshake (captured by
//! `gen_chain_fixtures`). Runs in CI with no server: replays the canned server
//! flight through the real engine with a [`PinnedRoots`] strategy anchored on
//! the stored root (the server omits it), and asserts the handshake completes
//! and the client's transmitted bytes are byte-for-byte the captured ones —
//! proving both the chain walk and the fixtures stay correct.

#![cfg(all(
    feature = "cipher-aes",
    feature = "ecdsa",
    feature = "x25519-kx",
    feature = "chain-verify",
    feature = "cert-der",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "mlkem"),
    not(feature = "blinding")
))]

use krabitls::backends::{Anchor, DerCert, PinnedRoots};
use krabitls::client::{ClientParams, DefaultConfig, DefaultScratch, NoClock, TlsStream};
use krabitls_fixtures::{CannedTransport, SeededRng};

const ROOT_DER: &[u8] = include_bytes!("../../testdata/certs_chain/ca0.der");

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets_chain/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets_chain/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_chain/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets_chain/004_c2s_ClientFinished_encrypted.hex");

/// Decode a `#`-commented hex fixture into bytes.
fn load(hex_with_comments: &str) -> Vec<u8> {
    let hex: String = hex_with_comments
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn replays_deep_chain_handshake_against_stored_root() {
    let client_hello = load(CLIENT_HELLO_HEX);
    let server_hello = load(SERVER_HELLO_HEX);
    let server_flight = load(SERVER_FLIGHT_HEX);
    let client_finished = load(CLIENT_FINISHED_HEX);

    let mut server_stream = server_hello.clone();
    server_stream.extend_from_slice(&server_flight);

    let anchors = [Anchor::Cert(ROOT_DER)];
    let verify: PinnedRoots<DerCert, NoClock, 10> = PinnedRoots::new(&anchors);
    let params = ClientParams::with_strategy("chain.test", verify);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);

    let tls = TlsStream::<_, DefaultConfig, _, 16384, 16645, 4096, 10>::connect(
        &params,
        &mut scratch,
        transport,
        &mut rng,
    )
    .expect("deep-chain handshake anchored on the stored root replays");

    let mut expected_tx = client_hello.clone();
    expected_tx.extend_from_slice(&client_finished);
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "client transmitted bytes must match the captured fixture"
    );
}

#[test]
fn wrong_anchor_rejects_the_same_flight() {
    // Same replay, but a bogus anchor must fail — the chain is trusted only via
    // the pinned root, not because the links are internally consistent.
    let server_hello = load(SERVER_HELLO_HEX);
    let server_flight = load(SERVER_FLIGHT_HEX);
    let mut server_stream = server_hello;
    server_stream.extend_from_slice(&server_flight);

    let anchors = [Anchor::Fingerprint([0x11; 32])];
    let verify: PinnedRoots<DerCert, NoClock, 10> = PinnedRoots::new(&anchors);
    let params = ClientParams::with_strategy("chain.test", verify);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);

    let result = TlsStream::<_, DefaultConfig, _, 16384, 16645, 4096, 10>::connect(
        &params,
        &mut scratch,
        transport,
        &mut rng,
    );
    assert!(result.is_err(), "an unpinned chain must not connect");
}
