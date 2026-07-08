//! Hermetic RSA mutual-TLS regression test: drives `DefaultStream::connect`
//! end-to-end through a seed-0 fixture whose server flight carries a
//! `CertificateRequest`, exercising the `WithClientAuth` path with an
//! [`RsaClientAuth`] signer (RSA-2048, `rsa_pss_rsae_sha256`
//! `CertificateVerify`) — no network, no OS RNG. The PSS salt comes from the
//! seeded connection entropy, so the client flight replays byte-exact.
//! Fixtures were captured once against a local `openssl s_server -tls1_3
//! -Verify` mutual-auth handshake (see `gen_mtls_rsa_fixtures.rs`).

// AES-128-GCM + ed25519 server leaf, `rsa` on (it shifts the ClientHello's
// signature_algorithms, so the capture requires it). `mldsa`/`mlkem`/
// `chacha20` shift the captured bytes further and are excluded like the
// sibling fixtures.
#![cfg(all(
    feature = "cipher-aes",
    feature = "rsa",
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "mlkem")
))]

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, RsaClientAuth, RuntimeSuitePolicy,
};
use krabitls_fixtures::{CannedTransport, SeededRng};

mod common;
#[path = "common/rsa_client_key.rs"]
mod rsa_client_key;

use common::parse_hex;
use rsa_client_key::{CLIENT_D_HEX, CLIENT_E, CLIENT_N_HEX};

const CLIENT_HELLO_HEX: &str =
    include_str!("../../testdata/packets_mtls_rsa/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str =
    include_str!("../../testdata/packets_mtls_rsa/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_mtls_rsa/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets_mtls_rsa/004_c2s_ClientSecondFlight_encrypted.hex");

/// The client's RSA-2048 leaf, sent in the client `Certificate`.
const CLIENT_LEAF_DER: &[u8] = include_bytes!("../../testdata/packets_mtls_rsa/client_leaf.der");

#[test]
fn facade_completes_rsa_mtls_handshake_against_canned_fixtures() {
    let mut server_stream = parse_hex(SERVER_HELLO_HEX);
    server_stream.extend_from_slice(&parse_hex(SERVER_FLIGHT_HEX));

    let n = parse_hex(CLIENT_N_HEX);
    let d = parse_hex(CLIENT_D_HEX);
    let signer = RsaClientAuth::from_components(&n, CLIENT_E, &d, CLIENT_LEAF_DER)
        .expect("fixture RSA components accepted");
    let params = ClientParams::self_signed("mtls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<2048>::new(&server_stream);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("facade must complete the seed-0 RSA mTLS handshake against canned fixtures");

    // Protected TX must be byte-identical to the capture: ClientHello plus
    // the coalesced `Certificate || CertificateVerify || Finished`. This
    // pins the whole path — CertificateRequest parse, sig_algs check, the
    // PSS signature (incl. the entropy-derived salt), and flight framing.
    let mut expected_tx = parse_hex(CLIENT_HELLO_HEX);
    expected_tx.extend_from_slice(&parse_hex(CLIENT_FLIGHT_HEX));
    assert_eq!(
        tls.transport().captured_tx(),
        expected_tx.as_slice(),
        "client RSA mTLS second flight diverged from the captured reference",
    );
}
