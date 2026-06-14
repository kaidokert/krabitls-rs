//! Host integration test that drives `DefaultStream::connect` end-to-end
//! through the seed-0 fixtures — no real transport, no OS RNG.

// `rsa` and `chacha20` change the ClientHello wire bytes (extra sig_alg /
// extra cipher suite), diverging from the captured seed-0 transcript.
#![cfg(all(
    feature = "canned-replay",
    not(feature = "rsa"),
    not(feature = "chacha20")
))]

use krabitls::client::canned::{CannedTransport, SeededRng};
use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};

/// Parse the testdata `.hex` format (skips `#`-comments + whitespace).
fn parse_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut nibbles = [0u8; 2];
    let mut have = 0;
    let mut in_comment = false;
    for &b in s.as_bytes() {
        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            continue;
        }
        match b {
            b'#' => in_comment = true,
            b' ' | b'\t' | b'\r' | b'\n' => {}
            c => {
                let nib = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("bad hex char: {c:#x}"),
                };
                nibbles[have] = nib;
                have += 1;
                if have == 2 {
                    out.push((nibbles[0] << 4) | nibbles[1]);
                    have = 0;
                }
            }
        }
    }
    assert_eq!(have, 0, "dangling nibble in hex input");
    out
}

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets/004_c2s_ClientFinished_encrypted.hex");
const APP_DATA_SEND_HEX: &str = include_str!("../../testdata/packets/005_c2s_AppData_send_0.hex");
const APP_DATA_REPLY_HEX: &str = include_str!("../../testdata/packets/006_s2c_AppData_reply_0.hex");

/// First app-data plaintext the Python client sent at seed 0.
/// Matches `tls_fixture/demo.sh`: `cli.py --send "hello from the embedded client"`.
const APP_DATA_SEND_PLAINTEXT: &[u8] = b"hello from the embedded client";
/// First app-data plaintext the Python server replied with at seed 0.
const APP_DATA_REPLY_PLAINTEXT: &[u8] = "hello back \u{2014} server here".as_bytes();

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
