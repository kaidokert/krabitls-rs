//! Drives `krabitls_nal_cli::connect` end-to-end through the seed-0 fixtures
//! over a mock [`TcpClientStack`], proving the NAL transport carries a full
//! handshake and byte-matches the Python reference — the same assertions as
//! `krabitls/tests/canned_handshake.rs`, only the transport differs.

// The seed-0 fixtures were captured under the default AES-128-GCM + Ed25519
// suite. `rsa` / `chacha20` / `ecdsa` each shift the ClientHello bytes (extra
// cipher suites or signature algorithms), so this byte-exact replay is gated to
// the plain default build — same as `krabitls/tests/canned_handshake.rs`.
#![cfg(not(any(feature = "rsa", feature = "chacha20", feature = "ecdsa")))]

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use embedded_nal::{TcpClientStack, TcpError, TcpErrorKind};
use krabitls::client::{ClientParams, DefaultScratch, RuntimeSuitePolicy};
use krabitls_fixtures::SeededRng;
use krabitls_nal_cli::connect;

mod common;
use common::parse_hex;

const CLIENT_HELLO: &str = include_str!("../../testdata/packets/001_c2s_ClientHello.hex");
const SERVER_HELLO: &str = include_str!("../../testdata/packets/002_s2c_ServerHello.hex");
const SERVER_FLIGHT: &str =
    include_str!("../../testdata/packets/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED: &str =
    include_str!("../../testdata/packets/004_c2s_ClientFinished_encrypted.hex");
const APP_SEND: &str = include_str!("../../testdata/packets/005_c2s_AppData_send_0.hex");
const APP_REPLY: &str = include_str!("../../testdata/packets/006_s2c_AppData_reply_0.hex");

const APP_SEND_PLAINTEXT: &[u8] = b"hello from the embedded client";
const APP_REPLY_PLAINTEXT: &[u8] = "hello back \u{2014} server here".as_bytes();

fn dummy_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)
}

// ---- mock TcpClientStack: a self-contained socket replaying one server tape ----

#[derive(Debug)]
struct MockError;
impl TcpError for MockError {
    fn kind(&self) -> TcpErrorKind {
        TcpErrorKind::Other
    }
}

struct MockSocket {
    rx: Vec<u8>,
    rx_pos: usize,
    tx: Vec<u8>,
}

impl MockSocket {
    /// Bytes the client wrote — the NAL analogue of `CannedTransport::captured_tx`.
    fn captured_tx(&self) -> &[u8] {
        &self.tx
    }
}

struct MockStack {
    server: Vec<u8>,
}

impl MockStack {
    fn new(server: Vec<u8>) -> Self {
        Self { server }
    }
}

impl TcpClientStack for MockStack {
    type TcpSocket = MockSocket;
    type Error = MockError;

    fn socket(&mut self) -> Result<MockSocket, MockError> {
        Ok(MockSocket {
            rx: self.server.clone(),
            rx_pos: 0,
            tx: Vec::new(),
        })
    }

    fn connect(&mut self, _s: &mut MockSocket, _remote: SocketAddr) -> nb::Result<(), MockError> {
        Ok(())
    }

    fn send(&mut self, s: &mut MockSocket, buf: &[u8]) -> nb::Result<usize, MockError> {
        s.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn receive(&mut self, s: &mut MockSocket, buf: &mut [u8]) -> nb::Result<usize, MockError> {
        let take = (s.rx.len() - s.rx_pos).min(buf.len());
        buf[..take].copy_from_slice(&s.rx[s.rx_pos..s.rx_pos + take]);
        s.rx_pos += take;
        Ok(take) // `Ok(0)` at EOF → krabitls maps to UnexpectedEof
    }

    fn close(&mut self, _s: MockSocket) -> Result<(), MockError> {
        Ok(())
    }
}

#[test]
fn nal_transport_completes_seed0_handshake() {
    let mut server = parse_hex(SERVER_HELLO);
    server.extend_from_slice(&parse_hex(SERVER_FLIGHT));

    let mut stack = MockStack::new(server);
    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = connect(&mut stack, dummy_addr(), &params, &mut scratch, &mut rng)
        .expect("handshake over the NAL transport");

    let mut expected = parse_hex(CLIENT_HELLO);
    expected.extend_from_slice(&parse_hex(CLIENT_FINISHED));
    assert_eq!(
        tls.transport().socket().captured_tx(),
        expected.as_slice(),
        "wire bytes over NAL must match the Python seed-0 reference",
    );
}

#[test]
fn nal_transport_round_trips_first_app_record() {
    let mut server = parse_hex(SERVER_HELLO);
    server.extend_from_slice(&parse_hex(SERVER_FLIGHT));
    server.extend_from_slice(&parse_hex(APP_REPLY));

    let mut stack = MockStack::new(server);
    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let mut tls = connect(&mut stack, dummy_addr(), &params, &mut scratch, &mut rng)
        .expect("handshake over the NAL transport");

    tls.write_all(APP_SEND_PLAINTEXT).expect("write app record");
    let mut buf = [0u8; 128];
    let n = tls.read(&mut buf).expect("read reply");
    assert_eq!(&buf[..n], APP_REPLY_PLAINTEXT, "decrypted reply plaintext");

    let mut expected = parse_hex(CLIENT_HELLO);
    expected.extend_from_slice(&parse_hex(CLIENT_FINISHED));
    expected.extend_from_slice(&parse_hex(APP_SEND));
    assert_eq!(
        tls.transport().socket().captured_tx(),
        expected.as_slice(),
        "encrypted app record over NAL must byte-match seed-0 packet 005",
    );
}
