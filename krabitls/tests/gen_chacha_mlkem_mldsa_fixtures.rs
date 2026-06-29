//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! echo server). Drives a seed-0 ChaCha20-Poly1305 krabitls client that advertises
//! ML-DSA signature algorithms against a server presenting an ML-DSA-44 leaf,
//! and writes the `testdata/packets_chacha_mlkem_mldsa/` replay fixtures
//! (`canned_handshake_mldsa.rs` replays them with no network).
//!
//! ML-DSA here is the server *certificate* signature (X25519MLKEM768 hybrid KEX);
//! the client verifies the self-signed ML-DSA cert + the ML-DSA
//! CertificateVerify. Full post-quantum: PQC key exchange and PQC certificate signature.
//!
//! Server — a self-signed ML-DSA-44 leaf whose SAN matches the client
//! hostname, plus a tiny fixed-reply TLS echo server (`num_tickets=0`):
//!
//! ```text
//! openssl req -x509 -newkey ML-DSA-44 -keyout server.key -out server.crt -days 36500 -nodes \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! ```
//!
//! ```python
//! import socket, ssl
//! ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
//! ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
//! ctx.num_tickets = 0
//! ctx.load_cert_chain("server.crt", "server.key")
//! srv = socket.create_server(("127.0.0.1", 14464))
//! while True:
//!     c, _ = srv.accept()
//!     t = ctx.wrap_socket(c, server_side=True)
//!     t.recv(4096); t.sendall(b"hello back from the test server"); t.close()
//! ```
//!
//! Client:
//!
//! ```text
//! KB_PORT=14464 cargo test --no-default-features --features chacha20,mlkem,mldsa \
//!   --test gen_chacha_mlkem_mldsa_fixtures -- --ignored --nocapture capture_chacha_mlkem_mldsa_fixtures
//! ```

#![cfg(all(
    feature = "chacha20",
    feature = "mlkem",
    feature = "mldsa",
    not(feature = "cipher-aes"),
    not(feature = "rsa")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy, Transport,
};
use krabitls_fixtures::SeededRng;

/// Records every byte read from / written to the socket so the exchange can be
/// split into TLS records afterward.
struct Tee {
    sock: TcpStream,
    rx: Vec<u8>,
    tx: Vec<u8>,
}

impl Transport for Tee {
    type Error = std::io::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = self.sock.read(buf)?;
        self.rx.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.sock.write_all(buf)?;
        self.tx.extend_from_slice(buf);
        Ok(())
    }
}

/// Split a TLS byte stream into records (`type(1) || version(2) || u16 len || body`).
fn records(mut b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while b.len() >= 5 {
        let len = u16::from_be_bytes([b[3], b[4]]) as usize;
        let Some((record, rest)) = 5usize.checked_add(len).and_then(|e| b.split_at_checked(e))
        else {
            break;
        };
        out.push(record);
        b = rest;
    }
    out
}

fn to_hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

const APP_SEND: &[u8] = b"krabitls roundtrip probe\n";
const APP_REPLY: &[u8] = b"hello back from the test server";

#[test]
#[ignore = "capture harness: needs a local TLS echo server (see module docs)"]
fn capture_chacha_mlkem_mldsa_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14464".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to echo server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let mut tls =
        DefaultStream::connect(&params, &mut scratch, tee, &mut rng).expect("seed-0 handshake");

    let tx_hs = tls.transport().tx.len();
    let rx_hs = tls.transport().rx.len();

    tls.write_all(APP_SEND).expect("write app data");
    let mut reply = [0u8; 128];
    let n = tls.read(&mut reply).expect("read reply");
    assert_eq!(
        &reply[..n],
        APP_REPLY,
        "unexpected echo payload; fixture 006 must stay deterministic",
    );

    let tee = tls.transport();
    let tx = records(&tee.tx[..tx_hs]);
    let app_send = records(&tee.tx[tx_hs..]);
    let app_reply = records(&tee.rx[rx_hs..]);
    let rx: Vec<&[u8]> = records(&tee.rx[..rx_hs])
        .into_iter()
        .filter(|r| r[0] != 0x14)
        .collect();

    eprintln!(
        "tx record types: {:?}",
        tx.iter().map(|r| r[0]).collect::<Vec<_>>()
    );
    eprintln!(
        "rx record types (CCS dropped): {:?}",
        rx.iter().map(|r| r[0]).collect::<Vec<_>>()
    );

    const CT_HANDSHAKE: u8 = 0x16;
    const CT_APPLICATION_DATA: u8 = 0x17;
    assert_eq!(
        tx.len(),
        2,
        "expected [ClientHello, Finished]; got {}",
        tx.len()
    );
    assert_eq!(
        tx[0][0], CT_HANDSHAKE,
        "TX[0] should be a plaintext ClientHello"
    );
    assert_eq!(
        tx[1][0], CT_APPLICATION_DATA,
        "TX[1] should be the encrypted Finished"
    );
    assert!(
        rx.len() >= 2,
        "expected [ServerHello, flight..]; got {}",
        rx.len()
    );
    assert_eq!(
        rx[0][0], CT_HANDSHAKE,
        "RX[0] should be a plaintext ServerHello"
    );
    assert!(
        rx[1..].iter().all(|r| r[0] == CT_APPLICATION_DATA),
        "flight records should all be encrypted (0x17)"
    );

    assert_eq!(app_send.len(), 1, "expected 1 client app record (005)");
    assert!(
        !app_reply.is_empty(),
        "expected a server reply record (006)"
    );
    assert_eq!(app_send[0][0], CT_APPLICATION_DATA);
    assert_eq!(
        app_reply[0][0], CT_APPLICATION_DATA,
        "006 should be app data"
    );

    let ch = tx[0];
    let cf = tx[1];
    let sh = rx[0];
    let flight: Vec<u8> = rx[1..].concat();

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/packets_chacha_mlkem_mldsa"
    );
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 X25519MLKEM768 + ChaCha20-Poly1305 + ML-DSA-44 {desc} ({} bytes),\n\
             # captured from a local fixed-reply TLS echo server. Regenerate with the\n\
             # `#[ignore]`d `capture_chacha_mlkem_mldsa_fixtures` test; do not hand-edit.\n\
             {}\n",
            bytes.len(),
            to_hex(bytes),
        );
        std::fs::write(format!("{dir}/{name}"), body).expect("write hex");
    };
    write("001_c2s_ClientHello.hex", "ClientHello", ch);
    write("002_s2c_ServerHello.hex", "ServerHello", sh);
    write(
        "003_s2c_ServerFlight_encrypted.hex",
        "encrypted server flight (EE..Finished)",
        &flight,
    );
    write(
        "004_c2s_ClientFinished_encrypted.hex",
        "client Finished",
        cf,
    );
    write(
        "005_c2s_AppData_send_0.hex",
        "first client app record",
        app_send[0],
    );
    write(
        "006_s2c_AppData_reply_0.hex",
        "first server app reply",
        app_reply[0],
    );
    eprintln!("wrote 6 fixtures to {dir}");
}
