//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local
//! `openssl s_server`). Drives a seed-0 ChaCha20-Poly1305 krabitls client
//! against openssl over a byte-recording transport and writes the
//! `testdata/packets_chacha/` handshake replay fixtures
//! (`canned_handshake_chacha.rs` replays them with no network).
//!
//! Server — a self-signed Ed25519 leaf whose SAN matches the client hostname,
//! plus a tiny fixed-reply TLS echo server (so the captured app round-trip is
//! deterministic; `num_tickets=0` keeps the flight ticket-free):
//!
//! ```text
//! openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 36500 -nodes \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! ```
//!
//! ```python
//! import socket, ssl, sys
//! ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
//! ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
//! ctx.num_tickets = 0
//! ctx.load_cert_chain("server.crt", "server.key")
//! srv = socket.create_server(("127.0.0.1", 14435))
//! while True:
//!     c, _ = srv.accept()
//!     t = ctx.wrap_socket(c, server_side=True)
//!     t.recv(4096); t.sendall(b"hello back from the test server"); t.close()
//! ```
//!
//! Client:
//!
//! ```text
//! KB_PORT=14434 cargo test --no-default-features --features chacha20 \
//!   --test gen_chacha_fixtures -- --ignored --nocapture capture_chacha_fixtures
//! ```
//!
//! The exchange is deterministic (seeded RNG), so the client ClientHello /
//! Finished are byte-exact and the replay test can assert the captured TX.

#![cfg(all(
    feature = "chacha20",
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
/// Stops at the first truncated/overrunning record rather than panicking.
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

#[test]
#[ignore = "capture harness: needs a local openssl s_server (see module docs)"]
fn capture_chacha_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14434".into());
    let sock =
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to openssl s_server");
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

    // Boundary between the handshake bytes and the app round-trip: everything
    // recorded after this is the first app record pair.
    let tx_hs = tls.transport().tx.len();
    let rx_hs = tls.transport().rx.len();

    // The echo server returns a fixed reply, giving a deterministic 006.
    tls.write_all(APP_SEND).expect("write app data");
    let mut reply = [0u8; 128];
    let n = tls.read(&mut reply).expect("read reply");
    eprintln!("app reply ({n} B): {:?}", core::str::from_utf8(&reply[..n]));

    let tee = tls.transport();
    let tx = records(&tee.tx[..tx_hs]);
    let app_send = records(&tee.tx[tx_hs..]);
    let app_reply = records(&tee.rx[rx_hs..]);
    // Drop the server's middlebox-compat ChangeCipherSpec (type 0x14); krabitls
    // never hashes it, and the fixtures omit it.
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

    // Fail loudly if openssl's record layout drifts from what the replay test
    // expects. TX is the plaintext ClientHello (0x16) then the encrypted
    // Finished (0x17); RX is the plaintext ServerHello (0x16) then the
    // encrypted flight records (0x17). `content_type` here is the *outer*
    // record type, so the protected handshake records read as 0x17.
    const CT_HANDSHAKE: u8 = 0x16;
    const CT_APPLICATION_DATA: u8 = 0x17;
    assert_eq!(
        tx.len(),
        2,
        "expected [ClientHello, Finished]; got {} TX records",
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
        "expected [ServerHello, flight..]; got {} RX records",
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

    // One client app record out; the reply is the first record back (a
    // trailing close_notify alert may share the segment — ignore it).
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

    // TX: [ClientHello] [ClientFinished].   RX: [ServerHello] [ServerFlight...]
    let ch = tx[0];
    let cf = tx[1];
    let sh = rx[0];
    let flight: Vec<u8> = rx[1..].concat();

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/packets_chacha");
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 ChaCha20-Poly1305 {desc} ({} bytes), captured from a\n\
             # local `openssl s_server` handshake. Regenerate with the `#[ignore]`d\n\
             # `gen_chacha_fixtures` test; do not hand-edit.\n\
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
