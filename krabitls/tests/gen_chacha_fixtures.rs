//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local
//! `openssl s_server`). Drives a seed-0 ChaCha20-Poly1305 krabitls client
//! against openssl over a byte-recording transport and writes the
//! `testdata/packets_chacha/` handshake replay fixtures
//! (`canned_handshake_chacha.rs` replays them with no network).
//!
//! Server — a self-signed Ed25519 leaf whose SAN matches the client hostname,
//! constrained to krabitls's ChaCha profile:
//!
//! ```text
//! openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 36500 -nodes \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! openssl s_server -accept 14434 -tls1_3 -cert server.crt -key server.key \
//!   -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519 -quiet
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
fn records(mut b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while b.len() >= 5 {
        let len = u16::from_be_bytes([b[3], b[4]]) as usize;
        let end = 5 + len;
        out.push(&b[..end]);
        b = &b[end..];
    }
    out
}

fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

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

    // Capture the handshake only; the app round-trip is exercised by the AES
    // facade test and ChaCha's AEAD is unit-tested separately.
    let tls =
        DefaultStream::connect(&params, &mut scratch, tee, &mut rng).expect("seed-0 handshake");

    let tee = tls.transport();
    let tx = records(&tee.tx);
    // Drop the server's middlebox-compat ChangeCipherSpec (type 0x14); krabitls
    // never hashes it, and the fixtures omit it.
    let rx: Vec<&[u8]> = records(&tee.rx)
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
    eprintln!("wrote 4 handshake fixtures to {dir}");
}
