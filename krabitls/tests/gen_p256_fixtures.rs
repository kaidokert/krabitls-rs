//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server pinned to secp256r1). Drives a seed-0 P-256 ECDHE + AES-128-GCM
//! krabitls client over a byte-recording transport and writes the
//! `testdata/packets_p256/` replay fixtures (`canned_handshake_p256.rs` replays
//! them with no network).
//!
//! krabitls offers X25519 *and* secp256r1, so the server must be restricted to
//! P-256 to force the classical ECDHE path. Self-signed Ed25519 leaf whose SAN
//! matches the client hostname, no tickets (deterministic flight):
//!
//! ```text
//! openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 36500 -nodes \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! openssl s_server -accept 14437 -tls1_3 -groups P-256 -num_tickets 0 \
//!   -cert server.crt -key server.key -quiet -www
//! ```
//!
//! ```text
//! KB_PORT=14437 cargo test --no-default-features --features cipher-aes,p256-kx \
//!   --test gen_p256_fixtures -- --ignored --nocapture capture_p256_fixtures
//! ```

#![cfg(all(
    feature = "cipher-aes",
    feature = "p256-kx",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
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

#[test]
#[ignore = "capture harness: needs a local P-256-only TLS server (see module docs)"]
fn capture_p256_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14437".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to P-256 server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, tee, &mut rng)
        .expect("seed-0 P-256 ECDHE handshake");

    let tee = tls.transport();
    let tx = records(&tee.tx);
    // Drop the server's middlebox-compat ChangeCipherSpec (0x14); krabitls never
    // hashes it and the fixtures omit it.
    let rx: Vec<&[u8]> = records(&tee.rx)
        .into_iter()
        .filter(|r| r[0] != 0x14)
        .collect();

    eprintln!(
        "tx types: {:?}",
        tx.iter().map(|r| r[0]).collect::<Vec<_>>()
    );
    eprintln!(
        "rx types: {:?}",
        rx.iter().map(|r| r[0]).collect::<Vec<_>>()
    );

    // TX starts with the plaintext ClientHello (0x16); RX is the plaintext
    // ServerHello (0x16) then the encrypted flight (0x17…).
    assert_eq!(tx[0][0], 0x16, "first TX record must be the ClientHello");
    assert_eq!(rx[0][0], 0x16, "first RX record must be the ServerHello");
    assert!(rx.len() >= 2, "expected ServerHello + encrypted flight");

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/packets_p256");
    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(format!("{dir}/001_c2s_ClientHello.hex"), to_hex(tx[0])).unwrap();
    std::fs::write(format!("{dir}/002_s2c_ServerHello.hex"), to_hex(rx[0])).unwrap();
    let flight: Vec<u8> = rx[1..].iter().flat_map(|r| r.iter().copied()).collect();
    std::fs::write(
        format!("{dir}/003_s2c_ServerFlight_encrypted.hex"),
        to_hex(&flight),
    )
    .unwrap();
    eprintln!("wrote {} server flight records to {dir}", rx.len() - 1);
}
