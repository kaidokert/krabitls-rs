//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server). Drives a seed-0 AES-128-GCM client with an RSA-2048 client
//! certificate over a byte-recording transport and writes the
//! `testdata/packets_mtls_rsa/` replay fixtures for
//! `canned_handshake_mtls_rsa.rs`.
//!
//! Server — ed25519 self-signed leaf, mutual auth against a client CA that
//! signed the fixture's RSA leaf (`client_leaf.der`; private half in
//! `common/rsa_client_key.rs`):
//!
//! ```text
//! openssl req -x509 -newkey ed25519 -keyout server.key -out server.crt -days 36500 -nodes \
//!   -subj "/CN=mtls-fixture.local" -addext "subjectAltName=DNS:mtls-fixture.local"
//! openssl req -x509 -newkey ed25519 -keyout clientca.key -out clientca.crt -days 36500 -nodes \
//!   -subj "/CN=krabitls fixture client CA"
//! openssl req -new -key client_rsa.key -out client_rsa.csr -subj "/CN=krabitls-rsa-fixture-client"
//! openssl x509 -req -in client_rsa.csr -CA clientca.crt -CAkey clientca.key \
//!   -CAcreateserial -days 36500 -out client_rsa.crt
//! openssl x509 -in client_rsa.crt -outform DER -out client_leaf.der
//! openssl s_server -accept 14437 -tls1_3 -cert server.crt -key server.key \
//!   -Verify 1 -CAfile clientca.crt -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 -www -quiet
//! ```
//!
//! ```text
//! KB_PORT=14437 cargo test --features rsa --test gen_mtls_rsa_fixtures \
//!   -- --ignored --nocapture capture_mtls_rsa_fixtures
//! ```

#![cfg(all(
    feature = "cipher-aes",
    feature = "rsa",
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "mlkem")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, RsaClientAuth, RuntimeSuitePolicy, Transport,
};
use krabitls_fixtures::SeededRng;

mod common;
#[path = "common/rsa_client_key.rs"]
mod rsa_client_key;

use common::parse_hex;
use rsa_client_key::{CLIENT_D_HEX, CLIENT_E, CLIENT_N_HEX};

const CLIENT_LEAF_DER: &[u8] = include_bytes!("../../testdata/packets_mtls_rsa/client_leaf.der");

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
#[ignore = "capture harness: needs a local mutual-auth openssl s_server (see module docs)"]
fn capture_mtls_rsa_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14437".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to s_server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let n = parse_hex(CLIENT_N_HEX);
    let d = parse_hex(CLIENT_D_HEX);
    let signer = RsaClientAuth::from_components(&n, CLIENT_E, &d, CLIENT_LEAF_DER)
        .expect("fixture RSA components accepted");
    let params = ClientParams::self_signed("mtls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let tls = DefaultStream::connect(&params, &mut scratch, tee, &mut rng)
        .expect("seed-0 RSA mTLS handshake");

    let tee = tls.transport();
    let tx = records(&tee.tx);
    // openssl interleaves a legacy ChangeCipherSpec; the replay drops it.
    let rx: Vec<&[u8]> = records(&tee.rx)
        .into_iter()
        .filter(|r| r[0] != 0x14)
        .collect();

    const CT_HANDSHAKE: u8 = 0x16;
    const CT_APPLICATION_DATA: u8 = 0x17;
    assert_eq!(
        tx.len(),
        2,
        "expected [ClientHello, ClientSecondFlight]; got {}",
        tx.len()
    );
    assert_eq!(tx[0][0], CT_HANDSHAKE);
    assert_eq!(tx[1][0], CT_APPLICATION_DATA);
    assert!(
        rx.len() >= 2,
        "expected [ServerHello, flight..]; got {}",
        rx.len()
    );
    assert_eq!(rx[0][0], CT_HANDSHAKE);
    assert!(rx[1..].iter().all(|r| r[0] == CT_APPLICATION_DATA));

    let flight: Vec<u8> = rx[1..].concat();

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/packets_mtls_rsa");
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 AES-128-GCM RSA-mTLS {desc} ({} bytes), captured\n\
             # from a local openssl s_server -Verify handshake. Regenerate with the\n\
             # `#[ignore]`d `gen_mtls_rsa_fixtures` test; do not hand-edit.\n\
             {}\n",
            bytes.len(),
            to_hex(bytes),
        );
        std::fs::write(format!("{dir}/{name}"), body).expect("write hex");
    };
    write("001_c2s_ClientHello.hex", "ClientHello", tx[0]);
    write("002_s2c_ServerHello.hex", "ServerHello", rx[0]);
    write(
        "003_s2c_ServerFlight_encrypted.hex",
        "encrypted server flight (EE + CertificateRequest + Certificate + CertificateVerify + Finished)",
        &flight,
    );
    write(
        "004_c2s_ClientSecondFlight_encrypted.hex",
        "encrypted client second flight (Certificate + CertificateVerify + Finished)",
        tx[1],
    );
    eprintln!(
        "wrote 4 fixtures: ch={} sh={} server_flight={} client_flight={}",
        tx[0].len(),
        rx[0].len(),
        flight.len(),
        tx[1].len()
    );
}
