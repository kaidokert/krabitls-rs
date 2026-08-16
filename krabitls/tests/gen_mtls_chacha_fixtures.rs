//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server). Drives a seed-0 ChaCha20-Poly1305 client with an Ed25519 client
//! certificate over a byte-recording transport and writes the
//! `testdata/packets_mtls_chacha/` replay fixtures for the footprint suite's
//! ChaCha-mTLS stack measurement.
//!
//! Like the Ed25519 mTLS fixture but the negotiated suite is
//! TLS_CHACHA20_POLY1305_SHA256 (build the client `--no-default-features
//! --features chacha20,cert-der,x25519-kx`). Ed25519 self-signed server leaf,
//! mutual auth against a client CA that signed the fixture's Ed25519 leaf
//! (`client_leaf.der`; seed below derives its key):
//!
//! ```text
//! openssl req -x509 -newkey ed25519 -keyout srv_ed.key -out srv_ed.crt -days 36500 -nodes \
//!   -subj "/CN=mtls-fixture.local" -addext "subjectAltName=DNS:mtls-fixture.local"
//! openssl req -x509 -newkey ed25519 -keyout clientca_ed.key -out clientca_ed.crt -days 36500 -nodes \
//!   -subj "/CN=krabitls fixture client CA"
//! openssl req -new -key client_ed.key -out client_ed.csr -subj "/CN=krabitls-ed25519-fixture-client"
//! openssl x509 -req -in client_ed.csr -CA clientca_ed.crt -CAkey clientca_ed.key \
//!   -CAcreateserial -days 36500 -out client_ed.crt
//! openssl x509 -in client_ed.crt -outform DER -out client_leaf.der
//! openssl s_server -accept 14440 -tls1_3 -cert srv_ed.crt -key srv_ed.key \
//!   -Verify 1 -CAfile clientca_ed.crt -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups X25519 -www -quiet
//! ```
//!
//! ```text
//! KB_PORT=14440 cargo test --no-default-features --features chacha20,cert-der,x25519-kx \
//!   --test gen_mtls_chacha_fixtures -- --ignored --nocapture capture_mtls_chacha_fixtures
//! ```

#![cfg(all(
    feature = "chacha20",
    not(feature = "cipher-aes"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem"),
    not(feature = "p256-kx"),
    not(feature = "blinding")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, Ed25519ClientAuth, RuntimeSuitePolicy, Transport,
};
use krabitls_fixtures::SeededRng;

const CLIENT_LEAF_DER: &[u8] = include_bytes!("../../testdata/packets_mtls_chacha/client_leaf.der");

/// Ed25519 seed for `client_leaf.der` — a test vector, derives its public key.
const CLIENT_SEED: [u8; 32] = [
    0xf2, 0x7f, 0x8c, 0xfc, 0xe9, 0x94, 0x5f, 0x91, 0x13, 0xab, 0xbb, 0xd4, 0x1a, 0x35, 0x94, 0x91,
    0xe6, 0x95, 0xaf, 0x92, 0x35, 0x65, 0xf8, 0xda, 0xc6, 0x25, 0xd1, 0xdd, 0x98, 0x80, 0x1b, 0xc9,
];

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
fn capture_mtls_chacha_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14440".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to s_server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let signer = Ed25519ClientAuth::from_seed(&CLIENT_SEED, CLIENT_LEAF_DER)
        .expect("seed derives the fixture client key");
    let params = ClientParams::self_signed("mtls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let tls = DefaultStream::connect(&params, &mut scratch, tee, &mut rng)
        .expect("seed-0 ChaCha mTLS handshake");

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

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/packets_mtls_chacha"
    );
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 ChaCha20-Poly1305 Ed25519-mTLS {desc} ({} bytes),\n\
             # captured from a local openssl s_server -Verify handshake. Regenerate\n\
             # with the `#[ignore]`d `gen_mtls_chacha_fixtures` test; do not hand-edit.\n\
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
        "wrote ChaCha-mTLS fixtures: ch={} sh={} server_flight={} client_flight={}",
        tx[0].len(),
        rx[0].len(),
        flight.len(),
        tx[1].len()
    );
}
