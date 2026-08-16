//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server). Drives a seed-0 AES-128-GCM client with an ECDSA P-256 client
//! certificate over secp256r1 (P-256) ECDHE against an ECDSA-P256 server, and
//! writes the `testdata/packets_mtls_p256_ecdsa/` replay fixtures for the
//! footprint suite's all-P-256 mTLS stack measurement (P-256 KEX + ECDSA server
//! cert + ECDSA client cert).
//!
//! Reuses the ECDSA client leaf + scalar from `packets_mtls_ecdsa`; the only
//! change from that capture is the server's `-groups` (P-256, not X25519).
//!
//! Server — ECDSA P-256 self-signed leaf (SAN=tls-fixture.local), mutual auth
//! against the client CA that signed `client_leaf.der`:
//!
//! ```text
//! openssl ecparam -genkey -name prime256v1 -noout -out ecsrv.key
//! openssl req -x509 -new -key ecsrv.key -out ecsrv.crt -days 36500 \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! openssl s_server -accept 14465 -tls1_3 -cert ecsrv.crt -key ecsrv.key \
//!   -Verify 1 -CAfile clientca.crt -ciphersuites TLS_AES_128_GCM_SHA256 \
//!   -groups P-256 -www -quiet
//! ```
//!
//! ```text
//! KB_PORT=14465 cargo test --features ecdsa,p256-kx,dev-utils --test gen_mtls_p256_ecdsa_fixtures \
//!   -- --ignored --nocapture capture_mtls_p256_ecdsa_fixtures
//! ```

#![cfg(all(
    feature = "cipher-aes",
    feature = "ecdsa",
    feature = "p256-kx",
    feature = "dev-utils",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "mlkem"),
    not(feature = "blinding")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, EcdsaClientAuth, RuntimeSuitePolicy, Transport,
};
use krabitls_fixtures::SeededRng;

const CLIENT_LEAF_DER: &[u8] =
    include_bytes!("../../testdata/packets_mtls_p256_ecdsa/client_leaf.der");
/// Big-endian P-256 client scalar for `client_leaf.der` — a test vector.
const CLIENT_SCALAR: [u8; 32] =
    krabitls::hex_decode("ec798c9d6ab974fe4b9d5e5e853e5003e2e2bcef642191c11b97b767964abfdd");

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
#[ignore = "capture harness: needs a local P-256 mutual-auth openssl s_server (see module docs)"]
fn capture_mtls_p256_ecdsa_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14465".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to s_server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let signer = EcdsaClientAuth::p256_from_scalar(&CLIENT_SCALAR, CLIENT_LEAF_DER)
        .expect("fixture P-256 scalar accepted");
    let params = ClientParams::self_signed("tls-fixture.local")
        .suite_policy(RuntimeSuitePolicy::Default)
        .with_client_auth(&signer);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let tls = DefaultStream::connect(&params, &mut scratch, tee, &mut rng)
        .expect("seed-0 P-256 ECDSA mTLS handshake");

    let tee = tls.transport();
    let tx = records(&tee.tx);
    let rx: Vec<&[u8]> = records(&tee.rx)
        .into_iter()
        .filter(|r| r[0] != 0x14) // drop the legacy ChangeCipherSpec
        .collect();

    const CT_HANDSHAKE: u8 = 0x16;
    const CT_APPLICATION_DATA: u8 = 0x17;
    assert_eq!(tx.len(), 2, "expected [ClientHello, SecondFlight]");
    assert_eq!(tx[0][0], CT_HANDSHAKE);
    assert_eq!(tx[1][0], CT_APPLICATION_DATA);
    assert!(rx.len() >= 2);
    assert_eq!(rx[0][0], CT_HANDSHAKE);
    assert!(rx[1..].iter().all(|r| r[0] == CT_APPLICATION_DATA));

    let flight: Vec<u8> = rx[1..].concat();
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/packets_mtls_p256_ecdsa"
    );
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 AES-128-GCM P-256-ECDHE ECDSA-P256-mTLS {desc} ({} bytes),\n\
             # captured from a local openssl s_server -Verify handshake. Regenerate\n\
             # with the `#[ignore]`d `gen_mtls_p256_ecdsa_fixtures` test; do not hand-edit.\n\
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
        "wrote P-256 ECDSA-mTLS fixtures: ch={} sh={} server_flight={} client_flight={}",
        tx[0].len(),
        rx[0].len(),
        flight.len(),
        tx[1].len()
    );
}
