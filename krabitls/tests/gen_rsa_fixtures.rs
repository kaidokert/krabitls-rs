//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server). Drives a seed-0 AES-128-GCM + RSA krabitls client over a
//! byte-recording transport and writes the `testdata/packets_rsa/` replay
//! fixtures (`canned_handshake.rs`'s RSA tests replay them with no network).
//!
//! Server — a self-signed RSA-2048 leaf (PKCS#1-v1.5 cert signature, which the
//! `rsa` cert parser verifies; RSA-PSS CertificateVerify) whose SAN matches the
//! client hostname, plus the same fixed-reply Python echo server as
//! `gen_chacha_fixtures` (`num_tickets=0`, load `rsa.crt`/`rsa.key`):
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -keyout rsa.key -out rsa.crt -days 36500 -nodes \
//!   -subj "/CN=tls-fixture.local" -addext "subjectAltName=DNS:tls-fixture.local"
//! ```
//!
//! ```text
//! KB_PORT=14436 cargo test --features rsa --test gen_rsa_fixtures \
//!   -- --ignored --nocapture capture_rsa_fixtures
//! ```
//!
//! After regenerating, update the `rsa_tests` crypto KAT in `src/tests.rs`: its
//! `FIXTURE_RSA_S_HS_TRAFFIC_SECRET_BYTES` is the new handshake's
//! `SERVER_HANDSHAKE_TRAFFIC_SECRET` (set `ctx.keylog_filename` on the echo
//! server, match the seed-0 client_random), and `FIXTURE_RSA_PACKET_3`'s length
//! is the new `003` byte size.

#![cfg(all(feature = "rsa", feature = "cipher-aes", not(feature = "chacha20")))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::client::{
    ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy, Transport,
};
use krabitls_fixtures::SeededRng;

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

#[test]
#[ignore = "capture harness: needs a local RSA echo server (see module docs)"]
fn capture_rsa_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14436".into());
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
        DefaultStream::connect(&params, &mut scratch, tee, &mut rng).expect("seed-0 RSA handshake");

    let tx_hs = tls.transport().tx.len();
    let rx_hs = tls.transport().rx.len();

    tls.write_all(APP_SEND).expect("write app data");
    let mut reply = [0u8; 128];
    let n = tls.read(&mut reply).expect("read reply");
    eprintln!("app reply ({n} B): {:?}", core::str::from_utf8(&reply[..n]));

    let tee = tls.transport();
    let tx = records(&tee.tx[..tx_hs]);
    let app_send = records(&tee.tx[tx_hs..]);
    let app_reply = records(&tee.rx[rx_hs..]);
    let rx: Vec<&[u8]> = records(&tee.rx[..rx_hs])
        .into_iter()
        .filter(|r| r[0] != 0x14)
        .collect();

    eprintln!(
        "tx {:?} / rx (CCS dropped) {:?}",
        tx.iter().map(|r| r[0]).collect::<Vec<_>>(),
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
    assert_eq!(tx[0][0], CT_HANDSHAKE);
    assert_eq!(tx[1][0], CT_APPLICATION_DATA);
    assert!(
        rx.len() >= 2,
        "expected [ServerHello, flight..]; got {}",
        rx.len()
    );
    assert_eq!(rx[0][0], CT_HANDSHAKE);
    assert!(rx[1..].iter().all(|r| r[0] == CT_APPLICATION_DATA));
    assert_eq!(app_send.len(), 1, "expected 1 client app record (005)");
    assert!(
        !app_reply.is_empty(),
        "expected a server reply record (006)"
    );
    assert_eq!(app_reply[0][0], CT_APPLICATION_DATA);

    let ch = tx[0];
    let cf = tx[1];
    let sh = rx[0];
    let flight: Vec<u8> = rx[1..].concat();

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/packets_rsa");
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 AES-128-GCM + RSA {desc} ({} bytes), captured from a\n\
             # local TLS echo server. Regenerate with the `#[ignore]`d\n\
             # `gen_rsa_fixtures` test; do not hand-edit.\n\
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
