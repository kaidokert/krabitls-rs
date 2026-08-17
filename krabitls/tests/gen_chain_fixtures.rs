//! One-time capture harness (NOT a CI test — `#[ignore]`d, needs a local TLS
//! server). Drives a seed-0 AES-128-GCM / X25519 krabitls client whose verify
//! strategy is [`PinnedRoots`] with a stored `Anchor::Cert` (the chain root,
//! NOT transmitted by the server) against an ECDSA-P256 server that presents a
//! deep intermediate chain, and writes `testdata/packets_chain/` replay
//! fixtures for the footprint suite's chain-validation stack measurement.
//!
//! This exercises the Tier-1.5 posture end-to-end through the real engine: the
//! server omits the root, and the client verifies the topmost transmitted
//! intermediate against the stored anchor cert parsed from flash.
//!
//! Server — the locally-minted ECDSA-P256 chain in `testdata/certs_chain`
//! (regenerate with the openssl recipe there), root omitted from `-cert_chain`:
//!
//! ```text
//! cat ca8.crt ca7.crt ca6.crt ca5.crt ca4.crt ca3.crt ca2.crt ca1.crt > inter.pem
//! openssl s_server -accept 14499 -tls1_3 -cert leaf.crt -key leaf.key \
//!   -cert_chain inter.pem -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 \
//!   -num_tickets 0 -www -quiet
//! ```
//!
//! ```text
//! KB_PORT=14499 cargo test --features ecdsa --test gen_chain_fixtures \
//!   -- --ignored --nocapture capture_chain_fixtures
//! ```

#![cfg(all(
    feature = "cipher-aes",
    feature = "ecdsa",
    feature = "x25519-kx",
    feature = "cert-der",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "mlkem"),
    not(feature = "blinding")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

use krabitls::backends::{Anchor, DerCert, PinnedRoots};
use krabitls::client::{
    ClientParams, DefaultConfig, DefaultScratch, NoClock, TlsStream, Transport,
};
use krabitls_fixtures::SeededRng;

/// The chain root — stored on the device, NOT transmitted by the server.
const ROOT_DER: &[u8] = include_bytes!("../../testdata/certs_chain/ca0.der");

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
#[ignore = "capture harness: needs a local deep-chain ECDSA s_server (see module docs)"]
fn capture_chain_fixtures() {
    let port = std::env::var("KB_PORT").unwrap_or_else(|_| "14499".into());
    let sock = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect to s_server");
    let tee = Tee {
        sock,
        rx: Vec::new(),
        tx: Vec::new(),
    };

    let anchors = [Anchor::Cert(ROOT_DER)];
    let verify: PinnedRoots<DerCert, NoClock, 10> = PinnedRoots::new(&anchors);
    let params = ClientParams::with_strategy("chain.test", verify);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    // MAX_CHAIN = 10 so the 9-cert transmitted chain (leaf + 8 intermediates) fits.
    let tls = TlsStream::<_, DefaultConfig, _, 16384, 16645, 4096, 10>::connect(
        &params,
        &mut scratch,
        tee,
        &mut rng,
    )
    .expect("seed-0 deep-chain handshake, anchored on the stored root");

    let tee = tls.transport();
    let tx = records(&tee.tx);
    let rx: Vec<&[u8]> = records(&tee.rx)
        .into_iter()
        .filter(|r| r[0] != 0x14) // drop the legacy ChangeCipherSpec
        .collect();

    const CT_HANDSHAKE: u8 = 0x16;
    const CT_APPLICATION_DATA: u8 = 0x17;
    assert_eq!(tx.len(), 2, "expected [ClientHello, encrypted Finished]");
    assert_eq!(tx[0][0], CT_HANDSHAKE);
    assert_eq!(tx[1][0], CT_APPLICATION_DATA);
    assert!(rx.len() >= 2);
    assert_eq!(rx[0][0], CT_HANDSHAKE);
    assert!(rx[1..].iter().all(|r| r[0] == CT_APPLICATION_DATA));

    let flight: Vec<u8> = rx[1..].concat();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/packets_chain");
    std::fs::create_dir_all(dir).expect("mkdir");
    let write = |name: &str, desc: &str, bytes: &[u8]| {
        let body = format!(
            "# krabitls seed-0 AES-128-GCM X25519 ECDSA-P256 deep-chain {desc} ({} bytes),\n\
             # captured against a local openssl s_server presenting leaf + 8 intermediates\n\
             # (root omitted), validated by PinnedRoots on the stored root. Regenerate with\n\
             # the `#[ignore]`d `gen_chain_fixtures` test; do not hand-edit.\n\
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
        "encrypted server flight (EE + Certificate[9] + CertificateVerify + Finished)",
        &flight,
    );
    write(
        "004_c2s_ClientFinished_encrypted.hex",
        "encrypted client Finished",
        tx[1],
    );
    eprintln!(
        "wrote deep-chain fixtures: ch={} sh={} server_flight={} client_finished={}",
        tx[0].len(),
        rx[0].len(),
        flight.len(),
        tx[1].len()
    );
}
