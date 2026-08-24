//! Proves `ClientConfig::Aes` drives an externally supplied `aead 0.6`
//! implementation through a complete TLS handshake and application record.

#![cfg(all(
    feature = "cipher-aes",
    not(feature = "chacha20"),
    not(feature = "rsa"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem")
))]

use core::sync::atomic::{AtomicUsize, Ordering};

use aead::array::Array;
use aead::consts::{U12, U16};
use aead::inout::InOutBuf;
use aead::{AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce, Tag, TagPosition};
use krabitls::backends::{DerCert, RustCrypto};
use krabitls::client::{
    ClientConfig, ClientParams, ConfigSuitePolicy, DefaultScratch, DefaultVerify, TlsStream,
};
#[cfg(feature = "dtls")]
use krabitls::dtls::{DatagramTransport, DtlsStream};
use krabitls_fixtures::{CannedTransport, SeededRng};

mod common;
use common::parse_hex;

const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets/001_c2s_ClientHello.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets/004_c2s_ClientFinished_encrypted.hex");

static CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);
static ENCRYPTIONS: AtomicUsize = AtomicUsize::new(0);
static DECRYPTIONS: AtomicUsize = AtomicUsize::new(0);

/// Distinct external AEAD type. It delegates cryptography to RustCrypto so the
/// host fixture remains authoritative, while counters prove KrabiTLS selected
/// this type rather than its bundled default.
struct InstrumentedAes(aes_gcm::Aes128Gcm);

impl KeySizeUser for InstrumentedAes {
    type KeySize = U16;
}

impl KeyInit for InstrumentedAes {
    fn new(key: &Key<Self>) -> Self {
        CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
        Self(aes_gcm::Aes128Gcm::new(&Array::from(<[u8; 16]>::from(
            *key,
        ))))
    }
}

impl AeadCore for InstrumentedAes {
    type NonceSize = U12;
    type TagSize = U16;
    const TAG_POSITION: TagPosition = TagPosition::Postfix;
}

impl AeadInOut for InstrumentedAes {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> Result<Tag<Self>, aead::Error> {
        ENCRYPTIONS.fetch_add(1, Ordering::SeqCst);
        self.0.encrypt_inout_detached(
            &Nonce::<aes_gcm::Aes128Gcm>::from(<[u8; 12]>::from(*nonce)),
            associated_data,
            buffer,
        )
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
        tag: &Tag<Self>,
    ) -> Result<(), aead::Error> {
        DECRYPTIONS.fetch_add(1, Ordering::SeqCst);
        self.0.decrypt_inout_detached(
            &Nonce::<aes_gcm::Aes128Gcm>::from(<[u8; 12]>::from(*nonce)),
            associated_data,
            buffer,
            &Tag::<aes_gcm::Aes128Gcm>::from(<[u8; 16]>::from(*tag)),
        )
    }
}

struct HardwareConfig;

impl ClientConfig for HardwareConfig {
    type Hkdf = RustCrypto;
    type CertParser = DerCert;
    type Ed25519 = RustCrypto;
    type Rsa = RustCrypto;
    type P256 = RustCrypto;
    type Aes = InstrumentedAes;
    const SUITES: ConfigSuitePolicy = ConfigSuitePolicy::AesOnly;
}

type HardwareStream<'s, T> = TlsStream<'s, T, HardwareConfig, DefaultVerify, 16384, 16645, 4096, 8>;

#[cfg(feature = "dtls")]
struct NullDatagram;

#[cfg(feature = "dtls")]
impl DatagramTransport for NullDatagram {
    type Error = core::convert::Infallible;

    fn send(&mut self, _datagram: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(None)
    }
}

#[test]
#[cfg(feature = "dtls")]
fn custom_aead_is_accepted_by_dtls_facade() {
    let stream: Option<DtlsStream<NullDatagram, InstrumentedAes>> = None;
    assert!(stream.is_none());
}

#[test]
fn custom_aead_runs_complete_canned_handshake() {
    CONSTRUCTIONS.store(0, Ordering::SeqCst);
    ENCRYPTIONS.store(0, Ordering::SeqCst);
    DECRYPTIONS.store(0, Ordering::SeqCst);

    let server_hello = parse_hex(SERVER_HELLO_HEX);
    let server_flight = parse_hex(SERVER_FLIGHT_HEX);
    let mut server_stream = Vec::with_capacity(server_hello.len() + server_flight.len());
    server_stream.extend_from_slice(&server_hello);
    server_stream.extend_from_slice(&server_flight);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);
    let params = ClientParams::self_signed("tls-fixture.local");

    let tls = HardwareStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("custom AES backend must complete the canned handshake");

    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = Vec::with_capacity(expected_ch.len() + expected_cf.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(tls.transport().captured_tx(), expected_tx);

    assert!(CONSTRUCTIONS.load(Ordering::SeqCst) >= 2);
    assert!(DECRYPTIONS.load(Ordering::SeqCst) >= 1);
    assert!(ENCRYPTIONS.load(Ordering::SeqCst) >= 1);
}
