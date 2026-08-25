//! End-to-end coverage for the `VerifyStrategy` plumbing — exercises
//! the surface `canned_handshake.rs` doesn't cover, which only hits
//! the default `SafeStrategy<PinOrSelfSigned, DerCert>`:
//!
//! - [`ClientParams::with_strategy`] with a non-default `V`
//! - `HandshakeError::StrategyRejected` when the strategy returns `Err`
//! - `HandshakeError::StrategyPubkeyMismatch` when the strategy hands
//!   back a `PreparedVerifier` built from material outside the chain
//!
//! Hostname-mismatch isn't tested here: passing a different hostname
//! to `ClientParams` changes SNI in the emitted ClientHello, which
//! shifts the transcript and desyncs the AEAD before the cert reaches
//! the strategy. `identity.rs::tests` covers `verify_hostname` at the
//! unit level; that's the correct granularity for SAN logic.

// Gated to AES + Ed25519: the seed-0 canned handshake only matches a build
// whose ClientHello advertises ed25519 + AES alone. `rsa`, `chacha20`, and
// `mldsa` each change the signature_algorithms or cipher list. The default
// `NoClock` strategy skips cert validity; the `Clocked` path is unit-tested
// elsewhere.
#![cfg(all(
    feature = "cipher-aes",
    not(feature = "rsa"),
    not(feature = "chacha20"),
    not(feature = "mldsa"),
    not(feature = "ecdsa"),
    not(feature = "mlkem"),
    // Replays the X25519 seed-0 fixtures; p256-kx shifts the ClientHello.
    not(feature = "p256-kx")
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use krabitls::backends::RustCrypto;
use krabitls::client::{
    CertChainView, ClientParams, ConnectError, DefaultConfig, DefaultScratch, DefaultVerify,
    Ed25519, HandshakeError, PinOrSelfSigned, PreparedVerifier, SafeStrategy, SigVerifierProvider,
    TlsStream, Trusted, VerifierBackend, VerifyStrategy,
};
use krabitls_fixtures::{CannedTransport, SeededRng};

const CLIENT_HELLO_HEX: &str = include_str!("../../testdata/packets/001_c2s_ClientHello.hex");
const SERVER_HELLO_HEX: &str = include_str!("../../testdata/packets/002_s2c_ServerHello.hex");
const SERVER_FLIGHT_HEX: &str =
    include_str!("../../testdata/packets/003_s2c_ServerFlight_encrypted.hex");
const CLIENT_FINISHED_HEX: &str =
    include_str!("../../testdata/packets/004_c2s_ClientFinished_encrypted.hex");

fn parse_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut nibbles = [0u8; 2];
    let mut have = 0;
    let mut in_comment = false;
    for &b in s.as_bytes() {
        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            continue;
        }
        match b {
            b'#' => in_comment = true,
            b' ' | b'\t' | b'\r' | b'\n' => {}
            c => {
                let nib = match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("bad hex char: {c:#x}"),
                };
                nibbles[have] = nib;
                have += 1;
                if have == 2 {
                    out.push((nibbles[0] << 4) | nibbles[1]);
                    have = 0;
                }
            }
        }
    }
    assert_eq!(have, 0, "dangling nibble in hex input");
    out
}

fn server_stream() -> Vec<u8> {
    let sh = parse_hex(SERVER_HELLO_HEX);
    let sf = parse_hex(SERVER_FLIGHT_HEX);
    let mut out = Vec::with_capacity(sh.len() + sf.len());
    out.extend_from_slice(&sh);
    out.extend_from_slice(&sf);
    out
}

fn default_verify() -> DefaultVerify {
    SafeStrategy::new(PinOrSelfSigned::self_signed())
}

/// Wraps any inner strategy and bumps a shared counter on every
/// `verify_chain` call. Proves the V type-parameter and its slot
/// lifetime survive the plumbing through `TlsEngine` end-to-end.
struct CountingStrategy<S> {
    inner: S,
    count: Arc<AtomicUsize>,
}

impl<S, P> VerifyStrategy<P> for CountingStrategy<S>
where
    S: VerifyStrategy<P>,
    P: VerifierBackend,
{
    type Error = S::Error;

    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<P>>,
    ) -> Result<Trusted<'slot, P>, Self::Error> {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.inner.verify_chain(chain, slot)
    }
}

/// Stream type alias parameterized over our custom `V`. The default
/// `DefaultStream` pins V to `DefaultVerify`, so a non-default V needs
/// an explicit instantiation.
type CountingStream<'s, T> =
    TlsStream<'s, T, DefaultConfig, CountingStrategy<DefaultVerify>, 16384, 16645, 4096, 8>;

#[test]
fn connect_with_custom_strategy_observes_one_verify_call() {
    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let stream_bytes = server_stream();
    let transport = CannedTransport::<512>::new(&stream_bytes);

    let count = Arc::new(AtomicUsize::new(0));
    let strategy = CountingStrategy {
        inner: default_verify(),
        count: count.clone(),
    };
    let params: ClientParams<'_, CountingStrategy<DefaultVerify>> =
        ClientParams::with_strategy("tls-fixture.local", strategy);

    let tls = CountingStream::connect(&params, &mut scratch, transport, &mut rng)
        .expect("custom-V handshake against canned fixtures");

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "strategy.verify_chain must be invoked exactly once per handshake",
    );

    // Captured TX matches CH || CF — the wrapper added no observable
    // difference vs the default-V path.
    let expected_ch = parse_hex(CLIENT_HELLO_HEX);
    let expected_cf = parse_hex(CLIENT_FINISHED_HEX);
    let mut expected_tx = Vec::with_capacity(expected_ch.len() + expected_cf.len());
    expected_tx.extend_from_slice(&expected_ch);
    expected_tx.extend_from_slice(&expected_cf);
    assert_eq!(tls.transport().captured_tx(), expected_tx.as_slice());
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("AlwaysReject")]
struct AlwaysRejectError;

struct AlwaysReject;

impl<P: VerifierBackend> VerifyStrategy<P> for AlwaysReject {
    type Error = AlwaysRejectError;

    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        _chain: CertChainView<'chain, 'src>,
        _slot: &'slot mut Option<PreparedVerifier<P>>,
    ) -> Result<Trusted<'slot, P>, Self::Error> {
        Err(AlwaysRejectError)
    }
}

type AlwaysRejectStream<'s, T> =
    TlsStream<'s, T, DefaultConfig, AlwaysReject, 16384, 16645, 4096, 8>;

#[test]
fn strategy_rejected_propagates_to_handshake_error() {
    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let stream_bytes = server_stream();
    let transport = CannedTransport::<512>::new(&stream_bytes);

    let params: ClientParams<'_, AlwaysReject> =
        ClientParams::with_strategy("tls-fixture.local", AlwaysReject);

    let err = AlwaysRejectStream::connect(&params, &mut scratch, transport, &mut rng)
        .err()
        .expect("rejecting strategy must abort the handshake");

    match err {
        ConnectError::Handshake(HandshakeError::StrategyRejected) => {}
        other => panic!("expected StrategyRejected, got {other:?}"),
    }
}

/// Returns a `PreparedVerifier` built from `attacker_pubkey`, ignoring
/// the real `chain[0]`. The engine's stack-owned `matches_cert`
/// cross-check has to catch this — otherwise a malicious strategy
/// could swap the verifier under the protocol.
struct LyingStrategy {
    attacker_pubkey: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("LyingStrategy")]
struct LyingError;

impl VerifyStrategy<RustCrypto> for LyingStrategy {
    type Error = LyingError;

    fn verify_chain<'chain, 'src, 'slot>(
        &self,
        _chain: CertChainView<'chain, 'src>,
        slot: &'slot mut Option<PreparedVerifier<RustCrypto>>,
    ) -> Result<Trusted<'slot, RustCrypto>, Self::Error> {
        let prepared = PreparedVerifier::ed25519(
            <RustCrypto as SigVerifierProvider<Ed25519>>::prepare(&self.attacker_pubkey)
                .expect("Ed25519 prepare is infallible"),
        );
        *slot = Some(prepared);
        Ok(Trusted::new(slot.as_ref().expect("just wrote it")))
    }
}

type LyingStream<'s, T> = TlsStream<'s, T, DefaultConfig, LyingStrategy, 16384, 16645, 4096, 8>;

#[test]
fn strategy_pubkey_mismatch_blocks_lying_strategy() {
    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let stream_bytes = server_stream();
    let transport = CannedTransport::<512>::new(&stream_bytes);

    let strategy = LyingStrategy {
        attacker_pubkey: [0xAAu8; 32],
    };
    let params: ClientParams<'_, LyingStrategy> =
        ClientParams::with_strategy("tls-fixture.local", strategy);

    let err = LyingStream::connect(&params, &mut scratch, transport, &mut rng)
        .err()
        .expect("matches_cert cross-check must reject the lying verifier");

    match err {
        ConnectError::Handshake(HandshakeError::StrategyPubkeyMismatch) => {}
        other => panic!("expected StrategyPubkeyMismatch, got {other:?}"),
    }
}
