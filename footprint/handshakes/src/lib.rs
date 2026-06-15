#![no_std]

//! Handshake-replay bodies for the footprint demos. Each `run_*()` drives
//! the typestate entered at `WaitServerFlight` via the `replay` feature so
//! x25519 + the early HKDF chain stay out of `.text`. The 16 KiB scratch
//! lives in `.bss` via [`with_buffers`].

use core::cell::RefCell;
use critical_section::Mutex;

#[cfg(feature = "chacha20")]
use krabitls::ChaCha20Poly1305Sha256;
use krabitls::Secret;
use krabitls::ServerFlightReassembler;
use krabitls::{
    Aes128GcmSha256, CLIENT_FINISHED_LEN, DerCert, Replay, RustCrypto, ServerPubkey, TlsConnection,
    TranscriptHash, WaitServerFlight, ZeroBuf,
};

/// Per-record decrypt scratch (RSA-2048 captured flight runs ~6.3 KiB).
pub const RECORD_BUF_CAP: usize = 8 * 1024;
/// Reassembler capacity (bytes).
pub const FLIGHT_BUF_CAP: usize = 8 * 1024;

static RECORD_BUF: Mutex<RefCell<[u8; RECORD_BUF_CAP]>> =
    Mutex::new(RefCell::new([0u8; RECORD_BUF_CAP]));
static REASSEMBLER: Mutex<RefCell<ServerFlightReassembler<FLIGHT_BUF_CAP>>> =
    Mutex::new(RefCell::new(ServerFlightReassembler::new()));

/// Lend the static scratch + a cleared reassembler under a critical section.
pub fn with_buffers<R>(
    f: impl FnOnce(&mut [u8; RECORD_BUF_CAP], &mut ServerFlightReassembler<FLIGHT_BUF_CAP>) -> R,
) -> R {
    critical_section::with(|cs| {
        let mut record = RECORD_BUF.borrow(cs).borrow_mut();
        let mut reassembler = REASSEMBLER.borrow(cs).borrow_mut();
        reassembler.clear();
        f(&mut record, &mut reassembler)
    })
}

/// Walk back-to-back TLS records and call `feed` with each header+body slice.
fn for_each_record<E>(
    flight_enc: &[u8],
    mut feed: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<()>,
{
    let mut rest = flight_enc;
    while !rest.is_empty() {
        if rest.len() < 5 {
            return Err(().into());
        }
        let body_len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        let (record, tail) = rest.split_at_checked(5 + body_len).ok_or(().into())?;
        feed(record)?;
        rest = tail;
    }
    Ok(())
}

mod fixture_aes_ed25519 {
    pub const CH: [u8; 137] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/ch.hex"));
    pub const SH: [u8; 95] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/sh.hex"));
    pub const S_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/s_hs_ts.hex"));
    pub const C_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/c_hs_ts.hex"));
    pub const FLIGHT_ENC: [u8; 582] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/flight_enc.hex"));
    pub const C_FINISHED: [u8; 58] =
        krabitls::hex_decode(include_str!("../../captured/aes_ed25519/c_finished.hex"));
}

#[cfg(feature = "chacha20")]
mod fixture_chacha_ed25519 {
    pub const CH: [u8; 139] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/ch.hex"));
    pub const SH: [u8; 95] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/sh.hex"));
    pub const S_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/s_hs_ts.hex"));
    pub const C_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/c_hs_ts.hex"));
    pub const FLIGHT_ENC: [u8; 582] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/flight_enc.hex"));
    pub const C_FINISHED: [u8; 58] =
        krabitls::hex_decode(include_str!("../../captured/chacha_ed25519/c_finished.hex"));
}

#[cfg(feature = "rsa")]
mod fixture_aes_rsa2048 {
    pub const CH: [u8; 137] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/ch.hex"));
    pub const SH: [u8; 95] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/sh.hex"));
    pub const S_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/s_hs_ts.hex"));
    pub const C_HS_TS: [u8; 32] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/c_hs_ts.hex"));
    pub const FLIGHT_ENC: [u8; 1336] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/flight_enc.hex"));
    pub const C_FINISHED: [u8; 58] =
        krabitls::hex_decode(include_str!("../../captured/aes_rsa2048/c_finished.hex"));
}

/// AES-128-GCM-SHA256 + Ed25519, captured s_server fixture.
pub fn run_aes_ed25519() -> Result<(), ()> {
    use fixture_aes_ed25519::*;
    with_buffers(|plaintext, reassembler| {
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&CH).map_err(|_| ())?;
        transcript.update_record(&SH).map_err(|_| ())?;

        let mut conn = <TlsConnection<
            WaitServerFlight<Aes128GcmSha256, Replay>,
            RustCrypto,
            RustCrypto,
        >>::from_handshake_secrets(
            transcript,
            Secret::new(ZeroBuf::<32>::new(C_HS_TS)),
            Secret::new(ZeroBuf::<32>::new(S_HS_TS)),
        )
        .map_err(|_| ())?;

        for_each_record(&FLIGHT_ENC, |record| {
            conn.feed_server_record(record, reassembler, &mut plaintext[..])
                .map(|_| ())
                .map_err(|_| ())
        })?;

        let conn = conn
            .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto, RustCrypto>(
                reassembler,
                krabitls::VerifyMode::SelfSigned,
            )
            .map_err(|_| ())?;
        if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
            return Err(());
        }

        let mut cf_out = [0u8; CLIENT_FINISHED_LEN];
        let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
        if record != &C_FINISHED[..] {
            return Err(());
        }
        Ok(())
    })
}

/// Baseline stub: same rodata as the real build; .text delta = crypto cost.
#[inline(never)]
pub fn baseline_aes_ed25519() -> bool {
    use core::hint::black_box;
    use fixture_aes_ed25519::*;
    black_box(&CH);
    black_box(&SH);
    black_box(&S_HS_TS);
    black_box(&C_HS_TS);
    black_box(&FLIGHT_ENC);
    black_box(&C_FINISHED);
    true
}

// ----------------------------------------------------------------------------
// Facade — full handshake via `DefaultStream::connect` against the seed-0
// canned fixtures.
// ----------------------------------------------------------------------------

#[cfg(feature = "canned-replay")]
mod fixture_aes_ed25519_facade {
    pub const CLIENT_HELLO: [u8; 149] = krabitls::hex_decode(include_str!(
        "../../../testdata/packets/001_c2s_ClientHello.hex"
    ));
    pub const SERVER_HELLO: [u8; 95] = krabitls::hex_decode(include_str!(
        "../../../testdata/packets/002_s2c_ServerHello.hex"
    ));
    pub const SERVER_FLIGHT: [u8; 415] = krabitls::hex_decode(include_str!(
        "../../../testdata/packets/003_s2c_ServerFlight_encrypted.hex"
    ));
    pub const CLIENT_FINISHED: [u8; 58] = krabitls::hex_decode(include_str!(
        "../../../testdata/packets/004_c2s_ClientFinished_encrypted.hex"
    ));
}

/// Drive the full facade handshake against canned seed-0 fixtures.
///
/// Composes SH + SF into a `CannedTransport`, then calls
/// `DefaultStream::connect()` with `SeededRng::new(0)` and
/// `ClientParams::self_signed("tls-fixture.local")`. On return the captured
/// TX must equal CH || CF byte-for-byte; otherwise the handshake produced
/// different wire bytes than the Python reference and we return `Err(())`.
#[cfg(feature = "canned-replay")]
pub fn run_aes_ed25519_facade() -> Result<(), ()> {
    use fixture_aes_ed25519_facade::*;
    use krabitls::client::canned::{CannedTransport, SeededRng};
    use krabitls::client::{ClientParams, DefaultScratch, DefaultStream, RuntimeSuitePolicy};

    // SH (95) + SF (415) = 510 bytes of canned server stream.
    let mut server_stream = [0u8; SERVER_HELLO.len() + SERVER_FLIGHT.len()];
    server_stream[..SERVER_HELLO.len()].copy_from_slice(&SERVER_HELLO);
    server_stream[SERVER_HELLO.len()..].copy_from_slice(&SERVER_FLIGHT);

    let mut scratch = DefaultScratch::new();
    let mut rng = SeededRng::new(0);
    let transport = CannedTransport::<512>::new(&server_stream);
    let params =
        ClientParams::self_signed("tls-fixture.local").suite_policy(RuntimeSuitePolicy::Default);

    let tls = DefaultStream::connect(&params, &mut scratch, transport, &mut rng).map_err(|_| ())?;

    // Captured TX must be CH || CF.
    let captured = tls.transport().captured_tx();
    let expected_len = CLIENT_HELLO.len() + CLIENT_FINISHED.len();
    if captured.len() != expected_len {
        return Err(());
    }
    if captured[..CLIENT_HELLO.len()] != CLIENT_HELLO[..] {
        return Err(());
    }
    if captured[CLIENT_HELLO.len()..] != CLIENT_FINISHED[..] {
        return Err(());
    }
    Ok(())
}

/// Baseline stub: same rodata footprint as `run_aes_ed25519_facade`,
/// without driving any crypto. `.text` delta = full facade-driven
/// handshake cost.
#[cfg(feature = "canned-replay")]
#[inline(never)]
pub fn baseline_aes_ed25519_facade() -> bool {
    use core::hint::black_box;
    use fixture_aes_ed25519_facade::*;
    black_box(&CLIENT_HELLO);
    black_box(&SERVER_HELLO);
    black_box(&SERVER_FLIGHT);
    black_box(&CLIENT_FINISHED);
    true
}

#[cfg(feature = "jedisct")]
mod jedisct_path {
    use super::*;
    use fixture_aes_ed25519::*;
    use krabitls::JedisctCrypto;

    pub fn run() -> Result<(), ()> {
        with_buffers(|plaintext, reassembler| {
            let mut transcript = TranscriptHash::<JedisctCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let mut conn = <TlsConnection<
                WaitServerFlight<Aes128GcmSha256, Replay>,
                JedisctCrypto,
                RustCrypto,
            >>::from_handshake_secrets(
                transcript,
                Secret::new(ZeroBuf::<32>::new(C_HS_TS)),
                Secret::new(ZeroBuf::<32>::new(S_HS_TS)),
            )
            .map_err(|_| ())?;

            for_each_record(&FLIGHT_ENC, |record| {
                conn.feed_server_record(record, reassembler, &mut plaintext[..])
                    .map(|_| ())
                    .map_err(|_| ())
            })?;

            let conn = conn
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto, RustCrypto>(
                    reassembler,
                    krabitls::VerifyMode::SelfSigned,
                )
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
                return Err(());
            }

            let mut cf_out = [0u8; CLIENT_FINISHED_LEN];
            let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
            if record != &C_FINISHED[..] {
                return Err(());
            }
            Ok(())
        })
    }
}

/// AES + Ed25519, HKDF/SHA-256 via jedisct1's `hmac-sha256`.
#[cfg(feature = "jedisct")]
pub fn run_aes_ed25519_jedisct() -> Result<(), ()> {
    jedisct_path::run()
}

#[cfg(feature = "jedisct")]
#[inline(never)]
pub fn baseline_aes_ed25519_jedisct() -> bool {
    baseline_aes_ed25519()
}

#[cfg(feature = "chacha20")]
mod chacha_path {
    use super::*;
    use fixture_chacha_ed25519::*;

    pub fn run() -> Result<(), ()> {
        with_buffers(|plaintext, reassembler| {
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let mut conn = <TlsConnection<
                WaitServerFlight<ChaCha20Poly1305Sha256, Replay>,
                RustCrypto,
                RustCrypto,
            >>::from_handshake_secrets(
                transcript,
                Secret::new(ZeroBuf::<32>::new(C_HS_TS)),
                Secret::new(ZeroBuf::<32>::new(S_HS_TS)),
            )
            .map_err(|_| ())?;

            for_each_record(&FLIGHT_ENC, |record| {
                conn.feed_server_record(record, reassembler, &mut plaintext[..])
                    .map(|_| ())
                    .map_err(|_| ())
            })?;

            let conn = conn
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto, RustCrypto>(
                    reassembler,
                    krabitls::VerifyMode::SelfSigned,
                )
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
                return Err(());
            }

            let mut cf_out = [0u8; CLIENT_FINISHED_LEN];
            let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
            if record != &C_FINISHED[..] {
                return Err(());
            }
            Ok(())
        })
    }

    #[inline(never)]
    pub fn baseline() -> bool {
        use core::hint::black_box;
        black_box(&CH);
        black_box(&SH);
        black_box(&S_HS_TS);
        black_box(&C_HS_TS);
        black_box(&FLIGHT_ENC);
        black_box(&C_FINISHED);
        true
    }
}

/// ChaCha20-Poly1305-SHA256 + Ed25519.
#[cfg(feature = "chacha20")]
pub fn run_chacha_ed25519() -> Result<(), ()> {
    chacha_path::run()
}

#[cfg(feature = "chacha20")]
#[inline(never)]
pub fn baseline_chacha_ed25519() -> bool {
    chacha_path::baseline()
}

#[cfg(feature = "rsa")]
mod rsa_path {
    use super::*;
    use fixture_aes_rsa2048::*;

    pub fn run() -> Result<(), ()> {
        with_buffers(|plaintext, reassembler| {
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let mut conn = <TlsConnection<
                WaitServerFlight<Aes128GcmSha256, Replay>,
                RustCrypto,
                RustCrypto,
            >>::from_handshake_secrets(
                transcript,
                Secret::new(ZeroBuf::<32>::new(C_HS_TS)),
                Secret::new(ZeroBuf::<32>::new(S_HS_TS)),
            )
            .map_err(|_| ())?;

            for_each_record(&FLIGHT_ENC, |record| {
                conn.feed_server_record(record, reassembler, &mut plaintext[..])
                    .map(|_| ())
                    .map_err(|_| ())
            })?;

            let conn = conn
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto, RustCrypto>(
                    reassembler,
                    krabitls::VerifyMode::SelfSigned,
                )
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Rsa { .. }) {
                return Err(());
            }

            let mut cf_out = [0u8; CLIENT_FINISHED_LEN];
            let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
            if record != &C_FINISHED[..] {
                return Err(());
            }
            Ok(())
        })
    }

    #[inline(never)]
    pub fn baseline() -> bool {
        use core::hint::black_box;
        black_box(&CH);
        black_box(&SH);
        black_box(&S_HS_TS);
        black_box(&C_HS_TS);
        black_box(&FLIGHT_ENC);
        black_box(&C_FINISHED);
        true
    }
}

/// AES-128-GCM-SHA256 + RSA-2048-PSS cert verify.
#[cfg(feature = "rsa")]
pub fn run_aes_rsa2048() -> Result<(), ()> {
    rsa_path::run()
}

#[cfg(feature = "rsa")]
#[inline(never)]
pub fn baseline_aes_rsa2048() -> bool {
    rsa_path::baseline()
}
