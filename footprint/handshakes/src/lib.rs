#![no_std]

//! Shared handshake-replay bodies for the footprint demos. Each `run_*()`
//! decrypts a captured TLS 1.3 server flight, verifies the cert chain and
//! CertificateVerify, and rebuilds the byte-exact client Finished. The
//! 16 KiB scratch (record + flight buffers) lives in `.bss` via
//! [`with_buffers`] so the demo crates' stack measurement isolates the
//! crypto + protocol cost.
//!
//! The handshake is driven through [`krabitls::TlsConnection`] entered at
//! `WaitServerFlight` via the `replay` feature — captured fixtures expose
//! pre-derived handshake-traffic secrets, so x25519 + the early HKDF chain
//! never reach `.text` and the historical M3 footprint numbers are
//! preserved.

use core::cell::RefCell;
use critical_section::Mutex;

#[cfg(feature = "chacha20")]
use krabitls::ChaCha20Poly1305Sha256;
use krabitls::newtype::Secret;
use krabitls::reassembler::ServerFlightReassembler;
use krabitls::{
    Aes128GcmSha256, DerCert, RustCrypto, ServerPubkey, TlsConnection, TranscriptHash,
    WaitServerFlight, ZeroBuf,
};

/// Per-record decrypt scratch. Sized to fit the largest TLS record body
/// the replay drives (RSA-2048 captured server flight runs ~6.3 KiB).
pub const RECORD_BUF_CAP: usize = 8 * 1024;

/// Flight-accumulator capacity (bytes). The reassembler owns this buffer
/// internally — sized to hold the largest reassembled server flight the
/// replays drive.
pub const FLIGHT_BUF_CAP: usize = 8 * 1024;

static RECORD_BUF: Mutex<RefCell<[u8; RECORD_BUF_CAP]>> =
    Mutex::new(RefCell::new([0u8; RECORD_BUF_CAP]));
static REASSEMBLER: Mutex<RefCell<ServerFlightReassembler<FLIGHT_BUF_CAP>>> =
    Mutex::new(RefCell::new(ServerFlightReassembler::new()));

/// Lend out the static scratch buffers under a critical section. The TLS
/// handshake runs entirely inside the closure; neither the per-record
/// plaintext buffer nor the reassembler's accumulator land on the stack.
/// The reassembler is `clear()`-ed before the closure runs so consecutive
/// `run_*` calls don't accidentally share state.
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

/// Walk `flight_enc` (back-to-back TLS records) and call `feed` with each
/// 5-byte-header-plus-body slice. The TLS record framing isn't typestate-
/// specific — the caller upstairs supplies its own driver/decryptor.
fn for_each_record<E>(
    flight_enc: &[u8],
    mut feed: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E>
where
    E: From<()>,
{
    let mut pos = 0;
    while pos < flight_enc.len() {
        if flight_enc.len() < pos + 5 {
            return Err(().into());
        }
        let body_len = u16::from_be_bytes([flight_enc[pos + 3], flight_enc[pos + 4]]) as usize;
        let end = pos + 5 + body_len;
        if flight_enc.len() < end {
            return Err(().into());
        }
        feed(&flight_enc[pos..end])?;
        pos = end;
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

/// AES-128-GCM-SHA256 + Ed25519 — replay a captured TLS 1.3 handshake from
/// a local openssl s_server.
pub fn run_aes_ed25519() -> Result<(), ()> {
    use fixture_aes_ed25519::*;
    with_buffers(|plaintext, reassembler| {
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&CH).map_err(|_| ())?;
        transcript.update_record(&SH).map_err(|_| ())?;

        let mut conn = <TlsConnection<
            WaitServerFlight<Aes128GcmSha256>,
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
            .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto>(reassembler)
            .map_err(|_| ())?;
        if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
            return Err(());
        }

        let mut cf_out = [0u8; 80];
        let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
        if record != &C_FINISHED[..] {
            return Err(());
        }
        Ok(())
    })
}

/// Baseline stub for `run_aes_ed25519` — touches every captured fixture so
/// rodata layout matches the real build; the `.text` delta isolates the
/// crypto + protocol code.
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
                WaitServerFlight<Aes128GcmSha256>,
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
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto>(reassembler)
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
                return Err(());
            }

            let mut cf_out = [0u8; 80];
            let record = conn.build_client_finished(&mut cf_out).map_err(|_| ())?;
            if record != &C_FINISHED[..] {
                return Err(());
            }
            Ok(())
        })
    }
}

/// AES-128-GCM-SHA256 + Ed25519 with the HKDF/SHA-256 backend swapped to
/// jedisct1's `hmac-sha256` crate. Same captured fixture as
/// [`run_aes_ed25519`].
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
                WaitServerFlight<ChaCha20Poly1305Sha256>,
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
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto>(reassembler)
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Ed25519(_, _)) {
                return Err(());
            }

            let mut cf_out = [0u8; 80];
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

/// ChaCha20-Poly1305-SHA256 + Ed25519. Replays a separate captured fixture
/// with the AEAD swapped from AES-128-GCM.
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
                WaitServerFlight<Aes128GcmSha256>,
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
                .finalize_server_flight::<FLIGHT_BUF_CAP, DerCert, RustCrypto>(reassembler)
                .map_err(|_| ())?;
            if !matches!(conn.server_pubkey(), ServerPubkey::Rsa { .. }) {
                return Err(());
            }

            let mut cf_out = [0u8; 80];
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
