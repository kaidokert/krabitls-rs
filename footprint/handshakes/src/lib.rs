#![no_std]

//! Shared handshake-replay bodies for the footprint demos. Each `run_*()`
//! decrypts a captured TLS 1.3 server flight, verifies the cert chain and
//! CertificateVerify, and rebuilds the byte-exact client Finished. The
//! 16 KiB scratch (record + flight buffers) lives in `.bss` via
//! [`with_buffers`] so the demo crates' stack measurement isolates the
//! crypto + protocol cost.

use core::cell::RefCell;
use critical_section::Mutex;

#[cfg(feature = "chacha20")]
use krabitls::ChaCha20Poly1305Sha256;
use krabitls::newtype::Secret;
use krabitls::{
    Aes128GcmSha256, CLIENT_FINISHED_LEN, CertParser, CertView, DerCert, RecordKeys, RustCrypto,
    TranscriptHash, ZeroBuf, extract_cert_der, parse_server_flight, split_inner_plaintext,
    verify_certificate_verify, verify_server_finished,
};

/// Per-record decrypt scratch. Sized to fit the largest TLS record body
/// the replay drives (RSA-2048 captured server flight runs ~6.3 KiB).
pub const RECORD_BUF_CAP: usize = 8 * 1024;

/// Flight-accumulator scratch.
pub const FLIGHT_BUF_CAP: usize = 8 * 1024;

static RECORD_BUF: Mutex<RefCell<[u8; RECORD_BUF_CAP]>> =
    Mutex::new(RefCell::new([0u8; RECORD_BUF_CAP]));
static FLIGHT_BUF: Mutex<RefCell<[u8; FLIGHT_BUF_CAP]>> =
    Mutex::new(RefCell::new([0u8; FLIGHT_BUF_CAP]));

/// Lend out the static scratch buffers under a critical section. The TLS
/// handshake runs entirely inside the closure; the buffers never land on
/// the stack.
pub fn with_buffers<R>(
    f: impl FnOnce(&mut [u8; RECORD_BUF_CAP], &mut [u8; FLIGHT_BUF_CAP]) -> R,
) -> R {
    critical_section::with(|cs| {
        let mut record = RECORD_BUF.borrow(cs).borrow_mut();
        let mut flight = FLIGHT_BUF.borrow(cs).borrow_mut();
        f(&mut record, &mut flight)
    })
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
    with_buffers(|plaintext, flight| {
        let mut transcript = TranscriptHash::<RustCrypto>::new();
        transcript.update_record(&CH).map_err(|_| ())?;
        transcript.update_record(&SH).map_err(|_| ())?;

        let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
        let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
        let s_hs_keys =
            RecordKeys::<Aes128GcmSha256>::derive::<RustCrypto>(&s_hs_ts).map_err(|_| ())?;

        let mut flight_len = 0usize;
        let mut pos = 0usize;
        let mut seq: u64 = 0;
        while pos < FLIGHT_ENC.len() {
            if FLIGHT_ENC.len() < pos + 5 {
                return Err(());
            }
            let body_len = u16::from_be_bytes([FLIGHT_ENC[pos + 3], FLIGHT_ENC[pos + 4]]) as usize;
            let end = pos + 5 + body_len;
            if FLIGHT_ENC.len() < end {
                return Err(());
            }
            let record = &FLIGHT_ENC[pos..end];

            let pt_slice = s_hs_keys
                .decrypt_record::<RustCrypto>(record, seq, plaintext)
                .map_err(|_| ())?;
            let (content, _ct) = split_inner_plaintext(pt_slice).map_err(|_| ())?;

            if flight_len + content.len() > flight.len() {
                return Err(());
            }
            flight[flight_len..flight_len + content.len()].copy_from_slice(content);
            flight_len += content.len();

            pos = end;
            seq += 1;
        }

        let parsed = parse_server_flight(&flight[..flight_len]).map_err(|_| ())?;
        let cert_der = extract_cert_der(parsed.cert_body).map_err(|_| ())?;
        let view = <DerCert as CertParser>::parse(cert_der).map_err(|_| ())?;
        if !matches!(view, CertView::Ed25519 { .. }) {
            return Err(());
        }

        transcript.update(parsed.ee_full);
        transcript.update(parsed.cert_full);
        let th_after_cert = transcript.snapshot();
        verify_certificate_verify::<RustCrypto>(&view, &th_after_cert, parsed.cv_body)
            .map_err(|_| ())?;

        transcript.update(parsed.cv_full);
        let th_after_cv = transcript.snapshot();
        verify_server_finished::<RustCrypto>(&s_hs_ts, &th_after_cv, parsed.fin_body)
            .map_err(|_| ())?;

        transcript.update(parsed.fin_full);
        let th_through_finished = transcript.snapshot();

        let mut cf_out = [0u8; 80];
        let record =
            RecordKeys::<Aes128GcmSha256>::build_client_finished::<RustCrypto, RustCrypto>(
                &c_hs_ts,
                &th_through_finished,
                0,
                &mut cf_out,
            )
            .map_err(|_| ())?;
        if record.len() != CLIENT_FINISHED_LEN || record != &C_FINISHED[..] {
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
        with_buffers(|plaintext, flight| {
            let mut transcript = TranscriptHash::<JedisctCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
            let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
            let s_hs_keys =
                RecordKeys::<Aes128GcmSha256>::derive::<JedisctCrypto>(&s_hs_ts).map_err(|_| ())?;

            let mut flight_len = 0usize;
            let mut pos = 0usize;
            let mut seq: u64 = 0;
            while pos < FLIGHT_ENC.len() {
                if FLIGHT_ENC.len() < pos + 5 {
                    return Err(());
                }
                let body_len =
                    u16::from_be_bytes([FLIGHT_ENC[pos + 3], FLIGHT_ENC[pos + 4]]) as usize;
                let end = pos + 5 + body_len;
                if FLIGHT_ENC.len() < end {
                    return Err(());
                }
                let record = &FLIGHT_ENC[pos..end];

                let pt_slice = s_hs_keys
                    .decrypt_record::<RustCrypto>(record, seq, plaintext)
                    .map_err(|_| ())?;
                let (content, _ct) = split_inner_plaintext(pt_slice).map_err(|_| ())?;

                if flight_len + content.len() > flight.len() {
                    return Err(());
                }
                flight[flight_len..flight_len + content.len()].copy_from_slice(content);
                flight_len += content.len();

                pos = end;
                seq += 1;
            }

            let parsed = parse_server_flight(&flight[..flight_len]).map_err(|_| ())?;
            let cert_der = extract_cert_der(parsed.cert_body).map_err(|_| ())?;
            let view = <DerCert as CertParser>::parse(cert_der).map_err(|_| ())?;
            if !matches!(view, CertView::Ed25519 { .. }) {
                return Err(());
            }

            transcript.update(parsed.ee_full);
            transcript.update(parsed.cert_full);
            let th_after_cert = transcript.snapshot();
            verify_certificate_verify::<RustCrypto>(&view, &th_after_cert, parsed.cv_body)
                .map_err(|_| ())?;

            transcript.update(parsed.cv_full);
            let th_after_cv = transcript.snapshot();
            verify_server_finished::<JedisctCrypto>(&s_hs_ts, &th_after_cv, parsed.fin_body)
                .map_err(|_| ())?;

            transcript.update(parsed.fin_full);
            let th_through_finished = transcript.snapshot();

            let mut cf_out = [0u8; 80];
            let record = RecordKeys::<Aes128GcmSha256>::build_client_finished::<
                JedisctCrypto,
                RustCrypto,
            >(&c_hs_ts, &th_through_finished, 0, &mut cf_out)
            .map_err(|_| ())?;
            if record.len() != CLIENT_FINISHED_LEN || record != &C_FINISHED[..] {
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
        with_buffers(|plaintext, flight| {
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
            let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
            let s_hs_keys = RecordKeys::<ChaCha20Poly1305Sha256>::derive::<RustCrypto>(&s_hs_ts)
                .map_err(|_| ())?;

            let mut flight_len = 0usize;
            let mut pos = 0usize;
            let mut seq: u64 = 0;
            while pos < FLIGHT_ENC.len() {
                if FLIGHT_ENC.len() < pos + 5 {
                    return Err(());
                }
                let body_len =
                    u16::from_be_bytes([FLIGHT_ENC[pos + 3], FLIGHT_ENC[pos + 4]]) as usize;
                let end = pos + 5 + body_len;
                if FLIGHT_ENC.len() < end {
                    return Err(());
                }
                let record = &FLIGHT_ENC[pos..end];

                let pt_slice = s_hs_keys
                    .decrypt_record::<RustCrypto>(record, seq, plaintext)
                    .map_err(|_| ())?;
                let (content, _ct) = split_inner_plaintext(pt_slice).map_err(|_| ())?;

                if flight_len + content.len() > flight.len() {
                    return Err(());
                }
                flight[flight_len..flight_len + content.len()].copy_from_slice(content);
                flight_len += content.len();

                pos = end;
                seq += 1;
            }

            let parsed = parse_server_flight(&flight[..flight_len]).map_err(|_| ())?;
            let cert_der = extract_cert_der(parsed.cert_body).map_err(|_| ())?;
            let view = <DerCert as CertParser>::parse(cert_der).map_err(|_| ())?;
            if !matches!(view, CertView::Ed25519 { .. }) {
                return Err(());
            }

            transcript.update(parsed.ee_full);
            transcript.update(parsed.cert_full);
            let th_after_cert = transcript.snapshot();
            verify_certificate_verify::<RustCrypto>(&view, &th_after_cert, parsed.cv_body)
                .map_err(|_| ())?;

            transcript.update(parsed.cv_full);
            let th_after_cv = transcript.snapshot();
            verify_server_finished::<RustCrypto>(&s_hs_ts, &th_after_cv, parsed.fin_body)
                .map_err(|_| ())?;

            transcript.update(parsed.fin_full);
            let th_through_finished = transcript.snapshot();

            let mut cf_out = [0u8; 80];
            let record = RecordKeys::<ChaCha20Poly1305Sha256>::build_client_finished::<
                RustCrypto,
                RustCrypto,
            >(&c_hs_ts, &th_through_finished, 0, &mut cf_out)
            .map_err(|_| ())?;
            if record.len() != CLIENT_FINISHED_LEN || record != &C_FINISHED[..] {
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
        with_buffers(|plaintext, flight| {
            let mut transcript = TranscriptHash::<RustCrypto>::new();
            transcript.update_record(&CH).map_err(|_| ())?;
            transcript.update_record(&SH).map_err(|_| ())?;

            let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
            let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
            let s_hs_keys =
                RecordKeys::<Aes128GcmSha256>::derive::<RustCrypto>(&s_hs_ts).map_err(|_| ())?;

            let mut flight_len = 0usize;
            let mut pos = 0usize;
            let mut seq: u64 = 0;
            while pos < FLIGHT_ENC.len() {
                if FLIGHT_ENC.len() < pos + 5 {
                    return Err(());
                }
                let body_len =
                    u16::from_be_bytes([FLIGHT_ENC[pos + 3], FLIGHT_ENC[pos + 4]]) as usize;
                let end = pos + 5 + body_len;
                if FLIGHT_ENC.len() < end {
                    return Err(());
                }
                let record = &FLIGHT_ENC[pos..end];

                let pt_slice = s_hs_keys
                    .decrypt_record::<RustCrypto>(record, seq, plaintext)
                    .map_err(|_| ())?;
                let (content, _ct) = split_inner_plaintext(pt_slice).map_err(|_| ())?;

                if flight_len + content.len() > flight.len() {
                    return Err(());
                }
                flight[flight_len..flight_len + content.len()].copy_from_slice(content);
                flight_len += content.len();

                pos = end;
                seq += 1;
            }

            let parsed = parse_server_flight(&flight[..flight_len]).map_err(|_| ())?;
            let cert_der = extract_cert_der(parsed.cert_body).map_err(|_| ())?;
            let view = <DerCert as CertParser>::parse(cert_der).map_err(|_| ())?;
            if !matches!(view, CertView::Rsa { .. }) {
                return Err(());
            }

            transcript.update(parsed.ee_full);
            transcript.update(parsed.cert_full);
            let th_after_cert = transcript.snapshot();
            verify_certificate_verify::<RustCrypto>(&view, &th_after_cert, parsed.cv_body)
                .map_err(|_| ())?;

            transcript.update(parsed.cv_full);
            let th_after_cv = transcript.snapshot();
            verify_server_finished::<RustCrypto>(&s_hs_ts, &th_after_cv, parsed.fin_body)
                .map_err(|_| ())?;

            transcript.update(parsed.fin_full);
            let th_through_finished = transcript.snapshot();

            let mut cf_out = [0u8; 80];
            let record = RecordKeys::<Aes128GcmSha256>::build_client_finished::<
                RustCrypto,
                RustCrypto,
            >(&c_hs_ts, &th_through_finished, 0, &mut cf_out)
            .map_err(|_| ())?;
            if record.len() != CLIENT_FINISHED_LEN || record != &C_FINISHED[..] {
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
