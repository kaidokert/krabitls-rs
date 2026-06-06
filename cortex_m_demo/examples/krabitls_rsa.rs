#![no_main]
#![no_std]

//! M3 footprint example: AES-128-GCM-SHA256 record layer + RSA-2048-PSS
//! server cert. Replays a TLS 1.3 handshake captured from a local openssl
//! s_server.

use cortex_m_rt::entry;
#[cfg(not(feature = "baseline"))]
use krabitls::newtype::Secret;
#[cfg(not(feature = "baseline"))]
use krabitls::{
    CLIENT_FINISHED_LEN, CertParser, CertView, DerCert, RustCrypto, TranscriptHash, ZeroBuf,
    build_client_finished, decrypt_record, extract_cert_der, parse_server_flight,
    split_inner_plaintext, traffic_keys, verify_certificate_verify, verify_server_finished,
};

const CH: [u8; 137] = krabitls::hex_decode(include_str!("../captured/aes_rsa2048/ch.hex"));
const SH: [u8; 95] = krabitls::hex_decode(include_str!("../captured/aes_rsa2048/sh.hex"));
const S_HS_TS: [u8; 32] = krabitls::hex_decode(include_str!("../captured/aes_rsa2048/s_hs_ts.hex"));
const C_HS_TS: [u8; 32] = krabitls::hex_decode(include_str!("../captured/aes_rsa2048/c_hs_ts.hex"));
const FLIGHT_ENC: [u8; 1234] =
    krabitls::hex_decode(include_str!("../captured/aes_rsa2048/flight_enc.hex"));
const C_FINISHED: [u8; 58] =
    krabitls::hex_decode(include_str!("../captured/aes_rsa2048/c_finished.hex"));

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(
        #[cfg(feature = "baseline")]
        || fake_pipeline(),
        #[cfg(not(feature = "baseline"))]
        || run().is_ok(),
        "krabitls_rsa",
    );
    loop {
        cortex_m::asm::nop();
    }
}

/// Baseline stub for `--features baseline,rsa`. Touches every captured fixture
/// so the rodata layout matches the real build; the .text delta isolates the
/// crypto + protocol code.
#[cfg(feature = "baseline")]
#[inline(never)]
fn fake_pipeline() -> bool {
    use core::hint::black_box;
    black_box(&CH);
    black_box(&SH);
    black_box(&S_HS_TS);
    black_box(&C_HS_TS);
    black_box(&FLIGHT_ENC);
    black_box(&C_FINISHED);
    true
}

#[cfg(not(feature = "baseline"))]
fn run() -> Result<(), ()> {
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript.update_record(&CH).map_err(|_| ())?;
    transcript.update_record(&SH).map_err(|_| ())?;

    let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
    let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
    let (s_hs_key, s_hs_iv) = traffic_keys::<RustCrypto>(&s_hs_ts).map_err(|_| ())?;

    // 8 KiB plaintext + 8 KiB flight buffers — uniform across all footprint-
    // suite rows so their stack deltas compare directly. The suite subtracts
    // the 16 KiB buffer footprint when emitting the table.
    let mut plaintext = [0u8; cortex_m_demo::RECORD_BUF_CAP];
    let mut flight = [0u8; cortex_m_demo::FLIGHT_BUF_CAP];
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

        let pt_slice =
            decrypt_record::<RustCrypto>(record, &s_hs_key, &s_hs_iv, seq, &mut plaintext)
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
    let record = build_client_finished::<RustCrypto, RustCrypto>(
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
}
