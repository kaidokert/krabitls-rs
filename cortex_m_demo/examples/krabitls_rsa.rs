#![no_main]
#![no_std]

//! M3 RSA verify resource measurement.
//!
//! Replays the encrypted server flight captured from a real `example.com`
//! handshake (Cloudflare RSA-2048 cert chain) and runs the full verify
//! pipeline: AEAD decrypt + parse_server_flight + cert parse (RSA SPKI) +
//! verify_certificate_verify (RSA-PSS-SHA256) + verify_server_finished +
//! build_client_finished.
//!
//! Captured via `krabitls_connect --capture <dir> example.com`. The captured
//! files are committed under `cortex_m_demo/captured_rsa/`.
//!
//! Buffers live as stack locals — M3's 64 KiB RAM has room for the ~16 KiB
//! total without `static mut` (which would force an `unsafe` block per
//! access and isn't worth the few-KiB stack-measurement clean-up here).
//! The cm0 microbit profile lacks the RAM for this example anyway and is
//! skipped in CI.

use cortex_m_rt::entry;
use krabitls::newtype::Secret;
use krabitls::{
    CertParser, CertView, DerCert, RustCrypto, TranscriptHash, ZeroBuf, build_client_finished,
    decrypt_record, extract_cert_der, parse_server_flight, split_inner_plaintext, traffic_keys,
    verify_certificate_verify, verify_server_finished,
};

/// Captured fixture from a real example.com handshake. Sizes embedded in
/// the type so a fixture-size drift trips a compile-time error rather than
/// a silent runtime mismatch.
const CH: [u8; 139] = krabitls::hex_decode(include_str!("../captured_rsa/ch.hex"));
const SH: [u8; 95] = krabitls::hex_decode(include_str!("../captured_rsa/sh.hex"));
const S_HS_TS: [u8; 32] = krabitls::hex_decode(include_str!("../captured_rsa/s_hs_ts.hex"));
const C_HS_TS: [u8; 32] = krabitls::hex_decode(include_str!("../captured_rsa/c_hs_ts.hex"));
const FLIGHT_ENC: [u8; 6292] = krabitls::hex_decode(include_str!("../captured_rsa/flight_enc.hex"));

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(|| run().is_ok(), "krabitls_rsa");
    // See krabitls.rs: `loop { nop }` to satisfy `fn() -> !` without
    // pulling in panic-fmt machinery via `unreachable!()`.
    loop {
        cortex_m::asm::nop();
    }
}

fn run() -> Result<(), ()> {
    // ---- TranscriptHash through CH + SH ----
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript.update_record(&CH).map_err(|_| ())?;
    transcript.update_record(&SH).map_err(|_| ())?;

    // ---- Derive s_hs (key, iv) from the captured traffic secret ----
    let s_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(S_HS_TS));
    let c_hs_ts: Secret = Secret::new(ZeroBuf::<32>::new(C_HS_TS));
    let (s_hs_key, s_hs_iv) = traffic_keys::<RustCrypto>(&s_hs_ts).map_err(|_| ())?;

    // ---- Walk encrypted flight records, decrypt, reassemble ----
    //
    // `plaintext` is the per-record decrypt scratch (sized for the largest
    // record we expect); `flight` accumulates the inner-handshake content
    // bytes across records. Both are stack-local — the captured fixture is
    // ~6.3 KiB inner, 8 KiB gives headroom for typical TLS records.
    let mut plaintext = [0u8; 8192];
    let mut flight = [0u8; 8192];
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

    // ---- Verify server flight ----
    let parsed = parse_server_flight(&flight[..flight_len]).map_err(|_| ())?;

    let cert_der = extract_cert_der(parsed.cert_body).map_err(|_| ())?;
    let view = <DerCert as CertParser>::parse(cert_der).map_err(|_| ())?;
    // Confirm we got the RSA path, not Ed25519 — sanity check on the fixture.
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

    // Build client Finished too — exercises the c_hs path so the measurement
    // covers all of "what you'd do in a real handshake."
    let mut cf_out = [0u8; 80];
    let _record = build_client_finished::<RustCrypto, RustCrypto>(
        &c_hs_ts,
        &th_through_finished,
        0,
        &mut cf_out,
    )
    .map_err(|_| ())?;
    Ok(())
}
