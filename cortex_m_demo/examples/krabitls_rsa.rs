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
//! Big buffers (plaintext + flight reassembly) live in `static mut` so they
//! don't inflate the stack measurement — they're well-known fixed costs of
//! the I/O loop, not of the RSA verify itself.

use cortex_m_rt::entry;
use krabitls::{
    CertParser, CertView, DerCert, RustCrypto, TranscriptHash, build_client_finished,
    decrypt_record, extract_cert_der, parse_server_flight, split_inner_plaintext, traffic_keys,
    verify_certificate_verify, verify_server_finished,
};

/// Captured fixture from a real example.com handshake.
const CH: &[u8] = include_bytes!("../captured_rsa/ch.bin");
const SH: &[u8] = include_bytes!("../captured_rsa/sh.bin");
const S_HS_TS: &[u8] = include_bytes!("../captured_rsa/s_hs_ts.bin");
const C_HS_TS: &[u8] = include_bytes!("../captured_rsa/c_hs_ts.bin");
const FLIGHT_ENC: &[u8] = include_bytes!("../captured_rsa/flight_enc.bin");

/// Plaintext buffer for decrypt_record. Sized for one large (up to ~16 KiB)
/// TLS record body. Lives in static so stack measurement isn't drowned by
/// what's really an I/O-loop concern.
static mut PLAINTEXT: [u8; 8192] = [0u8; 8192];
/// Reassembly buffer for the inner handshake content concatenated across
/// records. Sized for our captured fixture (~6.3 KiB inner) with headroom.
static mut FLIGHT: [u8; 8192] = [0u8; 8192];

#[entry]
fn main() -> ! {
    cortex_m_demo::test_fixture(|| run().is_ok(), "krabitls_rsa");
    unreachable!()
}

fn run() -> Result<(), ()> {
    // ---- TranscriptHash through CH + SH ----
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript.update_record(CH).map_err(|_| ())?;
    transcript.update_record(SH).map_err(|_| ())?;

    // ---- Derive s_hs (key, iv) from the captured traffic secret ----
    use krabitls::newtype::Secret;
    let s_hs_ts: Secret = Secret::new(S_HS_TS.try_into().map_err(|_| ())?);
    let c_hs_ts: Secret = Secret::new(C_HS_TS.try_into().map_err(|_| ())?);
    let (s_hs_key, s_hs_iv) = traffic_keys::<RustCrypto>(&s_hs_ts);

    // ---- Walk encrypted flight records, decrypt, reassemble ----
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

        // SAFETY: single-threaded M3, no concurrent access to PLAINTEXT / FLIGHT.
        let pt_buf = unsafe { &mut *core::ptr::addr_of_mut!(PLAINTEXT) };
        let plaintext = decrypt_record::<RustCrypto>(record, &s_hs_key, &s_hs_iv, seq, pt_buf)
            .map_err(|_| ())?;
        let (content, _ct) = split_inner_plaintext(plaintext).map_err(|_| ())?;

        let flight = unsafe { &mut *core::ptr::addr_of_mut!(FLIGHT) };
        if flight_len + content.len() > flight.len() {
            return Err(());
        }
        flight[flight_len..flight_len + content.len()].copy_from_slice(content);
        flight_len += content.len();

        pos = end;
        seq += 1;
    }

    // ---- Verify server flight ----
    let flight_view = unsafe { &*core::ptr::addr_of!(FLIGHT) };
    let parsed = parse_server_flight(&flight_view[..flight_len]).map_err(|_| ())?;

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
