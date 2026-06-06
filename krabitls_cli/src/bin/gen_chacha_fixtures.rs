//! Regenerate cortex_m_demo's ChaCha20-Poly1305 handshake fixtures from
//! the existing AES-128-GCM ones. Run once after the AES baseline changes.
//!
//! Decrypts each AES fixture under the AES-derived traffic key, re-encrypts
//! the same plaintext under the ChaCha-derived traffic key, writes hex to
//! cortex_m_demo/captured_chacha/.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_heapless::x25519;
use fixed_bigint::FixedUInt;
use krabitls::{
    DecryptError, EncryptError, HkdfLabelError, RustCrypto, TranscriptHash,
    application_traffic_secrets, build_client_finished_chacha, decrypt_record,
    decrypt_record_chacha, encrypt_record_chacha, handshake_secret, handshake_traffic_secrets,
    master_secret, parse_server_flight, split_inner_plaintext, traffic_keys, traffic_keys_chacha,
};

type Bn = FixedUInt<u32, 16, fixed_bigint::Ct>;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Copied from cortex_m_demo/src/lib.rs (single source of truth lives there,
// but cortex_m_demo is no_std so we can't import directly).
const CLIENT_X25519_PRIV: [u8; 32] = [
    0xac, 0xe1, 0xc2, 0x3b, 0x24, 0xdf, 0xad, 0x58, 0xc5, 0x4c, 0xcf, 0x4c, 0x1f, 0xe8, 0xdf, 0xe8,
    0x5e, 0x76, 0x0e, 0x02, 0x3b, 0x6c, 0xb6, 0x02, 0x2f, 0x70, 0x0f, 0x34, 0xde, 0x4c, 0x28, 0x28,
];
const SERVER_X25519_PUB: [u8; 32] = [
    0x60, 0x4d, 0x7a, 0x17, 0x18, 0x38, 0xbd, 0xa2, 0x15, 0xd2, 0xb5, 0x4a, 0x24, 0xfb, 0x7d, 0x3a,
    0x88, 0x8d, 0xa5, 0xac, 0x36, 0x72, 0x72, 0x6d, 0x20, 0x06, 0x44, 0x04, 0xf7, 0x06, 0xdb, 0x7e,
];
const PACKET_5_PLAINTEXT: &[u8] = b"hello from the embedded client";

/// Maximum overhead an `encrypt_record_chacha` call adds on top of the
/// inner content: 5 record header + 1 content_type + 16 AEAD tag.
const RECORD_OVERHEAD: usize = 5 + 1 + 16;

fn main() -> Result<()> {
    let testdata = repo_root().join("testdata/packets");
    let out_dir = repo_root().join("cortex_m_demo/captured_chacha");
    fs::create_dir_all(&out_dir)?;

    let ch = read_hex(testdata.join("001_c2s_ClientHello.hex"))?;
    let sh = read_hex(testdata.join("002_s2c_ServerHello.hex"))?;
    let p3_aes = read_hex(testdata.join("003_s2c_ServerFlight_encrypted.hex"))?;
    let p6_aes = read_hex(testdata.join("006_s2c_AppData_reply_0.hex"))?;

    // Recreate the key schedule (identical to the AES baseline through s_hs_ts).
    let dhe = x25519::<Bn>(&CLIENT_X25519_PRIV, &SERVER_X25519_PUB);
    let hs = handshake_secret::<RustCrypto>(&dhe).map_err(hkdf_err)?;
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript
        .update_record(&ch)
        .map_err(|e| format!("transcript ch: {e:?}"))?;
    transcript
        .update_record(&sh)
        .map_err(|e| format!("transcript sh: {e:?}"))?;
    let (c_hs_ts, s_hs_ts) =
        handshake_traffic_secrets::<RustCrypto>(&hs, &transcript.snapshot()).map_err(hkdf_err)?;

    // ---- packet 3: AES-decrypt → re-encrypt under ChaCha. ----
    let (s_aes_key, s_aes_iv) = traffic_keys::<RustCrypto>(&s_hs_ts).map_err(hkdf_err)?;
    let mut pt_buf = vec![0u8; p3_aes.len()];
    let p3_inner = decrypt_record::<RustCrypto>(&p3_aes, &s_aes_key, &s_aes_iv, 0, &mut pt_buf)
        .map_err(decrypt_err)?
        .to_vec();
    let (p3_content, p3_ct) = split_inner_plaintext(&p3_inner).map_err(decrypt_err)?;
    let (s_chacha_key, s_chacha_iv) =
        traffic_keys_chacha::<RustCrypto>(&s_hs_ts).map_err(hkdf_err)?;
    let mut p3_out = vec![0u8; p3_content.len() + RECORD_OVERHEAD];
    let p3_chacha = encrypt_record_chacha::<RustCrypto>(
        p3_content,
        p3_ct,
        &s_chacha_key,
        &s_chacha_iv,
        0,
        &mut p3_out,
    )
    .map_err(encrypt_err)?;
    write_hex(
        out_dir.join("003_s2c_ServerFlight_encrypted.hex"),
        p3_chacha,
    )?;

    // Round-trip sanity: decrypt with chacha, must match the AES plaintext.
    let mut p3_rt = vec![0u8; p3_chacha.len()];
    let p3_rt_plain =
        decrypt_record_chacha::<RustCrypto>(p3_chacha, &s_chacha_key, &s_chacha_iv, 0, &mut p3_rt)
            .map_err(decrypt_err)?;
    assert_eq!(p3_rt_plain, &p3_inner[..], "p3 chacha round-trip mismatch");

    // Walk the server flight to update the transcript through Finished.
    let flight =
        parse_server_flight(p3_content).map_err(|e| format!("parse_server_flight: {e:?}"))?;
    transcript.update(flight.ee_full);
    transcript.update(flight.cert_full);
    transcript.update(flight.cv_full);
    transcript.update(flight.fin_full);
    let th_through_sf = transcript.snapshot();

    // ---- packet 4: build client Finished under ChaCha (no AES analogue
    //      to decrypt — the M3 example compares the output of
    //      build_client_finished_chacha against this fixture). ----
    let mut cf_out = [0u8; 80];
    let p4_chacha = build_client_finished_chacha::<RustCrypto, RustCrypto>(
        &c_hs_ts,
        &th_through_sf,
        0,
        &mut cf_out,
    )
    .map_err(cf_err)?;
    write_hex(
        out_dir.join("004_c2s_ClientFinished_encrypted.hex"),
        p4_chacha,
    )?;

    // ---- App-data: derive c_ap_ts / s_ap_ts from master_secret + transcript-through-server-Finished. ----
    let ms = master_secret::<RustCrypto>(&hs).map_err(hkdf_err)?;
    let (c_ap_ts, s_ap_ts) =
        application_traffic_secrets::<RustCrypto>(&ms, &th_through_sf).map_err(hkdf_err)?;

    // packet 5: encrypt PACKET_5_PLAINTEXT under c_ap chacha.
    let (c_ap_key, c_ap_iv) = traffic_keys_chacha::<RustCrypto>(&c_ap_ts).map_err(hkdf_err)?;
    let mut p5_out = vec![0u8; PACKET_5_PLAINTEXT.len() + RECORD_OVERHEAD];
    let p5_chacha = encrypt_record_chacha::<RustCrypto>(
        PACKET_5_PLAINTEXT,
        krabitls::consts::CT_APPLICATION_DATA,
        &c_ap_key,
        &c_ap_iv,
        0,
        &mut p5_out,
    )
    .map_err(encrypt_err)?;
    write_hex(out_dir.join("005_c2s_AppData_send_0.hex"), p5_chacha)?;

    // packet 6: AES-decrypt under s_ap, re-encrypt under s_ap chacha.
    let (s_ap_aes_key, s_ap_aes_iv) = traffic_keys::<RustCrypto>(&s_ap_ts).map_err(hkdf_err)?;
    let mut p6_pt = vec![0u8; p6_aes.len()];
    let p6_inner =
        decrypt_record::<RustCrypto>(&p6_aes, &s_ap_aes_key, &s_ap_aes_iv, 0, &mut p6_pt)
            .map_err(decrypt_err)?
            .to_vec();
    let (p6_content, p6_ct) = split_inner_plaintext(&p6_inner).map_err(decrypt_err)?;
    let (s_ap_chacha_key, s_ap_chacha_iv) =
        traffic_keys_chacha::<RustCrypto>(&s_ap_ts).map_err(hkdf_err)?;
    let mut p6_out = vec![0u8; p6_content.len() + RECORD_OVERHEAD];
    let p6_chacha = encrypt_record_chacha::<RustCrypto>(
        p6_content,
        p6_ct,
        &s_ap_chacha_key,
        &s_ap_chacha_iv,
        0,
        &mut p6_out,
    )
    .map_err(encrypt_err)?;
    write_hex(out_dir.join("006_s2c_AppData_reply_0.hex"), p6_chacha)?;

    println!("wrote 4 fixtures to {}", out_dir.display());
    println!("  003 server flight     : {} bytes", p3_chacha.len());
    println!("  004 client Finished   : {} bytes", p4_chacha.len());
    println!("  005 c→s AppData send  : {} bytes", p5_chacha.len());
    println!("  006 s→c AppData reply : {} bytes", p6_chacha.len());
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("krabitls_cli sits one level under repo root")
        .to_path_buf()
}

fn read_hex(path: PathBuf) -> Result<Vec<u8>> {
    let s = fs::read_to_string(&path)?;
    let mut out = Vec::new();
    let mut it = s.bytes().peekable();
    let ctx = |label: &str| format!("{}: {label}", path.display());
    while let Some(&c) = it.peek() {
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
            it.next();
            continue;
        }
        if c == b'#' {
            while let Some(&c) = it.peek() {
                it.next();
                if c == b'\n' {
                    break;
                }
            }
            continue;
        }
        let hi_byte = it.next().ok_or_else(|| ctx("odd hex"))?;
        let lo_byte = it.next().ok_or_else(|| ctx("odd hex"))?;
        let hi = nibble(hi_byte).map_err(|e| ctx(&e))?;
        let lo = nibble(lo_byte).map_err(|e| ctx(&e))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: u8) -> std::result::Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("bad hex nibble: 0x{c:02x}")),
    }
}

fn write_hex<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<()> {
    let mut s = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            s.push('\n');
        } else if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s.push('\n');
    fs::write(path, s)?;
    Ok(())
}

fn hkdf_err(e: HkdfLabelError) -> Box<dyn std::error::Error> {
    format!("hkdf: {e:?}").into()
}
fn decrypt_err(e: DecryptError) -> Box<dyn std::error::Error> {
    format!("decrypt: {e:?}").into()
}
fn encrypt_err(e: EncryptError) -> Box<dyn std::error::Error> {
    format!("encrypt: {e:?}").into()
}
fn cf_err(e: krabitls::ClientFinishedError) -> Box<dyn std::error::Error> {
    format!("build_client_finished_chacha: {e:?}").into()
}
