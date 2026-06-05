//! krabitls_connect — TCP TLS 1.3 demo client built on the `krabitls` library.
//!
//! **NOT production-ready, NOT a secure HTTPS client.** This binary exists
//! to demonstrate that the sans-io krabitls library can be driven against
//! real public-internet servers end-to-end. It does the *protocol* side of
//! TLS 1.3 — TCP socket, record framing, SNI, multi-record server-flight
//! reassembly, CCS skip, RSA-PSS CertificateVerify — but skips every part
//! of the *trust* story:
//!
//!   - No cert chain walking. The leaf cert's signature (by some
//!     intermediate CA) is never verified against anything.
//!   - No trust anchor / CA bundle. (Optional `--pin <HEX>` flag now
//!     does pin a specific pubkey if the caller supplies one.)
//!
//! What *did* land for cert-content checks: `notBefore` / `notAfter`
//! is verified against `SystemTime::now()` via
//! `identity::verify_validity` (see PG #5 ✅).
//!
//! What *did* land for trust-establishment: SAN dNSName matching
//! against the connect hostname (always on; cert MUST declare a SAN
//! that matches), and optional `--pin` for byte-exact pubkey pinning
//! (Ed25519 32B, RSA-1024 128B, RSA-2048 256B).
//!
//! Without `--pin`, the trust story is "the cert declares a SAN that
//! matches the requested hostname AND chains to *some* intermediate the
//! server controls." A MITM with a self-issued cert whose SAN names the
//! requested hostname would clear that bar (because we don't validate
//! the intermediate). See PRODUCTION_GAPS.md gaps #5 and #24c for the
//! remaining open items.
//!
//! With `--pin`, the cert's pubkey must byte-match the pinned value, so
//! the MITM scenario above is closed for any host the user has pinned.
//!
//! Use this for: testing krabitls's protocol implementation against the
//! real web, exploring wire-level behavior, capturing handshake fixtures
//! for embedded measurement (`--capture DIR`).
//!
//! Usage:
//!     cargo run --bin krabitls_connect --features rsa -- example.com
//!     cargo run --bin krabitls_connect --features rsa -- example.com:443
//!     cargo run --bin krabitls_connect --features rsa -- --capture DIR HOST
//!     cargo run --bin krabitls_connect --features rsa -- --pin HEX  HOST

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

use krabitls::consts::CT_HANDSHAKE;
use krabitls::reassembler::ServerFlightReassembler;
use krabitls::{
    CertParser, CertView, DerCert, RustCrypto, TranscriptHash, application_traffic_secrets,
    build_client_finished, decrypt_record, encrypt_record, extract_cert_der, handshake_secret,
    handshake_traffic_secrets, master_secret, parse_server_flight, parse_server_hello,
    split_inner_plaintext, traffic_keys, verify_certificate_verify, verify_server_finished,
    write_client_hello,
};
use log::{debug, error, info, warn};

type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Convert a `Debug`-only error (krabitls's enums) into a `Box<dyn Error>`
/// with a contextual label. Lets us use `?` uniformly across krabitls + std
/// errors in this binary.
fn krabitls_err<E: core::fmt::Debug>(ctx: &'static str) -> impl FnOnce(E) -> Box<dyn Error> {
    move |e| format!("{ctx}: {e:?}").into()
}

// RFC 8446 §5.2: TLSCiphertext.length max = 2^14 + 256 (plaintext + AEAD
// overhead + content_type + zero padding). Plus the 5-byte record header.
const READ_BUF_CAP: usize = (1 << 14) + 256 + 5;
/// Upper bound on the reassembled server flight.
/// Public RSA chains routinely run 5-8 KiB; 16 KiB is generous headroom.
const FLIGHT_CAP: usize = 16 * 1024;

/// Caller-supplied pin in its owned-bytes form. Ed25519 pubkeys are 32
/// bytes; RSA pins are the modulus (128B for RSA-1024, 256B for RSA-2048),
/// with the exponent implied to be 65537 since that's universal.
enum Pin {
    Ed25519([u8; 32]),
    #[allow(dead_code)] // only used under feature = "rsa"
    Rsa(Vec<u8>),
}

impl Pin {
    fn as_pinned(&self) -> krabitls::identity::PinnedPubkey<'_> {
        use krabitls::identity::PinnedPubkey;
        match self {
            Pin::Ed25519(pk) => PinnedPubkey::Ed25519(*pk),
            #[cfg(feature = "rsa")]
            Pin::Rsa(modulus) => PinnedPubkey::Rsa {
                modulus,
                exponent: 65537,
            },
            #[cfg(not(feature = "rsa"))]
            Pin::Rsa(_) => unreachable!("RSA pin requires feature = \"rsa\""),
        }
    }
}

/// Parse a --pin argument: hex string whose length picks the key shape.
///   - 64 hex chars (32 bytes)   → Ed25519 pubkey
///   - 256 hex chars (128 bytes) → RSA-1024 modulus (e=65537 implied)
///   - 512 hex chars (256 bytes) → RSA-2048 modulus (e=65537 implied)
fn parse_pin(hex_str: &str) -> std::result::Result<Pin, String> {
    let bytes = decode_hex(hex_str).map_err(|e| format!("--pin: {e}"))?;
    match bytes.len() {
        32 => {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            Ok(Pin::Ed25519(pk))
        }
        128 | 256 => {
            #[cfg(feature = "rsa")]
            {
                Ok(Pin::Rsa(bytes))
            }
            #[cfg(not(feature = "rsa"))]
            {
                let _ = bytes;
                Err("RSA pin requires building with --features rsa".into())
            }
        }
        n => Err(format!(
            "--pin: expected 32 (Ed25519), 128 (RSA-1024), or 256 (RSA-2048) bytes, got {n}"
        )),
    }
}

fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|_| format!("bad hex byte at offset {i}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1);
    let mut host_arg: Option<String> = None;
    let mut capture_dir: Option<String> = None;
    let mut pin: Option<Pin> = None;
    while let Some(a) = args.next() {
        if a == "--capture" {
            capture_dir = args.next();
            if capture_dir.is_none() {
                error!("--capture requires a directory path");
                return ExitCode::FAILURE;
            }
        } else if a == "--pin" {
            let hex = match args.next() {
                Some(h) => h,
                None => {
                    error!("--pin requires a hex string");
                    return ExitCode::FAILURE;
                }
            };
            match parse_pin(&hex) {
                Ok(p) => pin = Some(p),
                Err(e) => {
                    error!("{e}");
                    return ExitCode::FAILURE;
                }
            }
        } else if host_arg.is_none() {
            host_arg = Some(a);
        } else {
            error!("unexpected arg: {a}");
            return ExitCode::FAILURE;
        }
    }
    let host_arg = match host_arg {
        Some(h) => h,
        None => {
            error!("usage: krabitls_connect [--capture DIR] [--pin HEX] HOST[:PORT]");
            return ExitCode::FAILURE;
        }
    };
    let (host, port) = match host_arg.split_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => {
                error!("invalid port in {host_arg:?}: {p:?} is not a u16");
                return ExitCode::FAILURE;
            }
        },
        None => (host_arg, 443u16),
    };
    match run(&host, port, capture_dir.as_deref(), pin.as_ref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(host: &str, port: u16, capture_dir: Option<&str>, pin: Option<&Pin>) -> Result<()> {
    // ---- OS RNG: ephemeral X25519 priv + ClientHello.random ----
    //
    // The scalar lives in `Zeroizing` so it's wiped when this function
    // returns — the cost of `x25519_base` / `x25519` taking it by reference
    // (a change in ed25519_heapless 0.0.3) is what makes this possible
    // without forcing extra copies. See PRODUCTION_GAPS #8 for what this
    // does NOT address (blinding, CT field-op audit).
    let mut x25519_priv = zeroize::Zeroizing::new([0u8; 32]);
    File::open("/dev/urandom")?.read_exact(&mut *x25519_priv)?;
    let mut ch_random = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut ch_random)?;
    let x25519_pub = ed25519_heapless::x25519_base::<Bn>(&x25519_priv);

    // ---- TCP ----
    let endpoint = format!("{host}:{port}");
    info!("connecting to {endpoint}");
    let mut stream = TcpStream::connect(&endpoint)?;

    // ---- Send ClientHello with SNI ----
    let host_bytes = host.as_bytes();
    let ch_len = krabitls::client_hello_len(Some(host_bytes.len()));
    let mut ch_buf = vec![0u8; ch_len];
    {
        let mut cursor: &mut [u8] = &mut ch_buf;
        write_client_hello(&mut cursor, &ch_random, &x25519_pub, Some(host_bytes))
            .map_err(krabitls_err("write_client_hello"))?;
    }
    stream.write_all(&ch_buf)?;
    info!("sent ClientHello ({} bytes, SNI={host})", ch_buf.len());

    // ---- Read ServerHello (one record, plaintext handshake) ----
    let mut transcript = TranscriptHash::<RustCrypto>::new();
    transcript
        .update_record(&ch_buf)
        .map_err(krabitls_err("transcript ch"))?;
    let sh_record = read_record(&mut stream)?;
    debug!(
        "first response record: type=0x{:02x} version=0x{:02x}{:02x} len={} bytes={}",
        sh_record[0],
        sh_record[1],
        sh_record[2],
        u16::from_be_bytes([sh_record[3], sh_record[4]]),
        hex(&sh_record[..sh_record.len().min(32)])
    );
    if sh_record[0] != CT_HANDSHAKE {
        // Plaintext alert in TLS 1.3 is content_type=21; body is (level, description).
        if sh_record[0] == 0x15 && sh_record.len() >= 7 {
            let level = sh_record[5];
            let desc = sh_record[6];
            return Err(format!(
                "server sent ALERT instead of ServerHello: level={} description={} (0x{:02x})",
                level, desc, desc
            )
            .into());
        }
        return Err(format!(
            "expected ServerHello (handshake/22), got content_type={} (record bytes: {})",
            sh_record[0],
            hex(&sh_record[..sh_record.len().min(16)])
        )
        .into());
    }
    transcript
        .update_record(&sh_record)
        .map_err(krabitls_err("transcript sh"))?;
    let sh = parse_server_hello(&sh_record).map_err(krabitls_err("parse_server_hello"))?;
    let server_x25519_share: [u8; 32] = *sh.x25519_share;
    info!("received ServerHello ({} bytes)", sh_record.len());

    // ---- Key schedule down to s_hs_traffic_secret ----
    let dhe = ed25519_heapless::x25519::<Bn>(&x25519_priv, &server_x25519_share);
    let hs =
        handshake_secret::<RustCrypto>(&dhe).map_err(|e| format!("handshake_secret: {:?}", e))?;
    let th_ch_sh = transcript.snapshot();
    let (c_hs_ts, s_hs_ts) = handshake_traffic_secrets::<RustCrypto>(&hs, &th_ch_sh)
        .map_err(|e| format!("handshake_traffic_secrets: {:?}", e))?;
    let (s_hs_key, s_hs_iv) =
        traffic_keys::<RustCrypto>(&s_hs_ts).map_err(|e| format!("traffic_keys: {:?}", e))?;

    // ---- Read encrypted server flight (one or more application_data records),
    //      skipping any middlebox-compat ChangeCipherSpec records. Reassemble
    //      the inner handshake bytes across records until we have all four
    //      messages (last one is Finished). ----
    let mut reassembler: ServerFlightReassembler<FLIGHT_CAP> = ServerFlightReassembler::new();
    // Raw encrypted server-flight records (concatenated, with their record
    // headers, CCS records dropped) — needed for the captured-fixture M3 demo
    // to exercise the full AEAD + verify pipeline against deterministic data.
    let mut flight_enc_bytes: Vec<u8> = Vec::new();
    let mut seq: u64 = 0;
    loop {
        let record = read_record(&mut stream)?;
        match record[0] {
            // change_cipher_spec — middlebox-compat, drop and don't bump seq.
            0x14 => {
                debug!("skip CCS record ({} bytes)", record.len());
                continue;
            }
            // application_data — decrypt under s_hs_traffic_secret.
            0x17 => {
                flight_enc_bytes.extend_from_slice(&record);
                let mut pt = vec![0u8; record.len()];
                let plaintext =
                    decrypt_record::<RustCrypto>(&record, &s_hs_key, &s_hs_iv, seq, &mut pt)
                        .map_err(krabitls_err("decrypt server flight"))?;
                let (content, inner_ct) = split_inner_plaintext(plaintext)
                    .map_err(krabitls_err("split inner plaintext"))?;
                if inner_ct != CT_HANDSHAKE {
                    return Err(format!(
                        "inner content_type {} during server flight, expected handshake",
                        inner_ct
                    )
                    .into());
                }
                reassembler
                    .push_content(content)
                    .map_err(krabitls_err("reassembler push"))?;
                seq += 1;
                debug!(
                    "decrypted handshake record seq={} ({} inner bytes; flight {} total)",
                    seq - 1,
                    content.len(),
                    reassembler.len()
                );
                if reassembler.is_complete() {
                    break;
                }
            }
            _ => {
                return Err(format!(
                    "unexpected record content_type 0x{:02x} during server flight",
                    record[0]
                )
                .into());
            }
        }
    }
    let flight_bytes = reassembler.as_slice();
    info!(
        "reassembled server flight: {} bytes from {} record(s)",
        flight_bytes.len(),
        seq,
    );

    // ---- Walk the flight + verify CertificateVerify + Finished ----
    let flight = parse_server_flight(flight_bytes).map_err(krabitls_err("parse_server_flight"))?;
    let cert_der = extract_cert_der(flight.cert_body).map_err(krabitls_err("extract_cert_der"))?;
    // Skip the cert *self-sig* check — public-internet leaf certs are signed
    // by an intermediate CA, not self-signed. The CertificateVerify check
    // below is what binds the server to the cert.
    let cert_view =
        <DerCert as CertParser>::parse(cert_der).map_err(krabitls_err("CertParser::parse"))?;
    log_cert_view(&cert_view);

    // SAN / hostname binding (PRODUCTION_GAPS #6). Without this, krabitls_connect
    // would accept any well-formed cert from any peer — a MITM with any
    // self-issued leaf cleared CertificateVerify. Now the cert must declare a
    // SAN dNSName matching the hostname the user asked for.
    use krabitls::identity::{verify_hostname, verify_pinned_pubkey};
    verify_hostname(&cert_view, host.as_bytes()).map_err(krabitls_err("verify_hostname"))?;
    info!("SAN binds hostname '{host}'");

    // Pinned-key check (PRODUCTION_GAPS #7). Only fires if the user passed
    // --pin; otherwise the cert is trusted purely on SAN + CertificateVerify
    // chaining (still no CA bundle).
    if let Some(p) = pin {
        verify_pinned_pubkey(&cert_view, &p.as_pinned())
            .map_err(krabitls_err("verify_pinned_pubkey"))?;
        info!("pinned pubkey matches");
    }

    // notBefore / notAfter window check (PRODUCTION_GAPS #5). krabitls_cli
    // enables `krabitls/validity` unconditionally — the binary always has
    // std::time::SystemTime to back the TimeSource.
    {
        use krabitls::identity::verify_validity;
        use krabitls::traits::TimeSource;
        struct SystemTimeSource;
        impl TimeSource for SystemTimeSource {
            fn now_unix_secs(&self) -> u64 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }
        }
        verify_validity(&cert_view, &SystemTimeSource).map_err(krabitls_err("verify_validity"))?;
        info!("cert notBefore/notAfter window OK");
    }

    transcript.update(flight.ee_full);
    transcript.update(flight.cert_full);
    let th_after_cert = transcript.snapshot();
    verify_certificate_verify::<RustCrypto>(&cert_view, &th_after_cert, flight.cv_body)
        .map_err(krabitls_err("verify_certificate_verify"))?;
    info!("CertificateVerify OK");

    transcript.update(flight.cv_full);
    let th_after_cv = transcript.snapshot();
    verify_server_finished::<RustCrypto>(&s_hs_ts, &th_after_cv, flight.fin_body)
        .map_err(krabitls_err("server Finished"))?;
    info!("server Finished MAC OK");

    transcript.update(flight.fin_full);
    let th_through_finished = transcript.snapshot();

    // ---- Optional: dump the captured handshake state for an offline replay
    //      demo (cortex_m_demo/examples/krabitls_rsa.rs). Bails after writing,
    //      since we'd otherwise also need to clean up the TCP socket. ----
    if let Some(dir) = capture_dir {
        dump_capture(
            dir,
            host,
            &ch_buf,
            &sh_record,
            &s_hs_ts,
            &c_hs_ts,
            &flight_enc_bytes,
            seq,
        )?;
        return Ok(());
    }

    // ---- Build + send client Finished ----
    let mut cf_out = [0u8; 80];
    let cf_record = build_client_finished::<RustCrypto, RustCrypto>(
        &c_hs_ts,
        &th_through_finished,
        0,
        &mut cf_out,
    )
    .map_err(krabitls_err("build_client_finished"))?;
    stream.write_all(cf_record)?;
    info!("sent client Finished ({} bytes)", cf_record.len());

    // ---- Application traffic secrets ----
    let ms = master_secret::<RustCrypto>(&hs).map_err(|e| format!("master_secret: {:?}", e))?;
    let (c_ap_ts, s_ap_ts) = application_traffic_secrets::<RustCrypto>(&ms, &th_through_finished)
        .map_err(|e| format!("application_traffic_secrets: {:?}", e))?;
    let (c_ap_key, c_ap_iv) = traffic_keys::<RustCrypto>(&c_ap_ts)
        .map_err(|e| format!("traffic_keys (c_ap): {:?}", e))?;
    let (s_ap_key, s_ap_iv) = traffic_keys::<RustCrypto>(&s_ap_ts)
        .map_err(|e| format!("traffic_keys (s_ap): {:?}", e))?;

    // ---- Send a GET request encrypted ----
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: krabitls_connect\r\nConnection: close\r\n\r\n",
    );
    let mut req_buf = vec![0u8; request.len() + 64];
    let req_record = encrypt_record::<RustCrypto>(
        request.as_bytes(),
        krabitls::consts::CT_APPLICATION_DATA,
        &c_ap_key,
        &c_ap_iv,
        0,
        &mut req_buf,
    )
    .map_err(krabitls_err("encrypt_record"))?;
    stream.write_all(req_record)?;
    info!(
        "sent GET / ({} plaintext, {} ciphertext bytes)",
        request.len(),
        req_record.len()
    );

    // ---- Read response records until the server closes / signals close_notify ----
    let mut rx_seq: u64 = 0;
    let mut body_total = 0usize;
    loop {
        let record = match read_record(&mut stream) {
            Ok(r) => r,
            Err(e) => {
                info!("read end: {e}");
                break;
            }
        };
        match record[0] {
            0x14 => continue, // ignore any further CCS
            0x17 => {
                let mut pt = vec![0u8; record.len()];
                let plaintext = match decrypt_record::<RustCrypto>(
                    &record, &s_ap_key, &s_ap_iv, rx_seq, &mut pt,
                ) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("decrypt failed: {e:?}");
                        break;
                    }
                };
                rx_seq += 1;
                let (content, inner_ct) = split_inner_plaintext(plaintext)
                    .map_err(krabitls_err("split inner plaintext"))?;
                match inner_ct {
                    // application_data — print as response body
                    0x17 => {
                        body_total += content.len();
                        std::io::stdout().write_all(content)?;
                    }
                    // alert — print and stop
                    0x15 => {
                        info!("alert: {:?}", content);
                        break;
                    }
                    // handshake post-handshake (NewSessionTicket etc.) — ignore
                    0x16 => {
                        debug!(
                            "post-handshake message ({} bytes, type=0x{:02x})",
                            content.len(),
                            content.first().copied().unwrap_or(0)
                        );
                    }
                    other => {
                        warn!("unexpected inner content_type 0x{other:02x}");
                    }
                }
            }
            other => {
                warn!("unexpected record content_type 0x{other:02x}");
                break;
            }
        }
    }
    info!("total response body bytes: {body_total}");
    Ok(())
}

/// Read exactly one TLS record (5-byte header + body) from the stream.
fn read_record(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let body_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if body_len > READ_BUF_CAP - 5 {
        return Err(format!("record body_len={body_len} exceeds 16 KiB max").into());
    }
    let mut record = vec![0u8; 5 + body_len];
    record[..5].copy_from_slice(&header);
    stream.read_exact(&mut record[5..])?;
    Ok(record)
}

fn log_cert_view(view: &CertView<'_>) {
    match view {
        CertView::Ed25519 { pubkey, .. } => {
            info!("server identity: Ed25519, pubkey={}", hex(&pubkey[..8]));
        }
        CertView::Rsa {
            modulus, exponent, ..
        } => {
            info!(
                "server identity: RSA-{}, e={}, modulus={}...",
                modulus.len() * 8,
                exponent,
                hex(&modulus[..8])
            );
        }
    }
}

/// Persist the captured handshake fixture to `dir/` so an offline replay
/// demo (cortex_m_demo/examples/krabitls_rsa.rs) can exercise the full RSA
/// verify pipeline against deterministic data.
#[allow(clippy::too_many_arguments)]
fn dump_capture(
    dir: &str,
    host: &str,
    ch: &[u8],
    sh: &[u8],
    s_hs_ts: &krabitls::newtype::Secret,
    c_hs_ts: &krabitls::newtype::Secret,
    flight_enc: &[u8],
    flight_record_count: u64,
) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let write = |name: &str, bytes: &[u8]| -> Result<()> {
        let path = format!("{dir}/{name}");
        std::fs::write(&path, bytes)?;
        debug!("capture wrote {} ({} bytes)", path, bytes.len());
        Ok(())
    };
    write("ch.bin", ch)?;
    write("sh.bin", sh)?;
    write("s_hs_ts.bin", s_hs_ts.as_bytes())?;
    write("c_hs_ts.bin", c_hs_ts.as_bytes())?;
    write("flight_enc.bin", flight_enc)?;
    write("host.txt", host.as_bytes())?;
    info!(
        "capture: {} encrypted flight records ({} total wire bytes) under s_hs_traffic_secret",
        flight_record_count,
        flight_enc.len()
    );
    Ok(())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
