//! krabitls_connect — TCP TLS 1.3 demo on the typestate API.
//!
//! **NOT production-ready.** No cert chain walking, no CA bundle.
//! `VerifyMode::TrustOnPin` skips the cert outer-sig verify; trust is
//! established via SAN matching (always on) + optional `--pin <HEX>` for
//! byte-exact pubkey pinning. `notBefore` / `notAfter` checked against
//! `SystemTime::now()`.
//!
//! Use for: testing protocol against the real web; capturing fixtures.
//!
//! Usage:
//!     cargo run --bin krabitls_connect --features rsa -- example.com
//!     cargo run --bin krabitls_connect --features rsa -- example.com:443
//!     cargo run --bin krabitls_connect --features rsa -- --capture DIR HOST
//!     cargo run --bin krabitls_connect --features rsa -- --pin HEX  HOST

use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(feature = "chacha20")]
use krabitls::ChaCha20Poly1305Sha256;
#[cfg(feature = "chacha20")]
use krabitls::consts::CIPHER_CHACHA20_POLY1305_SHA256;
use krabitls::consts::{CIPHER_AES_128_GCM_SHA256, CT_APPLICATION_DATA, CT_HANDSHAKE};
use krabitls::reassembler::ServerFlightReassembler;
use krabitls::{
    Aes128GcmSha256, CLIENT_FINISHED_LEN, CertParser, CertView, DerCert, FlightStep, Init,
    NegotiatedSuite, RustCrypto, TlsConnection, ZeroBuf, extract_cert_der, parse_server_flight,
};
use log::{debug, error, info, warn};

type Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Wrap a `Debug`-only krabitls error in `Box<dyn Error>` with a label.
fn krabitls_err<E: core::fmt::Debug>(ctx: &'static str) -> impl FnOnce(E) -> Box<dyn Error> {
    move |e| format!("{ctx}: {e:?}").into()
}

fn cipher_suite_name(suite: u16) -> &'static str {
    match suite {
        CIPHER_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        #[cfg(feature = "chacha20")]
        CIPHER_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "unknown",
    }
}

/// RFC 8446 §5.2 TLSCiphertext max + 5-byte record header.
const READ_BUF_CAP: usize = (1 << 14) + 256 + 5;
/// Upper bound on the reassembled server flight (public RSA chains run 5-8 KiB).
const FLIGHT_CAP: usize = 16 * 1024;

/// Ed25519 pubkey (32B) or RSA modulus (128B for RSA-1024, 256B for RSA-2048;
/// exponent assumed 65537).
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
    let bytes = s.as_bytes();
    if (bytes.len() & 1) != 0 {
        return Err("hex string must have even length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2])
            .map_err(|_| format!("non-ASCII byte at offset {i}"))?;
        let byte =
            u8::from_str_radix(pair, 16).map_err(|_| format!("bad hex byte at offset {i}"))?;
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

/// Loop `feed_server_record` until `FlightStep::Ready`. Buffers raw wire
/// bytes for the optional `--capture` path.
fn read_server_flight<S, H, C>(
    stream: &mut TcpStream,
    conn: &mut TlsConnection<krabitls::WaitServerFlight<S>, H, C>,
    reassembler: &mut ServerFlightReassembler<FLIGHT_CAP>,
    feed: impl Fn(
        &mut TlsConnection<krabitls::WaitServerFlight<S>, H, C>,
        &[u8],
        &mut ServerFlightReassembler<FLIGHT_CAP>,
        &mut [u8],
    ) -> std::result::Result<FlightStep, krabitls::ConnectionError>,
) -> Result<(Vec<u8>, u64)>
where
    S: krabitls::CipherSuite,
    H: krabitls::HkdfSha256,
{
    let mut flight_enc_bytes: Vec<u8> = Vec::new();
    let mut record_count: u64 = 0;
    let mut pt = vec![0u8; READ_BUF_CAP];
    loop {
        let record = read_record(stream)?;
        debug!(
            "server record: type=0x{:02x} len={} bytes={}",
            record[0],
            record.len(),
            hex(&record[..record.len().min(16)])
        );
        // Buffer all wire bytes so --capture is bit-identical.
        flight_enc_bytes.extend_from_slice(&record);
        let step = feed(conn, &record, reassembler, &mut pt)
            .map_err(krabitls_err("feed_server_record"))?;
        if record[0] != 0x14 {
            record_count += 1;
        }
        if matches!(step, FlightStep::Ready) {
            break;
        }
    }
    Ok((flight_enc_bytes, record_count))
}

/// Re-parse the cert for SAN / pin / validity checks after typestate verify.
fn inspect_cert(
    reassembler: &ServerFlightReassembler<FLIGHT_CAP>,
    host: &str,
    pin: Option<&Pin>,
) -> Result<()> {
    let flight_bytes = reassembler
        .flight_bytes()
        .ok_or("server flight not fully reassembled")?;
    let flight = parse_server_flight(flight_bytes).map_err(krabitls_err("parse_server_flight"))?;
    let cert_der = extract_cert_der(flight.cert_body).map_err(krabitls_err("extract_cert_der"))?;
    let cert_view =
        <DerCert as CertParser>::parse(cert_der).map_err(krabitls_err("CertParser::parse"))?;
    log_cert_view(&cert_view);

    use krabitls::identity::{verify_hostname, verify_pinned_pubkey};
    verify_hostname(&cert_view, host.as_bytes()).map_err(krabitls_err("verify_hostname"))?;
    info!("SAN binds hostname '{host}'");
    if let Some(p) = pin {
        verify_pinned_pubkey(&cert_view, &p.as_pinned())
            .map_err(krabitls_err("verify_pinned_pubkey"))?;
        info!("pinned pubkey matches");
    } else {
        log::warn!(
            "no --pin supplied: server identity is unauthenticated (SAN match alone is MITM-vulnerable). \
             Pass --pin <HEX> with the expected SPKI bytes to bind trust."
        );
    }
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
    Ok(())
}

fn run(host: &str, port: u16, capture_dir: Option<&str>, pin: Option<&Pin>) -> Result<()> {
    // ---- OS RNG: ephemeral X25519 priv + ClientHello.random ----
    let mut x25519_priv = ZeroBuf::<32>::new([0u8; 32]);
    getrandom::fill(&mut *x25519_priv).map_err(|e| format!("getrandom (x25519): {e}"))?;
    let mut ch_random = [0u8; 32];
    getrandom::fill(&mut ch_random).map_err(|e| format!("getrandom (ch_random): {e}"))?;
    let x25519_pub = ed25519_heapless::x25519_base::<Bn>(&x25519_priv);

    // ---- TCP ----
    let endpoint = format!("{host}:{port}");
    info!("connecting to {endpoint}");
    let mut stream = TcpStream::connect(&endpoint)?;
    // 15 s is generous for TLS handshakes; bounded so a stalled peer fails fast.
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    // ---- Init -> WaitServerHello: write ClientHello with SNI ----
    let host_bytes = host.as_bytes();
    let ch_len = krabitls::client_hello_len(Some(host_bytes.len()));
    let mut ch_wire = vec![0u8; ch_len];
    let conn = TlsConnection::<Init, RustCrypto, RustCrypto>::new(ch_random, x25519_priv);
    let (ch_wire, conn) = conn
        .write_client_hello_to_slice(&mut ch_wire, &x25519_pub, Some(host_bytes))
        .map_err(krabitls_err("write_client_hello"))?;
    stream.write_all(ch_wire)?;
    info!("sent ClientHello ({} bytes, SNI={host})", ch_wire.len());

    // ---- WaitServerHello -> NegotiatedSuite: read SH, run x25519, derive
    //      s_hs keys, land on the suite-typed `WaitServerFlight<S>`. ----
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
    let negotiated = conn
        .read_server_hello(&sh_record)
        .map_err(krabitls_err("read_server_hello"))?;
    let (suite_id, suite_label) = match &negotiated {
        NegotiatedSuite::Aes128Gcm(_) => (
            CIPHER_AES_128_GCM_SHA256,
            cipher_suite_name(CIPHER_AES_128_GCM_SHA256),
        ),
        #[cfg(feature = "chacha20")]
        NegotiatedSuite::ChaCha20Poly1305(_) => (
            CIPHER_CHACHA20_POLY1305_SHA256,
            cipher_suite_name(CIPHER_CHACHA20_POLY1305_SHA256),
        ),
    };
    info!("negotiated {suite_label} (0x{suite_id:04x})");

    // Per-suite methods live on concrete impl blocks, not on a generic
    // `impl<S: CipherSuite>`, so the two branches inline near-identically.
    let mut reassembler: ServerFlightReassembler<FLIGHT_CAP> = ServerFlightReassembler::new();
    match negotiated {
        NegotiatedSuite::Aes128Gcm(mut conn) => {
            let (flight_enc_bytes, record_count) = read_server_flight::<Aes128GcmSha256, _, _>(
                &mut stream,
                &mut conn,
                &mut reassembler,
                |c, r, ra, pt| c.feed_server_record(r, ra, pt),
            )?;
            info!(
                "reassembled server flight: {} inner bytes from {} record(s)",
                reassembler.len(),
                record_count,
            );

            let conn = conn
                .finalize_server_flight::<FLIGHT_CAP, DerCert, RustCrypto>(
                    &reassembler,
                    krabitls::VerifyMode::TrustOnPin,
                )
                .map_err(krabitls_err("finalize_server_flight"))?;
            info!("server flight verified (cert outer-sig + CertificateVerify + Finished)");
            inspect_cert(&reassembler, host, pin)?;

            if let Some(dir) = capture_dir {
                // Capture path: only need CH/SH/flight + hs secrets + CF bytes,
                // so build CF without advancing into AppData.
                let mut cf_buf = [0u8; CLIENT_FINISHED_LEN];
                let cf_record = conn
                    .build_client_finished(&mut cf_buf)
                    .map_err(krabitls_err("build_client_finished"))?;
                dump_capture(
                    dir,
                    host,
                    ch_wire,
                    &sh_record,
                    conn.s_hs_traffic_secret(),
                    conn.c_hs_traffic_secret(),
                    &flight_enc_bytes,
                    record_count,
                    cf_record,
                )?;
                return Ok(());
            }

            // Live path: finish_handshake + write CF + drive app data.
            let mut cf_buf = [0u8; CLIENT_FINISHED_LEN];
            let (cf_record, mut conn) = conn
                .finish_handshake(&mut cf_buf)
                .map_err(krabitls_err("finish_handshake"))?;
            stream.write_all(cf_record)?;
            info!("sent client Finished ({} bytes)", cf_record.len());

            let request = format!(
                "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: krabitls_connect\r\nConnection: close\r\n\r\n",
            );
            let mut req_buf = vec![0u8; request.len() + 64];
            let req_record = conn
                .encrypt_record(request.as_bytes(), CT_APPLICATION_DATA, &mut req_buf)
                .map_err(krabitls_err("encrypt_record"))?;
            stream.write_all(req_record)?;
            info!(
                "sent GET / ({} plaintext, {} ciphertext bytes)",
                request.len(),
                req_record.len()
            );
            drive_response::<Aes128GcmSha256, _, _>(&mut stream, &mut conn, |c, r, pt| {
                c.decrypt_record(r, pt)
            })?;
        }
        #[cfg(feature = "chacha20")]
        NegotiatedSuite::ChaCha20Poly1305(mut conn) => {
            let (flight_enc_bytes, record_count) =
                read_server_flight::<ChaCha20Poly1305Sha256, _, _>(
                    &mut stream,
                    &mut conn,
                    &mut reassembler,
                    |c, r, ra, pt| c.feed_server_record(r, ra, pt),
                )?;
            info!(
                "reassembled server flight: {} inner bytes from {} record(s)",
                reassembler.len(),
                record_count,
            );

            let conn = conn
                .finalize_server_flight::<FLIGHT_CAP, DerCert, RustCrypto>(
                    &reassembler,
                    krabitls::VerifyMode::TrustOnPin,
                )
                .map_err(krabitls_err("finalize_server_flight"))?;
            info!("server flight verified (cert outer-sig + CertificateVerify + Finished)");
            inspect_cert(&reassembler, host, pin)?;

            if let Some(dir) = capture_dir {
                let mut cf_buf = [0u8; CLIENT_FINISHED_LEN];
                let cf_record = conn
                    .build_client_finished(&mut cf_buf)
                    .map_err(krabitls_err("build_client_finished"))?;
                dump_capture(
                    dir,
                    host,
                    ch_wire,
                    &sh_record,
                    conn.s_hs_traffic_secret(),
                    conn.c_hs_traffic_secret(),
                    &flight_enc_bytes,
                    record_count,
                    cf_record,
                )?;
                return Ok(());
            }

            let mut cf_buf = [0u8; CLIENT_FINISHED_LEN];
            let (cf_record, mut conn) = conn
                .finish_handshake(&mut cf_buf)
                .map_err(krabitls_err("finish_handshake"))?;
            stream.write_all(cf_record)?;
            info!("sent client Finished ({} bytes)", cf_record.len());

            let request = format!(
                "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: krabitls_connect\r\nConnection: close\r\n\r\n",
            );
            let mut req_buf = vec![0u8; request.len() + 64];
            let req_record = conn
                .encrypt_record(request.as_bytes(), CT_APPLICATION_DATA, &mut req_buf)
                .map_err(krabitls_err("encrypt_record"))?;
            stream.write_all(req_record)?;
            info!(
                "sent GET / ({} plaintext, {} ciphertext bytes)",
                request.len(),
                req_record.len()
            );
            drive_response::<ChaCha20Poly1305Sha256, _, _>(&mut stream, &mut conn, |c, r, pt| {
                c.decrypt_record(r, pt)
            })?;
        }
    }

    Ok(())
}

/// Read response records until the peer closes or sends close_notify.
fn drive_response<S, H, C>(
    stream: &mut TcpStream,
    conn: &mut TlsConnection<krabitls::AppData<S>, H, C>,
    decrypt: impl for<'a> Fn(
        &mut TlsConnection<krabitls::AppData<S>, H, C>,
        &[u8],
        &'a mut [u8],
    ) -> std::result::Result<(&'a [u8], u8), krabitls::ConnectionError>,
) -> Result<()>
where
    S: krabitls::CipherSuite,
    H: krabitls::HkdfSha256,
{
    let mut body_total = 0usize;
    let mut pt = vec![0u8; READ_BUF_CAP];
    loop {
        let record = match read_record(stream) {
            Ok(r) => r,
            Err(e) => {
                info!("read end: {e}");
                break;
            }
        };
        match record[0] {
            0x14 => continue, // any straggler CCS
            0x17 => {
                let (content, inner_ct) = match decrypt(conn, &record, &mut pt) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("decrypt failed: {e:?}");
                        break;
                    }
                };
                match inner_ct {
                    0x17 => {
                        body_total += content.len();
                        std::io::stdout().write_all(content)?;
                    }
                    0x15 => {
                        info!("alert: {:?}", content);
                        break;
                    }
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

/// Read one TLS record (5-byte header + body).
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
            let preview = pubkey.get(..8).unwrap_or(&pubkey[..]);
            info!("server identity: Ed25519, pubkey={}", hex(preview));
        }
        CertView::Rsa {
            modulus, exponent, ..
        } => {
            let preview = modulus.get(..8).unwrap_or(modulus);
            info!(
                "server identity: RSA-{}, e={}, modulus={}...",
                modulus.len() * 8,
                exponent,
                hex(preview)
            );
        }
    }
}

/// Write the captured handshake fixture to `dir/` for offline replay.
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
    c_finished: &[u8],
) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let write_hex = |name: &str, label: &str, bytes: &[u8]| -> Result<()> {
        let path = format!("{dir}/{name}");
        let mut s = format!("# {label} from {host} ({} bytes).\n", bytes.len());
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(if i % 16 == 0 { '\n' } else { ' ' });
            }
            s.push_str(&format!("{b:02x}"));
        }
        s.push('\n');
        std::fs::write(&path, s)?;
        debug!("capture wrote {} ({} bytes)", path, bytes.len());
        Ok(())
    };
    write_hex("ch.hex", "ClientHello record", ch)?;
    write_hex("sh.hex", "ServerHello record", sh)?;
    write_hex(
        "s_hs_ts.hex",
        "server handshake traffic secret",
        s_hs_ts.as_bytes(),
    )?;
    write_hex(
        "c_hs_ts.hex",
        "client handshake traffic secret",
        c_hs_ts.as_bytes(),
    )?;
    write_hex("flight_enc.hex", "encrypted server flight", flight_enc)?;
    write_hex("c_finished.hex", "client Finished record", c_finished)?;
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
