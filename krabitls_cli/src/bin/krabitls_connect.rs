//! `krabitls_connect` — TCP TLS 1.3 demo on the high-level facade.
//!
//! **NOT production-ready.** No cert chain walking, no CA bundle.
//!
//! Usage:
//!     cargo run --bin krabitls_connect --features rsa -- example.com
//!     cargo run --bin krabitls_connect --features rsa -- example.com:443
//!     cargo run --bin krabitls_connect --features rsa -- --pin HEX  HOST

use std::error::Error;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use getrandom::SysRng;
#[cfg(feature = "rsa")]
use krabitls::client::RsaClientAuth;
use krabitls::client::{
    ClientAuthPolicy, ClientParams, ClockedVerify, ConnectError, DefaultConfig, DefaultScratch,
    Ed25519ClientAuth, MAX_CLIENT_CERT_DER, PinnedPubkey, RuntimeSuitePolicy, TimeSource,
    TlsStream, Transport,
};
use log::{error, info};
use zeroize::Zeroizing;

/// Wall clock from the host OS — enables the cert validity-window check.
struct SystemTimeSource;
impl TimeSource for SystemTimeSource {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

// Stream over the bundled config + a clocked pin/self-signed strategy. Same
// buffer/chain const generics as `DefaultStream`.
type ClockedStream<'s, T> =
    TlsStream<'s, T, DefaultConfig, ClockedVerify<SystemTimeSource>, 16384, 16645, 4096, 8>;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

enum Pin {
    Ed25519([u8; 32]),
    #[cfg(feature = "rsa")]
    Rsa(Vec<u8>),
}

impl Pin {
    fn as_pinned(&self) -> PinnedPubkey<'_> {
        match self {
            Pin::Ed25519(pk) => PinnedPubkey::Ed25519(*pk),
            #[cfg(feature = "rsa")]
            Pin::Rsa(modulus) => PinnedPubkey::Rsa {
                modulus,
                exponent: 65537,
            },
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

fn load_client_cert(cert_path: &str) -> std::result::Result<Vec<u8>, String> {
    let cert_der =
        std::fs::read(cert_path).map_err(|e| format!("--client-cert {cert_path:?}: {e}"))?;
    if cert_der.is_empty() {
        return Err(format!(
            "--client-cert {cert_path:?}: empty certificate file"
        ));
    }
    if cert_der.len() > MAX_CLIENT_CERT_DER {
        return Err(format!(
            "--client-cert {cert_path:?}: {} bytes exceeds the {MAX_CLIENT_CERT_DER}-byte client-auth buffer",
            cert_der.len()
        ));
    }
    Ok(cert_der)
}

fn load_client_auth(
    cert_path: &str,
    seed_hex: &str,
) -> std::result::Result<ClientAuthMaterial, String> {
    let cert_der = load_client_cert(cert_path)?;
    // Decode straight into the fixed `Zeroizing` array — the raw seed never
    // touches an intermediate heap buffer.
    let mut seed = Zeroizing::new([0u8; 32]);
    decode_hex_into(seed_hex, &mut seed[..]).map_err(|e| format!("--client-seed: {e}"))?;
    Ok(ClientAuthMaterial::Ed25519 { cert_der, seed })
}

#[cfg(feature = "rsa")]
fn load_client_auth_rsa(
    cert_path: &str,
    key_path: &str,
) -> std::result::Result<ClientAuthMaterial, String> {
    let cert_der = load_client_cert(cert_path)?;
    // Exact-size read into a fixed `Zeroizing` buffer (no heap for the key:
    // `fs::read`'s internal `read_to_end` may also realloc mid-read,
    // orphaning an unwiped copy, if the file changes size after the probe).
    let err = |e: std::io::Error| format!("--client-rsa-key {key_path:?}: {e}");
    let mut file = std::fs::File::open(key_path).map_err(err)?;
    let len = file.metadata().map_err(err)?.len() as usize;
    let mut key_der = Zeroizing::new([0u8; MAX_RSA_KEY_DER]);
    if len == 0 || len > key_der.len() {
        return Err(format!(
            "--client-rsa-key {key_path:?}: {len} bytes is not a plausible RSA-2048 key DER"
        ));
    }
    IoRead::read_exact(&mut file, &mut key_der[..len]).map_err(err)?;
    let (n, e, d) = parse_rsa_private_der(&key_der[..len])
        .map_err(|e| format!("--client-rsa-key {key_path:?}: {e}"))?;
    Ok(ClientAuthMaterial::Rsa { cert_der, n, e, d })
}

/// Read one DER TLV off the front of `b`, returning (tag, contents).
#[cfg(feature = "rsa")]
fn der_read<'a>(b: &mut &'a [u8]) -> std::result::Result<(u8, &'a [u8]), String> {
    if b.len() < 2 {
        return Err("truncated DER".into());
    }
    let tag = b[0];
    let (len, hdr) = match b[1] {
        n @ 0..=0x7f => (n as usize, 2),
        0x81 if b.len() >= 3 => (b[2] as usize, 3),
        0x82 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
        _ => return Err("unsupported DER length".into()),
    };
    let end = usize::checked_add(hdr, len).filter(|&e| e <= b.len());
    let Some(end) = end else {
        return Err("truncated DER".into());
    };
    let contents = &b[hdr..end];
    *b = &b[end..];
    Ok((tag, contents))
}

/// DER INTEGERs carry a leading 0x00 when the high bit is set.
#[cfg(feature = "rsa")]
fn strip_int_sign(i: &[u8]) -> &[u8] {
    if i.len() > 1 && i[0] == 0 { &i[1..] } else { i }
}

/// Upper bound on a PKCS#8/PKCS#1 RSA-2048 key DER (~1.2 KB in practice).
#[cfg(feature = "rsa")]
const MAX_RSA_KEY_DER: usize = 4096;

/// `(n, e, d)` big-endian components of an RSA private key. `n` is public;
/// `d` sits in a fixed left-padded `Zeroizing` array so the secret never
/// needs a heap allocation (keeps zeroize on its no-alloc feature set).
#[cfg(feature = "rsa")]
type RsaComponents = (Vec<u8>, u32, Zeroizing<[u8; 256]>);

/// Extract `(n, e, d)` from an RSA private key in PKCS#8 (`openssl genpkey`
/// output) or PKCS#1 DER. Only the fields krabitls needs are read; CRT
/// parameters are ignored.
#[cfg(feature = "rsa")]
fn parse_rsa_private_der(der: &[u8]) -> std::result::Result<RsaComponents, String> {
    let mut b = der;
    let (tag, seq) = der_read(&mut b)?;
    if tag != 0x30 {
        return Err(
            "expected DER SEQUENCE (is the key PEM? convert with `openssl pkey -outform der`)"
                .into(),
        );
    }
    let mut s = seq;
    let (t, _version) = der_read(&mut s)?;
    if t != 0x02 {
        return Err("expected version INTEGER".into());
    }
    let (t2, f2) = der_read(&mut s)?;
    let (n_int, mut rest) = match t2 {
        // PKCS#8: AlgorithmIdentifier, then an OCTET STRING wrapping PKCS#1.
        0x30 => {
            let (t3, keyoct) = der_read(&mut s)?;
            if t3 != 0x04 {
                return Err("expected PKCS#8 privateKey OCTET STRING".into());
            }
            let mut kb = keyoct;
            let (t4, kseq) = der_read(&mut kb)?;
            if t4 != 0x30 {
                return Err("expected PKCS#1 SEQUENCE inside PKCS#8".into());
            }
            let mut inner = kseq;
            let (tv, _v) = der_read(&mut inner)?;
            if tv != 0x02 {
                return Err("expected PKCS#1 version INTEGER".into());
            }
            let (tn, n) = der_read(&mut inner)?;
            if tn != 0x02 {
                return Err("expected modulus INTEGER".into());
            }
            (n, inner)
        }
        // PKCS#1: the version INTEGER was already consumed; this is n.
        0x02 => (f2, s),
        _ => return Err("unrecognized RSA key structure".into()),
    };
    let (te, e_int) = der_read(&mut rest)?;
    let (td, d_int) = der_read(&mut rest)?;
    if te != 0x02 || td != 0x02 {
        return Err("expected publicExponent + privateExponent INTEGERs".into());
    }
    let e_bytes = strip_int_sign(e_int);
    if e_bytes.len() > 4 {
        return Err("public exponent exceeds u32".into());
    }
    let mut e = 0u32;
    for &x in e_bytes {
        e = (e << 8) | x as u32;
    }
    let d_bytes = strip_int_sign(d_int);
    let mut d = Zeroizing::new([0u8; 256]);
    if d_bytes.is_empty() || d_bytes.len() > d.len() {
        return Err("private exponent is not a plausible RSA-2048 exponent".into());
    }
    d[256 - d_bytes.len()..].copy_from_slice(d_bytes);
    Ok((strip_int_sign(n_int).to_vec(), e, d))
}

/// Decode `s` (hex, no `0x`) into `out`, which fixes the expected byte count.
fn decode_hex_into(s: &str, out: &mut [u8]) -> std::result::Result<(), String> {
    let bytes = s.as_bytes();
    if bytes.len() != out.len() * 2 {
        return Err(format!(
            "expected {} hex bytes, got {}",
            out.len(),
            bytes.len() / 2
        ));
    }
    for (i, slot) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[i * 2..i * 2 + 2])
            .map_err(|_| format!("non-ASCII byte at offset {}", i * 2))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("bad hex byte at offset {}", i * 2))?;
    }
    Ok(())
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

/// Client-auth material for mutual TLS: the leaf DER sent in the client
/// `Certificate` plus the private key that signs `CertificateVerify`.
// Boxing the 256-byte `d` would put the secret back on the heap — inline is
// the point (one instance per invocation).
#[allow(clippy::large_enum_variant)]
enum ClientAuthMaterial {
    Ed25519 {
        cert_der: Vec<u8>,
        seed: Zeroizing<[u8; 32]>,
    },
    #[cfg(feature = "rsa")]
    Rsa {
        cert_der: Vec<u8>,
        n: Vec<u8>,
        e: u32,
        /// Left-padded to the full RSA-2048 width.
        d: Zeroizing<[u8; 256]>,
    },
}

/// `TcpStream` wrapper that satisfies the facade's `Transport` trait.
struct TcpTransport(TcpStream);

impl Transport for TcpTransport {
    type Error = std::io::Error;

    fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, Self::Error> {
        IoRead::read(&mut self.0, buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::result::Result<(), Self::Error> {
        IoWrite::write_all(&mut self.0, buf)
    }
}

fn run(
    host: &str,
    port: u16,
    pin: Option<&Pin>,
    auth: Option<&ClientAuthMaterial>,
    probe: Probe,
) -> Result<()> {
    let endpoint = format!("{host}:{port}");
    info!("connecting to {endpoint}");
    let tcp = TcpStream::connect(&endpoint)?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;

    let base = if let Some(p) = pin {
        ClientParams::pinned(host, p.as_pinned()).map_err(|e| format!("invalid --pin: {e}"))?
    } else {
        ClientParams::self_signed(host)
    }
    .suite_policy(RuntimeSuitePolicy::Default)
    .clocked(SystemTimeSource);

    // The client-auth policy is a type, so the with-auth and no-auth cases
    // dispatch to distinct monomorphizations of `drive_request` — the no-auth
    // binary never instantiates the certificate path.
    match auth {
        Some(ClientAuthMaterial::Ed25519 { cert_der, seed }) => {
            let signer = Ed25519ClientAuth::from_seed(seed, cert_der)
                .map_err(|_| "invalid --client-seed (Ed25519 key derivation failed)")?;
            info!(
                "client auth enabled (Ed25519, {} byte leaf)",
                cert_der.len()
            );
            drive_request(&base.with_client_auth(&signer), host, tcp, probe)
        }
        #[cfg(feature = "rsa")]
        Some(ClientAuthMaterial::Rsa { cert_der, n, e, d }) => {
            let signer = RsaClientAuth::from_components(n, *e, &d[..], cert_der)
                .map_err(|_| "invalid --client-rsa-key (expected an RSA-2048 key)")?;
            info!(
                "client auth enabled (RSA-{}, {} byte leaf)",
                n.len() * 8,
                cert_der.len()
            );
            drive_request(&base.with_client_auth(&signer), host, tcp, probe)
        }
        None => drive_request(&base, host, tcp, probe),
    }
}

/// Application-layer exchange after the handshake.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Probe {
    /// HTTP/1.0 GET, drain the response.
    Http,
    /// MQTT 3.1.1 CONNECT, expect a CONNACK with return code 0.
    Mqtt,
}

/// Drive the handshake + the selected application probe over a freshly
/// connected socket, generic over the client-auth policy `A`.
fn drive_request<A>(
    params: &ClientParams<'_, ClockedVerify<SystemTimeSource>, A>,
    host: &str,
    tcp: TcpStream,
    probe: Probe,
) -> Result<()>
where
    A: ClientAuthPolicy,
{
    let mut scratch = DefaultScratch::new();
    let mut rng = SysRng;
    let transport = TcpTransport(tcp);

    info!("driving TLS 1.3 handshake via TlsStream");
    let mut tls = match ClockedStream::connect(params, &mut scratch, transport, &mut rng) {
        Ok(s) => s,
        Err(e) => {
            error!("handshake failed: {}", describe_connect_error(&e));
            return Err(format!("handshake: {}", describe_connect_error(&e)).into());
        }
    };
    if probe == Probe::Mqtt {
        info!("handshake OK — sending MQTT CONNECT");
        // MQTT 3.1.1 CONNECT: clean session, keepalive 60 s, client id
        // "krabitls".
        const CONNECT: &[u8] = &[
            0x10, 0x14, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x08,
            b'k', b'r', b'a', b'b', b'i', b't', b'l', b's',
        ];
        tls.write_all(CONNECT)
            .map_err(|e| format!("mqtt CONNECT write: {}", describe_connect_error(&e)))?;
        let mut resp = [0u8; 4];
        let mut got = 0;
        while got < resp.len() {
            match tls.read(&mut resp[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => {
                    return Err(format!("mqtt CONNACK read: {}", describe_connect_error(&e)).into());
                }
            }
        }
        if got < 4 || resp[0] != 0x20 || resp[1] != 0x02 {
            return Err(format!("mqtt: expected CONNACK, got {:02x?}", &resp[..got]).into());
        }
        if resp[3] != 0x00 {
            return Err(format!("mqtt: CONNACK return code {}", resp[3]).into());
        }
        info!("MQTT CONNACK accepted (session_present={})", resp[2] & 1);
        // DISCONNECT, then close_notify.
        tls.write_all(&[0xe0, 0x00])
            .map_err(|e| format!("mqtt DISCONNECT write: {}", describe_connect_error(&e)))?;
        if let Err(e) = tls.close() {
            info!("close: {}", describe_connect_error(&e));
        }
        return Ok(());
    }
    info!("handshake OK — sending HTTP GET");

    // Minimal HTTP/1.0 GET so any server we point at responds.
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: krabitls_connect/0.1\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("write_all: {}", describe_connect_error(&e)))?;

    // Drain the response. Cap to ~64 KiB so we don't run forever on a misbehaving server.
    let mut out = Vec::with_capacity(8192);
    let mut buf = [0u8; 4096];
    let cap: usize = 64 * 1024;
    let mut read_error: Option<String> = None;
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= cap {
                    info!("response cap ({cap} bytes) reached — truncating");
                    break;
                }
            }
            Err(ConnectError::Closed) => break,
            Err(e) => {
                // Surface non-zero exit; break-then-Ok would mask
                // exactly the interop failures the real-world soak
                // is meant to find.
                read_error = Some(format!(
                    "read after {} bytes: {}",
                    out.len(),
                    describe_connect_error(&e)
                ));
                break;
            }
        }
    }

    // close_notify + drain; Drop would do this too but explicit is observable.
    if let Err(e) = tls.close() {
        info!("close: {}", describe_connect_error(&e));
    }

    info!("got {} bytes of app data", out.len());
    if let Some(nl) = out.iter().position(|&b| b == b'\n') {
        let status = core::str::from_utf8(&out[..nl])
            .unwrap_or("<non-utf8>")
            .trim();
        info!("status: {}", status);
    }

    if let Some(e) = read_error {
        return Err(e.into());
    }
    Ok(())
}

fn describe_connect_error(e: &ConnectError<std::io::Error>) -> String {
    format!("{e}")
}

fn parse_host_port(s: &str) -> std::result::Result<(String, u16), String> {
    // IPv6 literals are not supported (no bracket handling).
    if s.is_empty() {
        return Err("host is empty".into());
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if h.is_empty() {
            return Err(format!("host is empty in {s:?}"));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("invalid port in {s:?}: {p:?}"))?;
        return Ok((h.to_string(), port));
    }
    Ok((s.to_string(), 443))
}

fn print_usage() {
    eprintln!(
        "usage: krabitls_connect {{--pin <hex> | --self-signed}} <host>[:<port>]\n\
         \n\
         Drives a TLS 1.3 handshake via krabitls::client::TlsStream and emits an\n\
         HTTP/1.0 GET.\n\
         \n\
         A trust mode must be specified explicitly. There is no CA bundle in\n\
         krabitls, so an unattended no-pin connect would silently trust whatever\n\
         pubkey the peer presents (MITM-vulnerable). Choose one:\n\
         \n\
           --pin <hex>     Pin server pubkey. Length: 32 (Ed25519), 128 (RSA-1024),\n\
                           256 (RSA-2048). Hex without 0x prefix. Use against public\n\
                           CA-issued certs: SAN match + pubkey pin.\n\
           --self-signed   Trust the leaf's outer self-signature. Use against local\n\
                           fixtures / controlled servers whose cert is self-signed.\n\
                           Will reject a chain-rooted (CA-issued) cert.\n\
         \n\
         Optional client authentication (mutual TLS) — --client-cert plus one key:\n\
           --client-cert <path>     Client leaf certificate, DER-encoded.\n\
           --client-seed <hex>      32-byte Ed25519 seed (raw private key) as hex.\n\
           --client-rsa-key <path>  RSA-2048 private key, PKCS#8 or PKCS#1 DER\n\
                                    (needs --features rsa).\n\
         \n\
         Application probe (default: HTTP/1.0 GET):\n\
           --mqtt                 MQTT 3.1.1 CONNECT / CONNACK instead of HTTP.\n"
    );
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1);
    let mut host_arg: Option<String> = None;
    let mut pin: Option<Pin> = None;
    let mut self_signed = false;
    let mut client_cert_path: Option<String> = None;
    let mut client_seed_hex: Option<String> = None;
    let mut client_rsa_key_path: Option<String> = None;
    let mut probe = Probe::Http;
    while let Some(a) = args.next() {
        if a == "--pin" {
            let Some(hex_str) = args.next() else {
                eprintln!("error: --pin requires a value");
                print_usage();
                return ExitCode::from(2);
            };
            match parse_pin(&hex_str) {
                Ok(p) => pin = Some(p),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            }
        } else if a == "--self-signed" {
            self_signed = true;
        } else if a == "--client-cert" {
            let Some(v) = args.next() else {
                eprintln!("error: --client-cert requires a path");
                return ExitCode::from(2);
            };
            client_cert_path = Some(v);
        } else if a == "--client-seed" {
            let Some(v) = args.next() else {
                eprintln!("error: --client-seed requires a hex value");
                return ExitCode::from(2);
            };
            client_seed_hex = Some(v);
        } else if a == "--client-rsa-key" {
            let Some(v) = args.next() else {
                eprintln!("error: --client-rsa-key requires a path");
                return ExitCode::from(2);
            };
            client_rsa_key_path = Some(v);
        } else if a == "--mqtt" {
            probe = Probe::Mqtt;
        } else if a == "--help" || a == "-h" {
            print_usage();
            return ExitCode::SUCCESS;
        } else if host_arg.is_none() {
            host_arg = Some(a);
        } else {
            eprintln!("error: unexpected argument: {a}");
            print_usage();
            return ExitCode::from(2);
        }
    }

    let Some(spec) = host_arg else {
        eprintln!("error: missing host argument");
        print_usage();
        return ExitCode::from(2);
    };
    if pin.is_some() && self_signed {
        eprintln!("error: --pin and --self-signed are mutually exclusive");
        return ExitCode::from(2);
    }
    if pin.is_none() && !self_signed {
        eprintln!(
            "error: no trust mode supplied. Use --pin <hex> (public CA-issued certs)\n\
             or --self-signed (local fixtures). Defaulting to either silently\n\
             would be MITM-vulnerable."
        );
        return ExitCode::from(2);
    }
    let (host, port) = match parse_host_port(&spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let auth = match (client_cert_path, client_seed_hex, client_rsa_key_path) {
        (Some(path), Some(hex), None) => match load_client_auth(&path, &hex) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        #[cfg(feature = "rsa")]
        (Some(path), None, Some(key)) => match load_client_auth_rsa(&path, &key) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        #[cfg(not(feature = "rsa"))]
        (Some(_), None, Some(_)) => {
            eprintln!("error: --client-rsa-key requires building with --features rsa");
            return ExitCode::from(2);
        }
        (None, None, None) => None,
        _ => {
            eprintln!(
                "error: supply --client-cert with exactly one of --client-seed / --client-rsa-key"
            );
            return ExitCode::from(2);
        }
    };

    match run(&host, port, pin.as_ref(), auth.as_ref(), probe) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::from(1)
        }
    }
}
