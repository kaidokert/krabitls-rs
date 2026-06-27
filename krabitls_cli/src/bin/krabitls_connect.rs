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

fn load_client_auth(
    cert_path: &str,
    seed_hex: &str,
) -> std::result::Result<ClientAuthMaterial, String> {
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
    // Decode straight into the fixed `Zeroizing` array — the raw seed never
    // touches an intermediate heap buffer.
    let mut seed = Zeroizing::new([0u8; 32]);
    decode_hex_into(seed_hex, &mut seed[..]).map_err(|e| format!("--client-seed: {e}"))?;
    Ok(ClientAuthMaterial { cert_der, seed })
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
/// `Certificate` and the 32-byte Ed25519 seed that signs `CertificateVerify`.
struct ClientAuthMaterial {
    cert_der: Vec<u8>,
    seed: Zeroizing<[u8; 32]>,
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

fn run(host: &str, port: u16, pin: Option<&Pin>, auth: Option<&ClientAuthMaterial>) -> Result<()> {
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
        Some(m) => {
            let signer = Ed25519ClientAuth::from_seed(&m.seed, &m.cert_der)
                .map_err(|_| "invalid --client-seed (Ed25519 key derivation failed)")?;
            info!(
                "client auth enabled (Ed25519, {} byte leaf)",
                m.cert_der.len()
            );
            drive_request(&base.with_client_auth(&signer), host, tcp)
        }
        None => drive_request(&base, host, tcp),
    }
}

/// Drive the handshake + an HTTP/1.0 GET over a freshly connected socket,
/// generic over the client-auth policy `A`.
fn drive_request<A>(
    params: &ClientParams<'_, ClockedVerify<SystemTimeSource>, A>,
    host: &str,
    tcp: TcpStream,
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
         Optional client authentication (mutual TLS), supplied together:\n\
           --client-cert <path>   Client leaf certificate, DER-encoded.\n\
           --client-seed <hex>    32-byte Ed25519 seed (raw private key) as hex.\n"
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

    let auth = match (client_cert_path, client_seed_hex) {
        (Some(path), Some(hex)) => match load_client_auth(&path, &hex) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        (None, None) => None,
        _ => {
            eprintln!("error: --client-cert and --client-seed must be supplied together");
            return ExitCode::from(2);
        }
    };

    match run(&host, port, pin.as_ref(), auth.as_ref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::from(1)
        }
    }
}
