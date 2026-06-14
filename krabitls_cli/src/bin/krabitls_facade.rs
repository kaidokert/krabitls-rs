//! `krabitls_facade` — TCP TLS 1.3 demo on the high-level facade.
//!
//! **NOT production-ready.** No cert chain walking, no CA bundle.
//!
//! Usage:
//!     cargo run --bin krabitls_facade --features rsa -- example.com
//!     cargo run --bin krabitls_facade --features rsa -- example.com:443
//!     cargo run --bin krabitls_facade --features rsa -- --pin HEX  HOST

use std::error::Error;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use krabitls::client::{
    ClientParams, ConnectError, DefaultScratch, DefaultStream, RuntimeSuitePolicy, Transport,
};
use log::{error, info};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// ============================================================================
// CLI args + pin parsing
// ============================================================================

enum Pin {
    Ed25519([u8; 32]),
    #[allow(dead_code)] // only used under feature = "rsa"
    Rsa(Vec<u8>),
}

impl Pin {
    fn as_pinned(&self) -> krabitls::PinnedPubkey<'_> {
        use krabitls::PinnedPubkey;
        match self {
            Pin::Ed25519(pk) => PinnedPubkey::Ed25519(*pk),
            #[cfg(feature = "rsa")]
            Pin::Rsa(modulus) => PinnedPubkey::Rsa {
                modulus,
                exponent: 65537,
            },
            #[cfg(not(feature = "rsa"))]
            Pin::Rsa(_) => panic!("RSA pin requires feature = \"rsa\""),
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

// ============================================================================
// RNG adapter — wrap `getrandom` as a `rand_core::CryptoRng`.
// ============================================================================

/// OS-backed RNG. `getrandom::fill` is the only randomness source.
struct OsRng;

impl rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).expect("OS RNG failed");
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        getrandom::fill(&mut buf).expect("OS RNG failed");
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG failed");
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

// ============================================================================
// Transport adapter — `std::net::TcpStream` -> `krabitls::client::Transport`.
// ============================================================================

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

// ============================================================================
// Main flow
// ============================================================================

fn run(host: &str, port: u16, pin: Option<&Pin>) -> Result<()> {
    let endpoint = format!("{host}:{port}");
    info!("connecting to {endpoint}");
    let tcp = TcpStream::connect(&endpoint)?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;

    let mut scratch = DefaultScratch::new();
    let params = if let Some(p) = pin {
        ClientParams::pinned(host, p.as_pinned())
    } else {
        ClientParams::self_signed(host)
    }
    .suite_policy(RuntimeSuitePolicy::Default);

    let mut rng = OsRng;
    let transport = TcpTransport(tcp);

    info!("driving TLS 1.3 handshake via TlsStream");
    let mut tls = match DefaultStream::connect(&params, &mut scratch, transport, &mut rng) {
        Ok(s) => s,
        Err(e) => {
            error!("handshake failed: {}", describe_connect_error(&e));
            return Err(format!("handshake: {}", describe_connect_error(&e)).into());
        }
    };
    info!("handshake OK — sending HTTP GET");

    // Minimal HTTP/1.0 GET so any server we point at responds.
    let req = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: krabitls_facade/0.1\r\nConnection: close\r\n\r\n"
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

fn parse_host_port(s: &str) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.to_string(), port);
    }
    (s.to_string(), 443)
}

fn print_usage() {
    eprintln!(
        "usage: krabitls_facade [--pin <hex>] <host>[:<port>]\n\
         \n\
         Drives a TLS 1.3 handshake via krabitls::client::TlsStream and emits an\n\
         HTTP/1.0 GET. Sibling of krabitls_connect; intended as the canonical\n\
         end-to-end exercise of the facade.\n\
         \n\
         Options:\n\
           --pin <hex>    Pin server pubkey. Length: 32 (Ed25519), 128 (RSA-1024),\n\
                          256 (RSA-2048). Hex without 0x prefix.\n"
    );
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut args = std::env::args().skip(1);
    let mut host_arg: Option<String> = None;
    let mut pin: Option<Pin> = None;
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
    let (host, port) = parse_host_port(&spec);

    match run(&host, port, pin.as_ref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::from(1)
        }
    }
}
