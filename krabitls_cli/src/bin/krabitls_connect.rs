//! `krabitls_connect` — the krabitls TLS 1.3 client, driven over `embedded-nal`.
//!
//! The transport is an [`embedded_nal::TcpClientStack`]; here the concrete stack
//! is `std-embedded-nal` (host `std::net`). The same `krabitls_cli::connect`
//! and the `http` / `mqtt` probes run on any target NAL stack unchanged.
//!
//! Usage:
//!     krabitls_connect --self-signed example.com
//!     krabitls_connect --pin <hex> example.com:443
//!     krabitls_connect --self-signed --mqtt test.mosquitto.org:8883
//!     krabitls_connect --self-signed --client-cert leaf.der --client-seed <hex> host

#[cfg(feature = "rsa")]
use std::io::Read as IoRead;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use getrandom::SysRng;
#[cfg(feature = "rsa")]
use krabitls::client::RsaClientAuth;
use krabitls::client::{
    ClientAuthPolicy, ClientParams, ClockedVerify, DefaultScratch, Ed25519ClientAuth,
    MAX_CLIENT_CERT_DER, PinnedPubkey, RuntimeSuitePolicy, TimeSource,
};
use krabitls_cli::{connect, http, mqtt, resolve};
use log::{error, info};
use std_embedded_nal::Stack;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;

/// Host wall clock — enables the cert validity-window check.
struct SystemTimeSource;
impl TimeSource for SystemTimeSource {
    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Probe {
    Http,
    Mqtt,
}

// ------------------------------------------------------------------ pinning

enum Pin {
    Ed25519([u8; 32]),
    #[cfg(feature = "rsa")]
    Rsa(Vec<u8>),
    #[cfg(feature = "ecdsa")]
    EcdsaP256([u8; 65]),
    #[cfg(feature = "ecdsa")]
    EcdsaP384([u8; 97]),
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
            #[cfg(feature = "ecdsa")]
            Pin::EcdsaP256(pk) => PinnedPubkey::EcdsaP256(*pk),
            #[cfg(feature = "ecdsa")]
            Pin::EcdsaP384(pk) => PinnedPubkey::EcdsaP384(*pk),
        }
    }
}

fn parse_pin(hex_str: &str) -> Result<Pin> {
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
        65 => {
            #[cfg(feature = "ecdsa")]
            {
                if bytes[0] != 0x04 {
                    return Err("ECDSA P-256 pin must be a SEC1 uncompressed point (0x04)".into());
                }
                let mut pk = [0u8; 65];
                pk.copy_from_slice(&bytes);
                Ok(Pin::EcdsaP256(pk))
            }
            #[cfg(not(feature = "ecdsa"))]
            Err("ECDSA P-256 pin requires building with --features ecdsa".into())
        }
        97 => {
            #[cfg(feature = "ecdsa")]
            {
                if bytes[0] != 0x04 {
                    return Err("ECDSA P-384 pin must be a SEC1 uncompressed point (0x04)".into());
                }
                let mut pk = [0u8; 97];
                pk.copy_from_slice(&bytes);
                Ok(Pin::EcdsaP384(pk))
            }
            #[cfg(not(feature = "ecdsa"))]
            Err("ECDSA P-384 pin requires building with --features ecdsa".into())
        }
        n => Err(format!(
            "--pin: expected 32 (Ed25519), 65 (ECDSA P-256), 97 (ECDSA P-384), \
             128 (RSA-1024), or 256 (RSA-2048) bytes, got {n}"
        )),
    }
}

// -------------------------------------------------------------- client auth

/// Client-auth material for mutual TLS: the leaf DER sent in the client
/// `Certificate` plus the private key that signs `CertificateVerify`.
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
        d: Zeroizing<[u8; 256]>,
    },
}

fn load_client_cert(cert_path: &str) -> Result<Vec<u8>> {
    let cert_der =
        std::fs::read(cert_path).map_err(|e| format!("--client-cert {cert_path:?}: {e}"))?;
    if cert_der.is_empty() {
        return Err(format!("--client-cert {cert_path:?}: empty file"));
    }
    if cert_der.len() > MAX_CLIENT_CERT_DER {
        return Err(format!(
            "--client-cert {cert_path:?}: {} bytes exceeds the {MAX_CLIENT_CERT_DER}-byte buffer",
            cert_der.len()
        ));
    }
    Ok(cert_der)
}

fn load_client_auth_ed25519(cert_path: &str, seed_hex: &str) -> Result<ClientAuthMaterial> {
    let cert_der = load_client_cert(cert_path)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    decode_hex_into(seed_hex, &mut seed[..]).map_err(|e| format!("--client-seed: {e}"))?;
    Ok(ClientAuthMaterial::Ed25519 { cert_der, seed })
}

#[cfg(feature = "rsa")]
fn load_client_auth_rsa(cert_path: &str, key_path: &str) -> Result<ClientAuthMaterial> {
    let cert_der = load_client_cert(cert_path)?;
    // Exact-size read into a fixed `Zeroizing` buffer (no heap for the key).
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

// ------------------------------------------------------- RSA private-key DER

/// Upper bound on a PKCS#8/PKCS#1 RSA-2048 key DER (~1.2 KB in practice).
#[cfg(feature = "rsa")]
const MAX_RSA_KEY_DER: usize = 4096;

/// `(n, e, d)` big-endian components; `d` sits in a fixed left-padded
/// `Zeroizing` array so the secret never needs a heap allocation.
#[cfg(feature = "rsa")]
type RsaComponents = (Vec<u8>, u32, Zeroizing<[u8; 256]>);

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

/// Extract `(n, e, d)` from an RSA private key in PKCS#8 or PKCS#1 DER.
#[cfg(feature = "rsa")]
fn parse_rsa_private_der(der: &[u8]) -> std::result::Result<RsaComponents, String> {
    let mut b = der;
    let (tag, seq) = der_read(&mut b)?;
    if tag != 0x30 {
        return Err("expected DER SEQUENCE (convert with `openssl pkey -outform der`)".into());
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

// ---------------------------------------------------------------- hex utils

fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len() & 1 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..bytes.len())
        .step_by(2)
        .map(|i| {
            let pair =
                std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| format!("non-ASCII at {i}"))?;
            u8::from_str_radix(pair, 16).map_err(|_| format!("bad hex byte at {i}"))
        })
        .collect()
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
            .map_err(|_| format!("non-ASCII at {}", i * 2))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| format!("bad hex byte at {}", i * 2))?;
    }
    Ok(())
}

// ----------------------------------------------------------------- driving

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    if s.is_empty() {
        return Err("host is empty".into());
    }
    // IPv6 literals are not supported (no bracket handling).
    if let Some((h, p)) = s.rsplit_once(':') {
        if h.is_empty() {
            return Err(format!("host is empty in {s:?}"));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("invalid port in {s:?}"))?;
        return Ok((h.to_string(), port));
    }
    Ok((s.to_string(), 443))
}

fn run(
    host: &str,
    port: u16,
    pin: Option<&Pin>,
    auth: Option<&ClientAuthMaterial>,
    probe: Probe,
    middlebox_compat: bool,
    alpn: &[&[u8]],
) -> Result<()> {
    let mut stack = Stack;
    let addr = resolve(&mut stack, host, port).map_err(|e| format!("resolve {host}: {e:?}"))?;
    info!("connecting to {addr}");

    let mut base = if let Some(p) = pin {
        ClientParams::pinned(host, p.as_pinned()).map_err(|e| format!("invalid --pin: {e}"))?
    } else {
        ClientParams::self_signed(host)
    }
    .suite_policy(RuntimeSuitePolicy::Default)
    .clocked(SystemTimeSource)
    .middlebox_compat(middlebox_compat);
    if !alpn.is_empty() {
        base = base.alpn(alpn);
    }

    // The client-auth policy is a type, so with-auth and no-auth dispatch to
    // distinct monomorphizations — the no-auth binary never links the cert path.
    match auth {
        Some(ClientAuthMaterial::Ed25519 { cert_der, seed }) => {
            let signer = Ed25519ClientAuth::from_seed(seed, cert_der)
                .map_err(|_| "invalid --client-seed (Ed25519 key derivation failed)")?;
            info!("client auth: Ed25519, {} byte leaf", cert_der.len());
            drive(
                &mut stack,
                addr,
                &base.with_client_auth(&signer),
                host,
                probe,
            )
        }
        #[cfg(feature = "rsa")]
        Some(ClientAuthMaterial::Rsa { cert_der, n, e, d }) => {
            let signer = RsaClientAuth::from_components(n, *e, &d[..], cert_der)
                .map_err(|_| "invalid --client-rsa-key (expected an RSA-2048 key)")?;
            info!(
                "client auth: RSA-{}, {} byte leaf",
                n.len() * 8,
                cert_der.len()
            );
            drive(
                &mut stack,
                addr,
                &base.with_client_auth(&signer),
                host,
                probe,
            )
        }
        None => drive(&mut stack, addr, &base, host, probe),
    }
}

fn drive<A>(
    stack: &mut Stack,
    addr: core::net::SocketAddr,
    params: &ClientParams<'_, ClockedVerify<SystemTimeSource>, A>,
    host: &str,
    probe: Probe,
) -> Result<()>
where
    A: ClientAuthPolicy,
{
    let mut scratch = DefaultScratch::new();
    let mut rng = SysRng;

    info!("driving TLS 1.3 handshake over embedded-nal");
    let mut tls = connect(stack, addr, params, &mut scratch, &mut rng)
        .map_err(|e| format!("handshake: {e:?}"))?;

    match probe {
        Probe::Http => {
            let mut buf = [0u8; 16384];
            let resp =
                http::get(&mut tls, host, "/", &mut buf).map_err(|e| format!("http: {e:?}"))?;
            info!(
                "status {} — {} body bytes{}",
                resp.status,
                resp.body.len(),
                if resp.truncated { " (truncated)" } else { "" }
            );
        }
        Probe::Mqtt => {
            let session_present =
                mqtt::connect_probe(&mut tls).map_err(|e| format!("mqtt: {e:?}"))?;
            info!("MQTT CONNACK accepted (session_present={session_present})");
        }
    }
    let _ = tls.close();
    Ok(())
}

fn print_usage() {
    eprintln!(
        "usage: krabitls_connect {{--pin <hex> | --self-signed}} [--mqtt] \\\n\
         \x20             [--client-cert <der> {{--client-seed <hex> | --client-rsa-key <der>}}] \\\n\
         \x20             [--alpn <name>]... [--middlebox-compat] <host>[:<port>]\n\
         \n\
         krabitls TLS 1.3 client over embedded-nal (std-embedded-nal on host).\n\
         \n\
           --pin <hex>     Pin server pubkey: 32 (Ed25519), 65/97 (ECDSA),\n\
                           128/256 (RSA) bytes, hex without 0x.\n\
           --self-signed   Trust the leaf's self-signature (local fixtures).\n\
           --mqtt          MQTT 3.1.1 CONNECT/CONNACK instead of HTTP GET.\n\
           --client-cert   Client leaf cert (DER) for mutual TLS, plus one key:\n\
           --client-seed   32-byte Ed25519 seed (hex), or\n\
           --client-rsa-key  RSA-2048 private key DER (needs --features rsa).\n\
         \n\
         A trust mode is required — an unattended no-pin connect is\n\
         MITM-vulnerable (krabitls has no CA bundle)."
    );
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut host_arg: Option<String> = None;
    let mut pin: Option<Pin> = None;
    let mut self_signed = false;
    let mut probe = Probe::Http;
    let mut client_cert: Option<String> = None;
    let mut client_seed: Option<String> = None;
    let mut client_rsa_key: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();
    let mut middlebox_compat = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        macro_rules! value {
            ($flag:literal) => {{
                let Some(v) = args.next() else {
                    eprintln!(concat!("error: ", $flag, " requires a value"));
                    return ExitCode::from(2);
                };
                v
            }};
        }
        match a.as_str() {
            "--pin" => match parse_pin(&value!("--pin")) {
                Ok(p) => pin = Some(p),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            },
            "--self-signed" => self_signed = true,
            "--mqtt" => probe = Probe::Mqtt,
            "--client-cert" => client_cert = Some(value!("--client-cert")),
            "--client-seed" => client_seed = Some(value!("--client-seed")),
            "--client-rsa-key" => client_rsa_key = Some(value!("--client-rsa-key")),
            "--alpn" => alpn.push(value!("--alpn")),
            "--middlebox-compat" => middlebox_compat = true,
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            _ if host_arg.is_none() => host_arg = Some(a),
            _ => {
                eprintln!("error: unexpected argument: {a}");
                print_usage();
                return ExitCode::from(2);
            }
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
        eprintln!("error: no trust mode; use --pin <hex> or --self-signed");
        return ExitCode::from(2);
    }

    let auth = match (client_cert, client_seed, client_rsa_key) {
        (None, None, None) => None,
        (Some(cert), Some(seed), None) => match load_client_auth_ed25519(&cert, &seed) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        },
        #[cfg(feature = "rsa")]
        (Some(cert), None, Some(key)) => match load_client_auth_rsa(&cert, &key) {
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
        _ => {
            eprintln!("error: --client-cert needs exactly one of --client-seed / --client-rsa-key");
            return ExitCode::from(2);
        }
    };

    let (host, port) = match parse_host_port(&spec) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // embedded-nal has no timeout concept (a target bounds I/O with its own
    // timer); the old std client set a 15 s socket timeout. Restore a bounded
    // wait at the host level with a wall-clock watchdog so an unresponsive peer
    // can't hang the CLI — `nb::block!` in the transport would otherwise spin
    // forever.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let alpn_refs: Vec<&[u8]> = alpn.iter().map(|s| s.as_bytes()).collect();
        let _ = tx.send(run(
            &host,
            port,
            pin.as_ref(),
            auth.as_ref(),
            probe,
            middlebox_compat,
            &alpn_refs,
        ));
    });
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            error!("{e}");
            ExitCode::from(1)
        }
        Err(_) => {
            error!("no response within 30s — aborting");
            ExitCode::from(1)
        }
    }
}
