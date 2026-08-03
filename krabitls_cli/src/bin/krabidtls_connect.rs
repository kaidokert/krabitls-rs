//! DTLS 1.3 (RFC 9147) UDP probe: complete a handshake against a datagram
//! endpoint and exchange one application record.
//!
//! Usage:
//!     krabidtls_connect --pin <hex> host:port [message]
//!
//! `--pin` is the server's 32-byte Ed25519 public key (hex, no `0x`); the trust
//! decision is pin-based, so no SAN/hostname is required — matching test servers
//! (e.g. the wolfSSL example server) whose certificates carry no SAN. `message`
//! defaults to `hello from krabitls`.
//!
//! Host-only: the datagram transport is a `std::net::UdpSocket` with a receive
//! timeout, which drives the DTLS retransmit clock.

use std::net::{ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

use krabitls::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwned};
use krabitls::client::SafeStrategy;
use krabitls::dtls::{DatagramTransport, DtlsStream};

/// `std::net::UdpSocket` as a [`DatagramTransport`]. The socket is connected to
/// one peer and carries a read timeout, so a quiet link surfaces as `Ok(None)`.
struct UdpDatagram(UdpSocket);

impl DatagramTransport for UdpDatagram {
    type Error = std::io::Error;

    fn send(&mut self, datagram: &[u8]) -> Result<(), Self::Error> {
        self.0.send(datagram)?;
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self.0.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars (32 bytes), got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("bad hex byte at {}", i * 2))?;
    }
    Ok(out)
}

fn usage() {
    eprintln!("usage: krabidtls_connect --pin <hex-ed25519-pubkey> host:port [message]");
}

fn run() -> Result<(), String> {
    let mut pin: Option<[u8; 32]> = None;
    let mut endpoint: Option<String> = None;
    let mut message = String::from("hello from krabitls");

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pin" => {
                let v = args.next().ok_or("--pin requires a value")?;
                pin = Some(decode_hex_32(&v).map_err(|e| format!("--pin: {e}"))?);
            }
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            other if endpoint.is_none() => endpoint = Some(other.to_string()),
            other => message = other.to_string(),
        }
    }

    let pin = pin.ok_or("missing --pin <hex>")?;
    let endpoint = endpoint.ok_or("missing host:port")?;
    let remote = endpoint
        .to_socket_addrs()
        .map_err(|e| format!("resolve {endpoint}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {endpoint}"))?;

    let sock = UdpSocket::bind(if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| format!("bind: {e}"))?;
    sock.connect(remote).map_err(|e| format!("connect: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("set_read_timeout: {e}"))?;
    let transport = UdpDatagram(sock);

    let strategy =
        SafeStrategy::<_, DerCert>::new(PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(pin)));

    let mut x25519_priv = [0u8; 32];
    let mut client_random = [0u8; 32];
    getrandom::fill(&mut x25519_priv).map_err(|e| format!("rng: {e}"))?;
    getrandom::fill(&mut client_random).map_err(|e| format!("rng: {e}"))?;

    let mut flight_buf = [0u8; 4096];
    let mut stream = DtlsStream::connect::<_, 4>(
        transport,
        &strategy,
        None,
        &x25519_priv,
        &client_random,
        &mut flight_buf,
    )
    .map_err(|e| format!("handshake: {e:?}"))?;
    log::info!("DTLS 1.3 handshake complete with {remote}");

    let mut out = [0u8; 512];
    stream
        .send(message.as_bytes(), &mut out)
        .map_err(|e| format!("send: {e:?}"))?;
    log::info!("sent {} bytes", message.len());

    let mut buf = [0u8; 2048];
    match stream.recv(&mut buf).map_err(|e| format!("recv: {e:?}"))? {
        Some(n) => {
            println!("reply ({n} bytes): {}", String::from_utf8_lossy(&buf[..n]));
            Ok(())
        }
        None => Err("no reply before timeout".into()),
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            usage();
            ExitCode::FAILURE
        }
    }
}
