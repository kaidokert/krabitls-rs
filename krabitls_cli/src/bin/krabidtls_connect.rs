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
//! The datagram transport is an [`embedded_nal::UdpClientStack`] socket
//! (`std-embedded-nal` on the host), mirroring how the TLS binary drives a
//! `TcpClientStack`. The NAL `receive` is non-blocking, so [`NalDatagram::recv`]
//! polls it to a wall-clock deadline — that timeout is the DTLS retransmit clock.
//! Host-only for that clock and the system stack.

use std::net::ToSocketAddrs;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use embedded_nal::{UdpClientStack, nb};
use krabitls::backends::{DerCert, PinOrSelfSigned, PinnedPubkeyOwned};
use krabitls::client::SafeStrategy;
use krabitls::dtls::{DatagramTransport, DtlsStream};

/// One receive timeout, the DTLS retransmit interval.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);
/// Poll interval while waiting on the non-blocking NAL `receive`.
const POLL_INTERVAL: Duration = Duration::from_millis(2);

/// A connected [`embedded_nal::UdpClientStack`] socket as a
/// [`DatagramTransport`]. The stack's `receive` is `nb`, so `recv` polls it until
/// a datagram arrives or the timeout elapses (`Ok(None)`).
struct NalDatagram<'a, S: UdpClientStack> {
    stack: &'a mut S,
    socket: Option<S::UdpSocket>,
}

impl<'a, S: UdpClientStack> NalDatagram<'a, S> {
    fn open(stack: &'a mut S, remote: std::net::SocketAddr) -> Result<Self, S::Error> {
        let mut socket = stack.socket()?;
        if let Err(e) = stack.connect(&mut socket, remote) {
            let _ = stack.close(socket);
            return Err(e);
        }
        Ok(Self {
            stack,
            socket: Some(socket),
        })
    }
}

impl<S: UdpClientStack> DatagramTransport for NalDatagram<'_, S> {
    type Error = S::Error;

    fn send(&mut self, datagram: &[u8]) -> Result<(), Self::Error> {
        let socket = self
            .socket
            .as_mut()
            .expect("socket lives for the transport");
        nb::block!(self.stack.send(socket, datagram))
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        let deadline = Instant::now() + RECV_TIMEOUT;
        loop {
            let socket = self
                .socket
                .as_mut()
                .expect("socket lives for the transport");
            match self.stack.receive(socket, buf) {
                Ok((n, _peer)) => return Ok(Some(n)),
                Err(nb::Error::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(nb::Error::Other(e)) => return Err(e),
            }
        }
    }
}

impl<S: UdpClientStack> Drop for NalDatagram<'_, S> {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            let _ = self.stack.close(socket);
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

    let mut stack = std_embedded_nal::Stack;
    let transport =
        NalDatagram::open(&mut stack, remote).map_err(|e| format!("udp connect: {e}"))?;

    let strategy =
        SafeStrategy::<_, DerCert>::new(PinOrSelfSigned::pinned(PinnedPubkeyOwned::ed25519(pin)));

    let mut x25519_priv = [0u8; 32];
    let mut client_random = [0u8; 32];
    getrandom::fill(&mut x25519_priv).map_err(|e| format!("rng: {e}"))?;
    getrandom::fill(&mut client_random).map_err(|e| format!("rng: {e}"))?;

    let mut flight_buf = [0u8; 8192];
    let mut reasm_buf = [0u8; 8192];
    let mut stream = DtlsStream::connect::<_, 4>(
        transport,
        &strategy,
        None,
        &x25519_priv,
        &client_random,
        &mut flight_buf,
        &mut reasm_buf,
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
