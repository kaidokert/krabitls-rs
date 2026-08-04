//! DTLS 1.3 (RFC 9147) CoAP probe: complete a handshake against a coaps://
//! endpoint and GET one CoAP resource (coap-lite codec over the DTLS channel).
//!
//! Usage:
//!     krabidtls_connect {--pin <hex> | --self-signed} host:port [coap-path]
//!
//! `--pin` is the server's public key (hex, no `0x`) — 32 B Ed25519, 65/97 B
//! ECDSA, or 128/256 B RSA modulus; `--self-signed` trusts any self-signed leaf
//! (TOFU). Trust is pin/TOFU-based, so no SAN/hostname is required — matching test
//! servers whose certificates carry no SAN. The CoAP path defaults to
//! `/.well-known/core`.
//!
//! The datagram transport is an [`embedded_nal::UdpClientStack`] socket
//! (`std-embedded-nal` on the host), mirroring how the TLS binary drives a
//! `TcpClientStack`. The NAL `receive` is non-blocking, so [`NalDatagram::recv`]
//! polls it to a wall-clock deadline — that timeout is the DTLS retransmit clock.
//! Host-only for that clock and the system stack.

use std::net::ToSocketAddrs;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use coap_lite::{CoapOption, MessageClass, MessageType, Packet, RequestType};
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

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err("hex must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| format!("bad hex byte at {i}")))
        .collect()
}

/// Parse a `--pin` hex string into a pinned key, dispatching on length:
/// 32 = Ed25519, 65/97 = ECDSA P-256/P-384, 128/256 = RSA modulus (exp 65537).
/// Non-Ed25519 lengths require the matching build feature.
fn parse_pin(hex: &str) -> Result<PinnedPubkeyOwned, String> {
    let b = decode_hex(hex)?;
    match b.len() {
        32 => Ok(PinnedPubkeyOwned::ed25519(b.try_into().unwrap())),
        #[cfg(feature = "ecdsa")]
        65 => Ok(PinnedPubkeyOwned::ecdsa_p256(b.try_into().unwrap())),
        #[cfg(feature = "ecdsa")]
        97 => Ok(PinnedPubkeyOwned::ecdsa_p384(b.try_into().unwrap())),
        #[cfg(feature = "rsa")]
        128 | 256 | 384 | 512 => {
            PinnedPubkeyOwned::rsa(&b, 65537).map_err(|_| "RSA modulus too long".to_string())
        }
        n => Err(format!(
            "unexpected pin length {n} bytes (want 32 Ed25519; 65/97 ECDSA; 128/256 RSA, \
             with the matching feature built)"
        )),
    }
}

fn usage() {
    eprintln!(
        "usage: krabidtls_connect {{--pin <hex> | --self-signed}} host:port [coap-path]\n\
         \x20 --pin <hex>    server pubkey to pin: 32 (Ed25519), 65/97 (ECDSA), 128/256 (RSA)\n\
         \x20 --self-signed  trust any self-signed leaf (TOFU; dev only)\n\
         \x20 --cid <hex>    advertise an RFC 9146 connection id\n\
         \x20 coap-path      CoAP resource to GET (default /.well-known/core)"
    );
}

fn run() -> Result<(), String> {
    let mut pin: Option<PinnedPubkeyOwned> = None;
    let mut self_signed = false;
    let mut cid: Option<Vec<u8>> = None;
    let mut endpoint: Option<String> = None;
    let mut path = String::from("/.well-known/core");

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pin" => {
                let v = args.next().ok_or("--pin requires a value")?;
                pin = Some(parse_pin(&v).map_err(|e| format!("--pin: {e}"))?);
            }
            "--self-signed" => self_signed = true,
            "--cid" => {
                let v = args.next().ok_or("--cid requires a value")?;
                cid = Some(decode_hex(&v).map_err(|e| format!("--cid: {e}"))?);
            }
            "-h" | "--help" => {
                usage();
                return Ok(());
            }
            other if endpoint.is_none() => endpoint = Some(other.to_string()),
            other => path = other.to_string(),
        }
    }

    let decision = match (self_signed, pin) {
        (false, Some(p)) => PinOrSelfSigned::pinned(p),
        (true, None) => PinOrSelfSigned::self_signed(),
        (true, Some(_)) => return Err("--pin and --self-signed are mutually exclusive".into()),
        (false, None) => return Err("need --pin <hex> or --self-signed".into()),
    };
    let endpoint = endpoint.ok_or("missing host:port")?;
    let remote = endpoint
        .to_socket_addrs()
        .map_err(|e| format!("resolve {endpoint}: {e}"))?
        .next()
        .ok_or_else(|| format!("no address for {endpoint}"))?;

    let mut stack = std_embedded_nal::Stack;
    let transport =
        NalDatagram::open(&mut stack, remote).map_err(|e| format!("udp connect: {e}"))?;

    let strategy = SafeStrategy::<_, DerCert>::new(decision);

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
        cid.as_deref(),
        &x25519_priv,
        &client_random,
        &mut flight_buf,
        &mut reasm_buf,
    )
    .map_err(|e| format!("handshake: {e:?}"))?;
    log::info!(
        "DTLS 1.3 handshake complete with {remote}{}",
        if cid.is_some() {
            " (CID advertised)"
        } else {
            ""
        }
    );

    coap_get(&mut stream, &path)
}

/// Send a CoAP CON GET for `path` over the DTLS stream and print the response.
/// The DTLS app-data channel is the transport; coap-lite is just the codec.
fn coap_get<T: DatagramTransport>(stream: &mut DtlsStream<T>, path: &str) -> Result<(), String>
where
    T::Error: core::fmt::Debug,
{
    let mut req = Packet::new();
    req.header.set_type(MessageType::Confirmable);
    req.header.code = MessageClass::Request(RequestType::Get);
    req.header.message_id = 0x4b54; // 'KT'
    req.set_token(vec![0xde, 0xad, 0xbe, 0xef]);
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        req.add_option(CoapOption::UriPath, seg.as_bytes().to_vec());
    }
    let req_bytes = req.to_bytes().map_err(|e| format!("coap encode: {e:?}"))?;

    let mut out = vec![0u8; req_bytes.len() + 64];
    stream
        .send(&req_bytes, &mut out)
        .map_err(|e| format!("send: {e:?}"))?;
    log::info!("sent CoAP GET {path} ({} bytes)", req_bytes.len());

    // A CON request may get a piggybacked response, or an empty ACK followed by
    // a separate response; skip a bare ACK and take the first real message.
    let mut buf = [0u8; 2048];
    for _ in 0..4 {
        let n = stream
            .recv(&mut buf)
            .map_err(|e| format!("recv: {e:?}"))?
            .ok_or("no CoAP response before timeout")?;
        let resp = Packet::from_bytes(&buf[..n]).map_err(|e| format!("coap decode: {e:?}"))?;
        if resp.header.code == MessageClass::Empty {
            continue; // bare ACK; the response follows separately
        }
        let b = u8::from(resp.header.code);
        println!(
            "CoAP {}.{:02}  ({} B payload): {}",
            b >> 5,
            b & 0x1f,
            resp.payload.len(),
            String::from_utf8_lossy(&resp.payload)
        );
        return Ok(());
    }
    Err("only empty ACKs received".into())
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
