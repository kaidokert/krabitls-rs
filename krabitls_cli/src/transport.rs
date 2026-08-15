//! [`embedded-nal`](embedded_nal) → krabitls transport bridge.
//!
//! [`NalTransport`] presents a connected [`embedded_nal::TcpClientStack`] socket
//! as an [`embedded_io::Read`] + [`embedded_io::Write`] byte stream, so the
//! [`http`](crate::http) / [`mqtt`](crate::mqtt) probes can run over it directly
//! (plaintext) and krabitls's blanket `Transport` impl applies for the blocking
//! handshake. [`PollNal`] wraps it for the TLS path and overrides
//! [`read_nb`](krabitls::client::Transport::read_nb): the NAL stack's `receive`
//! is already `nb`, so a `WouldBlock` becomes `Ok(None)` instead of the blocking
//! spin, which is what gives a caller a non-blocking
//! [`TlsStream::try_read`](krabitls::client::TlsStream::try_read).

use core::net::{IpAddr, SocketAddr};

use embedded_io::{ErrorKind, ErrorType};
use embedded_nal::{AddrType, Dns, TcpClientStack};
use krabitls::client::{
    ClientAuthSign, ClientConfig, ClientParams, ConnectError, DefaultConfig, DefaultScratch,
    DefaultStreamWith, Transport, VerifyStrategy,
};

const SOCKET_LIVE: &str = "socket is present for the whole stream lifetime";

/// Transport error: a NAL stack error, adapted to [`embedded_io::Error`].
#[derive(Debug)]
pub struct NalError<E>(pub E);

impl<E: core::fmt::Debug> core::fmt::Display for NalError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NAL transport error: {:?}", self.0)
    }
}

impl<E: core::fmt::Debug> core::error::Error for NalError<E> {}

impl<E: core::fmt::Debug> embedded_io::Error for NalError<E> {
    fn kind(&self) -> ErrorKind {
        ErrorKind::Other
    }
}

/// A connected [`embedded_nal::TcpClientStack`] socket as an [`embedded_io`]
/// stream.
///
/// The NAL model inverts stream ownership — the *stack* performs socket ops and
/// the socket handle is passed in — so this bundles a stack borrow with its
/// socket. `nb::WouldBlock` is retried in place; the socket is released back to
/// the stack on drop.
pub struct NalTransport<'a, S: TcpClientStack> {
    stack: &'a mut S,
    socket: Option<S::TcpSocket>,
}

impl<'a, S: TcpClientStack> NalTransport<'a, S> {
    /// Open a socket on `stack` and connect it to `remote`.
    pub fn open(stack: &'a mut S, remote: SocketAddr) -> Result<Self, NalError<S::Error>> {
        let mut socket = stack.socket().map_err(NalError)?;
        if let Err(e) = nb::block!(stack.connect(&mut socket, remote)) {
            // No `NalTransport` exists yet, so `Drop` won't run — hand the
            // socket back explicitly. On stacks with a fixed handle pool, a
            // dropped-but-unclosed socket leaks a slot.
            let _ = stack.close(socket);
            return Err(NalError(e));
        }
        Ok(Self {
            stack,
            socket: Some(socket),
        })
    }

    /// The live socket handle (e.g. to inspect a test double's captured TX).
    pub fn socket(&self) -> &S::TcpSocket {
        self.socket.as_ref().expect(SOCKET_LIVE)
    }
}

impl<S: TcpClientStack> ErrorType for NalTransport<'_, S> {
    type Error = NalError<S::Error>;
}

impl<S: TcpClientStack> embedded_io::Read for NalTransport<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // `block!` returns on `Ok(n)` — including `Ok(0)`, EOF — and only spins
        // on `WouldBlock`.
        nb::block!(
            self.stack
                .receive(self.socket.as_mut().expect(SOCKET_LIVE), buf)
        )
        .map_err(NalError)
    }
}

impl<S: TcpClientStack> embedded_io::Write for NalTransport<'_, S> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        nb::block!(
            self.stack
                .send(self.socket.as_mut().expect(SOCKET_LIVE), buf)
        )
        .map_err(NalError)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<S: TcpClientStack> Drop for NalTransport<'_, S> {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            let _ = self.stack.close(socket);
        }
    }
}

/// Non-blocking `Transport` wrapper over [`NalTransport`] used for the TLS
/// path. It keeps the blocking `read`/`write_all` but overrides
/// [`read_nb`](krabitls::client::Transport::read_nb) to surface the NAL stack's
/// `WouldBlock` as `Ok(None)` — the hook for
/// [`TlsStream::try_read`](krabitls::client::TlsStream::try_read). A bare
/// `NalTransport` stays an `embedded_io::Read + Write` adapter (blocking
/// `Transport` via the blanket) so the plaintext [`http`](crate::http) /
/// [`mqtt`](crate::mqtt) probes still run directly over it.
pub struct PollNal<'a, S: TcpClientStack>(NalTransport<'a, S>);

impl<'a, S: TcpClientStack> PollNal<'a, S> {
    /// Wrap a connected [`NalTransport`].
    pub fn new(inner: NalTransport<'a, S>) -> Self {
        Self(inner)
    }

    /// The live socket handle (e.g. to inspect a test double's captured TX).
    pub fn socket(&self) -> &S::TcpSocket {
        self.0.socket()
    }
}

impl<S: TcpClientStack> Transport for PollNal<'_, S> {
    type Error = NalError<S::Error>;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        embedded_io::Read::read(&mut self.0, buf)
    }

    /// One `receive`; `WouldBlock` becomes `Ok(None)` instead of spinning.
    fn read_nb(&mut self, buf: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self
            .0
            .stack
            .receive(self.0.socket.as_mut().expect(SOCKET_LIVE), buf)
        {
            Ok(n) => Ok(Some(n)),
            Err(nb::Error::WouldBlock) => Ok(None),
            Err(nb::Error::Other(e)) => Err(NalError(e)),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        embedded_io::Write::write_all(&mut self.0, buf)
    }
}

/// The standard-profile stream over a [`PollNal`] transport with a caller-chosen
/// verify strategy `V`.
pub type NalStream<'s, S, V> = DefaultStreamWith<'s, PollNal<'s, S>, V>;

/// Resolve `host:port` to a [`SocketAddr`]. An IP literal is parsed directly;
/// otherwise `stack`'s [`Dns`] resolver is queried.
pub fn resolve<S: Dns>(stack: &mut S, host: &str, port: u16) -> Result<SocketAddr, S::Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let ip = nb::block!(stack.get_host_by_name(host, AddrType::Either))?;
    Ok(SocketAddr::new(ip, port))
}

/// Open a socket on `stack`, connect it to `remote`, and drive the TLS 1.3
/// handshake to a ready [`NalStream`].
pub fn connect<'s, S, R, V, A>(
    stack: &'s mut S,
    remote: SocketAddr,
    params: &ClientParams<'_, V, A>,
    scratch: &'s mut DefaultScratch,
    rng: &mut R,
) -> Result<NalStream<'s, S, V>, ConnectError<NalError<S::Error>>>
where
    S: TcpClientStack,
    R: rand_core::TryCryptoRng,
    V: VerifyStrategy<
            <DefaultConfig as ClientConfig>::Ed25519,
            <DefaultConfig as ClientConfig>::Rsa,
        >,
    A: ClientAuthSign<R>,
{
    let transport = PollNal::new(NalTransport::open(stack, remote).map_err(ConnectError::Io)?);
    NalStream::<S, V>::connect(params, scratch, transport, rng)
}
