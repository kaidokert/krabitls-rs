//! Blocking TLS 1.3 client handle. Sans-randomness — caller supplies the RNG.

use crate::TlsConnection;
use crate::connection::Init;

use super::engine::{EngineEvent, EngineState, TlsEngine};
use super::error::{ConfigError, ConnectError, HandshakeError, InternalError, WriteAppError};
use super::scratch::{
    FACADE_HOSTNAME_MAX, MIN_RECV, MIN_SEND_STANDARD, PROTO_MAX_INNER_PLAINTEXT, RECORD_OVERHEAD,
    Scratch,
};
use super::{ClientConfig, ClientParams, ConfigSuitePolicy, RuntimeSuitePolicy, Transport};

/// X25519 backend type; matches `connection.rs`.
type X25519Bn = fixed_bigint::FixedUInt<u32, 16, fixed_bigint::Ct>;

/// TLS 1.3 client handle.
pub struct TlsStream<
    's,
    T,
    C: ClientConfig,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
> where
    T: Transport,
{
    engine: TlsEngine<'s, C, FLIGHT, RECV, SEND>,
    transport: T,
}

/// Standard profile alias paired with `DefaultScratch`.
pub type DefaultStream<'s, T> = TlsStream<'s, T, super::DefaultConfig, 16384, 16645, 4096>;

impl<'s, T, C, const FLIGHT: usize, const RECV: usize, const SEND: usize>
    TlsStream<'s, T, C, FLIGHT, RECV, SEND>
where
    T: Transport,
    C: ClientConfig,
{
    /// Drive a full TLS 1.3 handshake against `transport` using
    /// `scratch` for all per-connection state.
    ///
    /// Construction errors:
    /// - [`ConnectError::Config`] for pre-flight failures (buffer sizes
    ///   too small for the negotiated profile, hostname > 255 bytes).
    /// - [`ConnectError::Io`] for any transport read/write error.
    /// - [`ConnectError::Handshake`] for any TLS-protocol-level
    ///   failure including identity, cert validity, RFC 8449
    ///   violations.
    /// - [`ConnectError::UnexpectedEof`] when the transport returns
    ///   `Ok(0)` mid-handshake.
    pub fn connect<R>(
        params: &ClientParams<'_>,
        scratch: &'s mut Scratch<FLIGHT, RECV, SEND>,
        transport: T,
        rng: &mut R,
    ) -> Result<Self, ConnectError<T::Error>>
    where
        R: rand_core::CryptoRng,
    {
        validate_construction::<RECV, SEND>(params)?;

        let mut client_random = [0u8; 32];
        let mut x25519_priv = crate::ZeroBuf::<32>::new([0u8; 32]);
        rng.fill_bytes(&mut client_random);
        rng.fill_bytes(&mut *x25519_priv);

        let x25519_pub = ed25519_heapless::x25519_base::<X25519Bn>(&x25519_priv);

        let our_recv_limit = TlsEngine::<'_, C, FLIGHT, RECV, SEND>::default_our_recv_limit();
        let suites = effective_suite_list::<C>(params.suite_policy);
        let init = TlsConnection::<Init, C::Hkdf, C::Record>::new(client_random, x25519_priv);

        let opts = crate::ClientHelloOptions {
            hostname: Some(params.hostname.as_bytes()),
            record_size_limit: Some(our_recv_limit),
            suites,
        };
        let (ch_len, wait_sh) = init
            .write_client_hello_to_slice_with(&mut scratch.ch, &x25519_pub, &opts)
            .map_err(map_client_hello_error)?;

        // 5. Transmit ClientHello directly — the Send-event path only
        //    ever carries protected records.
        let mut transport = transport;
        transport
            .write_all(&scratch.ch[..ch_len])
            .map_err(ConnectError::Io)?;

        // 6. Construct the engine in WaitServerHello state and drive
        //    the handshake-phase loop until HandshakeDone.
        let mut engine = TlsEngine::<C, FLIGHT, RECV, SEND>::new(
            scratch,
            EngineState::WaitServerHello(wait_sh),
            our_recv_limit,
            PROTO_MAX_INNER_PLAINTEXT,
            params.suite_policy,
        );
        drive_handshake(&mut engine, &mut transport, params)?;

        Ok(Self { engine, transport })
    }

    /// Read app data into `out`. `Ok(0)` = peer `close_notify`.
    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, ConnectError<T::Error>> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            match self.engine.step()? {
                EngineEvent::Send(_n) => {
                    self.drive_one_send_step()?;
                }
                EngineEvent::Recv => {
                    self.drive_one_recv_step()?;
                }
                EngineEvent::AppData => return Ok(self.engine.read_app(out)),
                EngineEvent::HandshakeDone => {
                    // Unreachable: `connect()` consumed the single
                    // `HandshakeDone` emission before the stream existed.
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::HandshakeDoneInDataPhase,
                    )));
                }
                EngineEvent::Closed => return Ok(0),
            }
        }
    }

    /// Write all of `buf` as one or more `application_data` records.
    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<(), ConnectError<T::Error>> {
        while !buf.is_empty() {
            self.drain_pending_send()?;
            match self.engine.write_app(buf) {
                // Zero progress on non-empty buf would spin; surface as error.
                Ok(0) => {
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::WriteAppZeroProgress,
                    )));
                }
                Ok(n) => buf = &buf[n..],
                Err(WriteAppError::Closed) => return Err(ConnectError::Closed),
                Err(WriteAppError::Busy) => {
                    self.drain_pending_send()?;
                    continue;
                }
                Err(WriteAppError::NotReady) => {
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::WriteBeforeHandshake,
                    )));
                }
                Err(WriteAppError::Other(e)) => return Err(ConnectError::Handshake(e)),
            }
            self.drain_pending_send()?;
        }
        Ok(())
    }

    /// Borrow the underlying transport (read-only).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Emit `close_notify` and drain. Idempotent. Drop runs this
    /// best-effort; explicit callers see the error. Pending sends
    /// flush *before* the `is_closed()` short-circuit so a retry
    /// after a failed close_notify re-attempts the flush.
    pub fn close(&mut self) -> Result<(), ConnectError<T::Error>> {
        self.drain_pending_send()?;
        if self.engine.is_closed() {
            return Ok(());
        }
        self.engine.close()?;
        self.drain_pending_send()
    }

    // ------------------------------------------------------------------
    // Private drive helpers
    // ------------------------------------------------------------------

    /// Drive one Send event. On `write_all` error, `mark_terminal`:
    /// `embedded_io::Write::write_all` may leave a prefix on the wire,
    /// and resending it would desync the AEAD sequence number.
    fn drive_one_send_step(&mut self) -> Result<(), ConnectError<T::Error>> {
        let bytes = self.engine.send_bytes();
        if bytes.is_empty() {
            return Err(ConnectError::Handshake(HandshakeError::Internal(
                InternalError::DrainStateInconsistent,
            )));
        }
        let n = bytes.len();
        if let Err(e) = self.transport.write_all(bytes) {
            self.engine.mark_terminal();
            return Err(ConnectError::Io(e));
        }
        self.engine.mark_sent(n)?;
        Ok(())
    }

    /// Drive a single `Recv` event: fill `engine.recv_buffer()` from
    /// the transport, ack with `advance()`.
    fn drive_one_recv_step(&mut self) -> Result<(), ConnectError<T::Error>> {
        let buf = self.engine.recv_buffer();
        debug_assert!(
            !buf.is_empty(),
            "Recv event with empty recv_buffer — invariant breach"
        );
        if buf.is_empty() {
            return Err(ConnectError::Handshake(HandshakeError::Internal(
                InternalError::RecvBufferEmptyOnRecvEvent,
            )));
        }
        let n = self.transport.read(buf).map_err(ConnectError::Io)?;
        if n == 0 {
            return Err(ConnectError::UnexpectedEof);
        }
        self.engine.advance(n)?;
        Ok(())
    }

    /// Drain any pending Send to completion.
    fn drain_pending_send(&mut self) -> Result<(), ConnectError<T::Error>> {
        if !self.engine.is_send_pending() {
            return Ok(());
        }
        loop {
            match self.engine.step()? {
                EngineEvent::Send(_) => {
                    self.drive_one_send_step()?;
                    if !self.engine.is_send_pending() {
                        return Ok(());
                    }
                }
                EngineEvent::AppData => {
                    // Caller invoked write/close while the engine has
                    // both a queued send and parked plaintext. Send
                    // dominates AppData in the engine's event priority,
                    // so this branch is only reachable after the send
                    // drains — i.e. the next iteration. Returning Ok
                    // lets the outer loop observe AppData via a
                    // subsequent `read()` call.
                    return Ok(());
                }
                EngineEvent::Closed => return Err(ConnectError::Closed),
                EngineEvent::HandshakeDone => continue,
                EngineEvent::Recv => {
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::DrainStateInconsistent,
                    )));
                }
            }
        }
    }
}

impl<T, C, const FLIGHT: usize, const RECV: usize, const SEND: usize> Drop
    for TlsStream<'_, T, C, FLIGHT, RECV, SEND>
where
    T: Transport,
    C: ClientConfig,
{
    fn drop(&mut self) {
        // Best-effort close_notify; Drop can't propagate.
        let _ = self.close();
    }
}

// ============================================================================
// Engine drive loop for the handshake phase
// ============================================================================

fn drive_handshake<C, T, const FLIGHT: usize, const RECV: usize, const SEND: usize>(
    engine: &mut TlsEngine<'_, C, FLIGHT, RECV, SEND>,
    transport: &mut T,
    params: &ClientParams<'_>,
) -> Result<(), ConnectError<T::Error>>
where
    T: Transport,
    C: ClientConfig,
{
    loop {
        match engine.step_handshake(params)? {
            EngineEvent::HandshakeDone => return Ok(()),
            EngineEvent::Send(_n) => {
                let bytes = engine.send_bytes();
                let n = bytes.len();
                if n == 0 {
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::DrainStateInconsistent,
                    )));
                }
                if let Err(e) = transport.write_all(bytes) {
                    engine.mark_terminal();
                    return Err(ConnectError::Io(e));
                }
                engine.mark_sent(n)?;
            }
            EngineEvent::Recv => {
                let buf = engine.recv_buffer();
                debug_assert!(
                    !buf.is_empty(),
                    "drive_handshake Recv event with empty buffer — invariant breach"
                );
                if buf.is_empty() {
                    return Err(ConnectError::Handshake(HandshakeError::Internal(
                        InternalError::RecvBufferEmptyOnRecvEvent,
                    )));
                }
                let n = transport.read(buf).map_err(ConnectError::Io)?;
                if n == 0 {
                    return Err(ConnectError::UnexpectedEof);
                }
                engine.advance(n)?;
            }
            EngineEvent::AppData => {
                // Unreachable: `HandshakeDone` fires first under the
                // engine's event priority.
                return Err(ConnectError::Handshake(HandshakeError::Internal(
                    InternalError::AppDataDuringDriveHandshake,
                )));
            }
            EngineEvent::Closed => return Err(ConnectError::Closed),
        }
    }
}

// ============================================================================
// Pre-flight + opts derivation
// ============================================================================

fn validate_construction<const RECV: usize, const SEND: usize>(
    params: &ClientParams<'_>,
) -> Result<(), ConfigError> {
    if params.hostname.len() > FACADE_HOSTNAME_MAX {
        return Err(ConfigError::HostnameTooLong);
    }
    if RECV < MIN_RECV {
        return Err(ConfigError::BufferTooSmall {
            needed: MIN_RECV,
            got: RECV,
        });
    }
    if SEND < MIN_SEND_STANDARD {
        return Err(ConfigError::BufferTooSmall {
            needed: MIN_SEND_STANDARD,
            got: SEND,
        });
    }
    // SEND must hold one full RECORD_OVERHEAD+plaintext record.
    debug_assert!(SEND > RECORD_OVERHEAD);
    Ok(())
}

fn effective_suite_list<C: ClientConfig>(runtime: RuntimeSuitePolicy) -> crate::SuiteList {
    match (C::SUITES, runtime) {
        (ConfigSuitePolicy::AesOnly, _) => crate::SuiteList::AesOnly,
        #[cfg(feature = "chacha20")]
        (ConfigSuitePolicy::AesAndChaCha, RuntimeSuitePolicy::AesOnly) => crate::SuiteList::AesOnly,
        #[cfg(feature = "chacha20")]
        (ConfigSuitePolicy::AesAndChaCha, RuntimeSuitePolicy::Default) => crate::SuiteList::Default,
    }
}

fn map_client_hello_error<E>(
    e: crate::ConnectionError<embedded_io::SliceWriteError>,
) -> ConnectError<E> {
    use crate::{ClientHelloError, ConnectionError};
    match e {
        ConnectionError::ClientHello(ClientHelloError::HostnameTooLong) => {
            ConnectError::Config(ConfigError::HostnameTooLong)
        }
        ConnectionError::ClientHello(
            ClientHelloError::Write(_) | ClientHelloError::MessageTooLong,
        ) => ConnectError::Handshake(HandshakeError::ClientHelloTooLong),
        other => ConnectError::Handshake(HandshakeError::Connection(
            other.map_writer(|_| unreachable!()),
        )),
    }
}

// ============================================================================
// embedded_io blanket impls
// ============================================================================

impl<T, C, const FLIGHT: usize, const RECV: usize, const SEND: usize> embedded_io::ErrorType
    for TlsStream<'_, T, C, FLIGHT, RECV, SEND>
where
    T: Transport,
    T::Error: embedded_io::Error + 'static,
    C: ClientConfig,
{
    type Error = StreamError<T::Error>;
}

impl<T, C, const FLIGHT: usize, const RECV: usize, const SEND: usize> embedded_io::Read
    for TlsStream<'_, T, C, FLIGHT, RECV, SEND>
where
    T: Transport,
    T::Error: embedded_io::Error + 'static,
    C: ClientConfig,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsStream::read(self, buf).map_err(StreamError::from)
    }
}

impl<T, C, const FLIGHT: usize, const RECV: usize, const SEND: usize> embedded_io::Write
    for TlsStream<'_, T, C, FLIGHT, RECV, SEND>
where
    T: Transport,
    T::Error: embedded_io::Error + 'static,
    C: ClientConfig,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // Records commit all-or-nothing; partial writes aren't expressible.
        TlsStream::write_all(self, buf).map_err(StreamError::from)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        // No buffering; write_all already drained.
        Ok(())
    }
}

/// Newtype wrapping `ConnectError` for `embedded_io::ErrorType`.
#[derive(Debug)]
pub struct StreamError<E>(pub ConnectError<E>);

impl<E> From<ConnectError<E>> for StreamError<E> {
    fn from(e: ConnectError<E>) -> Self {
        Self(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for StreamError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

impl<E: core::error::Error + 'static> core::error::Error for StreamError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.0.source()
    }
}

impl<E: embedded_io::Error + 'static> embedded_io::Error for StreamError<E> {
    fn kind(&self) -> embedded_io::ErrorKind {
        match &self.0 {
            ConnectError::Io(e) => e.kind(),
            ConnectError::UnexpectedEof => embedded_io::ErrorKind::BrokenPipe,
            ConnectError::Closed => embedded_io::ErrorKind::ConnectionAborted,
            ConnectError::Handshake(_) | ConnectError::Config(_) => embedded_io::ErrorKind::Other,
        }
    }
}
