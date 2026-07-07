//! Blocking TLS 1.3 client handle. Sans-randomness — caller supplies the RNG.

use crate::ClientHelloError;
use crate::client_flight::ClientAuthPolicy;
use crate::connection::ConnectionError;
use crate::connection::Init;
use crate::connection::TlsConnection;
use crate::traits::verify_strategy::VerifyStrategy;

use super::engine::{EngineEvent, EngineState, TlsEngine};
use super::error::{ConfigError, ConnectError, HandshakeError, InternalError, WriteAppError};
use super::scratch::{
    FACADE_HOSTNAME_MAX, MIN_RECV, MIN_SEND_STANDARD, RECORD_OVERHEAD, RecordSizeLimit, Scratch,
    client_auth_send_floor,
};
use super::{ClientConfig, ClientParams, ConfigSuitePolicy, RuntimeSuitePolicy, Transport};

/// X25519 backend type; matches `connection.rs`.
type X25519Bn = fixed_bigint::FixedUInt<u32, 16, const_num_traits::Ct>;

/// TLS 1.3 client handle.
///
/// `V` is the verify strategy the connection uses; `MAX_CHAIN` is the
/// upper bound on the server cert chain depth the strategy accepts.
/// Both have default values pinned by [`DefaultStream`].
pub struct TlsStream<
    's,
    T,
    C: ClientConfig,
    V,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
> where
    T: Transport,
{
    engine: TlsEngine<'s, C, FLIGHT, RECV, SEND, MAX_CHAIN>,
    transport: T,
    _v: core::marker::PhantomData<fn() -> V>,
}

/// Standard profile (pinned to [`DefaultScratch`](super::DefaultScratch)'s
/// dimensions and `DefaultConfig`) but with a caller-chosen verify strategy
/// `V`. Saves spelling out the buffer/chain const generics when only the
/// strategy differs from the default; for a non-default chain depth or buffer
/// profile, name [`TlsStream`] directly.
pub type DefaultStreamWith<'s, T, V> =
    TlsStream<'s, T, super::DefaultConfig, V, 16384, 16645, 4096, 8>;

/// Standard profile alias paired with `DefaultScratch`.
pub type DefaultStream<'s, T> = DefaultStreamWith<'s, T, super::DefaultVerify>;

impl<'s, T, C, V, const FLIGHT: usize, const RECV: usize, const SEND: usize, const MAX_CHAIN: usize>
    TlsStream<'s, T, C, V, FLIGHT, RECV, SEND, MAX_CHAIN>
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
    pub fn connect<R, A>(
        params: &ClientParams<'_, V, A>,
        scratch: &'s mut Scratch<FLIGHT, RECV, SEND>,
        transport: T,
        rng: &mut R,
    ) -> Result<Self, ConnectError<T::Error>>
    where
        R: rand_core::TryCryptoRng,
        V: VerifyStrategy<C::Ed25519, C::Rsa>,
        A: ClientAuthPolicy,
    {
        validate_construction::<_, _, RECV, SEND>(params)?;

        let mut client_random = [0u8; 32];
        let mut x25519_priv = crate::newtype::ZeroBuf::<32>::new([0u8; 32]);
        rng.try_fill_bytes(&mut client_random)
            .map_err(|_| HandshakeError::Rng)?;
        rng.try_fill_bytes(&mut *x25519_priv)
            .map_err(|_| HandshakeError::Rng)?;

        let x25519_pub = ed25519_heapless::x25519_base::<X25519Bn>(&x25519_priv);

        // Ephemeral ML-KEM-768 keypair for the X25519MLKEM768 key_share: the
        // decapsulator moves into the connection state; the public ek is
        // borrowed into the ClientHello options.
        #[cfg(feature = "mlkem")]
        let (mlkem, mlkem_ek) =
            crate::backends::mlkem::MlKem768::generate(rng).map_err(|_| HandshakeError::Rng)?;

        let our_recv_limit =
            TlsEngine::<'_, C, FLIGHT, RECV, SEND, MAX_CHAIN>::default_our_recv_limit();
        let suites = effective_suite_list::<C>(params.suite_policy);
        let init = TlsConnection::<Init, C::Hkdf>::new(
            client_random,
            x25519_priv,
            #[cfg(feature = "mlkem")]
            mlkem,
        );

        let opts = crate::ClientHelloOptions {
            hostname: Some(params.hostname.as_bytes()),
            record_size_limit: Some(our_recv_limit.get()),
            suites,
            #[cfg(feature = "mlkem")]
            mlkem_ek: Some(&mlkem_ek),
        };
        let (ch_len, wait_sh) = init
            .write_client_hello_to_slice_with(&mut scratch.ch, &x25519_pub, &opts)
            .map_err(map_client_hello_error)?;

        // Direct transmit because the Send-event path only carries protected records.
        let mut transport = transport;
        transport
            .write_all(&scratch.ch[..ch_len])
            .map_err(ConnectError::Io)?;

        let mut engine = TlsEngine::<C, FLIGHT, RECV, SEND, MAX_CHAIN>::new(
            scratch,
            EngineState::WaitServerHello(wait_sh),
            our_recv_limit,
            RecordSizeLimit::DEFAULT,
        );
        drive_handshake(&mut engine, &mut transport, params)?;

        Ok(Self {
            engine,
            transport,
            _v: core::marker::PhantomData,
        })
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
                    // Send dominates AppData in the engine's event priority.
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

impl<T, C, V, const FLIGHT: usize, const RECV: usize, const SEND: usize, const MAX_CHAIN: usize>
    Drop for TlsStream<'_, T, C, V, FLIGHT, RECV, SEND, MAX_CHAIN>
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

fn drive_handshake<
    C,
    T,
    V,
    A,
    const FLIGHT: usize,
    const RECV: usize,
    const SEND: usize,
    const MAX_CHAIN: usize,
>(
    engine: &mut TlsEngine<'_, C, FLIGHT, RECV, SEND, MAX_CHAIN>,
    transport: &mut T,
    params: &ClientParams<'_, V, A>,
) -> Result<(), ConnectError<T::Error>>
where
    T: Transport,
    C: ClientConfig,
    V: VerifyStrategy<C::Ed25519, C::Rsa>,
    A: ClientAuthPolicy,
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

fn validate_construction<V, A, const RECV: usize, const SEND: usize>(
    params: &ClientParams<'_, V, A>,
) -> Result<(), ConfigError>
where
    A: ClientAuthPolicy,
{
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
    // A mutual-auth policy emits the coalesced second flight, fragmented to the
    // peer's record_size_limit. `MAX_FLIGHT_LEN == 0` (NoClientAuth) needs only
    // MIN_SEND_STANDARD.
    if A::MAX_FLIGHT_LEN > 0 {
        // SEND must hold the worst-case fragmentation at the minimum legal
        // record_size_limit, so any compliant peer can be served.
        let needed = client_auth_send_floor(A::MAX_FLIGHT_LEN);
        if SEND < needed {
            return Err(ConfigError::BufferTooSmall { needed, got: SEND });
        }
        // The flight *plaintext* is built into the idle recv buffer, so RECV
        // must hold it too.
        if RECV < A::MAX_FLIGHT_LEN {
            return Err(ConfigError::BufferTooSmall {
                needed: A::MAX_FLIGHT_LEN,
                got: RECV,
            });
        }
    }
    // SEND must hold one full RECORD_OVERHEAD+plaintext record.
    debug_assert!(SEND > RECORD_OVERHEAD);
    Ok(())
}

fn effective_suite_list<C: ClientConfig>(runtime: RuntimeSuitePolicy) -> crate::SuiteList {
    match (C::SUITES, runtime) {
        #[cfg(feature = "cipher-aes")]
        (ConfigSuitePolicy::AesOnly, _) => crate::SuiteList::AesOnly,
        #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
        (ConfigSuitePolicy::AesAndChaCha, RuntimeSuitePolicy::AesOnly) => crate::SuiteList::AesOnly,
        #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
        (ConfigSuitePolicy::AesAndChaCha, RuntimeSuitePolicy::ChaChaOnly) => {
            crate::SuiteList::ChaChaOnly
        }
        #[cfg(all(feature = "cipher-aes", feature = "chacha20"))]
        (ConfigSuitePolicy::AesAndChaCha, RuntimeSuitePolicy::Default) => crate::SuiteList::Default,
        #[cfg(feature = "chacha20")]
        (ConfigSuitePolicy::ChaChaOnly, _) => crate::SuiteList::ChaChaOnly,
    }
}

fn map_client_hello_error<E>(e: ConnectionError<embedded_io::SliceWriteError>) -> ConnectError<E> {
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

impl<T, C, V, const FLIGHT: usize, const RECV: usize, const SEND: usize, const MAX_CHAIN: usize>
    embedded_io::ErrorType for TlsStream<'_, T, C, V, FLIGHT, RECV, SEND, MAX_CHAIN>
where
    T: Transport,
    T::Error: embedded_io::Error + 'static,
    C: ClientConfig,
{
    type Error = StreamError<T::Error>;
}

impl<T, C, V, const FLIGHT: usize, const RECV: usize, const SEND: usize, const MAX_CHAIN: usize>
    embedded_io::Read for TlsStream<'_, T, C, V, FLIGHT, RECV, SEND, MAX_CHAIN>
where
    T: Transport,
    T::Error: embedded_io::Error + 'static,
    C: ClientConfig,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsStream::read(self, buf).map_err(StreamError::from)
    }
}

impl<T, C, V, const FLIGHT: usize, const RECV: usize, const SEND: usize, const MAX_CHAIN: usize>
    embedded_io::Write for TlsStream<'_, T, C, V, FLIGHT, RECV, SEND, MAX_CHAIN>
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

// Facade-level KeyUpdate coverage: drives the public `read()` path end-to-end
// through a transport. Gated to the AES-only build like the rest of the fixture
// replays (uses the test-only `AppData` constructor + `decrypt_record`).
#[cfg(all(
    test,
    feature = "cipher-aes",
    not(feature = "chacha20"),
    not(feature = "rsa")
))]
mod tests {
    use super::*;
    use crate::aead::Aes128GcmSha256;
    use crate::backends::RustCrypto;
    use crate::client::{DefaultConfig, DefaultScratch, DefaultVerify};
    use crate::connection::AppData;
    use crate::consts::{CT_APPLICATION_DATA, CT_HANDSHAKE, HS_KEY_UPDATE};
    use crate::newtype::Secret;

    type AppConn = TlsConnection<AppData<Aes128GcmSha256>, RustCrypto>;
    type Stream<'s> =
        TlsStream<'s, MockIo<'s>, DefaultConfig, DefaultVerify, 16384, 16645, 4096, 8>;

    /// In-crate replay transport: a server tape to read and a fixed capture of
    /// client TX. Implements `embedded_io::Read`/`Write`, so krabitls's blanket
    /// `Transport` impl applies (no cross-crate dev-dep duplication, unlike
    /// `krabitls_fixtures::CannedTransport`).
    struct MockIo<'a> {
        rx: &'a [u8],
        rx_pos: usize,
        tx: [u8; 256],
        tx_pos: usize,
    }

    impl<'a> MockIo<'a> {
        fn new(rx: &'a [u8]) -> Self {
            Self {
                rx,
                rx_pos: 0,
                tx: [0u8; 256],
                tx_pos: 0,
            }
        }
        fn captured_tx(&self) -> &[u8] {
            &self.tx[..self.tx_pos]
        }
    }

    impl embedded_io::ErrorType for MockIo<'_> {
        type Error = core::convert::Infallible;
    }

    impl embedded_io::Read for MockIo<'_> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let take = (self.rx.len() - self.rx_pos).min(buf.len());
            buf[..take].copy_from_slice(&self.rx[self.rx_pos..self.rx_pos + take]);
            self.rx_pos += take;
            Ok(take)
        }
    }

    impl embedded_io::Write for MockIo<'_> {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.tx[self.tx_pos..self.tx_pos + buf.len()].copy_from_slice(buf);
            self.tx_pos += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// `(c_ap, s_ap)` secrets; the server is the mirror with these swapped.
    fn app_conn(c: u8, s: u8) -> AppConn {
        AppConn::from_app_secrets(Secret::from([c; 32]), Secret::from([s; 32]), 0, 0).unwrap()
    }

    /// A server `KeyUpdate(update_requested=1)` mid-stream is handled
    /// transparently by the public `read()`: the wrapper rotates receive keys,
    /// auto-emits our `KeyUpdate(0)` to the transport, and returns the server's
    /// post-update application data decrypted under the rotated keys.
    #[test]
    fn read_transparently_handles_server_key_update() {
        // Mirror server (swapped secrets) produces its post-handshake stream up
        // front: KeyUpdate(1) under gen-0 send keys, then app data under gen-1.
        let mut server = app_conn(0x43, 0x42);
        let mut ku = [0u8; 32];
        let ku_n = server.encrypt_key_update(true, &mut ku).unwrap().len();
        server.apply_send_key_update().unwrap();
        let mut app = [0u8; 96];
        let app_n = server
            .encrypt_record(b"post-update payload", CT_APPLICATION_DATA, &mut app)
            .unwrap()
            .len();
        let mut server_stream = [0u8; 160];
        server_stream[..ku_n].copy_from_slice(&ku[..ku_n]);
        server_stream[ku_n..ku_n + app_n].copy_from_slice(&app[..app_n]);
        let stream_len = ku_n + app_n;

        let mut scratch = DefaultScratch::new();
        let engine = TlsEngine::new(
            &mut scratch,
            EngineState::<DefaultConfig>::AppAes(app_conn(0x42, 0x43)),
            RecordSizeLimit::from_clamped(16384),
            RecordSizeLimit::from_clamped(16384),
        );
        let mut tls: Stream<'_> = TlsStream {
            engine,
            transport: MockIo::new(&server_stream[..stream_len]),
            _v: core::marker::PhantomData,
        };

        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"post-update payload");

        // The wrapper flushed exactly our KeyUpdate(0) to the transport; a
        // mirror server decrypts it under its old receive keys.
        let mut server_rx = app_conn(0x43, 0x42);
        let mut pt = [0u8; 32];
        let (content, ct) = server_rx
            .decrypt_record(tls.transport().captured_tx(), &mut pt)
            .unwrap();
        assert_eq!(ct, CT_HANDSHAKE);
        assert_eq!(content, &[HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00]);
    }
}
