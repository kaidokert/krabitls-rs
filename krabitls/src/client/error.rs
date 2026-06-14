//! Facade error tree. See per-enum docs.

use crate::ConnectionError;
use crate::IdentityError;
#[cfg(feature = "validity")]
use crate::ValidityError;

/// Outermost error returned by every public `TlsStream` method.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConnectError<E> {
    /// Transport returned an error.
    Io(E),

    /// Transport returned `Ok(0)` on a `read` mid-stream — peer closed
    /// without a `close_notify` alert.
    UnexpectedEof,

    /// Engine closed (initiated or peer `close_notify`).
    Closed,

    /// TLS protocol-level failure. Always fatal for this connection.
    Handshake(HandshakeError),

    /// Caller-side misconfiguration detected at `connect()` preflight or
    /// during construction.
    Config(ConfigError),
}

impl<E> From<HandshakeError> for ConnectError<E> {
    fn from(e: HandshakeError) -> Self {
        Self::Handshake(e)
    }
}

impl<E> From<ConfigError> for ConnectError<E> {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ConnectError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "transport I/O: {e}"),
            Self::UnexpectedEof => f.write_str("transport closed mid-TLS"),
            Self::Closed => f.write_str("TLS connection closed"),
            Self::Handshake(e) => write!(f, "handshake: {e}"),
            Self::Config(e) => write!(f, "config: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ConnectError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Handshake(e) => Some(e),
            Self::Config(e) => Some(e),
            Self::UnexpectedEof | Self::Closed => None,
        }
    }
}

/// TLS protocol-level failure.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HandshakeError {
    /// Wraps typestate `ConnectionError`.
    Connection(ConnectionError),
    /// SAN / pin check failure.
    Identity(IdentityError),
    /// Certificate validity window (`notBefore` / `notAfter`) check
    /// failed.
    #[cfg(feature = "validity")]
    Validity(ValidityError),

    /// ClientHello bytes overflowed `scratch.ch`.
    ClientHelloTooLong,

    /// 8449 enforcement: server sent a protected record whose length
    /// exceeds our advertised `record_size_limit`. Carries diagnostics so
    /// callers can distinguish peer noncompliance from local sizing.
    RecordTooLarge { limit: u16, got: u16 },

    /// Server's EncryptedExtensions `record_size_limit` was outside the
    /// RFC 8449 valid range `[64, 16385]`.
    InvalidRecordSizeLimit(u16),

    /// Caller called [`crate::client::TlsEngine::advance`](super) with
    /// `n` larger than the slice returned by `recv_buffer()`.
    AdvanceTooLarge,

    /// `write_app` invoked while a previous send is still pending
    /// `mark_sent` acknowledgement.
    Busy,

    /// `write_app` before handshake. Unreachable through public API.
    NotReady,

    /// Peer sent a post-handshake handshake message (NewSessionTicket /
    /// KeyUpdate / CertificateRequest / etc.). The facade does not
    /// support these; drop to the typestate API if you need them.
    PostHandshakeNotSupported,

    /// Engine invariant breach; see [`InternalError`].
    Internal(InternalError),
}

impl From<ConnectionError> for HandshakeError {
    fn from(e: ConnectionError) -> Self {
        Self::Connection(e)
    }
}

impl From<IdentityError> for HandshakeError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

#[cfg(feature = "validity")]
impl From<ValidityError> for HandshakeError {
    fn from(e: ValidityError) -> Self {
        Self::Validity(e)
    }
}

impl From<InternalError> for HandshakeError {
    fn from(e: InternalError) -> Self {
        Self::Internal(e)
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connection(e) => write!(f, "connection: {e}"),
            Self::Identity(e) => write!(f, "identity: {e}"),
            #[cfg(feature = "validity")]
            Self::Validity(e) => write!(f, "validity: {e}"),
            Self::ClientHelloTooLong => f.write_str("ClientHello overflowed scratch.ch"),
            Self::RecordTooLarge { limit, got } => write!(
                f,
                "peer record exceeds advertised limit (limit={limit}, got={got})"
            ),
            Self::InvalidRecordSizeLimit(v) => {
                write!(f, "peer record_size_limit out of range: {v}")
            }
            Self::AdvanceTooLarge => f.write_str("advance(n) larger than recv_buffer()"),
            Self::Busy => f.write_str("write_app while previous send pending mark_sent"),
            Self::NotReady => f.write_str("write_app before HandshakeDone"),
            Self::PostHandshakeNotSupported => {
                f.write_str("post-handshake handshake message not supported")
            }
            Self::Internal(e) => write!(f, "internal: {e}"),
        }
    }
}

impl core::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Connection(e) => Some(e),
            Self::Identity(e) => Some(e),
            #[cfg(feature = "validity")]
            Self::Validity(e) => Some(e),
            Self::Internal(e) => Some(e),
            Self::ClientHelloTooLong
            | Self::RecordTooLarge { .. }
            | Self::InvalidRecordSizeLimit(_)
            | Self::AdvanceTooLarge
            | Self::Busy
            | Self::NotReady
            | Self::PostHandshakeNotSupported => None,
        }
    }
}

/// Caller-side misconfiguration detected at `connect()` preflight.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfigError {
    /// Hostname exceeded 255-byte facade cap.
    HostnameTooLong,
    /// One of `FLIGHT` / `RECV` / `SEND` on the supplied `Scratch` is
    /// below the protocol minimum. `needed` is the smallest value that
    /// would satisfy the check.
    BufferTooSmall { needed: usize, got: usize },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HostnameTooLong => f.write_str("hostname exceeds the facade's 255-byte cap"),
            Self::BufferTooSmall { needed, got } => {
                write!(f, "Scratch buffer too small (needed {needed}, got {got})")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

/// Engine-internal invariant breach. Surfaced instead of panicking so
/// the wire can't trigger `unreachable!()` on Cortex-M.
#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum InternalError {
    /// `step()` yielded `Recv` but the recv buffer is empty.
    RecvBufferEmptyOnRecvEvent,
    /// `drain_one_send()` saw a non-`Send` event while `is_send_pending()`.
    DrainStateInconsistent,
    /// `write_app` returned `NotReady` after `connect()` consumed `HandshakeDone`.
    WriteBeforeHandshake,
    /// `mark_sent(k)` with `k > (send_pending_len - send_acked)`.
    MarkSentTooLarge,
    /// `step_handshake` invoked in the data phase.
    HandshakeStepInDataPhase,
    /// `step_handshake` invoked in `Init` or `Closed`.
    HandshakeStepWrongState,
    /// `handle_server_hello` called outside `WaitServerHello`.
    ServerHelloWrongState,
    /// `handle_flight_record` called outside `WaitFlight*`.
    FlightWrongState,
    /// `finalize_and_finish` called outside `WaitFlight*`.
    FinalizeWrongState,
    /// `frame_one_record` called with parked plaintext.
    FrameWithParkedPlaintext,
    /// `advance(n > 0)` invoked with parked plaintext (RecvState I3).
    AdvanceWhileParked,
    /// `drive_handshake` observed `AppData`.
    AppDataDuringDriveHandshake,
    /// `TlsStream::read` observed `HandshakeDone` in the data phase.
    HandshakeDoneInDataPhase,
    /// `write_app` returned `Ok(0)` with a non-empty plaintext buffer.
    WriteAppZeroProgress,
}

impl core::fmt::Display for InternalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::RecvBufferEmptyOnRecvEvent => "Recv event with empty recv_buffer",
            Self::DrainStateInconsistent => "drain_one_send state inconsistent",
            Self::WriteBeforeHandshake => "write_app before HandshakeDone",
            Self::MarkSentTooLarge => "mark_sent(n) exceeded pending send length",
            Self::HandshakeStepInDataPhase => "step_handshake invoked in data phase",
            Self::HandshakeStepWrongState => "step_handshake in Init or Closed state",
            Self::ServerHelloWrongState => "handle_server_hello with wrong state",
            Self::FlightWrongState => "handle_flight_record with wrong state",
            Self::FinalizeWrongState => "finalize_and_finish with wrong state",
            Self::FrameWithParkedPlaintext => "frame_one_record with parked plaintext",
            Self::AdvanceWhileParked => "advance(n > 0) while plaintext was parked",
            Self::AppDataDuringDriveHandshake => "drive_handshake observed AppData",
            Self::HandshakeDoneInDataPhase => "TlsStream::read observed HandshakeDone",
            Self::WriteAppZeroProgress => "write_app returned 0 with non-empty buffer",
        })
    }
}

impl core::error::Error for InternalError {}

/// `pub(crate)` so the wrapper maps `Closed` → `ConnectError::Closed`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum WriteAppError {
    Closed,
    Busy,
    NotReady,
    Other(HandshakeError),
}
