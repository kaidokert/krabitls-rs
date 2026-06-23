//! Wire-codec error types. Kept in a `pub(crate)` module so they don't
//! leak at the crate root; re-exported at `crate::client::error::*` for
//! consumers that match on `ConnectionError::{ClientHello, Parse}`.

/// Error returned by the in-crate `WriteExt::write_u24` helper.
//
// Manual `Display` / `Error` impls to avoid `thiserror`'s implicit `E: Display` bound on the struct.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Write24Error<E> {
    /// `n > 0xFF_FFFF` — cannot be encoded as a 24-bit big-endian field.
    Overflow,
    /// The underlying writer returned an error.
    Write(E),
}

impl<E> From<E> for Write24Error<E> {
    fn from(e: E) -> Self {
        Self::Write(e)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for Write24Error<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overflow => f.write_str("value does not fit in 24 bits"),
            Self::Write(e) => write!(f, "writer error: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Write24Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Overflow => None,
            Self::Write(e) => Some(e),
        }
    }
}

/// Errors from `write_client_hello`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientHelloError<E> {
    /// `hostname.len()` exceeds the u16 SNI `HostName` cap (RFC 6066 §3).
    HostnameTooLong,
    /// Computed ClientHello body exceeds TLS 1.3's `2^14` plaintext cap
    /// (RFC 8446 §5.1).
    MessageTooLong,
    /// A wire-format length field overflowed its encoding.
    IntegerOverflow,
    /// `record_size_limit` is outside the RFC 8449 valid range `[64, 2^14 + 1]`.
    RecordSizeLimitOutOfRange,
    /// The underlying writer returned an error.
    Write(E),
}

impl<E> From<E> for ClientHelloError<E> {
    fn from(e: E) -> Self {
        Self::Write(e)
    }
}

impl<E> ClientHelloError<E> {
    pub fn map_writer<F, U>(self, f: F) -> ClientHelloError<U>
    where
        F: FnOnce(E) -> U,
    {
        match self {
            Self::HostnameTooLong => ClientHelloError::HostnameTooLong,
            Self::MessageTooLong => ClientHelloError::MessageTooLong,
            Self::IntegerOverflow => ClientHelloError::IntegerOverflow,
            Self::RecordSizeLimitOutOfRange => ClientHelloError::RecordSizeLimitOutOfRange,
            Self::Write(e) => ClientHelloError::Write(f(e)),
        }
    }
}

impl<E> From<Write24Error<E>> for ClientHelloError<E> {
    fn from(e: Write24Error<E>) -> Self {
        match e {
            Write24Error::Overflow => Self::IntegerOverflow,
            Write24Error::Write(e) => Self::Write(e),
        }
    }
}

impl<E: core::fmt::Display> core::fmt::Display for ClientHelloError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HostnameTooLong => f.write_str("hostname exceeds the u16 SNI length cap"),
            Self::MessageTooLong => {
                f.write_str("ClientHello body exceeds the 2^14 plaintext fragment cap")
            }
            Self::IntegerOverflow => {
                f.write_str("a length field overflowed its wire-format encoding")
            }
            Self::RecordSizeLimitOutOfRange => {
                f.write_str("record_size_limit is outside the RFC 8449 valid range")
            }
            Self::Write(e) => write!(f, "writer error: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ClientHelloError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Write(e) => Some(e),
            Self::HostnameTooLong
            | Self::MessageTooLong
            | Self::IntegerOverflow
            | Self::RecordSizeLimitOutOfRange => None,
        }
    }
}

/// Reasons a `parse_*` call may fail.
#[derive(Debug, PartialEq, Eq, Clone, Copy, thiserror::Error)]
pub enum ParseError {
    /// Buffer ended mid-field, or a length prefix declared more bytes than remained.
    #[error("buffer ended mid-field or length prefix overran")]
    Truncated,
    /// TLS record content type wasn't `handshake` (22).
    #[error("record content_type was 0x{0:02x}, expected handshake (22)")]
    UnexpectedContentType(u8),
    /// Handshake message type wasn't `server_hello` (2).
    #[error("handshake type was 0x{0:02x}, expected server_hello (2)")]
    UnexpectedHandshakeType(u8),
    /// Record-layer or `ClientHello.legacy_version` wasn't 0x0303.
    #[error("legacy_version was 0x{0:04x}, expected 0x0303")]
    UnexpectedLegacyVersion(u16),
    /// Selected cipher suite isn't part of our locked profile.
    #[error("cipher suite 0x{0:04x} is outside the locked profile")]
    UnsupportedCipherSuite(u16),
    /// `legacy_compression_method` wasn't 0.
    #[error("legacy_compression_method was 0x{0:02x}, expected 0")]
    UnexpectedCompressionMethod(u8),
    /// `supported_versions` extension missing, malformed, or didn't pick TLS 1.3.
    #[error("supported_versions extension missing, malformed, or did not pick TLS 1.3")]
    BadSupportedVersions,
    /// `key_share` extension missing, wrong group, or wrong key length.
    #[error("key_share extension missing, wrong group, or wrong key length")]
    BadKeyShare,
    /// Bytes left over after the structure said it was done.
    #[error("bytes left over after the structure said it was done")]
    TrailingBytes,
    /// Outer length didn't match the body it framed.
    #[error("outer length did not match the body it framed")]
    LengthMismatch,

    /// ServerHello carried an extension type we did not offer in the ClientHello.
    /// Per RFC 8446 §4.1.4 the client MUST abort the handshake.
    #[error("ServerHello carried an extension type 0x{0:04x} not offered in the ClientHello")]
    UnknownExtension(u16),
    /// Same extension type appeared twice in the same extension block.
    /// RFC 8446 §4.2 forbids this.
    #[error("extension type 0x{0:04x} appeared twice in the same extension block")]
    DuplicateExtension(u16),
    /// Server echoed back a non-empty `legacy_session_id_echo`, but the client
    /// sent an empty `legacy_session_id`. RFC 8446 §4.1.3 requires the echo to
    /// match what was sent.
    #[error("server echoed a non-empty legacy_session_id_echo")]
    UnexpectedSessionIdEcho,
    /// `ServerHello.random` carries the magic value indicating this message is
    /// really a HelloRetryRequest. Our profile never expects HRR, so this is
    /// either a misconfigured server or a downgrade attempt.
    #[error("server requested HelloRetryRequest")]
    HelloRetryRequested,
    /// Last 8 bytes of `ServerHello.random` match the RFC 8446 §4.1.3 sentinel
    /// that a TLS-1.3-capable server uses when it has been forced to negotiate
    /// TLS 1.2 or below. A real TLS 1.3 server speaking only TLS 1.3 will never
    /// emit this; if we see it, the connection is being downgraded.
    #[error("ServerHello.random sentinel indicates a TLS-1.2-or-below downgrade")]
    DowngradeDetected,
    /// X25519 shared secret was the all-zero value. RFC 8446 §7.4.2.1 says the
    /// client MUST abort with `illegal_parameter`. Typically means a low-order
    /// server key_share.
    #[error("X25519 shared secret was the all-zero value (low-order point)")]
    DhAllZero,
}
