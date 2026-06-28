//! Caller-owned, no-alloc per-connection storage. Buffer sizes are const
//! generics; backend choice ([`super::ClientConfig`]) is orthogonal.

use crate::reassembler::ServerFlightReassembler;

/// 5-byte TLS record header.
pub(crate) const TLS_HEADER: usize = 5;
/// AEAD tag length for both AES-128-GCM and ChaCha20-Poly1305.
pub(crate) const AEAD_TAG: usize = 16;
/// Per-record overhead on the wire (header + AEAD tag). Used everywhere
/// the engine derives advertised limit ↔ buffer-size mappings.
pub(crate) const RECORD_OVERHEAD: usize = TLS_HEADER + AEAD_TAG;
pub(crate) use crate::consts::CONTENT_TYPE_LEN;
/// RFC 8449 §4 ceiling for TLS 1.3's `record_size_limit` extension.
pub(crate) const PROTO_MAX_INNER_PLAINTEXT: u16 = 16385;
/// RFC 8449 §4 floor for `record_size_limit`. Values below this are a
/// fatal protocol error.
pub(crate) const MIN_RECORD_SIZE_LIMIT: u16 = 64;

/// A validated RFC 8449 `record_size_limit`: the largest protected-record
/// *inner plaintext* (content + the 1-byte content type) the holder will
/// accept. Always within `[MIN_RECORD_SIZE_LIMIT, PROTO_MAX_INNER_PLAINTEXT]`,
/// so it can't be confused with an unvalidated record or buffer length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct RecordSizeLimit(u16);

/// `u16` out of the RFC 8449 `[64, 2^14 + 1]` range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecordSizeLimitOutOfRange;

impl RecordSizeLimit {
    /// RFC 8449 default when the peer advertises none: the protocol maximum.
    pub(crate) const DEFAULT: Self = Self(PROTO_MAX_INNER_PLAINTEXT);

    /// Wrap a value the caller has already constrained to range (e.g. our own
    /// buffer-derived limit). `const` so it composes in const derivations.
    pub(crate) const fn from_clamped(value: u16) -> Self {
        debug_assert!(value >= MIN_RECORD_SIZE_LIMIT && value <= PROTO_MAX_INNER_PLAINTEXT);
        Self(value)
    }

    pub(crate) const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for RecordSizeLimit {
    type Error = RecordSizeLimitOutOfRange;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (MIN_RECORD_SIZE_LIMIT..=PROTO_MAX_INNER_PLAINTEXT).contains(&value) {
            Ok(Self(value))
        } else {
            Err(RecordSizeLimitOutOfRange)
        }
    }
}

/// Locked-profile ServerHello on-wire record size. Plaintext (no AEAD
/// tag) so RFC 8449 negotiation doesn't constrain it; the recv buffer
/// must still be able to hold it. Under `mlkem` the `X25519MLKEM768`
/// server key_share carries an extra ML-KEM-768 ciphertext (1088 B).
#[cfg(not(feature = "mlkem"))]
pub(crate) const SERVER_HELLO_RECORD_LEN: usize = 95;
#[cfg(feature = "mlkem")]
pub(crate) const SERVER_HELLO_RECORD_LEN: usize = 95 + crate::backends::mlkem::MLKEM768_CT_BYTES;

/// Minimum `RECV` to receive both the locked-profile plaintext
/// ServerHello and a protected record at the smallest legal
/// `record_size_limit`. ServerHello (95 B) currently dominates.
pub const MIN_RECV: usize = {
    let proto_floor = MIN_RECORD_SIZE_LIMIT as usize + RECORD_OVERHEAD;
    if SERVER_HELLO_RECORD_LEN > proto_floor {
        SERVER_HELLO_RECORD_LEN
    } else {
        proto_floor
    }
};

/// Minimum `SEND` that holds the engine's largest single internally-
/// generated record. Today that's the Client Finished — alerts and
/// one-byte app records fit well under it.
pub const MIN_SEND_STANDARD: usize = max_const_3(
    crate::client_flight::CLIENT_FINISHED_LEN,
    TLS_HEADER + AEAD_TAG + 2 + 1, // 2-byte alert + content_type byte
    TLS_HEADER + AEAD_TAG + 1 + 1, // 1-byte app + content_type byte
);

/// Worst-case `SEND` for a client-auth second flight of `max_flight` plaintext
/// bytes. At the minimum legal `record_size_limit` it fragments into
/// `ceil(max_flight / (MIN_RECORD_SIZE_LIMIT - 1))` records (RFC 8446 §5.1),
/// each adding a content-type byte + record overhead. `0` ⇒ no flight.
pub(crate) const fn client_auth_send_floor(max_flight: usize) -> usize {
    if max_flight == 0 {
        return 0;
    }
    let records = max_flight.div_ceil(MIN_RECORD_SIZE_LIMIT as usize - CONTENT_TYPE_LEN);
    max_flight + records * (RECORD_OVERHEAD + CONTENT_TYPE_LEN)
}

/// Facade hostname-policy cap (255 bytes).
pub const FACADE_HOSTNAME_MAX: usize = 255;

/// ClientHello scratch capacity; held fixed so `Scratch::new` is `const`.
/// Single source of truth is [`crate::connection::CH_SCRATCH`] so the two
/// can't drift.
pub(crate) const CH_LEN: usize = crate::connection::CH_SCRATCH;

const fn max_const(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}
const fn max_const_3(a: usize, b: usize, c: usize) -> usize {
    max_const(max_const(a, b), c)
}

/// Per-connection scratch storage, parameterized over the three buffer
/// dimensions.
///
/// - `FLIGHT` — capacity of the server-flight reassembly buffer. Bounds the
///   largest reassembled handshake message (Certificate dominates).
///   Public RSA chains: 5–8 KiB. Self-signed Ed25519 leaf: 300–600 B.
/// - `RECV` — single full-record receive buffer. Caps incoming protected
///   records via RFC 8449 negotiation. Must be at least [`MIN_RECV`].
/// - `SEND` — single full-record send buffer. Sized for the largest
///   engine-internal send (Client Finished). Must be at least
///   [`MIN_SEND_STANDARD`].
#[repr(C)]
pub struct Scratch<const FLIGHT: usize, const RECV: usize, const SEND: usize> {
    pub(crate) reassembler: ServerFlightReassembler<FLIGHT>,
    pub(crate) recv_record: [u8; RECV],
    pub(crate) send_record: [u8; SEND],
    pub(crate) ch: [u8; CH_LEN],
}

impl<const FLIGHT: usize, const RECV: usize, const SEND: usize> Scratch<FLIGHT, RECV, SEND> {
    /// Construct a zeroed scratch. `const fn` so it can live in a `static`.
    ///
    /// A [`DefaultScratch`](super::DefaultScratch) is ~37 KiB — **do not** make
    /// one a local (`main`, a task loop): it will overflow almost any MCU
    /// stack. Place it in a `static` (e.g. behind a `Mutex<RefCell<…>>`) or,
    /// where `alloc` is available, a `Box`.
    pub const fn new() -> Self {
        Self {
            reassembler: ServerFlightReassembler::new(),
            recv_record: [0; RECV],
            send_record: [0; SEND],
            ch: [0; CH_LEN],
        }
    }

    /// Compile-time floor check, mirroring `validate_construction`'s runtime
    /// guard. User-supplied generics stay on the runtime path; the crate's own
    /// aliases force this (see below) so a mis-sized alias fails to build.
    const DIMENSIONS_VALID: () = {
        assert!(RECV >= MIN_RECV);
        assert!(SEND >= MIN_SEND_STANDARD);
    };
}

impl<const FLIGHT: usize, const RECV: usize, const SEND: usize> Default
    for Scratch<FLIGHT, RECV, SEND>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Public-internet profile — sized for arbitrary RSA chains and a
/// full-size receive record. ~37 KiB total.
pub type DefaultScratch = Scratch<16384, 16645, 4096>;

// Force the floor check for the crate-provided alias: a future edit that drops
// `DefaultScratch` below `MIN_RECV` / `MIN_SEND_STANDARD` fails to compile.
const _: () = DefaultScratch::DIMENSIONS_VALID;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_size_limit_validates_rfc8449_range() {
        assert!(RecordSizeLimit::try_from(MIN_RECORD_SIZE_LIMIT).is_ok());
        assert!(RecordSizeLimit::try_from(PROTO_MAX_INNER_PLAINTEXT).is_ok());
        assert_eq!(
            RecordSizeLimit::try_from(MIN_RECORD_SIZE_LIMIT - 1),
            Err(RecordSizeLimitOutOfRange)
        );
        assert_eq!(
            RecordSizeLimit::try_from(PROTO_MAX_INNER_PLAINTEXT + 1),
            Err(RecordSizeLimitOutOfRange)
        );
        assert_eq!(RecordSizeLimit::DEFAULT.get(), PROTO_MAX_INNER_PLAINTEXT);
        assert_eq!(RecordSizeLimit::from_clamped(8192).get(), 8192);
    }
}
