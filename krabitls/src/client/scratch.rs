//! Caller-owned, no-alloc per-connection storage. Buffer sizes are const
//! generics; backend choice ([`super::ClientConfig`]) is orthogonal.

use crate::ServerFlightReassembler;

/// 5-byte TLS record header.
pub(crate) const TLS_HEADER: usize = 5;
/// AEAD tag length for both AES-128-GCM and ChaCha20-Poly1305.
pub(crate) const AEAD_TAG: usize = 16;
/// Per-record overhead on the wire (header + AEAD tag). Used everywhere
/// the engine derives advertised limit ↔ buffer-size mappings.
pub(crate) const RECORD_OVERHEAD: usize = TLS_HEADER + AEAD_TAG;
/// RFC 8449 §4 ceiling for TLS 1.3's `record_size_limit` extension.
pub(crate) const PROTO_MAX_INNER_PLAINTEXT: u16 = 16385;
/// RFC 8449 §4 floor for `record_size_limit`. Values below this are a
/// fatal protocol error.
pub(crate) const MIN_RECORD_SIZE_LIMIT: u16 = 64;

/// Minimum `RECV` that lets the engine receive a record from a server
/// honouring the smallest legal `record_size_limit`.
///
/// `MIN_RECORD_SIZE_LIMIT (64) + RECORD_OVERHEAD (21) = 85`.
pub const MIN_RECV: usize = MIN_RECORD_SIZE_LIMIT as usize + RECORD_OVERHEAD;

/// Minimum `SEND` that holds the engine's largest single internally-
/// generated record. Today that's the Client Finished, sized exactly
/// by [`crate::CLIENT_FINISHED_LEN`] — alerts and one-byte app records
/// fit well under it.
pub const MIN_SEND_STANDARD: usize = max_const_3(
    crate::CLIENT_FINISHED_LEN,
    TLS_HEADER + AEAD_TAG + 2 + 1, // 2-byte alert + content_type byte
    TLS_HEADER + AEAD_TAG + 1 + 1, // 1-byte app + content_type byte
);

/// Facade hostname-policy cap (255 bytes).
pub const FACADE_HOSTNAME_MAX: usize = 255;

/// ClientHello scratch capacity; held fixed so `Scratch::new` is `const`.
pub(crate) const CH_LEN: usize = 512;

const fn max_const(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}
const fn max_const_3(a: usize, b: usize, c: usize) -> usize {
    max_const(max_const(a, b), c)
}

/// Per-connection scratch storage, parameterized over the three buffer
/// dimensions.
///
/// - `FLIGHT` — capacity of the [`ServerFlightReassembler`]. Bounds the
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
    /// Construct a zeroed scratch. `const fn` for `static` placement.
    pub const fn new() -> Self {
        Self {
            reassembler: ServerFlightReassembler::new(),
            recv_record: [0; RECV],
            send_record: [0; SEND],
            ch: [0; CH_LEN],
        }
    }
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

/// Controlled-peer Ed25519 profile — sized for a self-signed leaf and
/// 4 KiB protected records. ~6.6 KiB total.
pub type EmbeddedEd25519Scratch = Scratch<1024, 4096, 1024>;

/// Test-fixture profile. `FLIGHT = 512` is too small for any real
/// certificate chain; only use against synthetic / captured fixtures.
/// ~3.6 KiB total.
pub type MinimalScratch = Scratch<512, 2048, 512>;

/// Override `RECV` only; default `FLIGHT`/`SEND`.
pub type CustomRecv<const RECV: usize> = Scratch<16384, RECV, 4096>;

/// One-axis ergonomic override for the send buffer size.
pub type CustomSend<const SEND: usize> = Scratch<16384, 16645, SEND>;

/// One-axis ergonomic override for the flight-reassembly capacity.
pub type CustomFlight<const FLIGHT: usize> = Scratch<FLIGHT, 16645, 4096>;
